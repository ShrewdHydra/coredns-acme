package acme

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrNoAuthenticationCredentials = errors.New("no authentication credentials")
	ErrInvalidUsernameOrPassword   = errors.New("invalid username or password")
	ErrAuthDisabled                = errors.New("authentication disabled")
)

// Context key type to prevent collisions
type key int

// ACMEAccountKey is a context key for storing Account information
const ACMEAccountKey key = 0
const ACMERequestKey key = 1

// Auth is middleware that authenticates API requests
func (a *ACME) Auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r, a.AuthConfig.ExtractIPFromHeader)
		if clientIP == "" || !a.AuthConfig.AllowedIPs.contains(clientIP) {
			log.Warningf("Auth middleware: IP %s not allowed. Allowed IPs: %v", clientIP, a.AuthConfig.AllowedIPs)
			writeJSONError(w, "forbidden_ip", http.StatusForbidden)
			return
		}

		if r.Body == http.NoBody {
			log.Warning("Auth middleware: No request body found")
			writeJSONError(w, "no_request_body", http.StatusBadRequest)
			return
		}

		var dnsRecord ACMETxt
		if err := json.NewDecoder(r.Body).Decode(&dnsRecord); err != nil {
			log.Warningf("Auth middleware: Invalid request: %v", err)
			writeJSONError(w, "invalid_request", http.StatusBadRequest)
			return
		}

		dnsRecord.FQDN = dns.CanonicalName(dnsRecord.FQDN)
		if plugin.Zones(a.Zones).Matches(dnsRecord.FQDN) == "" {
			log.Warningf("Auth middleware: Invalid subdomain: %s", dnsRecord.FQDN)
			writeJSONError(w, "invalid_subdomain", http.StatusBadRequest)
			return
		}

		if !isValidTXT(dnsRecord.Value) {
			log.Warningf("Auth middleware: Invalid TXT record: %s", dnsRecord.Value)
			writeJSONError(w, "invalid_txt_record", http.StatusBadRequest)
			return
		}

		ctx := r.Context()

		if a.AuthConfig.RequireAuth {
			// Try to authenticate
			account, err := a.getAccountFromRequestAndSubdomain(r, dnsRecord.FQDN)
			if err != nil {
				log.Warningf("Auth middleware: Authentication failed: %v", err)
				writeJSONError(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if len(account.AllowedIPs) > 0 {
				if !account.AllowedIPs.contains(clientIP) {
					log.Warningf("Auth middleware: IP %s not allowed for account %s", clientIP, account.Username)
					writeJSONError(w, "forbidden_ip", http.StatusForbidden)
					return
				}
			}
			// Set account information in context
			ctx = context.WithValue(ctx, ACMEAccountKey, account)
		}

		ctx = context.WithValue(ctx, ACMERequestKey, dnsRecord)
		next(w, r.WithContext(ctx))
	}
}

// getAccountFromRequestAndSubdomain extracts the account from the request using
// either Basic Auth or X-Api-User and X-Api-Key headers
func (a *ACME) getAccountFromRequestAndSubdomain(r *http.Request, subdomain string) (Account, error) {
	if !a.AuthConfig.RequireAuth {
		return Account{}, ErrAuthDisabled
	}

	var username, password string
	var ok bool

	// Try Basic Auth
	username, password, ok = r.BasicAuth()
	if !ok {
		// Try X-Api headers
		username = r.Header.Get("X-Api-User")
		password = r.Header.Get("X-Api-Key")
	}

	if username == "" || password == "" {
		return Account{}, ErrNoAuthenticationCredentials
	}

	// Get and validate account
	account, err := a.db.GetAccount(username, subdomain)
	if err != nil {
		return Account{}, err
	}

	// Already does constant time comparison
	if bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(password)) != nil {
		return Account{}, ErrInvalidUsernameOrPassword
	}

	return account, nil
}

// getClientIP extracts the client IP from a request
func getClientIP(r *http.Request, headerName string) string {
	// Get the client IP from the header if configured
	if headerName != "" {
		return getIPFromHeader(r.Header.Get(headerName))
	}

	// Extract the client IP from RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Errorf("Failed to extract host from RemoteAddr %s: %v", r.RemoteAddr, err)
		return ""
	}
	return host
}

// getIPFromHeader extracts an IP from a header value
func getIPFromHeader(header string) string {
	if header == "" {
		return ""
	}

	ips := strings.Split(header, ",")

	for _, ip := range ips {
		trimmed := strings.TrimSpace(ip)
		if trimmed != "" {
			return trimmed
		}
	}

	return ""
}
