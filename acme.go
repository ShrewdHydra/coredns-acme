// Package acme implements a CoreDNS plugin that handles ACME DNS-01 challenges.
// It provides a REST API for updating TXT records needed for ACME DNS-01 validation.
package acme

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// TTL for TXT records - 60 seconds is reasonable for ACME challenges
const defaultTTL = 60

// ACME is a CoreDNS plugin that implements the ACME DNS challenge protocol
type ACME struct {
	Next       plugin.Handler
	Fall       fall.F
	Zones      []string
	apiServer  *http.Server
	ln         net.Listener
	db         DB
	AuthConfig AuthConfig
	APIConfig  APIConfig
	TLSConfig  *tls.Config
}

// APIConfig holds API server configuration
type APIConfig struct {
	// APIAddr is the address of the API server
	APIAddr string
	// EnableRegistration is a flag to enable registration
	EnableRegistration bool
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	// AllowedIPs is a list of IP addresses or CIDR blocks that are allowed to update records
	AllowedIPs CIDRList
	// ExtractIPFromHeader is the name of the header to use for client IP
	ExtractIPFromHeader string
	// RequireAuth determines if authentication is required for API record updates
	RequireAuth bool
}

// Name implements the plugin.Handler interface
func (a *ACME) Name() string { return "acme" }

// ServeDNS implements the plugin.Handler interface.
func (a *ACME) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.Name()
	queryType := dns.TypeToString[r.Question[0].Qtype]
	log.Debugf("Handling ACME challenge %s query for %s", queryType, qname)

	// Check if the query is for a zone we're authoritative for
	zone := plugin.Zones(a.Zones).Matches(qname)
	if zone == "" {
		log.Debugf("No zone matches for %s, falling through", qname)
		return plugin.NextOrFailure(a.Name(), a.Next, ctx, w, r)
	}

	// Check if it's an ACME challenge subdomain (_acme-challenge.<domain>)
	if !strings.HasPrefix(qname, "_acme-challenge.") {
		log.Debug("Not an ACME challenge subdomain, falling through")
		return plugin.NextOrFailure(a.Name(), a.Next, ctx, w, r)
	}

	// Increment the request counter
	RequestCount.WithLabelValues(metrics.WithServer(ctx), queryType).Inc()

	// Create the response
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Retrieve the record from the database
	records, err := a.db.GetRecords(qname)
	if err != nil {
		if err == ErrRecordNotFound {
			// Fall through to next plugin if no record found and fallthrough is enabled for this zone
			if a.Fall.Through(qname) {
				log.Debugf("No record found for %s, falling through to next plugin", qname)
				return plugin.NextOrFailure(a.Name(), a.Next, ctx, w, r)
			}
			log.Debugf("No record found for %s and no fallthrough, returning NXDOMAIN", qname)
			return dns.RcodeNameError, nil
		}
		log.Errorf("Error retrieving record for %s: %v", qname, err)
		return dns.RcodeServerFailure, err
	}

	// Check if it's a TXT record query
	if queryType != "TXT" && queryType != "ANY" {
		log.Debug("Not a TXT or ANY query. Responding with empty NOERROR.")
		// Empty answer section to signal that the name exists, but no records of this type
		state.W.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	// Create TXT record responses
	for _, record := range records {
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: defaultTTL},
			Txt: []string{record},
		})
	}
	log.Debugf("Serving TXT records for %s: %v", qname, m.Answer)

	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

// startAPIServer starts the HTTP API server
func (a *ACME) Startup() error {
	// If no API address is specified, skip starting the API server
	if a.APIConfig.APIAddr == "" {
		log.Debug("No API endpoint specified, skipping API server startup")
		return nil
	}

	log.Infof("Starting ACME API server on %s", a.APIConfig.APIAddr)
	ln, err := reuseport.Listen("tcp", a.APIConfig.APIAddr)
	if err != nil {
		log.Errorf("Failed to start API server: %s", err)
		return err
	}
	a.ln = ln

	mux := http.NewServeMux()
	if a.APIConfig.EnableRegistration {
		mux.HandleFunc("POST /register", a.handleRegister)
	}
	mux.HandleFunc("POST /present", a.Auth(a.handlePresent))
	mux.HandleFunc("POST /cleanup", a.Auth(a.handleCleanup))
	mux.HandleFunc("GET /health", a.handleHealth)

	a.apiServer = &http.Server{
		Addr:      a.APIConfig.APIAddr,
		Handler:   mux,
		TLSConfig: a.TLSConfig,
	}

	go func() {
		if err := a.apiServer.Serve(a.ln); err != nil {
			log.Errorf("Failed to start API server: %s", err)
		}
	}()
	return nil
}

func (a *ACME) Shutdown() error {
	var err error
	if a.apiServer != nil {
		err = a.apiServer.Shutdown(context.Background())
	}
	if a.ln != nil {
		err = a.ln.Close()
	}
	if a.db != nil {
		err = a.db.Close()
	}
	return err
}
