package acme

import (
	"fmt"
	"path/filepath"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	mwtls "github.com/coredns/coredns/plugin/pkg/tls"
	"github.com/miekg/dns"
	"golang.org/x/crypto/bcrypt"
)

var log = clog.NewWithPlugin("acme")

// init registers this plugin
func init() { plugin.Register("acme", setup) }

// setup sets up the plugin
func setup(c *caddy.Controller) error {
	a, err := parse(c)
	if err != nil {
		return plugin.Error("acme", err)
	}

	c.OnStartup(a.Startup)
	c.OnShutdown(a.Shutdown)

	// Add the plugin to the server
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		a.Next = next
		return a
	})

	return nil
}

// parse parses the plugin configuration
func parse(c *caddy.Controller) (*ACME, error) {
	config := dnsserver.GetConfig(c)

	a := &ACME{
		APIConfig: APIConfig{
			APIAddr:            "",
			EnableRegistration: false,
		},
		AuthConfig: AuthConfig{
			// ExtractIPFromHeader: "X-Forwarded-For",
			AllowedIPs:          CIDRList{}, // No IP restrictions by default
			ExtractIPFromHeader: "",
			RequireAuth:         false,
		},
	}

	accounts := []Account{}
	var dbType string
	var dbPath string

	// Parse the configuration
	for c.Next() {
		a.Zones = plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)
		for c.NextBlock() {
			switch c.Val() {
			case "fallthrough":
				a.Fall.SetZonesFromArgs(c.RemainingArgs())
			case "endpoint":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				a.APIConfig.APIAddr = c.Val()
			case "tls": // cert key cacertfile
				args := c.RemainingArgs()
				if len(args) > 3 {
					return nil, c.ArgErr()
				}

				for i := range args {
					if !filepath.IsAbs(args[i]) && config.Root != "" {
						args[i] = filepath.Join(config.Root, args[i])
					}
				}
				tlsConfig, err := mwtls.NewTLSConfigFromArgs(args...)
				if err != nil {
					return nil, err
				}
				a.TLSConfig = tlsConfig
			case "account":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				username := c.Val()
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				password := c.Val()

				// Initialize zone and allowedIPs
				zone := ""
				allowedIPs := CIDRList{}

				// Process remaining arguments which can be a zone or IP/CIDR blocks
				for c.NextArg() {
					arg := c.Val()

					// Check if it's a valid domain name (potential zone)
					_, ok := dns.IsDomainName(arg)
					if ok && zone == "" {
						zone = dns.CanonicalName(arg)
						continue
					}

					// Check if it's a valid IP or CIDR
					if isValidCIDR(arg) || isValidIP(arg) {
						allowedIPs = append(allowedIPs, arg)
						continue
					}

					return nil, c.Errf("invalid CIDR or DNS Zone: %s", arg)
				}

				accounts = append(accounts, Account{
					Username:   username,
					Password:   password,
					AllowedIPs: allowedIPs,
					Zone:       zone,
				})
			case "enable_registration":
				a.APIConfig.EnableRegistration = true
			case "allowfrom":
				for c.NextArg() {
					cidr := c.Val()
					if !isValidCIDR(cidr) && !isValidIP(cidr) {
						return nil, c.Errf("invalid CIDR: %s", cidr)
					}
					a.AuthConfig.AllowedIPs = append(a.AuthConfig.AllowedIPs, cidr)
				}
			case "db":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				dbType = c.Val()
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				dbPath = c.Val()
			case "extract_ip_from_header":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				a.AuthConfig.ExtractIPFromHeader = c.Val()
			case "require_auth":
				a.AuthConfig.RequireAuth = true
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}

	// Determine if API is enabled (endpoint is specified)
	apiEnabled := a.APIConfig.APIAddr != ""
	if !apiEnabled {
		log.Info("No API endpoint specified, running in DNS-only mode with read-only database")
	}

	// Initialize database with the appropriate read-only mode
	if dbType == "" {
		dbType = "badger"       // Default type
		dbPath = "acme_db_data" // Default path
	}

	var err error
	switch dbType {
	case "sqlite":
		a.db, err = NewSQLiteDBWithROOption(dbPath, !apiEnabled)
	case "badger":
		a.db, err = NewBadgerDBWithROOption(dbPath, !apiEnabled)
	default:
		return nil, fmt.Errorf("unknown database type: %s", dbType)
	}

	if err != nil {
		return nil, err
	}

	// Register any accounts defined in the configuration
	if apiEnabled {
		for _, account := range accounts {
			// Hash the password for storage
			passwordHash, err := bcrypt.GenerateFromPassword([]byte(account.Password), 10)
			if err != nil {
				return nil, fmt.Errorf("failed to hash password for account %s: %v", account.Username, err)
			}

			if err := a.db.RegisterAccount(account, passwordHash); err != nil {
				return nil, fmt.Errorf("failed to register account %s: %v", account.Username, err)
			}

			log.Infof("Registered account from config: username=%s, zone=%s", account.Username, account.Zone)
		}
	}

	return a, nil
}
