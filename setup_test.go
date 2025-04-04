package acme

import (
	"os"
	"strings"
	"testing"

	"github.com/coredns/caddy"
)

func TestSetup(t *testing.T) {
	// Create a temporary directory for the database files
	tmpDir, err := os.MkdirTemp("", "acme-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := tmpDir + "/acme.db"

	tests := []struct {
		name          string
		config        string
		serverBlock   []string
		expectedError bool
		errorContains string
	}{
		{
			name: "Valid minimal config",
			config: `acme {
			}`,
			serverBlock:   []string{"example.org"},
			expectedError: false,
		},
		{
			name: "Valid complete config",
			config: `acme {
				endpoint 0.0.0.0:8080
				db sqlite ` + dbPath + `
				extract_ip_from_header X-Forwarded-For
				allowfrom 10.0.0.0/8 192.168.0.0/16
				account test_user test_pass example.com
				account admin strong_pass example.org 10.0.0.1 192.168.1.0/24
				fallthrough
			}`,
			serverBlock:   []string{"example.org", "example.com"},
			expectedError: false,
		},
		{
			name: "Invalid DB type",
			config: `acme {
				db invalid ` + dbPath + `
			}`,
			serverBlock:   []string{"example.org"},
			expectedError: true,
			errorContains: "unknown database type",
		},
		{
			name: "Missing DB path",
			config: `acme {
				db sqlite
			}`,
			serverBlock:   []string{"example.org"},
			expectedError: true,
			errorContains: "Wrong argument count",
		},
		{
			name: "Unknown property",
			config: `acme {
				unknown property
			}`,
			serverBlock:   []string{"example.org"},
			expectedError: true,
			errorContains: "unknown property",
		},
		{
			name: "Missing account username",
			config: `acme {
				account
			}`,
			serverBlock:   []string{"example.org"},
			expectedError: true,
			errorContains: "Wrong argument count",
		},
		{
			name: "Missing account password",
			config: `acme {
				account user1
			}`,
			serverBlock:   []string{"example.org"},
			expectedError: true,
			errorContains: "Wrong argument count",
		},
		{
			name: "Invalid CIDR in account",
			config: `acme {
				account user1 pass1 example.org not*a*valid*cidr*or*domain
			}`,
			serverBlock:   []string{"example.org"},
			expectedError: true,
			errorContains: "invalid CIDR or DNS Zone",
		},
		{
			name: "Invalid CIDR in allowfrom",
			config: `acme {
				allowfrom invalid/cidr
			}`,
			serverBlock:   []string{"example.org"},
			expectedError: true,
			errorContains: "invalid CIDR",
		},
		{
			name: "Missing extract_ip_from_header value",
			config: `acme {
				extract_ip_from_header
			}`,
			serverBlock:   []string{"example.org"},
			expectedError: true,
			errorContains: "Wrong argument count",
		},
		{
			name: "Missing endpoint value",
			config: `acme {
				endpoint
			}`,
			serverBlock:   []string{"example.org"},
			expectedError: true,
			errorContains: "Wrong argument count",
		},
		{
			name: "Valid with multiple zones in server block",
			config: `acme {
			}`,
			serverBlock:   []string{"example.org", "example.com", "example.net"},
			expectedError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.config)
			c.ServerBlockKeys = tc.serverBlock

			err := setup(c)

			if tc.expectedError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tc.expectedError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tc.errorContains != "" && (err == nil || !strings.Contains(err.Error(), tc.errorContains)) {
				t.Errorf("Expected error containing %q but got: %v", tc.errorContains, err)
			}
		})
	}
}

func TestParse(t *testing.T) {
	// Create a temporary directory for test databases
	tmpDir, err := os.MkdirTemp("", "acme-parse-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := tmpDir + "/acme.db"

	tests := []struct {
		name                    string
		config                  string
		serverBlock             []string
		expectedError           bool
		errorContains           string
		checkZones              bool
		expectedZones           int
		checkAPIAddr            bool
		expectedAPIAddr         string
		checkHeaderName         bool
		expectedHeaderName      string
		checkAllowedIPs         bool
		expectedAllowedIPsCount int
		checkEnableReg          bool
		expectedEnableReg       bool
	}{
		{
			name:          "Parse zones from server block",
			config:        `acme {}`,
			serverBlock:   []string{"example.org", "example.com"},
			expectedError: false,
			checkZones:    true,
			expectedZones: 1,
		},
		{
			name: "Parse DB config",
			config: `acme {
				db sqlite ` + dbPath + `
			}`,
			serverBlock:   []string{"example.org"},
			expectedError: false,
		},
		{
			name: "Parse API address",
			config: `acme {
				endpoint 127.0.0.1:8080
			}`,
			serverBlock:     []string{"example.org"},
			expectedError:   false,
			checkAPIAddr:    true,
			expectedAPIAddr: "127.0.0.1:8080",
		},
		{
			name: "Parse auth config - extract_ip_from_header",
			config: `acme {
				extract_ip_from_header X-Real-IP
			}`,
			serverBlock:        []string{"example.org"},
			expectedError:      false,
			checkHeaderName:    true,
			expectedHeaderName: "X-Real-IP",
		},
		{
			name: "Parse auth config - allowfrom",
			config: `acme {
				allowfrom 192.168.1.1 10.0.0.0/24 172.16.0.5
			}`,
			serverBlock:             []string{"example.org"},
			expectedError:           false,
			checkAllowedIPs:         true,
			expectedAllowedIPsCount: 3,
		},
		{
			name: "Parse enable_registration",
			config: `acme {
				enable_registration
			}`,
			serverBlock:       []string{"example.org"},
			expectedError:     false,
			checkEnableReg:    true,
			expectedEnableReg: true,
		},
		{
			name: "Parse complete configuration",
			config: `acme {
				endpoint 0.0.0.0:8000
				db sqlite ` + dbPath + `
				extract_ip_from_header X-Custom-IP
				allowfrom 10.0.0.0/8 192.168.0.0/16
				account user1 pass1 example.com
				account admin strong_pass example.org 10.0.0.1 192.168.1.0/24
				enable_registration
				fallthrough example.net
			}`,
			serverBlock:             []string{"example.org", "example.com"},
			expectedError:           false,
			checkZones:              true,
			expectedZones:           2,
			checkAPIAddr:            true,
			expectedAPIAddr:         "0.0.0.0:8000",
			checkHeaderName:         true,
			expectedHeaderName:      "X-Custom-IP",
			checkAllowedIPs:         true,
			expectedAllowedIPsCount: 2,
			checkEnableReg:          true,
			expectedEnableReg:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.config)
			c.ServerBlockKeys = tc.serverBlock

			a, err := parse(c)

			// Check error expectations
			if tc.expectedError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tc.expectedError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tc.errorContains != "" && (err == nil || !strings.Contains(err.Error(), tc.errorContains)) {
				t.Errorf("Expected error containing %q but got: %v", tc.errorContains, err)
			}

			// If we expect success, check the parsed values
			if !tc.expectedError && err == nil {
				if tc.checkZones && len(a.Zones) != tc.expectedZones {
					t.Errorf("Expected %d zones, but got: %d", tc.expectedZones, len(a.Zones))
				}

				if tc.checkAPIAddr && a.APIConfig.APIAddr != tc.expectedAPIAddr {
					t.Errorf("Expected API address %s, but got: %s", tc.expectedAPIAddr, a.APIConfig.APIAddr)
				}

				if tc.checkHeaderName && a.AuthConfig.ExtractIPFromHeader != tc.expectedHeaderName {
					t.Errorf("Expected HeaderName %s, but got: %s", tc.expectedHeaderName, a.AuthConfig.ExtractIPFromHeader)
				}

				if tc.checkAllowedIPs && len(a.AuthConfig.AllowedIPs) != tc.expectedAllowedIPsCount {
					t.Errorf("Expected %d allowed IPs, but got: %d", tc.expectedAllowedIPsCount, len(a.AuthConfig.AllowedIPs))
				}

				if tc.checkEnableReg && a.APIConfig.EnableRegistration != tc.expectedEnableReg {
					t.Errorf("Expected EnableRegistration %v, but got: %v", tc.expectedEnableReg, a.APIConfig.EnableRegistration)
				}
			}
		})
	}
}
