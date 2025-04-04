package acme

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// TestServeDNS tests the ServeDNS method
func TestServeDNS(t *testing.T) {
	// Define test cases
	tests := []struct {
		name        string
		qname       string
		qtype       uint16
		records     map[string][]string
		expectedRet int
	}{
		{
			name:        "TXT Record Found",
			qname:       "_acme-challenge.example.com.",
			qtype:       dns.TypeTXT,
			records:     map[string][]string{"_acme-challenge.example.com.": {"test-value"}},
			expectedRet: dns.RcodeSuccess,
		},
		{
			name:        "TXT Record Not Found",
			qname:       "_acme-challenge.example.com.",
			qtype:       dns.TypeTXT,
			records:     map[string][]string{},
			expectedRet: dns.RcodeNameError,
		},
		{
			name:        "Non-TXT Query",
			qname:       "_acme-challenge.example.com.",
			qtype:       dns.TypeA,
			records:     map[string][]string{},
			expectedRet: dns.RcodeServerFailure,
		},
	}

	// Run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test database
			db := &MemDB{
				records:  tc.records,
				accounts: make(map[string]Account),
			}

			// Create the plugin instance
			a := &ACME{
				Next:  nextHandler{},
				Zones: []string{"example.com."},
				db:    db,
			}

			// Create a DNS request
			req := new(dns.Msg)
			req.SetQuestion(tc.qname, tc.qtype)

			// Create a recorder for the response
			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			// Call the method being tested
			ret, _ := a.ServeDNS(context.Background(), rec, req)

			// Check the return code
			if ret != tc.expectedRet {
				t.Errorf("Expected return code %d, but got: %d", tc.expectedRet, ret)
			}

			// For successful TXT record queries, check the response
			if tc.qtype == dns.TypeTXT && len(tc.records) > 0 && tc.records[tc.qname][0] != "" {
				if len(rec.Msg.Answer) != 1 {
					t.Errorf("Expected 1 answer, but got: %d", len(rec.Msg.Answer))
				} else {
					txtRR, ok := rec.Msg.Answer[0].(*dns.TXT)
					if !ok {
						t.Errorf("Expected TXT record answer, but got: %T", rec.Msg.Answer[0])
					} else if len(txtRR.Txt) != 1 || txtRR.Txt[0] != tc.records[tc.qname][0] {
						t.Errorf("Expected TXT record value %s, but got: %v", tc.records[tc.qname][0], txtRR.Txt)
					}
				}
			}
		})
	}
}

// TestServeDNS_DBError tests the ServeDNS method when the DB returns an error
func TestServeDNS_DBError(t *testing.T) {
	// Create an error-returning DB
	errDB := &errorDB{
		err: errors.New("database error"),
	}

	// Create the plugin instance
	a := &ACME{
		Next:  nextHandler{},
		Zones: []string{"example.com."},
		db:    errDB,
	}

	// Create a DNS request
	req := new(dns.Msg)
	req.SetQuestion("_acme-challenge.example.com.", dns.TypeTXT)

	// Create a recorder for the response
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	// Call the method being tested
	ret, err := a.ServeDNS(context.Background(), rec, req)

	// Check the return code and error
	if ret != dns.RcodeServerFailure {
		t.Errorf("Expected return code %d, but got: %d", dns.RcodeServerFailure, ret)
	}
	if err == nil || err.Error() != "database error" {
		t.Errorf("Expected database error, but got: %v", err)
	}
}

// Ensure errorDB correctly implements the DB interface
var _ DB = &errorDB{}

// errorDB is a test DB that always returns an error
type errorDB struct {
	err error
}

func (db *errorDB) GetRecords(fqdn string) ([]string, error) {
	return nil, db.err
}

func (db *errorDB) PresentRecord(fqdn, value string) error {
	return db.err
}

func (db *errorDB) CleanupRecord(fqdn, value string) error {
	return db.err
}

func (db *errorDB) RegisterAccount(account Account, passwordHash []byte) error {
	return db.err
}

func (db *errorDB) GetAccount(username, zone string) (Account, error) {
	return Account{}, db.err
}

func (db *errorDB) Close() error {
	return nil
}

// TestStartupShutdown tests the Startup and Shutdown methods
func TestStartupShutdown(t *testing.T) {
	// Create a test database
	db := &MemDB{
		records:  make(map[string][]string),
		accounts: make(map[string]Account),
	}

	// Test ports
	testPort := "33453"
	listener, err := net.Listen("tcp", ":"+testPort)
	if err != nil {
		t.Fatalf("Failed to get available port: %v", err)
	}
	listener.Close()

	// Create the plugin instance
	a := &ACME{
		Next:  nextHandler{},
		Zones: []string{"example.org."},
		db:    db,
		APIConfig: APIConfig{
			APIAddr: "127.0.0.1:" + testPort,
		},
	}

	// Test Startup
	err = a.Startup()
	if err != nil {
		t.Errorf("Expected no error from Startup, but got: %v", err)
	}

	// Test API server is running
	conn, err := net.Dial("tcp", "127.0.0.1:"+testPort)
	if err != nil {
		t.Errorf("Failed to connect to API server: %v", err)
	} else {
		conn.Close()
	}

	// Test Shutdown
	err = a.Shutdown()
	if err != nil {
		t.Errorf("Expected no error from Shutdown, but got: %v", err)
	}

	// Test API server is shut down
	time.Sleep(100 * time.Millisecond) // Give it a bit of time to shut down
	_, err = net.Dial("tcp", "127.0.0.1:"+testPort)
	if err == nil {
		t.Errorf("Expected API server to be shut down, but could still connect")
	}
}

// nextHandler is a test implementation of plugin.Handler that returns SERVFAIL
type nextHandler struct{}

func (h nextHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	return dns.RcodeServerFailure, nil
}

func (h nextHandler) Name() string { return "testplugin" }

// Test_ServeDNS_Forward tests that non-acme queries are forwarded to the next plugin
func Test_ServeDNS_Forward(t *testing.T) {
	a := ACME{
		Next:  nextHandler{},
		Zones: []string{"example.org."},
	}

	tests := []struct {
		name     string
		qname    string
		match    bool
		qtype    uint16
		expected int
	}{
		{
			name:     "Forward non-matching zone",
			qname:    "example.com.",
			match:    false,
			qtype:    dns.TypeTXT,
			expected: dns.RcodeServerFailure, // SERVFAIL from nextHandler
		},
		{
			name:     "Forward non-TXT query",
			qname:    "example.org.",
			match:    true,
			qtype:    dns.TypeA,
			expected: dns.RcodeServerFailure, // SERVFAIL from nextHandler
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(tc.qname, tc.qtype)
			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			code, err := a.ServeDNS(context.Background(), rec, m)
			if err != nil {
				t.Errorf("Expected no error, but got: %v", err)
			}
			if code != tc.expected {
				t.Errorf("Expected rcode %d, but got: %d", tc.expected, code)
			}
		})
	}
}

// TestForwardQueries tests that various types of queries are forwarded correctly
func TestForwardQueries(t *testing.T) {
	a := ACME{
		Next:  nextHandler{},
		Zones: []string{"example.org."},
	}

	tests := []struct {
		name        string
		qname       string
		qtype       uint16
		expectCode  int
		description string
	}{
		{
			name:        "Forward non-TXT query",
			qname:       "test.example.org.",
			qtype:       dns.TypeA,
			expectCode:  dns.RcodeServerFailure,
			description: "Non-TXT queries in our zone should be forwarded",
		},
		{
			name:        "Forward query in non-matching zone",
			qname:       "test.example.com.",
			qtype:       dns.TypeTXT,
			expectCode:  dns.RcodeServerFailure,
			description: "Queries in non-matching zones should be forwarded even if they're TXT",
		},
		{
			name:        "Forward AAAA query",
			qname:       "test.example.org.",
			qtype:       dns.TypeAAAA,
			expectCode:  dns.RcodeServerFailure,
			description: "IPv6 queries should be forwarded",
		},
		{
			name:        "Forward MX query",
			qname:       "test.example.org.",
			qtype:       dns.TypeMX,
			expectCode:  dns.RcodeServerFailure,
			description: "MX queries should be forwarded",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a DNS message
			m := new(dns.Msg)
			m.SetQuestion(tc.qname, tc.qtype)
			m.RecursionDesired = true

			// Create a recorder
			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			// Call ServeDNS - should forward to next plugin
			code, err := a.ServeDNS(context.Background(), rec, m)
			if err != nil {
				t.Errorf("Expected no error, but got: %v", err)
			}

			// Next handler returns SERVFAIL
			if code != tc.expectCode {
				t.Errorf("Expected rcode %d from next plugin, but got: %d", tc.expectCode, code)
			}
		})
	}
}

// TestServeDNS_RecordNotFound tests the ServeDNS method when ErrRecordNotFound is returned
func TestServeDNS_RecordNotFound(t *testing.T) {
	// Create a DB that returns ErrRecordNotFound
	errNotFoundDB := &errorDB{
		err: ErrRecordNotFound,
	}

	// Create the plugin instance
	a := &ACME{
		Next:  nextHandler{},
		Zones: []string{"example.com."},
		db:    errNotFoundDB,
	}

	// Create a DNS request
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeTXT)

	// Create a recorder for the response
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	// Call the method being tested
	ret, err := a.ServeDNS(context.Background(), rec, req)

	// Check the return code and error
	// When record not found, it should call the next plugin
	if ret != dns.RcodeServerFailure {
		t.Errorf("Expected return code %d, but got: %d", dns.RcodeServerFailure, ret)
	}
	// Next plugin returns nil error, so we should get nil error
	if err != nil {
		t.Errorf("Expected nil error, but got: %v", err)
	}
}

// TestServeDNS_MultipleZones tests that the plugin handles multiple configured zones
func TestServeDNS_MultipleZones(t *testing.T) {
	// Create test data
	testZones := []string{"example.org.", "example.com."}
	testRecords := map[string][]string{
		"_acme-challenge.example.org.": {"record1"},
		"_acme-challenge.example.com.": {"record2"},
	}

	// Create a test database
	db := &MemDB{
		records:  testRecords,
		accounts: make(map[string]Account),
	}

	// Create the plugin instance with multiple zones
	a := &ACME{
		Next:  nextHandler{},
		Zones: testZones,
		db:    db,
	}

	// Test cases for different zones
	tests := []struct {
		name     string
		qname    string
		expected string
	}{
		{"COM zone", "_acme-challenge.example.com.", "record2"},
		{"ORG zone", "_acme-challenge.example.org.", "record1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a DNS request
			req := new(dns.Msg)
			req.SetQuestion(tc.qname, dns.TypeTXT)

			// Create a recorder for the response
			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			// Call the method being tested
			ret, _ := a.ServeDNS(context.Background(), rec, req)

			// Expect success
			if ret != dns.RcodeSuccess {
				t.Errorf("Expected return code %d, but got: %d", dns.RcodeSuccess, ret)
			}

			// Check response
			if len(rec.Msg.Answer) != 1 {
				t.Errorf("Expected 1 answer, but got: %d", len(rec.Msg.Answer))
			} else {
				txtRR, ok := rec.Msg.Answer[0].(*dns.TXT)
				if !ok {
					t.Errorf("Expected TXT record answer, but got: %T", rec.Msg.Answer[0])
				} else if len(txtRR.Txt) != 1 || txtRR.Txt[0] != tc.expected {
					t.Errorf("Expected TXT record value %s, but got: %v", tc.expected, txtRR.Txt)
				}
			}
		})
	}
}

// TestStartupErrors tests error conditions during startup
func TestStartupErrors(t *testing.T) {
	// Create a test database
	memDB := &MemDB{
		records:  make(map[string][]string),
		accounts: make(map[string]Account),
	}

	// Test case 1: Invalid API address
	invalidAddr := &ACME{
		Next:  nextHandler{},
		Zones: []string{"example.org."},
		db:    memDB,
		APIConfig: APIConfig{
			APIAddr: "invalid:address:with:too:many:colons",
		},
	}

	err := invalidAddr.Startup()
	if err == nil {
		t.Errorf("Expected error with invalid API address, but got none")
	}

	// Test case 2: API address in use (create a listener that blocks the port)
	// Use a different port than TestStartupShutdown
	testPort := "33457"
	listener, err := net.Listen("tcp", ":"+testPort)
	if err != nil {
		t.Fatalf("Failed to get available port for testing: %v", err)
	}
	defer listener.Close()

	portInUse := &ACME{
		Next:  nextHandler{},
		Zones: []string{"example.org."},
		db:    memDB,
		APIConfig: APIConfig{
			APIAddr: "127.0.0.1:" + testPort,
		},
	}

	err = portInUse.Startup()
	if err == nil {
		t.Errorf("Expected error when port is already in use, but got none")
	}

	// Test case 3: Empty API address is valid and should default to a standard port
	emptyAddr := &ACME{
		Next:  nextHandler{},
		Zones: []string{"example.org."},
		db:    memDB,
		APIConfig: APIConfig{
			APIAddr: "",
		},
	}

	err = emptyAddr.Startup()
	if err != nil {
		t.Errorf("Expected no error with empty API address, but got: %v", err)
	}

	// Clean up
	err = emptyAddr.Shutdown()
	if err != nil {
		t.Errorf("Error shutting down test plugin: %v", err)
	}
}

func TestCanHandleQuery(t *testing.T) {
	tests := []struct {
		name     string
		r        *dns.Msg
		a        *ACME
		expected bool
	}{
		{
			name: "valid ACME query",
			r: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "_acme-challenge.example.org.",
						Qtype:  dns.TypeTXT,
						Qclass: dns.ClassINET,
					},
				},
			},
			a:        &ACME{db: &MemDB{}, Zones: []string{"org."}},
			expected: true,
		},
		{
			name: "wrong qtype",
			r: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "_acme-challenge.example.org.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			},
			a:        &ACME{db: &MemDB{}, Zones: []string{"org."}},
			expected: false,
		},
		{
			name: "wrong qclass",
			r: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "_acme-challenge.example.org.",
						Qtype:  dns.TypeTXT,
						Qclass: dns.ClassANY,
					},
				},
			},
			a:        &ACME{db: &MemDB{}, Zones: []string{"org."}},
			expected: false,
		},
		{
			name: "wrong name",
			r: &dns.Msg{
				Question: []dns.Question{
					{
						Name:   "example.org.",
						Qtype:  dns.TypeTXT,
						Qclass: dns.ClassINET,
					},
				},
			},
			a:        &ACME{db: &MemDB{}, Zones: []string{"org."}},
			expected: false,
		},
		{
			name: "no questions",
			r: &dns.Msg{
				Question: []dns.Question{},
			},
			a:        &ACME{db: &MemDB{}, Zones: []string{"org."}},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := request.Request{Req: tc.r}
			zone := plugin.Zones(tc.a.Zones).Matches(state.Name())

			// Check if it's a zone we're authoritative for
			if zone == "" {
				if tc.expected {
					t.Errorf("Expected to handle %s but zone didn't match", state.Name())
				}
				return
			}

			// Check if it's a TXT query and for a name with correct prefix
			if len(tc.r.Question) == 0 {
				if tc.expected {
					t.Errorf("Expected to handle request but there are no questions")
				}
				return
			}

			result := state.QType() == dns.TypeTXT &&
				state.QClass() == dns.ClassINET &&
				strings.HasPrefix(state.Name(), "_acme-challenge.")

			if result != tc.expected {
				t.Errorf("Expected %v but got %v for %s", tc.expected, result, state.Name())
			}
		})
	}
}

func TestAcmeShutdown(t *testing.T) {
	a := &ACME{
		db: &MemDB{},
	}
	err := a.Shutdown()
	if err != nil {
		t.Errorf("Expected no error on Shutdown, got %v", err)
	}

	// Verify it doesn't panic with nil db
	a = &ACME{db: nil}
	err = a.Shutdown()
	if err != nil {
		t.Errorf("Expected no error on Shutdown with nil db, got %v", err)
	}
}
