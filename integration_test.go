package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

func TestIntegrationWorkflow(t *testing.T) {
	// Create a temporary database
	dbFile := t.TempDir() + "/integration_test.db"
	database, err := NewSQLiteDB(dbFile)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer func() {
		database.Close()
		os.Remove(dbFile)
	}()

	// Create a test next handler
	next := plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		return dns.RcodeServerFailure, nil
	})

	// Create an ACME plugin instance
	a := &ACME{
		Next:  next,
		db:    database,
		Zones: []string{"example.org."},
		AuthConfig: AuthConfig{
			AllowedIPs:  []string{"127.0.0.1", "::1", "192.168.1.1/24"},
			RequireAuth: true,
		},
	}

	// Step 1: Register a new account
	registerBody := `{"username":"test_user", "password":"test_pass", "zone":"example.org", "allowfrom":["192.168.1.1/24"]}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(registerBody))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	a.handleRegister(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Expected status code %d, got %d", http.StatusCreated, rec.Code)
	}

	var registerResp map[string]string
	err = json.NewDecoder(rec.Body).Decode(&registerResp)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if registerResp["message"] != "Account registered successfully" {
		t.Fatalf("Invalid register response: %+v", registerResp)
	}

	// Step 2: Update a DNS record
	txt_A := strings.Repeat("A", 43)
	fqdn := "_acme-challenge.test_subdomain.example.org."
	updateBody := `{"fqdn":"` + fqdn + `","value":"` + txt_A + `"}`
	req = httptest.NewRequest(http.MethodPost, "/present", strings.NewReader(updateBody))
	req.RemoteAddr = "192.168.1.100:12345" // Within allowed CIDR
	req.SetBasicAuth("test_user", "test_pass")
	rec = httptest.NewRecorder()

	// Get the account and add it to the context
	account, err := a.getAccountFromRequestAndSubdomain(req, fqdn)
	if err != nil {
		t.Fatalf("Failed to get account from request: %v", err)
	}

	// Parse the update request to create the ACMETxt
	var dnsRecord ACMETxt
	err = json.NewDecoder(strings.NewReader(updateBody)).Decode(&dnsRecord)
	if err != nil {
		t.Fatalf("Failed to decode update request: %v", err)
	}

	ctx := context.WithValue(req.Context(), ACMEAccountKey, account)
	ctx = context.WithValue(ctx, ACMERequestKey, dnsRecord)
	req = req.WithContext(ctx)

	a.handlePresent(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status code %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	// Step 3: Query the DNS record
	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeTXT)

	w := &testResponseWriter{}

	_, err = a.ServeDNS(context.Background(), w, m)
	if err != nil {
		t.Fatalf("ServeDNS failed: %v", err)
	}

	// Check if response was generated
	if w.msg == nil {
		// This is also successful - no response means no records found
	} else if len(w.msg.Answer) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(w.msg.Answer))
	}

	// Verify TXT record
	txtRecord, ok := w.msg.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("Expected TXT record, got %T", w.msg.Answer[0])
	}

	if txtRecord.Txt[0] != txt_A {
		t.Fatalf("Unexpected TXT value: %v, expected %v", txtRecord.Txt, txt_A)
	}

	// Step 4: Update the TXT record with a different value and query it again
	txt_B := strings.Repeat("B", 43)
	updateBody = `{"fqdn":"` + fqdn + `","value":"` + txt_B + `"}`
	req = httptest.NewRequest(http.MethodPost, "/present", strings.NewReader(updateBody))
	req.RemoteAddr = "192.168.1.100:12345"
	req.SetBasicAuth("test_user", "test_pass")
	rec = httptest.NewRecorder()

	// Parse the update request
	err = json.NewDecoder(strings.NewReader(updateBody)).Decode(&dnsRecord)
	if err != nil {
		t.Fatalf("Failed to decode update request: %v", err)
	}

	ctx = context.WithValue(req.Context(), ACMEAccountKey, account)
	ctx = context.WithValue(ctx, ACMERequestKey, dnsRecord)
	req = req.WithContext(ctx)

	a.handlePresent(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status code %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	// Query again
	m = new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeTXT)
	w = &testResponseWriter{}

	_, err = a.ServeDNS(context.Background(), w, m)
	if err != nil {
		t.Fatalf("ServeDNS failed: %v", err)
	}

	if len(w.msg.Answer) != 2 {
		t.Fatalf("Expected 2 answers, got %d", len(w.msg.Answer))
	}

	txtRecord, ok = w.msg.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("Expected TXT record, got %T", w.msg.Answer[0])
	}

	if txtRecord.Txt[0] != txt_B {
		t.Fatalf("Unexpected TXT value: %v, expected %v", txtRecord.Txt, txt_B)
	}

	// Step 5: Test authentication failures
	// Incorrect password
	req = httptest.NewRequest(http.MethodPost, "/present", strings.NewReader(updateBody))
	req.RemoteAddr = "192.168.1.100:12345"
	req.SetBasicAuth("test_user", "wrong-password")
	rec = httptest.NewRecorder()

	// Try authentication manually to check it fails
	_, err = a.getAccountFromRequestAndSubdomain(req, fqdn)
	if err == nil {
		t.Fatalf("Expected authentication to fail with wrong password")
	}

	// Test with Auth middleware
	a.Auth(a.handlePresent)(rec, req)
	fmt.Println("rec: ", rec.Body.String())
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected status code %d or %d, got %d", http.StatusUnauthorized, http.StatusBadRequest, rec.Code)
	}

	// Step 6: Test IP restriction
	req = httptest.NewRequest(http.MethodPost, "/present", strings.NewReader(updateBody))
	req.RemoteAddr = "10.0.0.1:12345" // Outside allowed CIDR
	req.SetBasicAuth("test_user", "test_pass")
	rec = httptest.NewRecorder()

	// Test with Auth middleware
	a.Auth(a.handlePresent)(rec, req)
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden && rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected status code %d, %d or %d, got %d", http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest, rec.Code)
	}

	// Step 7: Test cleanup
	// First clean up the B record
	cleanupBody := `{"fqdn":"` + fqdn + `","value":"` + txt_B + `"}`
	req = httptest.NewRequest(http.MethodPost, "/cleanup", strings.NewReader(cleanupBody))
	req.RemoteAddr = "192.168.1.100:12345"
	req.SetBasicAuth("test_user", "test_pass")
	rec = httptest.NewRecorder()

	// Parse the cleanup request
	err = json.NewDecoder(strings.NewReader(cleanupBody)).Decode(&dnsRecord)
	if err != nil {
		t.Fatalf("Failed to decode cleanup request: %v", err)
	}

	ctx = context.WithValue(req.Context(), ACMEAccountKey, account)
	ctx = context.WithValue(ctx, ACMERequestKey, dnsRecord)
	req = req.WithContext(ctx)

	a.handleCleanup(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status code %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	// Then clean up the A record
	cleanupBody = `{"fqdn":"` + fqdn + `","value":"` + txt_A + `"}`
	req = httptest.NewRequest(http.MethodPost, "/cleanup", strings.NewReader(cleanupBody))
	req.RemoteAddr = "192.168.1.100:12345"
	req.SetBasicAuth("test_user", "test_pass")
	rec = httptest.NewRecorder()

	// Parse the cleanup request
	err = json.NewDecoder(strings.NewReader(cleanupBody)).Decode(&dnsRecord)
	if err != nil {
		t.Fatalf("Failed to decode cleanup request: %v", err)
	}

	ctx = context.WithValue(req.Context(), ACMEAccountKey, account)
	ctx = context.WithValue(ctx, ACMERequestKey, dnsRecord)
	req = req.WithContext(ctx)

	a.handleCleanup(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status code %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	// Query again to verify record is gone
	m = new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeTXT)
	w = &testResponseWriter{}

	_, err = a.ServeDNS(context.Background(), w, m)
	if err != nil {
		t.Fatalf("ServeDNS failed: %v", err)
	}

	// Check if response was generated
	if w.msg == nil {
		// This is also successful - no response means no records found
	} else if len(w.msg.Answer) != 0 {
		t.Fatalf("Expected 0 answers after cleanup, got %d", len(w.msg.Answer))
	}

	// Step 8: Test health endpoint
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	rec = httptest.NewRecorder()

	a.handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status code %d, got %d", http.StatusOK, rec.Code)
	}

	if rec.Body.String() != "OK" {
		t.Fatalf("Expected health status 'OK', got '%s'", rec.Body.String())
	}
}

// testResponseWriter is a simple implementation of dns.ResponseWriter for testing
type testResponseWriter struct {
	msg *dns.Msg
}

func (w *testResponseWriter) WriteMsg(m *dns.Msg) error {
	w.msg = m
	return nil
}

func (w *testResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (w *testResponseWriter) LocalAddr() net.Addr {
	return nil
}

func (w *testResponseWriter) RemoteAddr() net.Addr {
	return nil
}

func (w *testResponseWriter) TsigStatus() error {
	return nil
}

func (w *testResponseWriter) TsigTimersOnly(bool) {
}

func (w *testResponseWriter) Hijack() {
}

func (w *testResponseWriter) Close() error {
	return nil
}
