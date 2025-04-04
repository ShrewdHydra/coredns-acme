package acme

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestAuth(t *testing.T) {
	// Create a test account
	testAccount := Account{
		Username:   "test_user",
		Password:   "test_pass",
		Zone:       "test_subdomain.example.org.",
		AllowedIPs: []string{"192.168.1.100", "10.0.0.0/24"},
	}

	// Hash the password as it would be stored in the database
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("test_pass"), 10)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	testAccount.Password = string(hashedPassword)

	// Create a test DB
	memDB := &MemDB{
		records: make(map[string][]string),
		accounts: map[string]Account{
			"test_user:test_subdomain.example.org.": testAccount,
		},
	}

	// Create the plugin instance
	a := ACME{
		Zones: []string{"example.org."},
		db:    memDB,
		AuthConfig: AuthConfig{
			ExtractIPFromHeader: "X-Forwarded-For",
			RequireAuth:         true,
		},
	}

	// Create a handler for testing
	handlerCalled := false
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		// Verify the account is in the context
		acc, ok := r.Context().Value(ACMEAccountKey).(Account)
		if !ok {
			t.Error("Expected account in context, but none found")
			return
		}
		if acc.Username != testAccount.Username {
			t.Errorf("Expected username %s in context, but got %s", testAccount.Username, acc.Username)
		}
		// Verify the DNS record is in the context
		_, ok = r.Context().Value(ACMERequestKey).(ACMETxt)
		if !ok {
			t.Error("Expected DNS record in context, but none found")
			return
		}
		w.WriteHeader(http.StatusOK)
	}

	// Valid TXT record
	validTXTRecord := "abcdefghijklmnopqrstuvwxyz0123456789-_=ABCD"

	// Test cases
	tests := []struct {
		name           string
		method         string
		auth           string // Basic auth header value
		xApiUser       string
		xApiKey        string
		xForwardedFor  string
		body           string
		expectedStatus int
		shouldCallNext bool
		expectedError  string // Check JSON error response
	}{
		{
			name:           "Valid Basic Auth and IP",
			method:         http.MethodPost,
			auth:           "Basic " + basicAuth("test_user", "test_pass"),
			xForwardedFor:  "192.168.1.100",
			body:           `{"fqdn": "test_subdomain.example.org.", "value": "` + validTXTRecord + `"}`,
			expectedStatus: http.StatusOK,
			shouldCallNext: true,
		},
		{
			name:           "Valid API headers and IP",
			method:         http.MethodPost,
			xApiUser:       "test_user",
			xApiKey:        "test_pass",
			xForwardedFor:  "192.168.1.100",
			body:           `{"fqdn": "test_subdomain.example.org.", "value": "` + validTXTRecord + `"}`,
			expectedStatus: http.StatusOK,
			shouldCallNext: true,
		},
		{
			name:           "Valid credentials but IP not in allowed list",
			method:         http.MethodPost,
			auth:           "Basic " + basicAuth("test_user", "test_pass"),
			xForwardedFor:  "172.16.0.1",
			body:           `{"fqdn": "test_subdomain.example.org.", "value": "` + validTXTRecord + `"}`,
			expectedStatus: http.StatusForbidden,
			shouldCallNext: false,
			expectedError:  "forbidden_ip",
		},
		{
			name:           "Invalid credentials",
			method:         http.MethodPost,
			auth:           "Basic " + basicAuth("wrong_user", "wrong_pass"),
			xForwardedFor:  "192.168.1.100",
			body:           `{"fqdn": "test_subdomain.example.org.", "value": "` + validTXTRecord + `"}`,
			expectedStatus: http.StatusUnauthorized,
			shouldCallNext: false,
			expectedError:  "unauthorized",
		},
		{
			name:           "No credentials",
			method:         http.MethodPost,
			xForwardedFor:  "192.168.1.100",
			body:           `{"fqdn": "test_subdomain.example.org.", "value": "` + validTXTRecord + `"}`,
			expectedStatus: http.StatusUnauthorized,
			shouldCallNext: false,
			expectedError:  "unauthorized",
		},
		{
			name:           "Invalid TXT length",
			method:         http.MethodPost,
			auth:           "Basic " + basicAuth("test_user", "test_pass"),
			xForwardedFor:  "192.168.1.100",
			body:           `{"fqdn": "test_subdomain.example.org.", "value": "too_short"}`,
			expectedStatus: http.StatusBadRequest,
			shouldCallNext: false,
			expectedError:  "invalid_txt_record",
		},
		{
			name:           "Invalid domain",
			method:         http.MethodPost,
			auth:           "Basic " + basicAuth("test_user", "test_pass"),
			xForwardedFor:  "192.168.1.100",
			body:           `{"fqdn": "wrong_subdomain.example.org.", "value": "` + validTXTRecord + `"}`,
			expectedStatus: http.StatusUnauthorized,
			shouldCallNext: false,
			expectedError:  "unauthorized",
		},
		{
			name:           "Method not allowed",
			method:         http.MethodGet,
			auth:           "Basic " + basicAuth("test_user", "test_pass"),
			xForwardedFor:  "192.168.1.100",
			body:           `{"fqdn": "test_subdomain.example.org.", "value": "` + validTXTRecord + `"}`,
			expectedStatus: http.StatusOK, // Method is checked by router, not middleware
			shouldCallNext: true,
		},
		{
			name:           "IP in CIDR range",
			method:         http.MethodPost,
			auth:           "Basic " + basicAuth("test_user", "test_pass"),
			xForwardedFor:  "10.0.0.123",
			body:           `{"fqdn": "test_subdomain.example.org.", "value": "` + validTXTRecord + `"}`,
			expectedStatus: http.StatusOK,
			shouldCallNext: true,
		},
		{
			name:           "Invalid JSON body",
			method:         http.MethodPost,
			auth:           "Basic " + basicAuth("test_user", "test_pass"),
			xForwardedFor:  "192.168.1.100",
			body:           `{invalid_json`,
			expectedStatus: http.StatusBadRequest,
			shouldCallNext: false,
			expectedError:  "invalid_request",
		},
		{
			name:           "Empty request body",
			method:         http.MethodPost,
			auth:           "Basic " + basicAuth("test_user", "test_pass"),
			xForwardedFor:  "192.168.1.100",
			body:           ``,
			expectedStatus: http.StatusBadRequest,
			shouldCallNext: false,
			expectedError:  "no_request_body",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset the handler called flag
			handlerCalled = false

			// Create a request with the specified body
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			req := httptest.NewRequest(tc.method, "/update", body)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			if tc.xApiUser != "" {
				req.Header.Set("X-Api-User", tc.xApiUser)
			}
			if tc.xApiKey != "" {
				req.Header.Set("X-Api-Key", tc.xApiKey)
			}
			if tc.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tc.xForwardedFor)
			}
			req.Header.Set("Content-Type", "application/json")

			// Create a response recorder
			res := httptest.NewRecorder()

			// Apply the middleware
			handler := a.Auth(testHandler)
			handler(res, req)

			// Check the status code
			if res.Code != tc.expectedStatus {
				t.Errorf("Expected status code %d, but got: %d", tc.expectedStatus, res.Code)
			}

			// Check if the handler was called
			if handlerCalled != tc.shouldCallNext {
				t.Errorf("Expected handlerCalled=%v, but got: %v", tc.shouldCallNext, handlerCalled)
			}

			// Check the error response if specified
			if tc.expectedError != "" && !handlerCalled {
				var errResp map[string]string
				if err := json.NewDecoder(res.Body).Decode(&errResp); err != nil {
					t.Errorf("Failed to decode error response: %v", err)
				} else if errResp["error"] != tc.expectedError {
					t.Errorf("Expected error %q, but got: %q", tc.expectedError, errResp["error"])
				}
			}
		})
	}
}

func TestGetAccountFromRequestAndSubdomain(t *testing.T) {
	// Create a test account
	testAccount := Account{
		Username:   "test_user",
		Zone:       "test_subdomain.example.org.",
		AllowedIPs: []string{"192.168.1.100", "10.0.0.0/24"},
	}

	// Hash the password as it would be stored in the database
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("test_pass"), 10)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	testAccount.Password = string(hashedPassword)

	// Create a test DB
	memDB := &MemDB{
		records: make(map[string][]string),
		accounts: map[string]Account{
			"test_user:test_subdomain.example.org.": testAccount,
		},
	}

	// Create the plugin instance
	a := ACME{
		Zones: []string{"example.org."},
		db:    memDB,
		AuthConfig: AuthConfig{
			ExtractIPFromHeader: "X-Forwarded-For",
			RequireAuth:         true,
		},
	}

	// Test cases
	tests := []struct {
		name      string
		auth      string // Basic auth header value
		xApiUser  string
		xApiKey   string
		subdomain string
		expectErr bool
	}{
		{
			name:      "Valid Basic Auth",
			auth:      "Basic " + basicAuth("test_user", "test_pass"),
			subdomain: "test_subdomain.example.org.",
			expectErr: false,
		},
		{
			name:      "Invalid Basic Auth Password",
			auth:      "Basic " + basicAuth("test_user", "wrong_pass"),
			subdomain: "test_subdomain.example.org.",
			expectErr: true,
		},
		{
			name:      "Invalid Basic Auth Username",
			auth:      "Basic " + basicAuth("wrong_user", "test_pass"),
			subdomain: "test_subdomain.example.org.",
			expectErr: true,
		},
		{
			name:      "Valid API Headers",
			xApiUser:  "test_user",
			xApiKey:   "test_pass",
			subdomain: "test_subdomain.example.org.",
			expectErr: false,
		},
		{
			name:      "Invalid API Header Password",
			xApiUser:  "test_user",
			xApiKey:   "wrong_pass",
			subdomain: "test_subdomain.example.org.",
			expectErr: true,
		},
		{
			name:      "Invalid API Header Username",
			xApiUser:  "wrong_user",
			xApiKey:   "test_pass",
			subdomain: "test_subdomain.example.org.",
			expectErr: true,
		},
		{
			name:      "No Authentication",
			subdomain: "test_subdomain.example.org.",
			expectErr: true,
		},
		{
			name:      "Wrong Subdomain",
			auth:      "Basic " + basicAuth("test_user", "test_pass"),
			subdomain: "wrong_subdomain.example.org.",
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/update", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			if tc.xApiUser != "" {
				req.Header.Set("X-Api-User", tc.xApiUser)
			}
			if tc.xApiKey != "" {
				req.Header.Set("X-Api-Key", tc.xApiKey)
			}

			_, err := a.getAccountFromRequestAndSubdomain(req, tc.subdomain)

			// Check results
			if tc.expectErr && err == nil {
				t.Error("Expected an error, but got none")
			} else if !tc.expectErr && err != nil {
				t.Errorf("Expected no error, but got: %v", err)
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name        string
		headerName  string
		remoteAddr  string
		headerValue string
		expectedIP  string
	}{
		{
			name:       "Use RemoteAddr",
			remoteAddr: "192.168.1.100:12345",
			expectedIP: "192.168.1.100",
		},
		{
			name:        "Use Header",
			headerName:  "X-Forwarded-For",
			remoteAddr:  "192.168.1.100:12345",
			headerValue: "10.0.0.1",
			expectedIP:  "10.0.0.1",
		},
		{
			name:        "Use Header Multiple IPs",
			headerName:  "X-Forwarded-For",
			remoteAddr:  "192.168.1.100:12345",
			headerValue: "10.0.0.1, 172.16.0.1",
			expectedIP:  "10.0.0.1",
		},
		{
			name:        "Use Header Empty",
			headerName:  "X-Forwarded-For",
			remoteAddr:  "192.168.1.100:12345",
			headerValue: "",
			expectedIP:  "",
		},
		{
			name:       "Invalid RemoteAddr",
			remoteAddr: "invalid", // No port
			expectedIP: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/update", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.headerValue != "" {
				req.Header.Set(tc.headerName, tc.headerValue)
			}

			ip := getClientIP(req, tc.headerName)

			if ip != tc.expectedIP {
				t.Errorf("Expected IP %s, but got: %s", tc.expectedIP, ip)
			}
		})
	}
}

func TestGetIPFromHeader(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		expectedIP  string
	}{
		{
			name:        "Empty header",
			headerValue: "",
			expectedIP:  "",
		},
		{
			name:        "Single IP",
			headerValue: "192.168.1.100",
			expectedIP:  "192.168.1.100",
		},
		{
			name:        "Multiple IPs",
			headerValue: "192.168.1.100,10.0.0.1,172.16.0.1",
			expectedIP:  "192.168.1.100",
		},
		{
			name:        "IPs with whitespace",
			headerValue: " 192.168.1.100 , 10.0.0.1 , 172.16.0.1 ",
			expectedIP:  "192.168.1.100",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := getIPFromHeader(tc.headerValue)

			if ip != tc.expectedIP {
				t.Errorf("Expected IP %s, but got: %s", tc.expectedIP, ip)
			}
		})
	}
}

// Helper to create a basic auth string
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
