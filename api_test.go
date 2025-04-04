package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

func TestHandleRegister(t *testing.T) {
	clog.D.Set()

	tests := []struct {
		name                string
		requestBody         string
		expectedStatusCode  int
		expectedMessage     string
		expectAccountStored bool
		expectedUsername    string
		expectedZone        string
		expectedAllowedIPs  []string
	}{
		{
			name: "Valid registration",
			requestBody: `{
				"username": "test_user",
				"password": "test_pass",
				"zone": "example.org",
				"allowfrom": ["192.168.1.1", "10.0.0.0/24"]
			}`,
			expectedStatusCode:  http.StatusCreated,
			expectedMessage:     "Account registered successfully",
			expectAccountStored: true,
			expectedUsername:    "test_user",
			expectedZone:        "example.org.",
			expectedAllowedIPs:  []string{"192.168.1.1", "10.0.0.0/24"},
		},
		{
			name:               "Missing required fields",
			requestBody:        `{"zone": "example.org."}`,
			expectedStatusCode: http.StatusBadRequest,
			expectedMessage:    "",
		},
		{
			name: "Invalid zone format",
			requestBody: `{
				"username": "test_user",
				"password": "test_pass",
				"zone": "invalid-zone",
				"allowfrom": ["192.168.1.1"]
			}`,
			expectedStatusCode: http.StatusBadRequest,
			expectedMessage:    "",
		},
		{
			name: "Invalid CIDR in allowfrom",
			requestBody: `{
				"username": "test_user",
				"password": "test_pass",
				"zone": "example.org",
				"allowfrom": ["invalid-cidr"]
			}`,
			expectedStatusCode: http.StatusBadRequest,
			expectedMessage:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			memDB := &MemDB{
				records:  make(map[string][]string),
				accounts: make(map[string]Account),
			}

			a := ACME{
				Zones: []string{"example.org."},
				db:    memDB,
				AuthConfig: AuthConfig{
					ExtractIPFromHeader: "X-Forwarded-For",
				},
			}

			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader([]byte(tt.requestBody)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", "192.168.1.100")

			res := httptest.NewRecorder()
			a.handleRegister(res, req)

			if res.Code != tt.expectedStatusCode {
				t.Errorf("Expected status code %d, but got: %d", tt.expectedStatusCode, res.Code)
			}

			if tt.expectedStatusCode == http.StatusCreated {
				var resBody struct {
					Message string `json:"message"`
				}
				if err := json.NewDecoder(res.Body).Decode(&resBody); err != nil {
					t.Errorf("Failed to decode response: %v", err)
				}

				if resBody.Message != tt.expectedMessage {
					t.Errorf("Expected message '%s', but got: '%s'", tt.expectedMessage, resBody.Message)
				}

				if tt.expectAccountStored {
					var account Account
					var found bool
					for _, acc := range memDB.accounts {
						if acc.Username == tt.expectedUsername && acc.Zone == tt.expectedZone {
							account = acc
							found = true
							break
						}
					}

					if !found {
						t.Error("Expected account to be stored in the database")
					} else {
						if account.Username != tt.expectedUsername {
							t.Errorf("Expected username '%s', but got: '%s'", tt.expectedUsername, account.Username)
						}
						if account.Zone != tt.expectedZone {
							t.Errorf("Expected zone '%s', but got: '%s'", tt.expectedZone, account.Zone)
						}

						if tt.expectedAllowedIPs != nil {
							if len(account.AllowedIPs) != len(tt.expectedAllowedIPs) {
								t.Errorf("Expected %d allowed IPs, but got: %d", len(tt.expectedAllowedIPs), len(account.AllowedIPs))
							} else {
								for i, ip := range tt.expectedAllowedIPs {
									if i < len(account.AllowedIPs) && account.AllowedIPs[i] != ip {
										t.Errorf("Expected allowed IP '%s' at index %d, but got: '%s'", ip, i, account.AllowedIPs[i])
									}
								}
							}
						}
					}
				}
			}
		})
	}
}

func TestHandlePresent(t *testing.T) {
	// Create a test account
	testAccount := Account{
		Username:   "test_user",
		Password:   "test_pass",
		Zone:       "test_subdomain",
		AllowedIPs: []string{"192.168.1.100", "10.0.0.0/24"},
	}

	memDB := &MemDB{
		records: make(map[string][]string),
		accounts: map[string]Account{
			"test_user:test_subdomain": testAccount,
		},
	}

	fqdn := "test_subdomain.example.org."
	memDB.records[fqdn] = []string{"initial_value"}

	a := ACME{
		Zones: []string{"example.org."},
		db:    memDB,
		AuthConfig: AuthConfig{
			ExtractIPFromHeader: "X-Forwarded-For",
		},
	}

	validTXT := "abcdefghijklmnopqrstuvwxyz0123456789-_=ABCD"
	reqBody := []byte(`{"fqdn": "` + fqdn + `", "value": "` + validTXT + `"}`)

	req := httptest.NewRequest(http.MethodPost, "/present", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-User", "test_user")
	req.Header.Set("X-Api-Key", "test_pass")
	req.Header.Set("X-Forwarded-For", "192.168.1.100")

	// Store account and request in context (simulating Auth middleware)
	dnsRecord := ACMETxt{
		FQDN:  fqdn,
		Value: validTXT,
	}
	ctx := context.WithValue(req.Context(), ACMEAccountKey, testAccount)
	ctx = context.WithValue(ctx, ACMERequestKey, dnsRecord)
	req = req.WithContext(ctx)

	res := httptest.NewRecorder()
	a.handlePresent(res, req)

	expectedStatusCode := http.StatusOK

	if res.Code != expectedStatusCode {
		t.Errorf("Expected status code %d, but got: %d", expectedStatusCode, res.Code)
	}

	// Check that the record was updated
	records, err := memDB.GetRecords(fqdn)
	if err != nil {
		t.Errorf("Failed to get updated record: %v", err)
	}
	found := false
	for _, record := range records {
		if record == validTXT {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected TXT record value %s, but got: %v", validTXT, records)
	}
}

// TestHandleHealth tests the health endpoint
func TestHandleHealth(t *testing.T) {
	a := ACME{}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	res := httptest.NewRecorder()

	a.handleHealth(res, req)

	if res.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got: %d", http.StatusOK, res.Code)
	}
	if res.Body.String() != http.StatusText(http.StatusOK) {
		t.Errorf("Expected response body %s, but got: %s", http.StatusText(http.StatusOK), res.Body.String())
	}
}

// TestHandleUpdateErrors tests error cases for the update handler
func TestHandlePresentErrors(t *testing.T) {
	// Create a test account
	testAccount := Account{
		Username:   "test_user",
		Password:   "test_pass",
		Zone:       "test_subdomain",
		AllowedIPs: []string{"192.168.1.100", "10.0.0.0/24"},
	}

	// Create a test DB that returns errors
	errDB := &errorDB{
		err: errors.New("database error"),
	}

	// Create the plugin instance
	a := ACME{
		Zones: []string{"example.org."},
		db:    errDB,
		AuthConfig: AuthConfig{
			ExtractIPFromHeader: "X-Forwarded-For",
		},
	}

	// Create a valid TXT record
	validTXT := "abcdefghijklmnopqrstuvwxyz0123456789-_=ABCD"
	fqdn := "test_subdomain.example.org."

	// Test cases
	tests := []struct {
		name            string
		record          ACMETxt
		dbErr           error
		contextElements map[key]interface{}
		expectedCode    int
		expectedMessage string
	}{
		{
			name: "DB Error",
			record: ACMETxt{
				FQDN:  fqdn,
				Value: validTXT,
			},
			dbErr:           errors.New("database error"),
			contextElements: map[key]interface{}{ACMEAccountKey: testAccount, ACMERequestKey: ACMETxt{FQDN: fqdn, Value: validTXT}},
			expectedCode:    http.StatusInternalServerError,
			expectedMessage: "present_failed",
		},
		{
			name: "Missing Account in Context",
			record: ACMETxt{
				FQDN:  fqdn,
				Value: validTXT,
			},
			dbErr:           nil,
			contextElements: map[key]interface{}{ACMERequestKey: ACMETxt{FQDN: fqdn, Value: validTXT}},
			expectedCode:    http.StatusUnauthorized,
			expectedMessage: "unauthorized",
		},
		{
			name: "Missing Request in Context",
			record: ACMETxt{
				FQDN:  fqdn,
				Value: validTXT,
			},
			dbErr:           nil,
			contextElements: map[key]interface{}{ACMEAccountKey: testAccount},
			expectedCode:    http.StatusUnauthorized,
			expectedMessage: "unauthorized",
		},
		{
			name: "Request Type Assertion Failure",
			record: ACMETxt{
				FQDN:  fqdn,
				Value: validTXT,
			},
			dbErr:           nil,
			contextElements: map[key]interface{}{ACMEAccountKey: testAccount, ACMERequestKey: "invalid-type"},
			expectedCode:    http.StatusUnauthorized,
			expectedMessage: "unauthorized",
		},
		{
			name: "Account Type Assertion Failure",
			record: ACMETxt{
				FQDN:  fqdn,
				Value: validTXT,
			},
			dbErr:           nil,
			contextElements: map[key]interface{}{ACMEAccountKey: "invalid-type", ACMERequestKey: ACMETxt{FQDN: fqdn, Value: validTXT}},
			expectedCode:    http.StatusUnauthorized,
			expectedMessage: "unauthorized",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errDB.err = tc.dbErr

			reqBody := []byte(`{"fqdn": "` + tc.record.FQDN + `", "value": "` + tc.record.Value + `"}`)
			req := httptest.NewRequest(http.MethodPost, "/present", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")
			req.SetBasicAuth(testAccount.Username, testAccount.Password)
			req.Header.Set("X-Forwarded-For", "192.168.1.100")

			ctx := req.Context()
			for k, v := range tc.contextElements {
				ctx = context.WithValue(ctx, k, v)
			}
			req = req.WithContext(ctx)

			res := httptest.NewRecorder()

			a.handlePresent(res, req)
			if res.Code != tc.expectedCode {
				t.Errorf("Expected status code %d, but got: %d", tc.expectedCode, res.Code)
			}

			if tc.expectedMessage != "" {
				var respBody map[string]string
				err := json.NewDecoder(res.Body).Decode(&respBody)
				if err != nil {
					t.Errorf("Failed to decode response body: %v", err)
				}

				if errorMsg, ok := respBody["error"]; !ok || errorMsg != tc.expectedMessage {
					t.Errorf("Expected error message '%s', but got: %+v", tc.expectedMessage, respBody)
				}
			}
		})
	}
}

// TestHandleCleanup tests the normal operation of the cleanup handler
func TestHandleCleanup(t *testing.T) {
	// Create a test account
	testAccount := Account{
		Username:   "test_user",
		Password:   "test_pass",
		Zone:       "test_subdomain",
		AllowedIPs: []string{"192.168.1.100", "10.0.0.0/24"},
	}

	// Create the test records
	fqdn := "test_subdomain.example.org."
	txtValue1 := "abcdefghijklmnopqrstuvwxyz0123456789-_=ABCD"
	txtValue2 := "zyxwvutsrqponmlkjihgfedcba9876543210-_=ABCD"

	// Create a test DB with initial records
	memDB := &MemDB{
		records: map[string][]string{
			fqdn: {txtValue1, txtValue2},
		},
		accounts: map[string]Account{
			"test_user:test_subdomain": testAccount,
		},
	}

	// Create the plugin instance
	a := ACME{
		Zones: []string{"example.org."},
		db:    memDB,
		AuthConfig: AuthConfig{
			ExtractIPFromHeader: "X-Forwarded-For",
		},
	}

	// Create cleanup request
	reqBody := []byte(`{"fqdn": "` + fqdn + `", "value": "` + txtValue1 + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/cleanup", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-User", "test_user")
	req.Header.Set("X-Api-Key", "test_pass")
	req.Header.Set("X-Forwarded-For", "192.168.1.100")

	// Store account and request in context (simulating Auth middleware)
	dnsRecord := ACMETxt{
		FQDN:  fqdn,
		Value: txtValue1,
	}
	ctx := context.WithValue(req.Context(), ACMEAccountKey, testAccount)
	ctx = context.WithValue(ctx, ACMERequestKey, dnsRecord)
	req = req.WithContext(ctx)

	res := httptest.NewRecorder()
	a.handleCleanup(res, req)

	// Check for successful response
	if res.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got: %d", http.StatusOK, res.Code)
	}

	// Verify that the response contains the correct FQDN and TXT value
	var respBody map[string]string
	err := json.NewDecoder(res.Body).Decode(&respBody)
	if err != nil {
		t.Errorf("Failed to decode response body: %v", err)
	}

	if respBody["FQDN"] != fqdn {
		t.Errorf("Expected FQDN %s, but got: %s", fqdn, respBody["FQDN"])
	}

	if respBody["TXT"] != txtValue1 {
		t.Errorf("Expected TXT value %s, but got: %s", txtValue1, respBody["TXT"])
	}

	// Verify the record was cleaned up
	records, err := memDB.GetRecords(fqdn)
	if err != nil {
		t.Errorf("Failed to get records: %v", err)
	}

	for _, record := range records {
		if record == txtValue1 {
			t.Errorf("Record %s was not cleaned up", txtValue1)
		}
	}

	// Should only have the second value left
	if len(records) != 1 || records[0] != txtValue2 {
		t.Errorf("Expected records to contain only %s, but got: %v", txtValue2, records)
	}
}

// TestHandleCleanupErrors tests error cases for the cleanup handler
func TestHandleCleanupErrors(t *testing.T) {
	// Create a test account
	testAccount := Account{
		Username:   "test_user",
		Password:   "test_pass",
		Zone:       "test_subdomain",
		AllowedIPs: []string{"192.168.1.100", "10.0.0.0/24"},
	}

	// Create a test DB that returns errors
	errDB := &errorDB{
		err: errors.New("database error"),
	}

	// Create the plugin instance
	a := ACME{
		Zones: []string{"example.org."},
		db:    errDB,
		AuthConfig: AuthConfig{
			ExtractIPFromHeader: "X-Forwarded-For",
		},
	}

	// Create a valid record
	validTXT := "abcdefghijklmnopqrstuvwxyz0123456789-_=ABCD"
	fqdn := "test_subdomain.example.org."

	// Test cases
	tests := []struct {
		name            string
		record          ACMETxt
		dbErr           error
		contextElements map[key]interface{}
		expectedCode    int
		expectedMessage string
	}{
		{
			name: "DB Error",
			record: ACMETxt{
				FQDN:  fqdn,
				Value: validTXT,
			},
			dbErr:           errors.New("database error"),
			contextElements: map[key]interface{}{ACMEAccountKey: testAccount, ACMERequestKey: ACMETxt{FQDN: fqdn, Value: validTXT}},
			expectedCode:    http.StatusInternalServerError,
			expectedMessage: "cleanup_failed",
		},
		{
			name: "Missing Account in Context",
			record: ACMETxt{
				FQDN:  fqdn,
				Value: validTXT,
			},
			dbErr:           nil,
			contextElements: map[key]interface{}{ACMERequestKey: ACMETxt{FQDN: fqdn, Value: validTXT}},
			expectedCode:    http.StatusUnauthorized,
			expectedMessage: "unauthorized",
		},
		{
			name: "Missing Request in Context",
			record: ACMETxt{
				FQDN:  fqdn,
				Value: validTXT,
			},
			dbErr:           nil,
			contextElements: map[key]interface{}{ACMEAccountKey: testAccount},
			expectedCode:    http.StatusUnauthorized,
			expectedMessage: "unauthorized",
		},
		{
			name: "Request Type Assertion Failure",
			record: ACMETxt{
				FQDN:  fqdn,
				Value: validTXT,
			},
			dbErr:           nil,
			contextElements: map[key]interface{}{ACMEAccountKey: testAccount, ACMERequestKey: "invalid-type"},
			expectedCode:    http.StatusUnauthorized,
			expectedMessage: "unauthorized",
		},
		{
			name: "Account Type Assertion Failure",
			record: ACMETxt{
				FQDN:  fqdn,
				Value: validTXT,
			},
			dbErr:           nil,
			contextElements: map[key]interface{}{ACMEAccountKey: "invalid-type", ACMERequestKey: ACMETxt{FQDN: fqdn, Value: validTXT}},
			expectedCode:    http.StatusUnauthorized,
			expectedMessage: "unauthorized",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set the error for this test
			errDB.err = tc.dbErr

			// Create a request
			reqBody := []byte(`{"fqdn": "` + tc.record.FQDN + `", "value": "` + tc.record.Value + `"}`)
			req := httptest.NewRequest(http.MethodPost, "/cleanup", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")
			req.SetBasicAuth(testAccount.Username, testAccount.Password)
			req.Header.Set("X-Forwarded-For", "192.168.1.100")

			// Set up context with test-specific elements
			ctx := req.Context()
			for k, v := range tc.contextElements {
				ctx = context.WithValue(ctx, k, v)
			}
			req = req.WithContext(ctx)

			// Create a response recorder
			res := httptest.NewRecorder()

			// Call the handler
			a.handleCleanup(res, req)

			// Check the response code
			if res.Code != tc.expectedCode {
				t.Errorf("Expected status code %d, but got: %d", tc.expectedCode, res.Code)
			}

			// Check the response body contains the expected error message
			if tc.expectedMessage != "" {
				var respBody map[string]string
				err := json.NewDecoder(res.Body).Decode(&respBody)
				if err != nil {
					t.Errorf("Failed to decode response body: %v", err)
				}

				if errorMsg, ok := respBody["error"]; !ok || errorMsg != tc.expectedMessage {
					t.Errorf("Expected error message '%s', but got: %+v", tc.expectedMessage, respBody)
				}
			}
		})
	}
}
