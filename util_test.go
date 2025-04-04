package acme

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsValidCIDR tests the isValidCIDR function
func TestIsValidCIDR(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected bool
	}{
		{
			name:     "Valid IPv4 CIDR",
			cidr:     "192.168.1.0/24",
			expected: true,
		},
		{
			name:     "Valid IPv6 CIDR",
			cidr:     "2001:db8::/64",
			expected: true,
		},
		{
			name:     "Invalid CIDR format",
			cidr:     "192.168.1.0/33", // Invalid prefix length
			expected: false,
		},
		{
			name:     "Not a CIDR",
			cidr:     "192.168.1.1",
			expected: false,
		},
		{
			name:     "IPv6 CIDR with brackets",
			cidr:     "[2001:db8::]/64",
			expected: true, // Should be sanitized
		},
		{
			name:     "Empty string",
			cidr:     "",
			expected: false,
		},
		{
			name:     "Totally invalid",
			cidr:     "not-a-cidr",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidCIDR(tc.cidr)
			if result != tc.expected {
				t.Errorf("Expected %v for CIDR %s, but got: %v", tc.expected, tc.cidr, result)
			}
		})
	}
}

// TestIsValidIP tests the isValidIP function
func TestIsValidIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "Valid IPv4",
			ip:       "192.168.1.1",
			expected: true,
		},
		{
			name:     "Valid IPv6",
			ip:       "2001:db8::1",
			expected: true,
		},
		{
			name:     "Invalid IP format",
			ip:       "192.168.1.256", // Invalid octet
			expected: false,
		},
		{
			name:     "Not an IP",
			ip:       "not-an-ip",
			expected: false,
		},
		{
			name:     "Empty string",
			ip:       "",
			expected: false,
		},
		{
			name:     "IPv6 with brackets",
			ip:       "[2001:db8::1]", // Common in URLs
			expected: false,           // net.ParseIP doesn't handle brackets
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidIP(tc.ip)
			if result != tc.expected {
				t.Errorf("Expected %v for IP %s, but got: %v", tc.expected, tc.ip, result)
			}
		})
	}
}

// TestIsValidTXT tests the isValidTXT function
func TestIsValidTXT(t *testing.T) {
	tests := []struct {
		name     string
		txt      string
		expected bool
	}{
		{
			name:     "Valid TXT (exactly 43 chars)",
			txt:      "abcdefghijklmnopqrstuvwxyz0123456789-_=ABCD",
			expected: true,
		},
		{
			name:     "Invalid TXT (too short)",
			txt:      "abc",
			expected: false,
		},
		{
			name:     "Invalid TXT (too long)",
			txt:      "abcdefghijklmnopqrstuvwxyz0123456789-_=ABCDEF",
			expected: false,
		},
		{
			name:     "Invalid TXT (invalid character)",
			txt:      "abcdefghijklmnopqrstuvwxyz0123456789+/=ABCD", // + and / aren't allowed
			expected: false,
		},
		{
			name:     "Invalid TXT (empty)",
			txt:      "",
			expected: false,
		},
		{
			name:     "Invalid TXT (null)",
			txt:      string([]byte{0}),
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidTXT(tc.txt)
			if result != tc.expected {
				t.Errorf("Expected %v for %s, but got: %v", tc.expected, tc.txt, result)
			}
		})
	}
}

// TestSanitizeIPv6addr tests the sanitizeIPv6addr function
func TestSanitizeIPv6addr(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "IPv6 with brackets",
			input:    "[2001:db8::1]",
			expected: "2001:db8::1",
		},
		{
			name:     "IPv6 without brackets",
			input:    "2001:db8::1",
			expected: "2001:db8::1",
		},
		{
			name:     "IPv6 CIDR with brackets",
			input:    "[2001:db8::]/64",
			expected: "2001:db8::/64",
		},
		{
			name:     "IPv4 (no change)",
			input:    "192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := sanitizeIPv6addr(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %q, but got: %q", tc.expected, result)
			}
		})
	}
}

// TestWriteJSONError tests the writeJSONError function
func TestWriteJSONError(t *testing.T) {
	tests := []struct {
		name           string
		errorMessage   string
		statusCode     int
		expectedStatus int
		expectedBody   map[string]string
	}{
		{
			name:           "Not Found Error",
			errorMessage:   "not_found",
			statusCode:     http.StatusNotFound,
			expectedStatus: http.StatusNotFound,
			expectedBody:   map[string]string{"error": "not_found"},
		},
		{
			name:           "Bad Request Error",
			errorMessage:   "bad_request",
			statusCode:     http.StatusBadRequest,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]string{"error": "bad_request"},
		},
		{
			name:           "Internal Server Error",
			errorMessage:   "internal_error",
			statusCode:     http.StatusInternalServerError,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   map[string]string{"error": "internal_error"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a response recorder
			rr := httptest.NewRecorder()

			// Call the function
			writeJSONError(rr, tc.errorMessage, tc.statusCode)

			// Check status code
			if status := rr.Code; status != tc.expectedStatus {
				t.Errorf("Handler returned wrong status code: got %v want %v", status, tc.expectedStatus)
			}

			// Check content type
			contentType := rr.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Expected Content-Type to be 'application/json', but got: %v", contentType)
			}

			// Check the response body
			var responseBody map[string]string
			err := json.NewDecoder(rr.Body).Decode(&responseBody)
			if err != nil {
				t.Fatalf("Failed to decode response body: %v", err)
			}

			if responseBody["error"] != tc.expectedBody["error"] {
				t.Errorf("Expected error message %q, but got: %q", tc.expectedBody["error"], responseBody["error"])
			}
		})
	}
}

// TestWriteJSON tests the writeJSON function
func TestWriteJSON(t *testing.T) {
	tests := []struct {
		name           string
		data           interface{}
		statusCode     int
		expectedStatus int
	}{
		{
			name: "Simple Object",
			data: map[string]string{
				"message": "success",
				"status":  "ok",
			},
			statusCode:     http.StatusOK,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Array",
			data:           []string{"item1", "item2", "item3"},
			statusCode:     http.StatusCreated,
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Number",
			data:           42,
			statusCode:     http.StatusAccepted,
			expectedStatus: http.StatusAccepted,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a response recorder
			rr := httptest.NewRecorder()

			// Call the function
			writeJSON(rr, tc.data, tc.statusCode)

			// Check status code
			if status := rr.Code; status != tc.expectedStatus {
				t.Errorf("Handler returned wrong status code: got %v want %v", status, tc.expectedStatus)
			}

			// Check content type
			contentType := rr.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Expected Content-Type to be 'application/json', but got: %v", contentType)
			}

			// Check if the response is valid JSON
			var response interface{}
			err := json.NewDecoder(rr.Body).Decode(&response)
			if err != nil {
				t.Fatalf("Failed to decode response body: %v", err)
			}

			// For simple types, we can compare exactly
			switch data := tc.data.(type) {
			case int:
				if responseFloat, ok := response.(float64); !ok || float64(data) != responseFloat {
					t.Errorf("Expected response %v, but got: %v", data, responseFloat)
				}
			}
		})
	}
}
