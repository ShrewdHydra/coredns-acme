package acme

import (
	"encoding/json"
	"net"
	"net/http"
	"regexp"
)

const TXT_LENGTH = 43

// isValidCIDR checks if a CIDR is valid
func isValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(sanitizeIPv6addr(cidr))
	return err == nil
}

// isValidIP checks if an IP is valid
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// isValidTXT checks if a TXT record contains only valid characters for ACME challenges
func isValidTXT(txt string) bool {
	if len(txt) != TXT_LENGTH {
		return false
	}

	// ACME challenges use base64url encoding, which limits the characters to:
	// A-Z, a-z, 0-9, -, and _
	for _, c := range txt {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '=') {
			return false
		}
	}

	return true
}

// sanitizeIPv6addr removes brackets from IPv6 addresses, net.ParseCIDR needs this
func sanitizeIPv6addr(s string) string {
	re, _ := regexp.Compile(`[\[\]]+`)
	return re.ReplaceAllString(s, "")
}

// writeJSONError writes a standardized JSON error response
func writeJSONError(w http.ResponseWriter, message string, status int) {
	writeJSON(w, map[string]string{"error": message}, status)
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
