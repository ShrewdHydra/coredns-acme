package acme

import (
	"encoding/json"
	"net/http"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"golang.org/x/crypto/bcrypt"
)

type RegisterRequest struct {
	Username  string   `json:"username"`
	Password  string   `json:"password"`
	Zone      string   `json:"zone"`
	AllowFrom CIDRList `json:"allowfrom,omitempty"`
}

type ACMETxt struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

// handleRegister handles registration requests
func (a *ACME) handleRegister(w http.ResponseWriter, r *http.Request) {
	APIRequestCount.WithLabelValues("acme "+a.APIConfig.APIAddr, "register").Inc()

	var regRequest RegisterRequest

	if r.Body == http.NoBody {
		log.Warning("No registration request found in request body")
		writeJSONError(w, "no_registration_request", http.StatusBadRequest)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&regRequest); err != nil {
		log.Warningf("Invalid registration request: %v", err)
		writeJSONError(w, "malformed_json", http.StatusBadRequest)
		return
	}

	if regRequest.Username == "" || regRequest.Password == "" || regRequest.Zone == "" {
		log.Warning("Invalid registration request: missing required fields")
		writeJSONError(w, "missing_required_fields", http.StatusBadRequest)
		return
	}

	regRequest.Zone = dns.CanonicalName(regRequest.Zone)
	if plugin.Zones(a.Zones).Matches(regRequest.Zone) == "" {
		log.Warningf("Invalid registration request: invalid zone: %s", regRequest.Zone)
		writeJSONError(w, "invalid_zone", http.StatusBadRequest)
		return
	}

	account := Account{
		Username:   regRequest.Username,
		Password:   regRequest.Password,
		Zone:       regRequest.Zone,
		AllowedIPs: regRequest.AllowFrom,
	}

	if regRequest.AllowFrom != nil {
		if !regRequest.AllowFrom.isValid() {
			log.Warningf("Invalid CIDR mask in allowfrom: %v", regRequest.AllowFrom)
			writeJSONError(w, "invalid_allowfrom_cidr", http.StatusBadRequest)
			return
		}
		account.AllowedIPs = regRequest.AllowFrom
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(account.Password), 10)
	if err != nil {
		log.Errorf("Failed to generate password hash: %v", err)
		writeJSONError(w, "registration_failed", http.StatusInternalServerError)
		return
	}

	err = a.db.RegisterAccount(account, passwordHash)
	if err != nil {
		log.Errorf("Registration failed: %v", err)
		writeJSONError(w, "registration_failed", http.StatusInternalServerError)
		return
	}

	log.Infof("Account registered successfully - Username: %s, Subdomain: %s", account.Username, account.Zone)
	writeJSON(w, map[string]string{"message": "Account registered successfully"}, http.StatusCreated)
}

func (a *ACME) handlePresent(w http.ResponseWriter, r *http.Request) {
	APIRequestCount.WithLabelValues("acme "+a.APIConfig.APIAddr, "present").Inc()

	// Get account from context
	_, ok := r.Context().Value(ACMEAccountKey).(Account)
	if !ok {
		log.Warning("No account found in request context")
		writeJSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	presentRequest, ok := r.Context().Value(ACMERequestKey).(ACMETxt)
	if !ok {
		log.Warning("No present request found in request context")
		writeJSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	err := a.db.PresentRecord(presentRequest.FQDN, presentRequest.Value)
	if err != nil {
		log.Errorf("Present failed: %v", err)
		writeJSONError(w, "present_failed", http.StatusInternalServerError)
		return
	}

	log.Infof("TXT record updated successfully for %s (%s)", presentRequest.FQDN, presentRequest.Value)
	writeJSON(w, map[string]string{"FQDN": presentRequest.FQDN, "TXT": presentRequest.Value}, http.StatusOK)
}

func (a *ACME) handleCleanup(w http.ResponseWriter, r *http.Request) {
	APIRequestCount.WithLabelValues("acme "+a.APIConfig.APIAddr, "cleanup").Inc()

	// Get account from context
	_, ok := r.Context().Value(ACMEAccountKey).(Account)
	if !ok {
		log.Warning("No account found in request context")
		writeJSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	cleanupRequest, ok := r.Context().Value(ACMERequestKey).(ACMETxt)
	if !ok {
		log.Warning("No cleanup request found in request context")
		writeJSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	err := a.db.CleanupRecord(cleanupRequest.FQDN, cleanupRequest.Value)
	if err != nil {
		log.Errorf("Cleanup failed: %v", err)
		writeJSONError(w, "cleanup_failed", http.StatusInternalServerError)
		return
	}

	log.Infof("TXT record cleaned up successfully for %s (%s)", cleanupRequest.FQDN, cleanupRequest.Value)
	writeJSON(w, map[string]string{"FQDN": cleanupRequest.FQDN, "TXT": cleanupRequest.Value}, http.StatusOK)
}

// handleHealth handles health check
func (a *ACME) handleHealth(w http.ResponseWriter, r *http.Request) {
	APIRequestCount.WithLabelValues("acme "+a.APIConfig.APIAddr, "health").Inc()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}
