package acme

import (
	"errors"
	"strings"
)

// MemDB is an in-memory implementation of the DB interface
type MemDB struct {
	records  map[string][]string
	accounts map[string]Account
}

// Make sure memDB implements the DB interface
var _ DB = &MemDB{}

// NewMemDB creates a new in-memory database
func NewMemDB() *MemDB {
	return &MemDB{
		records:  make(map[string][]string),
		accounts: make(map[string]Account),
	}
}

// Close does nothing for memory DB
func (m *MemDB) Close() error {
	return nil
}

// GetRecords retrieves DNS records by FQDN
func (m *MemDB) GetRecords(fqdn string) ([]string, error) {
	records, ok := m.records[fqdn]
	if !ok || len(records) == 0 {
		return nil, ErrRecordNotFound
	}
	return records, nil
}

// GetAccount retrieves an account by username and zone, doing longest zone match
func (m *MemDB) GetAccount(username, subdomain string) (Account, error) {
	// First try exact match
	key := username + ":" + subdomain
	account, ok := m.accounts[key]
	if ok {
		return account, nil
	}

	// Try to find the longest matching zone
	var bestMatch Account
	var bestMatchLength int

	for k, acc := range m.accounts {
		parts := strings.Split(k, ":")
		if len(parts) != 2 || parts[0] != username {
			continue
		}

		zone := "." + parts[1]
		// Check if subdomain ends with zone (domain match logic)
		if strings.HasSuffix(subdomain, zone) && len(zone) > bestMatchLength {
			bestMatch = acc
			bestMatchLength = len(zone)
		}
	}

	if bestMatchLength > 0 {
		return bestMatch, nil
	}

	return Account{}, ErrRecordNotFound
}

// RegisterAccount creates a new account
func (m *MemDB) RegisterAccount(a Account, passwordHash []byte) error {
	a.Password = string(passwordHash)

	// Store with username:zone as key
	m.accounts[a.Username+":"+a.Zone] = a
	return nil
}

// PresentRecord adds or updates a DNS record
func (m *MemDB) PresentRecord(fqdn string, value string) error {
	// Check if the record already exists to avoid duplicates
	records := m.records[fqdn]
	for _, existing := range records {
		if existing == value {
			// Already exists, do nothing
			return nil
		}
	}

	// Add the new record
	m.records[fqdn] = append(m.records[fqdn], value)
	return nil
}

// CleanupRecord removes a DNS record
func (m *MemDB) CleanupRecord(fqdn string, value string) error {
	records, ok := m.records[fqdn]
	if !ok {
		return nil // Nothing to delete
	}

	for i, v := range records {
		if v == value {
			// Remove the record at index i
			m.records[fqdn] = append(records[:i], records[i+1:]...)
			return nil
		}
	}

	return errors.New("value not found")
}
