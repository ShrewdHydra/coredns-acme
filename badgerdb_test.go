package acme

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/dgraph-io/badger/v3"
)

func setupBadgerTestDB(t *testing.T) *BadgerDB {
	t.Helper()

	// Create a temporary database file with a unique name for each test
	dbFile := t.TempDir() + "/test.db"

	// Create a new database
	db, err := NewBadgerDB(dbFile)
	if err != nil {
		t.Fatalf("Failed to create BadgerDB: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
		os.Remove(dbFile)
	})

	return db
}
func TestBadgerDB_RegisterAccount(t *testing.T) {
	db := setupBadgerTestDB(t)

	tests := []struct {
		name         string
		account      Account
		passwordHash []byte
		wantErr      bool
	}{
		{
			name: "Valid account",
			account: Account{
				Username:   "test_user",
				Password:   "hashed_password",
				Zone:       "example.com",
				AllowedIPs: []string{"192.168.1.1", "10.0.0.0/24"},
			},
			passwordHash: []byte("hashed_password"),
			wantErr:      false,
		},
		{
			name: "Different zone, same username",
			account: Account{
				Username:   "test_user",
				Password:   "hashed_password",
				Zone:       "different.com",
				AllowedIPs: []string{"192.168.1.1"},
			},
			passwordHash: []byte("hashed_password"),
			wantErr:      false,
		},
		{
			name: "Duplicate account",
			account: Account{
				Username:   "test_user",
				Password:   "hashed_password",
				Zone:       "example.com",
				AllowedIPs: []string{"192.168.1.1"},
			},
			passwordHash: []byte("hashed_password"),
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := db.RegisterAccount(tt.account, tt.passwordHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterAccount() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				// Verify account exists in database
				var account Account
				err = db.db.View(func(txn *badger.Txn) error {
					accountKey := makeAccountKey(tt.account.Username, tt.account.Zone)
					item, err := txn.Get(accountKey)
					if err != nil {
						return err
					}
					return item.Value(func(val []byte) error {
						return json.Unmarshal(val, &account)
					})
				})

				if err != nil {
					t.Fatalf("Failed to query account: %v", err)
				}

				if account.Username != tt.account.Username ||
					account.Zone != tt.account.Zone ||
					!slices.Equal(account.AllowedIPs, tt.account.AllowedIPs) {
					t.Errorf("Retrieved account doesn't match stored account")
				}
			}
		})
	}
}

func TestBadgerDB_GetAccount(t *testing.T) {
	db := setupBadgerTestDB(t)

	// Set up test accounts
	testAccounts := []Account{
		{
			Username:   "user1",
			Password:   "pass1",
			Zone:       "example.com",
			AllowedIPs: []string{"192.168.1.1"},
		},
		{
			Username:   "user1",
			Password:   "pass1",
			Zone:       "sub.example.com",
			AllowedIPs: []string{"10.0.0.0/24"},
		},
		{
			Username:   "user2",
			Password:   "pass2",
			Zone:       "different.org",
			AllowedIPs: []string{"172.16.0.1"},
		},
	}

	// Register test accounts
	for _, acc := range testAccounts {
		err := db.RegisterAccount(acc, []byte(acc.Password))
		if err != nil {
			t.Fatalf("Failed to register test account: %v", err)
		}
	}

	tests := []struct {
		name      string
		username  string
		subdomain string
		wantZone  string
		wantErr   bool
	}{
		{
			name:      "Exact match",
			username:  "user1",
			subdomain: "example.com",
			wantZone:  "example.com",
			wantErr:   false,
		},
		{
			name:      "Subdomain match",
			username:  "user1",
			subdomain: "test.example.com",
			wantZone:  "example.com",
			wantErr:   false,
		},
		{
			name:      "Longer zone match",
			username:  "user1",
			subdomain: "test.sub.example.com",
			wantZone:  "sub.example.com",
			wantErr:   false,
		},
		{
			name:      "Different user",
			username:  "user1",
			subdomain: "different.org",
			wantZone:  "",
			wantErr:   true,
		},
		{
			name:      "Non-existent user",
			username:  "nonexistent",
			subdomain: "example.com",
			wantZone:  "",
			wantErr:   true,
		},
		{
			name:      "Non-matching subdomain",
			username:  "user1",
			subdomain: "nonmatching.org",
			wantZone:  "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acc, err := db.GetAccount(tt.username, tt.subdomain)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAccount() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if acc.Username != tt.username {
					t.Errorf("GetAccount() got username = %v, want %v", acc.Username, tt.username)
				}

				if acc.Zone != tt.wantZone {
					t.Errorf("GetAccount() got zone = %v, want %v", acc.Zone, tt.wantZone)
				}
			}
		})
	}
}

func TestBadgerDB_PresentAndGetRecords(t *testing.T) {
	db := setupBadgerTestDB(t)

	tests := []struct {
		name        string
		fqdn        string
		values      []string
		recordCount int
		wantErr     bool
	}{
		{
			name:        "Single record",
			fqdn:        "test.example.com",
			values:      []string{"test-value-1"},
			recordCount: 1,
			wantErr:     false,
		},
		{
			name:        "Multiple records",
			fqdn:        "multi.example.com",
			values:      []string{"value-1", "value-2", "value-3"},
			recordCount: 3,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Present each record
			for _, value := range tt.values {
				err := db.PresentRecord(tt.fqdn, value)
				if (err != nil) != tt.wantErr {
					t.Errorf("PresentRecord() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}

			// Get records
			records, err := db.GetRecords(tt.fqdn)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRecords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(records) != tt.recordCount {
					t.Errorf("GetRecords() got %d records, want %d", len(records), tt.recordCount)
				}

				// Check that all values are present
				valueMap := make(map[string]bool)
				for _, record := range records {
					valueMap[record] = true
				}

				for _, value := range tt.values {
					if !valueMap[value] {
						t.Errorf("GetRecords() missing value %s", value)
					}
				}
			}
		})
	}
}

func TestBadgerDB_GetRecords_NonExistent(t *testing.T) {
	db := setupBadgerTestDB(t)

	// Test GetRecords for non-existent record
	records, err := db.GetRecords("non-existent.example.com")

	// The function should return ErrRecordNotFound when no records are found
	if err != ErrRecordNotFound {
		t.Errorf("GetRecords() error = %v, want %v", err, ErrRecordNotFound)
	}

	if records != nil {
		t.Errorf("GetRecords() got %v, want nil", records)
	}
}

func TestBadgerDB_CleanupRecord(t *testing.T) {
	db := setupBadgerTestDB(t)

	tests := []struct {
		name    string
		fqdn    string
		values  []string
		cleanup string
		wantErr bool
	}{
		{
			name:    "Cleanup the only record",
			fqdn:    "cleanup1.example.com",
			values:  []string{"value-1"},
			cleanup: "value-1",
			wantErr: false,
		},
		{
			name:    "Cleanup a record from multiple",
			fqdn:    "cleanup2.example.com",
			values:  []string{"value-1", "value-2"},
			cleanup: "value-1",
			wantErr: false,
		},
		{
			name:    "Cleanup non-existent record",
			fqdn:    "nonexistent.example.com",
			values:  []string{},
			cleanup: "some-value",
			wantErr: false, // SQLite DELETE doesn't error if no rows are affected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Present each record
			for _, value := range tt.values {
				err := db.PresentRecord(tt.fqdn, value)
				if err != nil {
					t.Fatalf("Failed to present record: %v", err)
				}
			}

			// Cleanup one record
			err := db.CleanupRecord(tt.fqdn, tt.cleanup)
			if (err != nil) != tt.wantErr {
				t.Errorf("CleanupRecord() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify records
			records, err := db.GetRecords(tt.fqdn)
			expectedCount := len(tt.values)
			if tt.cleanup != "" && slices.Contains(tt.values, tt.cleanup) {
				expectedCount--
			}

			// If we expect all records to be gone, we should get ErrRecordNotFound
			if expectedCount == 0 {
				if err != ErrRecordNotFound {
					t.Errorf("Expected ErrRecordNotFound after cleanup, got %v", err)
				}
				if records != nil {
					t.Errorf("Expected nil records after cleanup, got %v", records)
				}
				return
			}

			// Otherwise we should get records without error
			if err != nil {
				t.Fatalf("Failed to get records: %v", err)
			}

			// Verify the cleanup record is gone
			for _, record := range records {
				if record == tt.cleanup {
					t.Errorf("CleanupRecord() failed, record %s still exists", tt.cleanup)
				}
			}

			// Verify count is correct
			if len(records) != expectedCount {
				t.Errorf("Expected %d records after cleanup, got %d", expectedCount, len(records))
			}
		})
	}
}

func TestBadgerDB_Close(t *testing.T) {
	db := setupBadgerTestDB(t)

	// Close the database
	err := db.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Verify database handles are closed by attempting a query
	db.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte("any-key"))
		if err != badger.ErrDBClosed {
			t.Errorf("Expected error ErrDBClosed when accessing closed database, got %v", err)
		}
		return nil
	})
}
