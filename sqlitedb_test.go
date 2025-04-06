package acme

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func setupSQLiteTestDB(t *testing.T) *SQLiteDB {
	t.Helper()

	// Create a temporary database file with a unique name for each test
	dbFile := t.TempDir() + "/test.db"

	// Create a new database
	db, err := NewSQLiteDB(dbFile)
	if err != nil {
		t.Fatalf("Failed to create SQLiteDB: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
		os.Remove(dbFile)
	})

	return db
}
func TestSQLiteDB_RegisterAccount(t *testing.T) {
	db := setupSQLiteTestDB(t)

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
			name: "Duplicate account",
			account: Account{
				Username:   "test_user",
				Password:   "hashed_password",
				Zone:       "example.com",
				AllowedIPs: []string{"192.168.1.1"},
			},
			passwordHash: []byte("hashed_password"),
			wantErr:      true, // Should fail because username+zone is a primary key
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
			wantErr:      false, // Should succeed as username+zone is unique
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
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM accounts WHERE username = ? AND zone = ?",
					tt.account.Username, tt.account.Zone).Scan(&count)

				if err != nil {
					t.Fatalf("Failed to query account: %v", err)
				}

				if count != 1 {
					t.Errorf("Expected 1 account, got %d", count)
				}
			}
		})
	}
}

func TestSQLiteDB_GetAccount(t *testing.T) {
	db := setupSQLiteTestDB(t)

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
			Username:   "user1",
			Password:   "pass1",
			Zone:       "other-example.com",
			AllowedIPs: []string{"192.168.1.1"},
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
		{
			name:      "Non-existing but similar subdomain",
			username:  "user1",
			subdomain: "non-existing.another-example.com",
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

func TestSQLiteDB_PresentAndGetRecords(t *testing.T) {
	db := setupSQLiteTestDB(t)

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

func TestSQLiteDB_GetRecords_NonExistent(t *testing.T) {
	db := setupSQLiteTestDB(t)

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

func TestSQLiteDB_CleanupRecord(t *testing.T) {
	db := setupSQLiteTestDB(t)

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

func TestSQLiteDB_Close(t *testing.T) {
	db := setupSQLiteTestDB(t)

	// Close the database
	err := db.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Verify database handles are closed by attempting a query
	_, err = db.Query("SELECT 1")
	if err == nil {
		t.Error("Expected error after Close(), got nil")
	}
}

func TestSQLiteDBReadOnly(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sqlite-readonly-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "acme-test.db")

	// First create and populate a database in read-write mode
	rwDB, err := NewSQLiteDBWithROOption(dbPath, false)
	if err != nil {
		t.Fatalf("Failed to create RW database: %v", err)
	}

	testRecord := "test.example.com"
	testValue := "test-token"

	// Add a record
	err = rwDB.PresentRecord(testRecord, testValue)
	if err != nil {
		t.Fatalf("Failed to add record: %v", err)
	}

	// Close the read-write database
	if err := rwDB.Close(); err != nil {
		t.Fatalf("Failed to close RW database: %v", err)
	}

	// Open the same database in read-only mode
	roDB, err := NewSQLiteDBWithROOption(dbPath, true)
	if err != nil {
		t.Fatalf("Failed to open database in read-only mode: %v", err)
	}
	defer roDB.Close()

	// Verify we can read the record
	records, err := roDB.GetRecords(testRecord)
	if err != nil {
		t.Fatalf("Failed to read record in read-only mode: %v", err)
	}
	if len(records) != 1 || records[0] != testValue {
		t.Fatalf("Expected record %s, got %v", testValue, records)
	}

	// Verify write operations fail
	err = roDB.PresentRecord("new.example.com", "new-token")
	if err == nil {
		t.Fatal("Expected error when writing to read-only database, got nil")
	}

	err = roDB.CleanupRecord(testRecord, testValue)
	if err == nil {
		t.Fatal("Expected error when deleting from read-only database, got nil")
	}
}
