package acme

import (
	"slices"
	"testing"
)

func TestNewMemDB(t *testing.T) {
	db := NewMemDB()

	if db == nil {
		t.Error("NewMemDB() returned nil")
	}

	if db.records == nil {
		t.Error("records map not initialized")
	}

	if db.accounts == nil {
		t.Error("accounts map not initialized")
	}
}

func TestMemDB_RegisterAndGetAccount(t *testing.T) {
	db := NewMemDB()

	testCases := []struct {
		name            string
		registerAcc     Account
		lookupUsername  string
		lookupSubdomain string
		wantFound       bool
		wantZone        string
	}{
		{
			name: "Exact match",
			registerAcc: Account{
				Username:   "user1",
				Password:   "pass1",
				Zone:       "example.org.",
				AllowedIPs: []string{"192.168.1.1"},
			},
			lookupUsername:  "user1",
			lookupSubdomain: "example.org.",
			wantFound:       true,
			wantZone:        "example.org.",
		},
		{
			name: "Subdomain match",
			registerAcc: Account{
				Username:   "user2",
				Password:   "pass2",
				Zone:       "example.com.",
				AllowedIPs: []string{"10.0.0.1/24"},
			},
			lookupUsername:  "user2",
			lookupSubdomain: "subdomain.example.com.",
			wantFound:       true,
			wantZone:        "example.com.",
		},
		{
			name: "Longest zone match",
			registerAcc: Account{
				Username:   "user3",
				Password:   "pass3",
				Zone:       "sub.example.net.",
				AllowedIPs: []string{},
			},
			lookupUsername:  "user3",
			lookupSubdomain: "test.sub.example.net.",
			wantFound:       true,
			wantZone:        "sub.example.net.",
		},
		{
			name: "No match",
			registerAcc: Account{
				Username:   "user4",
				Password:   "pass4",
				Zone:       "example.io.",
				AllowedIPs: []string{},
			},
			lookupUsername:  "nonexistent",
			lookupSubdomain: "example.io.",
			wantFound:       false,
			wantZone:        "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Register account
			err := db.RegisterAccount(tc.registerAcc, []byte("hashed_"+tc.registerAcc.Password))
			if err != nil {
				t.Fatalf("RegisterAccount() error = %v", err)
			}

			// Try to get the account
			acc, err := db.GetAccount(tc.lookupUsername, tc.lookupSubdomain)

			if tc.wantFound {
				if err != nil {
					t.Errorf("GetAccount() error = %v, wantErr %v", err, false)
					return
				}

				if acc.Username != tc.lookupUsername {
					t.Errorf("GetAccount() Username = %v, want %v", acc.Username, tc.lookupUsername)
				}

				if acc.Zone != tc.wantZone {
					t.Errorf("GetAccount() Zone = %v, want %v", acc.Zone, tc.wantZone)
				}

				if acc.Password != "hashed_"+tc.registerAcc.Password {
					t.Errorf("GetAccount() Password = %v, want %v", acc.Password, "hashed_"+tc.registerAcc.Password)
				}
			} else {
				if err != ErrRecordNotFound {
					t.Errorf("GetAccount() error = %v, want %v", err, ErrRecordNotFound)
				}
			}
		})
	}

	// Test multiple zone matching (which one is longer)
	t.Run("Multiple zones for same user", func(t *testing.T) {
		db := NewMemDB()

		// Register two accounts with same username but different zones
		acc1 := Account{
			Username: "multi",
			Password: "pass",
			Zone:     "example.org.",
		}
		acc2 := Account{
			Username: "multi",
			Password: "pass",
			Zone:     "sub.example.org.",
		}

		db.RegisterAccount(acc1, []byte("hash1"))
		db.RegisterAccount(acc2, []byte("hash2"))

		// Lookup with subdomain that matches both
		result, err := db.GetAccount("multi", "test.sub.example.org.")
		if err != nil {
			t.Errorf("GetAccount() error = %v", err)
			return
		}

		// Should match the longer zone
		if result.Zone != "sub.example.org." {
			t.Errorf("GetAccount() returned Zone = %v, want %v", result.Zone, "sub.example.org.")
		}
	})
}

func TestMemDB_PresentAndGetRecords(t *testing.T) {
	db := NewMemDB()

	testCases := []struct {
		name    string
		fqdn    string
		values  []string
		wantErr bool
	}{
		{
			name:    "Single record",
			fqdn:    "test.example.com.",
			values:  []string{"value1"},
			wantErr: false,
		},
		{
			name:    "Multiple records",
			fqdn:    "multi.example.org.",
			values:  []string{"value1", "value2", "value3"},
			wantErr: false,
		},
		{
			name:    "Duplicate values",
			fqdn:    "dupe.example.net.",
			values:  []string{"same-value", "same-value"},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Present each record
			for _, value := range tc.values {
				err := db.PresentRecord(tc.fqdn, value)
				if (err != nil) != tc.wantErr {
					t.Errorf("PresentRecord() error = %v, wantErr %v", err, tc.wantErr)
				}
			}

			// Get the records
			records, err := db.GetRecords(tc.fqdn)

			if tc.wantErr {
				if err == nil {
					t.Errorf("GetRecords() error = nil, wantErr %v", tc.wantErr)
				}
				return
			}

			// For duplicate values, we expect only one entry
			expectedLen := len(tc.values)
			if tc.name == "Duplicate values" {
				expectedLen = 1 // Only one unique value
			}

			if len(records) != expectedLen {
				t.Errorf("GetRecords() returned %d records, want %d", len(records), expectedLen)
			}

			// Check that all expected values are present
			for _, expected := range tc.values {
				found := false
				for _, actual := range records {
					if actual == expected {
						found = true
						break
					}
				}
				if !found && !(tc.name == "Duplicate values" && slices.Contains(records, expected)) {
					t.Errorf("GetRecords() did not return expected value %q", expected)
				}
			}
		})
	}

	// Test getting non-existent record
	t.Run("Non-existent record", func(t *testing.T) {
		records, err := db.GetRecords("nonexistent.example.com.")
		if err != ErrRecordNotFound {
			t.Errorf("GetRecords() error = %v, want %v", err, ErrRecordNotFound)
		}
		if records != nil {
			t.Errorf("GetRecords() = %v, want nil", records)
		}
	})
}

func TestMemDB_CleanupRecord(t *testing.T) {
	db := NewMemDB()

	// Set up test data
	db.PresentRecord("cleanup.example.org.", "value1")
	db.PresentRecord("cleanup.example.org.", "value2")
	db.PresentRecord("cleanup.example.org.", "value3")

	// Clean up second value
	err := db.CleanupRecord("cleanup.example.org.", "value2")
	if err != nil {
		t.Errorf("CleanupRecord() error = %v", err)
	}

	// Check the remaining records
	records, err := db.GetRecords("cleanup.example.org.")
	if err != nil {
		t.Errorf("GetRecords() error = %v", err)
		return
	}

	if len(records) != 2 {
		t.Errorf("Got %d records after cleanup, want 2", len(records))
	}

	// Value2 should be gone
	if slices.Contains(records, "value2") {
		t.Errorf("Records still contain 'value2' after cleanup")
	}

	// Clean up all records
	err = db.CleanupRecord("cleanup.example.org.", "value1")
	if err != nil {
		t.Errorf("CleanupRecord() error = %v", err)
	}

	err = db.CleanupRecord("cleanup.example.org.", "value3")
	if err != nil {
		t.Errorf("CleanupRecord() error = %v", err)
	}

	// Should get not found error now
	_, err = db.GetRecords("cleanup.example.org.")
	if err != ErrRecordNotFound {
		t.Errorf("GetRecords() error = %v, want %v", err, ErrRecordNotFound)
	}

	// Cleaning up non-existent value should return error
	err = db.CleanupRecord("cleanup.example.org.", "nonexistent")
	if err == nil || err.Error() != "value not found" {
		t.Errorf("CleanupRecord() error = %v, want 'value not found'", err)
	}

	// Cleaning up non-existent domain should not error
	err = db.CleanupRecord("nonexistent.example.com.", "value")
	if err != nil {
		t.Errorf("CleanupRecord() error = %v, want nil", err)
	}
}

func TestMemDB_Close(t *testing.T) {
	db := NewMemDB()

	// Close should always return nil for memDB
	err := db.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}
