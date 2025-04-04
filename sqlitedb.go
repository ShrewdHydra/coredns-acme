package acme

import (
	"database/sql"
	"errors"
	"runtime"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	ErrRecordNotFound = errors.New("record not found")
)

// SQLiteDB is a SQLite implementation of the DB interface
type SQLiteDB struct {
	writeDB *sql.DB
	readDB  *sql.DB
}

// NewSQLiteDB creates a new SQLite database
func NewSQLiteDB(path string) (*SQLiteDB, error) {
	log.Debugf("Creating new SQLite database at %s", path)
	writeDB, err := sql.Open("sqlite3", path)
	if err != nil {
		log.Errorf("Failed to open SQLite database: %v", err)
		return nil, err
	}
	writeDB.SetMaxOpenConns(1)

	readDB, err := sql.Open("sqlite3", path)
	if err != nil {
		log.Errorf("Failed to open SQLite database: %v", err)
		return nil, err
	}
	readDB.SetMaxOpenConns(max(4, runtime.NumCPU()))

	// Create tables if they don't exist
	_, err = writeDB.Exec(`
		CREATE TABLE IF NOT EXISTS records (
			fqdn TEXT NOT NULL,
			value TEXT NOT NULL,
			updated TIMESTAMP NOT NULL,
			created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (fqdn, value)
		);
		CREATE TABLE IF NOT EXISTS accounts (
			username TEXT NOT NULL,
			password TEXT NOT NULL,
			zone TEXT NOT NULL,
			allowfrom TEXT,
			created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (username, zone)
		);
	`)
	if err != nil {
		log.Errorf("Failed to create tables: %v", err)
		return nil, err
	}

	return &SQLiteDB{writeDB: writeDB, readDB: readDB}, nil
}

func (s *SQLiteDB) Close() error {
	if err := s.writeDB.Close(); err != nil {
		return err
	}
	return s.readDB.Close()
}

func (s *SQLiteDB) Exec(query string, args ...any) (sql.Result, error) {
	return s.writeDB.Exec(query, args...)
}

func (s *SQLiteDB) Query(query string, args ...any) (*sql.Rows, error) {
	return s.readDB.Query(query, args...)
}

func (s *SQLiteDB) QueryRow(query string, args ...any) *sql.Row {
	return s.readDB.QueryRow(query, args...)
}

// RegisterAccount creates a new account
func (s *SQLiteDB) RegisterAccount(a Account, passwordHash []byte) error {
	_, err := s.Exec("INSERT INTO accounts (username, password, zone, allowfrom) VALUES (?, ?, ?, ?)",
		a.Username, passwordHash, a.Zone, a.AllowedIPs.String())
	if err != nil {
		return err
	}

	return nil
}

// GetAccount retrieves an account by username and subdomain
func (s *SQLiteDB) GetAccount(username, subdomain string) (Account, error) {
	var a Account
	var allowedIPsStr string

	err := s.QueryRow("SELECT username, password, zone, allowfrom FROM accounts WHERE username = ? AND ? LIKE '%' || zone ORDER BY LENGTH(zone) DESC", username, subdomain).
		Scan(&a.Username, &a.Password, &a.Zone, &allowedIPsStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Account{}, ErrRecordNotFound
		}
		return Account{}, err
	}

	// Convert allowed IPs string to slice
	if allowedIPsStr != "" {
		a.AllowedIPs = NewCIDRList(allowedIPsStr)
	}

	return a, nil
}

// GetRecord retrieves a DNS record by domain
func (s *SQLiteDB) GetRecords(fqdn string) ([]string, error) {
	var values []string
	rows, err := s.Query("SELECT value FROM records WHERE fqdn = ? ORDER BY updated DESC", fqdn)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var value string
		err = rows.Scan(&value)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}

	if len(values) == 0 {
		return nil, ErrRecordNotFound
	}

	return values, nil
}

// PresentRecord updates a DNS record
func (s *SQLiteDB) PresentRecord(fqdn, value string) error {
	_, err := s.Exec("INSERT OR REPLACE INTO records (fqdn, value, updated) VALUES (?, ?, ?)", fqdn, value, time.Now())
	if err != nil {
		return err
	}

	return nil
}

func (s *SQLiteDB) CleanupRecord(fqdn, value string) error {
	_, err := s.Exec("DELETE FROM records WHERE fqdn = ? AND value = ?", fqdn, value)
	if err != nil {
		return err
	}
	return nil
}

// UpdateRotatedRecord updates the oldest TXT record for a domain
// This maintains two records and updates the oldest one first for ACME challenges
// func (s *SQLiteDB) UpdateRotatedRecord(subdomain, value string) error {
// 	// // Check if records exist for this domain
// 	// var count int
// 	// err := s.QueryRow("SELECT COUNT(*) FROM records WHERE domain LIKE ?", domain+"%").Scan(&count)
// 	// if err != nil {
// 	// 	log.Warningf("SQLiteDB: Failed to count records: %v", err)
// 	// 	return err
// 	// }

// 	tx, err := s.Begin()
// 	if err != nil {
// 		log.Warningf("SQLiteDB: Failed to begin transaction: %v", err)
// 		return err
// 	}

// 	defer func() {
// 		if err != nil {
// 			tx.Rollback()
// 		}
// 	}()

// 	primaryDomain := subdomain
// 	secondaryDomain := subdomain + "_2"
// 	now := time.Now()

// 	// Check how many records exist for this domain
// 	var count int
// 	err = tx.QueryRow("SELECT COUNT(*) FROM records WHERE domain IN (?, ?)",
// 		primaryDomain, secondaryDomain).Scan(&count)
// 	if err != nil {
// 		return err
// 	}

// 	// If no records exist, create both
// 	if count == 0 {
// 		_, err = tx.Exec("INSERT INTO records (domain, value, updated) VALUES (?, ?, ?)",
// 			primaryDomain, value, now)
// 		if err != nil {
// 			return err
// 		}

// 		_, err = tx.Exec("INSERT INTO records (domain, value, updated) VALUES (?, ?, ?)",
// 			secondaryDomain, value, now.Add(time.Second)) // Slightly newer
// 		if err != nil {
// 			return err
// 		}

// 		return tx.Commit()
// 	}

// 	// If only one record exists, create the missing one
// 	if count == 1 {
// 		var existingDomain string
// 		err = tx.QueryRow("SELECT domain FROM records WHERE domain IN (?, ?)",
// 			primaryDomain, secondaryDomain).Scan(&existingDomain)
// 		if err != nil {
// 			return err
// 		}

// 		var newDomain string
// 		if existingDomain == primaryDomain {
// 			newDomain = secondaryDomain
// 		} else {
// 			newDomain = primaryDomain
// 		}

// 		_, err = tx.Exec("INSERT INTO records (domain, value, updated) VALUES (?, ?, ?)",
// 			newDomain, value, now)
// 		if err != nil {
// 			log.Warningf("SQLiteDB: Failed to find oldest record: %v", err)
// 			return err
// 		}

// 		return tx.Commit()
// 	}

// 	// Both records exist - update the older one
// 	var oldestDomain string
// 	err = tx.QueryRow("SELECT domain FROM records WHERE domain IN (?, ?) ORDER BY updated ASC LIMIT 1",
// 		primaryDomain, secondaryDomain).Scan(&oldestDomain)
// 	if err != nil {
// 		return err
// 	}

// 	_, err = tx.Exec("UPDATE records SET value = ?, updated = ? WHERE domain = ?",
// 		value, now, oldestDomain)
// 	if err != nil {
// 		log.Warningf("SQLiteDB: Failed to commit transaction: %v", err)
// 		return err
// 	}

// 	return tx.Commit()
// }
