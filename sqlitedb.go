package acme

import (
	"database/sql"
	"errors"
	"runtime"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteDB is a SQLite implementation of the DB interface
type SQLiteDB struct {
	writeDB  *sql.DB
	readDB   *sql.DB
	readOnly bool
}

// NewSQLiteDB creates a new SQLite database
func NewSQLiteDB(path string) (*SQLiteDB, error) {
	return NewSQLiteDBWithROOption(path, false)
}

// NewSQLiteDBWithROOption creates a new SQLite database with specified read-only option
func NewSQLiteDBWithROOption(path string, readOnly bool) (*SQLiteDB, error) {
	log.Debugf("Creating new SQLite database at %s (readOnly: %v)", path, readOnly)

	if readOnly {
		// Open the database in read-only mode
		readDB, err := sql.Open("sqlite", path+"?mode=ro")
		if err != nil {
			log.Errorf("Failed to open SQLite database in read-only mode: %v", err)
			return nil, err
		}
		readDB.SetMaxOpenConns(max(4, runtime.NumCPU()))

		// For read-only mode, both writeDB and readDB point to the read-only connection
		return &SQLiteDB{writeDB: readDB, readDB: readDB, readOnly: true}, nil
	}

	// Normal read-write mode
	writeDB, err := sql.Open("sqlite", path)
	if err != nil {
		log.Errorf("Failed to open SQLite database: %v", err)
		return nil, err
	}
	writeDB.SetMaxOpenConns(1)

	readDB, err := sql.Open("sqlite", path)
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

	return &SQLiteDB{writeDB: writeDB, readDB: readDB, readOnly: false}, nil
}

func (s *SQLiteDB) Close() error {
	if err := s.writeDB.Close(); err != nil {
		return err
	}
	if s.readDB != s.writeDB {
		return s.readDB.Close()
	}
	return nil
}

func (s *SQLiteDB) Exec(query string, args ...any) (sql.Result, error) {
	if s.readOnly {
		return nil, ErrReadOnlyDatabase
	}
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
	if s.readOnly {
		return ErrReadOnlyDatabase
	}
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

	err := s.QueryRow("SELECT username, password, zone, allowfrom FROM accounts WHERE username = ? AND (zone = ? OR ? LIKE '%.' || zone) ORDER BY LENGTH(zone) DESC LIMIT 1", username, subdomain, subdomain).
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
	if s.readOnly {
		return ErrReadOnlyDatabase
	}
	_, err := s.Exec("INSERT OR REPLACE INTO records (fqdn, value, updated) VALUES (?, ?, ?)", fqdn, value, time.Now())
	if err != nil {
		return err
	}

	return nil
}

func (s *SQLiteDB) CleanupRecord(fqdn, value string) error {
	if s.readOnly {
		return ErrReadOnlyDatabase
	}
	_, err := s.Exec("DELETE FROM records WHERE fqdn = ? AND value = ?", fqdn, value)
	if err != nil {
		return err
	}
	return nil
}
