package acme

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v3"
)

// Key prefixes for BadgerDB
const (
	recordKeyPrefix  = "record:"
	accountKeyPrefix = "account:"
)

// BadgerDB is an implementation of the DB interface using Badger
type BadgerDB struct {
	db *badger.DB
}

// NewBadgerDB creates a new BadgerDB instance
func NewBadgerDB(path string) (*BadgerDB, error) {
	return NewBadgerDBWithROOption(path, false)
}

// NewBadgerDBWithROOption creates a new BadgerDB instance with specified read-only option
func NewBadgerDBWithROOption(path string, readOnly bool) (*BadgerDB, error) {
	opts := badger.DefaultOptions(path)
	opts.Logger = nil // Disable Badger's default logger
	opts.ReadOnly = readOnly
	opts.BypassLockGuard = readOnly

	log.Debugf("Opening BadgerDB at %s (readOnly: %v)", path, readOnly)

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open BadgerDB: %w", err)
	}

	// Run garbage collection in background (only for read-write databases)
	if !readOnly {
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
			again:
				err := db.RunValueLogGC(0.5)
				if err == nil {
					goto again
				}
			}
		}()
	}

	return &BadgerDB{db: db}, nil
}

// Close closes the BadgerDB database
func (b *BadgerDB) Close() error {
	return b.db.Close()
}

// makeRecordKey generates a key for a DNS record by fqdn and value
func makeRecordKey(fqdn, value string) []byte {
	return []byte(recordKeyPrefix + fqdn + ":" + value)
}

// makeAccountKey generates a key for an account by username and zone
func makeAccountKey(username, zone string) []byte {
	return []byte(accountKeyPrefix + username + ":" + zone)
}

// RegisterAccount adds or updates an account
func (b *BadgerDB) RegisterAccount(account Account, hashedPassword []byte) error {
	accountKey := makeAccountKey(account.Username, account.Zone)

	account.Password = string(hashedPassword)
	accountBytes, err := json.Marshal(account)
	if err != nil {
		return err
	}

	return b.db.Update(func(txn *badger.Txn) error {
		return txn.Set(accountKey, accountBytes)
	})
}

// GetAccount retrieves an account by username and zone
func (b *BadgerDB) GetAccount(username, zone string) (Account, error) {
	var account Account

	accountKey := makeAccountKey(username, zone)
	err := b.db.View(func(txn *badger.Txn) error {
		// First try exact match on username:zone
		item, err := txn.Get(accountKey)

		if err == nil {
			return item.Value(func(val []byte) error {
				return json.Unmarshal(val, &account)
			})
		}

		if err != badger.ErrKeyNotFound {
			return err
		}

		// Prefix scan for username:zone* keys
		zonePrefixKey := makeAccountKey(username, "")
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false

		it := txn.NewIterator(opts)
		defer it.Close()

		var bestMatch []byte
		var bestMatchLen int

		// Find all keys for this username
		for it.Seek(zonePrefixKey); it.ValidForPrefix(zonePrefixKey); it.Next() {
			item := it.Item()
			key := item.KeyCopy(nil)

			accountZone := "." + string(key[len(zonePrefixKey):])

			// If the zone ends with the query zone, it's a potential match
			if strings.HasSuffix(zone, accountZone) && len(accountZone) > bestMatchLen {
				bestMatch = key
				bestMatchLen = len(accountZone)
			}
		}

		if bestMatch == nil {
			return ErrRecordNotFound
		}

		item, err = txn.Get(bestMatch)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &account)
		})
	})

	if err != nil {
		return Account{}, err
	}

	if account.Username == "" {
		return account, ErrRecordNotFound
	}

	return account, nil
}

// GetRecords retrieves all TXT values for a given FQDN
func (b *BadgerDB) GetRecords(fqdn string) ([]string, error) {
	var records []string

	prefix := makeRecordKey(fqdn, "")
	err := b.db.View(func(txn *badger.Txn) error {
		iopt := badger.DefaultIteratorOptions
		iopt.PrefetchValues = false

		it := txn.NewIterator(iopt)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := item.Key()
			records = append(records, string(key[len(prefix):]))
		}
		return nil
	})

	if len(records) == 0 {
		return nil, ErrRecordNotFound
	}

	return records, err
}

// PresentRecord adds a TXT record for a FQDN
func (b *BadgerDB) PresentRecord(fqdn, value string) error {
	return b.db.Update(func(txn *badger.Txn) error {
		return txn.Set(makeRecordKey(fqdn, value), nil)
	})
}

// CleanupRecord removes a TXT record for a FQDN
func (b *BadgerDB) CleanupRecord(fqdn, value string) error {
	return b.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(makeRecordKey(fqdn, value))
	})
}
