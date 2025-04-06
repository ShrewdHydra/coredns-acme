package acme

import "errors"

var (
	ErrRecordNotFound   = errors.New("record not found")
	ErrReadOnlyDatabase = errors.New("database is in read-only mode")
)

// DB interface for different database backends
type DB interface {
	GetRecords(fqdn string) ([]string, error)
	PresentRecord(fqdn string, value string) error
	CleanupRecord(fqdn string, value string) error
	RegisterAccount(account Account, hashedPassword []byte) error
	GetAccount(username, zone string) (Account, error)
	Close() error
}
