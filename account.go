package acme

import (
	"crypto/rand"
	"math/big"

	"github.com/google/uuid"
)

// Account represents an API user
type Account struct {
	Username   string
	Password   string
	Zone       string
	AllowedIPs CIDRList
}

// func NewAccount() (Account, error) {
// 	// Generate a UUID-based username
// 	username, err := generateUUID()
// 	if err != nil {
// 		log.Warningf("NewAccount: Failed to generate UUID username: %v", err)
// 		return Account{}, err
// 	}

// 	// Generate a secure random password
// 	password, err := generateRandomString(40)
// 	if err != nil {
// 		log.Warningf("NewAccount: Failed to generate password: %v", err)
// 		return Account{}, err
// 	}

// 	// Generate a UUID-based subdomain
// 	subdomain, err := generateUUID()
// 	if err != nil {
// 		log.Warningf("NewAccount: Failed to generate subdomain: %v", err)
// 		return Account{}, err
// 	}

// 	return Account{
// 		Username: username,
// 		Password: password,
// 		Zone:     subdomain,
// 	}, nil
// }

// generateUUID generates a UUID string
func generateUUID() (string, error) {
	// Generate UUID v4
	id, err := uuid.NewRandom()
	if err != nil {
		log.Warningf("Failed to generate UUID: %v", err)
		return "", err
	}

	return id.String(), nil
}

// generateRandomString generates a random string of the specified length
func generateRandomString(length int) (string, error) {
	log.Debugf("Generating random string of length %d", length)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-_"
	ret := make([]byte, length)
	alphalen := big.NewInt(int64(len(alphabet)))

	for i := 0; i < length; i++ {
		c, err := rand.Int(rand.Reader, alphalen)
		if err != nil {
			return "", err
		}
		ret[i] = alphabet[c.Int64()]
	}

	return string(ret), nil
}
