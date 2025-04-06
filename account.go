package acme

// Account represents an API user
type Account struct {
	Username   string
	Password   string
	Zone       string
	AllowedIPs CIDRList
}
