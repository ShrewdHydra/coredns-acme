package acme

import (
	"net"
	"strings"
)

type CIDRList []string

// NewCIDRList creates a new CIDRList from a comma-separated string
func NewCIDRList(cidrs string) CIDRList {
	if cidrs == "" {
		return nil
	}

	// Split by comma and trim whitespace
	parts := strings.Split(cidrs, ",")
	result := make(CIDRList, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

// String returns a comma-separated string of CIDR entries
func (c *CIDRList) String() string {
	return strings.Join(*c, ",")
}

func (c *CIDRList) isValid() bool {
	for _, cidr := range *c {
		if !isValidCIDR(cidr) && !isValidIP(cidr) {
			return false
		}
	}
	return true
}

func (c *CIDRList) contains(ip string) bool {
	// If the list is empty, all IPs are allowed
	if len(*c) == 0 {
		return true
	}

	for _, cidr := range *c {
		if cidr == ip {
			return true
		}

		if strings.Contains(cidr, "/") {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Warningf("CIDRList: Failed to parse CIDR %s: %v", cidr, err)
				continue
			}

			ip := net.ParseIP(ip)
			if ip != nil && ipNet.Contains(ip) {
				return true
			}
		}
	}
	return false
}
