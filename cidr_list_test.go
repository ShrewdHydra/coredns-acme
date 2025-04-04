package acme

import "testing"

// TestCIDRListContains tests the CIDRList.contains method
func TestCIDRListContains(t *testing.T) {
	tests := []struct {
		name       string
		ipStr      string
		cidrList   CIDRList
		shouldPass bool
	}{
		{
			name:       "IP in list (exact match)",
			ipStr:      "192.168.1.1",
			cidrList:   CIDRList{"192.168.1.1"},
			shouldPass: true,
		},
		{
			name:       "IP in list (CIDR match)",
			ipStr:      "192.168.1.100",
			cidrList:   CIDRList{"192.168.1.0/24"},
			shouldPass: true,
		},
		{
			name:       "IP not in list",
			ipStr:      "192.168.2.1",
			cidrList:   CIDRList{"192.168.1.0/24"},
			shouldPass: false,
		},
		{
			name:       "IP with invalid CIDR in list",
			ipStr:      "192.168.1.1",
			cidrList:   CIDRList{"invalid/cidr"},
			shouldPass: false,
		},
		{
			name:       "IPv6 exact match",
			ipStr:      "2001:db8::1",
			cidrList:   CIDRList{"2001:db8::1"},
			shouldPass: true,
		},
		{
			name:       "IPv6 CIDR match",
			ipStr:      "2001:db8::1:2",
			cidrList:   CIDRList{"2001:db8::/64"},
			shouldPass: true,
		},
		{
			name:       "IPv6 not in list",
			ipStr:      "2001:db9::1",
			cidrList:   CIDRList{"2001:db8::/64"},
			shouldPass: false,
		},
		{
			name:       "Empty list",
			ipStr:      "192.168.1.1",
			cidrList:   CIDRList{},
			shouldPass: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.cidrList.contains(test.ipStr)
			if result != test.shouldPass {
				t.Errorf("Expected %v for IP %s with CIDR list %v, but got: %v",
					test.shouldPass, test.ipStr, test.cidrList, result)
			}
		})
	}
}
