package validation

import "net"

// ParseIP parses ipaddr and returns ErrInvalidIpAddress when it is not a
// valid IPv4 or IPv6 address.
func ParseIP(ipaddr string) (net.IP, error) {
	parsedIP := net.ParseIP(ipaddr)
	if parsedIP == nil {
		return nil, ErrInvalidIpAddress
	}
	return parsedIP, nil
}
