package validation

import "net"

var parseIPFunc = net.ParseIP

func ParseIP(ipaddr string) (net.IP, error) {
	parsedIP := parseIPFunc(ipaddr)
	if parsedIP == nil {
		return nil, ErrorInvalidIpAddress
	}
	return parsedIP, nil
}
