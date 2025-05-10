package dns

import (
	"net"
	"spf-checker/internal/validation"
	"strings"
)

var mechanismIp4 string = "ip4:"
var mechanismIp6 string = "ip6:"

type SpfRecord struct {
	txt string
	ip4 []string
	ip6 []string
}

func NewSpfRecord(txtRecord string) *SpfRecord {
	var ip4 []string
	var ip6 []string

	for _, value := range strings.Fields(txtRecord) {
		if value[:4] == mechanismIp4 {
			ip4 = append(ip4, value[4:])
		}
		if value[:4] == mechanismIp6 {
			ip6 = append(ip6, value[4:])
		}
	}

	return &SpfRecord{txt: txtRecord, ip4: ip4, ip6: ip6}
}

func (sr *SpfRecord) ContainsIP(ipaddr string) (bool, error) {
	spfIpaddrs := append(sr.ip4, sr.ip6...)

	parsedIpAddr, err := validation.ParseIP(ipaddr)
	if err != nil {
		return false, err
	}

	for _, spfIpaddr := range spfIpaddrs {
		_, ipNet, err := net.ParseCIDR(spfIpaddr)
		if err != nil {
			return false, err
		}
		if ipNet.Contains(parsedIpAddr) {
			return true, nil
		}
	}

	return false, nil
}
