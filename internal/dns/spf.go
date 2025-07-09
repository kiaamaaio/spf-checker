package dns

import (
	"net"
	"spf-checker/internal/validation"
	"strings"
)

var mechanismIp4 string = "ip4:"
var mechanismIp6 string = "ip6:"
var mechanismInclude string = "include:"

type SpfRecord struct {
	txt      string
	ip4      []string
	ip6      []string
	includes []string
}

func NewSpfRecord(txtRecord string) *SpfRecord {
	var ip4, ip6, includes []string

	for _, value := range strings.Fields(txtRecord) {
		switch {
		case strings.HasPrefix(value, mechanismIp4):
			ip4 = append(ip4, value[4:])
		case strings.HasPrefix(value, mechanismIp6):
			ip6 = append(ip6, value[4:])
		case strings.HasPrefix(value, mechanismInclude):
			includes = append(includes, value[8:])
		}
	}

	return &SpfRecord{txt: txtRecord, ip4: ip4, ip6: ip6, includes: includes}
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

func (sr *SpfRecord) ContainsIPRecursive(ipaddr string, visited map[string]struct{}) (bool, error) {
	found, err := sr.ContainsIP(ipaddr)
	if err != nil || found {
		return found, err
	}

	for _, included := range sr.includes {
		if _, ok := visited[included]; ok {
			continue
		}
		visited[included] = struct{}{}

		d := NewDomain(included)
		txt, err := d.GetSpfRecord()
		if err != nil {
			continue
		}

		child := NewSpfRecord(txt)
		found, err := child.ContainsIPRecursive(ipaddr, visited)
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
	}
	return false, nil
}
