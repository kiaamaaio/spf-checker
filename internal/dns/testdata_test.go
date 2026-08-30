package dns

import (
	"context"
	"fmt"
	"net"
)

// fakeResolver serves dns answers from static maps so that evaluation can be
// tested without touching the network.
type fakeResolver struct {
	txt  map[string][]string
	ips  map[string][]net.IP
	mx   map[string][]*net.MX
	logs []string
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		txt: map[string][]string{},
		ips: map[string][]net.IP{},
		mx:  map[string][]*net.MX{},
	}
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.logs = append(f.logs, "txt:"+name)
	records, ok := f.txt[name]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", name)
	}
	return records, nil
}

func (f *fakeResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	f.logs = append(f.logs, "ip:"+host)
	addrs, ok := f.ips[host]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", host)
	}
	return addrs, nil
}

func (f *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	f.logs = append(f.logs, "mx:"+name)
	records, ok := f.mx[name]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", name)
	}
	return records, nil
}

func ips(addrs ...string) []net.IP {
	parsed := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		parsed = append(parsed, net.ParseIP(addr))
	}
	return parsed
}
