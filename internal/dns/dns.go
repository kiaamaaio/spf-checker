package dns

import "net"

type Domain struct {
	name string
}

func NewDomain(name string) *Domain {
	return &Domain{name}
}

func (d *Domain) GetSpfRecords() ([]string, error) {
	txtRecords, err := net.LookupTXT(d.name)
	if err != nil {
		return nil, err
	}

	var spfRecords []string
	for _, txtRecord := range txtRecords {
		if len(txtRecord) >= 4 && txtRecord[:4] == "v=spf" {
			spfRecords = append(spfRecords, txtRecord)
		}
	}

	return spfRecords, nil
}
