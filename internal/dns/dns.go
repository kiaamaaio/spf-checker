package dns

import "net"

var spfVersion string = "v=spf1"

type Domain struct {
	name string
}

func NewDomain(name string) *Domain {
	return &Domain{name: name}
}

func (d *Domain) GetSpfRecords() ([]string, error) {
	txtRecords, err := net.LookupTXT(d.name)
	if err != nil {
		return nil, err
	}

	var spfRecords []string
	for _, txtRecord := range txtRecords {

		if len(txtRecord) >= 6 && txtRecord[:6] == spfVersion {
			spfRecords = append(spfRecords, txtRecord)
		}
	}

	return spfRecords, nil
}
