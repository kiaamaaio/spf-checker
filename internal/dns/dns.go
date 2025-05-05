package dns

import "net"

var spfVersion string = "v=spf1"
var txtLookupFunc = net.LookupTXT

type Domain struct {
	name string
}

func NewDomain(name string) *Domain {
	return &Domain{name: name}
}

func (d *Domain) GetSpfRecord() (string, error) {
	txtRecords, err := txtLookupFunc(d.name)
	if err != nil {
		return "", err
	}

	var spfRecord string
	for _, txtRecord := range txtRecords {

		if len(txtRecord) >= 6 && txtRecord[:6] == spfVersion {
			spfRecord = txtRecord
		}
	}

	return spfRecord, nil
}
