package dns

import (
	"errors"
	"testing"
)

func TestGetSpfRecord_Valid(t *testing.T) {
	testTxtRecord := "v=spf1 ip4:192.0.2.1/24 -all"
	txtLookupFunc = func(name string) ([]string, error) {
		return []string{"example-domain-verification=test1test1test1test1test1test1", testTxtRecord}, nil
	}
	defer func() { txtLookupFunc = nil }()

	d := NewDomain("example.test")
	record, err := d.GetSpfRecord()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if record != testTxtRecord {
		t.Errorf("unexpected record: %v", record)
	}
}

func TestGetSpfRecord_Invalid(t *testing.T) {
	testTxtRecord := "v=SPF1 ip4:192.0.2.1/24 -all"
	txtLookupFunc = func(name string) ([]string, error) {
		return []string{"example-domain-verification=test1test1test1test1test1test1", testTxtRecord}, nil
	}
	defer func() { txtLookupFunc = nil }()

	d := NewDomain("example.test")
	record, err := d.GetSpfRecord()

	if errors.Is(err, ErrorNoSpfRecord) {
		return
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if record != testTxtRecord {
		t.Errorf("unexpected record: %v", record)
	}

	t.Fatal("unexpected error")
}
