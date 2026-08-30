package dns

import (
	"context"
	"errors"
	"testing"
)

func TestGetSpfRecord(t *testing.T) {
	const spfRecord = "v=spf1 ip4:192.0.2.1/24 -all"

	tests := []struct {
		name    string
		records []string
		want    string
		wantErr error
	}{
		{
			name:    "picks the spf record out of other txt records",
			records: []string{"example-domain-verification=test1test1test1", spfRecord},
			want:    spfRecord,
		},
		{
			name:    "version token is case insensitive",
			records: []string{"V=SPF1 ip4:192.0.2.1/24 -all"},
			want:    "V=SPF1 ip4:192.0.2.1/24 -all",
		},
		{
			name:    "no spf record among the txt records",
			records: []string{"example-domain-verification=test1test1test1"},
			wantErr: ErrNoSpfRecord,
		},
		{
			name:    "v=spf10 is not an spf record",
			records: []string{"v=spf10 ip4:192.0.2.1/24 -all"},
			wantErr: ErrNoSpfRecord,
		},
		{
			name:    "more than one spf record is a permanent error",
			records: []string{spfRecord, "v=spf1 ip4:198.51.100.0/24 -all"},
			wantErr: ErrMultipleSpfRecords,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := newFakeResolver()
			resolver.txt["example.test"] = tt.records

			got, err := NewDomainWithResolver("example.test", resolver).GetSpfRecord(context.Background())

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("want error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("want %q, got %q", tt.want, got)
			}
		})
	}
}

func TestGetSpfRecordLookupFailure(t *testing.T) {
	resolver := newFakeResolver()

	_, err := NewDomainWithResolver("missing.test", resolver).GetSpfRecord(context.Background())

	if !errors.Is(err, ErrNoTxtRecord) {
		t.Fatalf("want error %v, got %v", ErrNoTxtRecord, err)
	}
}
