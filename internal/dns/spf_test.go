package dns

import (
	"testing"
)

func TestSpfCheck(t *testing.T) {
	tests := []struct {
		txtRecord string
		ip        string
		want      bool
	}{
		{
			txtRecord: "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 ~all",
			ip:        "192.0.2.1",
			want:      true,
		},
		{
			txtRecord: "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 ~all",
			ip:        "203.0.113.5",
			want:      false,
		},
		{
			txtRecord: "v=spf1 ip4:198.51.100.0/24 ~all",
			ip:        "198.51.100.42",
			want:      true,
		},
		{
			txtRecord: "v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 ~all",
			ip:        "2001:db8::1",
			want:      true,
		},
	}

	for _, tt := range tests {
		sr := NewSpfRecord(tt.txtRecord)
		got, err := sr.Check(tt.ip)
		if err != nil {
			t.Errorf("Check(%s) returned error: %v", tt.ip, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Check(%s) = %v; want %v", tt.ip, got, tt.want)
		}
	}
}
