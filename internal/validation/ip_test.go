package validation

import (
	"errors"
	"net"
	"testing"
)

func TestParseIP(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantIP  net.IP
		wantErr bool
	}{
		{
			name:    "valid IPv4",
			input:   "192.0.2.1",
			wantIP:  net.ParseIP("192.0.2.1"),
			wantErr: false,
		},
		{
			name:    "valid IPv6",
			input:   "2001:db8::1",
			wantIP:  net.ParseIP("2001:db8::1"),
			wantErr: false,
		},
		{
			name:    "invalid IPv4",
			input:   "999.999.999.999",
			wantIP:  nil,
			wantErr: true,
		},
		{
			name:    "invalid IPv6",
			input:   "2001:zzzz::1",
			wantIP:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIP, err := ParseIP(tt.input)

			if tt.wantErr {
				if !errors.Is(err, ErrorInvalidIpAddress) {
					t.Errorf("unexpected error: %v", err)
				}
				if gotIP != nil {
					t.Errorf("expected nil ip(got: %v)", gotIP)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !gotIP.Equal(tt.wantIP) {
				t.Errorf("unexpected ip(want: %v, got: %v)", tt.wantIP, gotIP)
			}
		})
	}
}
