package validation

import (
	"strings"
	"testing"
)

func TestValidateDnsRecordName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid domain", "example.com", false},
		{"valid trailing dot", "example.com.", false},
		{"valid underscore prefix", "_spf.example.com", false},
		{"valid underscore mid", "test_spf.example.com", false},
		{"invalid label too long", strings.Repeat("a", 64) + ".com", true},
		{"invalid total length", strings.Repeat("a.", 127) + "com", true},
		{"invalid character", "exam$ple.com", true},
		{"empty label", "example..com", true},
		{"starts with hyphen", "-abc.example.com", true},
		{"ends with hyphen", "abc-.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDnsRecordName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error: %v(input: %s, got: %v)", err, tt.input, tt.wantErr)
			}
		})
	}
}
