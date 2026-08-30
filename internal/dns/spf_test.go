package dns

import (
	"testing"
)

// TestParseSpfRecordMechanisms は、修飾子の分離と mechanism 名の
// 大文字小文字の扱いを検証する。どちらも修正前は誤っており、
// 修飾子付きの項目が丸ごと無視されていた。
func TestParseSpfRecordMechanisms(t *testing.T) {
	record := ParseSpfRecord("v=spf1 ip4:192.0.2.0/24 -ip4:198.51.100.1 IP6:2001:db8::/32 ~all")

	if len(record.Mechanisms) != 4 {
		t.Fatalf("want 4 mechanisms, got %d (%+v)", len(record.Mechanisms), record.Mechanisms)
	}
	if len(record.Unknown) != 0 {
		t.Errorf("unexpected unknown terms: %v", record.Unknown)
	}

	tests := []struct {
		index     int
		name      string
		value     string
		qualifier Qualifier
	}{
		{0, MechanismIP4, "192.0.2.0/24", QualifierPass},
		{1, MechanismIP4, "198.51.100.1", QualifierFail},
		{2, MechanismIP6, "2001:db8::/32", QualifierPass},
		{3, MechanismAll, "", QualifierSoftFail},
	}
	for _, tt := range tests {
		got := record.Mechanisms[tt.index]
		if got.Name != tt.name || got.Value != tt.value || got.Qualifier != tt.qualifier {
			t.Errorf("mechanism %d = %+v; want name=%s value=%s qualifier=%c",
				tt.index, got, tt.name, tt.value, tt.qualifier)
		}
	}
}

// TestParseSpfRecordDualCidrLength は、a/mx に続く
// ["/" ip4-len] ["//" ip6-len] の各組み合わせを解析できることを検証する。
func TestParseSpfRecordDualCidrLength(t *testing.T) {
	tests := []struct {
		term        string
		wantValue   string
		wantPrefix4 int
		wantPrefix6 int
	}{
		{"a", "", -1, -1},
		{"a/24", "", 24, -1},
		{"a//64", "", -1, 64},
		{"a/24//64", "", 24, 64},
		{"a:mail.example.com", "mail.example.com", -1, -1},
		{"a:mail.example.com/24//64", "mail.example.com", 24, 64},
		{"mx/16", "", 16, -1},
	}

	for _, tt := range tests {
		t.Run(tt.term, func(t *testing.T) {
			record := ParseSpfRecord("v=spf1 " + tt.term + " -all")
			if len(record.Unknown) != 0 {
				t.Fatalf("term %q was not parsed: %v", tt.term, record.Unknown)
			}
			got := record.Mechanisms[0]
			if got.Value != tt.wantValue || got.Prefix4 != tt.wantPrefix4 || got.Prefix6 != tt.wantPrefix6 {
				t.Errorf("got %+v; want value=%q prefix4=%d prefix6=%d",
					got, tt.wantValue, tt.wantPrefix4, tt.wantPrefix6)
			}
		})
	}
}

// TestParseSpfRecordModifiers は、redirect= と exp= を modifier として
// 扱い、mechanism と取り違えないことを検証する。
func TestParseSpfRecordModifiers(t *testing.T) {
	record := ParseSpfRecord("v=spf1 include:_spf.example.com redirect=_spf.example.org exp=why.example.com")

	if record.Redirect != "_spf.example.org" {
		t.Errorf("want redirect _spf.example.org, got %q", record.Redirect)
	}
	if record.Exp != "why.example.com" {
		t.Errorf("want exp why.example.com, got %q", record.Exp)
	}
	if len(record.Mechanisms) != 1 || record.Mechanisms[0].Name != MechanismInclude {
		t.Errorf("want a single include mechanism, got %+v", record.Mechanisms)
	}
}

// TestParseSpfRecordUnknownTerms は、解釈できない項目を Unknown に
// 集めたうえで、残りの項目の解析を続けることを検証する。
func TestParseSpfRecordUnknownTerms(t *testing.T) {
	record := ParseSpfRecord("v=spf1 ip4:192.0.2.0/24 bogus ip4 include: -all")

	want := []string{"bogus", "ip4", "include:"}
	if len(record.Unknown) != len(want) {
		t.Fatalf("want unknown %v, got %v", want, record.Unknown)
	}
	for i, term := range want {
		if record.Unknown[i] != term {
			t.Errorf("unknown[%d] = %q; want %q", i, record.Unknown[i], term)
		}
	}
}
