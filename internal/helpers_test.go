package dnspeek

import (
	"reflect"
	"strings"
	"testing"
)

func TestEnsurePort(t *testing.T) {
	tcs := []struct {
		in   string
		want string
	}{
		{"8.8.8.8", "8.8.8.8:53"},
		{"8.8.8.8:53", "8.8.8.8:53"},
		{"2001:db8::1", "[2001:db8::1]:53"},
		{"[2001:db8::1]:5353", "[2001:db8::1]:5353"},
	}

	for _, tc := range tcs {
		got := ensurePort(tc.in)
		if got != tc.want {
			t.Fatalf("ensurePort(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseRangeArg(t *testing.T) {
	tcs := []struct {
		in   string
		want []string
	}{
		{"192.0.2.0/30", []string{"192.0.2.1", "192.0.2.2"}},
		{"192.0.2.1-192.0.2.3", []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}},
		{"192.0.2.9", []string{"192.0.2.9"}},
	}

	for _, tc := range tcs {
		got, err := parseRangeArg(tc.in)
		if err != nil {
			t.Fatalf("parseRangeArg(%q) err=%v", tc.in, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("parseRangeArg(%q)=%v want %v", tc.in, got, tc.want)
		}
	}
}

func TestExpandRange(t *testing.T) {
	got, err := expandRange("192.0.2.1", "192.0.2.3")
	if err != nil {
		t.Fatalf("expandRange err=%v", err)
	}
	want := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expandRange=%v want %v", got, want)
	}
}

func TestUniqueStrings(t *testing.T) {
	got := uniqueStrings([]string{"a", "b", "a", "c", "b"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("uniqueStrings=%v want %v", got, want)
	}
}

func TestDedupeRecords(t *testing.T) {
	recs := []dnsRecord{
		{Type: "A", Name: "a", Address: "1.1.1.1"},
		{Type: "A", Name: "a", Address: "1.1.1.1"},
		{Type: "AAAA", Name: "a", Address: "2001:db8::1"},
	}
	got := dedupeRecords(recs)
	if len(got) != 2 {
		t.Fatalf("dedupeRecords len=%d want 2", len(got))
	}
}

func TestRenderRecord(t *testing.T) {
	rec := dnsRecord{
		Type:    "SRV",
		Name:    "_sip._tcp.example.com",
		Target:  "sip.example.com",
		Address: "192.0.2.10",
		Port:    5060,
		Note:    "ok",
	}
	got := renderRecord(rec)
	for _, part := range []string{
		"_sip._tcp.example.com",
		"sip.example.com",
		"192.0.2.10",
		"port 5060",
		"[ok]",
	} {
		if !strings.Contains(got, part) {
			t.Fatalf("renderRecord missing %q in %q", part, got)
		}
	}
}
