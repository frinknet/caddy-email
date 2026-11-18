package shared

import "testing"

func TestNormalizeAddress(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"a@b.com", "a@b.com", true},
		{"Name <a@b.com>", "a@b.com", true},
		{"\"A B\" <a@b.com>", "a@b.com", true},
		{"<a@b.com>", "a@b.com", true},
		{"", "", false},
		{"no-at-sign", "", false},
		{"a@b\r\nX-Injected: 1", "", false},
	}
	for _, tc := range cases {
		got, ok := NormalizeAddress(tc.in)
		if ok != tc.ok {
			t.Errorf("NormalizeAddress(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("NormalizeAddress(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidAddressStillAcceptsDisplayName(t *testing.T) {
	// ValidAddress is about well-formedness, not envelope form; NormalizeAddress
	// is what callers use to strip the display name.
	if !ValidAddress("Name <a@b.com>") {
		t.Error("ValidAddress should accept a display-name address")
	}
}
