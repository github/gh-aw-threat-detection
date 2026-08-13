package logsafe

import "testing"

func TestEscapeLegacyCommandMarker(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no marker", "plain text ## [not a marker]", "plain text ## [not a marker]"},
		{"leading marker", "##[add-mask]secret", `##\[add-mask]secret`},
		{"mid-line marker", "evidence: x ##[stop-commands]tok", `evidence: x ##\[stop-commands]tok`},
		{"repeated markers", "##[a]##[b]", `##\[a]##\[b]`},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EscapeLegacyCommandMarker(tc.in); got != tc.want {
				t.Errorf("EscapeLegacyCommandMarker(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestEscapedMarkerIsInert guards the property the escaping exists for: no
// escaped output may still contain a sequence the runner would match.
func TestEscapedMarkerIsInert(t *testing.T) {
	// A value crafted so that naively deleting the marker would splice a new
	// one back together must still come out inert.
	got := EscapeLegacyCommandMarker("###[##[[error]")
	if contains(got, LegacyCommandMarker) {
		t.Fatalf("escaped value still carries a live marker: %q", got)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
