// Package logsafe holds the renderings that keep untrusted text from acting as
// a GitHub Actions workflow command when it reaches a job log.
//
// It exists as its own package because more than one layer emits untrusted text
// — the detector's own diagnostics, the conclusion banners, and the forwarded
// engine subprocess stream — and those layers live in packages that do not
// otherwise depend on each other. A single definition here is what keeps them
// from drifting apart, which is exactly how a neutralization gap appears.
package logsafe

import "strings"

// LegacyCommandMarker is the runner's legacy workflow-command marker,
// "##[command]data". The Actions runner honors it in addition to the "::" form,
// and — unlike "::", which it accepts only at the start of a line (after
// trimming leading whitespace) — it locates this marker with an unanchored
// search. A legacy marker anywhere inside a log line is therefore a live
// command, so no line prefix, gutter, or indentation can render it inert: the
// value itself must be broken up. Reachable commands include add-mask (which
// redacts arbitrary text from the log) and stop-commands (which suppresses
// every later command, including the detector's own threat annotation).
const LegacyCommandMarker = "##["

// LegacyCommandMarkerEscaped is the inert rendering of LegacyCommandMarker. It
// keeps the sequence readable and greppable while breaking the runner's match.
const LegacyCommandMarkerEscaped = `##\[`

// EscapeLegacyCommandMarker renders every legacy workflow-command marker in s
// inert. It is safe to apply after other escaping passes as long as those
// passes cannot themselves synthesize a "##[" sequence.
func EscapeLegacyCommandMarker(s string) string {
	return strings.ReplaceAll(s, LegacyCommandMarker, LegacyCommandMarkerEscaped)
}
