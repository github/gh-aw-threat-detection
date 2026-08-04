package detector

import "strings"

// Host-side reason codes reported by the conclude subcommand and consumed by
// gh-aw's job-output contract (threat_detection_warning.cjs). They are mirrored
// here so the standalone detector and the gh-aw inline path categorize
// outcomes identically.
const (
	// ReasonThreatDetected marks a real security finding recorded by the
	// detection engine.
	ReasonThreatDetected = "threat_detected"
	// ReasonAgentFailure marks a tooling failure where the detection engine
	// itself never produced a verdict.
	ReasonAgentFailure = "agent_failure"
	// ReasonParseError marks a tooling failure where a verdict was expected
	// but could not be read or parsed.
	ReasonParseError = "parse_error"
)

// Markers embedded in rendered detection output so automated scanners can tell
// an infrastructure failure apart from an actual security finding. They mirror
// gh-aw's getThreatDetectedMarker/getThreatEngineErrorMarker exactly.
const (
	// ThreatDetectedMarker identifies output describing a real threat verdict.
	ThreatDetectedMarker = "<!-- gh-aw-threat-detected -->"
	// ThreatEngineErrorMarker identifies output describing a detection tooling
	// failure rather than a security finding.
	ThreatEngineErrorMarker = "<!-- gh-aw-threat-engine-error -->"
)

// IsToolingFailureReason reports whether reason indicates a tooling failure
// rather than an actual security finding. Tooling failures (agent_failure,
// parse_error) mean the detection engine itself crashed or could not produce a
// verdict, and must be surfaced as a distinct infrastructure error so scanners
// and reviewers do not treat them as threats.
func IsToolingFailureReason(reason string) bool {
	switch strings.TrimSpace(reason) {
	case ReasonAgentFailure, ReasonParseError:
		return true
	default:
		return false
	}
}

// ThreatMarker returns the marker matching reason: the engine-error marker for
// tooling failures, the threat marker for a recorded threat verdict, and an
// empty string for outcomes that describe neither (success, skipped, or an
// unrecognized reason).
func ThreatMarker(reason string) string {
	if IsToolingFailureReason(reason) {
		return ThreatEngineErrorMarker
	}
	if strings.TrimSpace(reason) == ReasonThreatDetected {
		return ThreatDetectedMarker
	}
	return ""
}

// ThreatHeadline returns the human-readable one-line headline for reason, used
// as the step-summary disclosure title and echoed into the job log. It mirrors
// gh-aw's engine-error and caution templates so both paths read identically.
func ThreatHeadline(reason string) string {
	switch {
	case IsToolingFailureReason(reason):
		return "Threat Detection Engine Failure — The analysis engine could not complete. This is a tooling failure, not a security finding."
	case strings.TrimSpace(reason) == ReasonThreatDetected:
		return "Agentic threat detected — Manual review is REQUIRED before any follow-up automation."
	default:
		return ""
	}
}
