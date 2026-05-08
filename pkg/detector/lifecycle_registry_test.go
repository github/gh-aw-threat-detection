package detector

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

var semverTagPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type lifecycleRegistry struct {
	SchemaVersion        string           `json:"schema_version"`
	LastUpdated          string           `json:"last_updated"`
	UnknownVersionPolicy string           `json:"unknown_version_policy"`
	Versions             []lifecycleEntry `json:"versions"`
}

type lifecycleEntry struct {
	Version            string `json:"version"`
	ImageDigest        string `json:"image_digest"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	ReplacementVersion string `json:"replacement_version"`
	ReplacementKind    string `json:"replacement_kind"`
	ReplacementDigest  string `json:"replacement_digest"`
	DeprecatedDate     string `json:"deprecated_date"`
	ObsoleteDate       string `json:"obsolete_date"`
	YankedDate         string `json:"yanked_date"`
	AdvisoryURL        string `json:"advisory_url"`
	Severity           string `json:"severity"`
	Urgency            string `json:"urgency"`
	MaintainerNote     string `json:"maintainer_note"`
	NoSafeReplacement  bool   `json:"no_safe_replacement"`
}

func TestThreatDetectionLifecycleRegistry(t *testing.T) {
	path := filepath.Join("..", "..", "releases", "threat-detection-lifecycle.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read lifecycle registry: %v", err)
	}

	var registry lifecycleRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		t.Fatalf("parse lifecycle registry JSON: %v", err)
	}

	if err := validateLifecycleRegistry(registry); err != nil {
		t.Fatal(err)
	}
}

func TestValidateLifecycleRegistry(t *testing.T) {
	validRegistry := lifecycleRegistry{
		SchemaVersion:        "1.0.0",
		LastUpdated:          "2026-05-07",
		UnknownVersionPolicy: "fail-closed",
		Versions: []lifecycleEntry{
			{
				Version:         "v1.1.0",
				Status:          "active",
				Reason:          "Supported release.",
				ReplacementKind: "none",
				AdvisoryURL:     "https://github.com/github/gh-aw-threat-detection/releases/tag/v1.1.0",
				Urgency:         "none",
				MaintainerNote:  "Current default release.",
			},
			{
				Version:            "v1.0.0",
				Status:             "deprecated",
				Reason:             "Superseded by v1.1.0.",
				ReplacementVersion: "v1.1.0",
				ReplacementKind:    "registry",
				DeprecatedDate:     "2026-05-07",
				AdvisoryURL:        "https://github.com/github/gh-aw-threat-detection/releases/tag/v1.1.0",
				Urgency:            "medium",
				MaintainerNote:     "Warn users and continue.",
			},
			{
				Version:            "v0.9.0",
				Status:             "obsolete",
				Reason:             "Known incompatible output contract.",
				ReplacementVersion: "v1.1.0",
				ReplacementKind:    "registry",
				DeprecatedDate:     "2026-04-01",
				ObsoleteDate:       "2026-05-07",
				AdvisoryURL:        "https://github.com/github/gh-aw-threat-detection/releases/tag/v1.1.0",
				Urgency:            "high",
				MaintainerNote:     "Fail closed before detector execution.",
			},
			{
				Version:            "v0.8.0",
				ImageDigest:        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Status:             "yanked",
				Reason:             "Unsafe detector behavior.",
				ReplacementVersion: "v1.1.0",
				ReplacementKind:    "registry",
				ReplacementDigest:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				YankedDate:         "2026-05-07",
				AdvisoryURL:        "https://github.com/github/gh-aw-threat-detection/releases/tag/v1.1.0",
				Severity:           "high",
				Urgency:            "high",
				MaintainerNote:     "Fail closed before detector execution.",
			},
		},
	}

	tests := []struct {
		name    string
		mutate  func(*lifecycleRegistry)
		wantErr bool
	}{
		{
			name: "valid registry",
		},
		{
			name: "duplicate version",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions = append(registry.Versions, registry.Versions[0])
			},
			wantErr: true,
		},
		{
			name: "invalid status",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions[0].Status = "retired"
			},
			wantErr: true,
		},
		{
			name: "leading zero version component",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions[0].Version = "v01.2.3"
			},
			wantErr: true,
		},
		{
			name: "deprecated version missing replacement",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions[1].ReplacementVersion = ""
			},
			wantErr: true,
		},
		{
			name: "obsolete version missing reason",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions[2].Reason = ""
			},
			wantErr: true,
		},
		{
			name: "obsolete date before deprecated date",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions[2].DeprecatedDate = "2026-05-07"
				registry.Versions[2].ObsoleteDate = "2026-05-06"
			},
			wantErr: true,
		},
		{
			name: "obsolete date may match deprecated date",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions[2].DeprecatedDate = "2026-05-07"
				registry.Versions[2].ObsoleteDate = "2026-05-07"
			},
		},
		{
			name: "invalid calendar date",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions[2].ObsoleteDate = "2026-99-99"
			},
			wantErr: true,
		},
		{
			name: "registry replacement must exist",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions[1].ReplacementVersion = "v2.0.0"
			},
			wantErr: true,
		},
		{
			name: "future replacement may be outside registry",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions[1].ReplacementVersion = "v2.0.0"
				registry.Versions[1].ReplacementKind = "future"
			},
		},
		{
			name: "future replacement rejects leading zero version component",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions[1].ReplacementVersion = "v02.0.0"
				registry.Versions[1].ReplacementKind = "future"
			},
			wantErr: true,
		},
		{
			name: "external replacement may be outside registry",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions[1].ReplacementVersion = "https://github.com/github/gh-aw/releases"
				registry.Versions[1].ReplacementKind = "external"
			},
		},
		{
			name: "unknown version policy must fail closed",
			mutate: func(registry *lifecycleRegistry) {
				registry.UnknownVersionPolicy = "warn"
			},
			wantErr: true,
		},
		{
			name: "yanked version missing image digest",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions[3].ImageDigest = ""
			},
			wantErr: true,
		},
		{
			name: "yanked version missing reason",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions[3].Reason = ""
			},
			wantErr: true,
		},
		{
			name: "yanked replacement cannot be obsolete",
			mutate: func(registry *lifecycleRegistry) {
				registry.Versions[3].ReplacementVersion = "v0.9.0"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := validRegistry
			registry.Versions = append([]lifecycleEntry(nil), validRegistry.Versions...)
			if tt.mutate != nil {
				tt.mutate(&registry)
			}

			err := validateLifecycleRegistry(registry)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateLifecycleRegistry() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidSemverTagAcceptsPrereleaseAndBuild(t *testing.T) {
	if !validSemverTag("v1.2.3-alpha.1+build.5") {
		t.Fatal("expected prerelease and build metadata semver tag to be valid")
	}
}

func validateLifecycleRegistry(registry lifecycleRegistry) error {
	if registry.SchemaVersion == "" {
		return fmt.Errorf("schema_version is required")
	}
	if !validDate(registry.LastUpdated) {
		return fmt.Errorf("last_updated must use YYYY-MM-DD")
	}
	if registry.UnknownVersionPolicy != "fail-closed" {
		return fmt.Errorf("unknown_version_policy must be fail-closed")
	}
	if len(registry.Versions) == 0 {
		return fmt.Errorf("at least one lifecycle entry is required")
	}

	versions := make(map[string]lifecycleEntry, len(registry.Versions))
	for _, entry := range registry.Versions {
		if entry.Version == "" {
			return fmt.Errorf("version is required")
		}
		if !validSemverTag(entry.Version) {
			return fmt.Errorf("version %q must be a semantic version tag like v1.2.3", entry.Version)
		}
		if _, ok := versions[entry.Version]; ok {
			return fmt.Errorf("duplicate lifecycle entry for %s", entry.Version)
		}
		versions[entry.Version] = entry
	}

	for _, entry := range registry.Versions {
		if err := validateLifecycleEntry(entry, versions); err != nil {
			return err
		}
	}

	return nil
}

func validateLifecycleEntry(entry lifecycleEntry, versions map[string]lifecycleEntry) error {
	allowedStatuses := map[string]struct{}{
		"active":     {},
		"deprecated": {},
		"obsolete":   {},
		"yanked":     {},
	}
	if _, ok := allowedStatuses[entry.Status]; !ok {
		return fmt.Errorf("%s has unsupported status %q", entry.Version, entry.Status)
	}

	if entry.ImageDigest != "" && !digestPattern.MatchString(entry.ImageDigest) {
		return fmt.Errorf("%s image_digest must be sha256:<64 lowercase hex characters>", entry.Version)
	}
	if entry.Reason == "" {
		return fmt.Errorf("%s must include a reason", entry.Version)
	}
	if entry.MaintainerNote == "" {
		return fmt.Errorf("%s must include a maintainer_note", entry.Version)
	}
	if !validUrgency(entry.Urgency) {
		return fmt.Errorf("%s has unsupported urgency %q", entry.Version, entry.Urgency)
	}
	if !validHTTPURL(entry.AdvisoryURL) {
		return fmt.Errorf("%s must include an advisory_url or release URL", entry.Version)
	}
	if entry.DeprecatedDate != "" && !validDate(entry.DeprecatedDate) {
		return fmt.Errorf("%s deprecated_date must use YYYY-MM-DD", entry.Version)
	}
	if entry.ObsoleteDate != "" && !validDate(entry.ObsoleteDate) {
		return fmt.Errorf("%s obsolete_date must use YYYY-MM-DD", entry.Version)
	}

	switch entry.Status {
	case "active":
		if entry.ReplacementKind != "none" || entry.ReplacementVersion != "" {
			return fmt.Errorf("%s active entries must not specify replacement guidance", entry.Version)
		}
		if entry.DeprecatedDate != "" || entry.ObsoleteDate != "" {
			return fmt.Errorf("%s active entries must not specify deprecated or obsolete dates", entry.Version)
		}
	case "deprecated":
		if entry.DeprecatedDate == "" {
			return fmt.Errorf("%s deprecated entries must include deprecated_date", entry.Version)
		}
		if err := validateReplacement(entry, versions); err != nil {
			return err
		}
	case "obsolete":
		if entry.DeprecatedDate == "" || entry.ObsoleteDate == "" {
			return fmt.Errorf("%s obsolete entries must include deprecated_date and obsolete_date", entry.Version)
		}
		deprecatedDate, ok := parseLifecycleDate(entry.DeprecatedDate)
		if !ok {
			return fmt.Errorf("%s deprecated_date must use YYYY-MM-DD", entry.Version)
		}
		obsoleteDate, ok := parseLifecycleDate(entry.ObsoleteDate)
		if !ok {
			return fmt.Errorf("%s obsolete_date must use YYYY-MM-DD", entry.Version)
		}
		if obsoleteDate.Before(deprecatedDate) {
			return fmt.Errorf("%s obsolete_date must be on or after deprecated_date", entry.Version)
		}
		if err := validateReplacement(entry, versions); err != nil {
			return err
		}
	case "yanked":
		if entry.ImageDigest == "" {
			return fmt.Errorf("%s yanked entries must include image_digest", entry.Version)
		}
		if !validDate(entry.YankedDate) {
			return fmt.Errorf("%s yanked_date must use YYYY-MM-DD", entry.Version)
		}
		if !validSeverity(entry.Severity) {
			return fmt.Errorf("%s has unsupported severity %q", entry.Version, entry.Severity)
		}
		if entry.NoSafeReplacement {
			if entry.ReplacementVersion != "" || entry.ReplacementDigest != "" || entry.ReplacementKind != "" {
				return fmt.Errorf("%s cannot set replacement guidance when no_safe_replacement is true", entry.Version)
			}
		} else {
			if err := validateReplacement(entry, versions); err != nil {
				return err
			}
			if !digestPattern.MatchString(entry.ReplacementDigest) {
				return fmt.Errorf("%s replacement_digest must be sha256:<64 lowercase hex characters>", entry.Version)
			}
			if replacement, ok := versions[entry.ReplacementVersion]; ok {
				if replacement.Status == "yanked" || replacement.Status == "obsolete" {
					return fmt.Errorf("%s replacement_version %s is %s", entry.Version, replacement.Version, replacement.Status)
				}
				if replacement.ImageDigest != "" && entry.ReplacementDigest != replacement.ImageDigest {
					return fmt.Errorf("%s replacement_digest does not match %s image_digest", entry.Version, replacement.Version)
				}
			}
		}
	}

	return nil
}

func validateReplacement(entry lifecycleEntry, versions map[string]lifecycleEntry) error {
	if entry.ReplacementVersion == "" {
		return fmt.Errorf("%s must include replacement guidance", entry.Version)
	}

	switch entry.ReplacementKind {
	case "registry":
		if _, ok := versions[entry.ReplacementVersion]; !ok {
			return fmt.Errorf("%s replacement_version %q does not exist in registry", entry.Version, entry.ReplacementVersion)
		}
	case "future":
		if !validSemverTag(entry.ReplacementVersion) {
			return fmt.Errorf("%s future replacement_version must be a semantic version tag", entry.Version)
		}
	case "external":
		if !validHTTPURL(entry.ReplacementVersion) {
			return fmt.Errorf("%s external replacement_version must be a URL", entry.Version)
		}
	default:
		return fmt.Errorf("%s has unsupported replacement_kind %q", entry.Version, entry.ReplacementKind)
	}

	return nil
}

func validSeverity(severity string) bool {
	allowedSeverities := map[string]struct{}{
		"low":      {},
		"medium":   {},
		"high":     {},
		"critical": {},
	}
	_, ok := allowedSeverities[severity]
	return ok
}

func validSemverTag(version string) bool {
	return semverTagPattern.MatchString(version)
}

func validDate(date string) bool {
	_, ok := parseLifecycleDate(date)
	return ok
}

func parseLifecycleDate(date string) (time.Time, bool) {
	parsed, err := time.Parse("2006-01-02", date)
	return parsed, err == nil && parsed.Format("2006-01-02") == date
}

func validUrgency(urgency string) bool {
	allowedUrgencies := map[string]struct{}{
		"none":     {},
		"low":      {},
		"medium":   {},
		"high":     {},
		"critical": {},
	}
	_, ok := allowedUrgencies[urgency]
	return ok
}

func validHTTPURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Host != "" && (parsed.Scheme == "https" || parsed.Scheme == "http")
}
