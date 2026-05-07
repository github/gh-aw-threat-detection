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

type lifecycleRegistry struct {
	SchemaVersion        string           `json:"schema_version"`
	LastUpdated          string           `json:"last_updated"`
	UnknownVersionPolicy string           `json:"unknown_version_policy"`
	Versions             []lifecycleEntry `json:"versions"`
}

type lifecycleEntry struct {
	Version            string `json:"version"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	ReplacementVersion string `json:"replacement_version"`
	ReplacementKind    string `json:"replacement_kind"`
	DeprecatedDate     string `json:"deprecated_date"`
	ObsoleteDate       string `json:"obsolete_date"`
	AdvisoryURL        string `json:"advisory_url"`
	Urgency            string `json:"urgency"`
	MaintainerNote     string `json:"maintainer_note"`
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

	versions := make(map[string]struct{}, len(registry.Versions))
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
		versions[entry.Version] = struct{}{}
	}

	for _, entry := range registry.Versions {
		if err := validateLifecycleEntry(entry, versions); err != nil {
			return err
		}
	}

	return nil
}

func validateLifecycleEntry(entry lifecycleEntry, versions map[string]struct{}) error {
	allowedStatuses := map[string]struct{}{
		"active":     {},
		"deprecated": {},
		"obsolete":   {},
	}
	if _, ok := allowedStatuses[entry.Status]; !ok {
		return fmt.Errorf("%s has unsupported status %q", entry.Version, entry.Status)
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
	}

	return nil
}

func validateReplacement(entry lifecycleEntry, versions map[string]struct{}) error {
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

func validSemverTag(version string) bool {
	return regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`).MatchString(version)
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
