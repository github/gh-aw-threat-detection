package releases

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

type lifecycleRegistry struct {
	SchemaVersion int                `json:"schema_version"`
	Releases      []lifecycleRelease `json:"releases"`
}

type lifecycleRelease struct {
	Version            string `json:"version"`
	ImageDigest        string `json:"image_digest"`
	Status             string `json:"status"`
	YankedDate         string `json:"yanked_date,omitempty"`
	Reason             string `json:"reason,omitempty"`
	Severity           string `json:"severity,omitempty"`
	ReplacementVersion string `json:"replacement_version,omitempty"`
	ReplacementDigest  string `json:"replacement_digest,omitempty"`
	NoSafeReplacement  bool   `json:"no_safe_replacement,omitempty"`
	AdvisoryURL        string `json:"advisory_url,omitempty"`
	MaintainerNote     string `json:"maintainer_note,omitempty"`
}

var (
	versionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	validStatuses  = map[string]bool{"active": true, "deprecated": true, "obsolete": true, "yanked": true}
	validSeverity  = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
)

func TestThreatDetectionLifecycleRegistry(t *testing.T) {
	contents, err := os.ReadFile("threat-detection-lifecycle.json")
	if err != nil {
		t.Fatalf("read lifecycle registry: %v", err)
	}

	var registry lifecycleRegistry
	if err := json.Unmarshal(contents, &registry); err != nil {
		t.Fatalf("parse lifecycle registry: %v", err)
	}

	if err := validateLifecycleRegistry(registry); err != nil {
		t.Fatal(err)
	}
}

func TestValidateLifecycleRegistryRequiresYankMetadata(t *testing.T) {
	registry := lifecycleRegistry{
		SchemaVersion: 1,
		Releases: []lifecycleRelease{{
			Version:     "v1.2.3",
			ImageDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Status:      "yanked",
		}},
	}

	err := validateLifecycleRegistry(registry)
	if err == nil {
		t.Fatal("expected missing yank metadata to fail validation")
	}
	if !strings.Contains(err.Error(), "yanked_date") {
		t.Fatalf("expected yanked_date validation error, got %v", err)
	}
}

func TestValidateLifecycleRegistryRejectsYankedReplacement(t *testing.T) {
	registry := lifecycleRegistry{
		SchemaVersion: 1,
		Releases: []lifecycleRelease{
			{
				Version:            "v1.2.3",
				ImageDigest:        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Status:             "yanked",
				YankedDate:         "2026-05-07",
				Reason:             "unsafe detector behavior",
				Severity:           "high",
				ReplacementVersion: "v1.2.4",
				ReplacementDigest:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
			{
				Version:           "v1.2.4",
				ImageDigest:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Status:            "yanked",
				YankedDate:        "2026-05-07",
				Reason:            "also unsafe",
				Severity:          "critical",
				NoSafeReplacement: true,
			},
		},
	}

	err := validateLifecycleRegistry(registry)
	if err == nil {
		t.Fatal("expected yanked replacement to fail validation")
	}
	if !strings.Contains(err.Error(), "replacement_version v1.2.4 is yanked") {
		t.Fatalf("expected yanked replacement validation error, got %v", err)
	}
}

func validateLifecycleRegistry(registry lifecycleRegistry) error {
	if registry.SchemaVersion != 1 {
		return fmt.Errorf("schema_version must be 1")
	}

	byVersion := make(map[string]lifecycleRelease, len(registry.Releases))
	byDigest := make(map[string]lifecycleRelease, len(registry.Releases))
	for _, release := range registry.Releases {
		if err := validateReleaseShape(release); err != nil {
			return err
		}
		if _, ok := byVersion[release.Version]; ok {
			return fmt.Errorf("duplicate version %s", release.Version)
		}
		byVersion[release.Version] = release
		if release.ImageDigest != "" {
			if _, ok := byDigest[release.ImageDigest]; ok {
				return fmt.Errorf("duplicate image_digest %s", release.ImageDigest)
			}
			byDigest[release.ImageDigest] = release
		}
	}

	for _, release := range registry.Releases {
		if release.Status != "yanked" || release.ReplacementVersion == "" {
			continue
		}
		replacement, ok := byVersion[release.ReplacementVersion]
		if !ok {
			continue
		}
		if replacement.Status == "yanked" || replacement.Status == "obsolete" {
			return fmt.Errorf("%s replacement_version %s is %s", release.Version, replacement.Version, replacement.Status)
		}
		if release.ReplacementDigest != "" && replacement.ImageDigest != "" && release.ReplacementDigest != replacement.ImageDigest {
			return fmt.Errorf("%s replacement_digest does not match %s image_digest", release.Version, replacement.Version)
		}
	}

	return nil
}

func validateReleaseShape(release lifecycleRelease) error {
	if !versionPattern.MatchString(release.Version) {
		return fmt.Errorf("version %q must be a semantic version tag like v1.2.3", release.Version)
	}
	if release.ImageDigest != "" && !digestPattern.MatchString(release.ImageDigest) {
		return fmt.Errorf("%s image_digest must be sha256:<64 lowercase hex characters>", release.Version)
	}
	if !validStatuses[release.Status] {
		return fmt.Errorf("%s status must be active, deprecated, obsolete, or yanked", release.Version)
	}

	if release.Status != "yanked" {
		return nil
	}
	if strings.TrimSpace(release.YankedDate) == "" {
		return fmt.Errorf("%s yanked releases require yanked_date", release.Version)
	}
	if _, err := time.Parse("2006-01-02", release.YankedDate); err != nil {
		return fmt.Errorf("%s yanked_date must use YYYY-MM-DD: %w", release.Version, err)
	}
	if strings.TrimSpace(release.Reason) == "" {
		return fmt.Errorf("%s yanked releases require reason", release.Version)
	}
	if !validSeverity[release.Severity] {
		return fmt.Errorf("%s yanked releases require severity low, medium, high, or critical", release.Version)
	}
	if release.NoSafeReplacement {
		if release.ReplacementVersion != "" || release.ReplacementDigest != "" {
			return fmt.Errorf("%s cannot set replacement fields when no_safe_replacement is true", release.Version)
		}
	} else {
		if !versionPattern.MatchString(release.ReplacementVersion) {
			return fmt.Errorf("%s yanked releases require replacement_version unless no_safe_replacement is true", release.Version)
		}
		if !digestPattern.MatchString(release.ReplacementDigest) {
			return fmt.Errorf("%s yanked releases require replacement_digest sha256:<64 lowercase hex characters>", release.Version)
		}
	}
	if release.AdvisoryURL != "" {
		parsed, err := url.ParseRequestURI(release.AdvisoryURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("%s advisory_url must be an absolute URL", release.Version)
		}
	}
	return nil
}
