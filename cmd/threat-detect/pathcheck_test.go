package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectPathCollisions_NoCollision(t *testing.T) {
	dir := t.TempDir()
	err := rejectPathCollisions(
		namedPath{"--a", filepath.Join(dir, "a.txt")},
		namedPath{"--b", filepath.Join(dir, "b.txt")},
		namedPath{"--c", ""},
	)
	if err != nil {
		t.Fatalf("rejectPathCollisions() error = %v, want nil", err)
	}
}

func TestRejectPathCollisions_DetectsCollision(t *testing.T) {
	dir := t.TempDir()
	same := filepath.Join(dir, "shared.txt")
	err := rejectPathCollisions(
		namedPath{"--a", same},
		namedPath{"--b", filepath.Join(dir, "b.txt")},
		namedPath{"--c", same},
	)
	if err == nil {
		t.Fatalf("rejectPathCollisions() error = nil, want collision error")
	}
	if !strings.Contains(err.Error(), "--a") || !strings.Contains(err.Error(), "--c") {
		t.Errorf("error = %q, want mentions of both --a and --c", err.Error())
	}
}

func TestRejectPathCollisions_EmptyPathsIgnored(t *testing.T) {
	err := rejectPathCollisions(
		namedPath{"--a", ""},
		namedPath{"--b", ""},
	)
	if err != nil {
		t.Fatalf("rejectPathCollisions() error = %v, want nil", err)
	}
}
