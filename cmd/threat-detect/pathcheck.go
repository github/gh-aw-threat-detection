package main

import "fmt"

// namedPath pairs a CLI flag or environment variable name with its resolved
// path, for use with rejectPathCollisions.
type namedPath struct {
	name string
	path string
}

// rejectPathCollisions ensures that no two of the given named, non-empty paths
// refer to the same file. Entries with an empty path are ignored. Each of
// these destinations is opened and written independently (and some are
// truncated), so aliasing any two would corrupt one or both — interleaving
// unrelated content, silently discarding a prior write, or (for GitHub Actions
// command files such as $GITHUB_OUTPUT/$GITHUB_ENV) getting rejected by the
// runner outright.
func rejectPathCollisions(entries ...namedPath) error {
	for i := 0; i < len(entries); i++ {
		if entries[i].path == "" {
			continue
		}
		for j := i + 1; j < len(entries); j++ {
			if entries[j].path == "" {
				continue
			}
			same, err := samePath(entries[i].path, entries[j].path)
			if err != nil {
				return fmt.Errorf("resolving output paths: %w", err)
			}
			if same {
				return fmt.Errorf("%s and %s must not point to the same file (%q)", entries[i].name, entries[j].name, entries[i].path)
			}
		}
	}
	return nil
}
