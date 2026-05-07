package tables

// nix_flake_inputs — metadata from flake.lock files found on the system.
//
// Searches standard locations for flake.lock files (system, user, and Home
// Manager configurations) and exposes each pinned input as a row. The rev
// and last_modified columns are particularly useful for fleet-wide drift
// detection — e.g. identifying hosts whose nixpkgs revision lags behind the
// desired pin.
//
// Example queries:
//
//	-- Find all nixpkgs revisions across the fleet
//	SELECT flake_path, rev, last_modified FROM nix_flake_inputs WHERE input = 'nixpkgs';
//
//	-- Hosts where nixpkgs is older than a specific revision
//	SELECT flake_path, rev FROM nix_flake_inputs
//	WHERE input = 'nixpkgs' AND rev != 'abc123deadbeef...';

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/osquery/osquery-go/plugin/table"
)

// FlakeInputs returns the nix_flake_inputs table plugin.
func FlakeInputs() *table.Plugin {
	columns := []table.ColumnDefinition{
		table.TextColumn("input", table.ColumnDescription("Input name as declared in the flake, e.g. 'nixpkgs'.")),
		table.TextColumn("type", table.ColumnDescription("Locked source type: github, gitlab, path, git, etc.")),
		table.TextColumn("owner", table.ColumnDescription("GitHub/GitLab owner.")),
		table.TextColumn("repo", table.ColumnDescription("GitHub/GitLab repository name.")),
		table.TextColumn("ref", table.ColumnDescription("Branch or tag reference.")),
		table.TextColumn("rev", table.ColumnDescription("Pinned git revision (SHA).")),
		table.BigIntColumn("last_modified", table.ColumnDescription("Unix timestamp of the pinned commit.")),
		table.TextColumn("nar_hash", table.ColumnDescription("Content-addressed hash of the fetched tree.")),
		table.TextColumn("url", table.ColumnDescription("URL for non-GitHub/GitLab inputs.")),
		table.TextColumn("flake_path", table.ColumnDescription("Absolute path to the flake.lock file.")),
	}
	return table.NewPlugin(
		"nix_flake_inputs",
		columns,
		generateFlakeInputs,
		table.WithDescription("Pinned input metadata extracted from flake.lock files. Useful for fleet drift detection — e.g. finding hosts whose nixpkgs revision lags a desired pin."),
		table.WithPlatforms("linux"),
		table.WithExample("SELECT flake_path, rev FROM nix_flake_inputs WHERE input = 'nixpkgs';"),
	)
}

// flakeLock mirrors the structure of a flake.lock file (version 7).
type flakeLock struct {
	Nodes   map[string]flakeNode `json:"nodes"`
	Root    string               `json:"root"`
	Version int                  `json:"version"`
}

type flakeNode struct {
	Locked  *flakeLocked  `json:"locked"`
	Original *flakeOriginal `json:"original"`
	Inputs  map[string]json.RawMessage `json:"inputs"`
}

type flakeLocked struct {
	Type         string `json:"type"`
	Owner        string `json:"owner"`
	Repo         string `json:"repo"`
	Rev          string `json:"rev"`
	LastModified int64  `json:"lastModified"`
	NarHash      string `json:"narHash"`
	URL          string `json:"url"`
	Ref          string `json:"ref"`
}

type flakeOriginal struct {
	Type  string `json:"type"`
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
	Ref   string `json:"ref"`
	URL   string `json:"url"`
}

// findFlakeLockPaths returns candidate flake.lock file paths.
func findFlakeLockPaths() []string {
	candidates := []string{
		"/etc/nixos/flake.lock",
	}

	// Per-user locations
	addUserPaths := func(home string) {
		candidates = append(candidates,
			filepath.Join(home, ".config", "home-manager", "flake.lock"),
			filepath.Join(home, ".config", "nixpkgs", "flake.lock"),
		)
	}

	addUserPaths("/root")

	if homeEntries, err := os.ReadDir("/home"); err == nil {
		for _, e := range homeEntries {
			if e.IsDir() {
				addUserPaths(filepath.Join("/home", e.Name()))
			}
		}
	}

	// Filter to paths that actually exist.
	var existing []string
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			existing = append(existing, p)
		}
	}
	return existing
}

func generateFlakeInputs(_ context.Context, _ table.QueryContext) ([]map[string]string, error) {
	var rows []map[string]string

	for _, lockPath := range findFlakeLockPaths() {
		data, err := os.ReadFile(lockPath)
		if err != nil {
			continue
		}

		var lock flakeLock
		if err := json.Unmarshal(data, &lock); err != nil {
			continue
		}

		// Collect which inputs are referenced by the root node so we report
		// the names that appear in the flake's inputs block.
		rootNode, ok := lock.Nodes[lock.Root]
		if !ok {
			continue
		}

		// Build a reverse map: node-key → input-name-as-declared-in-root
		inputName := map[string]string{}
		for name, rawRef := range rootNode.Inputs {
			var ref string
			// Inputs can be either a string node key or ["follows", "..."] array.
			if json.Unmarshal(rawRef, &ref) == nil {
				inputName[ref] = name
			}
		}

		for nodeKey, node := range lock.Nodes {
			if nodeKey == lock.Root {
				continue
			}
			if node.Locked == nil {
				continue
			}
			locked := node.Locked

			name := inputName[nodeKey]
			if name == "" {
				name = nodeKey
			}

			rows = append(rows, map[string]string{
				"input":         name,
				"type":          locked.Type,
				"owner":         locked.Owner,
				"repo":          locked.Repo,
				"ref":           coalesce(locked.Ref, originalRef(node)),
				"rev":           locked.Rev,
				"last_modified": strconv.FormatInt(locked.LastModified, 10),
				"nar_hash":      locked.NarHash,
				"url":           coalesce(locked.URL, buildURL(locked)),
				"flake_path":    lockPath,
			})
		}
	}

	return rows, nil
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func originalRef(node flakeNode) string {
	if node.Original == nil {
		return ""
	}
	return node.Original.Ref
}

// buildURL constructs a human-readable URL for github/gitlab inputs that
// don't have an explicit URL in their locked metadata.
func buildURL(l *flakeLocked) string {
	switch l.Type {
	case "github":
		if l.Rev != "" {
			return fmt.Sprintf("https://github.com/%s/%s/archive/%s.tar.gz", l.Owner, l.Repo, l.Rev)
		}
		return fmt.Sprintf("https://github.com/%s/%s", l.Owner, l.Repo)
	case "gitlab":
		if l.Rev != "" {
			return fmt.Sprintf("https://gitlab.com/%s/%s/-/archive/%s.tar.gz", l.Owner, l.Repo, l.Rev)
		}
		return fmt.Sprintf("https://gitlab.com/%s/%s", l.Owner, l.Repo)
	}
	return ""
}
