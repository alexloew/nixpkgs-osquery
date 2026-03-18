package tables

// nix_home_packages — packages managed by Home Manager.
//
// Locates Home Manager profiles in both the legacy location
// (/nix/var/nix/profiles/per-user/<user>/home-manager) and the XDG-state
// location (~/.local/state/nix/profiles/home-manager, used by Nix 2.4+).
//
// Also exposes the current generation number so Fleet queries can detect
// hosts that have not yet activated a new generation:
//
//	SELECT username, generation, pname, version FROM nix_home_packages
//	WHERE pname = 'neovim';

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alexloew/nixpkgs-osquery/osqext/plugin/table"
)

// HomePackages returns the nix_home_packages table plugin.
func HomePackages() *table.Plugin {
	columns := []table.ColumnDefinition{
		table.TextColumn("name"),        // full derivation name
		table.TextColumn("pname"),       // package name
		table.TextColumn("version"),     // version string
		table.TextColumn("store_path"),  // absolute /nix/store path
		table.TextColumn("username"),    // owning user
		table.BigIntColumn("generation"), // current Home Manager generation number
		table.TextColumn("profile_path"), // resolved profile store path
	}
	return table.NewPlugin("nix_home_packages", columns, generateHomePackages)
}

type hmProfile struct {
	username   string
	profileDir string // directory that contains the "home-manager" symlink
}

// homeManagerProfiles returns the set of Home Manager profile directories
// found on this system.
func homeManagerProfiles() []hmProfile {
	var profiles []hmProfile
	seen := map[string]bool{}

	add := func(username, dir string) {
		if !seen[dir] {
			seen[dir] = true
			profiles = append(profiles, hmProfile{username: username, profileDir: dir})
		}
	}

	// Legacy location: /nix/var/nix/profiles/per-user/<user>/home-manager
	const perUserDir = "/nix/var/nix/profiles/per-user"
	if entries, err := os.ReadDir(perUserDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			username := e.Name()
			dir := filepath.Join(perUserDir, username)
			// Check that a home-manager symlink exists in this dir.
			if _, err := os.Lstat(filepath.Join(dir, "home-manager")); err == nil {
				add(username, dir)
			}
		}
	}

	// XDG-state location: /home/<user>/.local/state/nix/profiles/
	if homeEntries, err := os.ReadDir("/home"); err == nil {
		for _, e := range homeEntries {
			if !e.IsDir() {
				continue
			}
			username := e.Name()
			dir := filepath.Join("/home", username, ".local", "state", "nix", "profiles")
			if _, err := os.Lstat(filepath.Join(dir, "home-manager")); err == nil {
				add(username, dir)
			}
		}
	}

	// root user XDG-state location
	rootDir := "/root/.local/state/nix/profiles"
	if _, err := os.Lstat(filepath.Join(rootDir, "home-manager")); err == nil {
		add("root", rootDir)
	}

	return profiles
}

// generationNumber parses the current generation from the symlink target of
// "<profileDir>/home-manager", which points to "home-manager-<N>-link".
func generationNumber(profileDir string) string {
	target, err := os.Readlink(filepath.Join(profileDir, "home-manager"))
	if err != nil {
		return "0"
	}
	base := filepath.Base(target)
	// base is e.g. "home-manager-47-link"
	parts := strings.Split(base, "-")
	// format: ["home", "manager", "<N>", "link"]
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err == nil {
			return p
		}
	}
	return "0"
}

func generateHomePackages(ctx context.Context, _ table.QueryContext) ([]map[string]string, error) {
	var rows []map[string]string

	for _, hm := range homeManagerProfiles() {
		profileLink := filepath.Join(hm.profileDir, "home-manager")
		resolved, err := filepath.EvalSymlinks(profileLink)
		if err != nil {
			continue
		}

		gen := generationNumber(hm.profileDir)

		out, err := exec.CommandContext(ctx, "nix-store", "-qR", resolved).Output()
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || !strings.HasPrefix(line, "/nix/store/") {
				continue
			}
			name, pname, version := ParseStorePath(line)
			rows = append(rows, map[string]string{
				"name":         name,
				"pname":        pname,
				"version":      version,
				"store_path":   line,
				"username":     hm.username,
				"generation":   gen,
				"profile_path": resolved,
			})
		}
	}

	return rows, nil
}
