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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/osquery/osquery-go/plugin/table"
)

// HomePackages returns the nix_home_packages table plugin.
func HomePackages() *table.Plugin {
	columns := []table.ColumnDefinition{
		table.TextColumn("name", table.ColumnDescription("Full derivation name.")),
		table.TextColumn("pname", table.ColumnDescription("Package name without version. Sourced from the .drv when available.")),
		table.TextColumn("version", table.ColumnDescription("Version string. Sourced from the .drv when available.")),
		table.TextColumn("store_path", table.ColumnDescription("Absolute /nix/store path of the package.")),
		table.TextColumn("derivation_path", table.ColumnDescription("Originating .drv path. Empty when keep-derivations is off or the .drv was garbage-collected.")),
		table.BigIntColumn("is_package", table.ColumnDescription("1 when the .drv exposes both env.pname and env.version; 0 for wrappers, hooks, locale data, unit scripts, etc.")),
		table.TextColumn("username", table.ColumnDescription("User whose Home Manager profile contains the package.")),
		table.BigIntColumn("generation", table.ColumnDescription("Active Home Manager generation number.")),
		table.TextColumn("profile_path", table.ColumnDescription("Resolved store path of the Home Manager profile.")),
	}
	return table.NewPlugin(
		"nix_home_packages",
		columns,
		generateHomePackages,
		table.WithDescription("Packages managed by Home Manager. Searches both legacy (/nix/var/nix/profiles/per-user) and XDG-state (~/.local/state/nix/profiles) locations. Use `WHERE is_package = 1` for the human-recognisable subset."),
		table.WithPlatforms("linux"),
		table.WithExample("SELECT username, generation, pname, version FROM nix_home_packages WHERE pname = 'neovim';"),
	)
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

		out, err := exec.CommandContext(ctx, nixStoreBin, "-qR", resolved).Output()
		if err != nil {
			continue
		}

		storePaths := scanStorePaths(out)
		drvByPath, infoByDrv := enrichClosure(ctx, storePaths)

		for _, p := range storePaths {
			row := buildPackageRow(p, drvByPath, infoByDrv)
			row["username"] = hm.username
			row["generation"] = gen
			row["profile_path"] = resolved
			rows = append(rows, row)
		}
	}

	return rows, nil
}
