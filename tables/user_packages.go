package tables

// nix_user_packages — packages installed in per-user nix-env profiles.
//
// Enumerates /nix/var/nix/profiles/per-user/<user>/profile for every user
// that has a nix-env profile on the system. Reports the transitive closure
// of each profile so that every package physically present is visible.
//
// Example queries:
//
//	SELECT pname, version, username FROM nix_user_packages;
//	SELECT * FROM nix_user_packages WHERE username = 'alice';

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/osquery/osquery-go/plugin/table"
)

// UserPackages returns the nix_user_packages table plugin.
func UserPackages() *table.Plugin {
	columns := []table.ColumnDefinition{
		table.TextColumn("name"),        // full derivation name
		table.TextColumn("pname"),       // package name
		table.TextColumn("version"),     // version string
		table.TextColumn("store_path"),  // absolute /nix/store path
		table.TextColumn("username"),    // owning user
		table.TextColumn("profile_path"), // resolved profile store path
	}
	return table.NewPlugin("nix_user_packages", columns, generateUserPackages)
}

func generateUserPackages(ctx context.Context, _ table.QueryContext) ([]map[string]string, error) {
	const perUserDir = "/nix/var/nix/profiles/per-user"

	entries, err := os.ReadDir(perUserDir)
	if err != nil {
		return nil, nil
	}

	var rows []map[string]string

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		username := entry.Name()
		profileLink := filepath.Join(perUserDir, username, "profile")

		resolved, err := filepath.EvalSymlinks(profileLink)
		if err != nil {
			// User has no active nix-env profile.
			continue
		}

		out, err := exec.CommandContext(ctx, nixStoreBin, "-qR", resolved).Output()
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
				"username":     username,
				"profile_path": resolved,
			})
		}
	}

	return rows, nil
}
