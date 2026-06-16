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
//	SELECT * FROM nix_user_packages WHERE username = 'alice' AND is_package = 1;

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/osquery/osquery-go/plugin/table"
)

// UserPackages returns the nix_user_packages table plugin.
func UserPackages() *table.Plugin {
	columns := []table.ColumnDefinition{
		table.TextColumn("name", table.ColumnDescription("Full derivation name.")),
		table.TextColumn("pname", table.ColumnDescription("Package name without version. Sourced from the .drv when available.")),
		table.TextColumn("version", table.ColumnDescription("Version string. Sourced from the .drv when available.")),
		table.TextColumn("store_path", table.ColumnDescription("Absolute /nix/store path of the package.")),
		table.TextColumn("derivation_path", table.ColumnDescription("Originating .drv path. Empty when keep-derivations is off or the .drv was garbage-collected.")),
		table.BigIntColumn("is_package", table.ColumnDescription("1 when the .drv exposes both env.pname and env.version; 0 for wrappers, hooks, locale data, unit scripts, etc.")),
		table.TextColumn("username", table.ColumnDescription("User whose nix-env profile contains the package.")),
		table.TextColumn("profile_path", table.ColumnDescription("Resolved store path of the user profile.")),
	}
	return table.NewPlugin(
		"nix_user_packages",
		columns,
		generateUserPackages,
		table.WithDescription("Packages installed in per-user nix-env profiles under /nix/var/nix/profiles/per-user/<user>/profile. Use `WHERE is_package = 1` for the human-recognisable subset."),
		table.WithPlatforms("linux"),
		table.WithExample("SELECT username, pname, version FROM nix_user_packages WHERE is_package = 1 ORDER BY username, pname;"),
	)
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

		storePaths := scanStorePaths(out)
		drvByPath, infoByDrv := enrichClosure(ctx, storePaths)

		for _, p := range storePaths {
			row := buildPackageRow(p, drvByPath, infoByDrv)
			row["username"] = username
			row["profile_path"] = resolved
			rows = append(rows, row)
		}
	}

	return rows, nil
}
