package tables

// nix_system_packages — packages in a NixOS system closure.
//
// By default queries the transitive closure of /run/current-system via
// nix-store, giving a complete software inventory of what is physically
// present on disk as part of the current system derivation. The closure
// path is configurable via the extension's --closure flag, which is useful
// for inspecting alternate generations, container/system images, or build
// outputs in CI.
//
// When the system retains derivations (the default on NixOS), rows are
// enriched with the originating .drv path, the authoritative pname /
// version from env.{pname,version}, and an `is_package` flag that filters
// out wrappers, hooks, locale data, etc.
//
// Example queries:
//
//	SELECT pname, version FROM nix_system_packages WHERE pname = 'openssl';
//	SELECT count(*) FROM nix_system_packages;
//	SELECT pname, version FROM nix_system_packages WHERE is_package = 1;

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strings"

	"github.com/osquery/osquery-go/plugin/table"
)

// SystemPackages returns the nix_system_packages table plugin. The given
// closurePath is queried with `nix-store -qR` at row generation time.
func SystemPackages(closurePath string) *table.Plugin {
	columns := []table.ColumnDefinition{
		table.TextColumn("name", table.ColumnDescription("Full derivation name, e.g. 'curl-7.88.1'.")),
		table.TextColumn("pname", table.ColumnDescription("Package name without version, e.g. 'curl'. Sourced from env.pname in the .drv when available, otherwise heuristically split from the store path.")),
		table.TextColumn("version", table.ColumnDescription("Version string. Sourced from env.version in the .drv when available, otherwise heuristically split from the store path.")),
		table.TextColumn("store_path", table.ColumnDescription("Absolute /nix/store path of the package.")),
		table.TextColumn("derivation_path", table.ColumnDescription("Originating .drv path. Empty when keep-derivations is off or the .drv was garbage-collected.")),
		table.BigIntColumn("is_package", table.ColumnDescription("1 when the .drv exposes both env.pname and env.version (a user-visible package); 0 for wrappers, hooks, locale data, unit scripts, etc.")),
	}
	gen := func(ctx context.Context, _ table.QueryContext) ([]map[string]string, error) {
		return generateSystemPackages(ctx, closurePath)
	}
	return table.NewPlugin(
		"nix_system_packages",
		columns,
		gen,
		table.WithDescription("Transitive closure of a NixOS system derivation (default: /run/current-system). Authoritative software inventory for fleet allow-listing and CVE triage. Use `WHERE is_package = 1` for the human-recognisable subset."),
		table.WithPlatforms("linux"),
		table.WithExample("SELECT pname, version FROM nix_system_packages WHERE is_package = 1 ORDER BY pname;"),
	)
}

func generateSystemPackages(ctx context.Context, closurePath string) ([]map[string]string, error) {
	out, err := exec.CommandContext(ctx, nixStoreBin, "-qR", closurePath).Output()
	if err != nil {
		// Not a NixOS system, closure path absent, or nix-store unavailable.
		return nil, nil
	}

	storePaths := scanStorePaths(out)
	drvByPath, infoByDrv := enrichClosure(ctx, storePaths)

	rows := make([]map[string]string, 0, len(storePaths))
	for _, p := range storePaths {
		rows = append(rows, buildPackageRow(p, drvByPath, infoByDrv))
	}
	return rows, nil
}

// scanStorePaths filters `nix-store -qR` output to /nix/store/* lines.
func scanStorePaths(out []byte) []string {
	var paths []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.HasPrefix(line, "/nix/store/") {
			paths = append(paths, line)
		}
	}
	return paths
}

// buildPackageRow assembles the common columns shared by all three
// package tables: name / pname / version / store_path / derivation_path /
// is_package. Caller adds table-specific fields (username, generation…).
func buildPackageRow(storePath string, drvByPath map[string]string, infoByDrv map[string]drvInfo) map[string]string {
	name, pname, version := ParseStorePath(storePath)
	drvPath := drvByPath[storePath]
	isPackage := "0"
	if info, ok := infoByDrv[drvPath]; ok {
		if info.Pname != "" {
			pname = info.Pname
		}
		if info.Version != "" {
			version = info.Version
		}
		if info.IsPackage {
			isPackage = "1"
		}
	}
	return map[string]string{
		"name":            name,
		"pname":           pname,
		"version":         version,
		"store_path":      storePath,
		"derivation_path": drvPath,
		"is_package":      isPackage,
	}
}
