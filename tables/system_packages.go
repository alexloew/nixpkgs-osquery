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
// Example queries:
//
//	SELECT pname, version FROM nix_system_packages WHERE pname = 'openssl';
//	SELECT count(*) FROM nix_system_packages;

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
		table.TextColumn("pname", table.ColumnDescription("Package name without version, e.g. 'curl'.")),
		table.TextColumn("version", table.ColumnDescription("Version string parsed from the derivation name.")),
		table.TextColumn("store_path", table.ColumnDescription("Absolute /nix/store path of the package.")),
	}
	gen := func(ctx context.Context, _ table.QueryContext) ([]map[string]string, error) {
		return generateSystemPackages(ctx, closurePath)
	}
	return table.NewPlugin(
		"nix_system_packages",
		columns,
		gen,
		table.WithDescription("Transitive closure of a NixOS system derivation (default: /run/current-system). Authoritative software inventory for fleet allow-listing and CVE triage."),
		table.WithPlatforms("linux"),
		table.WithExample("SELECT pname, version FROM nix_system_packages WHERE pname = 'openssl';"),
	)
}

func generateSystemPackages(ctx context.Context, closurePath string) ([]map[string]string, error) {
	out, err := exec.CommandContext(ctx, nixStoreBin, "-qR", closurePath).Output()
	if err != nil {
		// Not a NixOS system, closure path absent, or nix-store unavailable.
		return nil, nil
	}

	var rows []map[string]string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "/nix/store/") {
			continue
		}
		name, pname, version := ParseStorePath(line)
		rows = append(rows, map[string]string{
			"name":       name,
			"pname":      pname,
			"version":    version,
			"store_path": line,
		})
	}
	return rows, nil
}
