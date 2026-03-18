package tables

// nix_system_packages — packages in the active NixOS system closure.
//
// Queries the transitive closure of /run/current-system via nix-store,
// giving a complete software inventory of what is physically present on disk
// as part of the current system derivation. This is the authoritative source
// for CrowdStrike allow-listing and CVE triage across a NixOS fleet.
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

	"github.com/alexloew/nixpkgs-osquery/osqext/plugin/table"
)

// SystemPackages returns the nix_system_packages table plugin.
func SystemPackages() *table.Plugin {
	columns := []table.ColumnDefinition{
		table.TextColumn("name"),       // full derivation name, e.g. "curl-7.88.1"
		table.TextColumn("pname"),      // package name, e.g. "curl"
		table.TextColumn("version"),    // version string, e.g. "7.88.1"
		table.TextColumn("store_path"), // absolute /nix/store path
	}
	return table.NewPlugin("nix_system_packages", columns, generateSystemPackages)
}

func generateSystemPackages(ctx context.Context, _ table.QueryContext) ([]map[string]string, error) {
	out, err := exec.CommandContext(ctx, "nix-store", "-qR", "/run/current-system").Output()
	if err != nil {
		// Not a NixOS system, /run/current-system absent, or nix-store unavailable.
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
