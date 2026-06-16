package tables

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// nixStoreBin is the nix-store binary used to enumerate closures.
// nixBin is the nix CLI used for richer queries (derivation show). Both
// are resolved at init time: prefer whatever's on PATH (the Nix package
// wrapper injects nix), then fall back to the NixOS system profile.
var (
	nixStoreBin = resolveNixBinary("nix-store")
	nixBin      = resolveNixBinary("nix")
)

func resolveNixBinary(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return "/run/current-system/sw/bin/" + name
}

// storePathRe matches a valid Nix store path and captures the name-version
// portion after the 32-character hash.
//
//	/nix/store/<32-char-hash>-<name-version>
var storePathRe = regexp.MustCompile(`^/nix/store/[a-z0-9]{32}-(.+)$`)

// ParseStorePath extracts (name, pname, version) from a Nix store path.
//
// Examples:
//
//	/nix/store/…-curl-7.88.1          → ("curl-7.88.1",        "curl",           "7.88.1")
//	/nix/store/…-bash-5.2-p15         → ("bash-5.2-p15",       "bash",           "5.2-p15")
//	/nix/store/…-python3.11-numpy-1.24 → ("python3.11-numpy-1.24", "python3.11-numpy", "1.24")
//	/nix/store/…-gcc-wrapper           → ("gcc-wrapper",        "gcc-wrapper",    "")
func ParseStorePath(storePath string) (name, pname, version string) {
	m := storePathRe.FindStringSubmatch(storePath)
	if m == nil {
		name = filepath.Base(storePath)
		pname = name
		return
	}
	nameVer := m[1]
	name = nameVer
	pname, version = splitNameVersion(nameVer)
	return
}

// splitNameVersion splits a string like "curl-7.88.1" into ("curl", "7.88.1").
//
// The version begins at the last hyphen-separated segment that starts with a
// digit. This matches Nix's de-facto convention while handling multi-segment
// versions (e.g., "5.2-p15") and package names with embedded digits
// (e.g., "python3.11-numpy").
func splitNameVersion(s string) (pname, version string) {
	parts := strings.Split(s, "-")
	for i := len(parts) - 1; i > 0; i-- {
		if len(parts[i]) > 0 && parts[i][0] >= '0' && parts[i][0] <= '9' {
			return strings.Join(parts[:i], "-"), strings.Join(parts[i:], "-")
		}
	}
	return s, ""
}
