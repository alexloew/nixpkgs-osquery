package tables

// .drv enrichment for store paths.
//
// `nix-store -qR <closure>` returns store paths, but the boundary between
// pname and version is ambiguous (see parse.go) and there's no signal for
// "is this a user-visible package?" vs "is this a build artifact / hook /
// locale data?". When the host has `keep-derivations = true` (the default
// on NixOS), each store path's originating .drv carries env.pname and
// env.version verbatim — both authoritative and a useful filter.
//
// We batch the lookup in two subprocess calls per query:
//   1. `nix-store -q --deriver <paths…>`            → store path → .drv path
//   2. `nix derivation show <drvs…>`                 → JSON map of env attrs
//
// If either call fails (Nix unavailable, .drvs garbage-collected, etc.)
// we degrade silently to the heuristic-only path.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
)

// drvInfo captures the .drv fields we care about for enrichment.
type drvInfo struct {
	Pname     string
	Version   string
	IsPackage bool // env.pname AND env.version are both non-empty
}

// derivationShow is the subset of `nix derivation show` JSON we parse.
type derivationShow struct {
	Env map[string]string `json:"env"`
}

// resolveDerivers maps store paths to their .drv paths via a single batch
// invocation of `nix-store -q --deriver`. Paths whose deriver is unknown
// (or whose .drv has been GC'd) are omitted from the result.
func resolveDerivers(ctx context.Context, storePaths []string) map[string]string {
	if len(storePaths) == 0 {
		return nil
	}
	args := append([]string{"-q", "--deriver"}, storePaths...)
	out, err := exec.CommandContext(ctx, nixStoreBin, args...).Output()
	if err != nil {
		return nil
	}

	result := make(map[string]string, len(storePaths))
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	i := 0
	for scanner.Scan() {
		if i >= len(storePaths) {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line != "" && line != "unknown-deriver" && strings.HasSuffix(line, ".drv") {
			result[storePaths[i]] = line
		}
		i++
	}
	return result
}

// loadDerivationMeta runs `nix derivation show` over a batch of .drv paths
// and returns drv → drvInfo. Missing nix-command experimental feature, a
// non-existent .drv, or a parse failure all degrade to an empty map.
func loadDerivationMeta(ctx context.Context, drvPaths []string) map[string]drvInfo {
	if len(drvPaths) == 0 {
		return nil
	}
	// Deduplicate; nix derivation show errors out on dupes in some versions.
	seen := make(map[string]struct{}, len(drvPaths))
	unique := drvPaths[:0:0]
	for _, p := range drvPaths {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		unique = append(unique, p)
	}

	// `nix derivation show` is all-or-nothing: a single invalid store-path
	// argument aborts the entire batch with a non-zero exit. On NixOS this
	// happens routinely — a package's .drv is garbage-collected while its
	// output stays in the system closure, yet `nix-store -q --deriver` still
	// reports the (now-absent) deriver. Without filtering, one such .drv
	// zeroes out is_package for every row in the query. Drop invalid paths
	// first so enrichment degrades per-package instead of wholesale.
	unique = keepValidStorePaths(ctx, unique)
	if len(unique) == 0 {
		return nil
	}

	args := append([]string{
		"--extra-experimental-features", "nix-command",
		"derivation", "show",
	}, unique...)
	out, err := exec.CommandContext(ctx, nixBin, args...).Output()
	if err != nil {
		return nil
	}
	return parseDerivationShow(out)
}

// keepValidStorePaths returns the subset of paths that are valid (present and
// registered) in the Nix store, via a single
// `nix-store --check-validity --print-invalid` call. On any error it returns
// the input unchanged (best effort — let the caller try). This guards the
// batch `nix derivation show`, which treats any invalid argument as fatal for
// the whole invocation.
func keepValidStorePaths(ctx context.Context, paths []string) []string {
	if len(paths) == 0 {
		return paths
	}
	args := append([]string{"--check-validity", "--print-invalid"}, paths...)
	out, err := exec.CommandContext(ctx, nixStoreBin, args...).Output()
	if err != nil {
		return paths
	}
	invalid := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			invalid[line] = struct{}{}
		}
	}
	if len(invalid) == 0 {
		return paths
	}
	valid := paths[:0:0]
	for _, p := range paths {
		if _, bad := invalid[p]; !bad {
			valid = append(valid, p)
		}
	}
	return valid
}

// parseDerivationShow is split out for testability. It accepts both shapes
// of `nix derivation show` output:
//
//	modern (Nix ≥ ~2.30): {"version":N,"derivations":{<drv>:{…}}}
//	legacy:               {<drv>:{…}}
//
// The format gained the {version,derivations} envelope underneath us, which
// silently broke the legacy `map[string]derivationShow` decode (the numeric
// "version" field fails to unmarshal into the struct) and zeroed is_package
// across every row. Tolerating both shapes keeps us robust to the next bump.
//
// The envelope also keys its map by the store-relative basename
// (foo.drv) rather than the absolute /nix/store/foo.drv path the legacy
// format used. We normalize every key back to an absolute path so callers
// can look up by the deriver path from `nix-store -q --deriver`; without
// this, the lookup misses on modern Nix and is_package stays 0 everywhere.
func parseDerivationShow(data []byte) map[string]drvInfo {
	// Try the modern envelope first; fall back to the legacy flat object.
	var envelope struct {
		Derivations map[string]derivationShow `json:"derivations"`
	}
	var raw map[string]derivationShow
	if err := json.Unmarshal(data, &envelope); err == nil && len(envelope.Derivations) > 0 {
		raw = envelope.Derivations
	} else if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	result := make(map[string]drvInfo, len(raw))
	for drvPath, ds := range raw {
		key := drvPath
		if !strings.HasPrefix(key, "/nix/store/") {
			key = "/nix/store/" + key
		}
		pname := ds.Env["pname"]
		version := ds.Env["version"]
		result[key] = drvInfo{
			Pname:     pname,
			Version:   version,
			IsPackage: pname != "" && version != "",
		}
	}
	return result
}

// enrichClosure resolves derivers and meta for every store path in one
// pass. Returns store_path → (drv_path, drvInfo). The drv_path is "" when
// unavailable; the drvInfo zero value signals heuristic-only data.
func enrichClosure(ctx context.Context, storePaths []string) (drvPath map[string]string, info map[string]drvInfo) {
	drvPath = resolveDerivers(ctx, storePaths)
	if len(drvPath) == 0 {
		return drvPath, nil
	}
	drvs := make([]string, 0, len(drvPath))
	for _, d := range drvPath {
		drvs = append(drvs, d)
	}
	info = loadDerivationMeta(ctx, drvs)
	return drvPath, info
}
