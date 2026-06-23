package tables

import "testing"

// realCurlDerivation is a minimally trimmed `nix derivation show` output.
// We only parse env.pname / env.version, so the rest of the schema is
// represented but not exercised.
const realCurlDerivation = `{
  "/nix/store/abcdefghijklmnopqrstuvwxyz123456-curl-7.88.1.drv": {
    "args": ["-e", "/nix/store/.../builder.sh"],
    "builder": "/nix/store/.../bash",
    "env": {
      "name": "curl-7.88.1",
      "pname": "curl",
      "version": "7.88.1",
      "outputs": "bin dev devdoc man out",
      "system": "x86_64-linux"
    },
    "inputDrvs": {},
    "inputSrcs": [],
    "outputs": {
      "out": {"path": "/nix/store/.../out"}
    },
    "system": "x86_64-linux"
  },
  "/nix/store/abcdefghijklmnopqrstuvwxyz654321-bash-5.2-p15.drv": {
    "args": [],
    "builder": "/nix/store/.../bash",
    "env": {
      "name": "bash-5.2-p15",
      "pname": "bash",
      "version": "5.2-p15"
    },
    "inputDrvs": {},
    "inputSrcs": [],
    "outputs": {"out": {"path": "/nix/store/...-bash-5.2-p15"}},
    "system": "x86_64-linux"
  },
  "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-unit-script-foo-start.drv": {
    "args": [],
    "builder": "/nix/store/.../bash",
    "env": {
      "name": "unit-script-foo-start"
    },
    "inputDrvs": {},
    "inputSrcs": [],
    "outputs": {"out": {"path": "/nix/store/...-unit-script-foo-start"}},
    "system": "x86_64-linux"
  }
}`

// envelopedCurlDerivation is the modern `nix derivation show` output shape
// (Nix ≥ ~2.30), wrapping the per-drv map in {"version":N,"derivations":…}.
// Decoding this with the legacy `map[string]derivationShow` fails on the
// numeric "version" field, which is exactly the regression that silently
// zeroed is_package on production hosts running newer Nix.
const envelopedCurlDerivation = `{
  "version": 4,
  "derivations": {
    "/nix/store/abcdefghijklmnopqrstuvwxyz123456-curl-7.88.1.drv": {
      "args": ["-e", "/nix/store/.../builder.sh"],
      "builder": "/nix/store/.../bash",
      "env": {
        "name": "curl-7.88.1",
        "pname": "curl",
        "version": "7.88.1"
      },
      "outputs": {"out": {"path": "/nix/store/.../out"}},
      "system": "x86_64-linux"
    }
  }
}`

func TestParseDerivationShow(t *testing.T) {
	got := parseDerivationShow([]byte(realCurlDerivation))
	if len(got) != 3 {
		t.Fatalf("want 3 entries, got %d", len(got))
	}

	cases := []struct {
		drvPath   string
		pname     string
		version   string
		isPackage bool
	}{
		{
			drvPath:   "/nix/store/abcdefghijklmnopqrstuvwxyz123456-curl-7.88.1.drv",
			pname:     "curl",
			version:   "7.88.1",
			isPackage: true,
		},
		{
			drvPath:   "/nix/store/abcdefghijklmnopqrstuvwxyz654321-bash-5.2-p15.drv",
			pname:     "bash",
			version:   "5.2-p15",
			isPackage: true,
		},
		{
			// No env.pname / env.version — typical for systemd unit scripts,
			// hooks, locale data. Should be flagged is_package=0.
			drvPath:   "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-unit-script-foo-start.drv",
			pname:     "",
			version:   "",
			isPackage: false,
		},
	}
	for _, tc := range cases {
		info, ok := got[tc.drvPath]
		if !ok {
			t.Errorf("missing entry for %s", tc.drvPath)
			continue
		}
		if info.Pname != tc.pname || info.Version != tc.version || info.IsPackage != tc.isPackage {
			t.Errorf("%s: got (%q, %q, %v), want (%q, %q, %v)",
				tc.drvPath, info.Pname, info.Version, info.IsPackage,
				tc.pname, tc.version, tc.isPackage)
		}
	}
}

// TestParseDerivationShowEnveloped guards against the Nix output-format bump
// that wraps derivations in a {"version":N,"derivations":…} envelope. A
// regression here previously left is_package=0 on every row.
func TestParseDerivationShowEnveloped(t *testing.T) {
	got := parseDerivationShow([]byte(envelopedCurlDerivation))
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	const drv = "/nix/store/abcdefghijklmnopqrstuvwxyz123456-curl-7.88.1.drv"
	info, ok := got[drv]
	if !ok {
		t.Fatalf("missing entry for %s", drv)
	}
	if info.Pname != "curl" || info.Version != "7.88.1" || !info.IsPackage {
		t.Errorf("got (%q, %q, %v), want (curl, 7.88.1, true)",
			info.Pname, info.Version, info.IsPackage)
	}
}

func TestParseDerivationShowMalformed(t *testing.T) {
	if got := parseDerivationShow([]byte("not json")); got != nil {
		t.Errorf("expected nil on malformed JSON, got %v", got)
	}
	if got := parseDerivationShow([]byte("")); got != nil {
		t.Errorf("expected nil on empty input, got %v", got)
	}
	// Empty object is valid JSON but yields an empty map.
	got := parseDerivationShow([]byte("{}"))
	if got == nil || len(got) != 0 {
		t.Errorf("expected empty map on empty object, got %v", got)
	}
}
