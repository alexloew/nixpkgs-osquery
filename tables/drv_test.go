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
