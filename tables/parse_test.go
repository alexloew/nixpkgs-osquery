package tables

import "testing"

func TestParseStorePath(t *testing.T) {
	hash := "abcdefghijklmnopqrstuvwxyz123456"
	base := "/nix/store/" + hash + "-"

	cases := []struct {
		path    string
		name    string
		pname   string
		version string
	}{
		// Standard name-version
		{base + "curl-7.88.1", "curl-7.88.1", "curl", "7.88.1"},
		{base + "bash-5.2-p15", "bash-5.2-p15", "bash", "5.2-p15"},
		{base + "python3-3.11.6", "python3-3.11.6", "python3", "3.11.6"},
		{base + "nix-2.18.1", "nix-2.18.1", "nix", "2.18.1"},
		// Package name contains a digit (e.g., python3.11-numpy)
		{base + "python3.11-numpy-1.24.0", "python3.11-numpy-1.24.0", "python3.11-numpy", "1.24.0"},
		// Multi-segment version
		{base + "linux-6.1.55", "linux-6.1.55", "linux", "6.1.55"},
		// No version
		{base + "gcc-wrapper", "gcc-wrapper", "gcc-wrapper", ""},
		{base + "stdenv-linux", "stdenv-linux", "stdenv-linux", ""},
		// Single component
		{base + "bash", "bash", "bash", ""},
		// Path that doesn't look like a nix store path
		{"/usr/bin/curl", "curl", "curl", ""},
	}

	for _, tc := range cases {
		name, pname, version := ParseStorePath(tc.path)
		if name != tc.name || pname != tc.pname || version != tc.version {
			t.Errorf("ParseStorePath(%q)\n  got  (%q, %q, %q)\n  want (%q, %q, %q)",
				tc.path, name, pname, version, tc.name, tc.pname, tc.version)
		}
	}
}

func TestSplitNameVersion(t *testing.T) {
	cases := []struct {
		input   string
		pname   string
		version string
	}{
		{"curl-7.88.1", "curl", "7.88.1"},
		{"bash-5.2-p15", "bash", "5.2-p15"},
		{"python3.11-numpy-1.24.0", "python3.11-numpy", "1.24.0"},
		{"gcc-wrapper", "gcc-wrapper", ""},
		{"llvmPackages_16-llvm-16.0.6", "llvmPackages_16-llvm", "16.0.6"},
		{"go-1.21.3", "go", "1.21.3"},
		{"nodejs-18.18.2", "nodejs", "18.18.2"},
	}
	for _, tc := range cases {
		pname, version := splitNameVersion(tc.input)
		if pname != tc.pname || version != tc.version {
			t.Errorf("splitNameVersion(%q) = (%q, %q), want (%q, %q)",
				tc.input, pname, version, tc.pname, tc.version)
		}
	}
}
