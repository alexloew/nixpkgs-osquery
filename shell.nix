# Development shell for the nixpkgs-osquery Go extension.
#
# Usage:
#   nix-shell
#   go build -o nixpkgs-osquery .
#   go test ./tables/...
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "nixpkgs-osquery-dev";

  buildInputs = with pkgs; [
    go
    gopls          # Go language server
    gotools        # goimports, etc.
    osquery        # for integration testing
  ];

  shellHook = ''
    echo ""
    echo "nixpkgs-osquery development shell (Go)"
    echo "  Build:      go build -o nixpkgs-osquery ."
    echo "  Test:       go test ./tables/..."
    echo "  Run:        osqueryi --extension ./nixpkgs-osquery"
    echo ""
  '';
}
