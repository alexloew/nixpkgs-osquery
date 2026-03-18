# Development shell for the nixos-packages osquery extension.
#
# Usage:
#   nix-shell
#   python nixos_packages_extension.py --socket /run/osquery.em
#
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "nixpkgs-osquery-dev";

  buildInputs = with pkgs; [
    # Runtime dependencies
    osquery
    python3
    python3Packages.pip

    # Nix tools used by the extension at runtime
    nix
  ];

  shellHook = ''
    # Install the osquery Python SDK into a local venv if not present
    if [ ! -d .venv ]; then
      echo "Creating Python virtual environment..."
      python3 -m venv .venv
      .venv/bin/pip install --quiet osquery
    fi
    source .venv/bin/activate
    echo ""
    echo "NixOS osquery extension dev shell"
    echo "  Run:  python nixos_packages_extension.py --socket /run/osquery.em"
    echo "  Test: python -c 'import nixos_packages_extension; print(nixos_packages_extension.collect_all_packages()[:3])'"
    echo ""
  '';
}
