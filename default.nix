# Nix derivation for the nixpkgs-osquery extension.
#
# Build:   nix-build
# Result:  ./result/bin/nixpkgs-osquery
{ pkgs ? import <nixpkgs> {} }:

pkgs.buildGoModule {
  pname = "nixpkgs-osquery";
  version = "1.0.0";

  src = ./.;

  # Set to the hash printed by `nix-build` on first run, or use `null`
  # temporarily to fetch and compute it.
  vendorHash = null;

  meta = with pkgs.lib; {
    description = "osquery extension that enumerates packages on a NixOS system";
    license = licenses.mit;
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "nixpkgs-osquery";
  };
}
