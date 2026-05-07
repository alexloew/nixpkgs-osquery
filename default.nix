# Nix derivation for the nixpkgs-osquery extension.
#
# Build:   nix-build
# Result:  ./result/bin/nixpkgs-osquery (and .../nixpkgs-osquery.ext)
#
# Flake users should prefer `nix build` against flake.nix; this file is kept
# for environments without flakes enabled.
{ pkgs ? import <nixpkgs> {} }:

let
  version = "1.0.0";
in
pkgs.buildGoModule {
  pname = "nixpkgs-osquery";
  inherit version;

  src = ./.;

  # Recompute via `just update-vendor-hash` after any go.mod change.
  vendorHash = "sha256-qsjjO/7+QaxfBYhCvV4bgqnlYlzp7azV3Mv6n/SvS1Q=";

  ldflags = [
    "-s"
    "-w"
    "-X main.version=${version}"
    "-X main.builtBy=nix"
  ];

  # osquery's autoloader expects extension binaries to end in `.ext`.
  postInstall = ''
    ln -s nixpkgs-osquery $out/bin/nixpkgs-osquery.ext
  '';

  meta = with pkgs.lib; {
    description = "osquery extension that enumerates packages on a NixOS system";
    license = licenses.mit;
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "nixpkgs-osquery";
  };
}
