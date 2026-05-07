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

  nativeBuildInputs = [ pkgs.makeBinaryWrapper ];

  # Wrap the binary so `nix-store` is on PATH at runtime, and add the
  # `.ext` alias required by osquery's autoloader.
  postInstall = ''
    wrapProgram $out/bin/nixpkgs-osquery \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.nix ]}
    ln -s nixpkgs-osquery $out/bin/nixpkgs-osquery.ext
  '';

  meta = with pkgs.lib; {
    description = "osquery extension that enumerates packages on a NixOS system";
    license = licenses.mit;
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "nixpkgs-osquery";
  };
}
