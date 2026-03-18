# Nix derivation to package the nixos-packages osquery extension.
#
# Build:   nix-build
# Result:  ./result/bin/nixos-packages-extension
#
{ pkgs ? import <nixpkgs> {} }:

let
  pythonEnv = pkgs.python3.withPackages (ps: [
    ps.osquery or (ps.callPackage ./osquery-python.nix {})
  ]);
in
pkgs.stdenv.mkDerivation {
  pname = "nixos-packages-extension";
  version = "1.0.0";

  src = ./.;

  buildInputs = [ pythonEnv pkgs.makeWrapper ];

  installPhase = ''
    mkdir -p $out/bin $out/share/nixos-packages-extension

    cp nixos_packages_extension.py $out/share/nixos-packages-extension/

    makeWrapper ${pythonEnv}/bin/python3 $out/bin/nixos-packages-extension \
      --add-flags "$out/share/nixos-packages-extension/nixos_packages_extension.py"
  '';

  meta = with pkgs.lib; {
    description = "osquery extension that enumerates packages on a NixOS system";
    license = licenses.mit;
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "nixos-packages-extension";
  };
}
