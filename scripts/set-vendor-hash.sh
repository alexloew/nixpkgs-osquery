#!/usr/bin/env bash
# Recompute and write the Go vendorHash into flake.nix and default.nix.
#
# Requires `nix-prefetch` (available in the dev shell). Run after any change
# to go.mod / go.sum.
set -euo pipefail

cd "$(dirname "$0")/.."

NEW_HASH="$(nix-prefetch \
  --option extra-experimental-features flakes \
  '{ sha256 }: (builtins.getFlake (toString ./.)).packages.x86_64-linux.default.goModules.overrideAttrs (_: { vendorSha256 = sha256; })')"

echo "computed vendorHash: ${NEW_HASH}"

sed -i "s|vendorHash = .*;|vendorHash = \"${NEW_HASH}\";|" flake.nix default.nix

echo "updated flake.nix and default.nix"
