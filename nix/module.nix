# NixOS module for the nixpkgs-osquery extension.
#
# Import this module in your flake or configuration.nix:
#
#   imports = [ ./path/to/nixpkgs-osquery/nix/module.nix ];
#   services.osquery.nixPackagesExtension.enable = true;
#
{ config, pkgs, lib, ... }:

with lib;

let
  cfg = config.services.osquery.nixPackagesExtension;

  basePackage = pkgs.callPackage ../default.nix {};

  # If a non-default closure is requested, wrap the extension to pass
  # `--closure <path>` automatically. osqueryd doesn't forward arbitrary
  # arguments to autoloaded extensions, so the flag has to be baked in.
  extensionPackage =
    if cfg.closure == "/run/current-system" then basePackage
    else pkgs.runCommand "nixpkgs-osquery-wrapped" {
      nativeBuildInputs = [ pkgs.makeBinaryWrapper ];
    } ''
      mkdir -p $out/bin
      makeWrapper ${basePackage}/bin/nixpkgs-osquery $out/bin/nixpkgs-osquery \
        --add-flags "--closure ${cfg.closure}"
      ln -s nixpkgs-osquery $out/bin/nixpkgs-osquery.ext
    '';

  extensionBin = "${extensionPackage}/bin/nixpkgs-osquery.ext";
in
{
  options.services.osquery.nixPackagesExtension = {
    enable = mkEnableOption "NixOS packages osquery extension";

    closure = mkOption {
      type = types.str;
      default = "/run/current-system";
      description = ''
        Nix closure to enumerate for the nix_system_packages table.
        Defaults to the active NixOS system. Override to point at a
        specific generation, container image, or build output.

        Setting this to a non-default value generates a small wrapper
        derivation that bakes the flag into the extension binary, since
        osqueryd does not forward arguments to autoloaded extensions.
      '';
    };
  };

  config = mkIf cfg.enable {
    services.osquery.enable = true;

    # Tell osqueryd to read our autoload file and how long to wait for
    # extensions to register. Per the upstream extensions docs:
    # https://osquery.readthedocs.io/en/latest/deployment/extensions/
    services.osquery.flags = {
      extensions_autoload = "/etc/osquery/extensions.load";
      extensions_timeout = mkDefault 3;
      extensions_interval = mkDefault 3;
    };

    # The autoload file must be root-owned and not world-writable;
    # osqueryd refuses extensions whose path is writable by non-root.
    environment.etc."osquery/extensions.load" = {
      text = "${extensionBin}\n";
      mode = "0644";
      user = "root";
      group = "root";
    };
  };
}
