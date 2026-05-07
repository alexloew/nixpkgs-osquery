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

  nixpkgs-osquery = pkgs.callPackage ../default.nix {};

  # osquery loads extensions whose path ends in `.ext`.
  extensionBin = "${nixpkgs-osquery}/bin/nixpkgs-osquery.ext";
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
      '';
    };

    tables = mkOption {
      type = types.listOf (types.enum [
        "nix_system_packages"
        "nix_user_packages"
        "nix_home_packages"
        "nix_flake_inputs"
      ]);
      default = [
        "nix_system_packages"
        "nix_user_packages"
        "nix_home_packages"
        "nix_flake_inputs"
      ];
      description = ''
        Which tables to expose. All four are enabled by default.
        You can restrict this list if some sources are not relevant
        for your fleet (e.g. omit nix_home_packages on servers).
      '';
    };
  };

  config = mkIf cfg.enable {
    services.osquery.enable = true;

    environment.etc."osquery/extensions.load" = {
      text = "${extensionBin}\n";
      mode = "0644";
    };

    # nix-store is shelled out to at query time.
    environment.systemPackages = [ pkgs.nix ];
  };
}
