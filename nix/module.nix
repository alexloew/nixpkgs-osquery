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

  # Build the extension binary from source.
  nixpkgs-osquery = pkgs.buildGoModule {
    pname = "nixpkgs-osquery";
    version = "1.0.0";

    src = ../.;

    # Update this hash after running `nix build` for the first time:
    #   nix build && nix-prefetch-url --unpack file://$(pwd)/result
    # or use `vendorHash = null;` temporarily to get the expected hash.
    vendorHash = null;

    meta = {
      description = "osquery extension for NixOS/Nix package inventory";
      platforms = lib.platforms.linux;
    };
  };

  extensionBin = "${nixpkgs-osquery}/bin/nixpkgs-osquery";

  # Path to the extensions autoload file osqueryd reads at startup.
  autoloadFile = "/etc/osquery/extensions.load";
in
{
  options.services.osquery.nixPackagesExtension = {
    enable = mkEnableOption "NixOS packages osquery extension";

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
    # Ensure osquery daemon is enabled.
    services.osquery.enable = true;

    # Register the extension in the autoload file.
    environment.etc."osquery/extensions.load" = {
      text = "${extensionBin}\n";
      mode = "0644";
    };

    # Make nix-store available in the PATH that osqueryd inherits,
    # since the extension shells out to nix-store at query time.
    environment.systemPackages = [ pkgs.nix ];
  };
}
