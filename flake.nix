{
  description = "osquery extension exposing Nix/NixOS package information as virtual SQL tables";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        version = "1.0.0";

        nixpkgs-osquery = pkgs.buildGoModule {
          pname = "nixpkgs-osquery";
          inherit version;

          src = ./.;

          # Recompute via `just update-vendor-hash` after any go.mod change.
          vendorHash = "sha256-qsjjO/7+QaxfBYhCvV4bgqnlYlzp7azV3Mv6n/SvS1Q=";

          ldflags = [
            "-s"
            "-w"
            "-X main.version=${version}"
            "-X main.builtBy=flake"
          ];

          nativeBuildInputs = [ pkgs.makeBinaryWrapper ];

          # Wrap the binary so `nix-store` is on PATH at runtime — the
          # extension shells out to it. Also provide the `.ext` alias
          # required by osquery's autoloader.
          postInstall = ''
            wrapProgram $out/bin/nixpkgs-osquery \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.nix ]}
            ln -s nixpkgs-osquery $out/bin/nixpkgs-osquery.ext
          '';

          meta = with pkgs.lib; {
            description = "osquery extension that enumerates Nix/NixOS packages";
            license = licenses.mit;
            platforms = platforms.linux;
            mainProgram = "nixpkgs-osquery";
          };
        };
      in
      {
        packages = {
          inherit nixpkgs-osquery;
          default = nixpkgs-osquery;
        };

        # Mirror packages into checks so `nix flake check` actually
        # realizes the derivation (flake check otherwise only evaluates
        # packages.* without building them).
        checks = {
          inherit nixpkgs-osquery;
          default = nixpkgs-osquery;
        };

        apps = {
          default = {
            type = "app";
            program = "${nixpkgs-osquery}/bin/nixpkgs-osquery";
          };
        };

        devShells.default = pkgs.mkShell {
          name = "nixpkgs-osquery-dev";
          packages = with pkgs; [
            go
            gofumpt
            golangci-lint
            gopls
            goreleaser
            gotools
            just
            nix-prefetch
            osquery
          ];
          shellHook = ''
            echo ""
            echo "nixpkgs-osquery development shell"
            echo "  just build       Build the extension"
            echo "  just test        Run unit tests"
            echo "  just lint        Run golangci-lint"
            echo "  just fmt         Format with gofumpt"
            echo ""
          '';
        };
      }
    );
}
