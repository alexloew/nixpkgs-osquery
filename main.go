// nixpkgs-osquery: osquery extension exposing Nix/NixOS package information.
//
// Registers four virtual tables:
//   - nix_system_packages  packages in the active NixOS system closure
//   - nix_user_packages    packages in per-user nix-env profiles
//   - nix_home_packages    packages managed by Home Manager
//   - nix_flake_inputs     flake.lock input metadata
package main

import (
	"flag"
	"log"

	osquery "github.com/osquery/osquery-go"
	"github.com/alexloew/nixpkgs-osquery/tables"
)

func main() {
	var socket string
	flag.StringVar(&socket, "socket", "", "Path to the osquery extensions UNIX domain socket")
	// osquery also passes --timeout, --interval, --verbose; accept and ignore them.
	flag.Int("timeout", 0, "")
	flag.Int("interval", 0, "")
	flag.Bool("verbose", false, "")
	flag.Parse()

	if socket == "" {
		log.Fatal("--socket flag is required")
	}

	server, err := osquery.NewExtensionManagerServer("nixos_packages_extension", socket)
	if err != nil {
		log.Fatalf("failed to create extension manager server: %v", err)
	}

	server.RegisterPlugin(tables.SystemPackages())
	server.RegisterPlugin(tables.UserPackages())
	server.RegisterPlugin(tables.HomePackages())
	server.RegisterPlugin(tables.FlakeInputs())

	if err := server.Run(); err != nil {
		log.Fatalf("extension exited with error: %v", err)
	}
}
