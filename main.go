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
	"fmt"
	"log"
	"os"
	"time"

	osquery "github.com/osquery/osquery-go"

	"github.com/alexloew/nixpkgs-osquery/tables"
)

// Build-time metadata, populated via -ldflags "-X main.version=…".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "source"
)

func main() {
	var (
		socket   string
		timeout  int
		interval int
		closure  string
		showVer  bool
	)

	flag.StringVar(&socket, "socket", "", "Path to the osquery extensions UNIX domain socket")
	flag.IntVar(&timeout, "timeout", 3, "Seconds to wait for autoloaded extensions")
	flag.IntVar(&interval, "interval", 3, "Seconds between connectivity checks against osqueryd")
	flag.StringVar(&closure, "closure", "/run/current-system", "Nix closure to enumerate for nix_system_packages")
	flag.BoolVar(&showVer, "version", false, "Print version information and exit")
	// osquery may pass --verbose; accept and ignore.
	flag.Bool("verbose", false, "")
	flag.Parse()

	if showVer {
		fmt.Printf("nixpkgs-osquery %s (commit %s, built %s by %s)\n", version, commit, date, builtBy)
		return
	}

	if socket == "" {
		log.Fatal("--socket flag is required")
	}

	server, err := osquery.NewExtensionManagerServer(
		"nixos_packages_extension",
		socket,
		osquery.ServerTimeout(time.Duration(timeout)*time.Second),
		osquery.ServerPingInterval(time.Duration(interval)*time.Second),
		osquery.ExtensionVersion(version),
	)
	if err != nil {
		log.Fatalf("failed to create extension manager server: %v", err)
	}

	server.RegisterPlugin(tables.SystemPackages(closure))
	server.RegisterPlugin(tables.UserPackages())
	server.RegisterPlugin(tables.HomePackages())
	server.RegisterPlugin(tables.FlakeInputs())

	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "extension exited with error: %v\n", err)
		os.Exit(1)
	}
}
