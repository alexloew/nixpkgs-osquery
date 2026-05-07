// nixpkgs-osquery: osquery extension exposing Nix/NixOS package information.
//
// Registers four virtual tables:
//   - nix_system_packages  packages in the active NixOS system closure
//   - nix_user_packages    packages in per-user nix-env profiles
//   - nix_home_packages    packages managed by Home Manager
//   - nix_flake_inputs     flake.lock input metadata
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	osquery "github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"

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
		verbose  bool
		spec     bool
		showVer  bool
	)

	flag.StringVar(&socket, "socket", "", "Path to the osquery extensions UNIX domain socket")
	flag.IntVar(&timeout, "timeout", 3, "Seconds to wait for autoloaded extensions")
	flag.IntVar(&interval, "interval", 3, "Seconds between connectivity checks against osqueryd")
	flag.StringVar(&closure, "closure", "/run/current-system", "Nix closure to enumerate for nix_system_packages")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose debug logging")
	flag.BoolVar(&spec, "spec", false, "Print the JSON table specs and exit (no socket required)")
	flag.BoolVar(&showVer, "version", false, "Print version information and exit")
	flag.Parse()

	if showVer {
		fmt.Printf("nixpkgs-osquery %s (commit %s, built %s by %s)\n", version, commit, date, builtBy)
		return
	}

	if verbose {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
		log.Printf("verbose logging enabled (version=%s, commit=%s)", version, commit)
	}

	plugins := []*table.Plugin{
		tables.SystemPackages(closure),
		tables.UserPackages(),
		tables.HomePackages(),
		tables.FlakeInputs(),
	}

	if spec {
		specs := make([]any, 0, len(plugins))
		for _, p := range plugins {
			specs = append(specs, p.Spec())
		}
		out, err := json.MarshalIndent(specs, "", "  ")
		if err != nil {
			log.Fatalf("marshalling specs: %v", err)
		}
		fmt.Println(string(out))
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

	for _, p := range plugins {
		server.RegisterPlugin(p)
	}

	// Trigger graceful shutdown on SIGINT/SIGTERM so systemd/k8s stops
	// produce clean Thrift teardown rather than a yanked socket.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		if verbose {
			log.Printf("received %s, shutting down extension server", sig)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
	}()

	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "extension exited with error: %v\n", err)
		os.Exit(1)
	}
}
