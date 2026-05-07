# Task runner for nixpkgs-osquery. Run `just` to list targets.
default:
    @just --list

# Build the extension binary into ./nixpkgs-osquery.
build:
    go build -o nixpkgs-osquery .

# Build with version metadata baked in via -ldflags.
build-release VERSION="dev":
    go build \
      -ldflags "-s -w \
        -X main.version={{VERSION}} \
        -X main.commit=$(git rev-parse --short HEAD) \
        -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
        -X main.builtBy=just" \
      -o nixpkgs-osquery .

# Run unit tests.
test:
    go test ./...

# Run golangci-lint.
lint:
    golangci-lint run --config .golangci.yml ./...

# Format the codebase with gofumpt.
fmt:
    gofumpt -w .

# Build via the Nix flake (produces ./result/bin/nixpkgs-osquery[.ext]).
build-nix:
    nix build .

# Tidy go.mod / go.sum.
tidy:
    go mod tidy

# Update Go dependencies and re-tidy.
update-deps:
    go get -u ./...
    go mod tidy

# Recompute vendorHash in flake.nix and default.nix.
update-vendor-hash:
    ./scripts/set-vendor-hash.sh

# Update flake inputs.
update-flake:
    nix flake update
