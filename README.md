# nixpkgs-osquery

An [osquery](https://osquery.io/) extension written in Go (using
[kolide/osquery-go](https://github.com/kolide/osquery-go)) that exposes
NixOS/Nix package information as virtual SQL tables.

## Tables

### `nix_system_packages`

Full transitive closure of the active NixOS system derivation
(`/run/current-system`). This is the authoritative software inventory for
CrowdStrike allow-listing and CVE triage across a NixOS fleet.

| Column | Type | Description |
|--------|------|-------------|
| `name` | TEXT | Full derivation name, e.g. `curl-7.88.1` |
| `pname` | TEXT | Package name without version, e.g. `curl` |
| `version` | TEXT | Version string, e.g. `7.88.1` |
| `store_path` | TEXT | Absolute `/nix/store` path |

### `nix_user_packages`

Packages installed in per-user `nix-env` profiles
(`/nix/var/nix/profiles/per-user/<user>/profile`).

| Column | Type | Description |
|--------|------|-------------|
| `name` | TEXT | Full derivation name |
| `pname` | TEXT | Package name |
| `version` | TEXT | Version string |
| `store_path` | TEXT | Absolute `/nix/store` path |
| `username` | TEXT | Owning user |
| `profile_path` | TEXT | Resolved store path of the profile |

### `nix_home_packages`

Packages managed by [Home Manager](https://github.com/nix-community/home-manager).
Checks both the legacy profile location and the XDG-state location used by
Nix 2.4+.

| Column | Type | Description |
|--------|------|-------------|
| `name` | TEXT | Full derivation name |
| `pname` | TEXT | Package name |
| `version` | TEXT | Version string |
| `store_path` | TEXT | Absolute `/nix/store` path |
| `username` | TEXT | Owning user |
| `generation` | BIGINT | Current Home Manager generation number |
| `profile_path` | TEXT | Resolved store path of the Home Manager profile |

### `nix_flake_inputs`

Pinned input metadata from `flake.lock` files. Searches:
- `/etc/nixos/flake.lock` (system flake)
- `~/.config/home-manager/flake.lock`
- `~/.config/nixpkgs/flake.lock`

This table is particularly useful for fleet drift detection — querying
`WHERE input = 'nixpkgs'` across all hosts immediately shows which are
behind the desired revision pin.

| Column | Type | Description |
|--------|------|-------------|
| `input` | TEXT | Input name as declared in the flake, e.g. `nixpkgs` |
| `type` | TEXT | Source type: `github`, `gitlab`, `path`, `git`, … |
| `owner` | TEXT | GitHub/GitLab owner |
| `repo` | TEXT | GitHub/GitLab repository name |
| `ref` | TEXT | Branch or tag reference |
| `rev` | TEXT | Pinned git revision (SHA) |
| `last_modified` | BIGINT | Unix timestamp of the pinned commit |
| `nar_hash` | TEXT | Content-addressed hash of the fetched tree |
| `url` | TEXT | URL (for non-GitHub/GitLab inputs) |
| `flake_path` | TEXT | Absolute path to the `flake.lock` file |

---

## Example Queries

```sql
-- Full software inventory
SELECT pname, version FROM nix_system_packages ORDER BY pname;

-- Find a specific package anywhere on the system
SELECT pname, version, store_path
FROM nix_system_packages
WHERE pname LIKE '%openssl%';

-- Count packages by source
SELECT 'system' AS source, count(*) FROM nix_system_packages
UNION ALL
SELECT 'user', count(*) FROM nix_user_packages
UNION ALL
SELECT 'home', count(*) FROM nix_home_packages;

-- Show all users' installed packages
SELECT username, pname, version FROM nix_user_packages ORDER BY username, pname;

-- Detect Home Manager generation drift across fleet
SELECT username, generation, pname, version
FROM nix_home_packages
WHERE pname = 'neovim';

-- Show all pinned flake inputs (great for fleet nixpkgs revision audit)
SELECT input, rev, last_modified, flake_path
FROM nix_flake_inputs
ORDER BY input;

-- Find hosts not on the expected nixpkgs revision
SELECT flake_path, rev
FROM nix_flake_inputs
WHERE input = 'nixpkgs'
  AND rev != 'abc123deadbeef0000000000000000000000000000';
```

---

## Building

Requires Go 1.21+.

```bash
go mod tidy
go build -o nixpkgs-osquery .
```

Or via the [`justfile`](./justfile):

```bash
just build              # plain build
just build-release v1.0 # bakes in version/commit/date
just test
just lint
```

Or with Nix:

```bash
nix build               # flake: produces ./result/bin/nixpkgs-osquery[.ext]
nix develop             # flake dev shell (Go, gofumpt, golangci-lint, just, …)
# or, without flakes:
nix-build               # ./result/bin/nixpkgs-osquery
nix-shell
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--socket` | _(required for osquery)_ | Path to the osquery extensions UNIX domain socket. |
| `--timeout` | `3` | Seconds to wait for autoloaded extensions. |
| `--interval` | `3` | Seconds between connectivity checks against `osqueryd`. |
| `--closure` | `/run/current-system` | Nix closure to enumerate for `nix_system_packages`. Useful for inspecting alternate generations or build outputs in CI. |
| `--verbose` | `false` | Enable verbose debug logging. Honored when `osqueryd` autoloads with verbose mode. |
| `--spec` | `false` | Print the JSON spec for all four tables and exit. Useful for documentation generation and schema linting. |
| `--version` | — | Print version metadata and exit. |

## Running

### Interactive (osqueryi)

```bash
osqueryi --extension ./nixpkgs-osquery

osquery> SELECT pname, version FROM nix_system_packages LIMIT 10;
osquery> SELECT * FROM nix_flake_inputs;
```

### Daemon (osqueryd)

osquery's autoloader expects extension paths ending in `.ext`. The Nix
build provides `nixpkgs-osquery.ext` as a symlink alongside the bare
binary; for hand-built copies, symlink it yourself:

```bash
ln -s nixpkgs-osquery nixpkgs-osquery.ext
echo "/path/to/nixpkgs-osquery.ext" >> /etc/osquery/extensions.load
systemctl restart osqueryd
```

### NixOS module

```nix
# In your flake or configuration.nix:
imports = [ ./nixpkgs-osquery/nix/module.nix ];
services.osquery.nixPackagesExtension.enable = true;
```

The module wires the autoload file into `services.osquery.flags` so
`osqueryd` is launched with `--extensions_autoload`,
`--extensions_timeout`, and `--extensions_interval` set correctly. It
also generates a wrapper derivation when a non-default `closure` is
configured, since `osqueryd` does not forward arbitrary flags to
autoloaded extensions.

---

## Security model

osquery refuses to load any extension whose path is writable by a
non-root user. From the [extensions docs][]:

> the osquery agent will refuse to load an extension executable from
> the filesystem if the file's permissions allow write or modify by
> non-privileged accounts.

In practice this means:

- The Nix build outputs the binary under `/nix/store/...`, which is
  always root-owned and read-only. The NixOS module installs the
  autoload file at `/etc/osquery/extensions.load` with mode `0644`,
  owned by root.
- When invoking from an arbitrary location, ensure the binary and its
  parent directory are owned by `root` and not group/world-writable.
  `chown root:root nixpkgs-osquery && chmod 755 nixpkgs-osquery`.
- `--allow_unsafe` bypasses these checks for development. Do not use
  it in production.

[extensions docs]: https://osquery.readthedocs.io/en/latest/deployment/extensions/

---

## Store Path Parsing

Nix store path names follow the convention `<hash>-<pname>-<version>`. The
boundary between `pname` and `version` is ambiguous — Nix does not enforce a
separator — so this extension uses the heuristic:

> The version starts at the last hyphen-separated segment that begins with a
> digit.

This correctly handles:
- `curl-7.88.1` → pname=`curl`, version=`7.88.1`
- `bash-5.2-p15` → pname=`bash`, version=`5.2-p15`
- `python3.11-numpy-1.24.0` → pname=`python3.11-numpy`, version=`1.24.0`
- `gcc-wrapper` → pname=`gcc-wrapper`, version=`""`

See `tables/parse_test.go` for the full test matrix.

## Testing

```bash
go test ./...
# or
just test
```

## License

MIT
