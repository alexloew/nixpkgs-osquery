# nixpkgs-osquery

An [osquery](https://osquery.io/) extension that identifies software packages installed on a NixOS Linux system.

## Table: `nixos_packages`

| Column | Type | Description |
|--------|------|-------------|
| `name` | TEXT | Full derivation name (e.g. `curl-7.88.1`) |
| `pname` | TEXT | Package name without version (e.g. `curl`) |
| `version` | TEXT | Version string (e.g. `7.88.1`) |
| `store_path` | TEXT | Absolute path in the Nix store (e.g. `/nix/store/abc...-curl-7.88.1`) |
| `source` | TEXT | Where the package was found: `system`, `user-env`, or `nix-profile` |
| `status` | TEXT | Always `installed` |

### Sources

| Source | Description |
|--------|-------------|
| `system` | Packages in the NixOS system closure (`/run/current-system`) |
| `user-env` | User-installed packages managed by `nix-env` |
| `nix-profile` | User-installed packages managed by `nix profile` (Nix 2.4+) |

## Example Queries

```sql
-- All installed packages
SELECT * FROM nixos_packages;

-- Only system packages, sorted by name
SELECT pname, version, store_path
FROM nixos_packages
WHERE source = 'system'
ORDER BY pname;

-- Search for a specific package
SELECT * FROM nixos_packages WHERE pname LIKE '%python%';

-- Count packages by source
SELECT source, count(*) AS total
FROM nixos_packages
GROUP BY source;

-- Find packages with no version (build tools, data, etc.)
SELECT name, store_path FROM nixos_packages WHERE version = '';
```

## Installation

### Prerequisites

- osquery installed on the NixOS host
- Python 3.8+ with the `osquery` Python SDK

### Quick Start (nix-shell)

```bash
git clone <this-repo>
cd nixpkgs-osquery
nix-shell          # sets up Python venv with osquery SDK
```

### Manual pip install

```bash
pip install osquery
```

### Run with osqueryi (interactive)

```bash
# Start osqueryi with the extension loaded
osqueryi --extension /path/to/nixos_packages_extension.py

# Then in the osquery shell:
osquery> SELECT name, version, source FROM nixos_packages LIMIT 20;
```

### Run with osqueryd (daemon)

1. Add the extension path to your autoload file:

```bash
echo "/path/to/nixos_packages_extension.py" >> /etc/osquery/extensions.load
```

2. Restart osqueryd:

```bash
systemctl restart osqueryd
```

### NixOS module (osqueryd)

In your `configuration.nix`:

```nix
services.osquery = {
  enable = true;
  settings = {
    extensions_autoload = "/etc/osquery/extensions.load";
  };
};

environment.etc."osquery/extensions.load".text = ''
  /etc/osquery/nixos_packages_extension.py
'';
```

## How It Works

The extension queries three sources in order:

1. **System packages** — runs `nix-store -qR /run/current-system` to get all
   packages in the transitive closure of the active NixOS system derivation.

2. **User-env packages** — runs `nix-env --query --installed --json` to get
   packages installed in the current user's nix profile (classic Nix).

3. **Nix profile packages** — runs `nix profile list --json` to get packages
   managed by the newer `nix profile` command (Nix 2.4+).

Packages are de-duplicated by store path so that a package appearing in both
the system closure and a user profile is reported once per unique path.

Nix store path names follow the convention `<hash>-<pname>-<version>`, which
is parsed to populate the `pname` and `version` columns.

## Development

```bash
# Run a quick self-test (no osquery daemon needed)
python3 -c "
import nixos_packages_extension as ext
pkgs = ext.collect_all_packages()
print(f'Found {len(pkgs)} packages')
for p in pkgs[:5]:
    print(p)
"
```

## License

MIT
