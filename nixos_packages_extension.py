#!/usr/bin/env python3
"""
NixOS Packages Extension for osquery.

Provides the 'nixos_packages' virtual table with information about
packages installed on a NixOS system via the Nix package manager.

Usage:
    osqueryi --extension ./nixos_packages_extension.py
    osqueryd --extensions_autoload=/etc/osquery/extensions.load

Query examples:
    SELECT * FROM nixos_packages;
    SELECT name, version, source FROM nixos_packages WHERE source = 'system';
    SELECT count(*) FROM nixos_packages;
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

import osquery

# Matches /nix/store/<32-char-hash>-<name>
STORE_PATH_RE = re.compile(r"^/nix/store/[a-z0-9]{32}-(.+)$")


def split_name_version(name_version: str) -> tuple[str, str]:
    """
    Split a nix derivation name like 'curl-7.88.1' or 'python3-3.11.6'
    into (pname, version).

    Nix convention: the version starts at the last '-' segment that
    begins with a digit.
    """
    parts = name_version.split("-")
    for i in range(len(parts) - 1, 0, -1):
        if parts[i] and parts[i][0].isdigit():
            pname = "-".join(parts[:i])
            version = "-".join(parts[i:])
            return pname, version
    return name_version, ""


def parse_store_path(store_path: str) -> tuple[str, str, str]:
    """
    Parse a nix store path into (name, pname, version).

    Example:
        /nix/store/abc123...-curl-7.88.1  ->  ('curl-7.88.1', 'curl', '7.88.1')
        /nix/store/abc123...-bash-5.2-p15 ->  ('bash-5.2-p15', 'bash', '5.2-p15')
    """
    m = STORE_PATH_RE.match(store_path)
    if not m:
        basename = os.path.basename(store_path)
        return basename, basename, ""

    name_version = m.group(1)
    pname, version = split_name_version(name_version)
    return name_version, pname, version


def run_cmd(args: list[str], timeout: int = 30) -> Optional[str]:
    """Run a subprocess and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        pass
    return None


def get_system_packages() -> list[dict]:
    """
    Get packages from the active NixOS system closure.

    Queries /run/current-system via nix-store to enumerate all packages
    in the system derivation's transitive closure.
    """
    packages = []
    current_system = Path("/run/current-system")

    if not current_system.exists():
        return packages

    output = run_cmd(["nix-store", "-qR", str(current_system)])
    if not output:
        return packages

    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("/nix/store/"):
            continue
        name, pname, version = parse_store_path(line)
        packages.append(
            {
                "name": name,
                "pname": pname,
                "version": version,
                "store_path": line,
                "source": "system",
                "status": "installed",
            }
        )

    return packages


def get_user_env_packages() -> list[dict]:
    """
    Get packages installed in the user's nix profile via nix-env.

    Tries JSON output first for richer data, falls back to plain text.
    """
    packages = []

    # Attempt 1: nix-env --json (classic Nix, provides pname + version)
    output = run_cmd(["nix-env", "--query", "--installed", "--json"])
    if output:
        try:
            data = json.loads(output)
            for _attr, pkg in data.items():
                drv_name = pkg.get("name", "")
                pname = pkg.get("pname", "")
                version = pkg.get("version", "")

                # Derive pname/version from name if missing
                if drv_name and not pname:
                    _, pname, version = parse_store_path(
                        "/nix/store/" + "a" * 32 + "-" + drv_name
                    )

                # Find store path from outputs
                store_path = ""
                outputs = pkg.get("outputs", {})
                if outputs:
                    store_path = next(iter(outputs.values()), "")

                packages.append(
                    {
                        "name": drv_name or pname,
                        "pname": pname,
                        "version": version,
                        "store_path": store_path,
                        "source": "user-env",
                        "status": "installed",
                    }
                )
            return packages
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    # Attempt 2: nix-env plain text with --out-path
    output = run_cmd(["nix-env", "--query", "--installed", "--out-path"])
    if output:
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            drv_name = parts[0]
            store_path = parts[1]
            _, pname, version = parse_store_path(store_path)
            packages.append(
                {
                    "name": drv_name,
                    "pname": pname,
                    "version": version,
                    "store_path": store_path,
                    "source": "user-env",
                    "status": "installed",
                }
            )

    return packages


def get_nix2_profile_packages() -> list[dict]:
    """
    Get packages from nix profiles managed by the newer 'nix profile' command
    (Nix 2.4+).
    """
    packages = []

    # nix profile list --json is available in Nix 2.18+
    output = run_cmd(["nix", "profile", "list", "--json"])
    if not output:
        return packages

    try:
        data = json.loads(output)
        # Schema: {"version": 2, "elements": [{...}, ...]}
        elements = data.get("elements", [])
        for elem in elements:
            store_path = elem.get("storePath", "")
            if not store_path:
                # Older format may use "outputs"
                outputs = elem.get("outputs", {})
                store_path = next(iter(outputs.values()), "")

            name, pname, version = parse_store_path(store_path)

            # Use attrPath as a fallback for pname
            attr = elem.get("attrPath", "")
            if attr and not pname:
                pname = attr.split(".")[-1]

            packages.append(
                {
                    "name": name,
                    "pname": pname,
                    "version": version,
                    "store_path": store_path,
                    "source": "nix-profile",
                    "status": "installed",
                }
            )
    except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
        pass

    return packages


def collect_all_packages() -> list[dict]:
    """Aggregate packages from all sources, de-duplicated by store_path."""
    all_packages: list[dict] = []
    seen: set[str] = set()

    for pkg in (
        get_system_packages()
        + get_user_env_packages()
        + get_nix2_profile_packages()
    ):
        key = pkg["store_path"] or (pkg["name"] + pkg["source"])
        if key not in seen:
            seen.add(key)
            all_packages.append(pkg)

    return all_packages


@osquery.register_plugin
class NixosPackagesPlugin(osquery.plugin.TablePlugin):
    """
    osquery table plugin exposing NixOS/Nix packages.

    Sources queried:
      - system:      /run/current-system closure (NixOS system packages)
      - user-env:    nix-env managed user profile packages
      - nix-profile: nix profile managed packages (Nix 2.4+)
    """

    def name(self) -> str:
        return "nixos_packages"

    def columns(self) -> list:
        return [
            osquery.TableColumn(name="name", type=osquery.STRING),
            osquery.TableColumn(name="pname", type=osquery.STRING),
            osquery.TableColumn(name="version", type=osquery.STRING),
            osquery.TableColumn(name="store_path", type=osquery.STRING),
            osquery.TableColumn(name="source", type=osquery.STRING),
            osquery.TableColumn(name="status", type=osquery.STRING),
        ]

    def generate(self, context) -> list[dict]:
        return collect_all_packages()


if __name__ == "__main__":
    osquery.start_extension(
        name="nixos_packages_extension",
        version="1.0.0",
    )
