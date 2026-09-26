#!/usr/bin/env python3
"""engine_table.py -- read engine/kyverno/engine-table.yaml, and refuse a malformed row.

Eco-system ticket 146 item 1 (hub ADR-0033 point 4). The table lists every Kyverno version the
estate may run, with a sha256 for each CLI archive, for install.yaml and for the Helm chart. This
module is the one reader the platform's own scripts use. It checks the SHAPE of every row: an
exact X.Y.Z version, a 64-hex sha256 for every artefact, both CLI platforms the estate installs,
and a chart version. It cannot check that a sha256 is the right one; that is what the recorded
source in the table's header is for, and what `install-kyverno-engines.sh` measures when it
downloads.

Usage:
    engine_table.py rows <platform>   one line per row: <version> <url> <sha256>
    engine_table.py versions          the versions, one per line
    engine_table.py --selfcheck
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
TABLE = HERE / "kyverno" / "engine-table.yaml"
PLATFORMS = ("darwin_arm64", "linux_x86_64")
RELEASES = "https://github.com/kyverno/kyverno/releases/download"
_VERSION = re.compile(r"\d+\.\d+\.\d+")
_SHA = re.compile(r"[0-9a-f]{64}")


class TableError(ValueError):
    """The table does not have the shape every reader relies on."""


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise TableError(msg)


def load(path: Path | None = None) -> list[dict]:
    """Every row, validated. Raises TableError naming the first fault."""
    path = path or TABLE
    doc = yaml.safe_load(Path(path).read_text())
    _need(isinstance(doc, dict) and doc.get("schema") == 1, f"{path}: schema must be 1")
    _need(doc.get("engine") == "kyverno", f"{path}: engine must be kyverno")
    rows = doc.get("versions")
    _need(isinstance(rows, list) and rows, f"{path}: versions must be a non-empty list")
    seen: set[str] = set()
    for row in rows:
        _need(isinstance(row, dict), f"{path}: a row is not a mapping")
        v = row.get("version")
        _need(isinstance(v, str) and bool(_VERSION.fullmatch(v)), f"{path}: {v!r} is not an exact X.Y.Z")
        _need(v not in seen, f"{path}: {v} is listed twice")
        seen.add(v)
        cli = row.get("cli") or {}
        _need(str(cli.get("checksums", "")) == f"{RELEASES}/v{v}/checksums.txt",
              f"{path}: {v}: cli.checksums must name that release's own checksums.txt")
        for platform in PLATFORMS:
            art = cli.get(platform) or {}
            want = f"kyverno-cli_v{v}_{platform}.tar.gz"
            _need(art.get("file") == want, f"{path}: {v}: cli.{platform}.file must be {want}")
            _need(bool(_SHA.fullmatch(str(art.get("sha256", "")))), f"{path}: {v}: cli.{platform}.sha256 is not a sha256")
        inst = row.get("install") or {}
        _need(inst.get("url") == f"{RELEASES}/v{v}/install.yaml", f"{path}: {v}: install.url must be that release's install.yaml")
        _need(bool(_SHA.fullmatch(str(inst.get("sha256", "")))), f"{path}: {v}: install.sha256 is not a sha256")
        _need(bool(inst.get("source")), f"{path}: {v}: install.source must say where the sha256 came from")
        chart = row.get("chart") or {}
        _need(isinstance(chart.get("version"), str) and bool(_VERSION.fullmatch(chart["version"])),
              f"{path}: {v}: chart.version must be an exact X.Y.Z string")
        _need(chart.get("app_version") == "v" + v, f"{path}: {v}: chart.app_version must be v{v}")
        _need(bool(chart.get("index")), f"{path}: {v}: chart.index must say where the chart row came from")
        _need(bool(_SHA.fullmatch(str(chart.get("digest", "")))), f"{path}: {v}: chart.digest is not a sha256")
    charts = [r["chart"]["version"] for r in rows]
    _need(len(charts) == len(set(charts)), f"{path}: two rows name the same chart version")
    return rows


def cli_url(row: dict, platform: str) -> str:
    return f"{RELEASES}/v{row['version']}/{row['cli'][platform]['file']}"


def selfcheck() -> None:
    rows = load()
    assert [r["version"] for r in rows], "the table has no row"
    good = yaml.safe_load(TABLE.read_text())
    import copy
    import tempfile
    plants = {
        "a range, not a version": lambda d: d["versions"][0].__setitem__("version", ">=1.18"),
        "a short checksum": lambda d: d["versions"][0]["cli"]["linux_x86_64"].__setitem__("sha256", "cb2feb83"),
        "a missing platform": lambda d: d["versions"][0]["cli"].pop("darwin_arm64"),
        "an install sha with no source": lambda d: d["versions"][0]["install"].pop("source"),
        "a chart for another app version": lambda d: d["versions"][0]["chart"].__setitem__("app_version", "v9.9.9"),
        "a duplicate row": lambda d: d["versions"].append(copy.deepcopy(d["versions"][0])),
    }
    with tempfile.TemporaryDirectory() as tmp:
        for name, plant in plants.items():
            doc = copy.deepcopy(good)
            plant(doc)
            p = Path(tmp) / "t.yaml"
            p.write_text(yaml.safe_dump(doc))
            try:
                load(p)
            except TableError:
                continue
            raise AssertionError(f"the reader accepted {name}")
    print(f"selfcheck ok: {len(rows)} row(s) read; each of {len(plants)} planted faults refused")


def main(argv: list[str]) -> int:
    args = argv[1:]
    if args == ["--selfcheck"]:
        selfcheck()
        return 0
    try:
        rows = load()
    except (TableError, OSError, yaml.YAMLError) as exc:
        print(f"engine table unreadable: {exc}", file=sys.stderr)
        return 1
    if args == ["versions"]:
        print("\n".join(r["version"] for r in rows))
        return 0
    if len(args) == 2 and args[0] == "rows" and args[1] in PLATFORMS:
        for r in rows:
            print(r["version"], cli_url(r, args[1]), r["cli"][args[1]]["sha256"])
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
