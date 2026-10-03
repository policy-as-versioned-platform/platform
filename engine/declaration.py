#!/usr/bin/env python3
"""declaration.py -- read the engine an adopter declares in its own gitops/engine/kyverno.yaml.

Hub ADR-0033 point 2, eco-system tickets 147 and 148. An adopter owns its Kyverno version, and
`gitops/engine/kyverno.yaml` in its own repository is the one place it says which. Two platform
tools read it, and both read it here, so they cannot disagree about what a declaration says:

  compose/composition.py     pairs every composed line and the machinery with the declared
                             engine, and prices an unsupported pairing (ticket 148)
  shift-left/ci-check.py     runs each line in a workload's window only on an engine that line
                             supports (ticket 148)

The shape is the one each adopter's own `.github/scripts/engine_declaration.py` checks: exactly
the keys schema, engine, version, install and cli; schema 1 (an integer, not a YAML boolean);
engine kyverno; an exact X.Y.Z version string; that release's install.yaml URL and linux_x86_64
CLI archive; and a quoted 64-hex sha256 for each. Whether a sha256 is the RIGHT one is not
checked here: the hub holds every figure to the platform engine table's row for the version.

An ABSENT file is not a fault here. `read` returns None, and each caller says what an undeclared
engine means for it. A file that is present and does not read raises `Malformed`, naming why.

Usage:
    declaration.py read FILE        the declared version, or exit 1 naming the fault
    declaration.py --selfcheck
"""
from __future__ import annotations

import copy
import re
import sys
import tempfile
from pathlib import Path

import yaml

FILE = "gitops/engine/kyverno.yaml"
KEYS = frozenset({"schema", "engine", "version", "install", "cli"})
RELEASES = "https://github.com/kyverno/kyverno/releases/download"
_VERSION = re.compile(r"\d+\.\d+\.\d+")
_SHA = re.compile(r"[0-9a-f]{64}")


class Malformed(ValueError):
    """The declaration is present and does not have the shape every reader relies on."""


def read(path: Path) -> dict | None:
    """{engine, version, file} for the declaration at `path`, None when there is no file.
    Raises Malformed naming the first fault."""
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return None

    def need(ok: bool, why: str) -> None:
        if not ok:
            raise Malformed(f"{FILE} {why}")

    try:
        doc = yaml.safe_load(path.read_text())
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise Malformed(f"{FILE} is not readable ({type(exc).__name__}: {exc})") from exc
    need(isinstance(doc, dict), "is not a mapping")
    need(set(doc) == KEYS, f"must carry exactly the keys {sorted(KEYS)}, not {sorted(map(str, doc))}")
    need(type(doc["schema"]) is int and doc["schema"] == 1, "schema must be 1")
    need(doc["engine"] == "kyverno", "engine must be kyverno")
    version = doc["version"]
    need(isinstance(version, str) and bool(_VERSION.fullmatch(version)),
         f"version {version!r} is not an exact X.Y.Z string")
    install = doc["install"] if isinstance(doc["install"], dict) else {}
    want = f"{RELEASES}/v{version}/install.yaml"
    need(install.get("url") == want, f"install.url must be {want}")
    need(isinstance(install.get("sha256"), str) and bool(_SHA.fullmatch(install["sha256"])),
         "install.sha256 is not a quoted 64-hex sha256")
    cli = (doc["cli"] if isinstance(doc["cli"], dict) else {}).get("linux_x86_64")
    cli = cli if isinstance(cli, dict) else {}
    archive = f"kyverno-cli_v{version}_linux_x86_64.tar.gz"
    need(cli.get("file") == archive, f"cli.linux_x86_64.file must be {archive}")
    need(isinstance(cli.get("sha256"), str) and bool(_SHA.fullmatch(cli["sha256"])),
         "cli.linux_x86_64.sha256 is not a quoted 64-hex sha256")
    return {"engine": "kyverno", "version": version, "file": FILE}


def from_table(version: str, table: Path | None = None) -> dict:
    """A well-formed declaration of `version`, with the figures of that version's row in the
    platform engine table. For fixtures: a figure is read from the table, never invented."""
    table = table or Path(__file__).resolve().parent / "kyverno" / "engine-table.yaml"
    row = next(r for r in yaml.safe_load(Path(table).read_text())["versions"] if r["version"] == version)
    return {"schema": 1, "engine": "kyverno", "version": version,
            "install": {"url": row["install"]["url"], "sha256": row["install"]["sha256"]},
            "cli": {"linux_x86_64": {"file": row["cli"]["linux_x86_64"]["file"],
                                     "sha256": row["cli"]["linux_x86_64"]["sha256"]}}}


def selfcheck() -> int:
    good = from_table("1.18.2")
    plants = {
        "a range, not a version": lambda d: d.__setitem__("version", ">=1.18"),
        "a version YAML reads as a number": lambda d: d.__setitem__("version", 1.18),
        "a boolean schema": lambda d: d.__setitem__("schema", True),
        "another engine": lambda d: d.__setitem__("engine", "gatekeeper"),
        "a key no reader reads": lambda d: d.__setitem__("chart", "3.8.2"),
        "an install.yaml of another release": lambda d: d["install"].__setitem__(
            "url", f"{RELEASES}/v9.9.9/install.yaml"),
        "a short install checksum": lambda d: d["install"].__setitem__("sha256", "3dcd43ea"),
        "a CLI archive of another release": lambda d: d["cli"]["linux_x86_64"].__setitem__(
            "file", "kyverno-cli_v9.9.9_linux_x86_64.tar.gz"),
        "no CLI checksum": lambda d: d["cli"]["linux_x86_64"].pop("sha256"),
    }
    accepted = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "kyverno.yaml"
        path.write_text(yaml.safe_dump(good))
        assert read(path) == {"engine": "kyverno", "version": "1.18.2", "file": FILE}, read(path)
        assert read(Path(tmp) / "absent.yaml") is None
        for name, plant in {**plants, "not YAML": None, "an empty file": None}.items():
            if plant is None:
                path.write_text("schema: [1\n" if name == "not YAML" else "")
            else:
                doc = copy.deepcopy(good)
                plant(doc)
                path.write_text(yaml.safe_dump(doc))
            try:
                read(path)
            except Malformed:
                continue
            accepted.append(name)
    if accepted:
        print("FAIL: the reader accepted: " + "; ".join(accepted))
        return 1
    print(f"PASS: selfcheck: a declaration from the engine table's 1.18.2 row reads, an absent "
          f"file reads as undeclared, and each of {len(plants) + 2} planted declarations is refused")
    return 0


def main(argv: list[str]) -> int:
    args = argv[1:]
    if args == ["--selfcheck"]:
        return selfcheck()
    if len(args) == 2 and args[0] == "read":
        try:
            engine = read(Path(args[1]))
        except Malformed as exc:
            print(f"malformed: {exc}", file=sys.stderr)
            return 1
        print(engine["version"] if engine else "undeclared")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
