#!/usr/bin/env python3
"""Retired static operation selector; retained only to explain migration."""
from __future__ import annotations

import sys


def main() -> int:
    print("access.py is retired: the static operation table no longer makes access decisions. "
          "See ../break-glass/README.md for the priced offline fixture and its explicit "
          "scenario/bands inputs. The actor access plane remains shelved; this command "
          "does not authenticate a caller or grant access.", file=sys.stderr)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
