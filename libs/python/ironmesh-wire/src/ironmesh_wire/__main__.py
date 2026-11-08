"""``python -m ironmesh_wire`` entry point."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":  # pragma: no cover - exercised through subprocess in tests
    sys.exit(main())
