#!/usr/bin/env python3
"""ROMMAN launcher — runs the GUI."""

import sys
import io

# Fix Windows console encoding (only if stdout exists — windowed exe has None)
if sys.platform == "win32" and sys.stdout is not None:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from romman.gui import run

if __name__ == "__main__":
    run()
