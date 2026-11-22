"""XDelta/VCDIFF parser — uses pyxdelta to decode patches."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict
import tempfile
from pathlib import Path

# VCDIFF magic bytes (xdelta3)
VCDIFF_MAGIC = b"\xD6\xC3\xC4"


@dataclass
class XDeltaPatch:
    """Parsed xdelta patch as a dict of offset -> bytes."""
    changes: Dict[int, bytes] = field(default_factory=dict)
    raw_patch: bytes = b""

    def add(self, offset: int, data: bytes) -> None:
        if not data:
            return
        if offset in self.changes:
            self.changes[offset] += data
        else:
            self.changes[offset] = data

    def size(self) -> int:
        return sum(len(v) for v in self.changes.values())


def is_xdelta(data: bytes) -> bool:
    """Check if data looks like an xdelta/VCDIFF patch."""
    return data[:3] == VCDIFF_MAGIC


def parse_xdelta(patch_path: Path, base_rom: bytes) -> XDeltaPatch:
    """Parse an xdelta patch by decoding it against the base ROM.
    
    Decodes the patch to get the target ROM, then diffs against base
    to extract individual byte changes.
    """
    import pyxdelta

    if not is_xdelta(patch_path.read_bytes()[:3]):
        raise ValueError(f"Not an xdelta file: {patch_path}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        base_path = tmp / "base.bin"
        target_path = tmp / "target.bin"
        patch_path_copy = tmp / "patch.xdelta"

        # Write files
        base_path.write_bytes(base_rom)
        patch_path_copy.write_bytes(patch_path.read_bytes())

        # Decode: decode(base, patch, out)
        try:
            pyxdelta.decode(str(base_path), str(patch_path_copy), str(target_path))
        except Exception as e:
            raise ValueError(
                f"Failed to decode xdelta patch '{patch_path.name}': {e}. "
                "This usually means the patch was made for a different base ROM (wrong revision/header/dump)."
            ) from e

        if not target_path.exists():
            raise ValueError(f"Failed to decode xdelta patch: {patch_path}")

        target = target_path.read_bytes()

    # Diff target vs base to extract changes
    patch = XDeltaPatch(raw_patch=patch_path.read_bytes())
    i = 0
    min_len = min(len(target), len(base_rom))
    while i < min_len:
        if target[i] != base_rom[i]:
            start = i
            while i < min_len and target[i] != base_rom[i]:
                i += 1
            patch.add(start, target[start:i])
        else:
            i += 1
    # Handle target longer than base
    if len(target) > len(base_rom):
        patch.add(len(base_rom), target[len(base_rom):])

    return patch


def write_xdelta(target_rom: bytes, base_rom: bytes, output_path: Path) -> None:
    """Create an xdelta patch from base and target ROMs."""
    import pyxdelta

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        base_path = tmp / "base.bin"
        target_path = tmp / "target.bin"
        patch_path = tmp / "patch.xdelta"

        base_path.write_bytes(base_rom)
        target_path.write_bytes(target_rom)

        # run(base, target, patch)
        pyxdelta.run(str(base_path), str(target_path), str(patch_path))

        output_path.write_bytes(patch_path.read_bytes())
