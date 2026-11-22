"""ROM loading and diffing utilities."""

from __future__ import annotations
from pathlib import Path
from typing import Dict
from .changeset import ChangeSet
from .patchers.ips import parse_ips
from .patchers.bps import parse_bps
from .patchers.xdelta import parse_xdelta, is_xdelta


INES_MAGIC = b"NES\x1a"


def has_ines_header(data: bytes) -> bool:
    return len(data) >= 16 and data[:4] == INES_MAGIC


def normalize_nes_header(data: bytes, want_header: bool, reference_header: bytes | None = None) -> bytes:
    """Normalize NES ROM to have or not have iNES header."""
    got = has_ines_header(data)
    if got == want_header:
        return data
    if want_header:
        hdr = reference_header[:16] if reference_header and len(reference_header) >= 16 else (INES_MAGIC + b"\x00" * 12)
        return hdr + data
    # strip header
    return data[16:]


def normalize_for_base(data: bytes, base_rom: bytes) -> bytes:
    """If NES header presence differs from base, normalize data to match base layout."""
    if not base_rom:
        return data
    base_has = has_ines_header(base_rom)
    data_has = has_ines_header(data)
    if base_has == data_has:
        return data
    # Only normalize when it looks like NES data
    if base_has or data_has:
        return normalize_nes_header(data, base_has, reference_header=base_rom if base_has else None)
    return data


def load_input(path: Path, base_rom: bytes | None = None, nes_shift: int = 0) -> ChangeSet:
    """Load any supported input format and return a ChangeSet.
    
    Supports: .ips, .bps, .xdelta/.vcdiff, .bin (requires base_rom for .bin and .xdelta)
    nes_shift: add this offset to patch addresses (use 16 for headerless patch on headered ROM).
    """
    data = path.read_bytes()
    suffix = path.suffix.lower()

    def _shift(changes):
        if not nes_shift:
            return changes
        return {off + nes_shift: d for off, d in changes.items() if off + nes_shift >= 0}

    if suffix == ".ips" or data.startswith(b"PATCH"):
        patch = parse_ips(data)
        cs = ChangeSet(name=path.name, changes=_shift(patch.changes), source_format="ips")
        return cs

    elif suffix == ".bps" or data.startswith(b"BPS1"):
        if base_rom is None:
            raise ValueError(f"Base ROM required to extract changes from BPS: {path}")
        patch = parse_bps(data)
        changes = patch.extract_changes(base_rom)
        cs = ChangeSet(name=path.name, changes=_shift(changes), source_format="bps")
        return cs

    elif suffix in (".xdelta", ".vcdiff", ".xd") or is_xdelta(data):
        if base_rom is None:
            raise ValueError(f"Base ROM required to decode xdelta patch: {path}")
        patch = parse_xdelta(path, base_rom)
        cs = ChangeSet(name=path.name, changes=_shift(patch.changes), source_format="xdelta")
        return cs

    elif suffix in (".bin", ".rom", ".md", ".gen", ".nes"):
        if base_rom is None:
            raise ValueError(f"Base ROM required to diff .bin file: {path}")
        bin_data = normalize_for_base(data, base_rom)
        cs = ChangeSet(name=path.name, source_format="bin")
        i = 0
        min_len = min(len(bin_data), len(base_rom))
        while i < min_len:
            if bin_data[i] != base_rom[i]:
                start = i
                while i < min_len and bin_data[i] != base_rom[i]:
                    i += 1
                cs.changes[start] = bin_data[start:i]
            else:
                i += 1
        if len(bin_data) > len(base_rom):
            cs.changes[len(base_rom)] = bin_data[len(base_rom):]
        return cs

    else:
        # Try to detect by content
        if data.startswith(b"PATCH"):
            patch = parse_ips(data)
            return ChangeSet(name=path.name, changes=patch.changes, source_format="ips")
        elif data.startswith(b"BPS1"):
            if base_rom is None:
                raise ValueError(f"Base ROM required for BPS: {path}")
            patch = parse_bps(data)
            changes = patch.extract_changes(base_rom)
            return ChangeSet(name=path.name, changes=changes, source_format="bps")
        elif is_xdelta(data):
            if base_rom is None:
                raise ValueError(f"Base ROM required for xdelta: {path}")
            patch = parse_xdelta(path, base_rom)
            return ChangeSet(name=path.name, changes=patch.changes, source_format="xdelta")
        else:
            raise ValueError(f"Unknown format: {path} (try .ips, .bps, .xdelta, .bin)")


def load_base_rom(path: Path) -> bytes:
    """Load a base ROM file."""
    return path.read_bytes()


def apply_changes(base_rom: bytes, changeset: ChangeSet) -> bytes:
    """Apply a change set to a base ROM, returning the result."""
    result = bytearray(base_rom)
    for offset, data in changeset.changes.items():
        end = offset + len(data)
        if end > len(result):
            result.extend(b"\x00" * (end - len(result)))
        result[offset:end] = data
    return bytes(result)


def diff_roms(base: bytes, modified: bytes) -> Dict[int, bytes]:
    """Diff two ROMs and return address -> bytes for differences."""
    changes: Dict[int, bytes] = {}
    i = 0
    min_len = min(len(base), len(modified))
    while i < min_len:
        if base[i] != modified[i]:
            start = i
            while i < min_len and base[i] != modified[i]:
                i += 1
            changes[start] = modified[start:i]
        else:
            i += 1
    if len(modified) > len(base):
        changes[len(base)] = modified[len(base):]
    return changes
