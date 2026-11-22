"""Disassembly-aware rebasing heuristics.

Best-effort: remap patch offsets from a clean base to a disassembly-rebuilt ROM
when the rebuild shifted content. Uses context matching; ambiguous remaps are skipped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .changeset import ChangeSet


DISASM_PROFILES = [
    "Auto-detect",
    "Generic disassembly rebuild",
    "Sonic 2 Git Disasm (S2DISASM)",
]


@dataclass
class RebaseResult:
    changes: Dict[int, bytes]
    remapped: int = 0
    kept: int = 0
    dropped: int = 0
    ambiguous: int = 0
    warnings: List[str] = field(default_factory=list)


def parse_symbol_map(path: Path) -> Dict[str, int]:
    """Parse a simple symbol/map file. Supports common 'NAME = $XXXX', 'XXXX NAME', 'NAME: equ $XXXX' forms."""
    syms: Dict[str, int] = {}
    text = path.read_text(encoding="utf-8", errors="replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";") or line.startswith("#") or line.startswith("//"):
            continue
        # NAME = $1234 / NAME: equ $1234 / NAME equ $1234
        for sep in ["=", ":", " equ ", "\tequ "]:
            if sep in line:
                left, right = line.split(sep, 1)
                name = left.strip().strip(":")
                val = right.strip().split()[0].strip().strip("$")
                if name and _is_hex(val):
                    try:
                        syms[name] = int(val, 16)
                    except ValueError:
                        pass
                break
        else:
            # 001234 NAME or 0x001234 NAME
            parts = line.split()
            if len(parts) >= 2 and _is_hex(parts[0].lstrip("0x$")):
                try:
                    syms[parts[1].strip(":")] = int(parts[0].lstrip("0x$"), 16)
                except ValueError:
                    pass
    return syms


def _is_hex(s: str) -> bool:
    if not s:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def _find_unique(haystack: bytes, needle: bytes, near: Optional[int] = None, window: int = 0x40000) -> Optional[int]:
    if not needle or len(needle) > len(haystack):
        return None
    hits: List[int] = []
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx == -1:
            break
        hits.append(idx)
        start = idx + 1
        if len(hits) > 8:
            break
    if not hits:
        return None
    if len(hits) == 1:
        return hits[0]
    if near is not None:
        # pick closest hit within window if clearly better
        in_window = [h for h in hits if abs(h - near) <= window]
        if len(in_window) == 1:
            return in_window[0]
        if in_window:
            in_window.sort(key=lambda h: abs(h - near))
            if len(in_window) == 1 or abs(in_window[1] - near) - abs(in_window[0] - near) > 0x100:
                return in_window[0]
    return None


def rebase_changeset(
    cs: ChangeSet,
    base_rom: bytes,
    rebuild_rom: bytes,
    symbol_map: Optional[Dict[str, int]] = None,
) -> RebaseResult:
    """Remap a patch changeset (relative to clean base) onto a rebuild ROM.

    Strategy per change range:
    - If base bytes at offset still exist at same offset in rebuild and target slot differs as expected, keep.
    - Else try to locate base-context window in rebuild; if unique, remap.
    - Else drop with warning (unsafe to guess).
    """
    result = RebaseResult(changes={})
    sym = symbol_map or {}

    for offset, new_data in sorted(cs.changes.items()):
        old_data = base_rom[offset:offset + len(new_data)]
        if len(old_data) != len(new_data):
            result.dropped += len(new_data)
            result.warnings.append(f"{cs.name}: 0x{offset:06X} size mismatch vs base, skipped")
            continue

        rebuild_slot = rebuild_rom[offset:offset + len(new_data)] if offset + len(new_data) <= len(rebuild_rom) else b""

        # Same-offset safe: rebuild still has the original base bytes there (not shifted/overwritten by rebuild)
        if rebuild_slot == old_data:
            result.changes[offset] = bytes(new_data)
            result.kept += len(new_data)
            continue

        # If rebuild already contains the desired bytes, keep as no-op remap
        if rebuild_slot == new_data:
            result.kept += len(new_data)
            continue

        # Build context needle: base bytes around change
        ctx_before = 16
        ctx_after = 16
        ctx_start = max(0, offset - ctx_before)
        ctx_end = min(len(base_rom), offset + len(new_data) + ctx_after)
        needle = base_rom[ctx_start:ctx_end]
        rel = offset - ctx_start

        remapped_to: Optional[int] = None
        if len(needle) >= 12:
            hit = _find_unique(rebuild_rom, needle, near=offset)
            if hit is not None:
                candidate = hit + rel
                if candidate >= 0 and candidate + len(new_data) <= len(rebuild_rom) + 0x100000:
                    remapped_to = candidate

        # Fallback: try matching just old_data if reasonably unique
        if remapped_to is None and 4 <= len(old_data) <= 256:
            hit = _find_unique(rebuild_rom, old_data, near=offset)
            if hit is not None:
                remapped_to = hit

        if remapped_to is not None:
            if remapped_to != offset:
                result.remapped += len(new_data)
                result.warnings.append(
                    f"{cs.name}: remapped 0x{offset:06X} -> 0x{remapped_to:06X} ({len(new_data)} bytes)"
                )
            else:
                result.kept += len(new_data)
            # extend target if needed
            end = remapped_to + len(new_data)
            if end > len(rebuild_rom) and end <= len(rebuild_rom) + 0x400000:
                # allow expansion writes; caller applies on effective base
                pass
            result.changes[remapped_to] = bytes(new_data)
        else:
            # Ambiguous/no match - unsafe to guess. Drop but warn loudly.
            result.ambiguous += len(new_data)
            result.warnings.append(
                f"{cs.name}: could not confidently remap 0x{offset:06X} ({len(new_data)} bytes); skipped to avoid corruption"
            )

    return result


def rebase_changesets(
    change_sets: List[ChangeSet],
    base_rom: bytes,
    rebuild_rom: bytes,
    symbol_map: Optional[Dict[str, int]] = None,
) -> Tuple[List[ChangeSet], List[str]]:
    """Rebase multiple changesets onto rebuild ROM. Returns (new_changesets, warnings)."""
    out: List[ChangeSet] = []
    warnings: List[str] = []
    for cs in change_sets:
        rr = rebase_changeset(cs, base_rom, rebuild_rom, symbol_map=symbol_map)
        ncs = ChangeSet(name=cs.name, changes=rr.changes, source_format=cs.source_format)
        out.append(ncs)
        warnings.extend(rr.warnings)
        warnings.append(
            f"{cs.name}: rebase kept={rr.kept} remapped={rr.remapped} ambiguous/skipped={rr.ambiguous} dropped={rr.dropped}"
        )
    return out, warnings
