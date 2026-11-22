"""Game compatibility detection — identifies which ROM/hack belongs to which game."""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from .changeset import ChangeSet


@dataclass
class GameInfo:
    """Identified game/ROM information."""
    name: str
    size: int
    console: str  # "genesis", "snes", "unknown"
    title: str = ""
    checksum: str = ""


# Genesis/Mega Drive ROM signatures
GENESIS_MAGIC = b"SEGA"
GENESIS_CONSOLE = b"SEGA MEGA DRIVE"
GENESIS_CONSOLE_ALT = b"SEGA GENESIS"

# Known Genesis ROM sizes (common)
KNOWN_GENESIS_SIZES = {
    0x80000: "512KB",
    0x100000: "1MB",
    0x200000: "2MB",
    0x400000: "4MB",
}


def identify_rom(data: bytes) -> Optional[GameInfo]:
    """Try to identify a ROM file from its contents."""
    if len(data) < 0x200:
        return None
    
    # Check for Genesis ROM header at offset 0x100
    header = data[0x100:0x200]
    
    if GENESIS_CONSOLE in header or GENESIS_CONSOLE_ALT in header:
        # Extract console name
        console_str = header[:16].decode("ascii", errors="ignore").strip("\x00")
        
        # Extract ROM title (offset 0x120-0x14F, 48 bytes)
        title_bytes = data[0x120:0x150]
        title = title_bytes.decode("ascii", errors="ignore").strip("\x00").strip()
        
        # Calculate simple checksum (sum of all words from 0x200 to end)
        import struct
        checksum = 0
        for i in range(0x200, min(len(data), 0x200000), 2):
            if i + 1 < len(data):
                checksum = (checksum + struct.unpack(">H", data[i:i+2])[0]) & 0xFFFF
        
        return GameInfo(
            name=console_str,
            size=len(data),
            console="genesis",
            title=title,
            checksum=f"{checksum:04X}",
        )
    
    # Check for SNES ROM (different header location)
    # ... could add SNES detection later
    
    return None


def identify_changeset(cs: ChangeSet, base_rom: Optional[bytes] = None) -> Optional[GameInfo]:
    """Identify which game a change set belongs to."""
    
    # For .bin format, we have the full ROM
    if cs.source_format == "bin" and base_rom:
        # Try to identify from the base ROM
        return identify_rom(base_rom)
    
    # For patches, check if they contain game-specific metadata
    # BPS patches have source_size which we can compare
    if cs.source_format == "bps":
        # Check if BPS header contains size info
        # (This would need the raw patch data, which we don't have in ChangeSet)
        pass
    
    # For IPS, check if modifications are in expected regions
    if cs.source_format == "ips" and base_rom:
        # If the patch modifies addresses beyond the base ROM size, it's suspicious
        max_addr = 0
        for offset, data in cs.changes.items():
            max_addr = max(max_addr, offset + len(data))
        
        if max_addr > len(base_rom) * 1.5:  # Allow some expansion
            return GameInfo(
                name="unknown (expands beyond base ROM)",
                size=max_addr,
                console="unknown",
            )
    
    return None


def check_compatibility(
    base_rom: bytes,
    change_sets: list[ChangeSet],
    base_path: Optional[Path] = None,
) -> tuple[bool, list[str]]:
    """Check if all hacks are compatible with the base ROM and each other.
    
    Returns (is_compatible, list_of_issues).
    """
    issues: list[str] = []
    
    # Identify the base ROM
    base_info = identify_rom(base_rom)
    if base_info:
        print(f"Base ROM: {base_info.name} - {base_info.title} ({base_info.size} bytes)")
    else:
        print(f"Base ROM: {len(base_rom)} bytes (unrecognized format)")
    
    # Check each hack
    game_names: set[str] = set()
    
    for cs in change_sets:
        # Check if patch modifies addresses beyond base ROM (suspicious for same-game patches)
        max_addr = 0
        for offset, data in cs.changes.items():
            max_addr = max(max_addr, offset + len(data))
        
        if base_info and max_addr > base_info.size * 1.5:
            issues.append(
                f"{cs.name}: modifies up to 0x{max_addr:06X} but base ROM is only "
                f"0x{base_info.size:06X} — may be for a different game"
            )
        
        # For .bin files, try to identify the game
        if cs.source_format == "bin":
            # We'd need the original .bin data to identify it
            # For now, just check size
            if base_info and abs(max_addr - base_info.size) > base_info.size * 0.1:
                issues.append(
                    f"{cs.name}: size 0x{max_addr:06X} differs significantly from "
                    f"base ROM 0x{base_info.size:06X} — may be for a different game"
                )
    
    # Check for high conflict ratio (indicator of different games)
    if len(change_sets) >= 2:
        # Count conflicts without limit for accurate ratio
        total_conflicts = 0
        for i in range(len(change_sets)):
            for j in range(i + 1, len(change_sets)):
                conflicting = change_sets[i].conflicting_addresses(change_sets[j])
                total_conflicts += len(conflicting)
        
        # Calculate total modified bytes
        total_modified = sum(len(data) for cs in change_sets for data in cs.changes.values())
        
        if total_modified > 0 and total_conflicts > total_modified * 0.3:
            issues.append(
                f"Very high conflict ratio ({total_conflicts} conflicts / "
                f"{total_modified} modified bytes) — hacks may be for different games"
            )
    
    is_compatible = len(issues) == 0
    return is_compatible, issues


def is_disassembly_rebuild(cs: ChangeSet, base_rom: bytes) -> bool:
    """Heuristic: full .bin rebuilds that changed most of the ROM are likely disassembly builds."""
    if cs.source_format != "bin":
        return False
    changed = sum(len(d) for d in cs.changes.values())
    if len(base_rom) == 0:
        return False
    ratio = changed / max(1, len(base_rom))
    # Disassembly rebuilds typically rewrite a large portion of the ROM
    return ratio >= 0.35 and changed >= 0x20000


def suggest_test_case() -> str:
    """Suggest a valid test case for the user."""
    return """
To test ROMMAN properly, you need hacks for the SAME game:
- Two Sonic 2 patches (e.g., Boom Edition + another S2 hack)
- Two Sonic 1 patches
- Or create a synthetic test: take a base ROM, create patch A (modifies region X), 
  create patch B (modifies region Y), verify they merge cleanly

For Sonic 2, try finding other S2 hacks on ROMHacking.net or Sonic Retro.
"""
