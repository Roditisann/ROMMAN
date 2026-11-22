"""Tests for game compatibility detection."""

import sys
import io
from pathlib import Path

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent))

from romman.compat import identify_rom, check_compatibility, GameInfo
from romman.changeset import ChangeSet


def test_identify_genesis_rom():
    """Should identify a Genesis ROM from its header."""
    # Create a fake Genesis ROM header
    rom = bytearray(0x1000)
    # Console name at 0x100
    rom[0x100:0x110] = b"SEGA MEGA DRIVE "
    # Title at 0x120
    rom[0x120:0x140] = b"SONIC THE HEDGEHOG 2"
    
    info = identify_rom(bytes(rom))
    assert info is not None, "Should identify Genesis ROM"
    assert info.console == "genesis"
    assert "SEGA" in info.name
    print("  [OK] Genesis ROM identified")


def test_identify_unknown_rom():
    """Should return None for unknown format."""
    rom = bytes(0x1000)  # All zeros
    info = identify_rom(rom)
    assert info is None, "Should not identify unknown ROM"
    print("  [OK] Unknown ROM returns None")


def test_compatibility_same_game():
    """Two patches for the same game should be compatible."""
    # Create a fake base ROM (Genesis)
    base = bytearray(0x100000)
    base[0x100:0x110] = b"SEGA MEGA DRIVE "
    base[0x120:0x140] = b"SONIC THE HEDGEHOG 2"
    
    # Two patches modifying different regions
    cs1 = ChangeSet(name="hack1", changes={0x1000: b"\xAA\xBB"}, source_format="ips")
    cs2 = ChangeSet(name="hack2", changes={0x2000: b"\xCC\xDD"}, source_format="ips")
    
    is_compatible, issues = check_compatibility(bytes(base), [cs1, cs2])
    assert is_compatible, f"Should be compatible, got issues: {issues}"
    print("  [OK] Same-game patches are compatible")


def test_compatibility_different_game():
    """A patch for a different game should be flagged."""
    # Create a fake base ROM (Genesis, 1MB)
    base = bytearray(0x100000)
    base[0x100:0x110] = b"SEGA MEGA DRIVE "
    base[0x120:0x140] = b"SONIC THE HEDGEHOG 2"
    
    # A patch that modifies way beyond the base ROM (like a 4MB ROM hack)
    cs1 = ChangeSet(name="other_game", changes={0x300000: b"\xAA\xBB"}, source_format="ips")
    
    is_compatible, issues = check_compatibility(bytes(base), [cs1])
    assert not is_compatible, "Should not be compatible"
    assert len(issues) > 0, "Should have issues"
    print("  [OK] Different-game patch is flagged")


def test_compatibility_high_conflict_ratio():
    """Two patches with very high conflict ratio may be different games."""
    # Create a fake base ROM
    base = bytearray(0x100000)
    base[0x100:0x110] = b"SEGA MEGA DRIVE "
    
    # Two patches that conflict heavily (same addresses, different values)
    changes1 = {i: b"\xAA" for i in range(0x1000, 0x2000)}
    changes2 = {i: b"\xBB" for i in range(0x1000, 0x2000)}
    
    cs1 = ChangeSet(name="hack1", changes=changes1, source_format="ips")
    cs2 = ChangeSet(name="hack2", changes=changes2, source_format="ips")
    
    is_compatible, issues = check_compatibility(bytes(base), [cs1, cs2])
    # High conflict ratio should be flagged
    assert not is_compatible, "High conflict ratio should be flagged"
    print("  [OK] High conflict ratio is flagged")


if __name__ == "__main__":
    print("Running compatibility tests...\n")
    test_identify_genesis_rom()
    test_identify_unknown_rom()
    test_compatibility_same_game()
    test_compatibility_different_game()
    test_compatibility_high_conflict_ratio()
    print("\n[ALL PASS] Compatibility tests passed!")
