"""ROMMAN tests — core merge logic."""

import sys
import io
from pathlib import Path

# Fix Windows console encoding for checkmarks
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Add parent dir to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from romman.changeset import ChangeSet
from romman.merger import merge, detect_conflicts, detect_warnings
from romman.rom import apply_changes, diff_roms
from romman.patchers.ips import parse_ips, write_ips, IPSPatch


def test_no_conflicts():
    """Two hacks modifying different addresses should merge cleanly."""
    base = bytes(1000)

    cs1 = ChangeSet(name="hack1", changes={100: b"\xAA\xBB\xCC"})
    cs2 = ChangeSet(name="hack2", changes={500: b"\x11\x22\x33"})

    result = merge([cs1, cs2])
    assert result.success, "Should succeed with no conflicts"
    assert len(result.conflicts) == 0
    assert result.merged.changes[100] == b"\xAA\xBB\xCC"
    assert result.merged.changes[500] == b"\x11\x22\x33"
    print("✓ test_no_conflicts")


def test_conflict_detected():
    """Two hacks modifying the same address with different values."""
    cs1 = ChangeSet(name="hack1", changes={100: b"\xAA"})
    cs2 = ChangeSet(name="hack2", changes={100: b"\xBB"})

    result = merge([cs1, cs2])
    assert not result.success, "Should fail with conflicts"
    assert len(result.conflicts) == 1
    assert result.conflicts[0].address == 100
    assert result.conflicts[0].bytes_a == b"\xAA"
    assert result.conflicts[0].bytes_b == b"\xBB"
    print("✓ test_conflict_detected")


def test_conflict_resolution():
    """Priority should resolve conflicts."""
    cs1 = ChangeSet(name="hack1", changes={100: b"\xAA"})
    cs2 = ChangeSet(name="hack2", changes={100: b"\xBB"})

    # hack1 has higher priority
    result = merge([cs1, cs2], priority=["hack1", "hack2"])
    assert result.success, "Should succeed with priority"
    assert result.merged.changes[100] == b"\xAA", "hack1 should win"

    # hack2 has higher priority
    result = merge([cs1, cs2], priority=["hack2", "hack1"])
    assert result.success
    assert result.merged.changes[100] == b"\xBB", "hack2 should win"
    print("✓ test_conflict_resolution")


def test_overlapping_ranges():
    """Overlapping byte ranges should be detected."""
    cs1 = ChangeSet(name="hack1", changes={100: b"\xAA\xBB\xCC\xDD"})
    cs2 = ChangeSet(name="hack2", changes={102: b"\x11\x22"})

    conflicts = detect_conflicts([cs1, cs2])
    assert len(conflicts) == 2, f"Should find 2 conflicting addresses, got {len(conflicts)}"
    print("✓ test_overlapping_ranges")


def test_benign_overlap():
    """Same value at same address is not a conflict."""
    cs1 = ChangeSet(name="hack1", changes={100: b"\xAA\xBB"})
    cs2 = ChangeSet(name="hack2", changes={100: b"\xAA\xBB"})

    conflicts = detect_conflicts([cs1, cs2])
    assert len(conflicts) == 0, "Same values should not conflict"
    print("✓ test_benign_overlap")


def test_bin_diff():
    """Diffing two ROMs should extract changes."""
    base = bytes(range(100))
    modified = bytearray(base)
    modified[50] = 0xFF
    modified[51] = 0xFE

    changes = diff_roms(base, bytes(modified))
    assert 50 in changes
    assert changes[50] == b"\xFF\xFE"
    print("✓ test_bin_diff")


def test_apply_changes():
    """Applying changes should modify the base ROM."""
    base = bytes(1000)
    cs = ChangeSet(name="test", changes={100: b"\xAA\xBB\xCC"})

    result = apply_changes(base, cs)
    assert result[100] == 0xAA
    assert result[101] == 0xBB
    assert result[102] == 0xCC
    assert result[99] == 0x00  # Unchanged
    print("✓ test_apply_changes")


def test_ips_roundtrip():
    """IPS write → parse should be lossless."""
    original = IPSPatch(changes={100: b"\xAA\xBB\xCC", 500: b"\x11\x22"})
    data = write_ips(original)
    parsed = parse_ips(data)

    for offset, expected in original.changes.items():
        assert offset in parsed.changes, f"Missing offset {offset}"
        assert parsed.changes[offset] == expected, (
            f"Data mismatch at {offset}: {parsed.changes[offset].hex()} != {expected.hex()}"
        )
    print("✓ test_ips_roundtrip")


def test_merge_three():
    """Merge three hacks with two clean and one conflicting."""
    cs1 = ChangeSet(name="h1", changes={100: b"\xAA", 200: b"\xBB"})
    cs2 = ChangeSet(name="h2", changes={300: b"\xCC", 400: b"\xDD"})
    cs3 = ChangeSet(name="h3", changes={200: b"\xEE", 500: b"\xFF"})  # conflicts with h1 at 200

    result = merge([cs1, cs2, cs3], priority=["h1", "h3"])
    assert result.success
    assert result.merged.changes[100] == b"\xAA"
    assert result.merged.changes[200] == b"\xBB", "h1 should win at 200"
    assert result.merged.changes[300] == b"\xCC"
    assert result.merged.changes[400] == b"\xDD"
    assert result.merged.changes[500] == b"\xFF"
    print("✓ test_merge_three")


if __name__ == "__main__":
    test_no_conflicts()
    test_conflict_detected()
    test_conflict_resolution()
    test_overlapping_ranges()
    test_benign_overlap()
    test_bin_diff()
    test_apply_changes()
    test_ips_roundtrip()
    test_merge_three()
    print("\n✅ All tests passed!")
