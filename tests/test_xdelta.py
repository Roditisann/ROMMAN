"""Tests for xdelta patch support."""

import sys
import io
from pathlib import Path

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent))

from romman.patchers.xdelta import parse_xdelta, write_xdelta, is_xdelta, XDeltaPatch
from romman.changeset import ChangeSet
from romman.rom import load_input, apply_changes


def test_is_xdelta():
    """Should detect xdelta magic bytes."""
    assert is_xdelta(b"\xD6\xC3\xC4\x00") is True
    assert is_xdelta(b"PATCH") is False
    assert is_xdelta(b"BPS1") is False
    print("  [OK] is_xdelta detection")


def test_xdelta_roundtrip():
    """Create xdelta patch, decode it, verify changes match."""
    import tempfile
    tmp = Path(tempfile.mkdtemp())

    base = bytes(1024)
    target = bytearray(base)
    target[100] = 0xFF
    target[101] = 0xFE
    target[500] = 0xAA

    base_path = tmp / "base.bin"
    target_path = tmp / "target.bin"
    patch_path = tmp / "test.xdelta"

    base_path.write_bytes(base)
    target_path.write_bytes(bytes(target))

    # Create patch
    write_xdelta(bytes(target), base, patch_path)
    assert patch_path.exists(), "Patch file not created"
    assert is_xdelta(patch_path.read_bytes()), "Patch doesn't have xdelta magic"
    print(f"  [OK] xdelta patch created ({patch_path.stat().st_size} bytes)")

    # Parse patch
    patch = parse_xdelta(patch_path, base)
    assert isinstance(patch, XDeltaPatch)
    assert len(patch.changes) > 0, "No changes extracted"

    # Verify changes
    cs = ChangeSet(name="test", changes=patch.changes, source_format="xdelta")
    result = apply_changes(base, cs)
    assert result == bytes(target), "Decoded patch doesn't match target"
    print("  [OK] xdelta roundtrip produces correct output")


def test_xdelta_via_load_input():
    """load_input should handle .xdelta files."""
    import tempfile
    tmp = Path(tempfile.mkdtemp())

    base = bytes(2048)
    target = bytearray(base)
    target[1000:1010] = b"\xAA" * 10

    patch_path = tmp / "test.xdelta"
    write_xdelta(bytes(target), base, patch_path)

    cs = load_input(patch_path, base)
    assert cs.source_format == "xdelta"
    assert cs.changes, "No changes"

    result = apply_changes(base, cs)
    assert result == bytes(target)
    print("  [OK] load_input handles xdelta")


if __name__ == "__main__":
    print("Running xdelta tests...\n")
    test_is_xdelta()
    test_xdelta_roundtrip()
    test_xdelta_via_load_input()
    print("\n[ALL PASS] xdelta tests passed!")
