"""End-to-end CLI test with synthetic ROM hacks."""

import sys
import io
import tempfile
from pathlib import Path

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent))

from romman.cli import main
from romman.patchers.ips import IPSPatch, write_ips
from romman.patchers.bps import BPSPatch, write_bps


def test_cli_merge_clean():
    """Two IPS patches with no conflicts should merge cleanly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # Create a fake base ROM (1KB)
        base = bytes(range(256)) * 4  # 1024 bytes
        (tmp / "base.bin").write_bytes(base)

        # Create two non-overlapping IPS patches
        patch1 = IPSPatch(changes={100: b"\xAA\xBB\xCC"})
        patch2 = IPSPatch(changes={500: b"\x11\x22\x33"})
        (tmp / "hack1.ips").write_bytes(write_ips(patch1))
        (tmp / "hack2.ips").write_bytes(write_ips(patch2))

        # Run CLI
        output = tmp / "merged.bin"
        rc = main([
            str(tmp / "base.bin"),
            str(tmp / "hack1.ips"),
            str(tmp / "hack2.ips"),
            "-o", str(output),
        ])

        assert rc == 0, f"CLI returned {rc}"
        assert output.exists(), "Output file not created"

        # Verify merged content
        result = output.read_bytes()
        assert result[100] == 0xAA
        assert result[101] == 0xBB
        assert result[102] == 0xCC
        assert result[500] == 0x11
        assert result[501] == 0x22
        assert result[502] == 0x33
        assert result[0] == 0x00  # Unchanged byte
        print("  [OK] Merged output is correct")


def test_cli_conflict_check():
    """Conflicting patches should be detected with --check."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        base = bytes(1024)
        (tmp / "base.bin").write_bytes(base)

        # Two conflicting patches
        patch1 = IPSPatch(changes={100: b"\xAA"})
        patch2 = IPSPatch(changes={100: b"\xBB"})
        (tmp / "hack1.ips").write_bytes(write_ips(patch1))
        (tmp / "hack2.ips").write_bytes(write_ips(patch2))

        # --check should return 1 (conflicts found)
        rc = main([
            str(tmp / "base.bin"),
            str(tmp / "hack1.ips"),
            str(tmp / "hack2.ips"),
            "--check",
        ])
        assert rc == 1, f"Expected rc=1 for conflicts, got {rc}"
        print("  [OK] Conflict detection works")


def test_cli_priority_resolution():
    """Priority flag should resolve conflicts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        base = bytes(1024)
        (tmp / "base.bin").write_bytes(base)

        patch1 = IPSPatch(changes={100: b"\xAA"})
        patch2 = IPSPatch(changes={100: b"\xBB"})
        (tmp / "hack1.ips").write_bytes(write_ips(patch1))
        (tmp / "hack2.ips").write_bytes(write_ips(patch2))

        # hack2 has priority
        output = tmp / "merged.bin"
        rc = main([
            str(tmp / "base.bin"),
            str(tmp / "hack1.ips"),
            str(tmp / "hack2.ips"),
            "-o", str(output),
            "--priority", "hack2.ips", "hack1.ips",
        ])

        assert rc == 0, f"CLI returned {rc}"
        result = output.read_bytes()
        assert result[100] == 0xBB, f"hack2 should win, got 0x{result[100]:02X}"
        print("  [OK] Priority resolution works")


def test_cli_bin_input():
    """Full .bin hack should be diffed against base."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        base = bytes(1024)
        (tmp / "base.bin").write_bytes(base)

        # Create a "hack" as a full ROM with changes
        hack_rom = bytearray(base)
        hack_rom[200] = 0xFF
        hack_rom[201] = 0xFE
        (tmp / "sonicboom.bin").write_bytes(bytes(hack_rom))

        output = tmp / "merged.bin"
        rc = main([
            str(tmp / "base.bin"),
            str(tmp / "sonicboom.bin"),
            "-o", str(output),
        ])

        assert rc == 0
        result = output.read_bytes()
        assert result[200] == 0xFF
        assert result[201] == 0xFE
        print("  [OK] .bin input works")


def test_cli_output_ips():
    """Should be able to output IPS format."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        base = bytes(1024)
        (tmp / "base.bin").write_bytes(base)

        patch1 = IPSPatch(changes={100: b"\xAA\xBB"})
        (tmp / "hack1.ips").write_bytes(write_ips(patch1))

        output = tmp / "combined.ips"
        rc = main([
            str(tmp / "base.bin"),
            str(tmp / "hack1.ips"),
            "-o", str(output),
            "--format", "ips",
        ])

        assert rc == 0
        assert output.exists()
        # Verify it's a valid IPS file
        data = output.read_bytes()
        assert data.startswith(b"PATCH")
        assert data.endswith(b"EOF")
        print("  [OK] IPS output works")


def test_cli_mixed_formats():
    """Mix IPS and .bin inputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        base = bytes(1024)
        (tmp / "base.bin").write_bytes(base)

        patch1 = IPSPatch(changes={100: b"\xAA"})
        (tmp / "hack1.ips").write_bytes(write_ips(patch1))

        hack_rom = bytearray(base)
        hack_rom[500] = 0xFF
        (tmp / "hack2.bin").write_bytes(bytes(hack_rom))

        output = tmp / "merged.bin"
        rc = main([
            str(tmp / "base.bin"),
            str(tmp / "hack1.ips"),
            str(tmp / "hack2.bin"),
            "-o", str(output),
        ])

        assert rc == 0
        result = output.read_bytes()
        assert result[100] == 0xAA
        assert result[500] == 0xFF
        print("  [OK] Mixed format inputs work")


if __name__ == "__main__":
    print("Running CLI end-to-end tests...\n")
    test_cli_merge_clean()
    test_cli_conflict_check()
    test_cli_priority_resolution()
    test_cli_bin_input()
    test_cli_output_ips()
    test_cli_mixed_formats()
    print("\n[ALL PASS] CLI tests passed!")
