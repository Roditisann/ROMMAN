"""ROM checksum/hash fixups and identification helpers."""

from __future__ import annotations

import hashlib
import zlib
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class RomHashes:
    crc32: str
    md5: str
    size: int


def rom_hashes(data: bytes) -> RomHashes:
    return RomHashes(
        crc32=f"{zlib.crc32(data) & 0xFFFFFFFF:08X}",
        md5=hashlib.md5(data).hexdigest().upper(),
        size=len(data),
    )


def detect_system(data: bytes) -> str:
    if len(data) >= 0x200:
        hdr = data[0x100:0x120]
        if b"SEGA MEGA DRIVE" in hdr or b"SEGA GENESIS" in hdr or b"SEGA 32X" in hdr:
            return "genesis"
    if len(data) >= 0x150:
        # GB/GBC: Nintendo logo at 0x104-0x133, header checksum at 0x14D
        logo = bytes.fromhex(
            "CEED6666CC0D000B03730083000C000D0008111F888900EDCC6666CC0D000B0300730083000C000D0008111F888900ED"
        )
        if data[0x104:0x134] == logo:
            cgb = data[0x143] if len(data) > 0x143 else 0
            return "gbc" if cgb in (0x80, 0xC0) else "gb"
    # SNES heuristic: check LoROM/HiROM header checksums
    for offset, mode in ((0x7FFC, "lorom"), (0xFFFC, "hirom")):
        if len(data) >= offset + 4:
            complement = int.from_bytes(data[offset:offset+2], "little")
            checksum = int.from_bytes(data[offset+2:offset+4], "little")
            if (complement ^ checksum) == 0xFFFF and checksum != 0:
                return f"snes_{mode}"
    # iNES-wrapped NES - still NES, checksums differ; report nes
    if len(data) >= 16 and data[:4] == b"NES\x1a":
        return "nes"
    return "unknown"


def fix_genesis_checksum(data: bytearray) -> bool:
    """Recalculate Genesis 16-bit checksum at 0x18E-0x18F. Returns True if changed."""
    if len(data) < 0x200:
        return False
    checksum = 0
    for i in range(0x200, len(data), 2):
        word = data[i] << 8
        if i + 1 < len(data):
            word |= data[i + 1]
        checksum = (checksum + word) & 0xFFFF
    old = (data[0x18E] << 8) | data[0x18F]
    if old != checksum:
        data[0x18E] = (checksum >> 8) & 0xFF
        data[0x18F] = checksum & 0xFF
        return True
    return False


def fix_gb_checksum(data: bytearray) -> Tuple[bool, bool]:
    """Recalculate GB/GBC header checksum (0x14D) and global checksum (0x14E-14F).
    Returns (header_changed, global_changed)."""
    if len(data) < 0x150:
        return False, False
    # Header checksum: -sum(0x134..0x14C inclusive) - 1, 8-bit
    x = 0
    for i in range(0x134, 0x14D):
        x = (x - data[i] - 1) & 0xFF
    header_changed = data[0x14D] != x
    data[0x14D] = x

    # Global checksum: 16-bit sum of all bytes except 0x14E-0x14F
    g = 0
    for i, b in enumerate(data):
        if i in (0x14E, 0x14F):
            continue
        g = (g + b) & 0xFFFF
    old_g = (data[0x14E] << 8) | data[0x14F]
    global_changed = old_g != g
    data[0x14E] = (g >> 8) & 0xFF
    data[0x14F] = g & 0xFF
    return header_changed, global_changed


def fix_snes_checksum(data: bytearray) -> bool:
    """Recalculate SNES complement+checksum for detected LoROM/HiROM. Returns True if changed."""
    # Detect which header is valid
    target = None
    for offset, mode in ((0x7FFC, "lorom"), (0xFFFC, "hirom")):
        if len(data) >= offset + 4:
            complement = int.from_bytes(data[offset:offset+2], "little")
            checksum = int.from_bytes(data[offset+2:offset+4], "little")
            if (complement ^ checksum) == 0xFFFF and checksum != 0:
                target = offset
                break
    if target is None:
        # fallback heuristic: prefer hirom if size >= 0x10000 else lorom
        target = 0xFFFC if len(data) >= 0x10000 else 0x7FFC
        if len(data) < target + 4:
            return False

    # Compute checksum over entire ROM, optionally mirroring for power-of-two issues
    # Simple approach: sum all bytes as 16-bit
    total = sum(data) & 0xFFFF
    complement = (~total) & 0xFFFF
    old_c = int.from_bytes(data[target:target+2], "little")
    old_s = int.from_bytes(data[target+2:target+4], "little")
    if old_c == complement and old_s == total:
        return False
    data[target:target+2] = complement.to_bytes(2, "little")
    data[target+2:target+4] = total.to_bytes(2, "little")
    return True


def clean_ines_header(data: bytearray) -> bool:
    """Clean dirty iNES header junk (e.g. DiskDude!) in bytes 7-15 when not iNES 2.0."""
    if len(data) < 16 or data[:4] != b"NES\x1a":
        return False
    # iNES 2.0: bits 2-3 of byte 7 == 0b10
    if (data[7] & 0x0C) == 0x08:
        return False
    tail = bytes(data[7:16])
    if tail == b"\x00" * 9:
        return False
    # Common junk: "DiskDude!" or other printable garbage
    if b"DiskDude" in tail or any(b > 0x00 and (b < 0x20 or b > 0x7E) for b in tail) or any(b != 0 for b in tail):
        # Only clean if it looks like junk, not meaningful extended fields
        # Keep byte 7 lower bits? For iNES 1.0, bytes 7-15 are usually 0; clear 7-15.
        for i in range(7, 16):
            data[i] = 0
        return True
    return False


def apply_fixups(data: bytes) -> Tuple[bytes, list[str]]:
    """Apply known checksum fixups based on detected system. Returns (fixed_data, messages)."""
    buf = bytearray(data)
    msgs: list[str] = []
    sys = detect_system(data)
    if sys == "genesis":
        if fix_genesis_checksum(buf):
            msgs.append("Genesis checksum fixed (0x018E-0x018F)")
        else:
            msgs.append("Genesis checksum already OK")
    elif sys in ("gb", "gbc"):
        hc, gc = fix_gb_checksum(buf)
        if hc or gc:
            parts = []
            if hc: parts.append("header 0x014D")
            if gc: parts.append("global 0x014E-0x014F")
            msgs.append(f"GB/GBC checksum fixed ({', '.join(parts)})")
        else:
            msgs.append("GB/GBC checksums already OK")
    elif sys.startswith("snes"):
        if fix_snes_checksum(buf):
            msgs.append(f"SNES checksum fixed ({sys.split('_',1)[1].upper()})")
        else:
            msgs.append("SNES checksum already OK")
    elif sys == "nes":
        if clean_ines_header(buf):
            msgs.append("NES iNES header cleaned (bytes 7-15)")
    return bytes(buf), msgs
