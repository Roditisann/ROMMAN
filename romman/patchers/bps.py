"""BPS (Beat Patch System) parser and writer.

Format (by byuu):
  Header:  b"BPS1" + varint source_size + varint target_size
           + varint metadata_size + metadata
  Commands: varint-encoded (action | ((length-1) << 2))
    action 0: SourceRead  — copy from source at output offset
    action 1: TargetRead  — literal bytes follow
    action 2: SourceCopy  — varint delta offset, copy from source
    action 3: TargetCopy  — varint delta offset, copy from target
  Footer:  uint32 source_crc + uint32 target_crc + uint32 patch_crc

Variable-length number encoding (NOT LEB128):
  decode: data=0, shift=1
          loop: x=read(); data += (x&0x7f)*shift
                if x&0x80: break
                shift <<= 7; data += shift
  encode: loop: x = data & 0x7f; data >>= 7
                if data == 0: write(0x80|x); break
                write(x); data--
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
import struct
import zlib


# Command IDs (low 2 bits of the encoded command varint)
CMD_SOURCE_READ = 0
CMD_TARGET_READ = 1
CMD_SOURCE_COPY = 2
CMD_TARGET_COPY = 3


def read_varint(data: bytes, pos: int) -> Tuple[int, int]:
    """Read a BPS variable-length number. Returns (value, new_pos)."""
    value = 0
    shift = 1
    while True:
        if pos >= len(data):
            raise ValueError("Truncated varint")
        x = data[pos]
        pos += 1
        value += (x & 0x7F) * shift
        if x & 0x80:
            break
        shift <<= 7
        value += shift
    return value, pos


def write_varint(value: int) -> bytes:
    """Write a value as a BPS variable-length number."""
    out = bytearray()
    data = value
    while True:
        x = data & 0x7F
        data >>= 7
        if data == 0:
            out.append(0x80 | x)
            break
        out.append(x)
        data -= 1
    return bytes(out)


@dataclass
class BPSPatch:
    """Parsed BPS patch."""
    source_size: int = 0
    target_size: int = 0
    metadata: bytes = b""
    # Commands: list of (cmd_id, length, data_or_offset)
    commands: List[Tuple[int, int, bytes | int]] = field(default_factory=list)

    def apply(self, source: bytes) -> bytes:
        """Apply this BPS patch to a source ROM, returning the target."""
        if len(source) != self.source_size:
            raise ValueError(
                f"Source ROM size mismatch: expected {self.source_size}, got {len(source)}"
            )

        output = bytearray()
        source_rel = 0  # relative offset for SourceCopy
        target_rel = 0  # relative offset for TargetCopy

        for cmd_id, length, data in self.commands:
            if cmd_id == CMD_SOURCE_READ:
                # Copy from source at current output position
                start = len(output)
                output += source[start:start + length]

            elif cmd_id == CMD_TARGET_READ:
                # Literal bytes
                output += data  # type: ignore[operator]

            elif cmd_id == CMD_SOURCE_COPY:
                # Copy from source at source_rel (delta-encoded)
                source_rel += data  # type: ignore[operator]
                output += source[source_rel:source_rel + length]
                source_rel += length

            elif cmd_id == CMD_TARGET_COPY:
                # Copy from output at target_rel (delta-encoded)
                target_rel += data  # type: ignore[operator]
                # Copy byte-by-byte to handle overlapping regions
                for _ in range(length):
                    output.append(output[target_rel])
                    target_rel += 1

        return bytes(output)

    def extract_changes(self, source: bytes) -> Dict[int, bytes]:
        """Apply and extract per-address changes vs source."""
        target = self.apply(source)
        changes: Dict[int, bytes] = {}
        i = 0
        while i < len(source) and i < len(target):
            if source[i] != target[i]:
                start = i
                while i < len(source) and i < len(target) and source[i] != target[i]:
                    i += 1
                changes[start] = target[start:i]
            else:
                i += 1
        # Handle target longer than source
        if len(target) > len(source):
            changes[len(source)] = target[len(source):]
        return changes


def parse_bps(data: bytes) -> BPSPatch:
    """Parse a BPS patch file."""
    if not data.startswith(b"BPS1"):
        raise ValueError("Not a BPS file: missing BPS1 header")

    pos = 4
    patch = BPSPatch()

    patch.source_size, pos = read_varint(data, pos)
    patch.target_size, pos = read_varint(data, pos)
    meta_size, pos = read_varint(data, pos)
    patch.metadata = data[pos:pos + meta_size]
    pos += meta_size

    # Skip CRCs (source, target, patch) — 12 bytes at end
    data_end = len(data) - 12
    if data_end < pos:
        data_end = len(data)  # Fallback if no CRCs

    output_pos = 0
    source_rel = 0
    target_rel = 0

    while pos < data_end:
        cmd_data, pos = read_varint(data, pos)
        cmd_id = cmd_data & 3          # action is low 2 bits
        length = (cmd_data >> 2) + 1   # length-1 is stored above the action bits

        if cmd_id == CMD_SOURCE_READ:
            patch.commands.append((cmd_id, length, b""))
            output_pos += length

        elif cmd_id == CMD_TARGET_READ:
            patch.commands.append((cmd_id, length, data[pos:pos + length]))
            pos += length
            output_pos += length

        elif cmd_id == CMD_SOURCE_COPY:
            delta, pos = read_varint(data, pos)
            # Delta is sign-magnitude: bit 0 = sign, rest = magnitude
            sign = -1 if (delta & 1) else 1
            delta = (delta >> 1) * sign
            source_rel += delta
            patch.commands.append((cmd_id, length, delta))
            output_pos += length

        elif cmd_id == CMD_TARGET_COPY:
            delta, pos = read_varint(data, pos)
            sign = -1 if (delta & 1) else 1
            delta = (delta >> 1) * sign
            target_rel += delta
            patch.commands.append((cmd_id, length, delta))
            output_pos += length

        else:
            raise ValueError(f"Unknown BPS command: {cmd_id}")

    return patch


def write_bps(patch: BPSPatch, source: bytes, target: bytes) -> bytes:
    """Write a BPS patch from source and target ROMs (linear style)."""
    # Compute diff as contiguous changed ranges
    changes: List[Tuple[int, bytes]] = []
    i = 0
    min_len = min(len(source), len(target))
    while i < min_len:
        if source[i] != target[i]:
            start = i
            while i < min_len and source[i] != target[i]:
                i += 1
            changes.append((start, target[start:i]))
        else:
            i += 1
    if len(target) > len(source):
        changes.append((len(source), target[len(source):]))

    # Build header
    out = bytearray(b"BPS1")
    out += write_varint(len(source))
    out += write_varint(len(target))
    out += write_varint(len(patch.metadata))
    out += patch.metadata

    # Build commands
    cmd_bytes = bytearray()
    output_pos = 0

    for offset, data in changes:
        # Fill gap with SourceRead
        if offset > output_pos:
            gap = offset - output_pos
            cmd_bytes += write_varint((gap - 1) << 2 | CMD_SOURCE_READ)
            output_pos = offset

        # Write TargetRead for the actual change
        cmd_bytes += write_varint((len(data) - 1) << 2 | CMD_TARGET_READ)
        cmd_bytes += data
        output_pos += len(data)

    # Final SourceRead for remaining
    if output_pos < len(target):
        gap = len(target) - output_pos
        cmd_bytes += write_varint((gap - 1) << 2 | CMD_SOURCE_READ)

    out += cmd_bytes

    # CRCs
    source_crc = zlib.crc32(source) & 0xFFFFFFFF
    target_crc = zlib.crc32(target) & 0xFFFFFFFF
    patch_crc = zlib.crc32(bytes(out)) & 0xFFFFFFFF
    out += struct.pack("<III", source_crc, target_crc, patch_crc)

    return bytes(out)
