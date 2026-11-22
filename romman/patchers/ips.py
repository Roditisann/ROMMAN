"""IPS (International Patching System) parser and writer.

Format:
  Header:  b"PATCH"
  Records: 3-byte offset + 2-byte length + data
           If length == 0: RLE record — 2-byte RLE length + 1-byte value
  Footer:  b"EOF" (optional extension: 3-byte offset after EOF for >16MB ROMs)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict

HEADER = b"PATCH"
FOOTER = b"EOF"


@dataclass
class IPSPatch:
    """Parsed IPS patch as a dict of offset -> bytes."""
    changes: Dict[int, bytes] = field(default_factory=dict)

    def add(self, offset: int, data: bytes) -> None:
        if not data:
            return
        # Merge with existing entry if contiguous
        if offset in self.changes:
            self.changes[offset] += data
        else:
            self.changes[offset] = data

    def size(self) -> int:
        return sum(len(v) for v in self.changes.values())


def parse_ips(data: bytes) -> IPSPatch:
    """Parse an IPS patch file into an IPSPatch."""
    if not data.startswith(HEADER):
        raise ValueError("Not an IPS file: missing PATCH header")

    pos = len(HEADER)
    patch = IPSPatch()

    while pos < len(data):
        # Check for EOF
        if data[pos:pos + 3] == FOOTER:
            pos += 3
            # Check for extension (3-byte offset for large ROMs)
            if pos + 3 <= len(data):
                # Some tools append a 3-byte offset after EOF for >16MB support
                # We ignore it for now (rare in practice)
                pass
            break

        if pos + 5 > len(data):
            break  # Truncated record

        # Read 3-byte offset
        offset = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]
        pos += 3

        # Read 2-byte length
        length = (data[pos] << 8) | data[pos + 1]
        pos += 2

        if length == 0:
            # RLE record
            if pos + 3 > len(data):
                break
            rle_length = (data[pos] << 8) | data[pos + 1]
            rle_value = data[pos + 2]
            pos += 3
            patch.add(offset, bytes([rle_value]) * rle_length)
        else:
            # Normal record
            if pos + length > len(data):
                break  # Truncated
            patch.add(offset, data[pos:pos + length])
            pos += length

    return patch


def write_ips(patch: IPSPatch, base_size: int = 0) -> bytes:
    """Write an IPSPatch back to IPS format bytes."""
    out = bytearray(HEADER)

    for offset in sorted(patch.changes.keys()):
        data = patch.changes[offset]
        pos = 0

        while pos < len(data):
            chunk = data[pos:pos + 0xFFFF]  # Max 65535 bytes per record
            chunk_offset = offset + pos

            if len(chunk) == 1 and pos + 1 < len(data) and data[pos + 1] == chunk[0]:
                # Potential RLE — check if next bytes are same value
                run_len = 1
                while (pos + run_len < len(data) and
                       data[pos + run_len] == chunk[0] and
                       run_len < 0xFFFF):
                    run_len += 1
                if run_len >= 3:  # RLE only worth it for runs >= 3
                    # Write RLE record
                    out += bytes([
                        (chunk_offset >> 16) & 0xFF,
                        (chunk_offset >> 8) & 0xFF,
                        chunk_offset & 0xFF,
                        0, 0,  # length = 0 signals RLE
                        (run_len >> 8) & 0xFF,
                        run_len & 0xFF,
                        chunk[0]
                    ])
                    pos += run_len
                    continue

            # Normal record
            out += bytes([
                (chunk_offset >> 16) & 0xFF,
                (chunk_offset >> 8) & 0xFF,
                chunk_offset & 0xFF,
                (len(chunk) >> 8) & 0xFF,
                len(chunk) & 0xFF
            ])
            out += chunk
            pos += len(chunk)

    out += FOOTER
    return bytes(out)
