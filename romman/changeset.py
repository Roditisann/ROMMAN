"""Normalized change set: address -> bytes, regardless of source format."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple
from pathlib import Path


@dataclass
class ChangeSet:
    """A set of byte changes keyed by ROM offset."""
    name: str  # Hack name / filename
    changes: Dict[int, bytes] = field(default_factory=dict)
    source_format: str = "unknown"  # "ips", "bps", "bin"

    @property
    def addresses(self) -> Set[int]:
        """All modified addresses."""
        addrs: Set[int] = set()
        for offset, data in self.changes.items():
            addrs.update(range(offset, offset + len(data)))
        return addrs

    @property
    def ranges(self) -> List[Tuple[int, int]]:
        """Sorted list of (start, end_exclusive) contiguous ranges."""
        ranges = []
        for offset, data in self.changes.items():
            ranges.append((offset, offset + len(data)))
        ranges.sort()
        # Merge adjacent ranges
        merged: List[Tuple[int, int]] = []
        for start, end in ranges:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged

    def overlaps_with(self, other: "ChangeSet") -> List[Tuple[int, int, str, str]]:
        """Find overlapping address ranges between two change sets.
        
        Returns list of (start, end, self_name, other_name) for each overlap.
        """
        overlaps = []
        my_ranges = self.ranges
        other_ranges = other.ranges

        i, j = 0, 0
        while i < len(my_ranges) and j < len(other_ranges):
            my_start, my_end = my_ranges[i]
            other_start, other_end = other_ranges[j]

            # Find intersection
            start = max(my_start, other_start)
            end = min(my_end, other_end)

            if start < end:
                overlaps.append((start, end, self.name, other.name))

            # Advance the one that ends first
            if my_end < other_end:
                i += 1
            else:
                j += 1

        return overlaps

    def conflicting_addresses(self, other: "ChangeSet") -> Dict[int, Tuple[bytes, bytes]]:
        """Return dict of address -> (my_bytes, other_bytes) for actual conflicts.
        
        Only includes addresses where both patches write *different* values.
        Uses range-based intersection for performance.
        """
        conflicts: Dict[int, Tuple[bytes, bytes]] = {}
        
        # Build sorted range lists for both
        my_ranges = sorted(self.changes.items())
        other_ranges = sorted(other.changes.items())
        
        i, j = 0, 0
        while i < len(my_ranges) and j < len(other_ranges):
            my_off, my_data = my_ranges[i]
            other_off, other_data = other_ranges[j]
            my_end = my_off + len(my_data)
            other_end = other_off + len(other_data)
            
            # Find overlap
            start = max(my_off, other_off)
            end = min(my_end, other_end)
            
            if start < end:
                # Check for actual value conflicts in overlap
                for addr in range(start, end):
                    my_byte = my_data[addr - my_off:addr - my_off + 1]
                    other_byte = other_data[addr - other_off:addr - other_off + 1]
                    if my_byte != other_byte:
                        conflicts[addr] = (my_byte, other_byte)
            
            # Advance the one that ends first
            if my_end < other_end:
                i += 1
            else:
                j += 1
        
        return conflicts

    def get_byte(self, addr: int) -> bytes | None:
        """Get the byte(s) at a specific address."""
        for offset, data in self.changes.items():
            if offset <= addr < offset + len(data):
                rel = addr - offset
                return data[rel:rel + 1]
        return None

    @classmethod
    def from_bin(cls, bin_path: Path, base_rom: bytes, name: str = "") -> "ChangeSet":
        """Extract changes from a full .bin ROM vs a base ROM."""
        bin_data = bin_path.read_bytes()
        if not name:
            name = bin_path.name

        cs = cls(name=name, source_format="bin")
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
        # Handle ROM larger than base
        if len(bin_data) > len(base_rom):
            cs.changes[len(base_rom)] = bin_data[len(base_rom):]
        return cs

    def __repr__(self) -> str:
        n_ranges = len(self.ranges)
        n_addrs = len(self.addresses)
        return f"ChangeSet({self.name!r}, {n_ranges} ranges, {n_addrs} bytes, {self.source_format})"
