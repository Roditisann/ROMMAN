"""Merge engine: detects conflicts and merges change sets with optional priority."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from .changeset import ChangeSet


@dataclass
class Conflict:
    """A single address conflict between two change sets."""
    address: int
    hack_a: str
    hack_b: str
    bytes_a: bytes
    bytes_b: bytes

    @property
    def range_start(self) -> int:
        return self.address

    @property
    def range_end(self) -> int:
        return self.address + 1

    def __repr__(self) -> str:
        return (
            f"Conflict @ 0x{self.address:06X}: "
            f"{self.hack_a}={self.bytes_a.hex()} vs {self.hack_b}={self.bytes_b.hex()}"
        )


@dataclass
class MergeResult:
    """Result of a merge operation."""
    merged: ChangeSet
    conflicts: List[Conflict]
    warnings: List[str] = field(default_factory=list)
    success: bool = True


def detect_conflicts(change_sets: List[ChangeSet]) -> List[Conflict]:
    """Detect all conflicts between a list of change sets."""
    conflicts: List[Conflict] = []
    for i in range(len(change_sets)):
        for j in range(i + 1, len(change_sets)):
            cs_a = change_sets[i]
            cs_b = change_sets[j]
            conflicting = cs_a.conflicting_addresses(cs_b)
            # Limit output for huge conflict sets
            for addr, (bytes_a, bytes_b) in list(conflicting.items())[:1000]:
                conflicts.append(Conflict(
                    address=addr,
                    hack_a=cs_a.name,
                    hack_b=cs_b.name,
                    bytes_a=bytes_a,
                    bytes_b=bytes_b,
                ))
    return conflicts


def detect_warnings(change_sets: List[ChangeSet]) -> List[str]:
    """Detect semantic warnings (non-overlapping but suspicious)."""
    warnings: List[str] = []
    for i in range(len(change_sets)):
        for j in range(i + 1, len(change_sets)):
            cs_a = change_sets[i]
            cs_b = change_sets[j]
            overlaps = cs_a.overlaps_with(cs_b)
            for start, end, name_a, name_b in overlaps:
                # Check if they write the same value (benign overlap)
                same = True
                for addr in range(start, min(end, start + 100)):  # Sample check
                    ba = cs_a.get_byte(addr)
                    bb = cs_b.get_byte(addr)
                    if ba != bb:
                        same = False
                        break
                if same:
                    continue
                # Already reported as conflict, skip
            
            # Check for close-but-not-overlapping ranges (sorted merge approach)
            my_ranges = cs_a.ranges
            other_ranges = cs_b.ranges
            other_starts = [r[0] for r in other_ranges]  # Pre-compute once
            
            # Only check first N ranges to avoid O(n*m) blowup
            max_check = 500
            for (a_start, a_end) in my_ranges[:max_check]:
                # Binary search for nearby ranges in other
                import bisect
                idx = bisect.bisect_left(other_starts, a_start - 4)
                for k in range(idx, min(idx + 10, len(other_ranges))):
                    b_start, b_end = other_ranges[k]
                    gap = abs(a_start - b_end) if a_start >= b_end else abs(b_start - a_end)
                    if 0 < gap <= 4:
                        warnings.append(
                            f"{cs_a.name} @ 0x{a_start:06X}-0x{a_end:06X} and "
                            f"{cs_b.name} @ 0x{b_start:06X}-0x{b_end:06X} are "
                            f"{gap} bytes apart — possible semantic conflict"
                        )
                        if len(warnings) >= 50:
                            return warnings
    return warnings


def merge(
    change_sets: List[ChangeSet],
    priority: Optional[List[str]] = None,
) -> MergeResult:
    """Merge multiple change sets into one.
    
    Args:
        change_sets: List of change sets to merge.
        priority: Optional list of hack names in priority order (first = highest).
                  If None, conflicts will cause failure.
    
    Returns:
        MergeResult with merged changeset and any conflicts found.
    """
    if not change_sets:
        return MergeResult(
            merged=ChangeSet(name="empty"),
            conflicts=[],
            success=True,
        )

    conflicts = detect_conflicts(change_sets)
    warnings = detect_warnings(change_sets)

    # Build priority map: name -> rank (lower = higher priority)
    priority_map: Dict[str, int] = {}
    if priority:
        for rank, name in enumerate(priority):
            priority_map[name] = rank

    # Check if all conflicts can be resolved by priority
    unresolved: List[Conflict] = []
    resolved_conflicts: List[Conflict] = []
    for c in conflicts:
        if priority and c.hack_a in priority_map and c.hack_b in priority_map:
            resolved_conflicts.append(c)
        else:
            unresolved.append(c)

    # Sort by priority: lowest priority first, highest priority last (overwrites)
    if priority:
        ordered = sorted(
            change_sets,
            key=lambda cs: priority_map.get(cs.name, len(priority_map)),
            reverse=True  # Highest priority last so it overwrites
        )
    else:
        ordered = list(change_sets)

    # Merge: apply changes in order, later (higher priority) overwrites earlier
    merged = ChangeSet(name="merged", source_format="merged")
    for cs in ordered:
        for offset, data in cs.changes.items():
            merged.changes[offset] = data

    success = len(unresolved) == 0

    return MergeResult(
        merged=merged,
        conflicts=unresolved + resolved_conflicts,
        warnings=warnings,
        success=success,
    )


def compute_target(base_rom: bytes, cs: ChangeSet) -> bytearray:
    """Compute the full target ROM that a change set produces from base."""
    max_size = len(base_rom)
    for offset, data in cs.changes.items():
        max_size = max(max_size, offset + len(data))
    result = bytearray(base_rom)
    if max_size > len(result):
        result.extend(b"\x00" * (max_size - len(result)))
    for offset, data in cs.changes.items():
        result[offset:offset + len(data)] = data
    return result


def get_conflict_regions(change_sets: List[ChangeSet], cluster_gap: int = 32) -> List[dict]:
    """Compute contiguous conflict regions across all change sets.

    Range/slice-based for performance on large hacks. Regions separated by
    <= cluster_gap bytes share a cluster_id.

    Returns list of dicts:
        { 'start': int, 'end': int, 'hacks': {name: hexbyte}, 'size': int,
          'cluster_id': int, 'cluster_size': int, 'cluster_regions': int }
    sorted by start address.
    """
    # Collect differing runs as (start, end_exclusive, {hack: first_byte})
    raw: List[Tuple[int, int, Dict[str, int]]] = []

    for i in range(len(change_sets)):
        for j in range(i + 1, len(change_sets)):
            a_ranges = sorted(change_sets[i].changes.items())
            b_ranges = sorted(change_sets[j].changes.items())
            ai = bi = 0
            while ai < len(a_ranges) and bi < len(b_ranges):
                a_off, a_data = a_ranges[ai]
                b_off, b_data = b_ranges[bi]
                a_end = a_off + len(a_data)
                b_end = b_off + len(b_data)

                overlap_start = max(a_off, b_off)
                overlap_end = min(a_end, b_end)
                if overlap_start < overlap_end:
                    a_sl = a_data[overlap_start - a_off:overlap_end - a_off]
                    b_sl = b_data[overlap_start - b_off:overlap_end - b_off]
                    if a_sl != b_sl:
                        # Extract contiguous differing runs within overlap
                        k = 0
                        n = overlap_end - overlap_start
                        while k < n:
                            if a_sl[k] == b_sl[k]:
                                k += 1
                                continue
                            run_start = k
                            while k < n and a_sl[k] != b_sl[k]:
                                k += 1
                            s = overlap_start + run_start
                            raw.append((s, overlap_start + k, {
                                change_sets[i].name: a_sl[run_start],
                                change_sets[j].name: b_sl[run_start],
                            }))

                if a_end < b_end:
                    ai += 1
                elif b_end < a_end:
                    bi += 1
                else:
                    ai += 1
                    bi += 1

    if not raw:
        return []

    raw.sort(key=lambda r: r[0])

    # Merge adjacent/overlapping runs, unioning hack maps
    merged: List[Tuple[int, int, Dict[str, int]]] = []
    cur_s, cur_e, cur_h = raw[0][0], raw[0][1], dict(raw[0][2])
    for s, e, h in raw[1:]:
        if s <= cur_e:
            cur_e = max(cur_e, e)
            cur_h.update(h)
        else:
            merged.append((cur_s, cur_e, cur_h))
            cur_s, cur_e, cur_h = s, e, dict(h)
    merged.append((cur_s, cur_e, cur_h))

    # Build region dicts with cluster IDs
    result = []
    cluster_id = 0
    prev_end = None
    for s, e, hacks in merged:
        if prev_end is not None and (s - prev_end) > cluster_gap:
            cluster_id += 1
        result.append({
            "start": s,
            "end": e,
            "size": e - s,
            "hacks": {k: f"{v:02X}" for k, v in hacks.items()},
            "cluster_id": cluster_id,
        })
        prev_end = e

    cluster_sizes: Dict[int, int] = {}
    cluster_counts: Dict[int, int] = {}
    for r in result:
        cid = r["cluster_id"]
        cluster_sizes[cid] = cluster_sizes.get(cid, 0) + r["size"]
        cluster_counts[cid] = cluster_counts.get(cid, 0) + 1
    for r in result:
        cid = r["cluster_id"]
        r["cluster_size"] = cluster_sizes[cid]
        r["cluster_regions"] = cluster_counts[cid]

    return result


def merge_per_region(
    change_sets: List[ChangeSet],
    region_winners: List[Tuple[int, int, Optional[str]]],
    base_rom: bytes,
    global_priority: Optional[List[str]] = None,
) -> bytearray:
    """Merge with per-region winner assignment.
    
    Args:
        change_sets: The hacks to merge.
        region_winners: list of (start, end, winner_name). winner_name is a hack
                        name, or None to keep the base ROM value.
        base_rom: The base ROM.
        global_priority: Fallback priority for non-region addresses.
    
    Returns:
        The merged ROM as a bytearray.
    """
    # Compute each hack's full target ROM
    targets = {cs.name: compute_target(base_rom, cs) for cs in change_sets}
    
    # Determine max size
    max_size = len(base_rom)
    for t in targets.values():
        max_size = max(max_size, len(t))
    
    # Padded base for "keep base" regions
    padded_base = bytearray(base_rom)
    if len(padded_base) < max_size:
        padded_base.extend(b"\x00" * (max_size - len(padded_base)))
    
    # Start from base, apply all changes in global priority order (lowest first, highest last)
    result = bytearray(base_rom)
    if len(result) < max_size:
        result.extend(b"\x00" * (max_size - len(result)))
    priority_map = {name: i for i, name in enumerate(global_priority)} if global_priority else {}
    ordered = (
        sorted(change_sets, key=lambda cs: priority_map.get(cs.name, len(priority_map)), reverse=True)
        if global_priority else list(change_sets)
    )
    for cs in ordered:
        for offset, data in cs.changes.items():
            end = offset + len(data)
            if end > len(result):
                result.extend(b"\x00" * (end - len(result)))
            result[offset:end] = data
    
    # Apply per-region winners
    for start, end, winner in region_winners:
        if winner is None:
            result[start:end] = padded_base[start:end]
        else:
            t = targets.get(winner)
            if t is not None:
                result[start:end] = t[start:end]

    return result


def export_conflict_report(regions: List[dict], path, fmt: str = "json") -> None:
    """Export conflict regions to JSON or CSV for manual review."""
    import csv
    import json
    from pathlib import Path

    p = Path(path)
    if fmt == "csv":
        with p.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            hack_names = sorted({h for r in regions for h in r.get("hacks", {}).keys()})
            w.writerow(["start", "end", "size", "cluster_id", "cluster_size", "cluster_regions", "area"] + hack_names)
            for r in regions:
                area = "original" if r["start"] < 0x100000 else "expansion"
                row = [
                    f"0x{r['start']:06X}", f"0x{r['end']:06X}", r["size"],
                    r.get("cluster_id", ""), r.get("cluster_size", ""), r.get("cluster_regions", ""), area,
                ]
                for h in hack_names:
                    row.append(r.get("hacks", {}).get(h, ""))
                w.writerow(row)
    else:
        data = []
        for r in regions:
            d = dict(r)
            d["start_hex"] = f"0x{r['start']:06X}"
            d["end_hex"] = f"0x{r['end']:06X}"
            d["area"] = "original" if r["start"] < 0x100000 else "expansion"
            data.append(d)
        p.write_text(json.dumps({"regions": data, "count": len(data)}, indent=2), encoding="utf-8")
