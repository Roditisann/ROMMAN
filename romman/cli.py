"""ROMMAN command-line interface."""

from __future__ import annotations
import argparse
import sys
from pathlib import Path
from typing import List, Optional

from .changeset import ChangeSet
from .merger import merge, detect_conflicts, detect_warnings
from .rom import load_input, load_base_rom, apply_changes, diff_roms
from .compat import check_compatibility, identify_rom
from .patchers.ips import write_ips, IPSPatch
from .patchers.bps import write_bps, BPSPatch
from .patchers.xdelta import write_xdelta


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="romman",
        description="ROMMAN — Merge multiple ROM hacks without conflicts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  romman base.bin hack1.ips hack2.ips -o merged.bin
  romman base.bin hack1.bps hack2.bin -o merged.bin --format ips
  romman base.bin hack1.ips hack2.ips --check
  romman base.bin hack1.ips hack2.ips -o merged.bin --priority hack1.ips hack2.ips
        """,
    )

    parser.add_argument(
        "base",
        type=Path,
        help="Base ROM file (.bin)",
    )
    parser.add_argument(
        "hacks",
        nargs="+",
        type=Path,
        help="Hack files to merge (.ips, .bps, .bin)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Output file path",
    )
    parser.add_argument(
        "--format",
        choices=["bin", "nes", "unh", "ips", "bps", "xdelta"],
        default="bin",
        help="Output format (default: bin)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only check for conflicts, don't merge",
    )
    parser.add_argument(
        "--priority",
        nargs="+",
        default=None,
        help="Hack names in priority order (first = highest priority)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force merge even if compatibility issues are detected",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Export conflict report to .json or .csv",
    )
    parser.add_argument("--disasm-aware", action="store_true", help="Enable disassembly-aware rebase/merge mode")
    parser.add_argument("--disasm-profile", default="Auto-detect", help="Disassembly profile name")
    parser.add_argument("--disasm-map", type=Path, default=None, help="Symbol/map file for disassembly rebase")
    parser.add_argument("--disasm-project", type=Path, default=None, help="Disassembly project path for build hook")
    parser.add_argument("--disasm-build", default=None, help="Build command to run in disassembly project")
    parser.add_argument("--nes-shift", default="0", choices=["0", "16", "+16", "-16"], help="Shift patch offsets for NES header mismatch")

    args = parser.parse_args(argv)

    # Load base ROM
    if not args.base.exists():
        print(f"Error: Base ROM not found: {args.base}", file=sys.stderr)
        return 1
    base_rom = load_base_rom(args.base)
    from .fixups import rom_hashes, detect_system
    rh = rom_hashes(base_rom)
    print(f"Base ROM: {args.base.name} ({len(base_rom)} bytes) [{detect_system(base_rom)}] CRC32={rh.crc32} MD5={rh.md5}")

    # Load all hacks
    change_sets: List[ChangeSet] = []
    for hack_path in args.hacks:
        if not hack_path.exists():
            print(f"Error: Hack not found: {hack_path}", file=sys.stderr)
            return 1
        try:
            ns = int(args.nes_shift.replace("+", ""))
            cs = load_input(hack_path, base_rom, nes_shift=ns)
            change_sets.append(cs)
            print(f"  Loaded: {cs}")
        except Exception as e:
            print(f"Error loading {hack_path.name}: {e}", file=sys.stderr)
            return 1

    if not change_sets:
        print("Error: No hacks to merge", file=sys.stderr)
        return 1

    # Check game compatibility
    print("\n--- Game Compatibility ---")
    is_compatible, issues = check_compatibility(base_rom, change_sets, args.base)
    
    if issues:
        print(f"\n⚠ {len(issues)} compatibility issue(s):")
        for issue in issues:
            print(f"  {issue}")
        
        if not args.force:
            print("\n✗ Aborting: hacks may be for different games", file=sys.stderr)
            print("  Use --force to merge anyway (may produce broken ROM)", file=sys.stderr)
            return 1
        else:
            print("\n⚠ Continuing due to --force flag")
    else:
        print("✓ All hacks appear compatible")

    # Disassembly-aware handling
    from .compat import is_disassembly_rebuild
    from .merger import compute_target
    disasm_aware = bool(args.disasm_aware)
    rebuilds = [cs for cs in change_sets if is_disassembly_rebuild(cs, base_rom)]
    effective_base = base_rom
    merge_sets = change_sets
    if rebuilds:
        names = ", ".join(cs.name for cs in rebuilds)
        print(f"\nDisassembly rebuild detected: {names}")
        disasm_aware = True
        print(f"Disassembly-aware mode [{args.disasm_profile}]: rebasing other patches onto rebuild")
        if len(rebuilds) == 1 and len(change_sets) > 1:
            rebuild = rebuilds[0]
            effective_base = bytes(compute_target(base_rom, rebuild))
            merge_sets = [cs for cs in change_sets if cs is not rebuild]
        else:
            print("  Multiple rebuilds or only rebuilds loaded - falling back to normal merge")
    if disasm_aware and effective_base != base_rom and merge_sets:
        from .rebase import rebase_changesets, parse_symbol_map
        sym_map = None
        if args.disasm_map and args.disasm_map.exists():
            try:
                sym_map = parse_symbol_map(args.disasm_map)
                print(f"  Loaded symbol map: {args.disasm_map.name} ({len(sym_map)} symbols)")
            except Exception as e:
                print(f"  Symbol map load failed: {e}")
        rebased, rwarns = rebase_changesets(merge_sets, base_rom, effective_base, symbol_map=sym_map)
        merge_sets = rebased
        for w in rwarns[-20:]:
            print(f"    {w}")
        if len(rwarns) > 20:
            print(f"    ... {len(rwarns)-20} more rebase notes")
        print("  Rebase pass complete (best-effort; ambiguous offsets skipped)")

    # Detect conflicts
    print("\n--- Conflict Detection ---")
    conflicts = detect_conflicts(merge_sets)
    warnings = detect_warnings(merge_sets)

    if conflicts:
        print(f"\n⚠ {len(conflicts)} conflict(s) found:")
        by_pair = {}
        for c in conflicts:
            key = tuple(sorted([c.hack_a, c.hack_b]))
            by_pair.setdefault(key, []).append(c)
        for (a, b), cs in by_pair.items():
            print(f"\n  {a} vs {b}: {len(cs)} conflicting address(es)")
            for c in cs[:5]:
                print(f"    0x{c.address:06X}: {c.bytes_a.hex()} vs {c.bytes_b.hex()}")
            if len(cs) > 5:
                print(f"    ... and {len(cs) - 5} more")
    else:
        print("✓ No conflicts found")

    if warnings:
        print(f"\n⚠ {len(warnings)} warning(s):")
        for w in warnings[:10]:
            print(f"  {w}")
        if len(warnings) > 10:
            print(f"  ... and {len(warnings) - 10} more")

    if args.report:
        from .merger import get_conflict_regions, export_conflict_report
        regions = get_conflict_regions(merge_sets)
        fmt = "csv" if str(args.report).lower().endswith(".csv") else "json"
        export_conflict_report(regions, args.report, fmt=fmt)
        print(f"\nReport written: {args.report} ({len(regions)} regions)")

    if args.check:
        return 0 if not conflicts else 1

    # Merge
    print("\n--- Merging ---")
    result = merge(merge_sets, priority=args.priority)

    if not result.success:
        print("✗ Merge failed: unresolved conflicts", file=sys.stderr)
        if not args.priority:
            print("  Tip: use --priority to resolve conflicts", file=sys.stderr)
        return 1

    merged = result.merged
    print(f"✓ Merged: {merged}")

    # Apply to effective base (handles disasm rebase), normalize patch output to original base
    output_rom = apply_changes(effective_base, merged)
    from .fixups import apply_fixups
    output_rom, fix_msgs = apply_fixups(output_rom)
    for m in fix_msgs:
        print(f"  {m}")
    merged = ChangeSet(name="merged", source_format="merged")
    merged.changes = diff_roms(base_rom, output_rom)

    # Write output
    if args.output is None:
        args.output = Path(f"merged_{args.base.stem}.bin")

    if args.format in ("bin", "nes"):
        args.output.write_bytes(output_rom)
        print(f"✓ Written: {args.output} ({len(output_rom)} bytes)")
    elif args.format == "unh":
        from .rom import has_ines_header
        data = bytes(output_rom)
        if has_ines_header(data):
            data = data[16:]
        args.output.write_bytes(data)
        print(f"✓ Written: {args.output} ({len(data)} bytes, headerless)")

    elif args.format == "ips":
        ips_patch = IPSPatch(changes=merged.changes)
        ips_data = write_ips(ips_patch)
        args.output.write_bytes(ips_data)
        print(f"✓ Written: {args.output} ({len(ips_data)} bytes, IPS)")

    elif args.format == "bps":
        bps_patch = BPSPatch()
        bps_data = write_bps(bps_patch, base_rom, output_rom)
        args.output.write_bytes(bps_data)
        print(f"✓ Written: {args.output} ({len(bps_data)} bytes, BPS)")

    elif args.format == "xdelta":
        write_xdelta(output_rom, base_rom, args.output)
        print(f"✓ Written: {args.output} ({args.output.stat().st_size} bytes, XDelta)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
