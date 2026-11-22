# ROMMAN

**Merge multiple ROM hacks — with conflict detection and per-region control.**

ROMMAN loads multiple patches or full ROM dumps, analyzes which ROM addresses each hack modifies, detects overlaps, and merges them into a single output. When conflicts exist, you can resolve them by global priority or per-region Smart Merge.

## Features

- **Input formats**: IPS, BPS, XDelta, and full `.bin` ROM dumps
- **Output formats**: `.bin`/`.nes` (full ROM), headerless `.unh`, `.ips`, `.bps`, `.xdelta`
- **Conflict detection**: finds overlapping byte writes between hacks
- **Conflict clustering**: groups nearby conflict regions into clusters for safer whole-blob decisions
- **Raw merge**: global priority order (first wins conflicts)
- **Smart Merge (GUI)**: assign winner per conflict region/cluster, range select, filters, split-cluster warning
- **Disassembly-aware mode**: detects likely disassembly rebuilds, rebases other patches onto the rebuild using best-effort context matching; supports disasm profile dropdown, optional symbol/map file, and optional project build command hook
- **Conflict report export**: JSON/CSV report with addresses, sizes, clusters, area (original/expansion), and per-hack bytes
- **Compatibility warnings**: flags suspicious size/header/overlap patterns
- **CLI + GUI**: command-line for scripting, Tk GUI for visual resolution

## Usage

```bash
# Check for conflicts only
romman base.bin hack1.ips hack2.bps --check

# Merge into a full ROM (priority order: first wins)
romman base.bin hack1.ips hack2.bps -o merged.bin --priority hack1.ips hack2.bps

# Output as patch
romman base.bin hack1.ips hack2.bps -o combined.ips --format ips

# Disassembly-aware merge (auto-detect rebuild, optional map/build hook)
romman base.bin disasm_rebuild.bin other.ips -o merged.bin --disasm-aware --disasm-profile "Sonic 2 Git Disasm (S2DISASM)" --disasm-map symbols.map

# GUI
python -m romman.gui
```

## Smart Merge notes

- **Clusters** group nearby conflict regions (default gap <= 32 bytes). Prefer assigning whole clusters, not slices.
- **Split-cluster warning**: assigning different winners inside one cluster can corrupt compressed/structured data (e.g. Kosinski-compressed level layouts) and scramble in-game results.
- **Byte merge != semantic merge**: a clean apply or resolved byte conflict does not guarantee the hacks are logically compatible.

## Limitations

- ROMMAN merges **bytes**, not game logic. It cannot safely relocate conflicting expansion-space data or understand format-specific structures.
- Two hacks that modify the same subsystem (level layouts, collision, engine code, same expansion region) may be fundamentally incompatible.
- “No conflicts” is necessary but not sufficient; “resolved conflicts” can still produce glitches if the wrong bytes are mixed.
- **Disassembly-aware rebase is best-effort**: context matching can remap many shifted regions, but ambiguous or unmatched offsets are skipped to avoid corruption. Symbol/map files improve accuracy; full semantic/source-level rebasing is not guaranteed.
- Always test merged output in an emulator/real hardware workflow appropriate for the target ROM.

## Installation

```bash
pip install -e .
```

## License

MIT