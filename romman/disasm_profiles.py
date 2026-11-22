"""Disassembly profile rules.

Profiles encode known disassembly-specific byte changes so ROMMAN can auto-resolve
them during Auto-pick/merge instead of treating them as noisy conflicts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class DisasmRule:
    start: int
    end: int  # exclusive
    action: str  # prefer_patch | prefer_base | prefer_rebuild | ignore
    note: str = ""

    def matches(self, addr: int) -> bool:
        return self.start <= addr < self.end


@dataclass
class DisasmProfile:
    name: str
    description: str = ""
    rules: List[DisasmRule] = field(default_factory=list)
    source: str = "builtin"

    def action_for(self, start: int, end: int) -> Optional[DisasmRule]:
        # Return first rule that covers any part of the region; conservative: require full cover for auto action
        for r in self.rules:
            if r.start <= start and end <= r.end:
                return r
        return None


def _parse_int(v) -> int:
    if isinstance(v, int):
        return v
    s = str(v).strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    return int(s)


def load_profile(path: Path) -> DisasmProfile:
    data = json.loads(path.read_text(encoding="utf-8"))
    rules = []
    for r in data.get("rules", []):
        rules.append(DisasmRule(
            start=_parse_int(r["start"]),
            end=_parse_int(r["end"]),
            action=str(r.get("action", "prefer_patch")),
            note=str(r.get("note", "")),
        ))
    return DisasmProfile(
        name=str(data.get("name", path.stem)),
        description=str(data.get("description", "")),
        rules=rules,
        source=str(path),
    )


def builtin_profiles_dir() -> Path:
    # packaged alongside romman or in cwd/romman/profiles
    import sys
    here = Path(__file__).resolve().parent
    p = here / "profiles"
    if p.exists():
        return p
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        mp = Path(meipass) / "romman" / "profiles"
        if mp.exists():
            return mp
        mp2 = Path(meipass) / "profiles"
        if mp2.exists():
            return mp2
    return here.parent / "profiles"


def load_all_profiles(extra_dir: Optional[Path] = None) -> Dict[str, DisasmProfile]:
    profiles: Dict[str, DisasmProfile] = {}
    dirs = [builtin_profiles_dir()]
    if extra_dir:
        dirs.append(extra_dir)
    for d in dirs:
        if not d.exists():
            continue
        for p in sorted(d.glob("*.json")):
            try:
                prof = load_profile(p)
                profiles[prof.name] = prof
            except Exception:
                pass
    # Built-in minimal defaults if no files found
    if "Sonic 2 Git Disasm (S2DISASM)" not in profiles:
        profiles["Sonic 2 Git Disasm (S2DISASM)"] = DisasmProfile(
            name="Sonic 2 Git Disasm (S2DISASM)",
            description="Starter profile. Add rules for known S2DISASM byte changes.",
            rules=[],
            source="builtin",
        )
    if "Generic disassembly rebuild" not in profiles:
        profiles["Generic disassembly rebuild"] = DisasmProfile(
            name="Generic disassembly rebuild",
            description="Generic profile; no predefined rules.",
            rules=[],
            source="builtin",
        )
    if "No disassembly" not in profiles:
        profiles["No disassembly"] = DisasmProfile(
            name="No disassembly",
            description="Disable disassembly-specific handling.",
            rules=[],
            source="builtin",
        )
    return profiles


def resolve_region_with_profile(
    profile: Optional[DisasmProfile],
    start: int,
    end: int,
    hacks: Dict[str, str],
    rebuild_name: Optional[str],
) -> Optional[str]:
    """Return winner hack name, '__BASE__', or None if profile has no decision."""
    if profile is None:
        return None
    rule = profile.action_for(start, end)
    if rule is None:
        return None
    action = rule.action
    if action == "prefer_base":
        return "__BASE__"
    if action == "prefer_rebuild":
        return rebuild_name if rebuild_name in hacks else None
    if action == "prefer_patch":
        # prefer any non-rebuild hack involved in this region
        for h in hacks.keys():
            if h != rebuild_name:
                return h
        return rebuild_name
    if action == "ignore":
        # ignore = keep base for this conflict region
        return "__BASE__"
    return None
