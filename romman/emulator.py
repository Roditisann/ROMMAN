"""Emulator preview support for ROMMAN."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional

from .rom import load_base_rom, apply_changes, load_input


@dataclass
class Emulator:
    name: str
    path: str
    args: List[str] = None  # extra args before rom path

    def __post_init__(self):
        if self.args is None:
            self.args = []


CONFIG_DIR = Path(os.environ.get("APPDATA", Path.home())) / "romman"
CONFIG_PATH = CONFIG_DIR / "emulators.json"
CACHE_DIR = Path(tempfile.gettempdir()) / "romman_preview"


def _default_candidates() -> List[Path]:
    home = Path.home()
    candidates = [
        home / "Downloads" / "Blastem-win64-1.0.0" / "blastem-win64-1.0.0" / "blastem.exe",
        home / "Downloads" / "blastem" / "blastem.exe",
        home / "Desktop" / "blastem" / "blastem.exe",
        Path("C:/blastem/blastem.exe"),
        Path("C:/Program Files/BlastEm/blastem.exe"),
        Path("C:/Program Files (x86)/BlastEm/blastem.exe"),
    ]
    # also scan Downloads for blastem.exe
    dl = home / "Downloads"
    if dl.exists():
        try:
            for p in dl.rglob("blastem.exe"):
                candidates.append(p)
        except Exception:
            pass
    return candidates


def load_emulators() -> List[Emulator]:
    emus: List[Emulator] = []
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            for e in data.get("emulators", []):
                if e.get("path") and Path(e["path"]).exists():
                    emus.append(Emulator(name=e.get("name", "Emulator"), path=e["path"], args=e.get("args", [])))
        except Exception:
            pass

    # Auto-discover BlastEm if not configured
    known_paths = {e.path.lower() for e in emus}
    for c in _default_candidates():
        try:
            if c.exists() and str(c).lower() not in known_paths:
                emus.append(Emulator(name="BlastEm", path=str(c)))
                known_paths.add(str(c).lower())
                break
        except Exception:
            pass
    return emus


def save_emulators(emus: List[Emulator]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    data = {"emulators": [asdict(e) for e in emus]}
    CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def add_emulator(name: str, path: str, args: Optional[List[str]] = None) -> Emulator:
    emus = load_emulators()
    emu = Emulator(name=name, path=path, args=args or [])
    # replace if same path
    emus = [e for e in emus if e.path.lower() != path.lower()]
    emus.append(emu)
    save_emulators(emus)
    return emu


def is_rom_file(path: Path) -> bool:
    return path.suffix.lower() in {".bin", ".rom", ".md", ".gen", ".smd", ".nes", ".sfc", ".smc"}


def build_preview_rom(base_rom: Optional[bytes], base_path: Optional[Path], hack_path: Path) -> Path:
    """Return a playable ROM path for preview. Applies patch to base if needed."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if is_rom_file(hack_path):
        return hack_path

    if base_rom is None or base_path is None:
        raise ValueError("Load a base ROM first to preview patch files.")

    # Cache key: base hash + hack hash + hack mtime
    h = hashlib.sha1()
    h.update(base_rom[:65536])
    h.update(str(len(base_rom)).encode())
    try:
        hack_bytes = hack_path.read_bytes()
    except Exception as e:
        raise ValueError(f"Cannot read patch: {e}")
    h.update(hashlib.sha1(hack_bytes).digest())
    key = h.hexdigest()[:16]
    ext = base_path.suffix.lower() if base_path and base_path.suffix else ".bin"
    if ext not in {".bin", ".rom", ".md", ".gen", ".smd", ".nes", ".sfc", ".smc"}:
        ext = ".bin"
    out = CACHE_DIR / f"{hack_path.stem}_{key}{ext}"
    if out.exists():
        return out

    cs = load_input(hack_path, base_rom)
    merged = apply_changes(base_rom, cs)
    out.write_bytes(merged)
    return out


def launch_emulator(emu: Emulator, rom_path: Path) -> subprocess.Popen:
    cmd = [emu.path] + list(emu.args or []) + [str(rom_path)]
    # On Windows, launching directly is fine; BlastEm opens its own window.
    creationflags = 0
    if os.name == "nt":
        creationflags = 0x00000008  # DETACHED_PROCESS
    return subprocess.Popen(cmd, creationflags=creationflags)