"""ROMMAN GUI — simple black/white interface for merging ROM hacks."""

from __future__ import annotations
import json
import os
import sys
import tempfile
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
try:
    from PIL import Image, ImageTk
except Exception:
    Image = None
    ImageTk = None
from pathlib import Path
from typing import Dict, List, Optional

from .changeset import ChangeSet
from .merger import merge, detect_conflicts, detect_warnings
from .rom import load_input, load_base_rom, apply_changes, diff_roms
from .compat import check_compatibility, identify_rom
from .patchers.ips import write_ips, IPSPatch
from .patchers.bps import write_bps, BPSPatch
from .patchers.xdelta import write_xdelta
from .emulator import load_emulators, save_emulators, add_emulator, build_preview_rom, launch_emulator, is_rom_file

# Colors — simple black/white
BG = "#000000"
FG = "#FFFFFF"
BG_ALT = "#111111"
BG_ENTRY = "#1A1A1A"
BG_BUTTON = "#222222"
FG_DIM = "#888888"
FG_ERROR = "#FF4444"
FG_OK = "#44FF44"
FG_WARN = "#FFFF44"
BORDER = "#333333"


def _ask_merge_choice(root, conflict_bytes, num_regions):
    dlg = MergeChoiceDialog(root, conflict_bytes, num_regions)
    root.wait_window(dlg)
    return dlg.choice


def _ask_smart_merge(root, change_sets, regions, priority):
    sm = SmartMergeDialog(root, change_sets, regions, priority)
    root.wait_window(sm)
    if sm.cancelled:
        return None
    return sm.get_winners_list()


class RommanGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("ROMMAN — ROM Hack Merger")
        self.root.configure(bg=BG)
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        try:
            icon = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent)) / "Rommie.ico"
            if icon.exists():
                self.root.iconbitmap(default=str(icon))
        except Exception:
            pass

        self.base_rom_path: Optional[Path] = None
        self.base_rom: bytes = b""
        self.hack_paths: List[Path] = []
        self.change_sets: List[ChangeSet] = []
        self.priority: List[str] = []  # Ordered hack names
        self.selected_hack_idx: Optional[int] = None
        self._preview_cache: Dict[str, Path] = {}
        self.disasm_profile: str = "Auto-detect"
        self.disasm_map_path: Optional[Path] = None
        self.disasm_project_path: Optional[Path] = None
        self.disasm_build_cmd: str = ""

        self._build_ui()
        self._load_session()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _session_path(self) -> Path:
        base = Path(os.environ.get("APPDATA", Path.home())) / "romman"
        base.mkdir(parents=True, exist_ok=True)
        return base / "session.json"

    def _save_session(self):
        try:
            data = {
                "base_rom": str(self.base_rom_path) if self.base_rom_path else "",
                "hacks": [str(p) for p in self.hack_paths],
                "output": str(self.output_path) if self.output_path else "",
                "format": self.format_var.get(),
                "check_only": bool(self.check_var.get()),
                "disasm_aware": bool(self.disasm_var.get()),
                "disasm_profile": self.disasm_profile_var.get() if hasattr(self, "disasm_profile_var") else self.disasm_profile,
                "disasm_map": str(self.disasm_map_path) if self.disasm_map_path else "",
                "disasm_project": str(self.disasm_project_path) if self.disasm_project_path else "",
                "disasm_build_cmd": self.disasm_build_cmd_var.get() if hasattr(self, "disasm_build_cmd_var") else self.disasm_build_cmd,
                "nes_shift": self.nes_shift_var.get() if hasattr(self, "nes_shift_var") else "Auto",
            }
            self._session_path().write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _load_session(self):
        try:
            p = self._session_path()
            if not p.exists():
                return
            data = json.loads(p.read_text(encoding="utf-8"))
            base = data.get("base_rom", "")
            if base and Path(base).exists():
                self.base_rom_path = Path(base)
                try:
                    self.base_rom = load_base_rom(self.base_rom_path)
                    from .fixups import rom_hashes, detect_system
                    rh = rom_hashes(self.base_rom)
                    sys_name = detect_system(self.base_rom)
                    self.base_label.configure(text=f"{self.base_rom_path.name}  ({len(self.base_rom)} bytes)", fg=FG)
                    self._log(f"Restored base ROM: {self.base_rom_path.name} [{sys_name}] CRC32={rh.crc32} MD5={rh.md5}", "dim")
                except Exception:
                    self.base_rom_path = None
                    self.base_rom = b""
            hacks = data.get("hacks", [])
            for h in hacks:
                hp = Path(h)
                if hp.exists() and hp not in self.hack_paths:
                    self.hack_paths.append(hp)
                    self.priority.append(hp.name)
            if self.hack_paths:
                self._refresh_hack_rows()
                self._log(f"Restored {len(self.hack_paths)} hack(s)", "dim")
            out = data.get("output", "")
            if out:
                self.output_path = Path(out)
                self.output_label.configure(text=str(self.output_path))
            fmt = data.get("format", "bin")
            if fmt in ("bin", "nes", "unh", "ips", "bps", "xdelta"):
                self.format_var.set(fmt)
            self.check_var.set(bool(data.get("check_only", False)))
            self.disasm_var.set(bool(data.get("disasm_aware", False)))
            prof = data.get("disasm_profile", "Auto-detect")
            if hasattr(self, "disasm_profile_var"):
                try:
                    self.disasm_profile_var.set(prof)
                except Exception:
                    self.disasm_profile_var.set("Auto-detect")
            self.disasm_profile = prof
            dmap = data.get("disasm_map", "")
            self.disasm_map_path = Path(dmap) if dmap and Path(dmap).exists() else None
            if hasattr(self, "disasm_map_label"):
                self.disasm_map_label.configure(text=self.disasm_map_path.name if self.disasm_map_path else "(no map)")
            dproj = data.get("disasm_project", "")
            self.disasm_project_path = Path(dproj) if dproj and Path(dproj).exists() else None
            if hasattr(self, "disasm_project_label"):
                self.disasm_project_label.configure(text=str(self.disasm_project_path) if self.disasm_project_path else "(no project)")
            dcmd = data.get("disasm_build_cmd", "")
            self.disasm_build_cmd = dcmd
            if hasattr(self, "disasm_build_cmd_var"):
                self.disasm_build_cmd_var.set(dcmd)
            ns = data.get("nes_shift", "Auto")
            if hasattr(self, "nes_shift_var"):
                self.nes_shift_var.set(ns if ns in ("Auto", "0", "+16", "-16") else "Auto")
            self._update_merge_button()
        except Exception:
            pass

    def _on_close(self):
        if getattr(self, "_closing", False):
            return
        self._closing = True
        try:
            self._save_session()
        except Exception:
            pass
        try:
            for child in self.root.winfo_children():
                child.destroy()
            self.root.configure(bg="#000000")
            frame = tk.Frame(self.root, bg="#000000")
            frame.place(relx=0.5, rely=0.5, anchor="center")
            bye_photo = None
            if getattr(self, "_rommie_img", None) is not None and ImageTk is not None:
                big = self._rommie_img.resize((128, 128), Image.LANCZOS)
                bye_photo = ImageTk.PhotoImage(big)
                self._bye_photo = bye_photo  # keep ref
                tk.Label(frame, image=bye_photo, bg="#000000", borderwidth=0).pack()
            tk.Label(frame, text="Bye!", bg="#000000", fg="#FFFFFF", font=("Consolas", 8)).pack(pady=(10, 0))
            self.root.after(90, self.root.destroy)
        except Exception:
            self.root.destroy()

    def _build_ui(self):
        # Main container
        main = tk.Frame(self.root, bg=BG)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "Dark.Vertical.TScrollbar",
            background=BORDER, troughcolor="#000000", bordercolor="#000000",
            arrowcolor=FG, lightcolor=BORDER, darkcolor=BORDER
        )

        # --- Base ROM section ---
        base_frame = tk.LabelFrame(
            main, text="Base ROM", bg=BG, fg=FG,
            font=("Consolas", 10, "bold"), relief=tk.FLAT, bd=1
        )
        base_frame.pack(fill=tk.X, pady=(0, 8))

        base_row = tk.Frame(base_frame, bg=BG)
        base_row.pack(fill=tk.X, padx=5, pady=5)

        self.base_label = tk.Label(
            base_row, text="No ROM loaded", bg=BG, fg=FG_DIM,
            font=("Consolas", 9), anchor="w"
        )
        self.base_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.base_preview_btn = tk.Button(
            base_row, text="▶", command=self._preview_base,
            bg=BG_BUTTON, fg=FG_OK, font=("Consolas", 9, "bold"),
            relief=tk.FLAT, padx=6, pady=2, activebackground=BORDER, activeforeground=FG_OK
        )
        self.base_preview_btn.pack(side=tk.RIGHT, padx=(0, 4))

        self.base_btn = tk.Button(
            base_row, text="Load", command=self._load_base,
            bg=BG_BUTTON, fg=FG, font=("Consolas", 9),
            relief=tk.FLAT, padx=10, pady=2, activebackground=BORDER, activeforeground=FG
        )
        self.base_btn.pack(side=tk.RIGHT)

        # --- Hack files section ---
        hack_frame = tk.LabelFrame(
            main, text="Hack Files", bg=BG, fg=FG,
            font=("Consolas", 10, "bold"), relief=tk.FLAT, bd=1
        )
        hack_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        # Hack list + controls
        hack_top = tk.Frame(hack_frame, bg=BG)
        hack_top.pack(fill=tk.X, padx=5, pady=(5, 2))

        tk.Label(
            hack_top, text="Priority (top = wins conflicts):",
            bg=BG, fg=FG_DIM, font=("Consolas", 9)
        ).pack(side=tk.LEFT)

        btn_row = tk.Frame(hack_top, bg=BG)
        btn_row.pack(side=tk.RIGHT)

        for text, cmd in [
            ("+ Add", self._add_hacks),
            ("Remove", self._remove_selected),
            ("↑ Up", self._move_up),
            ("↓ Down", self._move_down),
        ]:
            tk.Button(
                btn_row, text=text, command=cmd,
                bg=BG_BUTTON, fg=FG, font=("Consolas", 9),
                relief=tk.FLAT, padx=6, pady=1,
                activebackground=BORDER, activeforeground=FG
            ).pack(side=tk.LEFT, padx=1)

        # Hack rows (scrollable)
        list_frame = tk.Frame(hack_frame, bg=BG)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        self.hack_canvas = tk.Canvas(list_frame, bg=BG_ENTRY, highlightthickness=1,
                                     highlightbackground=BORDER, highlightcolor=BORDER)
        scrollbar = ttk.Scrollbar(list_frame, command=self.hack_canvas.yview, style="Dark.Vertical.TScrollbar")
        self.hack_rows_frame = tk.Frame(self.hack_canvas, bg=BG_ENTRY)
        self.hack_rows_frame.bind("<Configure>", lambda e: self.hack_canvas.configure(scrollregion=self.hack_canvas.bbox("all")))
        self.hack_canvas.create_window((0, 0), window=self.hack_rows_frame, anchor="nw")
        self.hack_canvas.configure(yscrollcommand=scrollbar.set)
        self.hack_canvas.bind("<Configure>", lambda e: self.hack_canvas.itemconfig("all", width=e.width))
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.hack_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # --- Mascot ---
        self._build_mascot(main)

        # --- Options row ---
        opt_frame = tk.Frame(main, bg=BG)
        opt_frame.pack(fill=tk.X, pady=(0, 8))

        tk.Label(opt_frame, text="Output:", bg=BG, fg=FG_DIM, font=("Consolas", 9)).pack(side=tk.LEFT)
        self.format_var = tk.StringVar(value="bin")
        fmt_menu = tk.OptionMenu(
            opt_frame, self.format_var, "bin", "nes", "unh", "ips", "bps", "xdelta"
        )
        fmt_menu.configure(
            bg=BG_ENTRY, fg=FG, font=("Consolas", 9),
            activebackground=BORDER, activeforeground=FG,
            highlightthickness=0, relief=tk.FLAT
        )
        fmt_menu["menu"].configure(
            bg=BG_ENTRY, fg=FG, activebackground=BORDER, activeforeground=FG
        )
        fmt_menu.pack(side=tk.LEFT, padx=(5, 15))

        self.check_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            opt_frame, text="Check only (no merge)",
            variable=self.check_var,
            bg=BG, fg=FG, font=("Consolas", 9),
            selectcolor=BG_ENTRY, activebackground=BG, activeforeground=FG,
            highlightthickness=0
        ).pack(side=tk.LEFT)

        self.disasm_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            opt_frame, text="Disassembly-aware",
            variable=self.disasm_var,
            bg=BG, fg=FG, font=("Consolas", 9),
            selectcolor=BG_ENTRY, activebackground=BG, activeforeground=FG,
            highlightthickness=0
        ).pack(side=tk.LEFT, padx=(10, 0))

        tk.Label(opt_frame, text="NES hdr:", bg=BG, fg=FG_DIM, font=("Consolas", 9)).pack(side=tk.LEFT, padx=(10, 2))
        self.nes_shift_var = tk.StringVar(value="Auto")
        nes_menu = tk.OptionMenu(opt_frame, self.nes_shift_var, "Auto", "0", "+16", "-16")
        nes_menu.configure(bg=BG_ENTRY, fg=FG, font=("Consolas", 8), activebackground=BORDER, activeforeground=FG, highlightthickness=0, relief=tk.FLAT)
        nes_menu["menu"].configure(bg=BG_ENTRY, fg=FG, activebackground=BORDER, activeforeground=FG)
        nes_menu.pack(side=tk.LEFT)

        # --- Disassembly settings ---
        disasm_frame = tk.Frame(main, bg=BG)
        disasm_frame.pack(fill=tk.X, pady=(0, 8))
        tk.Label(disasm_frame, text="Disasm:", bg=BG, fg=FG_DIM, font=("Consolas", 9)).pack(side=tk.LEFT)
        try:
            from .disasm_profiles import load_all_profiles
            profile_names = ["Auto-detect", "No disassembly"] + sorted([k for k in load_all_profiles().keys() if k != "No disassembly"])
        except Exception:
            profile_names = ["Auto-detect", "No disassembly", "Generic disassembly rebuild", "Sonic 2 Git Disasm (S2DISASM)"]
        self.disasm_profile_var = tk.StringVar(value=self.disasm_profile)
        if self.disasm_profile not in profile_names:
            profile_names.append(self.disasm_profile)
        prof_menu = tk.OptionMenu(disasm_frame, self.disasm_profile_var, *profile_names)
        prof_menu.configure(bg=BG_ENTRY, fg=FG, font=("Consolas", 8), activebackground=BORDER, activeforeground=FG, highlightthickness=0, relief=tk.FLAT)
        prof_menu["menu"].configure(bg=BG_ENTRY, fg=FG, activebackground=BORDER, activeforeground=FG)
        prof_menu.pack(side=tk.LEFT, padx=(4, 8))
        tk.Button(disasm_frame, text="Map...", command=self._set_disasm_map, bg=BG_BUTTON, fg=FG, font=("Consolas", 8), relief=tk.FLAT, padx=6, pady=1).pack(side=tk.LEFT)
        self.disasm_map_label = tk.Label(disasm_frame, text="(no map)", bg=BG, fg=FG_DIM, font=("Consolas", 8), anchor="w")
        self.disasm_map_label.pack(side=tk.LEFT, padx=(4, 8))
        tk.Button(disasm_frame, text="Project...", command=self._set_disasm_project, bg=BG_BUTTON, fg=FG, font=("Consolas", 8), relief=tk.FLAT, padx=6, pady=1).pack(side=tk.LEFT)
        self.disasm_project_label = tk.Label(disasm_frame, text="(no project)", bg=BG, fg=FG_DIM, font=("Consolas", 8), anchor="w")
        self.disasm_project_label.pack(side=tk.LEFT, padx=(4, 8))
        tk.Label(disasm_frame, text="Build:", bg=BG, fg=FG_DIM, font=("Consolas", 8)).pack(side=tk.LEFT)
        self.disasm_build_cmd_var = tk.StringVar(value=self.disasm_build_cmd)
        tk.Entry(disasm_frame, textvariable=self.disasm_build_cmd_var, bg=BG_ENTRY, fg=FG, insertbackground=FG, font=("Consolas", 8), relief=tk.FLAT, width=24).pack(side=tk.LEFT, padx=(4, 0))

        # --- Actions ---
        action_frame = tk.Frame(main, bg=BG)
        action_frame.pack(fill=tk.X, pady=(0, 8))

        self.merge_btn = tk.Button(
            action_frame, text="MERGE", command=self._do_merge,
            bg=FG, fg=BG, font=("Consolas", 11, "bold"),
            relief=tk.FLAT, padx=20, pady=6,
            activebackground=FG_DIM, activeforeground=BG,
            state=tk.DISABLED
        )
        self.merge_btn.pack(side=tk.LEFT)

        self.preview_btn = tk.Button(
            action_frame, text="PREVIEW", command=self._preview_merge,
            bg=BG_BUTTON, fg=FG_OK, font=("Consolas", 11, "bold"),
            relief=tk.FLAT, padx=14, pady=6,
            activebackground=BORDER, activeforeground=FG_OK,
            state=tk.DISABLED
        )
        self.preview_btn.pack(side=tk.LEFT, padx=(8, 0))

        self.output_path: Optional[Path] = None
        self.output_btn = tk.Button(
            action_frame, text="Set Output...", command=self._set_output,
            bg=BG_BUTTON, fg=FG, font=("Consolas", 9),
            relief=tk.FLAT, padx=10, pady=4,
            activebackground=BORDER, activeforeground=FG
        )
        self.output_btn.pack(side=tk.LEFT, padx=(10, 0))

        self.report_btn = tk.Button(
            action_frame, text="Export Report...", command=self._export_report,
            bg=BG_BUTTON, fg=FG, font=("Consolas", 9),
            relief=tk.FLAT, padx=10, pady=4,
            activebackground=BORDER, activeforeground=FG,
            state=tk.DISABLED
        )
        self.report_btn.pack(side=tk.LEFT, padx=(10, 0))

        self.status_label = tk.Label(
            action_frame, text="", bg=BG, fg=FG_WARN, font=("Consolas", 9)
        )
        self.status_label.pack(side=tk.RIGHT)

        self.output_label = tk.Label(
            action_frame, text="", bg=BG, fg=FG_DIM,
            font=("Consolas", 9), anchor="w"
        )
        self.output_label.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)

        # --- Status / Log ---
        log_frame = tk.LabelFrame(
            main, text="Output", bg=BG, fg=FG,
            font=("Consolas", 10, "bold"), relief=tk.FLAT, bd=1
        )
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log = tk.Text(
            log_frame, bg=BG_ENTRY, fg=FG,
            font=("Consolas", 9), relief=tk.FLAT,
            insertbackground=FG, selectbackground=BORDER,
            highlightthickness=1, highlightcolor=BORDER, highlightbackground=BORDER,
            state=tk.DISABLED, wrap=tk.WORD
        )
        log_scroll = ttk.Scrollbar(log_frame, command=self.log.yview, style="Dark.Vertical.TScrollbar")
        self.log.configure(yscrollcommand=log_scroll.set)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Configure text tags for colored output
        self.log.tag_configure("ok", foreground=FG_OK)
        self.log.tag_configure("error", foreground=FG_ERROR)
        self.log.tag_configure("warn", foreground=FG_WARN)
        self.log.tag_configure("dim", foreground=FG_DIM)
        self.log.tag_configure("bold", font=("Consolas", 9, "bold"))

    def _build_mascot(self, parent):
        self._rommie_img = None
        self._rommie_photo = None
        try:
            if Image is None or ImageTk is None:
                return
            icon_path = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent)) / "Rommie.png"
            if not icon_path.exists():
                return
            img = Image.open(icon_path).convert("RGBA")
            self._rommie_img = img
            small = img.resize((56, 56), Image.LANCZOS)
            self._rommie_photo = ImageTk.PhotoImage(small)
            frame = tk.Frame(parent, bg=BG, highlightthickness=0)
            frame.pack(fill=tk.X, pady=(2, 6))
            inner = tk.Frame(frame, bg=BG)
            inner.pack(anchor="center")
            tk.Label(inner, image=self._rommie_photo, bg=BG, borderwidth=0).pack(side=tk.LEFT)
            tk.Label(
                inner, text="(This is Rommie. Don't mind him)",
                bg=BG, fg=FG_DIM, font=("Consolas", 8), justify=tk.LEFT
            ).pack(side=tk.LEFT, padx=(8, 0))
        except Exception:
            pass

    def _log(self, text: str, tag: str = ""):
        if threading.current_thread() is not threading.main_thread():
            self.root.after(0, lambda t=text, g=tag: self._log(t, g))
            return
        self.log.configure(state=tk.NORMAL)
        if tag:
            self.log.insert(tk.END, text + "\n", tag)
        else:
            self.log.insert(tk.END, text + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def _clear_log(self):
        if threading.current_thread() is not threading.main_thread():
            self.root.after(0, self._clear_log)
            return
        self.log.configure(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.configure(state=tk.DISABLED)

    def _ui_call(self, fn):
        """Run fn on the main Tk thread and return its result; safe to call from worker."""
        if threading.current_thread() is threading.main_thread():
            return fn()
        result = {}
        done = threading.Event()

        def run():
            try:
                result["value"] = fn()
            except Exception as e:
                result["error"] = e
            finally:
                done.set()

        self.root.after(0, run)
        done.wait()
        if "error" in result:
            raise result["error"]
        return result.get("value")

    def _set_busy(self, busy: bool, msg: str = ""):
        def apply():
            state = tk.DISABLED if busy else tk.NORMAL
            if hasattr(self, "merge_btn"):
                self.merge_btn.configure(state=state if (self.base_rom_path and self.hack_paths) else tk.DISABLED)
            if hasattr(self, "preview_btn"):
                self.preview_btn.configure(state=state if (self.base_rom_path and self.hack_paths) else tk.DISABLED)
            if hasattr(self, "status_label"):
                self.status_label.configure(text=msg if busy else "")
            self.root.configure(cursor="watch" if busy else "")
        if threading.current_thread() is not threading.main_thread():
            self.root.after(0, apply)
        else:
            apply()

    # --- Actions ---

    def _load_base(self):
        path = filedialog.askopenfilename(
            title="Select Base ROM",
            filetypes=[
                ("ROM files", "*.bin *.rom *.md *.gen *.nes"),
                ("All files", "*.*"),
            ]
        )
        if not path:
            return
        self.base_rom_path = Path(path)
        try:
            self.base_rom = load_base_rom(self.base_rom_path)
            from .fixups import rom_hashes, detect_system
            rh = rom_hashes(self.base_rom)
            sys_name = detect_system(self.base_rom)
            self.base_label.configure(
                text=f"{self.base_rom_path.name}  ({len(self.base_rom)} bytes)  [{sys_name}]",
                fg=FG
            )
            self._log(f"Loaded base ROM: {self.base_rom_path.name} ({len(self.base_rom)} bytes)", "ok")
            self._log(f"  CRC32: {rh.crc32}  MD5: {rh.md5}  System: {sys_name}", "dim")
            self._update_merge_button()
        except Exception as e:
            self._log(f"Error loading base ROM: {e}", "error")

    def _preview_base(self):
        if not self.base_rom_path or not self.base_rom_path.exists():
            messagebox.showwarning("Preview", "Load a base ROM first.", parent=self.root)
            return
        self._choose_and_launch_emulator(self.base_rom_path, is_base=True)

    def _preview_hack(self, idx: int):
        if idx < 0 or idx >= len(self.hack_paths):
            return
        path = self.hack_paths[idx]
        self._choose_and_launch_emulator(path, is_base=False)

    def _choose_and_launch_emulator(self, target: Path, is_base: bool = False):
        # Build playable ROM path
        try:
            if is_base or is_rom_file(target):
                rom_path = target
            else:
                if not self.base_rom:
                    messagebox.showwarning(
                        "Preview",
                        "Load a base ROM first to preview patch files.\nROMMAN will apply the patch automatically.",
                        parent=self.root
                    )
                    return
                rom_path = build_preview_rom(self.base_rom, self.base_rom_path, target)
        except Exception as e:
            messagebox.showerror("Preview Error", str(e), parent=self.root)
            return

        emus = load_emulators()
        dlg = EmulatorChooserDialog(self.root, emus, rom_path)
        self.root.wait_window(dlg)
        if dlg.selected:
            try:
                launch_emulator(dlg.selected, rom_path)
                self._log(f"  Preview launched: {target.name} -> {dlg.selected.name}", "ok")
            except Exception as e:
                messagebox.showerror("Launch Error", str(e), parent=self.root)

    def _refresh_hack_rows(self):
        for w in self.hack_rows_frame.winfo_children():
            w.destroy()
        for idx, path in enumerate(self.hack_paths):
            selected = (self.selected_hack_idx == idx)
            row_bg = BORDER if selected else BG_ENTRY
            row = tk.Frame(self.hack_rows_frame, bg=row_bg)
            row.pack(fill=tk.X, padx=1, pady=1)
            btn = tk.Button(
                row, text="▶", command=lambda i=idx: self._preview_hack(i),
                bg=BG_BUTTON, fg=FG_OK, font=("Consolas", 8, "bold"),
                relief=tk.FLAT, padx=4, pady=0, activebackground=BORDER
            )
            btn.pack(side=tk.LEFT, padx=(2, 4), pady=1)
            lbl = tk.Label(
                row, text=path.name, bg=row_bg, fg=FG,
                font=("Consolas", 9), anchor="w"
            )
            lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)
            for widget in (row, lbl):
                widget.bind("<Button-1>", lambda e, i=idx: self._select_hack(i))

    def _select_hack(self, idx):
        self.selected_hack_idx = idx
        self._refresh_hack_rows()

    def _add_hacks(self):
        paths = filedialog.askopenfilenames(
            title="Select Hack Files",
            filetypes=[
                ("Patch files", "*.ips *.bps *.xdelta *.vcdiff *.xd"),
                ("ROM files", "*.bin *.rom *.md *.gen *.nes"),
                ("All files", "*.*"),
            ]
        )
        for p in paths:
            path = Path(p)
            if path not in self.hack_paths:
                self.hack_paths.append(path)
                self.priority.append(path.name)
        self._refresh_hack_rows()
        self._update_merge_button()

    def _remove_selected(self):
        idx = self.selected_hack_idx
        if idx is None or idx < 0 or idx >= len(self.hack_paths):
            return
        self.hack_paths.pop(idx)
        if idx < len(self.priority):
            self.priority.pop(idx)
        if not self.hack_paths:
            self.selected_hack_idx = None
        else:
            self.selected_hack_idx = min(idx, len(self.hack_paths) - 1)
        self._refresh_hack_rows()
        self._update_merge_button()

    def _move_up(self):
        idx = self.selected_hack_idx
        if idx is None or idx == 0:
            return
        self.hack_paths[idx], self.hack_paths[idx - 1] = self.hack_paths[idx - 1], self.hack_paths[idx]
        if idx < len(self.priority) and idx - 1 < len(self.priority):
            self.priority[idx], self.priority[idx - 1] = self.priority[idx - 1], self.priority[idx]
        self.selected_hack_idx = idx - 1
        self._refresh_hack_rows()

    def _move_down(self):
        idx = self.selected_hack_idx
        if idx is None or idx >= len(self.hack_paths) - 1:
            return
        self.hack_paths[idx], self.hack_paths[idx + 1] = self.hack_paths[idx + 1], self.hack_paths[idx]
        if idx < len(self.priority) and idx + 1 < len(self.priority):
            self.priority[idx], self.priority[idx + 1] = self.priority[idx + 1], self.priority[idx]
        self.selected_hack_idx = idx + 1
        self._refresh_hack_rows()

    def _set_disasm_map(self):
        path = filedialog.askopenfilename(
            title="Select Disassembly Symbol/Map File",
            filetypes=[("Map/Symbol files", "*.map *.sym *.txt *.lst"), ("All files", "*.*")]
        )
        if path:
            self.disasm_map_path = Path(path)
            self.disasm_map_label.configure(text=self.disasm_map_path.name, fg=FG)

    def _set_disasm_project(self):
        path = filedialog.askdirectory(title="Select Disassembly Project Folder")
        if path:
            self.disasm_project_path = Path(path)
            self.disasm_project_label.configure(text=str(self.disasm_project_path), fg=FG)

    def _default_bin_ext(self) -> str:
        if self.base_rom_path and self.base_rom_path.suffix.lower() == ".nes":
            return ".nes"
        if self.base_rom_path and self.base_rom_path.suffix.lower() in {".sfc", ".smc"}:
            return self.base_rom_path.suffix.lower()
        return ".bin"

    def _set_output(self):
        fmt = self.format_var.get()
        ext = {"bin": self._default_bin_ext(), "nes": ".nes", "unh": ".unh", "ips": ".ips", "bps": ".bps", "xdelta": ".xdelta"}[fmt]
        path = filedialog.asksaveasfilename(
            title="Save Output As",
            defaultextension=ext,
            filetypes=[
                (f"{fmt.upper()} files", f"*{ext}"),
                ("All files", "*.*"),
            ]
        )
        if path:
            self.output_path = Path(path)
            self.output_label.configure(text=str(self.output_path))

    def _update_merge_button(self):
        ready = bool(self.base_rom_path and self.hack_paths)
        state = tk.NORMAL if ready else tk.DISABLED
        self.merge_btn.configure(state=state)
        self.preview_btn.configure(state=state)
        self.report_btn.configure(state=state)

    def _export_report(self):
        if not self.base_rom_path or not self.hack_paths:
            return
        try:
            base_rom = load_base_rom(self.base_rom_path)
            ns = self._nes_shift_int()
            change_sets = [load_input(p, base_rom, nes_shift=ns) for p in self.hack_paths]
            from .merger import get_conflict_regions, export_conflict_report
            regions = get_conflict_regions(change_sets)
        except Exception as e:
            messagebox.showerror("Export Error", str(e))
            return

        path = filedialog.asksaveasfilename(
            title="Export Conflict Report",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        fmt = "csv" if path.lower().endswith(".csv") else "json"
        try:
            export_conflict_report(regions, path, fmt=fmt)
            self._log(f"  Conflict report written: {path} ({len(regions)} regions)", "ok")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _nes_shift_int(self) -> int:
        v = self.nes_shift_var.get() if hasattr(self, "nes_shift_var") else "Auto"
        if v == "+16":
            return 16
        if v == "-16":
            return -16
        return 0

    def _try_disasm_build(self, project_path: Path, build_cmd: str, profile: str):
        """Best-effort: run disassembly build command and return produced ROM bytes, or None."""
        import subprocess, time
        self._log(f"\n  Disassembly build: running '{build_cmd}' in {project_path}", "warn")
        try:
            before = {p: p.stat().st_mtime for p in project_path.glob("**/*") if p.is_file()}
        except Exception:
            before = {}
        try:
            proc = subprocess.run(
                build_cmd, cwd=str(project_path), shell=True, capture_output=True, text=True, timeout=180
            )
            if proc.returncode != 0:
                self._log(f"  Build command failed (exit {proc.returncode})", "error")
                out = (proc.stdout or "") + "\n" + (proc.stderr or "")
                for line in out.strip().splitlines()[-10:]:
                    if line.strip():
                        self._log(f"    {line.strip()[:200]}", "dim")
                return None
        except Exception as e:
            self._log(f"  Build command error: {e}", "error")
            return None

        # Find likely ROM output: new/changed .bin/.md/.gen, prefer known names
        candidates = []
        try:
            for p in project_path.glob("**/*"):
                if not p.is_file():
                    continue
                if p.suffix.lower() not in (".bin", ".md", ".gen", ".smd"):
                    continue
                mt = p.stat().st_mtime
                prev = before.get(p)
                score = 0
                if prev is None or mt > prev + 0.001:
                    score += 10
                name = p.name.lower()
                if "sonic2" in name or "s2built" in name or "built" in name or "rom" in name:
                    score += 5
                if p.stat().st_size >= 0x80000:
                    score += 2
                if score > 0:
                    candidates.append((score, mt, p))
        except Exception:
            candidates = []
        if not candidates:
            self._log("  Build succeeded but no ROM output found (.bin/.md/.gen)", "warn")
            return None
        candidates.sort(reverse=True)
        rom_path = candidates[0][2]
        try:
            data = rom_path.read_bytes()
            self._log(f"  Build output: {rom_path.name} ({len(data)} bytes)", "ok")
            return data
        except Exception as e:
            self._log(f"  Failed to read build output {rom_path}: {e}", "error")
            return None

    def _build_merged_rom(self, for_preview: bool = False):
        if not self.base_rom_path or not self.hack_paths:
            return None

        self._clear_log()
        title = "=== ROMMAN Preview ===\n" if for_preview else "=== ROMMAN Merge ===\n"
        self._log(title, "bold")

        self.change_sets = []
        for path in self.hack_paths:
            try:
                cs = load_input(path, self.base_rom, nes_shift=self._nes_shift_int())
                self.change_sets.append(cs)
                self._log(f"  Loaded: {cs}", "dim")
            except Exception as e:
                self._log(f"  Error loading {path.name}: {e}", "error")
                return None

        self._log("\n--- Game Compatibility ---", "bold")
        is_compatible, issues = check_compatibility(self.base_rom, self.change_sets, self.base_rom_path)
        if issues:
            self._log(f"\n  ⚠ {len(issues)} compatibility issue(s):", "warn")
            for issue in issues:
                self._log(f"    {issue}", "warn")
            proceed = self._ui_call(lambda issues=issues: messagebox.askyesno(
                "Compatibility Warning",
                f"Found {len(issues)} compatibility issue(s):\n\n" +
                "\n".join(f"- {i}" for i in issues[:3]) +
                "\n\nHacks may be for different games. Continue anyway?",
                parent=self.root
            ))
            if not proceed:
                self._log("\n  Cancelled by user", "dim")
                return None
            self._log("\n  Continuing due to user confirmation...", "warn")
        else:
            self._log("  ✓ All hacks appear compatible", "ok")

        from .merger import get_conflict_regions, merge_per_region, compute_target
        from .compat import is_disassembly_rebuild

        disasm_aware = self._ui_call(lambda: bool(self.disasm_var.get()))
        disasm_profile = self._ui_call(lambda: self.disasm_profile_var.get() if hasattr(self, "disasm_profile_var") else "Auto-detect")
        if disasm_profile == "No disassembly":
            disasm_aware = False
        disasm_map_path = self.disasm_map_path
        disasm_project = self.disasm_project_path
        disasm_build_cmd = self._ui_call(lambda: self.disasm_build_cmd_var.get().strip() if hasattr(self, "disasm_build_cmd_var") else "")
        rebuilds = [] if disasm_profile == "No disassembly" else [cs for cs in self.change_sets if is_disassembly_rebuild(cs, self.base_rom)]
        effective_base = self.base_rom
        merge_sets = self.change_sets
        rebuild_name = None

        # Optional: build disassembly project to produce/reference a rebuild ROM
        built_rom = None
        if disasm_aware and disasm_project and disasm_build_cmd:
            built_rom = self._try_disasm_build(disasm_project, disasm_build_cmd, disasm_profile)

        if rebuilds:
            names = ", ".join(cs.name for cs in rebuilds)
            self._log(f"\n  Disassembly rebuild detected: {names}", "warn")
            if not disasm_aware:
                self._ui_call(lambda: self.disasm_var.set(True))
                disasm_aware = True
            self._log(f"  Disassembly-aware mode [{disasm_profile}]: using rebuild as base, rebasing other patches", "warn")
            if len(rebuilds) == 1 and len(self.change_sets) > 1:
                rebuild = rebuilds[0]
                rebuild_name = rebuild.name
                effective_base = bytes(compute_target(self.base_rom, rebuild))
                merge_sets = [cs for cs in self.change_sets if cs is not rebuild]
            else:
                self._log("  Multiple rebuilds or only rebuilds loaded - falling back to normal merge", "dim")
        elif built_rom is not None:
            self._log(f"\n  Disassembly build produced ROM: {len(built_rom)} bytes", "warn")
            self._log(f"  Using built ROM as disassembly reference/base [{disasm_profile}]", "warn")
            effective_base = built_rom
            # no rebuild changeset to remove; all change_sets are patches relative to clean base
            merge_sets = self.change_sets

        # Rebase non-rebuild patches onto the disassembly rebuild/base when aware
        if disasm_aware and effective_base != self.base_rom and merge_sets:
            from .rebase import rebase_changesets, parse_symbol_map
            sym_map = None
            if disasm_map_path and disasm_map_path.exists():
                try:
                    sym_map = parse_symbol_map(disasm_map_path)
                    self._log(f"  Loaded symbol map: {disasm_map_path.name} ({len(sym_map)} symbols)", "dim")
                except Exception as e:
                    self._log(f"  Symbol map load failed: {e}", "warn")
            try:
                rebased, rwarns = rebase_changesets(merge_sets, self.base_rom, effective_base, symbol_map=sym_map)
                merge_sets = rebased
                for w in rwarns[-20:]:
                    self._log(f"    {w}", "dim")
                if len(rwarns) > 20:
                    self._log(f"    ... {len(rwarns)-20} more rebase notes", "dim")
                self._log("  Rebase pass complete (best-effort; ambiguous offsets skipped)", "warn")
            except Exception as e:
                self._log(f"  Rebase failed, falling back to same-offset apply: {e}", "error")

        regions = get_conflict_regions(merge_sets)
        conflict_bytes = sum(r["size"] for r in regions)

        if regions:
            self._log(f"\n  CONFLICTS: {conflict_bytes:,} bytes in {len(regions):,} region(s)", "error")
        else:
            self._log("\n  No conflicts found", "ok")

        check_only = self._ui_call(lambda: bool(self.check_var.get()))
        if check_only and not for_preview:
            self._log("\n  [Check only - no merge performed]", "dim")
            return None

        priority = self.priority if self.priority else None
        output_rom = None
        merged = None

        if regions:
            choice = self._ui_call(lambda: _ask_merge_choice(self.root, conflict_bytes, len(regions)))
            if choice is None:
                self._log("\n  Merge cancelled by user", "dim")
                return None

            if choice == "auto":
                self._log("\n--- Auto-pick Merge ---", "bold")
                prio = {name: i for i, name in enumerate(priority or [cs.name for cs in merge_sets])}
                active_profile = None
                try:
                    from .disasm_profiles import load_all_profiles, resolve_region_with_profile
                    if disasm_profile != "No disassembly":
                        profiles = load_all_profiles()
                        active_profile = profiles.get(disasm_profile)
                        if active_profile and active_profile.rules:
                            self._log(f"  Disasm profile: {active_profile.name} ({len(active_profile.rules)} rules)", "dim")
                except Exception as e:
                    self._log(f"  Disasm profile load failed: {e}", "warn")
                    resolve_region_with_profile = None

                clusters = {}
                for idx, r in enumerate(regions):
                    clusters.setdefault(r.get("cluster_id", -1), []).append(idx)
                winners = []
                rule_hits = 0
                for cid, idxs in clusters.items():
                    scores = {}
                    for idx in idxs:
                        r = regions[idx]
                        for h in r.get("hacks", {}).keys():
                            scores[h] = scores.get(h, 0) + r["size"]
                    cluster_winner = min(scores.keys(), key=lambda h: (-scores[h], prio.get(h, 9999))) if scores else None
                    for idx in idxs:
                        r = regions[idx]
                        winner = cluster_winner
                        if active_profile and resolve_region_with_profile:
                            decided = resolve_region_with_profile(active_profile, r["start"], r["end"], r.get("hacks", {}), rebuild_name)
                            if decided == "__BASE__":
                                winner = None
                                rule_hits += 1
                            elif decided is not None:
                                winner = decided
                                rule_hits += 1
                        winners.append((r["start"], r["end"], winner))
                output_rom = merge_per_region(merge_sets, winners, effective_base, priority)
                merged = ChangeSet(name="merged", source_format="merged")
                merged.changes = diff_roms(self.base_rom, bytes(output_rom))
                extra = f", {rule_hits} rule-applied" if rule_hits else ""
                self._log(f"  Auto-picked {len(clusters)} cluster(s), {len(regions):,} regions resolved{extra}", "ok")
            elif choice == "smart":
                self._log("\n--- Smart Merge ---", "bold")
                self._log(f"  {len(regions):,} conflict regions to resolve", "dim")
                sm_result = self._ui_call(lambda: _ask_smart_merge(self.root, merge_sets, regions, priority))
                if sm_result is None:
                    self._log("  Smart merge cancelled", "dim")
                    return None
                output_rom = merge_per_region(merge_sets, sm_result, effective_base, priority)
                merged = ChangeSet(name="merged", source_format="merged")
                merged.changes = diff_roms(self.base_rom, bytes(output_rom))
                self._log(f"  Smart merge applied ({len(sm_result):,} regions resolved)", "ok")
            else:
                self._log("\n--- Merging (raw) ---", "bold")
                result = merge(merge_sets, priority=priority)
                if not result.success:
                    self._log("  MERGE FAILED: unresolved conflicts", "error")
                    self._log("  Tip: use Smart merge for per-region control", "dim")
                    return None
                merged = result.merged
                output_rom = apply_changes(effective_base, merged)
                self._log(f"  Merged: {merged}", "ok")
        else:
            self._log("\n--- Merging ---", "bold")
            result = merge(merge_sets, priority=priority)
            if not result.success:
                self._log("  MERGE FAILED", "error")
                return None
            merged = result.merged
            output_rom = apply_changes(effective_base, merged)
            self._log(f"  Merged: {merged}", "ok")

        # Apply system-specific checksum fixups
        if output_rom is not None:
            from .fixups import apply_fixups
            fixed_rom, fix_msgs = apply_fixups(bytes(output_rom))
            output_rom = fixed_rom
            for m in fix_msgs:
                self._log(f"  {m}", "dim")

        # Normalize merged changeset to be relative to original base ROM (important for rebase)
        if output_rom is not None:
            merged = ChangeSet(name="merged", source_format="merged")
            merged.changes = diff_roms(self.base_rom, bytes(output_rom))
        return bytes(output_rom), merged

    def _do_merge(self):
        fmt = self.format_var.get()
        out_path = self.output_path
        if out_path is None and self.base_rom_path:
            ext = {"bin": self._default_bin_ext(), "nes": ".nes", "unh": ".unh", "ips": ".ips", "bps": ".bps", "xdelta": ".xdelta"}.get(fmt, f".{fmt}")
            out_path = self.base_rom_path.parent / f"merged_{self.base_rom_path.stem}{ext}"
            self.output_path = out_path
            self.output_label.configure(text=str(out_path))

        def work():
            try:
                built = self._build_merged_rom(for_preview=False)
                if not built:
                    return
                output_rom, merged = built
                if fmt in ("bin", "nes"):
                    out_path.write_bytes(output_rom)
                elif fmt == "unh":
                    from .rom import has_ines_header
                    data = bytes(output_rom)
                    if has_ines_header(data):
                        data = data[16:]
                    out_path.write_bytes(data)
                elif fmt == "ips":
                    ips_patch = IPSPatch(changes=merged.changes)
                    out_path.write_bytes(write_ips(ips_patch))
                elif fmt == "bps":
                    bps_patch = BPSPatch()
                    out_path.write_bytes(write_bps(bps_patch, self.base_rom, output_rom))
                elif fmt == "xdelta":
                    write_xdelta(output_rom, self.base_rom, out_path)
                self._log(f"\n  Written: {out_path} ({out_path.stat().st_size} bytes)", "ok")
            except Exception as e:
                self._log(f"\n  Error: {e}", "error")
            finally:
                self.root.after(0, lambda: self._set_busy(False))

        self._set_busy(True, "Merging...")
        threading.Thread(target=work, daemon=True).start()

    def _preview_merge(self):
        def work():
            try:
                built = self._build_merged_rom(for_preview=True)
                if not built:
                    self.root.after(0, lambda: self._set_busy(False))
                    return
                output_rom, _merged = built
                preview_dir = Path(tempfile.gettempdir()) / "romman_preview"
                preview_dir.mkdir(parents=True, exist_ok=True)
                ext = self._default_bin_ext()
                out = preview_dir / f"merged_preview_{self.base_rom_path.stem}{ext}"
                out.write_bytes(output_rom)
                self._log(f"\n  Preview ROM: {out}", "ok")

                def after_write():
                    self._set_busy(False)
                    emus = load_emulators()
                    dlg = EmulatorChooserDialog(self.root, emus, out)
                    self.root.wait_window(dlg)
                    if dlg.selected:
                        try:
                            launch_emulator(dlg.selected, out)
                            self._log(f"  Preview launched in {dlg.selected.name}", "ok")
                        except Exception as e:
                            messagebox.showerror("Launch Error", str(e), parent=self.root)

                self.root.after(0, after_write)
            except Exception as e:
                self._log(f"\n  Error: {e}", "error")
                self.root.after(0, lambda: self._set_busy(False))

        self._set_busy(True, "Building preview...")
        threading.Thread(target=work, daemon=True).start()


class EmulatorChooserDialog(tk.Toplevel):
    """Choose an emulator to preview a ROM."""

    def __init__(self, parent, emulators, rom_path: Path):
        super().__init__(parent)
        self.title("Preview ROM")
        self.configure(bg=BG)
        self.geometry("520x320")
        self.transient(parent)
        self.grab_set()
        self.emulators = list(emulators)
        self.rom_path = rom_path
        self.selected = None

        tk.Label(self, text="Choose emulator", bg=BG, fg=FG,
                 font=("Consolas", 11, "bold")).pack(pady=(12, 2))
        tk.Label(self, text=str(rom_path.name), bg=BG, fg=FG_DIM,
                 font=("Consolas", 9)).pack(pady=(0, 10))

        list_frame = tk.Frame(self, bg=BG)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 8))
        self.listbox = tk.Listbox(list_frame, bg=BG_ENTRY, fg=FG, font=("Consolas", 9),
                                  relief=tk.FLAT, selectbackground=BORDER, selectforeground=FG,
                                  highlightthickness=1, highlightcolor=BORDER, highlightbackground=BORDER,
                                  activestyle="none")
        sb = tk.Scrollbar(list_frame, command=self.listbox.yview, bg=BG)
        self.listbox.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._refresh()

        self.listbox.bind("<Double-Button-1>", lambda e: self._launch_selected())
        self.listbox.bind("<Return>", lambda e: self._launch_selected())

        btns = tk.Frame(self, bg=BG)
        btns.pack(fill=tk.X, padx=12, pady=(0, 12))
        tk.Button(btns, text="Launch", command=self._launch_selected,
                  bg=FG, fg=BG, font=("Consolas", 9, "bold"), relief=tk.FLAT,
                  padx=10, pady=3, activebackground=FG_DIM).pack(side=tk.LEFT)
        tk.Button(btns, text="Add emulator...", command=self._add,
                  bg=BG_BUTTON, fg=FG, font=("Consolas", 9), relief=tk.FLAT,
                  padx=10, pady=3, activebackground=BORDER).pack(side=tk.LEFT, padx=(8, 0))
        tk.Button(btns, text="Cancel", command=self.destroy,
                  bg=BG_BUTTON, fg=FG_DIM, font=("Consolas", 9), relief=tk.FLAT,
                  padx=10, pady=3, activebackground=BORDER).pack(side=tk.RIGHT)

        if self.emulators:
            self.listbox.selection_set(0)

    def _refresh(self):
        self.listbox.delete(0, tk.END)
        for e in self.emulators:
            self.listbox.insert(tk.END, f"{e.name}  —  {e.path}")
        if not self.emulators:
            self.listbox.insert(tk.END, "(No emulators found - click Add emulator...)")

    def _launch_selected(self):
        if not self.emulators:
            self._add()
            return
        sel = self.listbox.curselection()
        if not sel:
            return
        self.selected = self.emulators[sel[0]]
        self.destroy()

    def _add(self):
        path = filedialog.askopenfilename(
            title="Select Emulator Executable",
            filetypes=[("Executables", "*.exe"), ("All files", "*.*")],
            parent=self,
        )
        if not path:
            return
        name = Path(path).stem
        # simple name prompt via dialog
        name = self._prompt_name(name)
        if not name:
            return
        emu = add_emulator(name, path)
        self.emulators = load_emulators()
        self._refresh()
        # select the added one
        for i, e in enumerate(self.emulators):
            if e.path.lower() == emu.path.lower():
                self.listbox.selection_clear(0, tk.END)
                self.listbox.selection_set(i)
                break

    def _prompt_name(self, default: str) -> Optional[str]:
        dlg = tk.Toplevel(self)
        dlg.title("Emulator Name")
        dlg.configure(bg=BG)
        dlg.geometry("320x130")
        dlg.transient(self)
        dlg.grab_set()
        result = {"name": None}
        tk.Label(dlg, text="Emulator name:", bg=BG, fg=FG, font=("Consolas", 9)).pack(pady=(12, 4))
        var = tk.StringVar(value=default)
        entry = tk.Entry(dlg, textvariable=var, bg=BG_ENTRY, fg=FG, insertbackground=FG,
                         relief=tk.FLAT, font=("Consolas", 9))
        entry.pack(fill=tk.X, padx=20)
        entry.select_range(0, tk.END)
        entry.focus_set()

        def ok():
            result["name"] = var.get().strip() or default
            dlg.destroy()

        tk.Button(dlg, text="OK", command=ok, bg=FG, fg=BG, font=("Consolas", 9, "bold"),
                  relief=tk.FLAT, padx=10, pady=2).pack(pady=10)
        dlg.bind("<Return>", lambda e: ok())
        self.wait_window(dlg)
        return result["name"]


class MergeChoiceDialog(tk.Toplevel):
    """Popup: raw merge vs smart (per-region) merge."""

    def __init__(self, parent, num_conflicts, num_regions):
        super().__init__(parent)
        self.title("Resolve Conflicts")
        self.configure(bg=BG)
        self.geometry("440x290")
        self.transient(parent)
        self.grab_set()
        self.choice = None

        tk.Label(
            self, text=f"{num_conflicts:,} conflicting bytes detected",
            bg=BG, fg=FG, font=("Consolas", 11, "bold")
        ).pack(pady=(20, 4))
        tk.Label(
            self, text=f"across {num_regions:,} regions",
            bg=BG, fg=FG_DIM, font=("Consolas", 9)
        ).pack(pady=(0, 16))

        tk.Label(
            self, text="How do you want to merge?",
            bg=BG, fg=FG, font=("Consolas", 10)
        ).pack(pady=(0, 8))

        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(fill=tk.X, padx=40)

        tk.Button(
            btn_frame, text="Auto-pick & Run (recommended)",
            command=lambda: self._choose("auto"),
            bg=FG, fg=BG, font=("Consolas", 9, "bold"),
            relief=tk.FLAT, padx=10, pady=5, activebackground=FG_DIM
        ).pack(fill=tk.X, pady=3)

        tk.Button(
            btn_frame, text="Raw merge (global priority)",
            command=lambda: self._choose("raw"),
            bg=BG_BUTTON, fg=FG, font=("Consolas", 9),
            relief=tk.FLAT, padx=10, pady=5, activebackground=BORDER
        ).pack(fill=tk.X, pady=3)

        tk.Button(
            btn_frame, text="Smart merge (manual per-region)",
            command=lambda: self._choose("smart"),
            bg=BG_BUTTON, fg=FG, font=("Consolas", 9),
            relief=tk.FLAT, padx=10, pady=5, activebackground=BORDER
        ).pack(fill=tk.X, pady=3)

        tk.Button(
            btn_frame, text="Cancel",
            command=lambda: self._choose(None),
            bg=BG_BUTTON, fg=FG_DIM, font=("Consolas", 9),
            relief=tk.FLAT, padx=10, pady=5, activebackground=BORDER
        ).pack(fill=tk.X, pady=3)

    def _choose(self, c):
        self.choice = c
        self.destroy()


class SmartMergeDialog(tk.Toplevel):
    """Per-region conflict resolution dialog."""

    def __init__(self, parent, change_sets, regions, global_priority):
        super().__init__(parent)
        self.title("Smart Merge — Assign Winners per Region")
        self.configure(bg=BG)
        self.geometry("980x680")
        self.transient(parent)
        self.grab_set()

        self.change_sets = change_sets
        self.regions = regions
        self.hack_names = [cs.name for cs in change_sets]
        self.global_priority = global_priority or self.hack_names
        self.cancelled = False

        # Default winner per region index = highest-priority hack involved
        self.winners: Dict[int, Optional[str]] = {}
        for idx, r in enumerate(regions):
            involved = [h for h in self.global_priority if h in r["hacks"]]
            self.winners[idx] = involved[0] if involved else None

        self._build()

    def _build(self):
        # Header
        tk.Label(
            self, text="Assign which hack wins each conflict region",
            bg=BG, fg=FG, font=("Consolas", 11, "bold")
        ).pack(pady=(10, 2))
        tk.Label(
            self, text="Select region(s), pick a winner, click Assign.  None = keep base ROM.",
            bg=BG, fg=FG_DIM, font=("Consolas", 9)
        ).pack(pady=(0, 8))

        # Toolbar
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill=tk.X, padx=10, pady=(0, 6))

        tk.Label(bar, text="Winner:", bg=BG, fg=FG_DIM, font=("Consolas", 9)).pack(side=tk.LEFT)
        self.winner_var = tk.StringVar(value=self.hack_names[0] if self.hack_names else "")
        menu = tk.OptionMenu(bar, self.winner_var, *(self.hack_names + ["(keep base)"]))
        menu.configure(bg=BG_ENTRY, fg=FG, font=("Consolas", 9), activebackground=BORDER,
                       highlightthickness=0, relief=tk.FLAT)
        menu["menu"].configure(bg=BG_ENTRY, fg=FG, activebackground=BORDER)
        menu.pack(side=tk.LEFT, padx=(5, 10))

        tk.Button(bar, text="Assign selected", command=self._assign_selected,
                  bg=BG_BUTTON, fg=FG, font=("Consolas", 9), relief=tk.FLAT,
                  padx=8, pady=2, activebackground=BORDER).pack(side=tk.LEFT)
        tk.Button(bar, text="Select cluster", command=self._select_cluster,
                  bg=BG_BUTTON, fg=FG_DIM, font=("Consolas", 9), relief=tk.FLAT,
                  padx=8, pady=2, activebackground=BORDER).pack(side=tk.LEFT, padx=(4, 0))
        tk.Button(bar, text="Assign cluster", command=self._assign_cluster,
                  bg=BG_BUTTON, fg=FG_DIM, font=("Consolas", 9), relief=tk.FLAT,
                  padx=8, pady=2, activebackground=BORDER).pack(side=tk.LEFT, padx=(4, 0))

        # Range select
        tk.Label(bar, text="Range:", bg=BG, fg=FG_DIM, font=("Consolas", 9)).pack(side=tk.LEFT, padx=(15, 0))
        self.range_start = tk.Entry(bar, width=8, bg=BG_ENTRY, fg=FG, font=("Consolas", 9),
                                    relief=tk.FLAT, insertbackground=FG)
        self.range_start.pack(side=tk.LEFT, padx=(4, 2))
        tk.Label(bar, text="-", bg=BG, fg=FG_DIM, font=("Consolas", 9)).pack(side=tk.LEFT)
        self.range_end = tk.Entry(bar, width=8, bg=BG_ENTRY, fg=FG, font=("Consolas", 9),
                                  relief=tk.FLAT, insertbackground=FG)
        self.range_end.pack(side=tk.LEFT, padx=(2, 6))
        tk.Button(bar, text="Select range", command=self._select_range,
                  bg=BG_BUTTON, fg=FG, font=("Consolas", 9), relief=tk.FLAT,
                  padx=8, pady=2, activebackground=BORDER).pack(side=tk.LEFT)

        # Quick assign buttons
        q = tk.Frame(self, bg=BG)
        q.pack(fill=tk.X, padx=10, pady=(0, 6))
        for name in self.hack_names:
            tk.Button(q, text=f"All → {name}", command=lambda n=name: self._assign_all(n),
                      bg=BG_BUTTON, fg=FG, font=("Consolas", 8), relief=tk.FLAT,
                      padx=6, pady=1, activebackground=BORDER).pack(side=tk.LEFT, padx=1)
        tk.Button(q, text="All → base", command=lambda: self._assign_all(None),
                  bg=BG_BUTTON, fg=FG_DIM, font=("Consolas", 8), relief=tk.FLAT,
                  padx=6, pady=1, activebackground=BORDER).pack(side=tk.LEFT, padx=1)
        tk.Button(q, text="Auto-pick & Run", command=self._auto_pick,
                  bg=FG, fg=BG, font=("Consolas", 8, "bold"), relief=tk.FLAT,
                  padx=8, pady=1, activebackground=FG_DIM).pack(side=tk.LEFT, padx=(8, 1))

        # Filters
        filt = tk.Frame(self, bg=BG)
        filt.pack(fill=tk.X, padx=10, pady=(0, 6))
        tk.Label(filt, text="Show:", bg=BG, fg=FG_DIM, font=("Consolas", 9)).pack(side=tk.LEFT)
        self.filter_scope = tk.StringVar(value="All")
        tk.OptionMenu(filt, self.filter_scope, "All", "Original ROM", "Expansion").configure(
            bg=BG_ENTRY, fg=FG, font=("Consolas", 9), highlightthickness=0, relief=tk.FLAT
        )
        # OptionMenu returns widget; easier to build separately
        for w in filt.winfo_children():
            pass
        # rebuild cleanly
        for w in filt.winfo_children():
            w.destroy()
        tk.Label(filt, text="Show:", bg=BG, fg=FG_DIM, font=("Consolas", 9)).pack(side=tk.LEFT)
        self.filter_scope = tk.StringVar(value="All")
        scope_menu = tk.OptionMenu(filt, self.filter_scope, "All", "Original ROM", "Expansion")
        scope_menu.configure(bg=BG_ENTRY, fg=FG, font=("Consolas", 9), activebackground=BORDER,
                             highlightthickness=0, relief=tk.FLAT)
        scope_menu["menu"].configure(bg=BG_ENTRY, fg=FG, activebackground=BORDER)
        scope_menu.pack(side=tk.LEFT, padx=(4, 10))
        tk.Label(filt, text="Min size:", bg=BG, fg=FG_DIM, font=("Consolas", 9)).pack(side=tk.LEFT)
        self.filter_min = tk.Entry(filt, width=6, bg=BG_ENTRY, fg=FG, font=("Consolas", 9),
                                   relief=tk.FLAT, insertbackground=FG)
        self.filter_min.pack(side=tk.LEFT, padx=(4, 10))
        tk.Button(filt, text="Filter", command=self._apply_filter,
                  bg=BG_BUTTON, fg=FG, font=("Consolas", 9), relief=tk.FLAT,
                  padx=8, pady=2, activebackground=BORDER).pack(side=tk.LEFT)
        tk.Button(filt, text="Clear", command=self._clear_filter,
                  bg=BG_BUTTON, fg=FG_DIM, font=("Consolas", 9), relief=tk.FLAT,
                  padx=8, pady=2, activebackground=BORDER).pack(side=tk.LEFT, padx=(4, 0))

        # Treeview
        tree_frame = tk.Frame(self, bg=BG)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 6))

        cols = ("addr", "size", "cluster", "winner") + tuple(f"h{i}" for i in range(len(self.hack_names)))
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="extended")
        self.tree.heading("addr", text="Address")
        self.tree.heading("size", text="Size")
        self.tree.heading("cluster", text="Cluster")
        self.tree.heading("winner", text="Winner")
        for i, name in enumerate(self.hack_names):
            self.tree.heading(f"h{i}", text=name[:18])
        self.tree.column("addr", width=150, anchor="w")
        self.tree.column("size", width=60, anchor="e")
        self.tree.column("cluster", width=70, anchor="center")
        self.tree.column("winner", width=150, anchor="w")
        for i in range(len(self.hack_names)):
            self.tree.column(f"h{i}", width=55, anchor="center")

        vsb = tk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview, bg=BG)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.tree.tag_configure("base", foreground=FG_DIM)
        self.tree.tag_configure("split", foreground=FG_WARN)
        self._populate()

        # Status
        self.status = tk.Label(self, text="", bg=BG, fg=FG_DIM, font=("Consolas", 9), anchor="w")
        self.status.pack(fill=tk.X, padx=10, pady=(0, 4))

        # Bottom buttons
        bottom = tk.Frame(self, bg=BG)
        bottom.pack(fill=tk.X, padx=10, pady=(0, 10))
        tk.Label(bottom, text=f"{len(self.regions):,} regions", bg=BG, fg=FG_DIM,
                 font=("Consolas", 9)).pack(side=tk.LEFT)
        tk.Button(bottom, text="Cancel", command=self._cancel,
                  bg=BG_BUTTON, fg=FG_DIM, font=("Consolas", 9), relief=tk.FLAT,
                  padx=12, pady=3, activebackground=BORDER).pack(side=tk.RIGHT, padx=(8, 0))
        tk.Button(bottom, text="Apply Smart Merge", command=self._apply,
                  bg=FG, fg=BG, font=("Consolas", 10, "bold"), relief=tk.FLAT,
                  padx=14, pady=3, activebackground=FG_DIM).pack(side=tk.RIGHT)

        self._update_status()

    def _matches_filter(self, r):
        scope = getattr(self, "filter_scope", None)
        scope_val = scope.get() if scope else "All"
        if scope_val == "Original ROM" and r["start"] >= 0x100000:
            return False
        if scope_val == "Expansion" and r["start"] < 0x100000:
            return False
        min_size = 0
        try:
            min_size = int(getattr(self, "filter_min", None).get() or "0")
        except Exception:
            min_size = 0
        if r["size"] < min_size:
            return False
        return True

    def _populate(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        shown = 0
        for idx, r in enumerate(self.regions):
            if not self._matches_filter(r):
                continue
            cid = r.get("cluster_id", 0)
            cr = r.get("cluster_regions", 1)
            vals = [
                f"0x{r['start']:06X}-0x{r['end']-1:06X}",
                f"{r['size']:,}",
                f"C{cid}({cr})",
                self.winners[idx] or "(base)",
            ]
            for i, name in enumerate(self.hack_names):
                vals.append(r["hacks"].get(name, "-"))
            self.tree.insert("", tk.END, iid=str(idx), values=vals)
            shown += 1
        self.status.configure(text=f"Showing {shown:,} / {len(self.regions):,} regions", fg=FG_DIM)

    def _apply_filter(self):
        self._populate()
        self._update_status()

    def _clear_filter(self):
        self.filter_scope.set("All")
        self.filter_min.delete(0, tk.END)
        self._populate()
        self._update_status()

    def _assign_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        w = self.winner_var.get()
        if w == "(keep base)":
            w = None
        for iid in sel:
            idx = int(iid)
            self.winners[idx] = w
            self.tree.set(iid, "winner", w or "(base)")
        self._update_status(len(sel))

    def _select_cluster(self):
        sel = self.tree.selection()
        if not sel:
            return
        cluster_ids = {self.regions[int(iid)].get("cluster_id", -1) for iid in sel}
        count = 0
        for idx, r in enumerate(self.regions):
            if r.get("cluster_id", -1) in cluster_ids:
                if self.tree.exists(str(idx)):
                    self.tree.selection_add(str(idx))
                count += 1
        self.status.configure(text=f"Selected {count} regions in {len(cluster_ids)} cluster(s)", fg=FG_OK)

    def _assign_cluster(self):
        sel = self.tree.selection()
        if not sel:
            return
        cluster_ids = {self.regions[int(iid)].get("cluster_id", -1) for iid in sel}
        w = self.winner_var.get()
        if w == "(keep base)":
            w = None
        count = 0
        for idx, r in enumerate(self.regions):
            if r.get("cluster_id", -1) in cluster_ids:
                self.winners[idx] = w
                iid = str(idx)
                if self.tree.exists(iid):
                    self.tree.set(iid, "winner", w or "(base)")
                count += 1
        self._update_status(count)

    def _select_range(self):
        try:
            s = int(self.range_start.get(), 16)
            e = int(self.range_end.get(), 16)
        except ValueError:
            self.status.configure(text="Invalid range (use hex, e.g. 045000)", fg=FG_ERROR)
            return
        count = 0
        for idx, r in enumerate(self.regions):
            if r["end"] > s and r["start"] < e:
                iid = str(idx)
                if self.tree.exists(iid):
                    self.tree.selection_add(iid)
                count += 1
        self.status.configure(text=f"Selected {count} regions in range", fg=FG_OK)

    def _assign_all(self, winner):
        for idx in range(len(self.regions)):
            self.winners[idx] = winner
            iid = str(idx)
            if self.tree.exists(iid):
                self.tree.set(iid, "winner", winner or "(base)")
        self._update_status(len(self.regions))

    def _auto_pick(self):
        # Cluster-safe auto-pick: for each cluster, choose hack with most bytes in that cluster;
        # tie-break by global priority.
        clusters: Dict[int, List[int]] = {}
        for idx, r in enumerate(self.regions):
            clusters.setdefault(r.get("cluster_id", -1), []).append(idx)

        prio = {name: i for i, name in enumerate(self.global_priority)}
        changed = 0
        for cid, idxs in clusters.items():
            scores: Dict[str, int] = {}
            for idx in idxs:
                r = self.regions[idx]
                for h in r.get("hacks", {}).keys():
                    scores[h] = scores.get(h, 0) + r["size"]
            if not scores:
                winner = None
            else:
                winner = min(scores.keys(), key=lambda h: (-scores[h], prio.get(h, 9999)))
            for idx in idxs:
                if self.winners.get(idx) != winner:
                    changed += 1
                self.winners[idx] = winner
                iid = str(idx)
                if self.tree.exists(iid):
                    self.tree.set(iid, "winner", winner or "(base)")
        self._update_status(changed)
        self._apply()

    def _update_status(self, changed=0):
        from collections import Counter
        c = Counter(v or "(base)" for v in self.winners.values())
        parts = ", ".join(f"{k}: {v:,}" for k, v in c.most_common())
        splits = len(self._split_clusters())
        split_txt = f"   |   ⚠ {splits} split cluster(s)" if splits else ""
        self.status.configure(text=f"{parts}{split_txt}   |   {changed} just changed")

    def _cancel(self):
        self.cancelled = True
        self.destroy()

    def _split_clusters(self):
        by_cluster: Dict[int, set] = {}
        for idx, r in enumerate(self.regions):
            cid = r.get("cluster_id", -1)
            by_cluster.setdefault(cid, set()).add(self.winners[idx] or "(base)")
        return [cid for cid, winners in by_cluster.items() if len(winners) > 1]

    def _apply(self):
        splits = self._split_clusters()
        if splits:
            from tkinter import messagebox
            msg = (
                f"{len(splits)} cluster(s) have mixed winners.\n\n"
                "Splitting a cluster can corrupt compressed/structured data "
                "(e.g. Kosinski level layouts), causing scrambled levels.\n\n"
                "Apply anyway?"
            )
            if not messagebox.askyesno("Cluster Split Warning", msg, parent=self):
                return
        self.destroy()

    def get_winners_list(self):
        return [(r["start"], r["end"], self.winners[idx]) for idx, r in enumerate(self.regions)]


def run():
    root = tk.Tk()
    RommanGUI(root)
    root.mainloop()


if __name__ == "__main__":
    run()
