import pyxdelta
import tempfile
from pathlib import Path

tmp = Path(tempfile.mkdtemp())

base = bytes(range(256)) * 4
target = bytearray(base)
target[100] = 0xFF
target[101] = 0xFE

(tmp / "base.bin").write_bytes(base)
(tmp / "target.bin").write_bytes(bytes(target))

# Create patch
pyxdelta.run(str(tmp / "target.bin"), str(tmp / "base.bin"), str(tmp / "patch.xdelta"))
patch_size = (tmp / "patch.xdelta").stat().st_size
print(f"Patch: {patch_size} bytes")

# Try different arg orders for decode
orders = [
    ("patch,base,out", (str(tmp / "patch.xdelta"), str(tmp / "base.bin"), str(tmp / "result1.bin"))),
    ("out,patch,base", (str(tmp / "result2.bin"), str(tmp / "patch.xdelta"), str(tmp / "base.bin"))),
    ("base,patch,out", (str(tmp / "base.bin"), str(tmp / "patch.xdelta"), str(tmp / "result3.bin"))),
]

for name, args in orders:
    try:
        pyxdelta.decode(*args)
        out = Path(args[2])
        if out.exists():
            data = out.read_bytes()
            match = data == bytes(target)
            print(f"  {name}: OK ({len(data)} bytes, match={match})")
        else:
            print(f"  {name}: no output file")
    except Exception as e:
        print(f"  {name}: {e}")
