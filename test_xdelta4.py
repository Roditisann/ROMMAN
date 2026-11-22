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

# Try different run arg orders
# xdelta3 CLI: xdelta3 -e -s source target output
# So maybe: run(source, target, patch) = run(base, target, patch)
for name, args in [
    ("target,base,patch", (str(tmp / "target.bin"), str(tmp / "base.bin"), str(tmp / "patch1.xdelta"))),
    ("base,target,patch", (str(tmp / "base.bin"), str(tmp / "target.bin"), str(tmp / "patch2.xdelta"))),
]:
    try:
        pyxdelta.run(*args)
        p = Path(args[2])
        print(f"  {name}: {p.stat().st_size} bytes")
    except Exception as e:
        print(f"  {name}: {e}")

# Now decode patch2 (base,target,patch order) with (base,patch,out)
print("\nDecode patch2:")
pyxdelta.decode(str(tmp / "base.bin"), str(tmp / "patch2.xdelta"), str(tmp / "result.bin"))
result = (tmp / "result.bin").read_bytes()
print(f"  Match: {result == bytes(target)}")
if result != bytes(target):
    for i in range(min(len(result), len(target))):
        if result[i] != target[i]:
            print(f"  Diff at {i}: got {result[i]:02X}, expected {target[i]:02X}")
            break
