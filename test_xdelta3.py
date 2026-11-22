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

# Try: base, patch, out
pyxdelta.decode(str(tmp / "base.bin"), str(tmp / "patch.xdelta"), str(tmp / "result.bin"))
result = (tmp / "result.bin").read_bytes()
print(f"Result size: {len(result)}, Expected: {len(target)}")
print(f"Match: {result == bytes(target)}")

if result != bytes(target):
    diffs = 0
    for i in range(min(len(result), len(target))):
        if result[i] != target[i]:
            print(f"  Diff at {i}: got {result[i]:02X}, expected {target[i]:02X}")
            diffs += 1
            if diffs > 5:
                break
    print(f"  ... and more" if diffs > 5 else "")
