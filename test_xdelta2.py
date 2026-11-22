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
print(f"Patch size: {(tmp / 'patch.xdelta').stat().st_size}")

# Decode with out,patch,base order
pyxdelta.decode(str(tmp / "result.bin"), str(tmp / "patch.xdelta"), str(tmp / "base.bin"))
result = (tmp / "result.bin").read_bytes()
print(f"Result size: {len(result)}")
print(f"Expected size: {len(target)}")
print(f"Match: {result == bytes(target)}")

# Check where they differ
if result != bytes(target):
    for i in range(min(len(result), len(target))):
        if result[i] != target[i]:
            print(f"  Diff at {i}: got {result[i]:02X}, expected {target[i]:02X}")
            if i > 110:
                break
