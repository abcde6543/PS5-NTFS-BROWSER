#!/usr/bin/env python3
"""Corruption fuzzer: damaged drives must give errors, never crashes or hangs.

Builds a small NTFS image, then repeatedly corrupts bytes in its metadata
(MFT records, index blocks, boot sector) and runs the sanitizer build of
ntfstool over the whole tree and every file.

Usage: tests/fuzz.py build/ntfstool-asan [iterations]
"""
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile

TOOL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfstool-asan")
ITER = int(sys.argv[2]) if len(sys.argv) > 2 else 300
WORK = tempfile.mkdtemp(prefix="ntfsfuzz-")
IMG = os.path.join(WORK, "base.img")
MNT = os.path.join(WORK, "mnt")


def sh(*a):
    subprocess.run(a, check=True, capture_output=True)


def build():
    with open(IMG, "wb") as f:
        f.truncate(16 << 20)
    sh("mkntfs", "-F", "-Q", "-c", "1024", IMG)
    os.makedirs(MNT)
    sh("ntfs-3g", "-o", "compression", IMG, MNT)
    try:
        r = random.Random(0)
        os.makedirs(os.path.join(MNT, "dir/sub"))
        for i in range(300):
            with open(os.path.join(MNT, "dir", "f%03d_%s.txt" % (i, "y" * (i % 30))), "wb") as f:
                f.write(r.randbytes(r.randint(0, 3000)))
        comp = os.path.join(MNT, "comp")
        os.mkdir(comp)
        sh("setfattr", "-n", "system.ntfs_attrib_be", "-v", "0x00000810", comp)
        with open(os.path.join(comp, "c.txt"), "wb") as f:
            f.write(b"compress me " * 30000)
        with open(os.path.join(MNT, "dir/sub/big.bin"), "wb") as f:
            f.write(r.randbytes(400_000))
    finally:
        sh("umount", MNT)


def metadata_regions(data):
    cluster = struct.unpack_from("<H", data, 11)[0] * data[13]
    mft = struct.unpack_from("<Q", data, 0x30)[0] * cluster
    regions = [(0, 512), (mft, mft + 120 * 1024)]
    # Index blocks: find "INDX" signatures.
    pos = data.find(b"INDX")
    while pos >= 0:
        regions.append((pos, pos + 4096))
        pos = data.find(b"INDX", pos + 4)
    return regions


def run(img, *args):
    try:
        r = subprocess.run([TOOL, args[0], img] + list(args[1:]), capture_output=True, timeout=30,
                           env=dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=0",
                                    UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"))
    except subprocess.TimeoutExpired:
        return "HANG", b""
    err = r.stderr.decode(errors="replace")
    if "Sanitizer" in err or "runtime error" in err or r.returncode < 0:
        return "CRASH", err
    return "ok", r.stdout


def main():
    build()
    base = open(IMG, "rb").read()
    regions = metadata_regions(base)
    bad = 0
    rng = random.Random(1234)
    img = os.path.join(WORK, "case.img")
    for it in range(ITER):
        data = bytearray(base)
        for _ in range(rng.choice([1, 2, 4, 16, 64])):
            lo, hi = rng.choice(regions)
            off = rng.randrange(lo, min(hi, len(data)))
            mode = rng.random()
            if mode < 0.5:
                data[off] = rng.randrange(256)
            elif mode < 0.8:
                data[off] ^= 1 << rng.randrange(8)
            else:
                v = rng.choice([0, 0xFF, 0x7F, 0x80, 0xFFFF, 0xFFFFFFFF])
                struct.pack_into("<I", data, off - off % 4, v & 0xFFFFFFFF)
        open(img, "wb").write(data)
        status, out = run(img, "tree")
        files = []
        if status == "ok":
            for line in out.decode(errors="replace").splitlines()[:400]:
                parts = line.split("\t", 2)
                if len(parts) == 3 and parts[0] == "f":
                    files.append(parts[2])
            for extra in (["info"], ["ls", "/dir"]):
                st2, o2 = run(img, *extra)
                if st2 != "ok":
                    status, out = st2, o2
                    break
        for p in files[:40]:
            if status != "ok":
                break
            status, out = run(img, "cat", p)
            if status == "ok":
                status = "ok"
        if status != "ok":
            bad += 1
            keep = os.path.join(WORK, "fail_%03d.img" % it)
            shutil.copy(img, keep)
            print("iteration %d: %s (saved %s)" % (it, status, keep))
            print(out if isinstance(out, str) else out[:2000])
            if bad >= 5:
                break
    print("%-34s %s  (%d corrupted images)" % ("corruption fuzzing", "PASS" if not bad else "FAIL", ITER))
    if bad:
        sys.exit(1)
    shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
