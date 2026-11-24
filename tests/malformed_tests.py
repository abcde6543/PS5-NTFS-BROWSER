#!/usr/bin/env python3
"""Hand-made malformed volumes: the driver must refuse them, not hang or read
outside its buffers.

fuzz.py flips single bytes or writes the words 0/FF/7F/80, so it never
produces the coordinated values below (a length of 0xFFFFFFxx, a run length
close to 2^52, ...). Each case patches one MFT record of a small image that
ntfs-3g filled, then runs the sanitizer build of ntfstool on it with a time
limit.

Needs: root, /dev/fuse, ntfs-3g. Usage: tests/malformed_tests.py build/ntfstool-asan
"""
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile

TOOL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfstool-asan")
WORK = tempfile.mkdtemp(prefix="ntfsmal-")
BASE = os.path.join(WORK, "base.img")
MNT = os.path.join(WORK, "mnt")
failures = []

AT_STD, AT_NAME, AT_DATA, AT_ROOT, AT_END = 0x10, 0x30, 0x80, 0x90, 0xFFFFFFFF


def sh(*a):
    subprocess.run(a, check=True, capture_output=True)


def build_base():
    with open(BASE, "wb") as f:
        f.truncate(16 << 20)
    sh("mkntfs", "-F", "-Q", "-c", "4096", BASE)
    os.makedirs(MNT)
    sh("ntfs-3g", BASE, MNT)
    try:
        with open(os.path.join(MNT, "small.txt"), "w") as f:
            f.write("resident file\n" * 20)
        with open(os.path.join(MNT, "res.txt"), "w") as f:
            f.write("another resident file\n" * 10)
        with open(os.path.join(MNT, "big.bin"), "wb") as f:
            f.write(random.Random(7).randbytes(40000))
        os.makedirs(os.path.join(MNT, "folder"))
        with open(os.path.join(MNT, "folder", "inside.txt"), "w") as f:
            f.write("inside\n")
        comp = os.path.join(MNT, "comp")              # compressed folder (as in fuzz.py)
        os.makedirs(comp)
        sh("setfattr", "-n", "system.ntfs_attrib_be", "-v", "0x00000810", comp)
        with open(os.path.join(comp, "packed.txt"), "wb") as f:
            f.write(b"compress me " * 30000)
    finally:
        sh("umount", MNT)


class Image:
    """Read and patch MFT records of a raw NTFS image (fixups handled)."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = bytearray(f.read())
        d = self.data
        self.cluster = struct.unpack_from("<H", d, 11)[0] * d[13]
        self.mft = struct.unpack_from("<Q", d, 0x30)[0] * self.cluster
        c = struct.unpack_from("<b", d, 0x40)[0]
        self.rec_size = c * self.cluster if c > 0 else 1 << -c

    def _off(self, n):
        return self.mft + n * self.rec_size

    def read(self, n):
        o = self._off(n)
        rec = bytearray(self.data[o:o + self.rec_size])
        if rec[:4] != b"FILE":
            return None
        ofs, cnt = struct.unpack_from("<HH", rec, 4)
        for i in range(1, cnt):
            rec[i * 512 - 2:i * 512] = rec[ofs + 2 * i:ofs + 2 * i + 2]
        return rec

    def write(self, n, rec):
        ofs, cnt = struct.unpack_from("<HH", rec, 4)
        usn = bytes(rec[ofs:ofs + 2])
        for i in range(1, cnt):
            rec[ofs + 2 * i:ofs + 2 * i + 2] = rec[i * 512 - 2:i * 512]
            rec[i * 512 - 2:i * 512] = usn
        o = self._off(n)
        self.data[o:o + self.rec_size] = rec

    @staticmethod
    def attrs(rec):
        p = struct.unpack_from("<H", rec, 0x14)[0]
        out = []
        while True:
            t = struct.unpack_from("<I", rec, p)[0]
            if t == AT_END:
                return out, p
            ln = struct.unpack_from("<I", rec, p + 4)[0]
            out.append((p, t, ln))
            p += ln

    def find(self, name):
        want = name.encode("utf-16-le")
        for n in range(16, 400):
            rec = self.read(n)
            if rec is None:
                continue
            try:
                attrs, _ = self.attrs(rec)
            except struct.error:
                continue                         # not a record we can walk
            for p, t, ln in attrs:
                if t == AT_NAME:
                    voff = struct.unpack_from("<H", rec, p + 20)[0]
                    nl = rec[p + voff + 64]
                    if bytes(rec[p + voff + 66:p + voff + 66 + 2 * nl]) == want:
                        return n
        raise SystemExit("record for %s not found" % name)

    def save(self, path):
        with open(path, "wb") as f:
            f.write(self.data)


def run(img, *args):
    """-> ("ok"|"HANG"|"CRASH", exit code, stdout, stderr)"""
    try:
        r = subprocess.run([TOOL, args[0], img] + list(args[1:]), capture_output=True, timeout=20,
                           env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0",
                                    UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"))
    except subprocess.TimeoutExpired:
        return "HANG", None, b"", ""
    err = r.stderr.decode(errors="replace")
    if "Sanitizer" in err or "runtime error" in err or r.returncode < 0:
        return "CRASH", r.returncode, r.stdout, err
    return "ok", r.returncode, r.stdout, err


def check(name, status, detail=""):
    print("%-52s %s %s" % (name, "PASS" if status == "ok" else "FAIL (%s)" % status,
                           detail if status != "ok" else ""))
    if status != "ok":
        failures.append(name)


def case(name, fname, patch, *cmds):
    im = Image(BASE)
    n = im.find(fname)
    rec = im.read(n)
    patch(im, rec)
    im.write(n, rec)
    path = os.path.join(WORK, "case.img")
    im.save(path)
    for cmd in cmds:
        status, rc, out, err = run(path, *cmd)
        check("%s (%s)" % (name, " ".join(cmd)), status, err.strip().splitlines()[:6] if err else "")


# 1. An attribute whose length makes (position + length) wrap around 2^32
#    sends the attribute cursor backwards: attribute 2 -> attribute 1 -> ...
def patch_wrap(im, rec):
    attrs, _ = im.attrs(rec)
    (p1, _, _), (p2, _, _) = attrs[0], attrs[1]
    struct.pack_into("<I", rec, p2 + 4, (p1 - p2) & 0xFFFFFFFF)


# 2. A run of 2^52 + 5 clusters: (vcn + len) * cluster wraps to 0x5000, so
#    reading at offset 0x5000 never advances.
def patch_runs(im, rec):
    attrs, end = im.attrs(rec)
    p, t, ln = [a for a in attrs if a[1] == AT_DATA][0]
    assert rec[p + 8] == 1, "big.bin must be non-resident"
    runs = bytes([0x17, 5, 0, 0, 0, 0, 0, 0x10, 0x40, 0]) + bytes(6)  # + padding to 16
    mp = struct.unpack_from("<H", rec, p + 32)[0]
    new_len = mp + len(runs)
    tail = bytes(rec[p + ln:end])                  # attributes after $DATA (none)
    rec[p + mp:p + mp + len(runs)] = runs
    struct.pack_into("<I", rec, p + 4, new_len)
    q = p + new_len
    rec[q:q + len(tail)] = tail
    struct.pack_into("<II", rec, q + len(tail), AT_END, 0)
    struct.pack_into("<I", rec, 0x18, q + len(tail) + 8)


# 3. A resident attribute whose length is 0xFFFFFFF8 passes the "inside the
#    record" check through the same wrap-around, and its value length (0x2000)
#    is then copied out of a 1 KiB record buffer.
def patch_resident(im, rec):
    attrs, _ = im.attrs(rec)
    p, _, _ = attrs[0]
    struct.pack_into("<I", rec, p, AT_DATA)            # first attribute becomes $DATA
    struct.pack_into("<I", rec, p + 4, 0xFFFFFFF8)
    struct.pack_into("<I", rec, p + 16, 0x2000)        # value length
    struct.pack_into("<H", rec, p + 20, 0x18)          # value offset
    rec[0x34:0x38] = bytes(4)                          # end the walk after it


# 4. The name offset of a named attribute points far outside the record.
def patch_nameoff(im, rec):
    attrs, _ = im.attrs(rec)
    p, _, _ = [a for a in attrs if a[1] == AT_ROOT][0]
    assert rec[p + 9] == 4, "$I30 expected"
    struct.pack_into("<H", rec, p + 10, 0xFFF0)


# 5. A resident value whose length is near 2^32: 'value offset + value length'
#    wraps around and passes the check, though the attribute itself is valid.
def patch_vlen(im, rec):
    attrs, _ = im.attrs(rec)
    p, _, _ = [a for a in attrs if a[1] == AT_DATA][0]
    assert rec[p + 8] == 0, "small.txt must be resident"
    struct.pack_into("<I", rec, p + 16, 0xFFFFFFF0)


# 6. A compressed file whose compression unit is 2^40 clusters: the shift is
#    undefined, and every unit from 18 up asks for 1 GB or more per read.
def patch_cu(im, rec):
    attrs, _ = im.attrs(rec)
    p, _, _ = [a for a in attrs if a[1] == AT_DATA][0]
    assert rec[p + 8] == 1 and struct.unpack_from("<H", rec, p + 12)[0] & 1,         "packed.txt must be compressed"
    rec[p + 34] = 40


def case_boot(name, offset, value, *cmds):
    """Patch one byte of the boot sector."""
    im = Image(BASE)
    im.data[offset] = value
    path = os.path.join(WORK, "case.img")
    im.save(path)
    for cmd in cmds:
        status, rc, out, err = run(path, *cmd)
        check("%s (%s)" % (name, " ".join(cmd)), status, err.strip().splitlines()[:6] if err else "")


def main():
    build_base()
    # Sanity: the untouched image works.
    status, rc, out, err = run(BASE, "cat", "/big.bin")
    check("untouched image reads back", status if rc == 0 else "exit %s" % rc, err)
    case("attribute length wraps 2^32", "small.txt", patch_wrap, ("cat", "/small.txt"), ("tree",))
    case("run length overflows cluster arithmetic", "big.bin", patch_runs, ("cat", "/big.bin"))
    case("resident length wraps, value read past record", "res.txt", patch_resident, ("cat", "/res.txt"))
    case("attribute name offset outside the record", "folder", patch_nameoff, ("ls", "/folder"))
    case("resident value length wraps 2^32", "small.txt", patch_vlen, ("cat", "/small.txt"))
    case("compression unit of 2^40 clusters", "packed.txt", patch_cu, ("cat", "/comp/packed.txt"))
    # 7.-9. Boot sector sizes given as powers of two with absurd exponents.
    case_boot("sectors per cluster 2^106", 0x0D, 0x96, ("ls", "/"))
    case_boot("MFT record size 2^102", 0x40, 0x9A, ("ls", "/"))
    case_boot("index block size 2^102", 0x44, 0x9A, ("ls", "/"))
    if failures:
        print("\nFAILED: " + ", ".join(failures))
        sys.exit(1)
    print("\nAll malformed-volume tests passed.")
    shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
