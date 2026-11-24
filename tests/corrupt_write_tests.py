#!/usr/bin/env python3
"""Writing to a damaged drive must fail cleanly, never write out of bounds.

fuzz.py and malformed_tests.py cover reading. This test damages a folder's
records the way a broken or hostile drive could and then asks the writer to
add a folder there, with the sanitizer build of ntfstool:

  alloc    the MFT record claims 0x8000 allocated bytes (the record is 1 KiB);
           index root growth then moved bytes past the record buffer
  entry    the first index root entry is a 16-byte entry without a key;
           the name comparison read 0x40+ bytes past it
  bitmap   the resident index bitmap's value offset is 0xFFF8; the free
           block search read (and a split would write) 64 KiB away
  root     the index root's entries claim to end 64 KiB past the value
           (the reader's index walk, which runs first, already refuses this
           one; the writer now checks it itself as well)

Each must end with an error and no sanitizer report.

Needs mkntfs. usage: corrupt_write_tests.py build/ntfstool-asan
"""
import os, shutil, struct, subprocess, sys, tempfile

TOOL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfstool-asan")
WORK = tempfile.mkdtemp(prefix="ntfsb-corrupt-")
failures = []


def check(name, cond, detail=""):
    print("%-44s %s %s" % (name, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        failures.append(name)


def tool(*args):
    try:
        r = subprocess.run([TOOL] + list(args), capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return None, "timed out"


def fresh(name, folders):
    img = os.path.join(WORK, name + ".img")
    with open(img, "wb") as f:
        f.truncate(16 << 20)
    subprocess.run(["mkntfs", "-F", "-Q", "-q", "-c", "4096", img], check=True, capture_output=True)
    for p in folders:
        rc, out = tool("mkdir", img, p)
        assert rc == 0, out
    return img


def find_dir_record(img, dname):
    """MFT record (offset, size, fixed-up bytes) of a folder below the root."""
    with open(img, "rb") as f:
        bs = f.read(512)
        cluster = struct.unpack_from("<H", bs, 0x0B)[0] * bs[0x0D]
        cpr = struct.unpack_from("<b", bs, 0x40)[0]
        rs = cpr * cluster if cpr > 0 else 1 << -cpr
        base = struct.unpack_from("<Q", bs, 0x30)[0] * cluster
        for ino in range(64, 512):
            f.seek(base + ino * rs)
            raw = bytearray(f.read(rs))
            if raw[:4] != b"FILE":
                continue
            ofs, cnt = struct.unpack_from("<HH", raw, 4)
            for i in range(1, cnt):
                raw[i * 512 - 2:i * 512] = raw[ofs + i * 2:ofs + i * 2 + 2]
            p = struct.unpack_from("<H", raw, 0x14)[0]
            while p + 8 <= rs:
                t, l = struct.unpack_from("<II", raw, p)
                if t == 0xFFFFFFFF or l == 0:
                    break
                if t == 0x30 and raw[p + 8] == 0:
                    fn = raw[p + struct.unpack_from("<H", raw, p + 20)[0]:]
                    name = fn[0x42:0x42 + 2 * fn[0x40]].decode("utf-16le")
                    if struct.unpack_from("<Q", fn, 0)[0] & 0xFFFFFFFFFFFF == 5 and name == dname:
                        return base + ino * rs, rs, raw
                p += l
    raise SystemExit("folder %s not found" % dname)


def attr(raw, atype):
    p = struct.unpack_from("<H", raw, 0x14)[0]
    while True:
        t, l = struct.unpack_from("<II", raw, p)
        if t == 0xFFFFFFFF:
            raise SystemExit("attribute %#x not found" % atype)
        if t == atype and raw[p + 8] == 0:
            return p
        p += l


def patch(img, off, pos, data):
    for k in range(len(data)):
        assert (pos + k) % 512 not in (510, 511), "patch hits a fixup slot"
    with open(img, "r+b") as f:
        f.seek(off + pos)
        f.write(data)


def case(name, folder, setup, damage):
    img = fresh(name, setup)
    off, rs, raw = find_dir_record(img, folder)
    damage(img, off, raw)
    for i in range(12):   # a few names, so a growing root reaches the damage
        rc, out = tool("mkdir", img, "/%s/%s%02d" % (folder, "N" * 100, i))
        bad = "Sanitizer" in out or "runtime error" in out or rc is None or (rc is not None and rc < 0)
        if bad or rc != 0:
            break
    check("%-7s fails cleanly" % name, not bad and rc != 0,
          "rc=%s %s" % (rc, out.strip().splitlines()[-1][:120] if out.strip() else ""))


def dmg_alloc(img, off, raw):
    patch(img, off, 0x1C, struct.pack("<I", 0x8000))


def dmg_entry(img, off, raw):
    p = attr(raw, 0x90)
    h = p + struct.unpack_from("<H", raw, p + 20)[0] + 0x10
    e = h + struct.unpack_from("<I", raw, h)[0]
    patch(img, off, e + 8, struct.pack("<HHH", 16, 0, 0))
    patch(img, off, e + 16, struct.pack("<QHHHH", 0, 16, 0, 2, 0))


def dmg_bitmap(img, off, raw):
    p = attr(raw, 0xB0)
    patch(img, off, p + 20, struct.pack("<H", 0xFFF8))


def dmg_root(img, off, raw):
    p = attr(raw, 0x90)
    h = p + struct.unpack_from("<H", raw, p + 20)[0] + 0x10
    patch(img, off, h + 4, struct.pack("<I", 0x10000))


def main():
    try:
        case("alloc", "d", ["/d", "/d/x"], dmg_alloc)
        case("entry", "e", ["/e", "/e/a"], dmg_entry)
        case("bitmap", "g", ["/g"] + ["/g/%s%d" % ("D" * 100, i) for i in range(1, 13)], dmg_bitmap)
        case("root", "r", ["/r", "/r/a"], dmg_root)
        # An undamaged drive still works.
        img = fresh("clean", ["/c"])
        rc, out = tool("mkdir", img, "/c/" + "N" * 100)
        check("undamaged drive still writable", rc == 0, out[-200:])
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
    print("\n%s" % ("ALL PASSED" if not failures else "FAILED: " + ", ".join(failures)))
    sys.exit(1 if failures else 0)


main()
