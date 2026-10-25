#!/usr/bin/env python3
"""End-to-end tests for the NTFS driver.

Builds NTFS images with mkntfs, fills them through ntfs-3g (FUSE) with the
awkward cases (huge directories, fragmentation, attribute lists, sparse and
compressed files, Unicode names, hard links...), then checks that our driver
lists exactly the same tree and returns byte-identical file contents.

Needs: root, /dev/fuse, ntfs-3g (mkntfs, ntfs-3g), setfattr.
Usage: tests/run_tests.py path/to/ntfstool
"""
import hashlib
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
import zlib

TOOL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfstool")
WORK = tempfile.mkdtemp(prefix="ntfstest-")
MNT = os.path.join(WORK, "mnt")
os.makedirs(MNT)
failures = []


def sh(*args, **kw):
    return subprocess.run(args, check=True, capture_output=True, **kw)


def mkimage(name, size_mb, cluster=4096, label="TestVol"):
    path = os.path.join(WORK, name)
    with open(path, "wb") as f:
        f.truncate(size_mb << 20)
    sh("mkntfs", "-F", "-Q", "-c", str(cluster), "-L", label, path)
    return path


class Mounted:
    def __init__(self, img, opts=""):
        self.img, self.opts = img, opts

    def __enter__(self):
        args = ["ntfs-3g", self.img, MNT]
        if self.opts:
            args[1:1] = ["-o", self.opts]
        sh(*args)
        return MNT

    def __exit__(self, *exc):
        sh("umount", MNT)


def rand_bytes(n, seed):
    r = random.Random(seed)
    return r.randbytes(n)


def compressible(n, seed):
    r = random.Random(seed)
    words = [b"alpha ", b"beta ", b"gamma ", b"delta ", b"PS5 ", b"NTFS\n"]
    out = bytearray()
    while len(out) < n:
        out += r.choice(words)
        if r.random() < 0.01:
            out += r.randbytes(r.randint(1, 64))
    return bytes(out[:n])


def ntfs_attrib(path, value):
    sh("setfattr", "-n", "system.ntfs_attrib_be", "-v", "0x%08x" % value, path)


# ---- Reference data from the FUSE mount ------------------------------------

def reference_tree(root):
    """(type, size, path) for every entry, plus a hash of every file."""
    entries, hashes = set(), {}
    for dirpath, dirnames, filenames in os.walk(root):
        rel = dirpath[len(root):]
        for d in dirnames:
            p = os.path.join(dirpath, d)
            if os.path.islink(p):
                entries.add(("f", None, rel + "/" + d))
            else:
                entries.add(("d", 0, rel + "/" + d))
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.islink(p):
                entries.add(("f", None, rel + "/" + fn))  # reparse point
                continue
            st = os.stat(p)
            entries.add(("f", st.st_size, rel + "/" + fn))
            with open(p, "rb") as f:
                hashes[rel + "/" + fn] = hashlib.sha256(f.read()).hexdigest()
    return entries, hashes


def our_tree(img):
    out = subprocess.run([TOOL, "tree", img], capture_output=True, check=True)
    entries = set()
    for line in out.stdout.decode().splitlines():
        t, size, path = line.split("\t", 2)
        entries.add((t, int(size), path))
    return entries


def our_cat(img, path):
    r = subprocess.run([TOOL, "cat", img, path], capture_output=True)
    if r.returncode:
        raise RuntimeError(r.stderr.decode().strip())
    return r.stdout


def check(name, img, ref_root_builder=None, opts=""):
    with Mounted(img, opts) as m:
        ref, hashes = reference_tree(m)
    ours = our_tree(img)
    # Symlinks are reparse points; their size differs between views.
    ref_cmp = {(t, s, p) for (t, s, p) in ref if s is not None}
    link_paths = {p for (t, s, p) in ref if s is None}
    ours_cmp = {e for e in ours if e[2] not in link_paths}
    hidden = {e for e in ours_cmp - ref_cmp if e[2].startswith(("/$", "/System Volume"))}
    missing, extra = ref_cmp - ours_cmp, ours_cmp - ref_cmp - hidden
    ok = not missing and not extra
    bad_hash = []
    for path, h in hashes.items():
        try:
            data = our_cat(img, path)
        except RuntimeError as e:
            bad_hash.append((path, str(e)))
            continue
        if hashlib.sha256(data).hexdigest() != h:
            bad_hash.append((path, "content differs (%d bytes)" % len(data)))
    ok = ok and not bad_hash
    print("%-34s %s  (%d entries, %d files hashed)" %
          (name, "PASS" if ok else "FAIL", len(ref_cmp), len(hashes)))
    if not ok:
        for e in sorted(missing)[:10]:
            print("   missing:", e)
        for e in sorted(extra)[:10]:
            print("   extra:  ", e)
        for e in bad_hash[:10]:
            print("   data:   ", e)
        failures.append(name)


# ---- Test volumes ----------------------------------------------------------

def populate_basic(m):
    open(os.path.join(m, "empty.bin"), "wb").close()
    with open(os.path.join(m, "tiny.txt"), "wb") as f:
        f.write(b"hello from NTFS\n")  # resident data
    with open(os.path.join(m, "one_cluster.bin"), "wb") as f:
        f.write(rand_bytes(4096, 1))
    with open(os.path.join(m, "odd_size.bin"), "wb") as f:
        f.write(rand_bytes(1_234_567, 2))
    os.makedirs(os.path.join(m, "a/b/c/d/e/f/g/h"))
    with open(os.path.join(m, "a/b/c/d/e/f/g/h/deep.txt"), "w") as f:
        f.write("deep\n")
    # Unicode, including characters outside the BMP (surrogate pairs).
    for n in ["Café crème.txt", "日本語のファイル.txt", "Ελληνικά", "emoji 🎮🕹️.txt",
              "spaces  and   tabs.txt", "#hash&amp;=?.txt", "ünïcödé"]:
        p = os.path.join(m, n)
        if "." in n:
            with open(p, "w") as f:
                f.write(n * 3)
        else:
            os.mkdir(p)
            with open(os.path.join(p, "inner.txt"), "w") as f:
                f.write("inside " + n)
    # Names that only differ in case (POSIX namespace).
    with open(os.path.join(m, "CaseTest.txt"), "w") as f:
        f.write("upper")
    with open(os.path.join(m, "casetest.txt"), "w") as f:
        f.write("lower")
    # Hard link and symlink.
    os.link(os.path.join(m, "tiny.txt"), os.path.join(m, "tiny_hardlink.txt"))
    os.symlink("tiny.txt", os.path.join(m, "tiny_symlink"))
    # Long name (255 UTF-16 units).
    with open(os.path.join(m, "L" * 251 + ".txt"), "w") as f:
        f.write("long")
    # Hidden + system file.
    p = os.path.join(m, "hidden.txt")
    with open(p, "w") as f:
        f.write("hidden")
    ntfs_attrib(p, 0x26)
    # Alternate data stream on a file (should not affect the main stream).
    with open(os.path.join(m, "ads.txt"), "w") as f:
        f.write("main stream")


def populate_bigdir(m, count=6000):
    d = os.path.join(m, "bigdir")
    os.mkdir(d)
    for i in range(count):
        with open(os.path.join(d, "file_%05d_%s.dat" % (i, "x" * (i % 40))), "wb") as f:
            f.write(str(i).encode() * (i % 7))


def populate_fragmented(m):
    # Fill the volume with small files, delete every other one, then write a
    # large file into the holes: thousands of runs and an attribute list.
    fill = os.path.join(m, "fill")
    os.mkdir(fill)
    chunk = rand_bytes(4096, 3)
    n = 0
    while n < 30000:
        try:
            with open(os.path.join(fill, "%d" % n), "wb") as f:
                f.write(chunk)
        except OSError:
            break
        n += 1
    for i in range(0, n, 2):
        os.unlink(os.path.join(fill, "%d" % i))
    with open(os.path.join(m, "fragmented.bin"), "wb") as f:
        f.write(rand_bytes(n // 2 * 4096 - 200_000, 4))


def populate_sparse(m):
    p = os.path.join(m, "sparse.bin")
    with open(p, "wb") as f:
        f.seek(50 << 20)
        f.write(b"middle of a sparse file")
        f.seek(120 << 20)
        f.write(rand_bytes(100_000, 5))
    p = os.path.join(m, "sparse_tail.bin")
    with open(p, "wb") as f:
        f.write(b"start")
        f.truncate(30 << 20)


def populate_compressed(m):
    d = os.path.join(m, "compressed")
    os.mkdir(d)
    ntfs_attrib(d, 0x810)  # directory + compressed: new files inherit it
    sizes = [10, 4095, 4096, 4097, 65535, 65536, 65537, 300_000, 3_000_000]
    for i, s in enumerate(sizes):
        with open(os.path.join(d, "text_%d.txt" % s), "wb") as f:
            f.write(compressible(s, 10 + i))
    # Incompressible data inside a compressed file (stored raw per unit).
    with open(os.path.join(d, "random.bin"), "wb") as f:
        f.write(rand_bytes(500_000, 6))
    # Mixed: compressible, random, zeros.
    with open(os.path.join(d, "mixed.bin"), "wb") as f:
        f.write(compressible(200_000, 7) + rand_bytes(200_000, 8) +
                b"\0" * 300_000 + compressible(77_777, 9))
    # Sparse hole inside a compressed file.
    with open(os.path.join(d, "comp_sparse.bin"), "wb") as f:
        f.write(compressible(100_000, 11))
        f.seek(5 << 20)
        f.write(compressible(100_000, 12))


def make_disk(name, part_imgs, scheme):
    """Wrap partition images in an MBR or GPT disk image."""
    path = os.path.join(WORK, name)
    lba = 2048
    layout = []
    for p in part_imgs:
        sectors = os.path.getsize(p) // 512
        layout.append((lba, sectors, p))
        lba += sectors + 2048
    total = lba + 2048
    with open(path, "wb") as f:
        f.truncate(total * 512)
        for start, sectors, p in layout:
            f.seek(start * 512)
            with open(p, "rb") as src:
                shutil.copyfileobj(src, f, 1 << 20)
        if scheme == "ext":
            # One extended partition holding a chain of logical partitions.
            ext_start = layout[0][0] - 63
            mbr = bytearray(512)
            mbr[446:462] = struct.pack("<B3sB3sII", 0, b"\0\0\0", 0x0F, b"\0\0\0",
                                       ext_start, total - ext_start - 1)
            mbr[510:512] = b"\x55\xaa"
            f.seek(0)
            f.write(mbr)
            for i, (start, sectors, _) in enumerate(layout):
                ebr_lba = start - 63
                ebr = bytearray(512)
                ebr[446:462] = struct.pack("<B3sB3sII", 0, b"\0\0\0", 0x07, b"\0\0\0", 63, sectors)
                if i + 1 < len(layout):
                    nxt = layout[i + 1][0] - 63
                    ebr[462:478] = struct.pack("<B3sB3sII", 0, b"\0\0\0", 0x05, b"\0\0\0",
                                               nxt - ext_start, layout[i + 1][1] + 63)
                ebr[510:512] = b"\x55\xaa"
                f.seek(ebr_lba * 512)
                f.write(ebr)
        elif scheme == "mbr":
            mbr = bytearray(512)
            for i, (start, sectors, _) in enumerate(layout):
                mbr[446 + i * 16: 462 + i * 16] = struct.pack(
                    "<B3sB3sII", 0, b"\0\0\0", 0x07, b"\0\0\0", start, sectors)
            mbr[510:512] = b"\x55\xaa"
            f.seek(0)
            f.write(mbr)
        else:
            entries = bytearray(128 * 128)
            ms_basic = uuid.UUID("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").bytes_le
            for i, (start, sectors, _) in enumerate(layout):
                entries[i * 128:(i + 1) * 128] = (
                    ms_basic + uuid.uuid4().bytes_le +
                    struct.pack("<QQQ", start, start + sectors - 1, 0) +
                    "Basic data".encode("utf-16le").ljust(72, b"\0"))
            hdr = bytearray(struct.pack(
                "<8sIIIIQQQQ16sQIII", b"EFI PART", 0x10000, 92, 0, 0, 1,
                total - 1, 34, total - 34, uuid.uuid4().bytes_le, 2, 128, 128,
                zlib.crc32(entries)))
            struct.pack_into("<I", hdr, 16, zlib.crc32(hdr))
            pmbr = bytearray(512)
            pmbr[446:462] = struct.pack("<B3sB3sII", 0, b"\0\0\0", 0xEE,
                                        b"\0\0\0", 1, min(total - 1, 0xFFFFFFFF))
            pmbr[510:512] = b"\x55\xaa"
            f.seek(0)
            f.write(pmbr)
            f.seek(512)
            f.write(hdr)
            f.seek(1024)
            f.write(entries)
    return path


def main():
    print("work dir:", WORK)

    img = mkimage("basic.img", 64)
    with Mounted(img) as m:
        populate_basic(m)
    with Mounted(img, "streams_interface=windows") as m:
        with open(os.path.join(m, "ads.txt:secret"), "w") as f:
            f.write("alternate stream data")
    check("basic / unicode / links", img)
    r = subprocess.run([TOOL, "cat", img, "/CAFÉ CRÈME.TXT"], capture_output=True)
    ok = r.returncode == 0 and r.stdout == ("Café crème.txt" * 3).encode()
    print("%-34s %s" % ("case-insensitive unicode lookup", "PASS" if ok else "FAIL"))
    if not ok:
        failures.append("case-insensitive lookup")
    r = subprocess.run([TOOL, "cat", img, "/CaseTest.txt"], capture_output=True)
    ok = r.stdout == b"upper"
    r = subprocess.run([TOOL, "cat", img, "/casetest.txt"], capture_output=True)
    ok = ok and r.stdout == b"lower"
    print("%-34s %s" % ("exact case preferred", "PASS" if ok else "FAIL"))
    if not ok:
        failures.append("exact case")
    r = subprocess.run([TOOL, "info", img], capture_output=True, text=True)
    info = dict(l.split("=", 1) for l in r.stdout.splitlines())
    with Mounted(img) as m:
        s = os.statvfs(m)
        ref_free = s.f_bfree * s.f_frsize
    ok = info.get("label") == "TestVol" and int(info["free"]) == ref_free
    print("%-34s %s  (free %s vs %d)" % ("volume info + free space",
          "PASS" if ok else "FAIL", info.get("free"), ref_free))
    if not ok:
        failures.append("volume info")

    img = mkimage("bigdir.img", 128)
    with Mounted(img) as m:
        populate_bigdir(m)
    check("6000-entry directory (B-tree)", img)

    img = mkimage("frag.img", 160)
    with Mounted(img) as m:
        populate_fragmented(m)
    check("fragmented file + $ATTRIBUTE_LIST", img)
    rec = subprocess.run(["ntfsinfo", "-v", "-F", "/fragmented.bin", img],
                         capture_output=True, text=True).stdout
    segs = rec.count("Dumping attribute $DATA")
    ok = "$ATTRIBUTE_LIST" in rec and segs > 1
    print("%-34s %s  (%d $DATA segments)" % ("  ...test really used a list",
          "PASS" if ok else "FAIL", segs))
    if not ok:
        failures.append("attribute list setup")

    img = mkimage("sparse.img", 64)
    with Mounted(img) as m:
        populate_sparse(m)
    check("sparse files", img)

    img = mkimage("comp.img", 96)
    with Mounted(img, "compression") as m:
        populate_compressed(m)
    check("LZNT1 compressed files", img, opts="compression")

    for cs in (512, 1024, 65536):
        img = mkimage("cs%d.img" % cs, 96, cluster=cs)
        with Mounted(img, "compression" if cs <= 4096 else "") as m:
            populate_basic(m)
            populate_bigdir(m, 1500)
            if cs <= 4096:
                populate_compressed(m)
        check("cluster size %d" % cs, img)

    p1 = mkimage("p1.img", 40, label="First")
    p2 = mkimage("p2.img", 40, label="Second")
    with Mounted(p2) as m:
        populate_basic(m)
    for scheme in ("mbr", "gpt", "ext"):
        disk = make_disk("disk_%s.img" % scheme, [p1, p2], scheme)
        # ntfstool opens the first NTFS partition: compare with p1.
        a = our_tree(disk)
        b = our_tree(p1)
        ok = a == b
        label = {"mbr": "MBR", "gpt": "GPT", "ext": "MBR logical (extended)"}[scheme]
        print("%-38s %s" % ("%s partition table" % label, "PASS" if ok else "FAIL"))
        if not ok:
            failures.append(scheme)

    print()
    if failures:
        print("FAILED:", ", ".join(failures))
        sys.exit(1)
    print("All tests passed.")
    shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
