#!/usr/bin/env python3
"""Damaged drives must not make the reader use memory or time out of all
proportion to what is on them.

Three hand-made cases, each changing a few fields of an ntfs-3g-made image:
- an $ATTRIBUTE_LIST that names the same $DATA segment 64K times: every
  entry appended the segment's runs again (hundreds of MB from 2 MB); also
  with the segment claiming highest VCN -1, so highest + 1 wraps to 0;
- a folder index whose blocks all point at the next block from every entry:
  a chain of five blocks was walked about 30^4 times (max_visits comes from
  the index size the drive claims, which was raised too);
- a boot sector claiming 2^44 sectors plus a $Bitmap with a huge sparse
  tail: counting free space walked a 256 GiB bitmap.

Each case runs the plain build of ntfstool with a 1 GiB address-space limit
and a time limit, and must end quickly, within 100 MB, with an error or a
correct result. A real fragmented file whose $DATA spans extension records
through an attribute list must still read back exactly.

Needs root (mkntfs, ntfs-3g). usage: reader_limits_tests.py build/ntfstool
"""
import os, random, resource, shutil, struct, subprocess, sys, tempfile, time

TOOL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfstool")
WORK = tempfile.mkdtemp(prefix="ntfslim-")
BASE = os.path.join(WORK, "base.img")
MNT = os.path.join(WORK, "mnt")
CS = 4096                      # cluster size of the test image
NFRAG = 600                    # data islands of the fragmented file
MEM_CAP = 1 << 30              # address-space limit for every run
TIME_CAP = 20                  # seconds
RSS_OK = 100 << 20             # what a damaged drive may cost at most
failures = []
AT_LIST, AT_DATA, AT_ROOT, AT_ALLOC, AT_END = 0x20, 0x80, 0x90, 0xA0, 0xFFFFFFFF


def sh(*a):
    subprocess.run(a, check=True, capture_output=True)


def frag_content():
    r = random.Random(11)
    return [r.randbytes(CS) for _ in range(NFRAG)]


def build_base():
    with open(BASE, "wb") as f:
        f.truncate(64 << 20)
    sh("mkntfs", "-F", "-Q", "-c", str(CS), BASE)
    os.makedirs(MNT)
    sh("ntfs-3g", BASE, MNT)
    try:
        d = os.path.join(MNT, "dir")
        os.makedirs(d)
        for i in range(250):
            with open(os.path.join(d, "file_%03d_%s.txt" % (i, "x" * 80)), "w") as f:
                f.write("%d\n" % i)
        os.makedirs(os.path.join(MNT, "frag"))
        # Data islands separated by holes: hundreds of runs, a $DATA split
        # over extension records and an attribute list (legitimately).
        with open(os.path.join(MNT, "frag", "a.bin"), "wb") as f:
            for i, blk in enumerate(frag_content()):
                f.seek(2 * i * CS)
                f.write(blk)
    finally:
        sh("umount", MNT)


class Image:
    """Read and patch MFT records and raw bytes of an NTFS image."""

    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = bytearray(f.read())
        d = self.data
        self.cluster = struct.unpack_from("<H", d, 11)[0] * d[13]
        self.mft = struct.unpack_from("<Q", d, 0x30)[0] * self.cluster
        c = struct.unpack_from("<b", d, 0x40)[0]
        self.rec_size = c * self.cluster if c > 0 else 1 << -c

    def read(self, n):
        o = self.mft + n * self.rec_size
        rec = bytearray(self.data[o:o + self.rec_size])
        if rec[:4] != b"FILE":
            return None
        ofs, cnt = struct.unpack_from("<HH", rec, 4)
        for i in range(1, cnt):
            rec[i * 512 - 2:i * 512] = rec[ofs + 2 * i:ofs + 2 * i + 2]
        return rec

    def write(self, n, rec):
        protect(rec)
        o = self.mft + n * self.rec_size
        self.data[o:o + self.rec_size] = rec

    @staticmethod
    def attrs(rec):
        p = struct.unpack_from("<H", rec, 0x14)[0]
        out = []
        while struct.unpack_from("<I", rec, p)[0] != AT_END:
            ln = struct.unpack_from("<I", rec, p + 4)[0]
            out.append((p, struct.unpack_from("<I", rec, p)[0], ln))
            p += ln
        return out

    def find(self, name, parent=None):
        want = name.encode("utf-16-le")
        for n in range(16, 2000):
            rec = self.read(n)
            if rec is None or not (struct.unpack_from("<H", rec, 0x16)[0] & 1):
                continue
            for p, t, ln in self.attrs(rec):
                if t == 0x30:
                    v = p + struct.unpack_from("<H", rec, p + 20)[0]
                    if bytes(rec[v + 66:v + 66 + 2 * rec[v + 64]]) == want:
                        base = struct.unpack_from("<Q", rec, 0x20)[0] & 0xFFFFFFFFFFFF
                        return base or n          # the name may sit in an extension record
        raise SystemExit("record for %s not found" % name)

    def save(self, path):
        with open(path, "wb") as f:
            f.write(self.data)


def protect(buf):
    """Re-apply the update sequence: last two bytes of each sector go to the USA."""
    ofs, cnt = struct.unpack_from("<HH", buf, 4)
    usn = (struct.unpack_from("<H", buf, ofs)[0] + 1) & 0xFFFF or 1
    struct.pack_into("<H", buf, ofs, usn)
    for i in range(1, cnt):
        buf[ofs + 2 * i:ofs + 2 * i + 2] = buf[i * 512 - 2:i * 512]
        struct.pack_into("<H", buf, i * 512 - 2, usn)


def runs_of(rec, p):
    """Decode a non-resident attribute's run list -> [(vcn, lcn or None, len)]."""
    mp = p + struct.unpack_from("<H", rec, p + 32)[0]
    out, vcn, lcn = [], 0, 0
    while rec[mp]:
        h = rec[mp]
        ls, os_ = h & 15, h >> 4
        ln = int.from_bytes(rec[mp + 1:mp + 1 + ls], "little")
        if os_:
            lcn += int.from_bytes(rec[mp + 1 + ls:mp + 1 + ls + os_], "little", signed=True)
            out.append((vcn, lcn, ln))
        else:
            out.append((vcn, None, ln))
        vcn += ln
        mp += 1 + ls + os_
    return out, mp


def attr_value(im, rec, p):
    """An attribute's value, resident or read through its run list."""
    if not rec[p + 8]:
        v = p + struct.unpack_from("<H", rec, p + 20)[0]
        return bytes(rec[v:v + struct.unpack_from("<I", rec, p + 16)[0]])
    size = struct.unpack_from("<Q", rec, p + 48)[0]
    out = bytearray()
    for vcn, lcn, ln in runs_of(rec, p)[0]:
        out += bytes(ln * im.cluster) if lcn is None else \
            im.data[lcn * im.cluster:(lcn + ln) * im.cluster]
    return bytes(out[:size])


def find_attr(im, n, atype):
    """(record number, record, offset) of the first attribute of a type of
    inode n, in its base record or in one of its extension records."""
    for m in [n] + list(range(16, 4000)):
        r = im.read(m)
        if r is None:
            continue
        if m != n and struct.unpack_from("<Q", r, 0x20)[0] & 0xFFFFFFFFFFFF != n:
            continue
        for p, t, ln in im.attrs(r):
            if t == atype and (atype != AT_ALLOC or not struct.unpack_from("<Q", r, p + 16)[0]):
                return m, r, p
    raise SystemExit("attribute %#x of record %d not found" % (atype, n))


def replace_attr(rec, p, new):
    """Swap the attribute at p for `new` (8-aligned), moving what follows."""
    old_len = struct.unpack_from("<I", rec, p + 4)[0]
    used = struct.unpack_from("<I", rec, 0x18)[0]
    tail = bytes(rec[p + old_len:used])
    end = p + len(new) + len(tail)
    assert end <= len(rec), "record too small"
    rec[p:p + len(new)] = new
    rec[p + len(new):end] = tail
    rec[end:used] = bytes(max(0, used - end))
    struct.pack_into("<I", rec, 0x18, end)


def free_clusters_at_end(im, n):
    """A cluster range near the end of the volume, assumed free (ntfs-3g allocates low)."""
    total = len(im.data) // im.cluster
    return total - n - 16


def run(img, *args):
    """-> (status, peak RSS bytes of this run, seconds, output tail)"""
    def limits():
        resource.setrlimit(resource.RLIMIT_AS, (MEM_CAP, MEM_CAP))
    out_path = os.path.join(WORK, "run.out")
    t0 = time.time()
    with open(out_path, "wb") as out:
        p = subprocess.Popen([TOOL, args[0], img] + list(args[1:]), stdout=out,
                             stderr=subprocess.STDOUT, preexec_fn=limits)
        status, peak = None, 0
        while status is None:
            pid, st, ru = os.wait4(p.pid, os.WNOHANG)
            if pid:
                peak = ru.ru_maxrss * 1024
                status = "crash" if os.WIFSIGNALED(st) else "ok"
            elif time.time() - t0 > TIME_CAP:
                p.kill()
                _, st, ru = os.wait4(p.pid, 0)
                peak, status = ru.ru_maxrss * 1024, "HANG"
            else:
                time.sleep(0.05)
        p.returncode = 0  # reaped above
    with open(out_path, "rb") as f:
        f.seek(max(0, os.path.getsize(out_path) - 300))
        tail = f.read().decode(errors="replace")
    return status, peak, time.time() - t0, tail


def check(name, cond, detail=""):
    print("%-56s %s %s" % (name, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        failures.append(name)


def bounded(name, img, *cmd):
    status, peak, secs, out = run(img, *cmd)
    check(name, status == "ok" and peak < RSS_OK,
          "%s, peak %d MB, %.1f s %s" % (status, peak >> 20, secs, out.strip()[-160:]))


# 1. $ATTRIBUTE_LIST naming the same $DATA segment 64K times. With wrap, the
#    segment also claims highest VCN 0xFFFFFFFFFFFFFFFF (as an empty attribute
#    does), so "highest + 1" wraps to 0 and can't serve as the progress check.
def case_attrlist(wrap=False):
    im = Image(BASE)
    n = im.find("a.bin")
    rec = im.read(n)
    lp = [a for a in im.attrs(rec) if a[1] == AT_LIST][0][0]
    lst = attr_value(im, rec, lp)
    first = None                                  # the $DATA entry with lowest VCN 0
    q = 0
    while q + 26 <= len(lst):
        ln = struct.unpack_from("<H", lst, q + 4)[0]
        if ln < 26:
            break
        if struct.unpack_from("<I", lst, q)[0] == AT_DATA and \
                struct.unpack_from("<Q", lst, q + 8)[0] == 0:
            first = bytes(lst[q:q + ln])
            break
        q += ln
    assert first, "no $DATA entry at VCN 0"
    if wrap:
        sref = struct.unpack_from("<Q", first, 16)[0] & 0xFFFFFFFFFFFF
        inst = struct.unpack_from("<H", first, 24)[0]
        srec = rec if sref == n else im.read(sref)
        sp = [p for p, t, ln in im.attrs(srec) if t == AT_DATA and
              struct.unpack_from("<H", srec, p + 14)[0] == inst][0]
        struct.pack_into("<Q", srec, sp + 24, 0xFFFFFFFFFFFFFFFF)
        if sref != n:
            im.write(sref, srec)
    entry = first.ljust(32, b"\0")[:32]
    entry = entry[:4] + struct.pack("<H", 32) + entry[6:]
    count = 65536
    listdata = entry * count                      # 2 MiB
    ncl = len(listdata) // im.cluster
    lcn = free_clusters_at_end(im, ncl)
    im.data[lcn * im.cluster:lcn * im.cluster + len(listdata)] = listdata
    # Non-resident $ATTRIBUTE_LIST: one run of ncl clusters at lcn.
    runl = bytes([0x22]) + struct.pack("<H", ncl) + struct.pack("<H", lcn) + b"\0"
    a = bytearray(0x40 + 8)
    struct.pack_into("<IIBBHHH", a, 0, AT_LIST, len(a), 1, 0, 0x40, 0,
                     struct.unpack_from("<H", rec, lp + 14)[0])
    struct.pack_into("<QQHH", a, 16, 0, ncl - 1, 0x40, 0)
    struct.pack_into("<QQQ", a, 40, ncl * im.cluster, len(listdata), len(listdata))
    a[0x40:0x40 + len(runl)] = runl
    replace_attr(rec, lp, a)
    im.write(n, rec)
    path = os.path.join(WORK, "attrlist%s.img" % ("-wrap" if wrap else ""))
    im.save(path)
    bounded("attribute list repeating one segment 64K times" +
            (", highest VCN -1" if wrap else ""), path, "cat", "/frag/a.bin")


# 2. Index blocks chained so that every entry points at the next block.
def case_index_chain():
    im = Image(BASE)
    n = im.find("dir")
    base = im.read(n)
    # A big folder may keep $INDEX_ROOT in an extension record.
    an, arec, ap = find_attr(im, n, AT_ALLOC)
    rn, rrec, rp = find_attr(im, n, AT_ROOT)
    if rn == an:
        rrec = arec
    runs, _ = runs_of(arec, ap)
    bs = 4096
    blocks = []                                   # physical offsets of VCN 0..4
    for vcn in range(5):
        r = [x for x in runs if x[0] <= vcn < x[0] + x[2] and x[1] is not None][0]
        blocks.append((r[1] + vcn - r[0]) * im.cluster)
    ref = n | struct.unpack_from("<H", base, 0x10)[0] << 48  # the folder itself
    key = bytearray(0x42 + 6)
    struct.pack_into("<Q", key, 0, 5)
    key[0x40] = 3
    key[0x42:] = "aaa".encode("utf-16-le")

    def entry(child, last=False):
        e = bytearray(16 + (0 if last else len(key))) + bytearray(8)
        struct.pack_into("<QHHH", e, 0, ref, len(e), 0 if last else len(key), 3 if last else 1)
        if not last:
            e[16:16 + len(key)] = key
        struct.pack_into("<Q", e, len(e) - 8, child)
        return e

    for i, off in enumerate(blocks):
        b = bytearray(bs)
        b[0:4] = b"INDX"
        struct.pack_into("<HH", b, 4, 0x28, bs // 512 + 1)
        struct.pack_into("<Q", b, 0x10, i)
        if i < 4:
            body = b"".join(entry(i + 1) for _ in range(30)) + entry(i + 1, last=True)
            flags = 1
        else:
            body = bytearray()
            for _ in range(30):
                e = bytearray(16 + len(key))
                struct.pack_into("<QHHH", e, 0, ref, len(e), len(key), 0)
                e[16:] = key
                body += e
            body += struct.pack("<QHHHH", 0, 16, 0, 2, 0)
            flags = 0
        struct.pack_into("<IIII", b, 0x18, 0x28, 0x28 + len(body), bs - 0x18, flags)
        b[0x40:0x40 + len(body)] = body
        protect(b)
        im.data[off:off + bs] = b
    # Root: just an END entry pointing at VCN 0.
    rv = rp + struct.unpack_from("<H", rrec, rp + 20)[0]
    end = entry(0, last=True)
    struct.pack_into("<IIII", rrec, rv + 16, 0x10, 0x10 + len(end), 0x10 + len(end), 1)
    rrec[rv + 32:rv + 32 + len(end)] = end
    # Claim a 16 GiB index so the old max_visits allows the whole walk.
    struct.pack_into("<QQQ", arec, ap + 40, 16 << 30, 16 << 30, 16 << 30)
    im.write(an, arec)
    if rn != an:
        im.write(rn, rrec)
    path = os.path.join(WORK, "chain.img")
    im.save(path)
    bounded("index blocks chained 30 ways, five deep (ls)", path, "ls", "/dir")


# 3. 2^44 sectors in the boot sector, $Bitmap with a huge sparse tail.
def case_free_scan():
    im = Image(BASE)
    struct.pack_into("<Q", im.data, 0x28, 1 << 44)
    rec = im.read(6)                              # $Bitmap
    dp = [p for p, t, ln in im.attrs(rec) if t == AT_DATA][0]
    runs, mp_end = runs_of(rec, dp)
    old = runs[-1][0] + runs[-1][2]
    extra = 1 << 26                               # clusters of zeros: 2^38 bytes of bitmap
    new = bytearray(rec[dp:mp_end]) + bytes([0x04]) + struct.pack("<I", extra) + b"\0"
    new += bytes(-len(new) % 8)
    struct.pack_into("<I", new, 4, len(new))
    struct.pack_into("<Q", new, 24, old + extra - 1)
    size = (old + extra) * im.cluster
    struct.pack_into("<QQQ", new, 40, size, size, size)
    replace_attr(rec, dp, new)
    im.write(6, rec)
    path = os.path.join(WORK, "freescan.img")
    im.save(path)
    bounded("2^44 sectors and a 256 GiB sparse $Bitmap (info)", path, "info")


def main():
    build_base()
    r = subprocess.run([TOOL, "cat", BASE, "/frag/a.bin"], capture_output=True)
    want = b"".join(blk + bytes(CS) for blk in frag_content())[:-CS]
    check("fragmented file with an attribute list reads back", r.stdout == want,
          "got %d bytes, want %d" % (len(r.stdout), len(want)))
    r = subprocess.run([TOOL, "ls", BASE, "/dir"], capture_output=True, text=True)
    check("untouched folder lists 250 files", r.stdout.count("file_") == 250,
          "%d" % r.stdout.count("file_"))
    case_attrlist()
    case_attrlist(wrap=True)
    case_index_chain()
    case_free_scan()
    if failures:
        print("\nFAILED: " + ", ".join(failures))
        sys.exit(1)
    print("\nAll reader limit tests passed.")
    shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
