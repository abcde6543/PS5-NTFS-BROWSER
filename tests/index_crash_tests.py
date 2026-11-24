#!/usr/bin/env python3
"""Crash tests for folder index updates.

Adding or removing a name can rewrite several index blocks of a folder (a
block splits, two blocks merge, an entry is borrowed from a neighbour). If
the drive is unplugged between two of those writes, the folder must still
list every name it had: a duplicate entry or a leaked index block is fine
(chkdsk tidies those up), a vanished name is not.

An LD_PRELOAD shim (compiled here) counts the tool's device writes and can
end the process with _exit() right after write K. Each operation is first
run to the end to count its writes (N); then, for every K in 1..N, a fresh
copy of the image gets the same operation cut off after write K, and the
result is judged by ntfs-3g (list the folder, look up every name), our own
reader (ntfstool ls) and ntfsfix -n.

Operations come from walks over folders built by ntfs-3g: names added one
after another into one stretch of a folder (leaf splits, then the parent
splits too), and names removed in random, ascending and descending order.
An operation is crash-tested when it changes more than one index node, or
a block and the root: splits, merges into either neighbour, borrowing from
a full neighbour, an inner entry replaced from a leaf, the root shrinking.

Needs: root, /dev/fuse, ntfs-3g, ntfsfix, cc. Usage:
  tests/index_crash_tests.py build/ntfstool
(the plain build: the shim cannot be preloaded into the ASan one)
"""
import os
import random
import shutil
import subprocess
import sys
import tempfile

TOOL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfstool")
WORK = tempfile.mkdtemp(prefix="ntfscrash-")
MNT = os.path.join(WORK, "mnt")
os.makedirs(MNT)
SHIM = os.path.join(WORK, "crash.so")
failures = []
stats = {"ops": 0, "points": 0, "bad": 0}

SHIM_SRC = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static long writes, crash_after = -1;
static int logfd = -1;

static void note(const void *buf, size_t len, long long off) {
  if (crash_after < 0) {
    const char *s = getenv("CRASH_AFTER");
    crash_after = s ? atol(s) : 0;
    if ((s = getenv("CRASH_LOG"))) logfd = open(s, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  }
  writes++;
  if (logfd >= 0) {
    const char *kind = len >= 4 && !memcmp(buf, "INDX", 4) ? "INDX"
                     : len >= 4 && !memcmp(buf, "FILE", 4) ? "FILE" : "DATA";
    char line[96];
    int n = snprintf(line, sizeof line, "%s %lld %zu\n", kind, off, len);
    if (write(logfd, line, (size_t)n) < 0) _exit(98);
  }
  if (crash_after > 0 && writes >= crash_after) _exit(99);
}

#define WRAP(name, offt)                                                    \
  ssize_t name(int fd, const void *buf, size_t len, offt off) {             \
    static ssize_t (*real)(int, const void *, size_t, offt);                \
    if (!real) real = (ssize_t (*)(int, const void *, size_t, offt))dlsym(RTLD_NEXT, #name); \
    ssize_t r = real(fd, buf, len, off);                                    \
    if (r > 0) note(buf, (size_t)r, (long long)off);                        \
    return r;                                                               \
  }
WRAP(pwrite, off_t)
WRAP(pwrite64, off64_t)
"""


def sh(*a, check=True):
    return subprocess.run(a, check=check, capture_output=True)


def mkimage(name, mb):
    p = os.path.join(WORK, name)
    with open(p, "wb") as f:
        f.truncate(mb << 20)
    sh("mkntfs", "-F", "-Q", "-c", "4096", "-L", "C", p)
    return p


def copy(src, dst):
    shutil.copyfile(src, dst)
    return dst


def run(img, cmd, crash_after=0):
    """Run ntfstool <cmd> on img; returns (exit code, list of writes)."""
    log = os.path.join(WORK, "writes.log")
    env = dict(os.environ, LD_PRELOAD=SHIM, CRASH_AFTER=str(crash_after), CRASH_LOG=log)
    r = subprocess.run([TOOL, cmd[0], img] + cmd[1:], capture_output=True, text=True, env=env)
    with open(log) as f:
        writes = [ln.split() for ln in f.read().splitlines()]
    return r.returncode, writes, r.stderr.strip()


def listing(img, folder):
    """Names our reader lists (None if it fails)."""
    r = subprocess.run([TOOL, "ls", img, folder], capture_output=True, text=True)
    if r.returncode:
        return None
    return [ln.split(None, 3)[3] for ln in r.stdout.splitlines() if ln.strip()]


def norm(chunk):
    """What a record or index block holds, without the update sequence
    numbers (new on every write) and, for index blocks, without the unused
    space and header details a rewrite of the same entries may change."""
    b = bytearray(chunk)
    if b[:4] not in (b"FILE", b"INDX") or len(b) < 8:
        return bytes(b)
    ofs, cnt = int.from_bytes(b[4:6], "little"), int.from_bytes(b[6:8], "little")
    if ofs + 2 * cnt > len(b) or cnt * 512 > len(b) + 512:
        return bytes(b)
    for i in range(1, cnt):
        b[i * 512 - 2:i * 512] = b[ofs + 2 * i:ofs + 2 * i + 2]
    b[ofs:ofs + 2 * cnt] = bytes(2 * cnt)
    if b[:4] == b"INDX":
        eo, il = int.from_bytes(b[0x18:0x1C], "little"), int.from_bytes(b[0x1C:0x20], "little")
        return bytes(b[0x10:0x18]) + bytes(b[0x24:0x25]) + bytes(b[0x18 + eo:0x18 + il])
    return bytes(b)


def changed_nodes(a, b):
    """Index blocks (4 KiB) and MFT records whose content differs."""
    indx = recs = 0
    with open(a, "rb") as fa, open(b, "rb") as fb:
        while True:
            x, y = fa.read(1 << 20), fb.read(1 << 20)
            if not x and not y:
                break
            if x == y:
                continue
            for o in range(0, max(len(x), len(y)), 4096):
                cx, cy = x[o:o + 4096], y[o:o + 4096]
                if cx == cy:
                    continue
                if cx[:4] == b"INDX" or cy[:4] == b"INDX":
                    indx += norm(cx) != norm(cy)
                    continue
                for r in range(0, 4096, 1024):
                    rx, ry = cx[r:r + 1024], cy[r:r + 1024]
                    if (rx[:4] == b"FILE" or ry[:4] == b"FILE") and norm(rx) != norm(ry):
                        recs += 1
    return indx, recs


def judge(img, folder, names):
    """Names (from `names`) that are lost, plus other problems."""
    lost, problems = set(), []
    ours = listing(img, folder)
    if ours is None:
        problems.append("ntfstool ls failed")
    else:
        lost |= set(names) - set(ours)
    r = sh("ntfsfix", "-n", img, check=False)
    if r.returncode:
        out = (r.stdout + r.stderr).decode(errors="replace").strip().splitlines()
        problems.append("ntfsfix -n: " + " | ".join(out[-2:]))
    if sh("ntfs-3g", "-o", "ro", img, MNT, check=False).returncode:
        problems.append("ntfs-3g cannot mount")
        return lost, problems
    try:
        top = os.path.join(MNT, folder.strip("/"))
        try:
            seen = set(os.listdir(top))
        except OSError as e:
            problems.append("ntfs-3g listdir: %s" % e)
            seen = set()
        lost |= set(names) - seen
        for n in names:
            if n in lost:
                continue
            try:
                os.stat(os.path.join(top, n))  # lookup through the B-tree
            except OSError:
                lost.add(n)
    finally:
        sh("umount", MNT)
    return lost, problems


def crash_test(label, base, folder, cmd, names):
    """Cut the operation off after every one of its writes."""
    trial = os.path.join(WORK, "trial.img")
    rc, writes, err = run(copy(base, trial), cmd)
    if rc:
        failures.append(label)
        print("%-58s FAIL (setup: %s)" % (label, err[:200]))
        return
    n = len(writes)
    bad = []
    for k in range(1, n + 1):
        run(copy(base, trial), cmd, k)
        lost, problems = judge(trial, folder, names)
        if lost or problems:
            bad.append((k, writes[k - 1][0], sorted(lost), problems))
    stats["ops"] += 1
    stats["points"] += n
    stats["bad"] += len(bad)
    print("%-58s %s (%d crash points%s)" % (label, "FAIL" if bad else "PASS", n,
                                             ", %d lose names" % len(bad) if bad else ""))
    for k, kind, lost, problems in bad[:6]:
        what = ("lost %d: %s" % (len(lost), ", ".join(x[:12] + "..." for x in lost[:4]))) if lost else ""
        print("   after write %d/%d (%s): %s %s" % (k, n, kind, what, "; ".join(problems)))
    if bad:
        failures.append(label)


def build_folder(names, seed):
    """An image whose /d holds the names (empty files), created by ntfs-3g
    in random order. The MFT gets spare records first, so the operations
    under test never have to grow it."""
    img = mkimage("base.img", 32)
    order = list(names)
    random.Random(seed).shuffle(order)
    sh("ntfs-3g", img, MNT)
    try:
        d = os.path.join(MNT, "d")
        os.makedirs(d)
        for n in order:
            open(os.path.join(d, n), "w").close()
        pad = os.path.join(MNT, "pad")
        os.makedirs(pad)
        for i in range(500):
            open(os.path.join(pad, str(i)), "w").close()
        shutil.rmtree(pad)
    finally:
        sh("umount", MNT)
    return img


def long_name(i):
    return "n%04d_" % i + "x" * 84


def short_name(i):
    return "s%04d" % i


def s_insert(label, names, extra, limit):
    """Insert names one by one into the same stretch of the folder, so a
    leaf splits again and again until its parent splits as well. Every
    insert that rewrites more than one index node in a way not seen yet
    gets crash-tested."""
    img = build_folder(names, len(names))
    anchor = sorted(names)[len(names) // 3]
    cur = copy(img, os.path.join(WORK, "cur.img"))
    nxt = os.path.join(WORK, "next.img")
    live = set(names)
    seen = set()
    for j in range(extra):
        new = (anchor + "_new%03d_" % j + "y" * 140)[:240]
        cmd = ["mkdir", "/d/" + new]
        rc, writes, err = run(copy(cur, nxt), cmd)
        if rc:
            failures.append(label)
            print("%-58s FAIL (mkdir: %s)" % (label, err[:200]))
            return
        blocks, recs = changed_nodes(cur, nxt)
        if blocks >= 2 and (blocks, recs) not in seen:
            seen.add((blocks, recs))
            crash_test("%s: add #%d, %d blocks + %d records change" % (label, j + 1, blocks, recs),
                       cur, "/d", cmd, sorted(live))
            if len(seen) >= limit:
                break
        live.add(new)
        os.replace(nxt, cur)
    if not seen:
        failures.append(label)
        print("%-58s FAIL (no insert split a block)" % label)


def s_remove(label, names, walk, limit, steps=None):
    """Remove names one by one (random, ascending or descending order);
    crash-test removals that move entries between index nodes or change
    the root as well as a block, at most two of each kind. Ascending and
    descending walks empty leaves next to untouched neighbours, which is
    where merges into the right or left neighbour and borrowing from a full
    neighbour happen."""
    count = len(names)
    img = build_folder(names, count + 1)
    order = sorted(names, reverse=walk == "descending")
    if walk == "random":
        random.Random(5).shuffle(order)
    cur = os.path.join(WORK, "cur.img")
    nxt = os.path.join(WORK, "next.img")
    copy(img, cur)
    live = set(names)
    seen = {}
    for n in order[:steps]:
        live.discard(n)
        cmd = ["rm", "/d/" + n]
        rc, writes, err = run(copy(cur, nxt), cmd)
        if rc:
            failures.append(label)
            print("%-58s FAIL (rm %s: %s)" % (label, n[:12], err[:200]))
            return
        blocks, recs = changed_nodes(cur, nxt)
        if (blocks >= 2 or (blocks >= 1 and recs >= 2)) and seen.get((blocks, recs), 0) < 2:
            seen[(blocks, recs)] = seen.get((blocks, recs), 0) + 1
            crash_test("%s: rm #%d, %d blocks + %d records change" %
                       (label, count - len(live), blocks, recs), cur, "/d", cmd, sorted(live))
            if sum(seen.values()) >= limit:
                break
        os.replace(nxt, cur)


def scenario(name, fn, *a):
    try:
        fn(name, *a)
    except Exception as e:  # noqa: BLE001
        print("%-58s FAIL (exception: %r)" % (name, e))
        failures.append(name)


def main():
    print("work dir:", WORK)
    src = os.path.join(WORK, "crash.c")
    with open(src, "w") as f:
        f.write(SHIM_SRC)
    sh("cc", "-shared", "-fPIC", "-O2", "-o", SHIM, src, "-ldl")
    scenario("add, short names", s_insert, [short_name(i) for i in range(150)], 300, 4)
    scenario("add, long names", s_insert, [long_name(i) for i in range(700)], 200, 4)
    scenario("remove, short names", s_remove, [short_name(i) for i in range(150)], "random", 10)
    scenario("remove, 60 long names", s_remove, [long_name(i) for i in range(60)], "random", 10)
    scenario("remove, 700 long names, ascending", s_remove,
             [long_name(i) for i in range(700)], "ascending", 10, 180)
    scenario("remove, 700 long names, descending", s_remove,
             [long_name(i) for i in range(700)], "descending", 10, 180)
    print()
    print("%d operations, %d crash points, %d lose names or break the volume" %
          (stats["ops"], stats["points"], stats["bad"]))
    if failures:
        print("FAILED:", ", ".join(failures))
        sys.exit(1)
    print("All index crash tests passed.")
    shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
