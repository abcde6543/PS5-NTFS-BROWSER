#!/usr/bin/env python3
"""Stress tests for deleting from NTFS.

Every scenario deletes with our driver (via ntfstool rm/rmtree) and is then
judged by our structural checker (index B-tree shape, cluster and MFT
accounting, no leaked clusters), ntfsresize --check, and ntfs-3g, which must
read back every surviving file byte for byte and keep working on the volume.

Needs: root, /dev/fuse, ntfs-3g, setfattr. Usage: tests/delete_tests.py build/ntfstool
"""
import hashlib
import os
import random
import shutil
import subprocess
import sys
import tempfile

TOOL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfstool")
WORK = tempfile.mkdtemp(prefix="ntfsdel-")
MNT = os.path.join(WORK, "mnt")
os.makedirs(MNT)
failures = []


def sh(*a, check=True):
    return subprocess.run(a, check=check, capture_output=True)


def tool(*a):
    return subprocess.run([TOOL] + list(a), capture_output=True, text=True)


def mkimage(name, mb, cluster=4096):
    p = os.path.join(WORK, name)
    with open(p, "wb") as f:
        f.truncate(mb << 20)
    sh("mkntfs", "-F", "-Q", "-c", str(cluster), "-L", "D", p)
    return p


def judge(img, expect, base="/"):
    """Return a list of problems ([] = fine)."""
    problems = []
    r = tool("check", img)
    if r.returncode or "leaked_clusters=0" not in r.stdout:
        problems.append("check: %s %s" % (r.stdout.strip(), r.stderr.strip()[:400]))
    r = sh("ntfsresize", "--check", "--force", img, check=False)
    if r.returncode:
        problems.append("ntfsresize: " + (r.stdout + r.stderr).decode()[-300:])
    if problems:
        return problems
    sh("ntfs-3g", "-o", "ro", img, MNT)
    try:
        top = os.path.join(MNT, base.strip("/"))
        for rel, h in expect.items():
            p = os.path.join(top, rel)
            if h is None:
                if os.path.lexists(p):
                    problems.append("ntfs-3g still sees deleted " + rel)
                    break
                continue
            try:
                with open(p, "rb") as f:
                    if hashlib.sha256(f.read()).hexdigest() != h:
                        problems.append("content differs: " + rel)
                        break
            except OSError as e:
                problems.append("ntfs-3g: %s" % e)
                break
    finally:
        sh("umount", MNT)
    return problems


def report(name, problems):
    print("%-48s %s" % (name, "FAIL" if problems else "PASS"))
    for p in problems[:5]:
        print("   " + p)
    if problems:
        failures.append(name)


def fill(root, rnd, n, max_size, dirs=1):
    os.makedirs(root, exist_ok=True)
    out = {}
    dl = [""]
    for d in range(dirs - 1):
        rel = os.path.join(rnd.choice(dl), "d%02d" % d)
        os.makedirs(os.path.join(root, rel), exist_ok=True)
        dl.append(rel)
    for i in range(n):
        rel = os.path.join(rnd.choice(dl), "f%05d_%s.bin" % (i, "z" * (i % 29)))
        data = rnd.randbytes(rnd.randint(0, max_size))
        with open(os.path.join(root, rel), "wb") as f:
            f.write(data)
        out[rel] = hashlib.sha256(data).hexdigest()
    return out


def s_big_folder(name):
    """Delete from a 4000-entry folder in random order down to empty."""
    for cs in (512, 4096, 65536):
        img = mkimage("big%d.img" % cs, 160 if cs < 65536 else 420, cs)
        local = os.path.join(WORK, "big%d" % cs)
        exp = fill(local, random.Random(cs), 4000, 3000)
        r = tool("putdir", img, local, "/big")
        if r.returncode:
            report("%s (%d B clusters)" % (name, cs), [r.stderr[:300]])
            continue
        order = sorted(exp)
        random.Random(1).shuffle(order)
        problems = []
        for k, rel in enumerate(order):
            r = tool("rm", img, "/big/" + rel)
            if r.returncode:
                problems.append("rm %s: %s" % (rel, r.stderr.strip()))
                break
            exp[rel] = None
            if k in (100, 1000, 2500):
                c = tool("check", img)
                if c.returncode:
                    problems.append("after %d deletes: %s" % (k + 1, c.stderr.strip()[:300]))
                    break
                if k == 1000:
                    problems += judge(img, exp, "/big")
                    if problems:
                        break
        if not problems:
            problems += judge(img, {}, "/")
            r = tool("ls", img, "/big")
            if r.stdout.strip():
                problems.append("folder not empty: " + r.stdout[:200])
            r = tool("rm", img, "/big")
            if r.returncode:
                problems.append("rmdir: " + r.stderr)
            problems += judge(img, {}, "/")
        report("%s (%d B clusters)" % (name, cs), problems)


def s_ntfs3g_files(name):
    """Files ntfs-3g made: 8.3 names, compressed, sparse, fragmented."""
    img = mkimage("kinds.img", 96)
    sh("ntfs-3g", "-o", "compression", img, MNT)
    exp = {}
    try:
        top = os.path.join(MNT, "kinds")
        os.makedirs(os.path.join(top, "comp"))
        sh("setfattr", "-n", "system.ntfs_attrib_be", "-v", "0x00000810", os.path.join(top, "comp"))
        for i in range(30):
            with open(os.path.join(top, "comp", "c%d.txt" % i), "wb") as f:
                f.write((b"compress me %d " % i) * 20000)
        with open(os.path.join(top, "sparse.bin"), "wb") as f:
            f.seek(40 << 20)
            f.write(b"end")
        # Long name + Windows-style 8.3 alias (two index entries).
        for i in range(20):
            p = os.path.join(top, "Long File Name Number %02d.document" % i)
            with open(p, "w") as f:
                f.write("x" * i)
            sh("setfattr", "-n", "system.ntfs_dos_name", "-v", "LONGFI~%d.DOC" % (i % 9 + 1) if i < 9 else
               "LONGF%03d.DOC" % i, p, check=False)
        # Fragmented files with attribute lists.
        fill_dir = os.path.join(top, "fill")
        os.mkdir(fill_dir)
        chunk = os.urandom(4096)
        n = 0
        while n < 30000:
            try:
                with open(os.path.join(fill_dir, str(n)), "wb") as f:
                    f.write(chunk)
            except OSError:
                break
            n += 1
        for i in range(0, n, 2):
            os.unlink(os.path.join(fill_dir, str(i)))
        frag = os.urandom(n // 2 * 4096 - 300_000)
        with open(os.path.join(top, "fragmented.bin"), "wb") as f:
            f.write(frag)
        keep = os.urandom(50_000)
        with open(os.path.join(top, "keep.bin"), "wb") as f:
            f.write(keep)
        exp["keep.bin"] = hashlib.sha256(keep).hexdigest()
    finally:
        sh("umount", MNT)
    info = subprocess.run(["ntfsinfo", "-v", "-F", "/kinds/fragmented.bin", img],
                          capture_output=True, text=True).stdout
    problems = [] if "$ATTRIBUTE_LIST" in info else ["test setup: no attribute list"]
    dos = subprocess.run([TOOL, "ls", img, "/kinds"], capture_output=True, text=True).stdout
    for p in ("/kinds/fragmented.bin", "/kinds/sparse.bin", "/kinds/Long File Name Number 03.document",
              "/kinds/LONGF015.DOC", "/kinds/Long File Name Number 07.document"):
        r = tool("rm", img, p)
        if r.returncode:
            problems.append("rm %s: %s" % (p, r.stderr.strip()))
        exp[os.path.relpath(p, "/kinds")] = None
    exp["Long File Name Number 15.document"] = None
    r = tool("rmtree", img, "/kinds/comp")
    if r.returncode:
        problems.append("rmtree comp: " + r.stderr.strip())
    r = tool("rmtree", img, "/kinds/fill")
    if r.returncode:
        problems.append("rmtree fill: " + r.stderr.strip()[:200])
    problems += judge(img, exp, "/kinds")
    left = subprocess.run([TOOL, "ls", img, "/kinds"], capture_output=True, text=True).stdout
    for gone in ("Number 03", "Number 07", "Number 15", "fragmented", "sparse"):
        if gone in left:
            problems.append("still listed: " + gone)
    report(name, problems)
    _ = dos


def s_refusals(name):
    img = mkimage("refuse.img", 48)
    sh("ntfs-3g", img, MNT)
    try:
        os.makedirs(os.path.join(MNT, "full/sub"))
        with open(os.path.join(MNT, "full/sub/x"), "w") as f:
            f.write("x")
        with open(os.path.join(MNT, "linked"), "w") as f:
            f.write("data")
        os.link(os.path.join(MNT, "linked"), os.path.join(MNT, "linked2"))
        with open(os.path.join(MNT, "tracked"), "w") as f:
            f.write("t")
        sh("setfattr", "-n", "system.ntfs_object_id", "-v", "0x" + "11" * 16,
           os.path.join(MNT, "tracked"), check=False)
    finally:
        sh("umount", MNT)
    problems = []
    for path, why in (("/full", "Directory not empty"), ("/$MFT", "not permitted"),
                      ("/linked", "not supported"), ("/nope", "No such")):
        r = tool("rm", img, path)
        if r.returncode == 0 or why not in r.stderr:
            problems.append("%s: expected '%s', got rc=%d %s" % (path, why, r.returncode, r.stderr.strip()))
    obj = subprocess.run(["ntfsinfo", "-F", "/tracked", img], capture_output=True, text=True).stdout
    if "OBJECT_ID" in obj:
        r = tool("rm", img, "/tracked")
        if r.returncode == 0:
            problems.append("/tracked with object id was deleted")
    problems += judge(img, {}, "/")
    report(name, problems)


def s_random_mix(name):
    """Random adds and deletes by us, interleaved with ntfs-3g edits."""
    img = mkimage("mix.img", 160)
    rnd = random.Random(9)
    live = {}
    for rnd_no in range(10):
        local = os.path.join(WORK, "mix%d" % rnd_no)
        exp = fill(local, random.Random(rnd_no), rnd.randint(100, 500), 20000, dirs=rnd.randint(1, 5))
        r = tool("putdir", img, local, "/mix/r%d" % rnd_no)
        if r.returncode:
            report(name, ["putdir: " + r.stderr[:300]])
            return
        for k, h in exp.items():
            live["r%d/%s" % (rnd_no, k)] = h
        for k in rnd.sample(sorted(live), min(len(live) // 3, 300)):
            if live[k] is None:
                continue
            r = tool("rm", img, "/mix/" + k)
            if r.returncode:
                report(name, ["rm %s: %s" % (k, r.stderr.strip())])
                return
            live[k] = None
        if rnd_no % 3 == 2:
            victim = "r%d" % rnd.randint(0, rnd_no)
            r = tool("rmtree", img, "/mix/" + victim)
            if r.returncode and "No such" not in r.stderr:
                report(name, ["rmtree: " + r.stderr[:300]])
                return
            for k in list(live):
                if k.startswith(victim + "/"):
                    live[k] = None
        # ntfs-3g deletes and adds in the same folders.
        sh("ntfs-3g", img, MNT)
        try:
            alive = [k for k, h in live.items() if h is not None]
            for k in rnd.sample(alive, min(20, len(alive))):
                os.unlink(os.path.join(MNT, "mix", k))
                live[k] = None
            d = os.path.join(MNT, "mix", "by_ntfs3g_%d" % rnd_no)
            os.makedirs(d, exist_ok=True)
            for i in range(40):
                with open(os.path.join(d, "n%d" % i), "w") as f:
                    f.write("n" * i)
        finally:
            sh("umount", MNT)
        c = tool("check", img)
        if c.returncode:
            report(name, ["round %d: %s" % (rnd_no, c.stderr.strip()[:300])])
            return
    report(name, judge(img, live, "/mix"))


def scenario(name, fn):
    try:
        fn(name)
    except Exception as e:  # noqa: BLE001
        report(name, ["exception: %r" % e])


def main():
    print("work dir:", WORK)
    scenario("4000 files deleted one by one, then folder", s_big_folder)
    scenario("8.3 aliases, compressed, sparse, attr lists", s_ntfs3g_files)
    scenario("refusals leave the volume intact", s_refusals)
    scenario("10 rounds add/delete mixed with ntfs-3g", s_random_mix)
    print()
    if failures:
        print("FAILED:", ", ".join(failures))
        sys.exit(1)
    print("All delete tests passed.")
    shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
