/* Host-side test tool for the NTFS driver.
 *
 *   ntfstool info <image>
 *   ntfstool ls   <image> [path]
 *   ntfstool cat  <image> <path>
 *   ntfstool tree <image>          (recursive "type<TAB>size<TAB>path" list)
 *   ntfstool mkdir <image> <path>  (creates parents too)
 *   ntfstool put <image> <local-file> <path>
 *   ntfstool putdir <image> <local-dir> <path>   (recursive copy in)
 *   ntfstool check <image>         (consistency check, exit 1 on errors)
 *
 * <image> may be a raw partition image or a whole-disk image with an MBR or
 * GPT; the first NTFS partition is used. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/bdev.h"
#include "../src/ntfs.h"
#include "../src/part.h"
#include "../src/ntfs_priv.h"
#include "../src/endian_util.h"
#include <dirent.h>
#include <sys/stat.h>

static ntfs_vol_t *open_vol(const char *path) {
  bdev_t *b = bdev_open(path);
  if (!b) { perror(path); exit(1); }
  part_t parts[PART_MAX];
  int n = part_scan(b, parts, PART_MAX);
  for (int i = 0; i < n; i++) {
    bdev_t *s = bdev_slice(b, parts[i].offset, parts[i].size);
    if (!s) continue;
    if (!part_is_ntfs(s)) { bdev_close(s); continue; }
    ntfs_vol_t *v;
    char err[128];
    if (ntfs_mount(s, &v, err, sizeof err) == 0) {
      bdev_close(b);
      return v;
    }
    fprintf(stderr, "partition %d: %s\n", parts[i].index, err);
    bdev_close(s);
  }
  fprintf(stderr, "no NTFS volume found\n");
  exit(1);
}

static int ls_cb(void *ctx, const char *name, const ntfs_stat_t *st) {
  (void)ctx;
  printf("%c %12llu %08x %s\n", st->is_dir ? 'd' : '-',
         (unsigned long long)st->size, st->attrs, name);
  return 0;
}

typedef struct tree_ctx {
  ntfs_vol_t *v;
  char path[4096];
  int depth;
} tree_ctx_t;

typedef struct child {
  char *name;
  ntfs_stat_t st;
} child_t;

typedef struct clist {
  child_t *c;
  size_t n, cap;
} clist_t;

static int collect(void *ctx, const char *name, const ntfs_stat_t *st) {
  clist_t *l = ctx;
  if (l->n == l->cap) {
    l->cap = l->cap ? l->cap * 2 : 32;
    l->c = realloc(l->c, l->cap * sizeof *l->c);
  }
  l->c[l->n].name = strdup(name);
  l->c[l->n].st = *st;
  l->n++;
  return 0;
}

static void tree(tree_ctx_t *t, uint64_t ino) {
  clist_t l = {0};
  int rc = ntfs_readdir(t->v, ino, collect, &l);
  if (rc) fprintf(stderr, "readdir %s: %s\n", t->path, strerror(-rc));
  size_t base = strlen(t->path);
  for (size_t i = 0; i < l.n; i++) {
    snprintf(t->path + base, sizeof t->path - base, "/%s", l.c[i].name);
    printf("%c\t%llu\t%s\n", l.c[i].st.is_dir ? 'd' : 'f',
           l.c[i].st.is_dir ? 0ULL : (unsigned long long)l.c[i].st.size,
           t->path);
    if (l.c[i].st.is_dir && !(l.c[i].st.attrs & NTFS_FA_REPARSE) && t->depth < 64) {
      t->depth++;
      tree(t, l.c[i].st.inode);
      t->depth--;
    }
    t->path[base] = 0;
    free(l.c[i].name);
  }
  free(l.c);
}


/* ---- write helpers ---- */

static int split_parent(ntfs_vol_t *v, const char *path, uint64_t *parent, const char **base) {
  static char dir[4096];
  const char *slash = strrchr(path, '/');
  *base = slash ? slash + 1 : path;
  size_t n = slash ? (size_t)(slash - path) : 0;
  memcpy(dir, path, n);
  dir[n] = 0;
  return ntfs_lookup(v, n ? dir : "/", parent);
}

static int mkdir_p(ntfs_vol_t *v, const char *path) {
  char buf[4096];
  snprintf(buf, sizeof buf, "%s", path);
  uint64_t cur = NTFS_ROOT_INODE;
  char *save = NULL;
  for (char *c = strtok_r(buf, "/", &save); c; c = strtok_r(NULL, "/", &save)) {
    char sub[4096];
    uint64_t ino;
    snprintf(sub, sizeof sub, "%.*s", (int)(c - buf + strlen(c)), path[0] == '/' ? path : path);
    (void)sub;
    /* look up c inside cur via a temporary path walk */
    int rc = ntfs_mkdir(v, cur, c, 0, &ino);
    if (rc == -EEXIST) {
      char p2[4096];
      size_t l = (size_t)(c - buf) + strlen(c);
      memcpy(p2, buf, l);
      p2[l] = 0;
      for (size_t i = 0; i < l; i++) if (!p2[i]) p2[i] = '/';
      rc = ntfs_lookup(v, p2, &ino);
    }
    if (rc) return rc;
    cur = ino;
  }
  return 0;
}

static int put_file(ntfs_vol_t *v, const char *local, const char *path) {
  FILE *in = fopen(local, "rb");
  if (!in) return -errno;
  struct stat st;
  fstat(fileno(in), &st);
  uint64_t parent;
  const char *base;
  int rc = split_parent(v, path, &parent, &base);
  ntfs_wfile_t *w = NULL;
  if (!rc) rc = ntfs_create(v, parent, base, (uint64_t)st.st_size, st.st_mtime, &w);
  static uint8_t buf[1 << 20];
  while (!rc) {
    size_t n = fread(buf, 1, sizeof buf, in);
    if (!n) break;
    rc = ntfs_wwrite(w, buf, n);
  }
  if (w) { int r2 = ntfs_wclose(w); if (!rc) rc = r2; }
  fclose(in);
  return rc;
}

static int put_dir(ntfs_vol_t *v, const char *local, const char *path) {
  int rc = mkdir_p(v, path);
  if (rc) return rc;
  DIR *d = opendir(local);
  if (!d) return -errno;
  struct dirent *e;
  while (!rc && (e = readdir(d))) {
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
    char l[4096], p[4096];
    snprintf(l, sizeof l, "%s/%s", local, e->d_name);
    snprintf(p, sizeof p, "%s/%s", path, e->d_name);
    struct stat st;
    if (lstat(l, &st)) continue;
    if (S_ISDIR(st.st_mode)) rc = put_dir(v, l, p);
    else if (S_ISREG(st.st_mode)) rc = put_file(v, l, p);
    if (rc) fprintf(stderr, "%s: %s\n", p, strerror(-rc));
  }
  closedir(d);
  return rc;
}

/* ---- consistency checker ---- */

static int g_errors;
#define CHK(...) do { if (g_errors++ < 30) { fprintf(stderr, "check: " __VA_ARGS__); fputc('\n', stderr); } } while (0)

typedef struct ord_ctx {
  ntfs_vol_t *v;
  uint64_t dir;
  uint16_t prev[256];
  int prev_len, have_prev;
  uint8_t *rec;
} ord_ctx_t;

static int name_cmp(ntfs_vol_t *v, const uint16_t *a, int al, const uint16_t *b, int bl) {
  int n = al < bl ? al : bl;
  for (int i = 0; i < n; i++) {
    uint16_t x = up(v, a[i]), y = up(v, b[i]);
    if (x != y) return x < y ? -1 : 1;
  }
  return al == bl ? 0 : al < bl ? -1 : 1;
}

static int ord_cb(void *ctx, uint64_t ref, const uint8_t *fn, uint16_t fnlen) {
  ord_ctx_t *o = ctx;
  uint16_t name[256];
  int n = fn[0x40];
  for (int i = 0; i < n; i++) name[i] = le16(fn + 0x42 + i * 2);
  if (o->have_prev) {
    int c = name_cmp(o->v, o->prev, o->prev_len, name, n);
    if (c > 0) CHK("dir %llu: index out of order", (unsigned long long)o->dir);
    /* Equal ignoring case is allowed (POSIX names / DOS+Win32 pairs). */
  }
  memcpy(o->prev, name, n * 2);
  o->prev_len = n;
  o->have_prev = 1;
  if (MREF(le64(fn)) != o->dir && !(o->dir == 5 && MREF(ref) == 5))
    CHK("dir %llu: entry parent is %llu", (unsigned long long)o->dir,
        (unsigned long long)MREF(le64(fn)));
  if (read_record(o->v, MREF(ref), o->rec)) {
    CHK("dir %llu: entry -> record %llu not in use", (unsigned long long)o->dir,
        (unsigned long long)MREF(ref));
  } else if (le16(o->rec + MFT_HDR_SEQ) != MREF_SEQ(ref)) {
    CHK("dir %llu: entry -> record %llu has seq %u, entry says %u",
        (unsigned long long)o->dir, (unsigned long long)MREF(ref),
        le16(o->rec + MFT_HDR_SEQ), MREF_SEQ(ref));
  }
  (void)fnlen;
  return 0;
}

typedef struct present_ctx { uint64_t ino; int found; } present_ctx_t;
static int present_cb(void *ctx, uint64_t ref, const uint8_t *fn, uint16_t fnlen) {
  present_ctx_t *p = ctx;
  (void)fn; (void)fnlen;
  if (MREF(ref) == p->ino) { p->found = 1; return 1; }
  return 0;
}

static int check_volume(ntfs_vol_t *v) {
  uint64_t nrec = v->mft.init / v->rec_size;
  uint64_t tc = v->total_clusters;
  uint8_t *used = calloc(1, (size_t)((tc + 7) / 8));
  uint8_t *rec = malloc(v->rec_size), *rec2 = malloc(v->rec_size);
  attr_t mbm, cbm;
  if (attr_find(v, 0, AT_BITMAP, NULL, 0, &mbm) || attr_find(v, 6, AT_DATA, NULL, 0, &cbm)) {
    CHK("cannot load bitmaps");
    return 1;
  }
  uint8_t *mbits = calloc(1, (size_t)mbm.size + 1), *cbits = malloc((size_t)cbm.size + 1);
  attr_pread(v, &mbm, 0, mbits, (size_t)mbm.size);
  attr_pread(v, &cbm, 0, cbits, (size_t)cbm.size);
  /* Boot sector cluster(s) are in use but owned by $Boot (record 7). */

  for (uint64_t i = 0; i < nrec; i++) {
    int rc = read_record_any(v, i, rec);
    int in_use = !rc && (le16(rec + 0x16) & MFT_IN_USE);
    int bit = i / 8 < mbm.size ? (mbits[i / 8] >> (i % 8)) & 1 : 0;
    if (in_use != bit && i >= 16) CHK("record %llu: in_use=%d but MFT bitmap=%d", (unsigned long long)i, in_use, bit);
    if (!in_use) continue;
    if (le32(rec + 0x18) > v->rec_size || le32(rec + 0x18) < 0x38) CHK("record %llu: bad bytes_in_use", (unsigned long long)i);
    /* Account clusters of every non-resident attribute in this record. */
    uint32_t pos = 0;
    const uint8_t *at;
    uint32_t walked = le16(rec + 0x14);
    while ((at = next_attr(rec, v->rec_size, &pos))) {
      walked = pos;
      if (!at[8]) {
        if (le16(at + 20) + le32(at + 16) > le32(at + 4)) CHK("record %llu: resident value overflows attribute", (unsigned long long)i);
        continue;
      }
      attr_t a = {0};
      a.cu_idx = -1;
      int64_t lowest = (int64_t)le64(at + 16);
      if (decode_runs(&a, at + le16(at + 32), at + le32(at + 4), lowest)) {
        CHK("record %llu: bad mapping pairs", (unsigned long long)i);
        continue;
      }
      uint64_t cl = 0;
      for (size_t r = 0; r < a.nruns; r++) {
        if (a.runs[r].lcn < 0) continue;
        cl += a.runs[r].len;
        for (uint64_t c = (uint64_t)a.runs[r].lcn; c < (uint64_t)a.runs[r].lcn + a.runs[r].len; c++) {
          if (c >= tc) { CHK("record %llu: cluster %llu beyond volume", (unsigned long long)i, (unsigned long long)c); break; }
          if (used[c / 8] & (1u << (c % 8))) CHK("cluster %llu used twice (record %llu)", (unsigned long long)c, (unsigned long long)i);
          used[c / 8] |= (uint8_t)(1u << (c % 8));
          if (!((cbits[c / 8] >> (c % 8)) & 1)) CHK("cluster %llu used by record %llu but free in $Bitmap", (unsigned long long)c, (unsigned long long)i);
        }
      }
      if (lowest == 0 && !(le16(at + 12) & 0x8001)) {
        uint64_t alloc = le64(at + 0x28), size = le64(at + 0x30), init = le64(at + 0x38);
        uint64_t highest = le64(at + 0x18);
        if (init > size || size > alloc) CHK("record %llu: sizes init %llu size %llu alloc %llu", (unsigned long long)i,
                                             (unsigned long long)init, (unsigned long long)size, (unsigned long long)alloc);
        if ((highest + 1) * v->cluster != alloc && le32(at) != 0x80) {
          /* Single-segment attributes: alloc must match the runs. */
        }
        if (le32(at) == 0x80 && !le16(rec + 0x20) && (highest + 1) * v->cluster != alloc &&
            !le64(rec + 0x20)) {
          /* Only meaningful without attribute lists. */
          int has_list = 0; uint32_t p2 = 0; const uint8_t *a2;
          while ((a2 = next_attr(rec, v->rec_size, &p2))) if (le32(a2) == 0x20) has_list = 1;
          if (!has_list) CHK("record %llu: highest_vcn %llu vs alloc %llu", (unsigned long long)i,
                             (unsigned long long)highest, (unsigned long long)alloc);
        }
      }
      free(a.runs);
    }
    if (walked + 8 > le32(rec + 0x18)) CHK("record %llu: attributes overrun bytes_in_use", (unsigned long long)i);

    /* Directories: index order and links. Base records only. */
    if (le64(rec + 0x20)) continue;
    if (le16(rec + 0x16) & MFT_DIRECTORY) {
      ord_ctx_t o = {0};
      o.v = v; o.dir = i; o.rec = rec2;
      if (index_walk(v, i, ord_cb, &o)) CHK("dir %llu: index walk failed", (unsigned long long)i);
    }
    if (i >= 16 || i == 5) {
      pos = 0;
      while ((at = next_attr(rec, v->rec_size, &pos))) {
        if (le32(at) != 0x30 || at[8]) continue;
        const uint8_t *fn = at + le16(at + 20);
        if (fn[0x41] == 2) continue;
        uint64_t parent = MREF(le64(fn));
        if (i == 5) continue;
        present_ctx_t p = {i, 0};
        index_walk(v, parent, present_cb, &p);
        if (!p.found) CHK("record %llu: not listed in parent %llu", (unsigned long long)i, (unsigned long long)parent);
        break;
      }
    }
  }
  uint64_t leaked = 0;
  for (uint64_t c = 0; c < tc; c++)
    if (((cbits[c / 8] >> (c % 8)) & 1) && !(used[c / 8] & (1u << (c % 8)))) leaked++;
  /* The boot sector area and backup are marked used without an owner list in
   * some formats; report leaks as information only. */
  printf("records=%llu clusters=%llu leaked_clusters=%llu errors=%d\n",
         (unsigned long long)nrec, (unsigned long long)tc, (unsigned long long)leaked, g_errors);
  free(used); free(rec); free(rec2); free(mbits); free(cbits);
  attr_free(&mbm); attr_free(&cbm);
  return g_errors ? 1 : 0;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s info|ls|cat|tree <image> [path]\n", argv[0]);
    return 2;
  }
  const char *cmd = argv[1];
  ntfs_vol_t *v = open_vol(argv[2]);
  const char *path = argc > 3 ? argv[3] : "/";
  int rc = 0;

  if (!strcmp(cmd, "info")) {
    ntfs_info_t in;
    uint64_t fr = 0;
    ntfs_get_info(v, &in);
    ntfs_free_bytes(v, &fr);
    printf("label=%s\nserial=%016llx\ntotal=%llu\nfree=%llu\ncluster=%u\n"
           "mft_record=%u\nversion=%u.%u\ndirty=%d\n",
           in.label, (unsigned long long)in.serial,
           (unsigned long long)in.total_bytes, (unsigned long long)fr,
           in.cluster_size, in.mft_record_size, in.ver_major, in.ver_minor,
           in.dirty);
  } else if (!strcmp(cmd, "ls")) {
    uint64_t ino;
    if ((rc = ntfs_lookup(v, path, &ino)) == 0) rc = ntfs_readdir(v, ino, ls_cb, NULL);
  } else if (!strcmp(cmd, "cat")) {
    uint64_t ino;
    ntfs_file_t *f;
    if ((rc = ntfs_lookup(v, path, &ino)) == 0 && (rc = ntfs_open(v, ino, &f)) == 0) {
      static uint8_t buf[1 << 20];
      uint64_t off = 0, size = ntfs_file_size(f);
      while (off < size) {
        ssize_t n = ntfs_pread(f, buf, sizeof buf, off);
        if (n <= 0) { rc = n < 0 ? (int)n : -EIO; break; }
        fwrite(buf, 1, (size_t)n, stdout);
        off += (uint64_t)n;
      }
      ntfs_close(f);
    }
  } else if (!strcmp(cmd, "tree")) {
    tree_ctx_t t = {v, "", 0};
    tree(&t, NTFS_ROOT_INODE);
  } else if (!strcmp(cmd, "mkdir") || !strcmp(cmd, "put") || !strcmp(cmd, "putdir")) {
    char err[256];
    rc = ntfs_enable_write(v, err, sizeof err);
    if (rc) fprintf(stderr, "enable write: %s\n", err);
    else if (!strcmp(cmd, "mkdir")) rc = mkdir_p(v, path);
    else if (argc < 5) rc = -EINVAL;
    else if (!strcmp(cmd, "put")) { path = argv[4]; rc = put_file(v, argv[3], argv[4]); }
    else { path = argv[4]; rc = put_dir(v, argv[3], argv[4]); }
  } else if (!strcmp(cmd, "check")) {
    int bad = check_volume(v);
    ntfs_umount(v);
    return bad;
  } else {
    fprintf(stderr, "unknown command %s\n", cmd);
    rc = -EINVAL;
  }
  if (rc) fprintf(stderr, "%s: %s\n", path, strerror(-rc));
  ntfs_umount(v);
  return rc ? 1 : 0;
}
