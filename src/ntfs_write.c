/* NTFS write support: create folders and files, fill them sequentially.
 *
 * Deliberately limited to operations that only *add* to the volume, so the
 * worst case of an interrupted write (e.g. the drive is unplugged) is a few
 * lost clusters or a partly written file, which chkdsk tidies up.
 *
 * Layouts follow what ntfs-3g produces (48-byte $STANDARD_INFORMATION plus an
 * inline security descriptor, POSIX namespace names), which Windows has
 * accepted for many years. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "endian_util.h"
#include "ntfs_priv.h"
#include "utf.h"

#define AT_SECURITY_DESCRIPTOR 0x50

#define FIRST_FREE_RECORD 64   /* leave the reserved/system area alone */
#define MFT_GROW_RECORDS  256  /* records added when the MFT is full */
#define INIT_FLUSH_EVERY  (256ull * 1024 * 1024)

#define FA_ARCHIVE 0x00000020u
#define FA_DUP_I30 0x10000000u

#define NS_POSIX 0

struct ntfs_wfile {
  ntfs_vol_t *v;
  uint64_t    inode;
  attr_t      a;       /* runs of the unnamed $DATA */
  uint64_t    pos;     /* bytes written = initialized size */
  uint64_t    flushed; /* initialized size last stored in the record */
};

/* Self-relative security descriptor: owner/group Administrators, DACL
 * granting Everyone full control (inheritable). Same bytes ntfs-3g uses. */
static const uint8_t SD_DEFAULT[80] = {
    0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00,
    0x20, 0x02, 0x00, 0x00, 0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x03, 0x14, 0x00, 0xff, 0x01, 0x1f, 0x00, 0x01, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};

/* ---- Small helpers ------------------------------------------------------- */

static inline uint32_t align8(uint32_t x) { return (x + 7) & ~7u; }

static void put_le32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void put_le64(uint8_t *p, uint64_t v) {
  put_le32(p, (uint32_t)v);
  put_le32(p + 4, (uint32_t)(v >> 32));
}

static uint64_t unix2nt(int64_t t) {
  if (t < -11644473600LL) t = -11644473600LL;
  return (uint64_t)(t + 11644473600LL) * 10000000ULL;
}

static uint64_t now_nt(void) { return unix2nt((int64_t)time(NULL)); }

/* ---- Raw attribute writes ------------------------------------------------ */

/* Write into already-allocated clusters of a non-resident attribute. */
static int write_raw(ntfs_vol_t *v, const attr_t *a, uint64_t off,
                     const uint8_t *buf, size_t len) {
  uint32_t cs = v->cluster;
  while (len) {
    int64_t vcn = (int64_t)(off / cs);
    const run_t *r = find_run(a, vcn);
    if (!r || r->lcn < 0) return -EIO; /* never write into holes */
    uint64_t run_end = (uint64_t)(r->vcn + (int64_t)r->len) * cs;
    size_t n = run_end - off < len ? (size_t)(run_end - off) : len;
    uint64_t phys = (uint64_t)r->lcn * cs + (off - (uint64_t)r->vcn * cs);
    if (bdev_write(v->dev, phys, buf, n)) return -EIO;
    buf += n; off += n; len -= n;
  }
  return 0;
}

/* Reverse of apply_fixups: protect a record before it goes to disk. */
static int prepare_fixups(uint8_t *buf, uint32_t size) {
  uint16_t ofs = le16(buf + 4), cnt = le16(buf + 6);
  if (cnt < 2 || (uint32_t)(cnt - 1) * 512 != size || ofs + cnt * 2u > size)
    return -EIO;
  uint16_t usn = (uint16_t)(le16(buf + ofs) + 1);
  if (usn == 0 || usn == 0xFFFF) usn = 1;
  put_le16(buf + ofs, usn);
  for (uint16_t i = 1; i < cnt; i++) {
    uint8_t *tail = buf + i * 512 - 2;
    memcpy(buf + ofs + i * 2, tail, 2);
    put_le16(tail, usn);
  }
  return 0;
}

/* Write an (unprotected, in-memory) MFT record, plus its mirror copy. */
static int write_record(ntfs_vol_t *v, uint64_t inode, const uint8_t *rec) {
  uint8_t *tmp = malloc(v->rec_size);
  if (!tmp) return -ENOMEM;
  memcpy(tmp, rec, v->rec_size);
  int rc = prepare_fixups(tmp, v->rec_size);
  if (!rc) rc = write_raw(v, &v->mft, inode * v->rec_size, tmp, v->rec_size);
  if (!rc && inode < v->mirr_recs &&
      bdev_write(v->dev, v->mftmirr_lcn * v->cluster + inode * v->rec_size, tmp,
                 v->rec_size))
    rc = -EIO;
  free(tmp);
  return rc;
}

/* ---- Editing attributes inside a record ---------------------------------- */

static uint8_t *rec_attr(uint8_t *rec, uint32_t rec_size, uint32_t type,
                         const uint16_t *name, int nlen) {
  uint32_t pos = 0;
  const uint8_t *at;
  while ((at = next_attr(rec, rec_size, &pos)))
    if (le32(at) == type && attr_name_eq(at, name, nlen)) return (uint8_t *)at;
  return NULL;
}

/* Change the length of the attribute at `at`, shifting what follows. */
static int rec_resize(uint8_t *rec, uint8_t *at, uint32_t newlen) {
  uint32_t oldlen = le32(at + 4), used = le32(rec + 0x18), cap = le32(rec + 0x1C);
  newlen = align8(newlen);
  if (used - oldlen + newlen > cap) return -ENOSPC;
  uint32_t tail = used - (uint32_t)(at - rec) - oldlen;
  memmove(at + newlen, at + oldlen, tail);
  put_le32(at + 4, newlen);
  put_le32(rec + 0x18, used - oldlen + newlen);
  return 0;
}

/* Insert a complete attribute keeping the type order. Sets its instance. */
static int rec_insert(uint8_t *rec, uint32_t rec_size, uint8_t *attr) {
  uint32_t len = le32(attr + 4), used = le32(rec + 0x18), cap = le32(rec + 0x1C);
  if (used + len > cap) return -ENOSPC;
  uint32_t type = le32(attr);
  uint32_t p = le16(rec + 0x14);
  while (p + 8 <= used) {
    uint32_t t = le32(rec + p);
    if (t == AT_END || t > type) break;
    uint32_t l = le32(rec + p + 4);
    if (!l) return -EIO;
    p += l;
  }
  memmove(rec + p + len, rec + p, used - p);
  memcpy(rec + p, attr, len);
  uint16_t inst = le16(rec + 0x28);
  put_le16(rec + p + 14, inst);
  put_le16(rec + 0x28, (uint16_t)(inst + 1));
  put_le32(rec + 0x18, used + len);
  (void)rec_size;
  return 0;
}

/* Replace the value of a resident attribute. */
static int set_resident_value(uint8_t *rec, uint8_t *at, const void *val, uint32_t vlen) {
  uint16_t voff = le16(at + 20);
  int rc = rec_resize(rec, at, voff + vlen);
  if (rc) return rc;
  put_le32(at + 16, vlen);
  memcpy(at + voff, val, vlen);
  uint32_t total = le32(at + 4);
  if (total > voff + vlen) memset(at + voff + vlen, 0, total - voff - vlen);
  return 0;
}

static uint32_t build_resident(uint8_t *out, uint32_t type, const uint16_t *name,
                               int nlen, const void *val, uint32_t vlen,
                               uint8_t rflags) {
  uint32_t voff = align8(0x18 + (uint32_t)nlen * 2);
  uint32_t len = align8(voff + vlen);
  memset(out, 0, len);
  put_le32(out, type);
  put_le32(out + 4, len);
  out[8] = 0;
  out[9] = (uint8_t)nlen;
  put_le16(out + 10, 0x18);
  put_le32(out + 16, vlen);
  put_le16(out + 20, (uint16_t)voff);
  out[22] = rflags;
  for (int i = 0; i < nlen; i++) put_le16(out + 0x18 + i * 2, name[i]);
  if (vlen) memcpy(out + voff, val, vlen);
  return len;
}

static int sbytes(int64_t x) {
  int n = 1;
  while (n < 8) {
    int64_t lim = (int64_t)1 << (8 * n - 1);
    if (x >= -lim && x < lim) break;
    n++;
  }
  return n;
}

/* Encode a run list as mapping pairs. Returns the length or -1. */
static int encode_runs(const attr_t *a, uint8_t *out, size_t max) {
  size_t o = 0;
  int64_t prev = 0;
  for (size_t i = 0; i < a->nruns; i++) {
    const run_t *r = &a->runs[i];
    int lb = sbytes((int64_t)r->len), ob = 0;
    int64_t delta = 0;
    if (r->lcn >= 0) {
      delta = r->lcn - prev;
      ob = sbytes(delta);
      prev = r->lcn;
    }
    if (o + 1 + (size_t)lb + (size_t)ob + 1 > max) return -1;
    out[o++] = (uint8_t)(lb | ob << 4);
    for (int k = 0; k < lb; k++) out[o++] = (uint8_t)((uint64_t)r->len >> (8 * k));
    for (int k = 0; k < ob; k++) out[o++] = (uint8_t)((uint64_t)delta >> (8 * k));
  }
  out[o++] = 0;
  return (int)o;
}

/* Build a non-resident attribute header + mapping pairs into out. */
static int build_nonresident(uint8_t *out, size_t max, uint32_t type,
                             const uint16_t *name, int nlen, const attr_t *a,
                             uint16_t flags) {
  uint32_t mpoff = align8(0x40 + (uint32_t)nlen * 2);
  if (mpoff >= max) return -ENOSPC;
  memset(out, 0, mpoff);
  int mp = encode_runs(a, out + mpoff, max - mpoff);
  if (mp < 0) return -ENOSPC;
  uint32_t len = align8(mpoff + (uint32_t)mp);
  if (len > max) return -ENOSPC;
  memset(out + mpoff + mp, 0, len - mpoff - (uint32_t)mp);
  uint64_t clusters = 0;
  for (size_t i = 0; i < a->nruns; i++) clusters += a->runs[i].len;
  put_le32(out, type);
  put_le32(out + 4, len);
  out[8] = 1;
  out[9] = (uint8_t)nlen;
  put_le16(out + 10, 0x40);
  put_le16(out + 12, flags);
  put_le64(out + 0x10, 0);
  put_le64(out + 0x18, clusters ? clusters - 1 : (uint64_t)-1);
  put_le16(out + 0x20, (uint16_t)mpoff);
  put_le64(out + 0x28, a->alloc);
  put_le64(out + 0x30, a->size);
  put_le64(out + 0x38, a->init);
  for (int i = 0; i < nlen; i++) put_le16(out + 0x40 + i * 2, name[i]);
  return (int)len;
}

/* Rewrite a non-resident attribute in place from a (runs, sizes). */
static int update_nonresident(uint8_t *rec, uint32_t rec_size, uint8_t *at,
                              const attr_t *a) {
  uint8_t tmp[4096];
  int nlen = at[9];
  uint16_t name[255];
  for (int i = 0; i < nlen; i++) name[i] = le16(at + le16(at + 10) + i * 2);
  int len = build_nonresident(tmp, sizeof tmp < rec_size ? sizeof tmp : rec_size,
                              le32(at), name, nlen, a, le16(at + 12));
  if (len < 0) return len;
  uint16_t inst = le16(at + 14);
  int rc = rec_resize(rec, at, (uint32_t)len);
  if (rc) return rc;
  memcpy(at, tmp, (size_t)len);
  put_le16(at + 14, inst);
  return 0;
}

/* ---- Cluster allocation -------------------------------------------------- */

/* Set or clear count bits starting at bit in a non-resident bitmap. */
static int bitmap_set(ntfs_vol_t *v, attr_t *bm, uint64_t bit, uint64_t count, int val) {
  uint8_t buf[4096];
  while (count) {
    uint64_t byte0 = bit / 8;
    size_t nbytes = (size_t)((bit % 8 + count + 7) / 8);
    if (nbytes > sizeof buf) nbytes = sizeof buf;
    if (attr_pread(v, bm, byte0, buf, nbytes) != (ssize_t)nbytes) return -EIO;
    uint64_t done = 0;
    for (uint64_t b = bit % 8; b < nbytes * 8 && done < count; b++, done++) {
      if (val) buf[b / 8] |= (uint8_t)(1u << (b % 8));
      else buf[b / 8] &= (uint8_t)~(1u << (b % 8));
    }
    if (write_raw(v, bm, byte0, buf, nbytes)) return -EIO;
    bit += done;
    count -= done;
  }
  return 0;
}

static void free_clusters(ntfs_vol_t *v, const attr_t *runs) {
  for (size_t i = 0; i < runs->nruns; i++) {
    if (runs->runs[i].lcn < 0) continue;
    bitmap_set(v, &v->cbmp, (uint64_t)runs->runs[i].lcn, runs->runs[i].len, 0);
    if (v->free_known) v->free_clusters += runs->runs[i].len;
  }
}

/* One first-fit pass: collect free extents of at least min_len clusters
 * (except that an extent covering the remainder is always fine), starting
 * at the allocation hint and wrapping around once. */
static int alloc_pass(ntfs_vol_t *v, uint64_t count, attr_t *out, int64_t vcn,
                      size_t max_runs, uint64_t min_len, uint8_t *buf, size_t bufsz) {
  uint64_t total = v->total_clusters, need = count;
  uint64_t start = v->alloc_hint < total ? v->alloc_hint : 0;
  size_t found = 0, first = out->nruns;
  for (int pass = 0; pass < 2 && need; pass++) {
    uint64_t lo = pass ? 0 : start, hi = pass ? start : total;
    uint64_t run_start = 0, run_len = 0, chunk_lo = 1, chunk_hi = 0;
    for (uint64_t c = lo; c <= hi && need;) {
      int used = 1;
      if (c < hi) {
        if (c < chunk_lo || c >= chunk_hi) {
          uint64_t byte0 = c / 8;
          size_t n = (size_t)((hi + 7) / 8 - byte0);
          if (n > bufsz) n = bufsz;
          if (attr_pread(v, &v->cbmp, byte0, buf, n) != (ssize_t)n) return -EIO;
          chunk_lo = byte0 * 8;
          chunk_hi = (byte0 + n) * 8;
        }
        uint8_t byte = buf[(c - chunk_lo) / 8];
        if (!run_len && !(c % 8) && byte == 0xFF && c + 8 <= hi) { c += 8; continue; }
        used = (byte >> (c % 8)) & 1;
      }
      if (!used) {
        if (!run_len) run_start = c;
        run_len++;
        c++;
        if (run_len < need) continue;
      } else {
        c++;
        if (!run_len) continue;
        if (run_len < min_len && run_len < need) { run_len = 0; continue; }
      }
      if (found >= max_runs) {
        out->nruns = first;
        return -EFBIG;
      }
      if (run_push(out, vcn, (int64_t)run_start, run_len)) return -ENOMEM;
      found++;
      vcn += (int64_t)run_len;
      need -= run_len;
      run_len = 0;
    }
  }
  if (need) {
    out->nruns = first;
    return -ENOSPC;
  }
  return 0;
}

/* Find count free clusters as at most max_runs extents and append them to
 * out starting at vcn. Does not touch the bitmap. Prefers one contiguous
 * extent; otherwise uses extents of at least count/max_runs clusters so the
 * extent limit is met whenever the free space allows it. */
static int alloc_clusters(ntfs_vol_t *v, uint64_t count, attr_t *out, int64_t vcn,
                          size_t max_runs) {
  enum { CHUNK = 64 * 1024 };
  uint8_t *buf = malloc(CHUNK);
  if (!buf) return -ENOMEM;
  if (!max_runs) max_runs = 1;
  int rc = alloc_pass(v, count, out, vcn, 1, count, buf, CHUNK);
  if (rc == -ENOSPC && max_runs > 1) {
    uint64_t min_len = (count + max_runs - 1) / max_runs;
    rc = alloc_pass(v, count, out, vcn, max_runs, min_len, buf, CHUNK);
  }
  if (rc == -ENOSPC) {
    /* Distinguish "full" from "too fragmented". */
    uint64_t free_total = 0;
    attr_t probe = {0};
    probe.cu_idx = -1;
    if (alloc_pass(v, count, &probe, 0, (size_t)-1, 1, buf, CHUNK) == 0) free_total = count;
    free(probe.runs);
    if (free_total >= count) rc = -EFBIG;
  }
  free(buf);
  return rc;
}

/* Wrapper that allocates into a fresh list, marks the bitmap and then
 * appends to out. Keeps bitmap updates exact even when runs merge. */
static int alloc_and_mark(ntfs_vol_t *v, uint64_t count, attr_t *out, int64_t vcn,
                          size_t max_runs) {
  attr_t fresh = {0};
  fresh.cu_idx = -1;
  int rc = alloc_clusters(v, count, &fresh, vcn, max_runs);
  if (rc) { free(fresh.runs); return rc; }
  for (size_t i = 0; i < fresh.nruns && !rc; i++)
    rc = bitmap_set(v, &v->cbmp, (uint64_t)fresh.runs[i].lcn, fresh.runs[i].len, 1);
  if (rc) {
    free_clusters(v, &fresh);
    free(fresh.runs);
    return rc;
  }
  if (v->free_known) v->free_clusters -= count;
  const run_t *last = &fresh.runs[fresh.nruns - 1];
  v->alloc_hint = (uint64_t)last->lcn + last->len;
  for (size_t i = 0; i < fresh.nruns && !rc; i++)
    rc = run_push(out, fresh.runs[i].vcn, fresh.runs[i].lcn, fresh.runs[i].len);
  free(fresh.runs);
  return rc;
}

/* ---- MFT record allocation ----------------------------------------------- */

static void format_empty_record(ntfs_vol_t *v, uint8_t *rec, uint64_t inode,
                                uint16_t seq) {
  memset(rec, 0, v->rec_size);
  memcpy(rec, "FILE", 4);
  uint16_t usa_cnt = (uint16_t)(v->rec_size / 512 + 1);
  put_le16(rec + 4, 0x30);
  put_le16(rec + 6, usa_cnt);
  put_le16(rec + 0x30, 1);
  put_le16(rec + 0x10, seq);
  uint32_t ao = align8(0x30 + usa_cnt * 2u);
  put_le16(rec + 0x14, (uint16_t)ao);
  put_le32(rec + ao, AT_END);
  put_le32(rec + 0x18, ao + 8);
  put_le32(rec + 0x1C, v->rec_size);
  put_le32(rec + 0x2C, (uint32_t)inode);
}

/* Grow $MFT (and its bitmap) when there are no free records left. */
static int extend_mft(ntfs_vol_t *v) {
  if (v->has_list_mft) return -ENOSPC;
  uint8_t *rec0 = malloc(v->rec_size), *blank = malloc(v->rec_size);
  attr_t grown = {0}, bmp = {0}, fresh = {0};
  grown.cu_idx = bmp.cu_idx = fresh.cu_idx = -1;
  int rc = (!rec0 || !blank) ? -ENOMEM : read_record(v, INODE_MFT, rec0);
  if (rc) goto out;

  uint64_t old_recs = v->mft.init / v->rec_size;
  uint64_t bytes = 0, clusters = 0, new_recs = 0;

  /* Prefer space right after the current end of the MFT. */
  const run_t *last = &v->mft.runs[v->mft.nruns - 1];
  uint64_t save_hint = v->alloc_hint;
  v->alloc_hint = last->lcn >= 0 ? (uint64_t)last->lcn + last->len : save_hint;
  for (size_t i = 0; i < v->mft.nruns && !rc; i++)
    rc = run_push(&grown, v->mft.runs[i].vcn, v->mft.runs[i].lcn, v->mft.runs[i].len);
  int64_t vcn_end = (int64_t)(v->mft.alloc / v->cluster);
  /* Grow by 256 records if free space allows it in a few extents, otherwise
   * by less: each extent costs room in record 0. */
  static const struct { uint32_t recs; size_t runs; } steps[] = {
      {MFT_GROW_RECORDS, 8}, {64, 4}, {16, 2}, {4, 1}};
  for (size_t k = 0; k < sizeof steps / sizeof steps[0] && !rc; k++) {
    bytes = (uint64_t)steps[k].recs * v->rec_size;
    bytes = (bytes + v->cluster - 1) / v->cluster * v->cluster;
    clusters = bytes / v->cluster;
    new_recs = (v->mft.alloc + bytes) / v->rec_size;
    int r2 = alloc_and_mark(v, clusters, &fresh, vcn_end, steps[k].runs);
    if (!r2) break;
    if (r2 != -EFBIG) { rc = r2; break; }
    if (k + 1 == sizeof steps / sizeof steps[0]) rc = -ENOSPC;
  }
  v->alloc_hint = save_hint;
  if (rc) goto out;
  for (size_t i = 0; i < fresh.nruns && !rc; i++)
    rc = run_push(&grown, fresh.runs[i].vcn, fresh.runs[i].lcn, fresh.runs[i].len);
  if (rc) goto undo;

  /* Format the new records before the MFT points at them. */
  for (uint64_t r = v->mft.alloc / v->rec_size; r < new_recs && !rc; r++) {
    format_empty_record(v, blank, r, 1);
    put_le16(blank + 0x16, 0);
    rc = prepare_fixups(blank, v->rec_size);
    if (!rc) rc = write_raw(v, &grown, r * v->rec_size, blank, v->rec_size);
  }
  if (rc) goto undo;

  /* Initialise any records that were allocated but past init. */
  for (uint64_t r = old_recs; r < v->mft.alloc / v->rec_size && !rc; r++) {
    format_empty_record(v, blank, r, 1);
    rc = prepare_fixups(blank, v->rec_size);
    if (!rc) rc = write_raw(v, &grown, r * v->rec_size, blank, v->rec_size);
  }
  if (rc) goto undo;

  grown.alloc = v->mft.alloc + bytes;
  grown.size = grown.init = new_recs * v->rec_size;

  /* The MFT bitmap must have a bit for every record. */
  uint8_t *bat = rec_attr(rec0, v->rec_size, AT_BITMAP, NULL, 0);
  if (!bat) { rc = -EIO; goto undo; }
  uint64_t need_bytes = (new_recs + 63) / 64 * 8;
  if (!bat[8]) {
    uint32_t vlen = le32(bat + 16);
    if (need_bytes > vlen) {
      uint8_t *val = calloc(1, (size_t)need_bytes);
      if (!val) { rc = -ENOMEM; goto undo; }
      memcpy(val, bat + le16(bat + 20), vlen);
      rc = set_resident_value(rec0, bat, val, (uint32_t)need_bytes);
      free(val);
      if (rc) goto undo;
    }
  } else {
    rc = absorb(&bmp, bat, le32(bat + 4), 1);
    if (rc) goto undo;
    if (need_bytes > bmp.alloc) {
      uint64_t extra = (need_bytes - bmp.alloc + v->cluster - 1) / v->cluster;
      rc = alloc_and_mark(v, extra, &bmp, (int64_t)(bmp.alloc / v->cluster), 4);
      if (rc) goto undo;
      bmp.alloc += extra * v->cluster;
    }
    if (need_bytes > bmp.init) {
      size_t z = (size_t)(need_bytes - bmp.init);
      uint8_t *zero = calloc(1, z);
      if (!zero) { rc = -ENOMEM; goto undo; }
      rc = write_raw(v, &bmp, bmp.init, zero, z);
      free(zero);
      if (rc) goto undo;
      bmp.init = bmp.size = need_bytes;
    }
    rc = update_nonresident(rec0, v->rec_size, bat, &bmp);
    if (rc) goto undo;
  }

  uint8_t *dat = rec_attr(rec0, v->rec_size, AT_DATA, NULL, 0);
  if (!dat) { rc = -EIO; goto undo; }
  rc = update_nonresident(rec0, v->rec_size, dat, &grown);
  if (rc) goto undo;
  rc = write_record(v, INODE_MFT, rec0);
  if (rc) goto out; /* record may be half written: don't free its clusters */

  /* Switch the in-memory MFT over. */
  attr_free(&v->mft);
  v->mft = grown;
  memset(&grown, 0, sizeof grown);
  goto out;

undo:
  free_clusters(v, &fresh);
out:
  attr_free(&fresh);
  attr_free(&grown);
  attr_free(&bmp);
  free(rec0);
  free(blank);
  return rc;
}

/* Find and claim a free MFT record. Returns its number in *inode. */
static int alloc_record(ntfs_vol_t *v, uint64_t *inode) {
  for (int attempt = 0; attempt < 2; attempt++) {
    attr_t bm;
    int rc = attr_find(v, INODE_MFT, AT_BITMAP, NULL, 0, &bm);
    if (rc) return rc;
    uint64_t nrec = v->mft.init / v->rec_size;
    uint64_t limit = bm.size * 8 < nrec ? bm.size * 8 : nrec;
    uint64_t start = v->mft_hint >= FIRST_FREE_RECORD && v->mft_hint < limit
                         ? v->mft_hint : FIRST_FREE_RECORD;
    uint8_t buf[4096];
    uint64_t found = (uint64_t)-1;
    for (int pass = 0; pass < 2 && found == (uint64_t)-1; pass++) {
      uint64_t lo = pass ? FIRST_FREE_RECORD : start, hi = pass ? start : limit;
      for (uint64_t b = lo; b < hi && found == (uint64_t)-1;) {
        uint64_t byte0 = b / 8;
        size_t n = (size_t)((hi + 7) / 8 - byte0);
        if (n > sizeof buf) n = sizeof buf;
        if (attr_pread(v, &bm, byte0, buf, n) != (ssize_t)n) { attr_free(&bm); return -EIO; }
        for (uint64_t k = b; k < (byte0 + n) * 8 && k < hi; k++) {
          if (!(buf[k / 8 - byte0] & (1u << (k % 8)))) { found = k; break; }
        }
        b = (byte0 + n) * 8;
      }
    }
    if (found == (uint64_t)-1) {
      attr_free(&bm);
      if (attempt) return -ENOSPC;
      rc = extend_mft(v);
      if (rc) return rc;
      continue;
    }

    /* Claim the bit. */
    if (bm.resident) {
      uint8_t *rec0 = malloc(v->rec_size);
      rc = rec0 ? read_record(v, INODE_MFT, rec0) : -ENOMEM;
      uint8_t *bat = rc ? NULL : rec_attr(rec0, v->rec_size, AT_BITMAP, NULL, 0);
      if (!rc && (!bat || bat[8])) rc = -EIO;
      if (!rc) {
        bat[le16(bat + 20) + found / 8] |= (uint8_t)(1u << (found % 8));
        rc = write_record(v, INODE_MFT, rec0);
      }
      free(rec0);
    } else {
      rc = bitmap_set(v, &bm, found, 1, 1);
    }
    attr_free(&bm);
    if (rc) return rc;
    v->mft_hint = found + 1;
    *inode = found;
    return 0;
  }
  return -ENOSPC;
}

static void release_record(ntfs_vol_t *v, uint64_t inode) {
  attr_t bm;
  if (attr_find(v, INODE_MFT, AT_BITMAP, NULL, 0, &bm)) return;
  if (bm.resident) {
    uint8_t *rec0 = malloc(v->rec_size);
    if (rec0 && read_record(v, INODE_MFT, rec0) == 0) {
      uint8_t *bat = rec_attr(rec0, v->rec_size, AT_BITMAP, NULL, 0);
      if (bat && !bat[8]) {
        bat[le16(bat + 20) + inode / 8] &= (uint8_t)~(1u << (inode % 8));
        write_record(v, INODE_MFT, rec0);
      }
    }
    free(rec0);
  } else {
    bitmap_set(v, &bm, inode, 1, 0);
  }
  attr_free(&bm);
  /* Mark the record itself unused too. */
  uint8_t *rec = malloc(v->rec_size);
  if (rec && read_record_any(v, inode, rec) == 0) {
    put_le16(rec + 0x16, 0);
    write_record(v, inode, rec);
  }
  free(rec);
}

/* ---- Directory index insertion ------------------------------------------- */

typedef struct ient {
  uint8_t *p;
  uint32_t len;
} ient_t;

typedef struct xnode {
  ient_t  *e;
  int      n, cap;
  int      internal;  /* entries have sub-nodes */
  int64_t  vcn;       /* -1 for the root */
} xnode_t;

typedef struct ictx {
  ntfs_vol_t *v;
  uint64_t    dir;
  /* The record holding $INDEX_ROOT, and the one holding $INDEX_ALLOCATION
   * and $BITMAP. Usually both are the directory's base record (arec == rec);
   * big folders can have them in extension records via an attribute list. */
  uint8_t    *rec;
  uint64_t    rec_ino;
  uint8_t    *arec;
  uint64_t    arec_ino;
  int         arec_dirty;
  int         has_list;
  uint32_t    ibs;      /* index block size */
  uint32_t    vcn_unit;
  attr_t      alloc;    /* $INDEX_ALLOCATION:$I30 */
  int         has_alloc;
  int         rec_dirty;
} ictx_t;

static void node_free(xnode_t *x) {
  for (int i = 0; i < x->n; i++) free(x->e[i].p);
  free(x->e);
  memset(x, 0, sizeof *x);
}

static int node_insert(xnode_t *x, int at, uint8_t *p, uint32_t len) {
  if (x->n == x->cap) {
    int nc = x->cap ? x->cap * 2 : 16;
    ient_t *e = realloc(x->e, (size_t)nc * sizeof *e);
    if (!e) return -ENOMEM;
    x->e = e;
    x->cap = nc;
  }
  memmove(&x->e[at + 1], &x->e[at], (size_t)(x->n - at) * sizeof *x->e);
  x->e[at].p = p;
  x->e[at].len = len;
  x->n++;
  return 0;
}

static int node_parse(xnode_t *x, const uint8_t *p, const uint8_t *end) {
  while (p + 16 <= end) {
    uint32_t len = le16(p + 8);
    uint16_t flags = le16(p + 12);
    if (len < 16 || p + len > end || (len & 7)) return -EIO;
    uint8_t *c = malloc(len);
    if (!c) return -ENOMEM;
    memcpy(c, p, len);
    if (node_insert(x, x->n, c, len)) { free(c); return -ENOMEM; }
    if (flags & IE_NODE) x->internal = 1;
    if (flags & IE_LAST) return 0;
    p += len;
  }
  return -EIO; /* no terminating entry */
}

static uint32_t node_bytes(const xnode_t *x) {
  uint32_t t = 0;
  for (int i = 0; i < x->n; i++) t += x->e[i].len;
  return t;
}

static int ie_has_sub(const ient_t *e) { return (le16(e->p + 12) & IE_NODE) != 0; }
static int ie_is_end(const ient_t *e) { return (le16(e->p + 12) & IE_LAST) != 0; }
static int64_t ie_sub(const ient_t *e) { return (int64_t)le64(e->p + e->len - 8); }

/* Give an entry a sub-node pointer (adding the 8-byte field if needed). */
static int ie_set_sub(ient_t *e, int64_t vcn) {
  if (!ie_has_sub(e)) {
    uint8_t *n = realloc(e->p, e->len + 8);
    if (!n) return -ENOMEM;
    e->p = n;
    e->len += 8;
    put_le16(e->p + 8, (uint16_t)e->len);
    put_le16(e->p + 12, (uint16_t)(le16(e->p + 12) | IE_NODE));
  }
  put_le64(e->p + e->len - 8, (uint64_t)vcn);
  return 0;
}

static ient_t make_end(void) {
  ient_t e = {calloc(1, 16), 16};
  if (e.p) {
    put_le16(e.p + 8, 16);
    put_le16(e.p + 12, IE_LAST);
  }
  return e;
}

/* NTFS file name collation: case-insensitive via $UpCase, then exact. */
static int collate(const ntfs_vol_t *v, const uint16_t *a, int al, const uint8_t *b,
                   int bl) {
  int n = al < bl ? al : bl;
  for (int i = 0; i < n; i++) {
    uint16_t x = up(v, a[i]), y = up(v, le16(b + i * 2));
    if (x != y) return x < y ? -1 : 1;
  }
  if (al != bl) return al < bl ? -1 : 1;
  return 0;
}

static int entry_cmp(const ntfs_vol_t *v, const uint16_t *name, int nlen,
                     const ient_t *e) {
  if (ie_is_end(e)) return -1;
  const uint8_t *fn = e->p + 16;
  return collate(v, name, nlen, fn + 0x42, fn[0x40]);
}

static int load_block(ictx_t *c, int64_t vcn, xnode_t *x) {
  uint8_t *b = malloc(c->ibs);
  if (!b) return -ENOMEM;
  int rc = 0;
  if (attr_pread(c->v, &c->alloc, (uint64_t)vcn * c->vcn_unit, b, c->ibs) != (ssize_t)c->ibs ||
      memcmp(b, "INDX", 4) || apply_fixups(b, c->ibs))
    rc = -EIO;
  if (!rc) {
    const uint8_t *h = b + 0x18;
    uint32_t eo = le32(h), il = le32(h + 4);
    if (0x18 + (uint64_t)il > c->ibs || eo >= il) rc = -EIO;
    else rc = node_parse(x, h + eo, h + il);
    x->vcn = vcn;
    if (!rc) x->internal = (h[12] & 1) != 0;
  }
  free(b);
  return rc;
}

static uint32_t block_entries_offset(uint32_t ibs) {
  return align8(0x28 + (ibs / 512 + 1) * 2) - 0x18;
}

static int block_fits(const ictx_t *c, const xnode_t *x) {
  return block_entries_offset(c->ibs) + node_bytes(x) <= c->ibs - 0x18;
}

static int write_block(ictx_t *c, const xnode_t *x) {
  uint8_t *b = calloc(1, c->ibs);
  if (!b) return -ENOMEM;
  uint16_t usa_cnt = (uint16_t)(c->ibs / 512 + 1);
  memcpy(b, "INDX", 4);
  put_le16(b + 4, 0x28);
  put_le16(b + 6, usa_cnt);
  put_le64(b + 0x10, (uint64_t)x->vcn);
  put_le16(b + 0x28, 1);
  uint32_t eo = block_entries_offset(c->ibs);
  uint8_t *h = b + 0x18, *p = h + eo;
  for (int i = 0; i < x->n; i++) {
    memcpy(p, x->e[i].p, x->e[i].len);
    p += x->e[i].len;
  }
  put_le32(h, eo);
  put_le32(h + 4, eo + node_bytes(x));
  put_le32(h + 8, c->ibs - 0x18);
  h[12] = x->internal ? 1 : 0;
  int rc = prepare_fixups(b, c->ibs);
  if (!rc) rc = write_raw(c->v, &c->alloc, (uint64_t)x->vcn * c->vcn_unit, b, c->ibs);
  free(b);
  return rc;
}

/* Rebuild $INDEX_ROOT's value from a node. */
static int store_root(ictx_t *c, const xnode_t *x) {
  uint8_t *at = rec_attr(c->rec, c->v->rec_size, AT_INDEX_ROOT, I30, 4);
  if (!at || at[8]) return -EIO;
  const uint8_t *old = at + le16(at + 20);
  uint32_t ebytes = node_bytes(x), vlen = 0x20 + ebytes;
  uint8_t *val = malloc(vlen);
  if (!val) return -ENOMEM;
  memcpy(val, old, 0x10);
  put_le32(val + 0x10, 0x10);
  put_le32(val + 0x14, 0x10 + ebytes);
  put_le32(val + 0x18, 0x10 + ebytes);
  memset(val + 0x1C, 0, 4);
  val[0x1C] = x->internal ? 1 : 0;
  uint8_t *p = val + 0x20;
  for (int i = 0; i < x->n; i++) {
    memcpy(p, x->e[i].p, x->e[i].len);
    p += x->e[i].len;
  }
  int rc = set_resident_value(c->rec, at, val, vlen);
  free(val);
  if (!rc) c->rec_dirty = 1;
  return rc;
}

/* Root edits must leave room for the rest of the record. */
static int root_fits(ictx_t *c, const xnode_t *x) {
  uint8_t *at = rec_attr(c->rec, c->v->rec_size, AT_INDEX_ROOT, I30, 4);
  if (!at) return 0;
  uint32_t cur = le32(at + 4);
  uint32_t want = align8(le16(at + 20) + 0x20 + node_bytes(x));
  uint32_t used = le32(c->rec + 0x18), cap = le32(c->rec + 0x1C);
  /* Keep a quarter of the record free, as Windows effectively does, so later
   * changes by any driver rarely need an attribute list. */
  return used - cur + want <= cap - cap / 4;
}

/* Add capacity to $INDEX_ALLOCATION (and size $BITMAP to match). Reserve
 * more as the folder grows (like Windows does) and try to extend the last
 * extent, so even huge folders need only a few extents in their record. */
static int grow_index_alloc(ictx_t *c) {
  ntfs_vol_t *v = c->v;
  uint8_t *rec = c->arec;
  uint64_t nblocks = c->alloc.size / c->ibs;
  uint64_t grow_blocks = nblocks ? nblocks : 1;
  uint64_t max_blocks = (1024 * 1024) / c->ibs;
  if (grow_blocks > max_blocks) grow_blocks = max_blocks ? max_blocks : 1;
  uint64_t clusters = (grow_blocks * c->ibs + v->cluster - 1) / v->cluster;
  int64_t vcn_end = (int64_t)(c->alloc.alloc / v->cluster);
  const run_t *last = c->alloc.nruns ? &c->alloc.runs[c->alloc.nruns - 1] : NULL;
  uint64_t save_hint = v->alloc_hint;
  if (last && last->lcn >= 0) v->alloc_hint = (uint64_t)last->lcn + last->len;
  attr_t fresh = {0};
  fresh.cu_idx = -1;
  int rc = alloc_and_mark(v, clusters, &fresh, vcn_end, 4);
  if (rc == -EFBIG || rc == -ENOSPC) {
    free(fresh.runs);
    memset(&fresh, 0, sizeof fresh);
    fresh.cu_idx = -1;
    clusters = (c->ibs + v->cluster - 1) / v->cluster;
    rc = alloc_and_mark(v, clusters, &fresh, vcn_end, 1);
  }
  v->alloc_hint = save_hint;
  if (rc) { free(fresh.runs); return rc; }

  attr_t grown = {0};
  grown.cu_idx = -1;
  for (size_t i = 0; i < c->alloc.nruns && !rc; i++)
    rc = run_push(&grown, c->alloc.runs[i].vcn, c->alloc.runs[i].lcn, c->alloc.runs[i].len);
  for (size_t i = 0; i < fresh.nruns && !rc; i++)
    rc = run_push(&grown, fresh.runs[i].vcn, fresh.runs[i].lcn, fresh.runs[i].len);
  grown.alloc = c->alloc.alloc + clusters * v->cluster;
  grown.size = grown.init = grown.alloc;

  /* Make a copy of the record so a failure leaves it untouched. */
  uint8_t *copy = rc ? NULL : malloc(v->rec_size);
  if (!rc && !copy) rc = -ENOMEM;
  if (!rc) memcpy(copy, rec, v->rec_size);
  uint8_t *ia = rc ? NULL : rec_attr(copy, v->rec_size, AT_INDEX_ALLOCATION, I30, 4);
  if (!rc) rc = ia ? update_nonresident(copy, v->rec_size, ia, &grown) : -EIO;
  if (!rc) {
    /* The bitmap needs a bit per block, in 8-byte steps. */
    uint8_t *bat = rec_attr(copy, v->rec_size, AT_BITMAP, I30, 4);
    uint64_t blocks = grown.size / c->ibs;
    uint32_t need = (uint32_t)((blocks + 63) / 64 * 8);
    if (!bat || bat[8]) rc = -ENOTSUP;
    else if (le32(bat + 16) < need) {
      uint8_t *val = calloc(1, need);
      if (!val) rc = -ENOMEM;
      else {
        memcpy(val, bat + le16(bat + 20), le32(bat + 16));
        rc = set_resident_value(copy, bat, val, need);
        free(val);
      }
    }
  }
  if (rc) {
    free(copy);
    free_clusters(v, &fresh);
    free(fresh.runs);
    attr_free(&grown);
    return rc;
  }
  memcpy(rec, copy, v->rec_size);
  free(copy);
  free(fresh.runs);
  attr_free(&c->alloc);
  c->alloc = grown;
  c->arec_dirty = 1;
  return 0;
}

static uint64_t free_index_blocks(ictx_t *c) {
  uint8_t *bat = rec_attr(c->arec, c->v->rec_size, AT_BITMAP, I30, 4);
  if (!bat || bat[8]) return 0;
  uint32_t blen = le32(bat + 16);
  const uint8_t *bits = bat + le16(bat + 20);
  uint64_t nblocks = c->alloc.size / c->ibs, n = 0;
  for (uint64_t b = 0; b < nblocks && b < (uint64_t)blen * 8; b++)
    if (!(bits[b / 8] & (1u << (b % 8)))) n++;
  return n;
}

/* Make sure `need` index blocks can be claimed without allocating, so an
 * insertion never fails half way through for lack of space. */
static int reserve_blocks(ictx_t *c, uint64_t need) {
  if (!c->has_alloc) return 0; /* the first block is created up front */
  for (int guard = 0; guard < 64; guard++) {
    if (free_index_blocks(c) >= need) return 0;
    int rc = grow_index_alloc(c);
    if (rc) return rc;
  }
  return -ENOSPC;
}

/* Allocate a new index block (creating $INDEX_ALLOCATION if needed). */
static int new_block(ictx_t *c, int64_t *vcn_out) {
  ntfs_vol_t *v = c->v;
  uint8_t *rec = c->arec;
  int rc;

  if (!c->has_alloc) {
    /* Adding attributes to a folder with an attribute list would mean
     * editing the list too; not supported. */
    if (c->has_list) return -ENOTSUP;
    /* First block: create $INDEX_ALLOCATION and $BITMAP. */
    uint64_t clusters = (c->ibs + v->cluster - 1) / v->cluster;
    attr_t a = {0};
    a.cu_idx = -1;
    rc = alloc_and_mark(v, clusters, &a, 0, 1);
    if (rc) { free(a.runs); return rc; }
    a.alloc = clusters * v->cluster;
    a.size = a.init = a.alloc;
    uint8_t tmp[256];
    int len = build_nonresident(tmp, sizeof tmp, AT_INDEX_ALLOCATION, I30, 4, &a, 0);
    uint8_t bits[8] = {0};
    uint8_t btmp[64];
    build_resident(btmp, AT_BITMAP, I30, 4, bits, 8, 0);
    rc = len < 0 ? len : rec_insert(rec, v->rec_size, tmp);
    if (!rc) rc = rec_insert(rec, v->rec_size, btmp);
    if (rc) { free_clusters(v, &a); free(a.runs); return rc; }
    c->alloc = a;
    c->has_alloc = 1;
    c->arec_dirty = 1;
  }

  uint8_t *bat = rec_attr(rec, v->rec_size, AT_BITMAP, I30, 4);
  if (!bat || bat[8]) return -ENOTSUP; /* non-resident index bitmap */
  uint64_t nblocks = c->alloc.size / c->ibs;
  uint64_t b;
  for (int attempt = 0; attempt < 2; attempt++) {
    uint32_t blen = le32(bat + 16);
    uint8_t *bits = bat + le16(bat + 20);
    for (b = 0; b < nblocks && b < (uint64_t)blen * 8; b++)
      if (!(bits[b / 8] & (1u << (b % 8)))) break;
    if (b < nblocks && b < (uint64_t)blen * 8) break;
    /* Only reached when nothing was reserved (e.g. the root split path). */
    rc = grow_index_alloc(c);
    if (rc) return rc;
    bat = rec_attr(rec, v->rec_size, AT_BITMAP, I30, 4);
    nblocks = c->alloc.size / c->ibs;
  }
  if (b >= nblocks || b / 8 >= le32(bat + 16)) return -ENOSPC;
  bat[le16(bat + 20) + b / 8] |= (uint8_t)(1u << (b % 8));
  c->arec_dirty = 1;
  *vcn_out = (int64_t)(b * c->ibs / c->vcn_unit);
  return 0;
}

/* Split an overflowing block into a new left block and itself (right).
 * Returns the entry to push up (with sub = left block). */
static int split_block(ictx_t *c, xnode_t *x, ient_t *up_out) {
  int keys = x->n - 1; /* excluding END */
  uint32_t total = node_bytes(x) - x->e[x->n - 1].len, acc = 0;
  int m = 0;
  while (m < keys - 1 && acc + x->e[m].len < total / 2) acc += x->e[m++].len;
  if (m < 1) m = 1;
  if (m >= keys) m = keys - 1;

  xnode_t left = {0};
  left.internal = x->internal;
  int rc = new_block(c, &left.vcn);
  for (int i = 0; i < m && !rc; i++) {
    rc = node_insert(&left, left.n, x->e[i].p, x->e[i].len);
    if (!rc) x->e[i].p = NULL;
  }
  ient_t mid = x->e[m];
  ient_t end = rc ? (ient_t){0} : make_end();
  if (!rc && !end.p) rc = -ENOMEM;
  if (!rc && ie_has_sub(&mid)) rc = ie_set_sub(&end, ie_sub(&mid));
  if (!rc) rc = node_insert(&left, left.n, end.p, end.len);
  if (rc) { free(end.p); node_free(&left); return rc; }

  /* Right keeps entries after the median (and the original END). */
  for (int i = 0; i < m; i++) free(x->e[i].p);
  memmove(&x->e[0], &x->e[m + 1], (size_t)(x->n - m - 1) * sizeof *x->e);
  x->n -= m + 1;

  int64_t left_vcn = left.vcn;
  rc = write_block(c, &left);
  node_free(&left);
  if (rc) { free(mid.p); return rc; }
  rc = ie_set_sub(&mid, left_vcn);
  if (rc) { free(mid.p); return rc; }
  *up_out = mid;
  return 0;
}

/* Which record holds the $I30 attribute `type` of a directory with an
 * attribute list. *nseg (optional) gets the number of segments. */
static int locate_attr(ntfs_vol_t *v, uint64_t dir, uint32_t type, uint64_t *ino, int *nseg) {
  uint8_t *rec = malloc(v->rec_size);
  if (!rec) return -ENOMEM;
  int rc = read_record(v, dir, rec);
  uint8_t *la = rc ? NULL : rec_attr(rec, v->rec_size, AT_ATTRIBUTE_LIST, NULL, 0);
  attr_t a = {0};
  a.cu_idx = -1;
  uint8_t *buf = NULL;
  if (!rc && !la) rc = -EIO;
  if (!rc) rc = absorb(&a, la, le32(la + 4), 1);
  if (!rc && a.size > 65536) rc = -ENOTSUP;
  if (!rc && !(buf = malloc((size_t)a.size + 1))) rc = -ENOMEM;
  if (!rc && attr_pread(v, &a, 0, buf, (size_t)a.size) != (ssize_t)a.size) rc = -EIO;
  int found = 0;
  for (size_t p = 0; !rc && p + 26 <= a.size;) {
    const uint8_t *e = buf + p;
    uint16_t elen = le16(e + 4);
    if (elen < 26 || p + elen > a.size) break;
    p += elen;
    if (le32(e) != type || e[6] != 4) continue;
    int match = 1;
    for (int i = 0; i < 4; i++)
      if (le16(e + e[7] + i * 2) != I30[i]) match = 0;
    if (!match) continue;
    if (!found || le64(e + 8) == 0) *ino = MREF(le64(e + 16));
    found++;
  }
  if (!rc && !found) rc = -ENOENT;
  if (nseg) *nseg = found;
  free(buf);
  attr_free(&a);
  free(rec);
  return rc;
}

static int index_insert(ntfs_vol_t *v, uint64_t dir, const uint8_t *key,
                        uint32_t klen, uint64_t ref) {
  ictx_t c = {0};
  c.v = v;
  c.dir = dir;
  c.alloc.cu_idx = -1;
  xnode_t path[MAX_DEPTH];
  int pos[MAX_DEPTH], depth = 0;
  memset(path, 0, sizeof path);
  ient_t ne = {0};
  int rc;

  c.rec = malloc(v->rec_size);
  if (!c.rec) return -ENOMEM;
  c.arec = c.rec;
  c.rec_ino = c.arec_ino = dir;
  rc = read_record(v, dir, c.rec);
  if (rc) goto out;
  if (rec_attr(c.rec, v->rec_size, AT_ATTRIBUTE_LIST, NULL, 0)) {
    c.has_list = 1;
    uint64_t ri = 0, ai = 0, bi = 0;
    int nseg = 0;
    rc = locate_attr(v, dir, AT_INDEX_ROOT, &ri, NULL);
    if (rc) goto out;
    int ia = locate_attr(v, dir, AT_INDEX_ALLOCATION, &ai, &nseg);
    if (ia && ia != -ENOENT) { rc = ia; goto out; }
    if (!ia && (nseg != 1 || locate_attr(v, dir, AT_BITMAP, &bi, NULL) || bi != ai)) {
      rc = -ENOTSUP;
      goto out;
    }
    if (ri != dir) {
      rc = read_record_any(v, ri, c.rec);
      if (rc) goto out;
      c.rec_ino = ri;
    }
    if (!ia && ai != ri) {
      c.arec = malloc(v->rec_size);
      if (!c.arec) { rc = -ENOMEM; goto out; }
      rc = read_record_any(v, ai, c.arec);
      if (rc) goto out;
      c.arec_ino = ai;
    } else {
      c.arec_ino = ri;
    }
  }

  uint8_t *ra = rec_attr(c.rec, v->rec_size, AT_INDEX_ROOT, I30, 4);
  if (!ra || ra[8]) { rc = -ENOTDIR; goto out; }
  const uint8_t *rv = ra + le16(ra + 20);
  if (le32(rv) != AT_FILE_NAME || le32(rv + 4) != 1) { rc = -ENOTSUP; goto out; }
  c.ibs = le32(rv + 8);
  if (c.ibs < 512 || c.ibs > 65536) { rc = -EIO; goto out; }
  c.vcn_unit = v->cluster <= c.ibs ? v->cluster : 512;
  if (attr_find(v, dir, AT_INDEX_ALLOCATION, I30, 4, &c.alloc) == 0) c.has_alloc = 1;

  /* New entry. */
  ne.len = align8(16 + klen);
  ne.p = calloc(1, ne.len);
  if (!ne.p) { rc = -ENOMEM; goto out; }
  put_le64(ne.p, ref);
  put_le16(ne.p + 8, (uint16_t)ne.len);
  put_le16(ne.p + 10, (uint16_t)klen);
  memcpy(ne.p + 16, key, klen);
  uint16_t name[255];
  int nlen = key[0x40];
  for (int i = 0; i < nlen; i++) name[i] = le16(key + 0x42 + i * 2);

  /* Descend to the leaf. */
  {
    const uint8_t *h = rv + 0x10;
    uint32_t eo = le32(h), il = le32(h + 4);
    path[0].vcn = -1;
    rc = node_parse(&path[0], h + eo, h + il);
    if (rc) goto out;
    path[0].internal = (h[12] & 1) != 0 || path[0].internal;
  }
  for (;;) {
    xnode_t *x = &path[depth];
    int i = 0;
    for (; i < x->n; i++) {
      int cmp = entry_cmp(v, name, nlen, &x->e[i]);
      if (cmp == 0) { rc = -EEXIST; goto out; }
      if (cmp < 0) break;
    }
    if (i == x->n) { rc = -EIO; goto out; }
    pos[depth] = i;
    if (!ie_has_sub(&x->e[i])) break;
    if (!c.has_alloc || depth + 1 >= MAX_DEPTH) { rc = -EIO; goto out; }
    depth++;
    rc = load_block(&c, ie_sub(&x->e[i]), &path[depth]);
    if (rc) goto out;
  }

  /* Each level may split, plus a new block if the root moves down. */
  rc = reserve_blocks(&c, (uint64_t)depth + 2);
  if (rc) goto out;

  /* Insert into the leaf, then fix overflows bottom-up. */
  rc = node_insert(&path[depth], pos[depth], ne.p, ne.len);
  if (rc) goto out;
  ne.p = NULL;

  for (int d = depth; d >= 0; d--) {
    xnode_t *x = &path[d];
    if (d > 0) {
      if (block_fits(&c, x)) { rc = write_block(&c, x); break; }
      ient_t upe;
      rc = split_block(&c, x, &upe);
      if (!rc) rc = write_block(&c, x);
      if (!rc) rc = node_insert(&path[d - 1], pos[d - 1], upe.p, upe.len);
      if (rc) break;
      continue;
    }
    /* Root. */
    if (root_fits(&c, x)) { rc = store_root(&c, x); break; }
    /* Move everything into a new block; the root keeps just END -> block. */
    xnode_t child = *x;
    memset(x, 0, sizeof *x);
    /* Shrink the root first so the record has room for the new
     * $INDEX_ALLOCATION/$BITMAP attributes. */
    {
      xnode_t tmp = {0};
      ient_t e0 = make_end();
      rc = e0.p ? node_insert(&tmp, 0, e0.p, e0.len) : -ENOMEM;
      if (rc) free(e0.p);
      if (!rc) rc = store_root(&c, &tmp);
      node_free(&tmp);
    }
    if (!rc) rc = new_block(&c, &child.vcn);
    if (rc) { node_free(&child); break; }
    while (!rc && !block_fits(&c, &child)) {
      /* Too big for one block: split it, the median goes into the root. */
      ient_t upe;
      rc = split_block(&c, &child, &upe);
      if (!rc) rc = node_insert(x, x->n, upe.p, upe.len);
    }
    if (!rc) rc = write_block(&c, &child);
    int64_t cv = child.vcn;
    node_free(&child);
    if (rc) break;
    ient_t end = make_end();
    if (!end.p) { rc = -ENOMEM; break; }
    rc = ie_set_sub(&end, cv);
    if (!rc) rc = node_insert(x, x->n, end.p, end.len);
    if (rc) { free(end.p); break; }
    x->internal = 1;
    rc = store_root(&c, x);
    break;
  }

  if (c.arec == c.rec && c.arec_dirty) c.rec_dirty = 1;
  if (!rc && c.arec != c.rec && c.arec_dirty) rc = write_record(v, c.arec_ino, c.arec);
  if (!rc && c.rec_dirty) rc = write_record(v, c.rec_ino, c.rec);

out:
  if (c.arec && c.arec != c.rec) free(c.arec);
  free(ne.p);
  for (int d = 0; d < MAX_DEPTH; d++) node_free(&path[d]);
  attr_free(&c.alloc);
  free(c.rec);
  return rc;
}

/* ---- Creating files and folders ------------------------------------------ */

typedef struct exist_ctx {
  ntfs_vol_t     *v;
  const uint16_t *name;
  int             nlen;
  int             found;
} exist_ctx_t;

static int exist_cb(void *ctx, uint64_t ref, const uint8_t *fn, uint16_t fnlen) {
  exist_ctx_t *e = ctx;
  (void)ref;
  if (fn[0x40] != e->nlen || 0x42u + fn[0x40] * 2u > fnlen) return 0;
  if (collate(e->v, e->name, e->nlen, fn + 0x42, fn[0x40]) == 0) {
    e->found = 1;
    return 1;
  }
  return 0;
}

static int check_name(const char *name, uint16_t *out, int *nlen) {
  if (!*name || strchr(name, '/') || !strcmp(name, ".") || !strcmp(name, ".."))
    return -EINVAL;
  int n = utf8_to_utf16(name, out, 255);
  if (n <= 0) return -ENAMETOOLONG;
  *nlen = n;
  return 0;
}

/* Build $FILE_NAME value. */
static uint32_t make_fn(uint8_t *fn, uint64_t parent_ref, const uint16_t *name, int nlen,
                        uint64_t ct, uint64_t mt, uint64_t alloc, uint64_t size,
                        uint32_t fattr) {
  uint32_t len = 0x42 + (uint32_t)nlen * 2;
  memset(fn, 0, len);
  put_le64(fn, parent_ref);
  put_le64(fn + 0x08, ct);
  put_le64(fn + 0x10, mt);
  put_le64(fn + 0x18, ct);
  put_le64(fn + 0x20, ct);
  put_le64(fn + 0x28, alloc);
  put_le64(fn + 0x30, size);
  put_le32(fn + 0x38, fattr);
  fn[0x40] = (uint8_t)nlen;
  fn[0x41] = NS_POSIX;
  for (int i = 0; i < nlen; i++) put_le16(fn + 0x42 + i * 2, name[i]);
  return len;
}

/* Common part of mkdir/create: returns the new record (unprotected) with
 * $STANDARD_INFORMATION, $FILE_NAME and $SECURITY_DESCRIPTOR, plus the key
 * for the parent's index. */
static int start_record(ntfs_vol_t *v, uint64_t parent, const uint16_t *name, int nlen,
                        int is_dir, uint64_t alloc, uint64_t size, int64_t mtime,
                        uint8_t *rec, uint8_t *key, uint32_t *klen, uint64_t *ino,
                        uint64_t *ref) {
  /* Parent must be a directory we can read; get its sequence number. */
  uint8_t *prec = malloc(v->rec_size);
  if (!prec) return -ENOMEM;
  int rc = read_record(v, parent, prec);
  if (!rc && !(le16(prec + 0x16) & MFT_DIRECTORY)) rc = -ENOTDIR;
  uint64_t parent_ref = parent | (uint64_t)le16(prec + MFT_HDR_SEQ) << 48;
  free(prec);
  if (rc) return rc;

  exist_ctx_t ex = {v, name, nlen, 0};
  rc = index_walk(v, parent, exist_cb, &ex);
  if (rc < 0) return rc;
  if (ex.found) return -EEXIST;

  rc = alloc_record(v, ino);
  if (rc) return rc;
  uint16_t seq = 1;
  if (read_record_any(v, *ino, rec) == 0) {
    seq = (uint16_t)(le16(rec + MFT_HDR_SEQ) + 1);
    if (!seq) seq = 1;
  }
  format_empty_record(v, rec, *ino, seq);
  put_le16(rec + 0x12, 1);
  put_le16(rec + 0x16, MFT_IN_USE | (is_dir ? MFT_DIRECTORY : 0));
  *ref = *ino | (uint64_t)seq << 48;

  uint64_t now = now_nt(), mt = mtime > 0 ? unix2nt(mtime) : now;
  uint8_t si[48] = {0};
  put_le64(si, mt);
  put_le64(si + 0x08, mt);
  put_le64(si + 0x10, now);
  put_le64(si + 0x18, now);
  put_le32(si + 0x20, FA_ARCHIVE);

  uint8_t abuf[1024];
  uint32_t l = build_resident(abuf, AT_STANDARD_INFORMATION, NULL, 0, si, sizeof si, 0);
  rc = rec_insert(rec, v->rec_size, abuf);
  uint32_t fattr = FA_ARCHIVE | (is_dir ? FA_DUP_I30 : 0);
  *klen = make_fn(key, parent_ref, name, nlen, mt, mt, alloc, size, fattr);
  if (!rc) {
    l = build_resident(abuf, AT_FILE_NAME, NULL, 0, key, *klen, 1);
    rc = rec_insert(rec, v->rec_size, abuf);
  }
  if (!rc) {
    l = build_resident(abuf, AT_SECURITY_DESCRIPTOR, NULL, 0, SD_DEFAULT,
                       sizeof SD_DEFAULT, 0);
    rc = rec_insert(rec, v->rec_size, abuf);
  }
  (void)l;
  if (rc) release_record(v, *ino);
  return rc;
}

static int finish_record(ntfs_vol_t *v, uint64_t parent, uint64_t ino, uint64_t ref,
                         const uint8_t *rec, const uint8_t *key, uint32_t klen) {
  int rc = write_record(v, ino, rec);
  if (!rc) rc = index_insert(v, parent, key, klen, ref);
  if (rc) release_record(v, ino);
  bdev_flush(v->dev);
  return rc;
}

int ntfs_mkdir(ntfs_vol_t *v, uint64_t parent, const char *name, int64_t mtime,
               uint64_t *inode) {
  uint16_t n16[255];
  int nlen, rc = check_name(name, n16, &nlen);
  if (rc) return rc;
  pthread_mutex_lock(&v->lock);
  if (!v->rw) { pthread_mutex_unlock(&v->lock); return -EROFS; }
  uint8_t *rec = malloc(v->rec_size), key[0x42 + 510];
  uint32_t klen;
  uint64_t ino, ref;
  rc = rec ? start_record(v, parent, n16, nlen, 1, 0, 0, mtime, rec, key, &klen, &ino, &ref)
           : -ENOMEM;
  if (!rc) {
    /* Empty $INDEX_ROOT:$I30. */
    uint8_t val[0x30] = {0};
    put_le32(val, AT_FILE_NAME);
    put_le32(val + 4, 1);
    put_le32(val + 8, v->idx_size);
    val[12] = (uint8_t)(v->idx_size >= v->cluster ? v->idx_size / v->cluster
                                                  : v->idx_size / 512);
    put_le32(val + 0x10, 0x10);
    put_le32(val + 0x14, 0x20);
    put_le32(val + 0x18, 0x20);
    put_le16(val + 0x20 + 8, 16);
    put_le16(val + 0x20 + 12, IE_LAST);
    uint8_t abuf[128];
    build_resident(abuf, AT_INDEX_ROOT, I30, 4, val, sizeof val, 0);
    rc = rec_insert(rec, v->rec_size, abuf);
    if (rc) release_record(v, ino);
  }
  if (!rc) rc = finish_record(v, parent, ino, ref, rec, key, klen);
  if (!rc && inode) *inode = ino;
  free(rec);
  pthread_mutex_unlock(&v->lock);
  return rc;
}

int ntfs_create(ntfs_vol_t *v, uint64_t parent, const char *name, uint64_t size,
                int64_t mtime, ntfs_wfile_t **out) {
  uint16_t n16[255];
  int nlen, rc = check_name(name, n16, &nlen);
  if (rc) return rc;
  ntfs_wfile_t *f = calloc(1, sizeof *f);
  if (!f) return -ENOMEM;
  f->a.cu_idx = -1;
  pthread_mutex_lock(&v->lock);
  if (!v->rw) { pthread_mutex_unlock(&v->lock); free(f); return -EROFS; }

  uint8_t *rec = malloc(v->rec_size), key[0x42 + 510];
  uint32_t klen = 0;
  uint64_t ino = 0, ref = 0;
  uint64_t clusters = (size + v->cluster - 1) / v->cluster;
  uint64_t alloc = clusters * v->cluster;
  if (!rec) rc = -ENOMEM;

  /* Space first: how many runs fit depends on the name length. */
  if (!rc && clusters) {
    uint32_t fixed = align8(0x30 + (v->rec_size / 512 + 1) * 2) + /* header */
                     (0x18 + 48) +                                 /* SI */
                     align8(0x18 + 0x42 + (uint32_t)nlen * 2) +    /* FN */
                     align8(0x18 + sizeof SD_DEFAULT) +           /* SD */
                     0x40 + 8 + 8;                                 /* DATA hdr, end */
    size_t space = v->rec_size > fixed ? v->rec_size - fixed : 0;
    size_t max_runs = space / 12; /* worst case bytes per run on big volumes */
    if (max_runs < 1) rc = -ENAMETOOLONG;
    else rc = alloc_and_mark(v, clusters, &f->a, 0, max_runs);
    if (rc == -EFBIG) rc = -ENOSPC; /* free space too fragmented */
  }
  f->a.alloc = alloc;
  f->a.size = size;
  f->a.init = 0;

  if (!rc) rc = start_record(v, parent, n16, nlen, 0, alloc, size, mtime, rec, key, &klen,
                             &ino, &ref);
  if (!rc) {
    uint8_t abuf[1024];
    if (clusters) {
      int l = build_nonresident(abuf, sizeof abuf, AT_DATA, NULL, 0, &f->a, 0);
      rc = l < 0 ? l : rec_insert(rec, v->rec_size, abuf);
    } else {
      build_resident(abuf, AT_DATA, NULL, 0, NULL, 0, 0);
      rc = rec_insert(rec, v->rec_size, abuf);
    }
    if (rc) release_record(v, ino);
    if (!rc) rc = finish_record(v, parent, ino, ref, rec, key, klen);
  }
  if (rc && clusters) free_clusters(v, &f->a);
  free(rec);
  pthread_mutex_unlock(&v->lock);
  if (rc) {
    attr_free(&f->a);
    free(f);
    return rc;
  }
  f->v = v;
  f->inode = ino;
  *out = f;
  return 0;
}

int ntfs_wopen(ntfs_vol_t *v, uint64_t inode, ntfs_wfile_t **out, uint64_t *done) {
  ntfs_wfile_t *f = calloc(1, sizeof *f);
  if (!f) return -ENOMEM;
  pthread_mutex_lock(&v->lock);
  int rc = v->rw ? attr_find(v, inode, AT_DATA, NULL, 0, &f->a) : -EROFS;
  if (!rc && (f->a.flags & (ATTR_COMPRESSED | ATTR_ENCRYPTED | ATTR_SPARSE)))
    rc = -ENOTSUP;
  if (!rc && f->a.resident && f->a.size) rc = -ENOTSUP;
  if (!rc && !f->a.resident) {
    /* Everything up to the size must be backed by clusters. */
    uint64_t need = (f->a.size + v->cluster - 1) / v->cluster, have = 0;
    for (size_t i = 0; i < f->a.nruns; i++)
      if (f->a.runs[i].lcn >= 0) have += f->a.runs[i].len;
    if (have < need) rc = -ENOTSUP;
  }
  pthread_mutex_unlock(&v->lock);
  if (rc) { attr_free(&f->a); free(f); return rc; }
  f->v = v;
  f->inode = inode;
  f->pos = f->flushed = f->a.resident ? 0 : f->a.init;
  *done = f->a.resident ? f->a.size : f->pos;
  *out = f;
  return 0;
}

static int store_init(ntfs_wfile_t *f) {
  ntfs_vol_t *v = f->v;
  if (f->a.resident || f->flushed == f->pos) return 0;
  uint8_t *rec = malloc(v->rec_size);
  if (!rec) return -ENOMEM;
  int rc = read_record(v, f->inode, rec);
  uint8_t *at = rc ? NULL : rec_attr(rec, v->rec_size, AT_DATA, NULL, 0);
  if (!rc && (!at || !at[8] || le64(at + 0x10) != 0)) rc = -EIO;
  if (!rc) {
    put_le64(at + 0x38, f->pos);
    rc = write_record(v, f->inode, rec);
  }
  free(rec);
  if (!rc) f->flushed = f->pos;
  return rc;
}

int ntfs_wwrite(ntfs_wfile_t *f, const void *buf, size_t len) {
  if (!len) return 0;
  if (f->pos + len > f->a.size) return -EFBIG;
  ntfs_vol_t *v = f->v;
  pthread_mutex_lock(&v->lock);
  int rc = write_raw(v, &f->a, f->pos, buf, len);
  if (!rc) {
    f->pos += len;
    if (f->pos - f->flushed >= INIT_FLUSH_EVERY) {
      bdev_flush(v->dev);
      rc = store_init(f);
    }
  }
  pthread_mutex_unlock(&v->lock);
  return rc;
}

int ntfs_wclose(ntfs_wfile_t *f) {
  if (!f) return 0;
  ntfs_vol_t *v = f->v;
  pthread_mutex_lock(&v->lock);
  bdev_flush(v->dev);
  int rc = store_init(f);
  bdev_flush(v->dev);
  pthread_mutex_unlock(&v->lock);
  attr_free(&f->a);
  free(f);
  return rc;
}

/* ---- Enabling writes ----------------------------------------------------- */

typedef struct hib_ctx {
  ntfs_vol_t *v;
  uint64_t    ref;
} hib_ctx_t;

static int hib_cb(void *ctx, uint64_t ref, const uint8_t *fn, uint16_t fnlen) {
  static const char want[] = "hiberfil.sys";
  hib_ctx_t *h = ctx;
  if (fn[0x40] != 12 || fnlen < 0x42 + 24) return 0;
  for (int i = 0; i < 12; i++) {
    uint16_t c = le16(fn + 0x42 + i * 2);
    if (c >= 'A' && c <= 'Z') c = (uint16_t)(c + 32);
    if (c != (uint8_t)want[i]) return 0;
  }
  h->ref = ref;
  return 1;
}

int ntfs_can_write(ntfs_vol_t *v, char *why, size_t len) {
  pthread_mutex_lock(&v->lock);
  int rc = 0;
  if (v->ver_major != 3) {
    snprintf(why, len, "only NTFS 3.x volumes can be written");
    rc = -ENOTSUP;
  } else if (v->dirty) {
    snprintf(why, len, "Windows did not unmount this drive cleanly. Plug it into "
                       "Windows and use \"Safely remove\" (or run chkdsk) first");
    rc = -EBUSY;
  } else if (v->upcase_len < 0x10000) {
    snprintf(why, len, "the $UpCase table is missing or incomplete");
    rc = -ENOTSUP;
  }
  if (!rc) {
    /* A pending journal means Windows would replay it over our changes. */
    attr_t lf;
    if (attr_find(v, INODE_LOGFILE, AT_DATA, NULL, 0, &lf) == 0) {
      uint8_t pg[512];
      if (attr_pread(v, &lf, 0, pg, sizeof pg) == (ssize_t)sizeof pg) {
        if (!memcmp(pg, "CHKD", 4)) {
          snprintf(why, len, "chkdsk has unfinished work on this drive");
          rc = -EBUSY;
        } else if (!memcmp(pg, "RSTR", 4)) {
          uint16_t ro = le16(pg + 0x18);
          if (ro + 0x10 <= 510) {
            uint16_t in_use = le16(pg + ro + 0x0C), flags = le16(pg + ro + 0x0E);
            if (in_use != 0xFFFF && !(flags & 0x0002)) {
              snprintf(why, len, "the drive's journal has unsaved changes (Windows "
                                 "Fast Startup?). Shut Windows down fully or use "
                                 "\"Safely remove\" first");
              rc = -EBUSY;
            }
          }
        }
      }
      attr_free(&lf);
    }
  }
  if (!rc) {
    hib_ctx_t h = {v, 0};
    index_walk(v, NTFS_ROOT_INODE, hib_cb, &h);
    if (h.ref) {
      attr_t d;
      if (attr_find(v, MREF(h.ref), AT_DATA, NULL, 0, &d) == 0) {
        uint8_t sig[4] = {0};
        if (d.size >= 4 && attr_pread(v, &d, 0, sig, 4) == 4 &&
            (!memcmp(sig, "hibr", 4) || !memcmp(sig, "HIBR", 4) ||
             !memcmp(sig, "wake", 4) || !memcmp(sig, "WAKE", 4))) {
          snprintf(why, len, "Windows is hibernated on this drive (Fast Startup). "
                             "Shut Windows down fully first");
          rc = -EBUSY;
        }
        attr_free(&d);
      }
    }
  }
  pthread_mutex_unlock(&v->lock);
  return rc;
}

int ntfs_enable_write(ntfs_vol_t *v, char *err, size_t errlen) {
  int rc = ntfs_can_write(v, err, errlen);
  if (rc) return rc;
  pthread_mutex_lock(&v->lock);
  if (v->rw) { pthread_mutex_unlock(&v->lock); return 0; }
  rc = bdev_enable_write(v->dev);
  if (rc) {
    snprintf(err, errlen, "the drive can't be opened for writing: %s", strerror(-rc));
    pthread_mutex_unlock(&v->lock);
    return rc;
  }
  rc = attr_find(v, INODE_BITMAP, AT_DATA, NULL, 0, &v->cbmp);
  if (!rc && (v->cbmp.resident || v->cbmp.size * 8 < v->total_clusters)) rc = -EIO;
  attr_t mirr;
  if (!rc && attr_find(v, INODE_MFTMIRR, AT_DATA, NULL, 0, &mirr) == 0) {
    v->mirr_recs = (uint32_t)(mirr.size / v->rec_size);
    attr_free(&mirr);
  }
  if (!rc) {
    /* Empty the journal like ntfs-3g does, so Windows starts a fresh log
     * instead of trying to replay an old one. */
    attr_t lf;
    if (attr_find(v, INODE_LOGFILE, AT_DATA, NULL, 0, &lf) == 0 && !lf.resident) {
      enum { CH = 1024 * 1024 };
      uint8_t *ff = malloc(CH);
      if (ff) {
        memset(ff, 0xFF, CH);
        for (uint64_t off = 0; off < lf.init && !rc; off += CH) {
          size_t n = lf.init - off < CH ? (size_t)(lf.init - off) : CH;
          if (write_raw(v, &lf, off, ff, n)) rc = -EIO;
        }
        free(ff);
      }
      attr_free(&lf);
    }
  }
  if (rc) {
    attr_free(&v->cbmp);
    snprintf(err, errlen, "could not prepare the drive for writing");
  } else {
    v->alloc_hint = v->mft_lcn + v->total_clusters / 8;
    if (v->alloc_hint >= v->total_clusters) v->alloc_hint = 0;
    v->mft_hint = FIRST_FREE_RECORD;
    v->rw = 1;
    bdev_flush(v->dev);
  }
  pthread_mutex_unlock(&v->lock);
  return rc;
}

void ntfs_disable_write(ntfs_vol_t *v) {
  pthread_mutex_lock(&v->lock);
  if (v->rw) bdev_flush(v->dev);
  v->rw = 0;
  pthread_mutex_unlock(&v->lock);
}

int ntfs_is_writable(ntfs_vol_t *v) {
  pthread_mutex_lock(&v->lock);
  int rw = v->rw;
  pthread_mutex_unlock(&v->lock);
  return rw;
}
