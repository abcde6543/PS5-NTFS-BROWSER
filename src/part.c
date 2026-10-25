#include "part.h"

#include <stdlib.h>
#include <string.h>

#include "endian_util.h"

int part_is_ntfs(bdev_t *b) {
  uint8_t bs[512];
  if (bdev_read(b, 0, bs, sizeof bs) != 0) return 0;
  return memcmp(bs + 3, "NTFS    ", 8) == 0 && bs[510] == 0x55 && bs[511] == 0xAA;
}

static void add(part_t *parts, int *n, int max, uint64_t off, uint64_t size,
                const char *scheme, int index, uint64_t disk) {
  if (*n >= max || !size || off >= disk) return;
  if (size > disk - off) size = disk - off;
  parts[*n].offset = off;
  parts[*n].size = size;
  parts[*n].index = index;
  strncpy(parts[*n].scheme, scheme, sizeof parts[*n].scheme - 1);
  (*n)++;
}

static int scan_gpt(bdev_t *b, part_t *parts, int max) {
  uint64_t disk = bdev_size(b);
  /* The GPT header is at LBA 1: try the device's sector size first. */
  uint32_t sizes[] = {bdev_sector_size(b), 512, 4096};
  for (int s = 0; s < 3; s++) {
    uint32_t ss = sizes[s];
    if (s && ss == sizes[0]) continue;
    uint8_t hdr[512];
    if (bdev_read(b, ss, hdr, sizeof hdr) != 0) continue;
    if (memcmp(hdr, "EFI PART", 8) != 0) continue;

    uint64_t ent_lba = le64(hdr + 72);
    uint32_t count = le32(hdr + 80);
    uint32_t esize = le32(hdr + 84);
    if (esize < 128 || esize > 4096 || count > 1024) return 0;

    int n = 0;
    uint8_t *e = malloc(esize);
    if (!e) return 0;
    for (uint32_t i = 0; i < count && n < max; i++) {
      if (bdev_read(b, ent_lba * ss + (uint64_t)i * esize, e, esize) != 0) break;
      static const uint8_t zero[16];
      if (!memcmp(e, zero, 16)) continue; /* unused entry */
      uint64_t first = le64(e + 32), last = le64(e + 40);
      if (last < first) continue;
      add(parts, &n, max, first * ss, (last - first + 1) * ss, "gpt",
          (int)i + 1, disk);
    }
    free(e);
    return n;
  }
  return 0;
}

static int scan_mbr(bdev_t *b, part_t *parts, int max) {
  uint64_t disk = bdev_size(b);
  uint64_t ss = bdev_sector_size(b); /* MBR LBAs are logical sectors */
  uint8_t mbr[512];
  if (bdev_read(b, 0, mbr, sizeof mbr) != 0) return 0;
  if (mbr[510] != 0x55 || mbr[511] != 0xAA) return 0;
  /* A volume boot record also ends in 55AA; don't misread it as an MBR. */
  if (!memcmp(mbr + 3, "NTFS    ", 8) || !memcmp(mbr + 3, "EXFAT   ", 8))
    return 0;

  int n = 0;
  for (int i = 0; i < 4; i++) {
    const uint8_t *e = mbr + 446 + i * 16;
    uint8_t type = e[4];
    uint32_t lba = le32(e + 8), cnt = le32(e + 12);
    if (e[0] != 0 && e[0] != 0x80) return 0; /* not a real partition table */
    if (!type || !cnt) continue;

    if (type == 0x05 || type == 0x0F || type == 0x85) {
      /* Extended partition: walk the chain of EBRs. */
      uint64_t ext = lba, cur = lba;
      int logical = 5;
      for (int guard = 0; guard < 64 && n < max; guard++) {
        uint8_t ebr[512];
        if (bdev_read(b, cur * ss, ebr, sizeof ebr) != 0) break;
        if (ebr[510] != 0x55 || ebr[511] != 0xAA) break;
        const uint8_t *l = ebr + 446, *nx = ebr + 446 + 16;
        if (l[4] && le32(l + 12))
          add(parts, &n, max, (cur + le32(l + 8)) * ss,
              (uint64_t)le32(l + 12) * ss, "mbr", logical++, disk);
        if (!nx[4] || !le32(nx + 8)) break;
        cur = ext + le32(nx + 8);
      }
    } else if (type != 0xEE) {
      add(parts, &n, max, (uint64_t)lba * ss, (uint64_t)cnt * ss, "mbr",
          i + 1, disk);
    }
  }
  return n;
}

int part_scan(bdev_t *b, part_t *parts, int max) {
  int n = scan_gpt(b, parts, max);
  if (!n) n = scan_mbr(b, parts, max);
  if (!n && max > 0) {
    parts[0].offset = 0;
    parts[0].size = bdev_size(b);
    parts[0].index = 0;
    strcpy(parts[0].scheme, "none");
    n = 1;
  }
  return n;
}
