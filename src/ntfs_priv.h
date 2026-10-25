/* Internal structures shared by the NTFS reader (ntfs.c) and writer
 * (ntfs_write.c). Not part of the public API. */
#pragma once

#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>

#include "bdev.h"
#include "ntfs.h"

/* ---- On-disk constants --------------------------------------------------- */

#define AT_STANDARD_INFORMATION 0x10
#define AT_ATTRIBUTE_LIST       0x20
#define AT_FILE_NAME            0x30
#define AT_VOLUME_NAME          0x60
#define AT_VOLUME_INFORMATION   0x70
#define AT_DATA                 0x80
#define AT_INDEX_ROOT           0x90
#define AT_INDEX_ALLOCATION     0xA0
#define AT_END                  0xFFFFFFFFu

#define ATTR_COMPRESSED 0x0001
#define ATTR_ENCRYPTED  0x4000
#define ATTR_SPARSE     0x8000

#define MFT_IN_USE    0x0001
#define MFT_DIRECTORY 0x0002

#define IE_NODE 0x01  /* entry has a sub-node */
#define IE_LAST 0x02  /* terminating entry, no key */

#define NS_DOS 2

#define INODE_MFT     0
#define INODE_VOLUME  3
#define INODE_BITMAP  6
#define INODE_UPCASE  10
#define FIRST_USER_INODE 16

#define MREF(x) ((x) & 0x0000FFFFFFFFFFFFULL)

#define MAX_DEPTH 32
#define MREF_SEQ(x) ((uint16_t)((x) >> 48))
#define AT_BITMAP 0xB0
#define INODE_MFTMIRR 1
#define INODE_LOGFILE 2
#define MFT_HDR_SEQ 0x10

extern const uint16_t I30[4];

/* ---- In-memory structures ------------------------------------------------ */

typedef struct run {
  int64_t  vcn;
  int64_t  lcn;   /* -1 = sparse (reads as zeros) */
  uint64_t len;   /* clusters */
} run_t;

typedef struct attr {
  int      resident;
  uint8_t *data;        /* resident value */
  uint32_t data_len;
  run_t   *runs;
  size_t   nruns, cap;
  uint64_t size, init, alloc;
  uint16_t flags;
  uint32_t cu_clusters; /* compression unit, 0 if not compressed */

  /* Cache of the most recently decompressed compression unit. */
  uint8_t *cu_buf;
  int64_t  cu_idx;
} attr_t;

struct ntfs_vol {
  pthread_mutex_t lock;
  bdev_t  *dev;
  uint32_t cluster;
  uint32_t rec_size;
  uint64_t total_clusters;
  uint64_t serial;
  attr_t   mft;          /* $MFT unnamed $DATA */
  uint16_t *upcase;
  uint32_t upcase_len;
  char     label[128];
  uint8_t  ver_major, ver_minor;
  int      dirty;
  int      free_known;
  uint64_t free_clusters;
  int      has_list_mft;   /* $MFT itself has an attribute list */
  uint64_t mft_lcn;
  uint64_t mftmirr_lcn;
  uint32_t idx_size;       /* default index block size for new folders */
  uint32_t sector;         /* bytes per sector from the boot sector */

  /* Write support (see ntfs_write.c). */
  int      rw;             /* writes enabled */
  attr_t   cbmp;           /* $Bitmap $DATA: cluster allocation bitmap */
  uint64_t alloc_hint;     /* next cluster to try when allocating */
  uint64_t mft_hint;       /* next MFT record to try */
  uint32_t mirr_recs;      /* records mirrored in $MFTMirr */
};

struct ntfs_file {
  ntfs_vol_t *v;
  attr_t      a;
};

/* Index walk callback: return 1 to stop, 0 to continue, <0 on error.
 * ref is the full file reference (sequence number in the top 16 bits). */
typedef int (*idx_cb)(void *ctx, uint64_t ref, const uint8_t *fn, uint16_t fnlen);

int64_t  nt2unix(uint64_t t);
void     attr_free(attr_t *a);
int      run_push(attr_t *a, int64_t vcn, int64_t lcn, uint64_t len);
int      decode_runs(attr_t *a, const uint8_t *p, const uint8_t *end, int64_t vcn);
int      apply_fixups(uint8_t *buf, uint32_t size);
const run_t *find_run(const attr_t *a, int64_t vcn);
ssize_t  attr_pread(ntfs_vol_t *v, attr_t *a, uint64_t off, void *out, size_t len);
int      read_record(ntfs_vol_t *v, uint64_t inode, uint8_t *buf);
/* Like read_record but also accepts records that are not in use. */
int      read_record_any(ntfs_vol_t *v, uint64_t inode, uint8_t *buf);
const uint8_t *next_attr(const uint8_t *rec, uint32_t rec_size, uint32_t *pos);
int      attr_name_eq(const uint8_t *at, const uint16_t *name, int nlen);
int      absorb(attr_t *a, const uint8_t *at, uint32_t at_len, int first);
int      attr_find(ntfs_vol_t *v, uint64_t inode, uint32_t type,
                   const uint16_t *name, int nlen, attr_t *out);
int      index_walk(ntfs_vol_t *v, uint64_t inode, idx_cb cb, void *ctx);
int      stat_locked(ntfs_vol_t *v, uint64_t inode, ntfs_stat_t *st);
uint16_t up(const ntfs_vol_t *v, uint16_t c);
int      lookup_locked(ntfs_vol_t *v, const char *path, uint64_t *inode);
