/* A small, read-only NTFS driver that runs entirely in user space.
 *
 * Supports: NTFS 3.x volumes with any cluster size, fragmented and very large
 * files, attribute lists, directory B-trees of any size, sparse files,
 * LZNT1 compressed files, Unicode names, case-insensitive lookup, hard links
 * and 8.3 short-name lookup. Encrypted (EFS) file contents cannot be read.
 *
 * All functions are thread-safe; each volume serialises access internally.
 * Errors are returned as negative errno values. */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "bdev.h"

#define NTFS_ROOT_INODE 5

/* Windows file attribute bits (as stored in $STANDARD_INFORMATION). */
#define NTFS_FA_READONLY   0x0001
#define NTFS_FA_HIDDEN     0x0002
#define NTFS_FA_SYSTEM     0x0004
#define NTFS_FA_DIRECTORY  0x0010
#define NTFS_FA_ARCHIVE    0x0020
#define NTFS_FA_SPARSE     0x0200
#define NTFS_FA_REPARSE    0x0400
#define NTFS_FA_COMPRESSED 0x0800
#define NTFS_FA_ENCRYPTED  0x4000

typedef struct ntfs_vol ntfs_vol_t;
typedef struct ntfs_file ntfs_file_t;

typedef struct ntfs_stat {
  uint64_t inode;
  uint64_t size;     /* logical size of the unnamed data stream */
  uint64_t alloc;    /* bytes allocated on disk */
  int64_t  crtime;   /* Unix time, seconds */
  int64_t  mtime;
  int64_t  atime;
  uint32_t attrs;    /* NTFS_FA_* */
  uint32_t nlink;
  int      is_dir;
} ntfs_stat_t;

typedef struct ntfs_info {
  char     label[128];   /* UTF-8 volume label, may be empty */
  uint64_t serial;
  uint64_t total_bytes;
  uint32_t cluster_size;
  uint32_t mft_record_size;
  uint8_t  ver_major, ver_minor;
  int      dirty;        /* volume was not cleanly unmounted */
} ntfs_info_t;

/* Called once per directory entry. Return non-zero to stop early. */
typedef int (*ntfs_dir_cb)(void *ctx, const char *name, const ntfs_stat_t *st);

/* Mount the NTFS file system on b. The volume takes ownership of b. On
 * failure, b is left open and an error string is written to err. */
int  ntfs_mount(bdev_t *b, ntfs_vol_t **out, char *err, size_t errlen);
void ntfs_umount(ntfs_vol_t *v);

void ntfs_get_info(ntfs_vol_t *v, ntfs_info_t *info);

/* Free space in bytes. Scans $Bitmap the first time (can take a moment on
 * large volumes), then returns the cached value. */
int  ntfs_free_bytes(ntfs_vol_t *v, uint64_t *out);

/* Resolve a '/'-separated UTF-8 path (relative to the volume root). */
int  ntfs_lookup(ntfs_vol_t *v, const char *path, uint64_t *inode);
int  ntfs_stat(ntfs_vol_t *v, uint64_t inode, ntfs_stat_t *st);

/* List a directory. Metadata files ($MFT, $Bitmap...) and DOS short-name
 * aliases are skipped. Entries arrive in NTFS collation order. */
int  ntfs_readdir(ntfs_vol_t *v, uint64_t dir_inode, ntfs_dir_cb cb, void *ctx);

int     ntfs_open(ntfs_vol_t *v, uint64_t inode, ntfs_file_t **out);
ssize_t ntfs_pread(ntfs_file_t *f, void *buf, size_t len, uint64_t off);
uint64_t ntfs_file_size(const ntfs_file_t *f);
void    ntfs_close(ntfs_file_t *f);

/* Exposed for unit tests. Returns decompressed length or -1. */
ssize_t ntfs_lznt1_decompress(const uint8_t *src, size_t srclen, uint8_t *dst,
                              size_t dstlen);
