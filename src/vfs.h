/* One view over two kinds of storage:
 *   - "ps5":  the console's own file system (native POSIX calls)
 *   - "ntfsN": NTFS volumes found on USB drives or image files, read through
 *             our own driver because the PS5 kernel has no NTFS support. */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "http.h"
#include "ntfs.h"

typedef enum { VOL_NATIVE, VOL_NTFS } vol_kind_t;

typedef struct vol {
  char        id[16];
  vol_kind_t  kind;
  char        label[160];
  char        device[300];   /* device node or image path */
  char        scheme[8];     /* partition scheme */
  int         partition;     /* partition number, 0 = whole device */
  uint64_t    size;
  uint64_t    serial;
  ntfs_vol_t *ntfs;
  int         refs;
  int         detached;      /* removed; freed when the last user is done */
} vol_t;

typedef struct ventry {
  char    *name;
  int      is_dir;
  int      is_link;
  int      hidden;     /* hidden or system */
  uint64_t size;
  int64_t  mtime;
  uint32_t attrs;      /* NTFS attributes; 0 for native */
} ventry_t;

typedef struct vlist {
  ventry_t *e;
  size_t    n, cap;
} vlist_t;

typedef struct vfile {
  vol_t       *vol;
  int          fd;
  ntfs_file_t *nf;
  uint64_t     size;
} vfile_t;

void vfs_init(void);

/* Look up a volume by id; returns a reference that must be released. */
vol_t *vfs_get(const char *id);
void   vfs_put(vol_t *v);

/* Probe device nodes (PS5) or the configured image list (host). Volumes
 * whose device disappeared are removed. If force, devices that were already
 * probed and rejected are tried again. Returns the number of NTFS volumes. */
int vfs_rescan(int force);

/* Register extra device/image paths to probe on every scan (host builds). */
void vfs_add_source(const char *path);

/* Mount a specific image or device path. Writes an error message on failure. */
int vfs_mount_path(const char *path, char *err, size_t errlen);
int vfs_unmount(const char *id);

/* JSON array of mounted volumes. */
void vfs_volumes_json(buf_t *b);

/* Bump on every change to the volume list; lets the UI refresh. */
unsigned vfs_generation(void);

int  vfs_list(vol_t *v, const char *path, vlist_t *out);
void vfs_list_free(vlist_t *l);
int  vfs_stat(vol_t *v, const char *path, ventry_t *out); /* out->name unset */

int     vfs_open(vol_t *v, const char *path, vfile_t *f);
ssize_t vfs_pread(vfile_t *f, void *buf, size_t len, uint64_t off);
void    vfs_close(vfile_t *f);

/* ---- Writing ---- */

/* Turn writing on/off for an NTFS volume. err gets the reason on failure. */
int vfs_set_writable(vol_t *v, int on, char *err, size_t errlen);

/* Create one folder (parent must exist). */
int vfs_mkdir(vol_t *v, const char *path);

/* Make sure a folder and its parents exist. */
int vfs_mkdirs(vol_t *v, const char *path);

/* Free bytes on the volume that holds path (-1 if unknown). */
int64_t vfs_free_bytes(vol_t *v, const char *path);

typedef struct vwfile {
  vol_t        *vol;
  int           fd;
  ntfs_wfile_t *nw;
  int64_t       mtime;
  char          tmp[1100], final[1100];
} vwfile_t;

/* Open path for writing a file of exactly size bytes. If the same file was
 * partly written before, *done says how much is there already (writing
 * continues from it); *done == size means it is already complete.
 * -EEXIST if a different file has that name. */
int vfs_wopen(vol_t *v, const char *path, uint64_t size, int64_t mtime,
              vwfile_t *w, uint64_t *done);
int vfs_wwrite(vwfile_t *w, const void *buf, size_t len);
/* ok = 0 abandons the file (native: removes the partial copy). */
int vfs_wclose(vwfile_t *w, int ok);

/* Normalise a client-supplied path: collapse "//", drop "." and reject "..".
 * Output always starts with '/'. Returns 0 on success. */
int vfs_clean_path(const char *in, char *out, size_t outlen);
