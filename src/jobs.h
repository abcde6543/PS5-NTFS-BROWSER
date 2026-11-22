/* Background copy jobs: copy files or whole folders from any volume (usually
 * an NTFS drive) into a folder on the console or onto an NTFS drive. Jobs run one
 * at a time in a worker thread so USB reads stay sequential. */
#pragma once

#include "http.h"

void jobs_init(void);

/* Queue a copy of vol:src into the folder dvol:dest_dir. The destination can
 * be console storage ("ps5") or an NTFS drive with writing turned on.
 * Returns the job id (>0) or a negative errno with a message in err. */
int jobs_copy(const char *vol, const char *src, const char *dvol, const char *dest_dir,
              char *err, size_t errlen);

int  jobs_cancel(int id);

/* 1 if a queued or running job reads from or writes to this volume. */
int  jobs_vol_busy(const char *vol);
void jobs_clear_finished(void);
void jobs_json(buf_t *b);
