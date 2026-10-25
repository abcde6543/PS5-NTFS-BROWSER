/* Background copy jobs: copy files or whole folders from any volume (usually
 * an NTFS drive) into a directory on the console's own storage. Jobs run one
 * at a time in a worker thread so USB reads stay sequential. */
#pragma once

#include "http.h"

void jobs_init(void);

/* Queue a copy of vol:src into the native directory dest_dir. Returns the
 * job id (>0) or a negative errno with a message in err. */
int jobs_copy(const char *vol, const char *src, const char *dest_dir,
              char *err, size_t errlen);

int  jobs_cancel(int id);
void jobs_clear_finished(void);
void jobs_json(buf_t *b);
