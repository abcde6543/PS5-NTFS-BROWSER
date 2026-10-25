/* Platform specific bits: PS5 vs. a desktop build used for testing. */
#pragma once

#include <stddef.h>

#include "http.h"

void plat_init(void);

/* Show a system notification on the PS5 (stderr elsewhere). */
void plat_notify(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* First non-loopback IPv4 address, or "127.0.0.1". */
void plat_ip(char *out, size_t len);

/* Open the PS5 web browser at url. Returns 0 on success. */
int plat_launch_browser(const char *url);

/* JSON array of quick-access folders on the native file system. */
void plat_places_json(buf_t *b);

/* Suggested destination folder for copies. */
const char *plat_default_dest(void);

const char *plat_name(void);
