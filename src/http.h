/* Minimal HTTP/1.1 server: thread per connection, keep-alive, byte ranges. */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct buf {
  char  *data;
  size_t len, cap;
  int    oom;
} buf_t;

void buf_init(buf_t *b);
void buf_free(buf_t *b);
void buf_add(buf_t *b, const void *data, size_t len);
void buf_puts(buf_t *b, const char *s);
void buf_printf(buf_t *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
/* Append s as a JSON string literal (quotes included). Invalid UTF-8 bytes
 * are replaced with U+FFFD so the output is always valid JSON. */
void buf_json_str(buf_t *b, const char *s);

typedef struct http_req {
  int    fd;
  char   method[8];
  char   path[1024];      /* decoded path, no query string */
  char  *query;           /* raw query string (not decoded) */
  int    has_range;
  int64_t range_start;    /* -1 = suffix range */
  int64_t range_end;      /* -1 = open ended */
  int    keep_alive;
  int    sent_headers;
  int    head_only;
  int    trusted;         /* sent the X-NTFSB header: same-origin UI call */
  char   raw[16384];
} http_req_t;

typedef void (*http_handler)(http_req_t *r);

/* Bind and listen on port (all interfaces). Returns a socket or -errno. */
int http_listen(uint16_t port);

/* Serve connections on a listening socket forever. */
void http_run(int listen_fd, http_handler h);

/* Fetch a decoded query parameter into out. Returns 1 if present. */
int http_param(const http_req_t *r, const char *name, char *out, size_t outlen);

/* Send a complete response. */
void http_send(http_req_t *r, int status, const char *ctype, const void *body,
               size_t len, const char *extra_headers);
void http_send_json(http_req_t *r, int status, buf_t *b);
void http_send_error(http_req_t *r, int status, const char *msg);

/* Streaming: send headers with a known length, then write the body. */
void http_begin(http_req_t *r, int status, const char *ctype, uint64_t len,
                const char *extra_headers);
int  http_write(http_req_t *r, const void *data, size_t len);

const char *http_status_text(int status);
