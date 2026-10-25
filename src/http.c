#include "http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "utf.h"

#define MAX_CLIENTS 64
#define IDLE_TIMEOUT_SEC 30

/* ---- Growable buffer ----------------------------------------------------- */

void buf_init(buf_t *b) { memset(b, 0, sizeof *b); }

void buf_free(buf_t *b) {
  free(b->data);
  memset(b, 0, sizeof *b);
}

static int buf_reserve(buf_t *b, size_t extra) {
  if (b->oom) return -1;
  if (b->len + extra + 1 <= b->cap) return 0;
  size_t nc = b->cap ? b->cap : 4096;
  while (nc < b->len + extra + 1) nc *= 2;
  char *d = realloc(b->data, nc);
  if (!d) { b->oom = 1; return -1; }
  b->data = d;
  b->cap = nc;
  return 0;
}

void buf_add(buf_t *b, const void *data, size_t len) {
  if (buf_reserve(b, len)) return;
  memcpy(b->data + b->len, data, len);
  b->len += len;
  b->data[b->len] = 0;
}

void buf_puts(buf_t *b, const char *s) { buf_add(b, s, strlen(s)); }

void buf_printf(buf_t *b, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  char tmp[512];
  int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
  va_end(ap);
  if (n < 0) return;
  if ((size_t)n < sizeof tmp) { buf_add(b, tmp, (size_t)n); return; }
  if (buf_reserve(b, (size_t)n)) return;
  va_start(ap, fmt);
  vsnprintf(b->data + b->len, (size_t)n + 1, fmt, ap);
  va_end(ap);
  b->len += (size_t)n;
}

void buf_json_str(buf_t *b, const char *s) {
  const unsigned char *p = (const unsigned char *)s;
  size_t avail = strlen(s);
  buf_add(b, "\"", 1);
  while (*p) {
    unsigned char c = *p;
    if (c == '"' || c == '\\') {
      char e[2] = {'\\', (char)c};
      buf_add(b, e, 2);
      p++; avail--;
    } else if (c < 0x20) {
      buf_printf(b, "\\u%04x", c);
      p++; avail--;
    } else if (c < 0x80) {
      buf_add(b, p, 1);
      p++; avail--;
    } else {
      int n = utf8_seq_len(p, avail);
      if (n) { buf_add(b, p, (size_t)n); p += n; avail -= (size_t)n; }
      else { buf_puts(b, "\xEF\xBF\xBD"); p++; avail--; }
    }
  }
  buf_add(b, "\"", 1);
}

/* ---- Request parsing ----------------------------------------------------- */

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Percent-decode src[0..len) into out. '+' becomes a space if plus. */
static int url_decode(const char *src, size_t len, char *out, size_t outlen,
                      int plus) {
  size_t o = 0;
  for (size_t i = 0; i < len; i++) {
    char c = src[i];
    if (c == '%' && i + 2 < len && hexval(src[i + 1]) >= 0 &&
        hexval(src[i + 2]) >= 0) {
      c = (char)(hexval(src[i + 1]) << 4 | hexval(src[i + 2]));
      i += 2;
    } else if (c == '+' && plus) {
      c = ' ';
    }
    if (!c) return -1; /* no embedded NULs */
    if (o + 1 >= outlen) return -1;
    out[o++] = c;
  }
  out[o] = 0;
  return 0;
}

int http_param(const http_req_t *r, const char *name, char *out, size_t outlen) {
  if (!r->query) return 0;
  size_t nl = strlen(name);
  const char *p = r->query;
  while (*p) {
    const char *amp = strchr(p, '&');
    size_t seg = amp ? (size_t)(amp - p) : strlen(p);
    const char *eq = memchr(p, '=', seg);
    size_t klen = eq ? (size_t)(eq - p) : seg;
    if (klen == nl && !memcmp(p, name, nl)) {
      if (!eq) { if (outlen) out[0] = 0; return 1; }
      return url_decode(eq + 1, seg - klen - 1, out, outlen, 1) == 0;
    }
    p += seg;
    if (*p == '&') p++;
  }
  return 0;
}

static void parse_range(http_req_t *r, const char *v) {
  while (*v == ' ') v++;
  if (strncasecmp(v, "bytes=", 6)) return;
  v += 6;
  if (strchr(v, ',')) return; /* multiple ranges: serve whole body */
  char *end;
  if (*v == '-') {
    long long n = strtoll(v + 1, &end, 10);
    if (end == v + 1 || n <= 0) return;
    r->range_start = -1;
    r->range_end = n;
  } else {
    long long s = strtoll(v, &end, 10);
    if (end == v || *end != '-' || s < 0) return;
    r->range_start = s;
    v = end + 1;
    if (*v) {
      long long e = strtoll(v, &end, 10);
      if (end == v || e < s) return;
      r->range_end = e;
    } else {
      r->range_end = -1;
    }
  }
  r->has_range = 1;
}

/* Read one request head. Returns 0 on success, -1 to close. */
static int read_request(http_req_t *r, char *carry, size_t *carry_len) {
  size_t len = *carry_len;
  memcpy(r->raw, carry, len);
  char *hend = NULL;
  for (;;) {
    r->raw[len] = 0;
    if ((hend = strstr(r->raw, "\r\n\r\n"))) break;
    if (len >= sizeof r->raw - 1) return -1;
    ssize_t n = recv(r->fd, r->raw + len, sizeof r->raw - 1 - len, 0);
    if (n <= 0) return -1;
    len += (size_t)n;
  }
  size_t head_len = (size_t)(hend - r->raw) + 4;

  /* Request line */
  char *line_end = strstr(r->raw, "\r\n");
  *line_end = 0;
  char *sp1 = strchr(r->raw, ' ');
  if (!sp1) return -1;
  *sp1 = 0;
  char *target = sp1 + 1;
  char *sp2 = strchr(target, ' ');
  if (!sp2) return -1;
  *sp2 = 0;
  char *version = sp2 + 1;
  snprintf(r->method, sizeof r->method, "%s", r->raw);
  r->keep_alive = strcmp(version, "HTTP/1.0") != 0;
  r->head_only = !strcmp(r->method, "HEAD");

  char *q = strchr(target, '?');
  if (q) { *q = 0; r->query = q + 1; }
  if (url_decode(target, strlen(target), r->path, sizeof r->path, 0)) return -1;

  /* Headers */
  uint64_t content_length = 0;
  char *h = line_end + 2;
  while (h < hend) {
    char *e = strstr(h, "\r\n");
    *e = 0;
    char *colon = strchr(h, ':');
    if (colon) {
      *colon = 0;
      char *v = colon + 1;
      while (*v == ' ') v++;
      if (!strcasecmp(h, "Range")) parse_range(r, v);
      else if (!strcasecmp(h, "Connection")) {
        if (strcasestr(v, "close")) r->keep_alive = 0;
        else if (strcasestr(v, "keep-alive")) r->keep_alive = 1;
      } else if (!strcasecmp(h, "X-NTFSB")) {
        /* Browsers only let same-origin pages add custom headers, so other
         * websites can't trigger actions on this server. */
        r->trusted = 1;
      } else if (!strcasecmp(h, "Content-Length")) {
        content_length = strtoull(v, NULL, 10);
      }
    }
    h = e + 2;
  }

  /* We take no request bodies; discard any that arrive (bounded). */
  size_t extra = len - head_len;
  if (content_length > 1024 * 1024) return -1;
  if (extra > content_length) {
    size_t keep = extra - (size_t)content_length;
    memmove(carry, r->raw + head_len + content_length, keep);
    *carry_len = keep;
  } else {
    uint64_t left = content_length - extra;
    char junk[4096];
    while (left) {
      ssize_t n = recv(r->fd, junk, left < sizeof junk ? (size_t)left : sizeof junk, 0);
      if (n <= 0) return -1;
      left -= (uint64_t)n;
    }
    *carry_len = 0;
  }
  return 0;
}

/* ---- Responses ----------------------------------------------------------- */

const char *http_status_text(int s) {
  switch (s) {
    case 200: return "OK";
    case 206: return "Partial Content";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 416: return "Range Not Satisfiable";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    case 507: return "Insufficient Storage";
    default:  return "Error";
  }
}

int http_write(http_req_t *r, const void *data, size_t len) {
  const char *p = data;
  while (len) {
    ssize_t n = send(r->fd, p, len, 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      r->keep_alive = 0;
      return -1;
    }
    p += n;
    len -= (size_t)n;
  }
  return 0;
}

void http_begin(http_req_t *r, int status, const char *ctype, uint64_t len,
                const char *extra) {
  char h[2048];
  int n = snprintf(h, sizeof h,
                   "HTTP/1.1 %d %s\r\n"
                   "Content-Type: %s\r\n"
                   "Content-Length: %llu\r\n"
                   "Connection: %s\r\n"
                   "%s\r\n",
                   status, http_status_text(status), ctype,
                   (unsigned long long)len, r->keep_alive ? "keep-alive" : "close",
                   extra ? extra : "");
  if (n > 0 && (size_t)n < sizeof h) http_write(r, h, (size_t)n);
  r->sent_headers = 1;
}

void http_send(http_req_t *r, int status, const char *ctype, const void *body,
               size_t len, const char *extra) {
  http_begin(r, status, ctype, len, extra);
  if (!r->head_only && len) http_write(r, body, len);
}

void http_send_json(http_req_t *r, int status, buf_t *b) {
  if (b->oom) {
    http_send_error(r, 500, "out of memory");
    return;
  }
  http_send(r, status, "application/json; charset=utf-8", b->data ? b->data : "",
            b->len, "Cache-Control: no-store\r\n");
}

void http_send_error(http_req_t *r, int status, const char *msg) {
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"error\":");
  buf_json_str(&b, msg);
  buf_puts(&b, "}");
  http_send(r, status, "application/json; charset=utf-8", b.data ? b.data : "{}",
            b.len, "Cache-Control: no-store\r\n");
  buf_free(&b);
}

/* ---- Server loop --------------------------------------------------------- */

typedef struct client {
  int fd;
  http_handler h;
} client_t;

static pthread_mutex_t g_count_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_clients;

static void *client_main(void *arg) {
  client_t c = *(client_t *)arg;
  free(arg);

  http_req_t *r = malloc(sizeof *r);
  char *carry = malloc(sizeof r->raw);
  size_t carry_len = 0;
  if (r && carry) {
    for (;;) {
      memset(r, 0, offsetof(http_req_t, raw));
      r->fd = c.fd;
      if (read_request(r, carry, &carry_len)) break;
      c.h(r);
      if (!r->sent_headers) http_send_error(r, 500, "no response");
      if (!r->keep_alive) break;
    }
  }
  free(r);
  free(carry);
  close(c.fd);
  pthread_mutex_lock(&g_count_lock);
  g_clients--;
  pthread_mutex_unlock(&g_count_lock);
  return NULL;
}

int http_listen(uint16_t port) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) return -errno;
  int one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

  struct sockaddr_in a;
  memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 32)) {
    int e = errno;
    close(s);
    return -e;
  }
  return s;
}

void http_run(int s, http_handler h) {
  int one = 1;
  for (;;) {
    int fd = accept(s, NULL, NULL);
    if (fd < 0) {
      if (errno == EINTR || errno == ECONNABORTED) continue;
      usleep(100000);
      continue;
    }
    pthread_mutex_lock(&g_count_lock);
    int busy = g_clients >= MAX_CLIENTS;
    if (!busy) g_clients++;
    pthread_mutex_unlock(&g_count_lock);
    if (busy) { close(fd); continue; }

    struct timeval tv = {IDLE_TIMEOUT_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif

    client_t *c = malloc(sizeof *c);
    pthread_t t;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&at, 256 * 1024);
    int started = 0;
    if (c) {
      c->fd = fd;
      c->h = h;
      started = pthread_create(&t, &at, client_main, c) == 0;
    }
    if (!started) {
      free(c);
      close(fd);
      pthread_mutex_lock(&g_count_lock);
      g_clients--;
      pthread_mutex_unlock(&g_count_lock);
    }
    pthread_attr_destroy(&at);
  }
}
