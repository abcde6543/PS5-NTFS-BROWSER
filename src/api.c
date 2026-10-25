/* HTTP routes for the web UI. */
#include "api.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mount.h>
#include <sys/stat.h>

#if defined(__linux__)
#include <sys/statfs.h>
#endif

#include "jobs.h"
#include "platform.h"
#include "vfs.h"
#include "web_index.h"

#define STREAM_BUF (1024 * 1024)

static uint16_t g_port;

void api_set_port(uint16_t port) { g_port = port; }

/* ---- Helpers ------------------------------------------------------------- */

static int err_status(int rc) {
  switch (-rc) {
    case ENOENT:  return 404;
    case ENOTDIR: return 400;
    case EISDIR:  return 400;
    case EACCES:  return 403;
    case EPERM:   return 403;
    case EINVAL:  return 400;
    default:      return 500;
  }
}

static const char *err_text(int rc) {
  if (rc == -EACCES) return "access denied (encrypted or protected)";
  if (rc == -EIO) return "I/O error (drive removed or file system damaged?)";
  return strerror(-rc);
}

/* Shared parameter handling: ?vol=...&path=... */
static vol_t *get_vol_path(http_req_t *r, char *path, size_t plen) {
  char vol[32] = "", raw[1024] = "/";
  http_param(r, "vol", vol, sizeof vol);
  http_param(r, "path", raw, sizeof raw);
  if (vfs_clean_path(raw, path, plen)) {
    http_send_error(r, 400, "bad path");
    return NULL;
  }
  vol_t *v = vfs_get(vol[0] ? vol : "ps5");
  if (!v) http_send_error(r, 404, "volume not found (was the drive removed?)");
  return v;
}

static int require_post(http_req_t *r) {
  if (strcmp(r->method, "POST")) {
    http_send_error(r, 405, "use POST");
    return -1;
  }
  if (!r->trusted) {
    http_send_error(r, 403, "missing X-NTFSB header");
    return -1;
  }
  return 0;
}

static const struct { const char *ext, *type; } mime[] = {
    {"txt", "text/plain; charset=utf-8"}, {"log", "text/plain; charset=utf-8"},
    {"ini", "text/plain; charset=utf-8"}, {"cfg", "text/plain; charset=utf-8"},
    {"md", "text/plain; charset=utf-8"},  {"nfo", "text/plain; charset=utf-8"},
    {"srt", "text/plain; charset=utf-8"}, {"csv", "text/plain; charset=utf-8"},
    {"xml", "text/plain; charset=utf-8"}, {"json", "application/json"},
    {"htm", "text/plain; charset=utf-8"}, {"html", "text/plain; charset=utf-8"},
    {"jpg", "image/jpeg"}, {"jpeg", "image/jpeg"}, {"png", "image/png"},
    {"gif", "image/gif"}, {"webp", "image/webp"}, {"bmp", "image/bmp"},
    {"svg", "text/plain; charset=utf-8"}, {"ico", "image/x-icon"},
    {"mp4", "video/mp4"}, {"m4v", "video/mp4"}, {"webm", "video/webm"},
    {"mkv", "video/x-matroska"}, {"mov", "video/quicktime"},
    {"mp3", "audio/mpeg"}, {"m4a", "audio/mp4"}, {"aac", "audio/aac"},
    {"ogg", "audio/ogg"}, {"opus", "audio/ogg"}, {"wav", "audio/wav"},
    {"flac", "audio/flac"}, {"pdf", "application/pdf"},
};

static const char *mime_for(const char *path) {
  const char *dot = strrchr(path, '.');
  const char *slash = strrchr(path, '/');
  if (dot && (!slash || dot > slash)) {
    for (size_t i = 0; i < sizeof mime / sizeof mime[0]; i++)
      if (!strcasecmp(dot + 1, mime[i].ext)) return mime[i].type;
  }
  return "application/octet-stream";
}

/* filename*=UTF-8''... per RFC 5987, plus an ASCII fallback. */
static void content_disposition(char *out, size_t len, const char *path, int dl) {
  const char *base = strrchr(path, '/');
  base = base ? base + 1 : path;
  char ascii[256], enc[1024];
  size_t a = 0, e = 0;
  for (const unsigned char *p = (const unsigned char *)base; *p; p++) {
    if (a + 1 < sizeof ascii)
      ascii[a++] = (*p < 0x80 && *p >= 0x20 && *p != '"' && *p != '\\') ? (char)*p : '_';
    int plain = (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
                (*p >= '0' && *p <= '9') || strchr("-._~", *p);
    if (e + 4 >= sizeof enc) break;
    if (plain) enc[e++] = (char)*p;
    else e += (size_t)snprintf(enc + e, sizeof enc - e, "%%%02X", *p);
  }
  ascii[a] = 0;
  enc[e] = 0;
  snprintf(out, len, "Content-Disposition: %s; filename=\"%s\"; filename*=UTF-8''%s\r\n",
           dl ? "attachment" : "inline", ascii, enc);
}

/* ---- Routes -------------------------------------------------------------- */

static void route_index(http_req_t *r) {
  http_send(r, 200, "text/html; charset=utf-8", web_index_html, web_index_html_len,
            "Cache-Control: no-cache\r\n");
}

static void route_status(http_req_t *r) {
  char ip[64];
  plat_ip(ip, sizeof ip);
  buf_t b;
  buf_init(&b);
  buf_printf(&b, "{\"app\":\"NTFS Browser\",\"version\":\"%s\",\"platform\":\"%s\","
                 "\"ip\":\"%s\",\"port\":%u,\"gen\":%u,\"default_dest\":",
             APP_VERSION, plat_name(), ip, g_port, vfs_generation());
  buf_json_str(&b, plat_default_dest());
  buf_puts(&b, ",\"places\":");
  plat_places_json(&b);
  buf_puts(&b, "}");
  http_send_json(r, 200, &b);
  buf_free(&b);
}

static void route_volumes(http_req_t *r) {
  buf_t b;
  buf_init(&b);
  buf_printf(&b, "{\"gen\":%u,\"volumes\":", vfs_generation());
  vfs_volumes_json(&b);
  buf_puts(&b, "}");
  http_send_json(r, 200, &b);
  buf_free(&b);
}

static void route_volinfo(http_req_t *r) {
  char path[1024];
  vol_t *v = get_vol_path(r, path, sizeof path);
  if (!v) return;
  buf_t b;
  buf_init(&b);
  if (v->kind == VOL_NTFS) {
    uint64_t fr = 0;
    int rc = ntfs_free_bytes(v->ntfs, &fr);
    if (rc) buf_printf(&b, "{\"size\":%llu}", (unsigned long long)v->size);
    else buf_printf(&b, "{\"size\":%llu,\"free\":%llu}", (unsigned long long)v->size,
                    (unsigned long long)fr);
  } else {
    struct statfs sf;
    if (statfs(path, &sf) == 0)
      buf_printf(&b, "{\"size\":%llu,\"free\":%llu}",
                 (unsigned long long)sf.f_blocks * (unsigned long long)sf.f_bsize,
                 (unsigned long long)sf.f_bavail * (unsigned long long)sf.f_bsize);
    else
      buf_puts(&b, "{}");
  }
  vfs_put(v);
  http_send_json(r, 200, &b);
  buf_free(&b);
}

static void route_list(http_req_t *r) {
  char path[1024];
  vol_t *v = get_vol_path(r, path, sizeof path);
  if (!v) return;
  vlist_t l;
  int rc = vfs_list(v, path, &l);
  if (rc) {
    vfs_put(v);
    http_send_error(r, err_status(rc), err_text(rc));
    return;
  }
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"vol\":");
  buf_json_str(&b, v->id);
  buf_puts(&b, ",\"path\":");
  buf_json_str(&b, path);
  buf_puts(&b, ",\"entries\":[");
  for (size_t i = 0; i < l.n; i++) {
    ventry_t *e = &l.e[i];
    buf_puts(&b, i ? ",{\"n\":" : "{\"n\":");
    buf_json_str(&b, e->name);
    buf_printf(&b, ",\"d\":%d,\"s\":%llu,\"t\":%lld,\"h\":%d,\"l\":%d,\"a\":%u}",
               e->is_dir, (unsigned long long)e->size, (long long)e->mtime,
               e->hidden, e->is_link, e->attrs);
  }
  buf_puts(&b, "]}");
  vfs_list_free(&l);
  vfs_put(v);
  http_send_json(r, 200, &b);
  buf_free(&b);
}

static void route_file(http_req_t *r) {
  char path[1024], dl[8] = "";
  vol_t *v = get_vol_path(r, path, sizeof path);
  if (!v) return;
  http_param(r, "dl", dl, sizeof dl);

  vfile_t f;
  int rc = vfs_open(v, path, &f);
  if (rc) {
    vfs_put(v);
    http_send_error(r, err_status(rc), err_text(rc));
    return;
  }

  uint64_t start = 0, end = f.size ? f.size - 1 : 0;
  int status = 200;
  char extra[1600], cd[1200], cr[128] = "";
  if (r->has_range && f.size) {
    if (r->range_start < 0) {
      uint64_t n = (uint64_t)r->range_end;
      start = n >= f.size ? 0 : f.size - n;
    } else {
      start = (uint64_t)r->range_start;
      if (r->range_end >= 0 && (uint64_t)r->range_end < end) end = (uint64_t)r->range_end;
    }
    if (start >= f.size) {
      snprintf(extra, sizeof extra, "Content-Range: bytes */%llu\r\n",
               (unsigned long long)f.size);
      vfs_close(&f);
      vfs_put(v);
      http_send(r, 416, "text/plain", "", 0, extra);
      return;
    }
    status = 206;
    snprintf(cr, sizeof cr, "Content-Range: bytes %llu-%llu/%llu\r\n",
             (unsigned long long)start, (unsigned long long)end,
             (unsigned long long)f.size);
  }
  content_disposition(cd, sizeof cd, path, dl[0] == '1');
  snprintf(extra, sizeof extra, "Accept-Ranges: bytes\r\n%s%sCache-Control: no-cache\r\n",
           cr, cd);
  uint64_t len = f.size ? end - start + 1 : 0;
  http_begin(r, status, dl[0] == '1' ? "application/octet-stream" : mime_for(path),
             len, extra);

  if (!r->head_only && len) {
    uint8_t *buf = malloc(STREAM_BUF);
    uint64_t off = start, left = len;
    while (buf && left) {
      size_t want = left < STREAM_BUF ? (size_t)left : STREAM_BUF;
      ssize_t n = vfs_pread(&f, buf, want, off);
      if (n <= 0) break;
      if (http_write(r, buf, (size_t)n)) break;
      off += (uint64_t)n;
      left -= (uint64_t)n;
    }
    /* A short body breaks framing: make sure the connection is closed. */
    if (left) r->keep_alive = 0;
    free(buf);
  }
  vfs_close(&f);
  vfs_put(v);
}

static void route_rescan(http_req_t *r) {
  if (require_post(r)) return;
  int n = vfs_rescan(1);
  buf_t b;
  buf_init(&b);
  buf_printf(&b, "{\"ntfs_volumes\":%d}", n);
  http_send_json(r, 200, &b);
  buf_free(&b);
}

static void route_mount(http_req_t *r) {
  if (require_post(r)) return;
  char path[1024] = "", err[256];
  if (!http_param(r, "path", path, sizeof path) || !path[0]) {
    http_send_error(r, 400, "path required");
    return;
  }
  if (vfs_mount_path(path, err, sizeof err)) {
    http_send_error(r, 400, err);
    return;
  }
  route_volumes(r);
}

static void route_unmount(http_req_t *r) {
  if (require_post(r)) return;
  char vol[32] = "";
  http_param(r, "vol", vol, sizeof vol);
  if (vfs_unmount(vol)) {
    http_send_error(r, 404, "volume not found");
    return;
  }
  route_volumes(r);
}

static int mkdir_p(const char *path) {
  char tmp[1024];
  snprintf(tmp, sizeof tmp, "%s", path);
  for (char *p = tmp + 1; *p; p++) {
    if (*p != '/') continue;
    *p = 0;
    if (mkdir(tmp, 0777) && errno != EEXIST) return -errno;
    *p = '/';
  }
  if (mkdir(tmp, 0777) && errno != EEXIST) return -errno;
  return 0;
}

static void route_mkdir(http_req_t *r) {
  if (require_post(r)) return;
  char raw[1024] = "", path[1024];
  http_param(r, "path", raw, sizeof raw);
  if (!raw[0] || vfs_clean_path(raw, path, sizeof path)) {
    http_send_error(r, 400, "bad path");
    return;
  }
  int rc = mkdir_p(path);
  if (rc) {
    http_send_error(r, err_status(rc), strerror(-rc));
    return;
  }
  http_send(r, 200, "application/json", "{}", 2, NULL);
}

static void route_copy(http_req_t *r) {
  if (require_post(r)) return;
  char vol[32] = "", src_raw[1024] = "", dest_raw[1024] = "", src[1024], dest[1024];
  char err[256];
  http_param(r, "vol", vol, sizeof vol);
  http_param(r, "path", src_raw, sizeof src_raw);
  http_param(r, "dest", dest_raw, sizeof dest_raw);
  if (!dest_raw[0]) snprintf(dest_raw, sizeof dest_raw, "%s", plat_default_dest());
  if (vfs_clean_path(src_raw, src, sizeof src) ||
      vfs_clean_path(dest_raw, dest, sizeof dest)) {
    http_send_error(r, 400, "bad path");
    return;
  }
  int rc = mkdir_p(dest);
  if (rc) {
    snprintf(err, sizeof err, "cannot create %s: %s", dest, strerror(-rc));
    http_send_error(r, 400, err);
    return;
  }
  int id = jobs_copy(vol[0] ? vol : "ps5", src, dest, err, sizeof err);
  if (id < 0) {
    http_send_error(r, 400, err);
    return;
  }
  buf_t b;
  buf_init(&b);
  buf_printf(&b, "{\"job\":%d}", id);
  http_send_json(r, 200, &b);
  buf_free(&b);
}

static void route_jobs(http_req_t *r) {
  buf_t b;
  buf_init(&b);
  buf_puts(&b, "{\"jobs\":");
  jobs_json(&b);
  buf_puts(&b, "}");
  http_send_json(r, 200, &b);
  buf_free(&b);
}

static void route_cancel(http_req_t *r) {
  if (require_post(r)) return;
  char id[16] = "";
  http_param(r, "id", id, sizeof id);
  if (jobs_cancel(atoi(id))) {
    http_send_error(r, 404, "no such job");
    return;
  }
  route_jobs(r);
}

static void route_clear(http_req_t *r) {
  if (require_post(r)) return;
  jobs_clear_finished();
  route_jobs(r);
}

void api_handle(http_req_t *r) {
  static const struct {
    const char *path;
    void (*fn)(http_req_t *);
  } routes[] = {
      {"/", route_index},
      {"/index.html", route_index},
      {"/api/status", route_status},
      {"/api/volumes", route_volumes},
      {"/api/volinfo", route_volinfo},
      {"/api/list", route_list},
      {"/api/file", route_file},
      {"/api/rescan", route_rescan},
      {"/api/mount", route_mount},
      {"/api/unmount", route_unmount},
      {"/api/mkdir", route_mkdir},
      {"/api/copy", route_copy},
      {"/api/jobs", route_jobs},
      {"/api/jobs/cancel", route_cancel},
      {"/api/jobs/clear", route_clear},
  };
  for (size_t i = 0; i < sizeof routes / sizeof routes[0]; i++) {
    if (!strcmp(r->path, routes[i].path)) {
      routes[i].fn(r);
      return;
    }
  }
  http_send_error(r, 404, "not found");
}
