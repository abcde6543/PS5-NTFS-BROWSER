#include "platform.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __PROSPERO__

typedef struct notify_request {
  char useless1[45];
  char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);
int sceUserServiceInitialize(void *);
int sceSystemServiceLaunchWebBrowser(const char *uri, void *);

static int g_user_service;

void plat_init(void) {
  /* Needed for launching the browser; may already be initialised by the
   * loader, which is fine. */
  g_user_service = sceUserServiceInitialize(0) == 0;
}

void plat_notify(const char *fmt, ...) {
  notify_request_t req;
  memset(&req, 0, sizeof req);
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(req.message, sizeof req.message, fmt, ap);
  va_end(ap);
  sceKernelSendNotificationRequest(0, &req, sizeof req, 0);
  printf("[ntfs-browser] %s\n", req.message);
}

int plat_launch_browser(const char *url) {
  return sceSystemServiceLaunchWebBrowser(url, 0);
}

const char *plat_name(void) { return "ps5"; }
const char *plat_default_dest(void) { return "/data/NTFS-Copies"; }

void plat_places_json(buf_t *b) {
  static const struct { const char *path, *label; } places[] = {
      {"/data", "Internal /data"},
      {"/data/homebrew", "Homebrew"},
      {"/mnt/usb0", "USB 0 (exFAT/FAT)"}, {"/mnt/usb1", "USB 1 (exFAT/FAT)"},
      {"/mnt/usb2", "USB 2 (exFAT/FAT)"}, {"/mnt/usb3", "USB 3 (exFAT/FAT)"},
      {"/mnt/usb4", "USB 4 (exFAT/FAT)"}, {"/mnt/usb5", "USB 5 (exFAT/FAT)"},
      {"/mnt/usb6", "USB 6 (exFAT/FAT)"}, {"/mnt/usb7", "USB 7 (exFAT/FAT)"},
      {"/mnt/ext0", "Extended storage"}, {"/mnt/ext1", "M.2 storage"},
      {"/", "Root /"},
  };
  buf_puts(b, "[");
  int first = 1;
  for (size_t i = 0; i < sizeof places / sizeof places[0]; i++) {
    struct stat st;
    if (stat(places[i].path, &st) || !S_ISDIR(st.st_mode)) continue;
    buf_printf(b, "%s{\"path\":\"%s\",\"label\":\"%s\"}", first ? "" : ",",
               places[i].path, places[i].label);
    first = 0;
  }
  buf_puts(b, "]");
}

#else /* desktop build */

void plat_init(void) {}

void plat_notify(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "[ntfs-browser] ");
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}

int plat_launch_browser(const char *url) {
  (void)url;
  return -1;
}

const char *plat_name(void) { return "host"; }

const char *plat_default_dest(void) {
  static char dest[1024];
  if (!dest[0]) {
    char cwd[900];
    if (!getcwd(cwd, sizeof cwd)) strcpy(cwd, "/tmp");
    snprintf(dest, sizeof dest, "%s/NTFS-Copies", cwd);
  }
  return dest;
}

void plat_places_json(buf_t *b) {
  char cwd[1024];
  buf_puts(b, "[{\"path\":\"/\",\"label\":\"Root /\"}");
  const char *home = getenv("HOME");
  if (home && *home) {
    buf_puts(b, ",{\"path\":");
    buf_json_str(b, home);
    buf_puts(b, ",\"label\":\"Home\"}");
  }
  if (getcwd(cwd, sizeof cwd)) {
    buf_puts(b, ",{\"path\":");
    buf_json_str(b, cwd);
    buf_puts(b, ",\"label\":\"Working folder\"}");
  }
  buf_puts(b, "]");
}

#endif

void plat_ip(char *out, size_t len) {
  snprintf(out, len, "127.0.0.1");
  struct ifaddrs *ifa = NULL;
  if (getifaddrs(&ifa)) return;
  for (struct ifaddrs *i = ifa; i; i = i->ifa_next) {
    if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
    if (i->ifa_flags & IFF_LOOPBACK) continue;
    if (!(i->ifa_flags & IFF_UP)) continue;
    struct sockaddr_in *sa = (struct sockaddr_in *)i->ifa_addr;
    inet_ntop(AF_INET, &sa->sin_addr, out, (socklen_t)len);
    break;
  }
  freeifaddrs(ifa);
}
