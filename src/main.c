/* NTFS Browser for jailbroken PS5 consoles.
 *
 * Runs as an ELF payload. It finds NTFS formatted USB drives, mounts them
 * read-only with a built-in NTFS driver and serves a file browser UI on
 * http://<console-ip>:8085 that also opens in the PS5's own web browser.
 *
 * Desktop build (for testing): ./ntfs-browser [-p port] [image-or-device ...] */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api.h"
#include "http.h"
#include "jobs.h"
#include "platform.h"
#include "vfs.h"

#ifndef DEFAULT_PORT
#define DEFAULT_PORT 8085
#endif

#ifndef LAUNCH_BROWSER
#define LAUNCH_BROWSER 1
#endif

/* Pick up drives that are plugged in or removed while we run. */
static void *hotplug_thread(void *arg) {
  (void)arg;
  int last = -1;
  for (;;) {
    sleep(3);
    unsigned before = vfs_generation();
    int n = vfs_rescan(0);
    if (vfs_generation() != before && n > last && last >= 0)
      plat_notify("NTFS Browser: %d NTFS volume(s) available", n);
    last = n;
  }
  return NULL;
}

int main(int argc, char **argv) {
  uint16_t port = DEFAULT_PORT;
  signal(SIGPIPE, SIG_IGN);
  plat_init();
  vfs_init();

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-p") && i + 1 < argc) {
      port = (uint16_t)atoi(argv[++i]);
    } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
      printf("usage: %s [-p port] [ntfs-image-or-device ...]\n", argv[0]);
      return 0;
    } else {
      vfs_add_source(argv[i]);
    }
  }

  int fd = http_listen(port);
  if (fd < 0) {
    if (fd == -EADDRINUSE) {
      plat_notify("NTFS Browser is already running on port %u", port);
#if LAUNCH_BROWSER && defined(__PROSPERO__)
      char url[64];
      snprintf(url, sizeof url, "http://127.0.0.1:%u/", port);
      plat_launch_browser(url);
#endif
    } else {
      plat_notify("NTFS Browser: cannot listen on port %u: %s", port, strerror(-fd));
    }
    return 1;
  }

  api_set_port(port);
  jobs_init();
  int n = vfs_rescan(1);

  char ip[64];
  plat_ip(ip, sizeof ip);
  plat_notify("NTFS Browser %s\nhttp://%s:%u\n%d NTFS volume(s) found", APP_VERSION,
              ip, port, n);

  pthread_t t;
  pthread_create(&t, NULL, hotplug_thread, NULL);
  pthread_detach(t);

#if LAUNCH_BROWSER && defined(__PROSPERO__)
  {
    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%u/", port);
    if (plat_launch_browser(url))
      plat_notify("Open http://%s:%u in a browser", ip, port);
  }
#endif

  http_run(fd, api_handle);
  return 0;
}
