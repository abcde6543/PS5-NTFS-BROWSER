# NTFS Browser for PS5

A file browser payload for jailbroken PS5 consoles that can **read NTFS
drives**. The PS5 only understands exFAT and FAT32, so an NTFS-formatted USB
drive normally shows up as unusable. This payload includes its own read-only
NTFS driver, so you can browse such a drive, preview files and copy them onto
the console, without reformatting.

It runs as a small web server on the console. The interface opens in the PS5's
own browser (controller friendly), and you can also open it from a phone or PC
on the same network.

```
http://<ps5-ip>:8085
```

![Browsing an NTFS drive](docs/browser.png)

## Features

- **Finds NTFS drives automatically**, including drives plugged in while it
  runs. Handles MBR (including logical partitions), GPT and unpartitioned
  drives. You can also open raw `.img` disk images.
- **Browse** with breadcrumbs, filter-as-you-type, sorting, and a list that
  stays fast with tens of thousands of files.
- **Previews**: images, video and audio (streamed, with seeking), text in
  UTF-8 and UTF-16, and a hex view for binary files.
- **Copy to PS5**: copy files or whole folders from the NTFS drive to internal
  storage (`/data/...`) or an exFAT USB drive. Copies run in the background
  with progress, speed and time remaining, and can be cancelled. The free
  space is checked before starting. Files that already exist are skipped, so
  you can resume an interrupted copy.
- **Download** files to a phone or PC through the browser.

  ![Copy progress](docs/transfers.png)

- **Also browses the console's own file system** (`/data`, `/mnt/usb0`, ...).
- **Controller and keyboard navigation** (see below).

### NTFS support

| | |
|---|---|
| NTFS 3.0 / 3.1 (Windows XP – 11) | ✅ |
| Cluster sizes 512 B – 2 MB | ✅ |
| Huge, fragmented files (`$ATTRIBUTE_LIST`) | ✅ |
| Big folders (multi-level directory B-trees) | ✅ |
| Compressed files (LZNT1, "Compress contents to save disk space") | ✅ |
| Sparse files | ✅ |
| Unicode names, including emoji | ✅ |
| Case-insensitive paths, hard links | ✅ |
| Volumes not cleanly unmounted / hibernated by Windows Fast Startup | ✅ read-only, flagged as "dirty" |
| Encrypted files (EFS) | ❌ listed, but contents can't be read |
| Symlinks / junctions | shown, not followed |
| Alternate data streams | ignored (main stream only) |
| Writing to NTFS | ❌ read-only by design |

The driver never writes to the drive. If Windows wasn't shut down cleanly, the
most recent changes may still be in the NTFS journal and won't be visible. Use
"Safely remove" on Windows before unplugging.

## Requirements

- A PS5 running an exploit with an **ELF loader**, for example
  [elfldr](https://github.com/ps5-payload-dev/elfldr) on port 9021 or
  etaHEN's payload loader. Firmware support depends on your exploit chain, not
  on this payload.
- A USB drive formatted as NTFS.

## Install and run

1. Get `ntfs-browser.elf` (build it as described below, or use the prebuilt
   file in this folder).
2. Run your jailbreak so the ELF loader is listening.
3. Send the payload, using one of these:
   ```sh
   # with the PS5 payload SDK
   make deploy PS5_HOST=192.168.1.50
   # or with netcat / socat
   nc -q0 192.168.1.50 9021 < ntfs-browser.elf
   socat -u FILE:ntfs-browser.elf TCP:192.168.1.50:9021
   ```
   With etaHEN you can also put the file in its payload folder and launch it
   from the etaHEN menu.
4. A notification shows the address, and the PS5 browser opens on the file
   browser. Plug in the NTFS drive; it appears in the sidebar within about
   3 seconds.

Sending the payload again while it's already running just reopens the
browser.

### Controls

| Controller | Keyboard | Action |
|---|---|---|
| D-pad ↑ ↓ / left stick | ↑ ↓ | Move |
| ✕ | Enter / → | Open folder or preview file |
| ○ | Backspace / ← | Parent folder (closes dialogs) |
| □ | Space | Select / deselect |
| △ | C | Copy selection to PS5 |
| L1 / R1 | Page Up / Down | Page up / down |
| | `/` | Filter |

In the PS5 browser, the controller usually drives a pointer, so you can always
click as well. The gamepad mappings work where the browser exposes the
Gamepad API.

> **Downloads on the console:** the PS5 browser can't save files. On the
> console, use **Copy to PS5**; use **Download** from a phone or PC.

## Building

### PS5 payload

Install the [PS5 payload SDK](https://github.com/ps5-payload-dev/sdk) (needs
`clang` and `lld` 18+), either from its release zip or from source:

```sh
git clone https://github.com/ps5-payload-dev/sdk.git
cd sdk && sudo make DESTDIR=/opt/ps5-payload-sdk install
```

Then:

```sh
make                                  # -> ntfs-browser.elf
make PS5_PAYLOAD_SDK=/path/to/sdk     # SDK elsewhere
make PORT=9090                        # different HTTP port (default 8085)
make LAUNCH_BROWSER=0                 # don't open the PS5 browser on start
```

### Desktop build (for development)

The same code builds on Linux, macOS and FreeBSD. It serves the same UI and
reads NTFS images or devices you pass on the command line:

```sh
make host
./build/ntfs-browser -p 8085 my-ntfs.img /dev/sdb   # then open http://localhost:8085
./build/ntfstool ls   my-ntfs.img /some/folder
./build/ntfstool cat  my-ntfs.img /some/file.txt
./build/ntfstool tree my-ntfs.img
./build/ntfstool info my-ntfs.img
```

### Tests

```sh
sudo make test     # Linux; needs ntfs-3g, attr (setfattr), python3 and /dev/fuse
```

- `tests/run_tests.py` builds NTFS images with `mkntfs`, fills them through
  `ntfs-3g` with the awkward cases (6,000-file folders, files fragmented across
  13 MFT records, compressed and sparse files, Unicode and case-only name
  differences, hard links, 512 B / 1 KB / 64 KB clusters, MBR / GPT / logical
  partitions). It then checks that this driver lists the same tree and returns
  byte-identical contents for every file. Runs under AddressSanitizer and UBSan.
- `tests/fuzz.py` corrupts NTFS metadata at random (300 images) and checks
  that damaged drives produce errors, never crashes, hangs or leaks.
- `tests/test_server.py` exercises the HTTP API end to end: listing,
  downloads, byte ranges, keep-alive, 16 parallel streams, copy jobs, resume,
  cancel, mount and unmount, and the security checks.

## How it works

```
src/
  main.c       start-up, notifications, hot-plug thread
  http.c       small HTTP/1.1 server (keep-alive, ranges, thread per client)
  api.c        JSON API + file streaming
  vfs.c        one view over console storage and NTFS volumes; device scanning
  jobs.c       background copy queue
  ntfs.c       the read-only NTFS driver
  part.c       MBR / GPT partition tables
  bdev.c       sector-aligned raw device access with a read cache
  utf.c        UTF-16 <-> UTF-8
  platform.c   PS5 specifics (notifications, opening the browser, IP address)
web/index.html the whole UI, embedded into the payload at build time
```

USB drives appear on the PS5 as FreeBSD `da` devices (`/dev/da0`, ...). The
payload opens the device read-only, finds the partitions, and reads NTFS
structures directly: boot sector → `$MFT` → MFT records (with update-sequence
fixups) → attributes → data runs. Raw disk devices only allow reads at
sector-aligned offsets and lengths, so `bdev.c` rounds every read to the
sector size and keeps an 8 MB block cache.

### API

All responses are JSON unless noted. Requests that change something must be
`POST` and carry an `X-NTFSB: 1` header.

| Method | Path | Parameters |
|---|---|---|
| GET | `/api/status` | |
| GET | `/api/volumes` | |
| GET | `/api/volinfo` | `vol` |
| GET | `/api/list` | `vol`, `path` |
| GET/HEAD | `/api/file` (raw bytes, supports `Range`) | `vol`, `path`, `dl=1` to download |
| POST | `/api/copy` | `vol`, `path`, `dest` |
| GET | `/api/jobs` | |
| POST | `/api/jobs/cancel` | `id` |
| POST | `/api/jobs/clear` | |
| POST | `/api/rescan`, `/api/mount` (`path`), `/api/unmount` (`vol`), `/api/mkdir` (`path`) | |

`vol` is `ps5` for the console's own file system, or the `id` of an NTFS
volume from `/api/volumes`.

## Security

While it runs, **anyone on your local network can browse the console's files
and the NTFS drive, and start copies onto the console**. This is the same as
FTP payloads. The server never deletes or overwrites anything except files
inside the copy destination you choose. State-changing requests need a custom
header, so other websites open in the PS5 browser can't trigger them. HTML and
SVG files from the drive are served as plain text so they can't run scripts.
Stop the payload, or reboot, when you're done, and don't expose port 8085 to
the internet.

## Troubleshooting

- **Drive not listed.** Press **Rescan**. Check that the drive is NTFS and
  not BitLocker-encrypted. If your console names USB devices differently, use
  **Open image** with the device path (for example `/dev/da0`); browse `/dev`
  under *Root /* to find it. Some USB hubs and enclosures need a moment after
  plugging in, so the app retries several times.
- **"Volume is dirty".** Windows didn't unmount it cleanly, or Fast Startup
  hibernated it. Browsing works; to see the latest changes, plug it into
  Windows and use *Safely remove* (or run `chkdsk`).
- **"Port 8085 already in use".** Another copy is running. Sending the payload
  again just reopens the browser.
- **Copy fails with "not enough space".** The total size of the selection is
  checked against free space in the destination before copying.

## License

GPL-3.0-or-later, the same as the PS5 payload SDK. See `LICENSE`.
