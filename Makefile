# NTFS Browser for jailbroken PS5 consoles.
#
#   make                 build the PS5 payload  (needs PS5_PAYLOAD_SDK)
#   make deploy          send it to the console (PS5_HOST, PS5_PORT)
#   make host            build the desktop version + ntfstool for testing
#   make test            run the NTFS test suite (Linux, root, ntfs-3g)
#   make clean

PS5_HOST ?= ps5
PS5_PORT ?= 9021
PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk

PORT           ?= 8085
LAUNCH_BROWSER ?= 1

HOST_CC ?= cc
HOST_WARN := $(shell $(HOST_CC) -Werror -Wno-format-truncation -x c -c -o /dev/null /dev/null 2>/dev/null && echo -Wno-format-truncation)

SRCS := src/main.c src/api.c src/http.c src/vfs.c src/jobs.c src/platform.c \
        src/ntfs.c src/bdev.c src/part.c src/utf.c
HDRS := $(wildcard src/*.h) build/web_index.h

COMMON_CFLAGS := -std=gnu11 -Wall -Wextra -Wno-unused-parameter -O2 -Ibuild \
                 -DDEFAULT_PORT=$(PORT) -DLAUNCH_BROWSER=$(LAUNCH_BROWSER)

PS5_CC     := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
PS5_STRIP  := $(PS5_PAYLOAD_SDK)/bin/prospero-strip
PS5_DEPLOY := $(PS5_PAYLOAD_SDK)/bin/prospero-deploy

ELF := ntfs-browser.elf

.PHONY: all ps5 host test deploy clean

all: ps5

ps5: $(ELF)

$(ELF): $(SRCS) $(HDRS)
	@test -x $(PS5_CC) || { echo "PS5 SDK not found: set PS5_PAYLOAD_SDK (see README)"; exit 1; }
	$(PS5_CC) $(COMMON_CFLAGS) -o $@ $(SRCS) -lSceSystemService -lSceUserService -lpthread
	$(PS5_STRIP) --strip-debug $@ 2>/dev/null || true

build/bin2c: tools/bin2c.c
	@mkdir -p build
	$(HOST_CC) -O2 -o $@ $<

build/web_index.h: web/index.html build/bin2c
	build/bin2c $< $@ web_index_html

host: build/ntfs-browser build/ntfstool

build/ntfs-browser: $(SRCS) $(HDRS)
	$(HOST_CC) $(COMMON_CFLAGS) $(HOST_WARN) -D_GNU_SOURCE -g -o $@ $(SRCS) -lpthread

build/ntfstool: tools/ntfstool.c src/ntfs.c src/bdev.c src/part.c src/utf.c $(wildcard src/*.h)
	$(HOST_CC) $(COMMON_CFLAGS) $(HOST_WARN) -D_GNU_SOURCE -g -o $@ tools/ntfstool.c src/ntfs.c src/bdev.c src/part.c src/utf.c -lpthread

# Sanitiser build of the test tool, used by the test suite.
build/ntfstool-asan: tools/ntfstool.c src/ntfs.c src/bdev.c src/part.c src/utf.c $(wildcard src/*.h)
	@mkdir -p build
	$(HOST_CC) -std=gnu11 -D_GNU_SOURCE -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
	  -o $@ tools/ntfstool.c src/ntfs.c src/bdev.c src/part.c src/utf.c -lpthread

test: build/ntfstool-asan build/ntfs-browser
	python3 tests/run_tests.py build/ntfstool-asan
	python3 tests/fuzz.py build/ntfstool-asan
	python3 tests/test_server.py build/ntfs-browser

deploy: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $(ELF)

clean:
	rm -rf build $(ELF)
