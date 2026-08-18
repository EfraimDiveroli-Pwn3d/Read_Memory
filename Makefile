CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -g
LDFLAGS ?=
STATIC_CC ?= musl-gcc
STRIP ?= strip

PROGRAM := readmem
SOURCE := Read_mem.c
RELEASE_DIR ?= dist
RELEASE_ARCH ?= $(shell uname -m)
STATIC_BINARY := $(RELEASE_DIR)/$(PROGRAM)-linux-$(RELEASE_ARCH)
RELEASE_CFLAGS ?= -O2 -DNDEBUG -ffunction-sections -fdata-sections -Werror
RELEASE_LDFLAGS ?= -static -Wl,--gc-sections

WARNINGS := -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2
STANDARD := -std=c17
HARDENING_CFLAGS := -D_FORTIFY_SOURCE=2 -fstack-protector-strong
HARDENING_LDFLAGS := -Wl,-z,relro,-z,now,-z,noexecstack

.PHONY: all clean test install release release-static

all: $(PROGRAM)

$(PROGRAM): $(SOURCE)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(STANDARD) $(WARNINGS) $(HARDENING_CFLAGS) $< \
		$(LDFLAGS) $(HARDENING_LDFLAGS) -o $@

release: release-static

release-static: $(STATIC_BINARY)

$(STATIC_BINARY): $(SOURCE)
	mkdir -p "$(RELEASE_DIR)"
	$(STATIC_CC) $(CPPFLAGS) $(RELEASE_CFLAGS) $(STANDARD) $(WARNINGS) \
		$(HARDENING_CFLAGS) $< $(RELEASE_LDFLAGS) $(HARDENING_LDFLAGS) -o $@
	$(STRIP) --strip-unneeded $@

tests/readmem-test-target: tests/target.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(STANDARD) $(WARNINGS) $< $(LDFLAGS) -o $@

test: readmem tests/readmem-test-target
	bash ./tests/integration.sh

install: $(PROGRAM)
	install -d "$(DESTDIR)/usr/local/bin"
	install -m 0755 $(PROGRAM) "$(DESTDIR)/usr/local/bin/$(PROGRAM)"

clean:
	rm -f $(PROGRAM) tests/readmem-test-target $(STATIC_BINARY)
