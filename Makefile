PKGNAME := node-ssl-shim

CC     ?= gcc
CFLAGS := -std=c11 -pedantic -Wall -Wextra -Werror -ggdb

# Standard installation directories, override as needed
prefix ?= /usr/local
includedir ?= $(prefix)/include
libdir ?= $(prefix)/lib

INSTALL ?= install -p
RM ?= rm -f

# Code lives in src directory
sources := $(wildcard src/*.c)
headers := $(wildcard src/*.h)
objects := $(addsuffix .o,$(basename $(sources)))

# Should link with OpenSSL 1.0.*
CFLAGS += $(shell pkg-config --cflags openssl)
LDFLAGS += $(shell pkg-config --libs-only-L openssl)
LDLIBS += $(shell pkg-config --libs-only-l openssl)

.PHONY: all clean install prebuilt test

all: lib$(PKGNAME).a

# Install files to configured directories
install: lib$(PKGNAME).a $(headers)
	$(INSTALL) -Dt$(libdir) -m0755 $<
	$(INSTALL) -Dt$(includedir)/$(PKGNAME) -m0644 $(headers)

# Generate archive with prebuilt files
prebuilt: $(PKGNAME)-prebuilt.tar.gz

# Build and run the test suite
test: test/suite
	@./$<

# Clean all build artifacts
clean:
	$(RM) -r $(PKGNAME)*.tar.gz dist/
	$(RM) test/suite test/*.o
	$(RM) lib$(PKGNAME).a
	$(RM) $(objects)


lib$(PKGNAME).a: lib$(PKGNAME).a($(objects))

$(PKGNAME)-prebuilt.tar.gz: override prefix := dist
$(PKGNAME)-prebuilt.tar.gz: install
	tar -czf $@ --transform='s|^dist/|$(PKGNAME)/|' $(wildcard dist/*)


test/suite: CFLAGS += $(shell pkg-config --cflags check)
test/suite: LDLIBS += $(shell pkg-config --libs check)
test/suite: $(addsuffix .o,$(basename $(wildcard test/*.c))) lib$(PKGNAME).a
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
