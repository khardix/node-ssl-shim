PKGNAME := node-ssl-shim

CC     ?= gcc
CFLAGS := -std=c11 -pedantic -Wall -Wextra -Werror -ggdb

# Code lives in src directory
sources := $(wildcard src/*.c)
headers := $(wildcard src/*.h)
objects := $(addsuffix .o,$(basename $(sources)))

# Should link with OpenSSL 1.0.*
CFLAGS += $(shell pkg-config --cflags openssl)
LDFLAGS += $(shell pkg-config --libs-only-L openssl)
LDLIBS += $(shell pkg-config --libs-only-l openssl)

.PHONY: all archive clean test

all: lib$(PKGNAME).a test/suite
archive: $(PKGNAME).tar.gz
test: test/suite
	@./$<

lib$(PKGNAME).a: lib$(PKGNAME).a($(objects))

test/suite: CFLAGS += $(shell pkg-config --cflags check)
test/suite: LDLIBS += $(shell pkg-config --libs check)
test/suite: lib$(PKGNAME).a $(addsuffix .o,$(basename $(wildcard test/*.c)))
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

dist/: lib$(PKGNAME).a $(headers)
	install -Dt $@ -m 0755 $<
	install -Dt $@/include/ssl-shim/ -m 0644 $(headers)

$(PKGNAME).tar.gz: dist/
	tar -czf $@ --transform='s|^$<|$(PKGNAME)/|' $(wildcard $<*)

clean:
	$(RM) -r $(PKGNAME).tar.gz dist/
	$(RM) test/suite test/*.o
	$(RM) lib$(PKGNAME).a
	$(RM) $(objects)
