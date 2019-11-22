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

.PHONY: all archive clean

all: lib$(PKGNAME).a
archive: $(PKGNAME).tar.gz

lib$(PKGNAME).a: lib$(PKGNAME).a($(objects))

dist/: lib$(PKGNAME).a $(headers)
	install -Dt $@ -m 0755 $<
	install -Dt $@/include/ssl-shim/ -m 0644 $(headers)

$(PKGNAME).tar.gz: dist/
	tar -czf $@ --transform='s|^$<|$(PKGNAME)/|' $(wildcard $<*)

clean:
	$(RM) -r $(PKGNAME).tar.gz dist/
	$(RM) lib$(PKGNAME).a
	$(RM) $(objects)
