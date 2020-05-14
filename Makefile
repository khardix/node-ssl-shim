# ### Metadata ################################################################
PKGNAME     := node-ssl-shim
VERSION     := $(shell git rev-parse --short --tags HEAD||echo "UNKNOWN")

# ### Installation directories ################################################
prefix      := /usr/local
includedir   = $(prefix)/include
libdir       = $(prefix)/lib

# ### Compilation configuration ###############################################
CC          := gcc
CFLAGS      := -std=c11 -pedantic -Wall -Wextra -Werror -ggdb -fPIC

INSTALL     := install -p
RM          := rm -f

# Code lives in src directory
sources := $(wildcard src/*.c)
headers := $(wildcard src/*.h)
objects := $(sources:.c=.o)

# Should link with OpenSSL 1.0.*
CFLAGS += $(shell pkg-config --cflags openssl)
LDFLAGS += $(shell pkg-config --libs-only-L openssl)
LDLIBS += $(shell pkg-config --libs-only-l openssl)

# ### Compilation rules #######################################################
.PHONY: all archive wip-archive install prebuilt test clean

# Compile the project
all: lib$(PKGNAME).a

# Archive of the current (committed) git HEAD
archive: $(PKGNAME)-$(VERSION).tar.gz
# Archive of the current state of the directory, including uncommitted changes
wip-archive: $(PKGNAME)-wip.tar.gz

# Install output files to appropriate directories
install: lib$(PKGNAME).a $(headers) | $(libdir)/ $(includedir)/$(PKGNAME)/
	$(INSTALL) -t$(libdir) -m0755 $<
	$(INSTALL) -t$(includedir)/$(PKGNAME) -m0644 $(headers)

# Generate archive with prebuilt files
prebuilt: $(PKGNAME)-prebuilt.tar.gz

# Build and run the test suite
test: test/suite
	@./$<

# Clean all build artifacts
clean:
	$(RM) -r $(PKGNAME)*.tar.gz $(PKGNAME)/
	$(RM) test/suite test/*.o
	$(RM) lib$(PKGNAME).a
	$(RM) $(objects)


lib$(PKGNAME).a: lib$(PKGNAME).a($(objects))

%/:
	mkdir -p $@

$(PKGNAME)-$(VERSION).tar.gz:
	git archive -o $(PKGNAME)-$(VERSION).tar.gz --prefix=$(PKGNAME)/ HEAD

$(PKGNAME)-wip.tar.gz:
	@touch $@  # tar complains when directory changes while it is archived
	tar --exclude-vcs --exclude-vcs-ignores --transform='s|^\.|$(PKGNAME)|' \
		-czf $@ .

$(PKGNAME)-prebuilt.tar.gz: override prefix := $(PKGNAME)
$(PKGNAME)-prebuilt.tar.gz: install
	tar -czf $@ $(wildcard $(PKGNAME)/*)


test/suite: CFLAGS += $(shell pkg-config --cflags check)
test/suite: LDLIBS += $(shell pkg-config --libs check)
test/suite: $(addsuffix .o,$(basename $(wildcard test/*.c))) lib$(PKGNAME).a
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
