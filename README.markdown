NodeJS – OpenSSL shim library
=============================

This library implements a thin compatibility layer between OpenSSL 1.0.*
and NodeJS versions that do not support building against that OpenSSL version(s) natively.

The goal is to backport (ideally), re-implement (usually), or disable (where necessary)
any OpenSSL APIs that NodeJS expects, but the older OpenSSL version does not provide.

Building and installation
-------------------------

The project use simple Makefile to both build and install:

```sh
$ make
# make prefix=${PREFIX} install  # Installs to /usr/local by default
```

Dependencies are handled using `pkg-config`;
currently, the only dependency is OpenSSL itself in an appropriate version.

Documentation
-------------

All provided functions shall behave as described in the [official OpenSSL manual pages][];
in case of ambiguity, they shall follow the implementation in [OpenSSL upstream][].
Short summary is usually provided in the form of Doxygen-style comments in the source code,
but only as a convenience – the manual pages are the definitive source of information.

The back-ported constants shall have the same value as defined in the [OpenSSL upstream][].

[official OpenSSL manual pages]: https://www.openssl.org/docs/manpages.html
[OpenSSL upstream]: https://www.openssl.org/source/gitrepo.html

Releases and versioning
-----------------------

This library should currently be considered as experimental;
no versioning scheme is implementer nor any "stable" release planned.
If you need one, contact the maintainers and we will figure something out.

License
-------

The library is currently available under MIT license
(see the [LICENSE][./LICENSE] file for details).
