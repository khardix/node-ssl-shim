/*
 * MIT License
 *
 * Copyright (c) 2019 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/** @file Backports of BIO-related functions. */
#ifndef _NODE_SSL_SHIM_BIO_H_
#define _NODE_SSL_SHIM_BIO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "features.h"
#if OPENSSL_IS_LEGACY

#include <openssl/bio.h>

/** Associate a custom data with a BIO. */
void BIO_set_data(BIO *a, void *ptr);
/** Retrieve the custom data associated with a BIO. */
void *BIO_get_data(BIO *a);

/** Indicate initialization status by setting the `init` flag. */
void BIO_set_init(BIO *a, int init);
/** Retrieve current initialization status. */
int BIO_get_init(BIO *a);

/** Indicate shutdown status by setting the `shutdown` flag. */
void BIO_set_shutdown(BIO *a, int shut);
/** Retrieve current shutdown status. */
int BIO_get_shutdown(BIO *a);

/** Allocate new BIO_METHOD. */
BIO_METHOD *BIO_meth_new(int type, const char *name);

/** Get callback implementing the BIO_write operation. */
int (*BIO_meth_get_write(const BIO_METHOD *biom))(BIO *, const char *, int);
/** Set callback implementing the BIO_write operation. */
int BIO_meth_set_write(BIO_METHOD *biom,
		       int (*write)(BIO *, const char *, int));

/** Get callback implementing the BIO_read operation. */
int (*BIO_meth_get_read(const BIO_METHOD *biom))(BIO *, char *, int);
/** Set callback implementing the BIO_read operation. */
int BIO_meth_set_read(BIO_METHOD *biom, int (*read)(BIO *, char *, int));

/** Get callback implementing the BIO_puts operation. */
int (*BIO_meth_get_puts(const BIO_METHOD *biom))(BIO *, const char *);
/** Set callback implementing the BIO_puts operation. */
int BIO_meth_set_puts(BIO_METHOD *biom, int (*puts)(BIO *, const char *));

/** Get callback implementing the BIO_gets operation. */
int (*BIO_meth_get_gets(const BIO_METHOD *biom))(BIO *, char *, int);
/** Set callback implementing the BIO_gets operation. */
int BIO_meth_set_gets(BIO_METHOD *biom, int (*gets)(BIO *, char *, int));

/** Get callback implementing the BIO_ctrl operation. */
long (*BIO_meth_get_ctrl(const BIO_METHOD *biom))(BIO *, int, long, void *);
/** Set callback implementing the BIO_ctrl operation. */
int BIO_meth_set_ctrl(BIO_METHOD *biom, long (*ctrl)(BIO *, int, long, void *));

/** Get callback implementing the BIO_new operation. */
int (*BIO_meth_get_create(const BIO_METHOD *bion))(BIO *);
/** Set callback implementing the BIO_new operation. */
int BIO_meth_set_create(BIO_METHOD *biom, int (*create)(BIO *));

/** Get callback implementing the BIO_free operation. */
int (*BIO_meth_get_destroy(const BIO_METHOD *biom))(BIO *);
/** Set callback implementing the BIO_free operation. */
int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy)(BIO *));

#endif /* OPENSSL_IS_LEGACY */
#ifdef __cplusplus
}
#endif
#endif /* _NODE_SSL_SHIM_BIO_H_ */
