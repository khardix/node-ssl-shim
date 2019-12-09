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

#endif /* OPENSSL_IS_LEGACY */
#endif /* _NODE_SSL_SHIM_BIO_H_ */
