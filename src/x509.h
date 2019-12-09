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

/** @file X509 compatibility layer for legacy OpenSSL. */

#ifndef _NODE_SSL_SHIM_X509_H_
#define _NODE_SSL_SHIM_X509_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "features.h"
#if OPENSSL_IS_LEGACY

#include <openssl/x509.h>

/** Increment X509 certificate reference. */
int X509_up_ref(X509 *x);
int X509_STORE_up_ref(X509_STORE *x);

#endif /* OPENSSL_IS_LEGACY */
#ifdef __cplusplus
}
#endif
#endif /* _NODE_SSL_SHIM_X509_H_ */
