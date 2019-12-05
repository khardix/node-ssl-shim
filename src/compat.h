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

/** @file Compatibility layer for legacy OpenSSL.
 *
 * Most of the definitions are taken from official OpenSSL wiki:
 * <https://wiki.openssl.org/index.php/OpenSSL_1.1.0_Changes>.
 *
 * Other functions defined here are miscellaneous ones
 * that do not warrant a separate file (yet).
 */
#ifndef _NODE_SSL_SHIM_COMPAT_H_
#define _NODE_SSL_SHIM_COMPAT_H_

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>

#include "features.h"

#if OPENSSL_IS_LEGACY

/** Allocate and zero-fill a continuous chunk of memory. */
void *OPENSSL_zalloc(size_t size);

/** Create new HMAC_CTX. */
HMAC_CTX *HMAC_CTX_new();
/** Create new EVP_MD_CTX. */
EVP_MD_CTX *EVP_MD_CTX_new();

/** Retrieve Diffie-Hellman p, q, and g parameters. */
void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q,
		 const BIGNUM **g);
/** Retrieve RSA key parameters. */
void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e,
		  const BIGNUM **d);

/** Increment reference count of a private key. */
int EVP_PKEY_up_ref(EVP_PKEY *key);

/** Fill a contiguous memory with 0s and then free it. */
void OPENSSL_clear_free(void *memory, size_t len);

/** Cleans up digest context ctx and frees up the space allocated to it. */
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
/** Erase the key and any other data from the context and free it. */
void HMAC_CTX_free(HMAC_CTX *ctx);

#endif /* OPENSSL_IS_LEGACY */

#endif /* _NODE_SSL_SHIM_COMPAT_H_ */
