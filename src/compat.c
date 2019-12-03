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

/** @file Implementation of compatibility layer for legacy OpenSSL.
 *
 * Most of the definitions are taken from official OpenSSL wiki:
 * <https://wiki.openssl.org/index.php/OpenSSL_1.1.0_Changes>.
 */

#include <openssl/crypto.h>

#include "compat.h"

#if OPENSSL_IS_LEGACY

/** Retrieve Diffie-Hellman p, q, and g parameters. */
void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q,
		 const BIGNUM **g)
{
	if (dh == NULL) {
		return;
	}

	if (p != NULL) {
		*p = dh->p;
	}
	if (q != NULL) {
		*q = dh->q;
	}
	if (g != NULL) {
		*g = dh->g;
	}
}
/** Retrieve RSA key parameters. */
void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e,
		  const BIGNUM **d)
{
	if (r == NULL) {
		return;
	}

	if (n != NULL) {
		*n = r->n;
	}
	if (e != NULL) {
		*e = r->e;
	}
	if (d != NULL) {
		*d = r->d;
	}
}

/** Increment reference count of a private key. */
int EVP_PKEY_up_ref(EVP_PKEY *key)
{
	if (key == NULL) {
		return 0;
	}

	int prev = CRYPTO_add(&key->references, 1, CRYPTO_LOCK_EVP_PKEY);
	return (prev > 1) ? 1 : 0;
}

/** Fill a contiguous memory with 0s and then free it. */
void OPENSSL_clear_free(void *memory, size_t len)
{
	if (memory == NULL || len == 0) {
		return;
	}

	OPENSSL_cleanse(memory, len);
	OPENSSL_free(memory);
}

/** Cleans up digest context ctx and frees up the space allocated to it. */
void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
	if (ctx == NULL) {
		return;
	}

	EVP_MD_CTX_cleanup(ctx);
	OPENSSL_free(ctx);
}

/** Erase the key and any other data from the context and free it. */
void HMAC_CTX_free(HMAC_CTX *ctx)
{
	if (ctx == NULL) {
		return;
	}

	HMAC_CTX_cleanup(ctx);
	EVP_MD_CTX_free(&ctx->i_ctx);
	EVP_MD_CTX_free(&ctx->o_ctx);
	EVP_MD_CTX_free(&ctx->md_ctx);
	OPENSSL_free(ctx);
}

#endif /* OPENSSL_IS_LEGACY */
