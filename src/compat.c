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

#include <stdatomic.h>

#include "compat.h"

#if OPENSSL_IS_LEGACY

const SSL_METHOD *TLS_method()
{
	return SSLv23_method();
}

const SSL_METHOD *TLS_server_method()
{
	return SSLv23_server_method();
}

const SSL_METHOD *TLS_client_method()
{
	return SSLv23_client_method();
}

/** Atomically increase reference count for X509. */
int X509_up_ref(X509 *x)
{
	if (x == NULL) {
		return 0;
	}

	int prev = atomic_fetch_add_explicit((_Atomic int *)&x->references, 1,
					     memory_order_relaxed);
	return (prev > 1) ? 1 : 0;
}
/** Atomically increase reference count for X509_STORE. */
int X509_STORE_up_ref(X509_STORE *xs)
{
	if (xs == NULL) {
		return 0;
	}

	int prev = atomic_fetch_add_explicit((_Atomic int *)&xs->references, 1,
					     memory_order_relaxed);
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
