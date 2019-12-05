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

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "constants.h"
#include "compat.h"

#if OPENSSL_IS_LEGACY

/** Allocate and zero-fill a continuous chunk of memory. */
void *OPENSSL_zalloc(size_t size)
{
	void *memory = OPENSSL_malloc(size);

	if (memory != NULL) {
		memset(memory, 0, size); // NOLINT – C11 provides memset_s
	}

	return memory;
}

/** Create new HMAC_CTX. */
HMAC_CTX *HMAC_CTX_new()
{
	HMAC_CTX *ctx = OPENSSL_zalloc(sizeof(HMAC_CTX));
	if (ctx != NULL) {
		HMAC_CTX_init(ctx);
	}

	return ctx;
}

/** Create new EVP_MD_CTX. */
EVP_MD_CTX *EVP_MD_CTX_new()
{
	return OPENSSL_zalloc(sizeof(EVP_MD_CTX));
}

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

/** One-shot signing of single block of data.
 *
 * @param[in] ctx The signature context.
 * @param[out] sigret The final signature.
 * @param[out] siglen Length of the final signature.
 * @param[in] tbs The block of data to be signed.
 * @param[in] tbslen Length of the block of data to be signed.
 * @return 1 for success, 0 for failure.
 */
int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen,
		   const unsigned char *tbs, size_t tbslen)
{
	if (ctx == NULL || tbs == NULL) {
		return 0;
	}

	if (sigret != NULL && (EVP_DigestSignUpdate(ctx, tbs, tbslen) <= 0)) {
		return 0;
	}

	return EVP_DigestSignFinal(ctx, sigret, siglen);
}
/** One-shot signature verification for single block of data.
 *
 * @param[in] ctx Verification context.
 * @param[in] sigret Signature to verify.
 * @param[in] siglen Length of the signature to verify.
 * @param[in] tbs Data to verify.
 * @param[in] tbslen Length of the data to verify.
 * @return 1 for success, 0 for failed verification,
 * other values for more serious errors.
 */
int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
		     size_t siglen, const unsigned char *tbs, size_t tbslen)
{
	if (ctx == NULL || sigret == NULL || tbs == NULL) {
		return -1;
	}

	if (EVP_DigestVerifyUpdate(ctx, tbs, tbslen) <= 0) {
		return -1;
	}

	return EVP_DigestVerifyFinal(ctx, sigret, siglen);
}

/** Finalize digest computation with XOF (eXtendable Output Functions).
 *
 * XOF is not supported by legacy OpenSSL, and as such,
 * this function always fails.
 */
int EVP_DigestFinalXOF(EVP_MD_CTX *ctx __attribute__((unused)),
		       unsigned char *md __attribute__((unused)),
		       size_t size __attribute__((unused)))
{
	EVPerr(EVP_F_EVP_DIGESTFINALXOF, EVP_R_UNSUPPORTED_ALGORITHM);
	return 0;
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
