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

#include <limits.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/dsa.h>
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

/** Duplicate memory contents in a new location. */
void *CRYPTO_memdup(const void *data, size_t size, const char *file, int line)
{
	void *result = NULL;

	if (data == NULL || size > INT_MAX) {
		return result;
	}

	result = CRYPTO_malloc(size, file, line);
	if (result == NULL) {
		return result;
	}

	return memcpy(result, data, size); // NOLINT – C11 provides memcpy_s
}

/** Convert n to zero-padded big-endian form. */
int BN_bn2binpad(const BIGNUM *n, unsigned char *to, int tolen)
{
	if (n == NULL || to == NULL || tolen < 0) {
		return -1;
	}

	/* Set the whole buffer to zero, then write the number at the end. */
	size_t actual_size = BN_num_bytes(n);
	intmax_t offset = (intmax_t)tolen - (intmax_t)actual_size;
	if (offset < 0) {
		return -1;
	}

	OPENSSL_cleanse(to, tolen);
	return BN_bn2bin(n, to + offset);
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
/** Set Diffie-Hellman p, q, and g parameters.
 *
 * If the fields p and/or g in dh are NULL,
 * the corresponding parameter must not be NULL.
 * The q field may remain NULL.
 */
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
	if (dh == NULL || (dh->p == NULL && p == NULL) ||
	    (dh->g == NULL && g == NULL)) {
		return 0;
	}

	if (p != NULL) {
		BN_free(dh->p);
		dh->p = p;
	}
	if (q != NULL) {
		BN_free(dh->q);
		dh->q = q;
	}
	if (g != NULL) {
		BN_free(dh->g);
		dh->g = g;
	}

	if (q != NULL) {
		dh->length = BN_num_bits(q);
	}

	return 1;
}
/** Retrieve public and private keys from DH structure. */
void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
	if (dh == NULL) {
		return;
	}
	if (pub_key != NULL) {
		*pub_key = dh->pub_key;
	}
	if (priv_key != NULL) {
		*priv_key = dh->priv_key;
	}
}
/** Set Diffie-Hellman public and/or private keys.
 *
 * According to OpenSSL wiki:
 *
 * > If the pub_key field in dh is NULL,
 * > the pub_key parameter must not be NULL.
 * > priv_key field may be left NULL.
 *
 * However, the NodeJS assumes that the keys might be set independently,
 * so the above property is not checked.
 */
int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
	if (dh == NULL) {
		return 0;
	}

	if (pub_key != NULL) {
		BN_free(dh->pub_key);
		dh->pub_key = pub_key;
	}
	if (priv_key != NULL) {
		BN_free(dh->priv_key);
		dh->priv_key = priv_key;
	}

	return 1;
}
/** Retrieve DSA parameter p. */
const BIGNUM *DSA_get0_p(const DSA *dsa)
{
	if (dsa == NULL) {
		return NULL;
	}

	return dsa->p;
}
/** Retrieve DSA parameter q. */
const BIGNUM *DSA_get0_q(const DSA *dsa)
{
	if (dsa == NULL) {
		return NULL;
	}

	return dsa->q;
}
/** Retrieve DSA parameter q. */
const BIGNUM *DSA_get0_g(const DSA *dsa)
{
	if (dsa == NULL) {
		return NULL;
	}

	return dsa->g;
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
/** Retrieve ECDSA_SIG parameter r. */
const BIGNUM *ECDSA_SIG_get0_r(const ECDSA_SIG *sig)
{
	if (sig == NULL) {
		return 0;
	}

	return sig->r;
}
/** Retrieve ECDSA_SIG parameter s. */
const BIGNUM *ECDSA_SIG_get0_s(const ECDSA_SIG *sig)
{
	if (sig == NULL) {
		return 0;
	}

	return sig->s;
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

/** Extract DSA private key without incrementing reference count.
 *
 * @return Pointer to DSA structure, or NULL if the key is of invalid type.
 */
DSA *EVP_PKEY_get0_DSA(EVP_PKEY *key)
{
	if (key == NULL || key->type != EVP_PKEY_DSA) {
		return NULL;
	}

	return key->pkey.dsa;
}

/** Extract EC_KEY private key without incrementing reference count.
 *
 * @return Pointer to EC_KEY structure, or NULL if the key is of invalid type.
 */
EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *key)
{
	if (key == NULL || key->type != EVP_PKEY_EC) {
		return NULL;
	}

	return key->pkey.ec;
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

	EVP_MD_CTX_cleanup(&ctx->i_ctx);
	EVP_MD_CTX_cleanup(&ctx->o_ctx);
	EVP_MD_CTX_cleanup(&ctx->md_ctx);
	HMAC_CTX_cleanup(ctx);
	OPENSSL_free(ctx);
}

#endif /* OPENSSL_IS_LEGACY */
