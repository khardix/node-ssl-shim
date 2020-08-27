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

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>

#include "features.h"

#if OPENSSL_IS_LEGACY

/** Allocate and zero-fill a continuous chunk of memory. */
void *OPENSSL_zalloc(size_t size);

/** Duplicate memory into new location. */
void *CRYPTO_memdup(const void *data, size_t size, const char *file, int line);
#define OPENSSL_memdup(data, size) \
	CRYPTO_memdup((data), (size), __FILE__, __LINE__)

/** Convert n to zero-padded big-endian form. */
int BN_bn2binpad(const BIGNUM *n, unsigned char *to, int tolen);

/** Create new HMAC_CTX. */
HMAC_CTX *HMAC_CTX_new();
/** Create new EVP_MD_CTX. */
EVP_MD_CTX *EVP_MD_CTX_new();

/** RSA-PSS macros.
 *
 * These should all fail with undefined operation error on legacy OpenSSL.
 */
#define EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, len)              \
	EVP_PKEY_CTX_ctrl((ctx), EVP_PKEY_RSA_PSS, EVP_PKEY_OP_KEYGEN, \
			  EVP_PKEY_CTRL_RSA_PSS_SALTLEN, (len), NULL)
#define EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, md)               \
	EVP_PKEY_CTX_ctrl((ctx), EVP_PKEY_RSA_PSS, EVP_PKEY_OP_KEYGEN, \
			  EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void *)(md))
#define EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md)                    \
	EVP_PKEY_CTX_ctrl((ctx), EVP_PKEY_RSA_PSS, EVP_PKEY_OP_KEYGEN, \
			  EVP_PKEY_CTRL_MD, 0, (void *)(md))

/** Retrieve internal pointer to ASN.1 data. */
const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *astring);
/** Retrieve Diffie-Hellman p, q, and g parameters. */
void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q,
		 const BIGNUM **g);
/** Set Diffie-Hellman p, q, and g parameters. */
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
/** Retrieve public and private keys from DH structure. */
void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key);
/** Set Diffie-Hellman public and/or private keys. */
int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key);
/** Retrieve DSA parameter p. */
const BIGNUM *DSA_get0_p(const DSA *dsa);
/** Retrieve DSA parameter q. */
const BIGNUM *DSA_get0_q(const DSA *dsa);
/** Retrieve DSA parameter g. */
const BIGNUM *DSA_get0_g(const DSA *dsa);
/** Retrieve all DSA parameters at once. */
void DSA_get0_pqg(const DSA *dsa, const BIGNUM **p, const BIGNUM **q,
		  const BIGNUM **g);
/** Set all DSA parameters at once. */
int DSA_set0_pqg(DSA *dsa, BIGNUM *p, BIGNUM *q, BIGNUM *g);
/** Retrieve RSA key parameters. */
void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e,
		  const BIGNUM **d);
/** Retrieve ECDSA_SIG parameter r. */
const BIGNUM *ECDSA_SIG_get0_r(const ECDSA_SIG *sig);
/** Retrieve ECDSA_SIG parameter s. */
const BIGNUM *ECDSA_SIG_get0_s(const ECDSA_SIG *sig);
/** Set ECDSA_SIG parameters. */
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);

/** Increment reference count of a private key. */
int EVP_PKEY_up_ref(EVP_PKEY *key);
/** Return DSA private key without incrementing reference count. */
DSA *EVP_PKEY_get0_DSA(EVP_PKEY *key);
/** Return EC_KEY private key without incrementing reference count. */
EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *key);

/** One-shot signing of single block of data. */
int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen,
		   const unsigned char *tbs, size_t tbslen);
/** One-shot signature verification for single block of data. */
int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
		     size_t siglen, const unsigned char *tbs, size_t tbslen);

/** Finalize digest computation with XOF (eXtendable Output Functions). */
int EVP_DigestFinalXOF(EVP_MD_CTX *ctx, unsigned char *md, size_t size);

/** Fill a contiguous memory with 0s and then free it. */
void OPENSSL_clear_free(void *memory, size_t len);

/** Cleans up digest context ctx and frees up the space allocated to it. */
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
/** Erase the key and any other data from the context and free it. */
void HMAC_CTX_free(HMAC_CTX *ctx);

#endif /* OPENSSL_IS_LEGACY */
#ifdef __cplusplus
}
#endif
#endif /* _NODE_SSL_SHIM_COMPAT_H_ */
