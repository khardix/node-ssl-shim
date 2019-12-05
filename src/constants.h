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

/** @file Constant values backported from newer OpenSSL. */
#ifndef _NODE_SSL_SHIM_CONSTANTS_H_
#define _NODE_SSL_SHIM_CONSTANTS_H_

#include "features.h"

#if OPENSSL_IS_LEGACY

/* Error codes */
#define ERR_LIB_OSSL_STORE 44
#define ERR_LIB_CT 50
#define ERR_LIB_ASYNC 51
#define ERR_LIB_KDF 52
#define ERR_LIB_SM2 53

/* Protocol versions */
#define TLS1_3_VERSION 0x0304

/* Cipher identifiers */
#define NID_rsassaPss 912
#define NID_chacha20_poly1305 1018
#define NID_X25519 1034
#define NID_X448 1035
#define NID_ED25519 1087
#define NID_ED448 1088

#define EVP_PKEY_RSA_PSS NID_rsassaPss
#define EVP_PKEY_X25519 NID_X25519
#define EVP_PKEY_X448 NID_X448
#define EVP_PKEY_ED25519 NID_ED25519
#define EVP_PKEY_ED448 NID_ED448

/* Renamed control codes */
#define EVP_CTRL_AEAD_GET_TAG EVP_CTRL_GCM_GET_TAG
#define EVP_CTRL_AEAD_SET_IVLEN EVP_CTRL_GCM_SET_IVLEN
#define EVP_CTRL_AEAD_SET_TAG EVP_CTRL_GCM_SET_TAG

/* Unimplemented features */
#define EVP_MD_FLAG_XOF 0x0002
#define EVP_F_EVP_DIGESTFINALXOF 174
#define EVP_R_NOT_XOF_OR_INVALID_LENGTH 178

#endif /* OPENSSL_IS_LEGACY */

#endif /* _NODE_SSL_SHIM_CONSTANTS_H_ */
