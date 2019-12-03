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

/** @file Eliptic Curve compatibility layer for legacy OpenSSL. */

#ifndef _NODE_SSL_SHIM_EC_H_
#define _NODE_SSL_SHIM_EC_H_

#include "features.h"
#if OPENSSL_IS_LEGACY

#include <openssl/ec.h>

/* EC constants – taken from upstream */
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

/** Measure the number of bits of the group's order. */
int EC_GROUP_order_bits(const EC_GROUP *group);

#endif /* OPENSSL_IS_LEGACY */

#endif /* _NODE_SSL_SHIM_EC_H_ */
