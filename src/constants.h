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

#endif /* OPENSSL_IS_LEGACY */

#endif /* _NODE_SSL_SHIM_CONSTANTS_H_ */
