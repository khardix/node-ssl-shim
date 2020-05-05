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

/** @file TLS compatibility layer for legacy OpenSSL. */

#ifndef _NODE_SSL_SHIM_TLS_H_
#define _NODE_SSL_SHIM_TLS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "features.h"
#if OPENSSL_IS_LEGACY

#include <openssl/ssl.h>

/** Keylog callback signature */
typedef void SSL_CTX_keylog_cb_func(const SSL *ssl, const char *line);

/** Version-flexible TLS method. */
const SSL_METHOD *TLS_method();
/** Version-flexible TLS server method. */
const SSL_METHOD *TLS_server_method();
/** Version-flexible TLS client method. */
const SSL_METHOD *TLS_client_method();

/** Obtain pointer to session ticket and it's length. */
void SSL_SESSION_get0_ticket(const SSL_SESSION *s, const unsigned char **tick,
			     size_t *len);

/** Determine status of TLS extension. */
long SSL_get_tlsext_status_type(SSL *s);

/** Set diagnostic key logging callback.
 * UNSUPPORTED – Provided as no-op.
 */
void SSL_CTX_set_keylog_callback(SSL_CTX *ctx, SSL_CTX_keylog_cb_func callback);
/** Get diagnostic key logging callback.
 * UNSUPPORTED – No-op, always returns NULL.
 */
SSL_CTX_keylog_cb_func *SSL_CTX_get_keylog_callback(const SSL_CTX *ctx);

#endif /* OPENSSL_IS_LEGACY */
#ifdef __cplusplus
}
#endif
#endif /* _NODE_SSL_SHIM_TLS_H_ */
