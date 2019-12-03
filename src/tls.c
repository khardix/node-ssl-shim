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

/** @file Implementation of TLS compatibility layer for legacy OpenSSL. */

#include "tls.h"
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

/** Obtain pointer to session ticket and it's length. */
void SSL_SESSION_get0_ticket(const SSL_SESSION *s, const unsigned char **tick,
			     size_t *len)
{
	if (s == NULL) {
		return;
	}

	if (tick != NULL) {
		*tick = s->tlsext_tick;
	}
	if (len != NULL) {
		*len = s->tlsext_ticklen;
	}
}

/** Determine status of TLS extension.
 *
 * @return The TLSext status, or -1 in case of error.
 */
long SSL_get_tlsext_status_type(SSL *s)
{
	if (s == NULL) {
		return -1l;
	} else {
		return s->tlsext_status_type;
	}
}

#endif /* OPENSSL_IS_LEGACY */
