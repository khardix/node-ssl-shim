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

/** @file Implementation of X509 compatibility layer for legacy OpenSSL. */

#include <stdatomic.h>

#include "x509.h"

#if OPENSSL_IS_LEGACY

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

#endif /* OPENSSL_IS_LEGACY */
