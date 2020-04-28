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

/* Legacy OpenSSL does not use std atomics. */
#include <openssl/crypto.h>

#include "x509.h"

#if OPENSSL_IS_LEGACY

/** Atomically increase reference count for X509. */
int X509_up_ref(X509 *x)
{
	if (x == NULL) {
		return 0;
	}

	int prev = CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
	return (prev > 1) ? 1 : 0;
}
/** Atomically increase reference count for X509_STORE. */
int X509_STORE_up_ref(X509_STORE *xs)
{
	if (xs == NULL) {
		return 0;
	}

	int prev = CRYPTO_add(&xs->references, 1, CRYPTO_LOCK_X509_STORE);
	return (prev > 1) ? 1 : 0;
}

/** Retrieve X509 objects from store. */
STACK_OF(X509_OBJECT) * X509_STORE_get0_objects(const X509_STORE *xs)
{
	if (xs == NULL) {
		return NULL;
	}

	return xs->objs;
}

/** Determine type of X509 object.
 *
 * @return Type of the object, or X509_LU_FAIL when object is NULL.
 */
int X509_OBJECT_get_type(const X509_OBJECT *object)
{
	if (object == NULL) {
		return X509_LU_FAIL;
	}

	return object->type;
}
/** Extract X509 data structure from generic X509 object.
 *
 * @return Pointer to the X509 structure;
 * NULL if object is NULL or of different type than X509_LU_X509.
 */
X509 *X509_OBJECT_get0_X509(const X509_OBJECT *object)
{
	if (object == NULL || object->type != X509_LU_X509) {
		return NULL;
	}

	return object->data.x509;
}

#endif /* OPENSSL_IS_LEGACY */
