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

#include <openssl/bn.h>

#include "ec.h"

#if OPENSSL_IS_LEGACY

/** Measure the number of bits of the group's order.
 *
 * If the number of bits cannot be measured for any reason, 0 is returned.
 */
int EC_GROUP_order_bits(const EC_GROUP *group)
{
	int result = 0;

	if (group == NULL) {
		return result;
	}

	BIGNUM *order = BN_new();
	BN_CTX *context = BN_CTX_new();
	if (order == NULL || context == NULL) {
		goto cleanup;
	}

	int ec = EC_GROUP_get_order(group, order, context);
	if (ec != 1) {
		goto cleanup;
	}

	result = BN_num_bits(order);

cleanup:
	BN_CTX_free(context);
	BN_free(order);

	return result;
}

#endif /* OPENSSL_IS_LEGACY */
