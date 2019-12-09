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

/** @file Backports of BIO-related functions. */
#include "bio.h"

#if OPENSSL_IS_LEGACY

#include <openssl/bio.h>
#include <openssl/err.h>

#include "constants.h"
#include "compat.h"

/** Associate a custom data with a BIO. */
void BIO_set_data(BIO *a, void *ptr)
{
	if (a == NULL) {
		return;
	}

	a->ptr = ptr;
}
/** Retrieve the custom data associated with a BIO. */
void *BIO_get_data(BIO *a)
{
	if (a == NULL) {
		return NULL;
	}

	return a->ptr;
}

/** Indicate initialization status by setting the `init` flag. */
void BIO_set_init(BIO *a, int init)
{
	if (a == NULL) {
		return;
	}

	a->init = init;
}
/** Retrieve current initialization status. */
int BIO_get_init(BIO *a)
{
	if (a == NULL) {
		return 0; /* Initialization not complete. */
	}

	return a->init;
}

/** Indicate shutdown status by setting the `shutdown` flag. */
void BIO_set_shutdown(BIO *a, int shut)
{
	if (a == NULL) {
		return;
	}

	a->shutdown = shut;
}
/** Retrieve current shutdown status. */
int BIO_get_shutdown(BIO *a)
{
	if (a == NULL) {
		return 0;
	}

	return a->shutdown;
}

/** Allocate new BIO_METHOD. */
BIO_METHOD *BIO_meth_new(int type, const char *name)
{
	BIO_METHOD *method = OPENSSL_zalloc(sizeof(BIO_METHOD));
	if (method == NULL) {
		goto fail;
	}

	method->name = OPENSSL_strdup(name);
	if (method->name == NULL) {
		goto fail;
	}

	method->type = type;

	return method;

fail:
	OPENSSL_free(method);
	BIOerr(BIO_F_BIO_METH_NEW, ERR_R_MALLOC_FAILURE);
	return NULL;
}

/** Get callback implementing the BIO_write operation. */
int (*BIO_meth_get_write(const BIO_METHOD *biom))(BIO *, const char *, int)
{
	if (biom == NULL) {
		return NULL;
	}

	return biom->bwrite;
}
/** Set callback implementing the BIO_write operation. */
int BIO_meth_set_write(BIO_METHOD *biom, int (*write)(BIO *, const char *, int))
{
	if (biom == NULL) {
		return 0;
	}

	biom->bwrite = write;
	return 1;
}

/** Get callback implementing the BIO_read operation. */
int (*BIO_meth_get_read(const BIO_METHOD *biom))(BIO *, char *, int)
{
	if (biom == NULL) {
		return NULL;
	}

	return biom->bread;
}
/** Set callback implementing the BIO_read operation. */
int BIO_meth_set_read(BIO_METHOD *biom, int (*read)(BIO *, char *, int))
{
	if (biom == NULL) {
		return 0;
	}

	biom->bread = read;
	return 1;
}

/** Get callback implementing the BIO_puts operation. */
int (*BIO_meth_get_puts(const BIO_METHOD *biom))(BIO *, const char *)
{
	if (biom == NULL) {
		return NULL;
	}

	return biom->bputs;
}
/** Set callback implementing the BIO_puts operation. */
int BIO_meth_set_puts(BIO_METHOD *biom, int (*puts)(BIO *, const char *))
{
	if (biom == NULL) {
		return 0;
	}

	biom->bputs = puts;
	return 1;
}

/** Get callback implementing the BIO_gets operation. */
int (*BIO_meth_get_gets(const BIO_METHOD *biom))(BIO *, char *, int)
{
	if (biom == NULL) {
		return NULL;
	}

	return biom->bgets;
}
/** Set callback implementing the BIO_gets operation. */
int BIO_meth_set_gets(BIO_METHOD *biom, int (*gets)(BIO *, char *, int))
{
	if (biom == NULL) {
		return 0;
	}

	biom->bgets = gets;
	return 1;
}

/** Get callback implementing the BIO_ctrl operation. */
long (*BIO_meth_get_ctrl(const BIO_METHOD *biom))(BIO *, int, long, void *)
{
	if (biom == NULL) {
		return NULL;
	}

	return biom->ctrl;
}
/** Set callback implementing the BIO_ctrl operation. */
int BIO_meth_set_ctrl(BIO_METHOD *biom, long (*ctrl)(BIO *, int, long, void *))
{
	if (biom == NULL) {
		return 0;
	}

	biom->ctrl = ctrl;
	return 1;
}

/** Get callback implementing the BIO_new operation. */
int (*BIO_meth_get_create(const BIO_METHOD *bion))(BIO *)
{
	if (bion == NULL) {
		return NULL;
	}

	return bion->create;
}
/** Set callback implementing the BIO_new operation. */
int BIO_meth_set_create(BIO_METHOD *biom, int (*create)(BIO *))
{
	if (biom == NULL) {
		return 0;
	}

	biom->create = create;
	return 1;
}

/** Get callback implementing the BIO_free operation. */
int (*BIO_meth_get_destroy(const BIO_METHOD *biom))(BIO *)
{
	if (biom == NULL) {
		return NULL;
	}

	return biom->destroy;
}
/** Set callback implementing the BIO_free operation. */
int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy)(BIO *))
{
	if (biom == NULL) {
		return 0;
	}

	biom->destroy = destroy;
	return 1;
}

#endif /* OPENSSL_IS_LEGACY */
