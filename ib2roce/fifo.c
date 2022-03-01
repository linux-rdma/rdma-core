/*
 * FIFO handling for IB2ROCE
 *
 * (C) 2022 Christoph Lameter <cl@linux.com>
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Author: Christoph Lameter [cl@linux.com]$
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <errno.h>

#include "fifo.h"
#include "errno.h"

/* Return true if it is the first item */
bool fifo_put(struct fifo *f, void *new)
{
	bool first = fifo_empty(f);

	f->list[f->free++] = new;

	if (f->free == f->size)	/* Wraparound */
		f->free = 0;

	if (f->free == f->first) {
		/* FIFO is full. Allocate more space */
		unsigned old_first = f->first;
		unsigned pointers_to_move = f->size - old_first;

		/* Update to open a hole of f->size pointers in the middle */
		f->first += f->size;
		f->size += f->size;

		if (f->list == f->init_list) {

			f->list = malloc(f->size * sizeof(void *));
			memcpy(f->list, f->init_list, sizeof(f->init_list));

		} else
			f->list = realloc(f->list, f->size * sizeof(void *));

		/* Move upper part of the list into the right position */
		memcpy(f->list + f->first,
			f->list + old_first,
			pointers_to_move * sizeof(void *));
	}

	return first;
}

void *fifo_get(struct fifo *f)
{
	void *r;

	if (fifo_empty(f))
		/* FIFO empty */
		return NULL;

	r = f->list[f->first++];

	/* Wrap around if we were at the last pointer in the list */
	if (f->first == f->size)
		f->first = 0;

	return r;
}

void fifo_init(struct fifo *f)
{
	memset(f, 0, sizeof(struct fifo));
	f->size = 12;
	f->list = f->init_list;
}

void *fifo_first(struct fifo *f)
{
	if (fifo_empty(f))
		return NULL;

	return f->list[f->first];
}

int fifo_items(struct fifo *f)
{
	if (f->free >= f->first)
		return f->free - f->first;

	return f->free + f->size - f->first;
}

void fifo_test(void)
{
	struct fifo f;
	unsigned long out = 0;
	unsigned long i;
	unsigned long seed = time(NULL);
	unsigned int max = rand() % 10000000;
	unsigned int mod = 3;

	srand(seed);
	max = rand() % 10000000;
	printf("FIFO Test with %d items\n", max);
	fifo_init(&f);

	if (!fifo_empty(&f))
		abort();

	for(i = 0; i < max; i++) {
		fifo_put(&f, (void *)i);

		if ((i % mod) == 0) {
			if (out != (unsigned long) fifo_get(&f))
				abort();
			else
				out++;
		}
		if ((i % 100) == 0)
			mod = 1 + (rand() & 0x3);
	}
	if (fifo_empty(&f))
		abort();

	printf("%d FIFO items left after awhile. Freeing them\n", fifo_items(&f));

	while (out < max) {
		if (out != (unsigned long) fifo_get(&f))
			abort();
		else
			out++;
	}

	if (!fifo_empty(&f))
		abort();

	if (fifo_get(&f))
		abort();

	printf("FIFO ok\n");
}

