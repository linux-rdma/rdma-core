/*
 * FIFO and HASH handling for IB2ROCE
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
#include <string.h>
#include <time.h>

#include "util.h"

static void hash_expand(struct hash *h);

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
		if (i % 100)
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

struct hash *hash_create(unsigned offset, unsigned length)
{
	struct hash *h = calloc(1, sizeof(struct hash));

	h->key_offset = offset;
	h->key_length = length;

	h->hash_bits = HASH_INIT_BITS;
	h->table = h->local_table;

	return h;
}

static unsigned hash_calculate(struct hash *h, void *key)
{
	unsigned hash = 0;;
	unsigned i;

	if (h->hash_bits <= 8) {
		char *k = key;
	
		for(i = 0; i < h->key_length; i++)
			hash += k[i];
	} else if (h->hash_bits <= 16) {
		unsigned short *k = key;

		for(i = 0; i < h->key_length / sizeof(unsigned short); i++)
			hash += k[i] << i;
	} else {
		unsigned int *k = key;

		for(i = 0; i < h->key_length / sizeof(unsigned int); i++)
			hash += k[i] << i;
	} 

	return hash & ((1 << h->hash_bits) - 1);
}

static inline void *hash_to_pointer(unsigned long x)
{
	void *p;

	p =(void *)(x & ~HASH_COLL_BITS);

	return p;
}

static int hash_keycomp_ko(struct hash *h, void *key, void *object)
{
	return memcmp(key, object + h->key_offset, h->key_length);
}

static int hash_keycomp_oo(struct hash *h, void *o1, void *o2)
{
	return memcmp(o1 + h->key_offset, o2 + h->key_offset, h->key_length);
}

void hash_add(struct hash *h, void *object)
{
	unsigned hash = hash_calculate(h, object + h->key_offset);
	unsigned long o = (unsigned long)object;
	unsigned long x;
	unsigned i;

	if (o & HASH_COLL_BITS) {
		printf("Can only handle 8 byte aligned objects\n");
		abort();
	}

	x = h->table[hash];

	if (!x) {
		h->table[hash] = o;
		return;
	}

	/* Hash collision */
	if (hash_keycomp_oo(h, object, hash_to_pointer(x)) == 0) {
		printf("Key exists on hash_add()\n");
		abort();
	}

	/* Find the next free entry in the collision table */
	for (i = 1; i <= HASH_COLL_BITS; i++)
		if (h->coll[i] == 0)
			break;

	if (i <= HASH_COLL_BITS) {
		h->table[hash] = o | i;	/* Store object pointing to collision entry at i */
		h->coll[i] = x;		/* Store old entry in collision table */
		return;
	}

	/* Too many collisions. Table reorg needed */
	hash_expand(h);
	hash_add(h, object);
}

void hash_del(struct hash *h, void *object)
{
	unsigned hash = hash_calculate(h, object + h->key_offset);
	unsigned long x;
	unsigned coll;

	x = h->table[hash];

	coll = x & HASH_COLL_BITS;
	if (!coll) {
		/*
		 * This is the only entry and therefore we skip the compare and just
		 * wipe the entry without comparing the key
		 */
		if (hash_keycomp_oo(h, object, hash_to_pointer(x)))
			goto no_key;

		h->table[hash] = 0;
		return;
	}

	/* There are overflow entries.... Figure out which one to erase */
	if (hash_keycomp_oo(h, object, hash_to_pointer(x)) == 0)
	{
		/*
		 * Key in hash matches. Copy entry from collision table and
		 * free it
		*/
		h->table[hash] = h->coll[coll];
		h->coll[coll] = 0;
		return;
	}

	/*
	 * Not in the table, so check in the collision chains
	 */
	while (coll) {
		unsigned coll_new;
	
		x = h->coll[coll];
		coll_new = x & HASH_COLL_BITS;

		if (hash_keycomp_oo(h, object, hash_to_pointer(x)) == 0)
		{
			h->coll[coll] = h->coll[coll_new];
			h->coll[coll_new] = 0;
			return;
		}
		coll = coll_new;
	}

no_key:
	/* Key not present in chain. Ewwwwh */
	printf("Key does not exist on hash_del()\n");
	abort();
}

void *hash_find(struct hash *h, void *key)
{
	unsigned hash = hash_calculate(h, key);
	unsigned long x;
	unsigned coll;

	x = h->table[hash];

	if (!x)
		goto not_found;

	if (hash_keycomp_ko(h, key, hash_to_pointer(x)) == 0)
		return hash_to_pointer(x);

	coll = x & HASH_COLL_BITS;
	while (coll) {
		x = h->coll[coll];
		coll = x & HASH_COLL_BITS;
		if (hash_keycomp_ko(h, key, hash_to_pointer(x)) == 0)
			return hash_to_pointer(x);
	}

not_found:
	return NULL;
}

static int hash_colls(struct hash *h)
{
	unsigned i, colls;

	colls = 0;
	for (i = 1; i <= HASH_COLL_BITS; i++)
		if (h->coll[i])
			colls++;

	return colls;
}

/* Read N objects starting at the mths one */
int hash_get_objects(struct hash *h, unsigned first, unsigned number, void **objects)
{
	unsigned i;
	unsigned items = 0;
	unsigned stored = 0;
	
	for(i = 1; i <= HASH_COLL_BITS; i++) {
		unsigned long o = h->coll[i];

		if (o) {
			items++;
			if (items > first) {
				objects[stored++] = hash_to_pointer(o);
				if (stored == number)
					return stored;
			}
		}
	}

	for(i = 0; i < (1 << h->hash_bits); i++) {
		unsigned long o = h->table[i];

		if (o) {
	       		items++;
			if (items > first) {
				objects[stored++] = hash_to_pointer(o);
				if (stored == number)
					return stored;
			}
		}

	}
	return stored;
}

unsigned long hash_items(struct hash *h)
{
	unsigned i;
	unsigned items = 0;
	
	for(i = 0; i <= HASH_COLL_BITS; i++) {
		unsigned long o = h->coll[i];

		if (o)
			items++;
	}

	for(i = 0; i < (1 << h->hash_bits); i++) {
		unsigned long o = h->table[i];

		if (o)
	       		items++;
	}
	return items;
}

static void hash_expand(struct hash *h)
{
	struct hash old = *h;
	unsigned oldsize = 1 << h->hash_bits;
	unsigned n;
	unsigned i;

redo:
	n = 0;
	h->hash_bits++;
	if (h->hash_bits > 30)
		abort();

	memset(h->coll, 0, sizeof(h->coll));
	h->table = calloc(1, sizeof(unsigned long) * (1 << h->hash_bits));

	/* Add old collision entries */
	for(i = 1; i < 8; i++) {
		unsigned long o = old.coll[i];

		if (o) {
			hash_add(h, hash_to_pointer(o));
			n++;
		}
	}

	for(i = 0; i < oldsize; i++) {
		unsigned long o = old.table[i];

		if (o) {
			int c;

			hash_add(h, hash_to_pointer(o));
			n++;
			c = hash_colls(h);
			
			if (c > (HASH_COLL_BITS + 1) / 2) {
				free(h->table);
				goto redo;
			}
		}
	}
	if (old.table != h->local_table)
		free(old.table);
}

void hash_test(void)
{
	struct hash *h;
	unsigned long i;
	unsigned long seed = time(NULL);
	unsigned int max;
	unsigned int mod = 3;
	void *list[50];

	srand(seed);
	max = rand() % 1000000;
	printf("Hash Test with %d items\n", max);
	h = hash_create(0, sizeof(unsigned long));

	for(i = 0; i < max; i++) {
		struct entry {
			unsigned long key;
		} *e;

		e = malloc(sizeof(struct entry));
		e->key = i;
		hash_add(h, e);

		if ((i % mod) == 0) {
			hash_del(h, e);
		}
		if ((i % 100) == 0)
			mod = 1 + (rand() & 0x3);

	}

	printf("%ld Hash items left after awhile. Freeing them\n", hash_items(h));

	while ((i = hash_get_objects(h, 0, 50, list))) {
		int j;

		for(j = 0; j < i; j++)
			hash_del(h, list[j]);
	}

	printf("%ld items left. Hash ok\n", hash_items(h));
}

