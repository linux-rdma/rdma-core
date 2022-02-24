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
#include <stdint.h>

#include "util.h"

#define COLL_COUNT_IN_TABLE 1
#define NO_COLLISION 0

#define MAX_COLLISIONS 200

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

/*
 * Dynamic Hash that reorganizes itself to fit the load
 */

struct hash *hash_create(unsigned offset, unsigned length)
{
	struct hash *h = calloc(1, sizeof(struct hash));

	h->key_offset = offset;
	h->key_length = length;
	h->table = h->local;
	h->flags = HASH_FLAG_LOCAL;
	h->hash_bits = HASH_INIT_BITS;
	h->coll_bits = HASH_COLL_INIT_BITS;
	h->coll_unit = 4;
	return h;
}

static unsigned hash_calculate(struct hash *h, uint8_t *key)
{
	/* FNV 1a Algorithm yielding a 32 bit hash. See Wikipedia */
	unsigned hash = 2166136261;
	unsigned i;

	for (i = 0; i < h->key_length; i++) {
		hash ^= key[i];
		hash *= 16777619;
	}

	return hash & ((1 << h->hash_bits) - 1);
}

static inline void *hash_to_pointer(unsigned long x)
{
	unsigned long y = x & ~0x07;

	return (void *)y;
}

static int hash_keycomp_ko(struct hash *h, void *key, void *object)
{
	return memcmp(key, object + h->key_offset, h->key_length);
}

static int hash_keycomp_oo(struct hash *h, void *o1, void *o2)
{
	return memcmp(o1 + h->key_offset, o2 + h->key_offset, h->key_length);
}

static void **coll_alloc(struct hash *h, int words)
{
	void **ct = h->table + (1 << h->hash_bits);
	void **ce = ct + (1 << h->coll_bits);
	unsigned match = words > h->coll_unit ? words : h->coll_unit;
	unsigned units = (match + (h->coll_unit - 1)) / h->coll_unit;
	void **p;
	unsigned last = 0;

	if (h->flags & HASH_FLAG_STATISTICS)
		last = h->coll_last;
retry:
	/*
	 * Trivial implementation for now. We should pick up
	 * at the last address for larger collision tables
	 */
	for (p = ct + last; p < ce; p += h->coll_unit) {
		unsigned len = 0;
		void **q;

		for (q = p; q < ce && len < units; q += h->coll_unit, len++)
			if (*q)
				break;

		if (len == units) {
			if (h->flags & HASH_FLAG_STATISTICS)
				h->coll_last = p - ct;
			return p;
		}
	}
	if ((h->flags & HASH_FLAG_STATISTICS) && h->coll_last) {
		/* Search the beginning */
		ce = ct + h->coll_last;
		h->coll_last = 0;
		goto retry;
	}
	/* Out of Collision space */
	return NULL;

}

static void *set_lower(void *p, unsigned lower)
{
	unsigned long x = (unsigned long)p;

	x |= lower;

	return (void *)x;
}

static int get_lower(void *p)
{
	unsigned long x = (unsigned long)p;

	return x & 0x7;
}

static void *clear_lower(void *p)
{
	unsigned long x = (unsigned long)p;

	x &= ~0x7;

	return (void *)x;
}

static unsigned get_u64(void **p)
{
	return (unsigned long)(*p);
}

static void set_u64(void **p, unsigned x)
{
	*p = (void *)((unsigned long)(x));
}

void hash_add(struct hash *h, void *object)
{
	unsigned hash = hash_calculate(h, object + h->key_offset);
	unsigned lower_bits;
	void *x;		/* Existing hash table entry */
	void **cp;		/* Pointer to collision entry */
	void **objtable;	/* Pointer to the list of colliding objects */

	lower_bits = get_lower(object);
	if (lower_bits) {
		printf("Can only handle 8 byte aligned objects\n");
		abort();
	}

	x = h->table[hash];

	if (!x) {
		h->table[hash] = object;
		return;
	}

	lower_bits = get_lower(x);

	if (!lower_bits) {

		/* Hash collision ... check if bad things(tm) are happening ... */
		if (hash_keycomp_oo(h, object, x) == 0) {
			printf("Key exists on hash_add()\n");
			abort();
		}

		/* New collision entry. 2 Pointers allocated in overflow area */
		cp = coll_alloc(h, 2);
		if (!cp)
			goto extend_hash;

		cp[0] = object;
		cp[1] = x;
		h->table[hash] = set_lower(cp, 2);
		return;
	}

	x = clear_lower(x);

	/* This must be a collision entry in the table since the lower bits are set */
	cp = (void **)x;

	if (lower_bits == COLL_COUNT_IN_TABLE)	/* Collision number in the collision table */
	{
		unsigned nr = get_u64(cp);

		objtable = cp + 1;

		if (nr + 1 >= MAX_COLLISIONS) {
			printf("Hash chains reached maximum size of 200 elements.\n");
			abort();
		}

		if (objtable[nr]) {	/* Not fitting. Move it */
			void **ncp;
			unsigned long size = nr * sizeof(void *);

			ncp = coll_alloc(h, nr + 2);
			if (!ncp)
				goto extend_hash;

			memcpy(ncp + 1, objtable, size);
			memset(cp + 1, 0, size);
			cp[0] = NULL;

			cp = ncp;
			objtable = cp + 1;

			if (h->flags & HASH_FLAG_STATISTICS)
				h->coll_reloc++;

			h->table[hash] = set_lower(cp, COLL_COUNT_IN_TABLE);
		}

		objtable[nr] = object;
		set_u64(cp, nr + 1);

		return;
	}

	/* Existing Collision entry that may be extended without much additional action */
	if (lower_bits < 7) {

		objtable = cp;

	       	if (objtable[lower_bits]) {
			void **ncp;
			unsigned size = lower_bits * sizeof(void *);

			/* Need to rellocate the entries */
			ncp = coll_alloc(h, lower_bits + 1);
			if (!ncp)
				goto extend_hash;

			memcpy(ncp, objtable, size);
			memset(objtable, 0, size);
			objtable = ncp;
			if (h->flags & HASH_FLAG_STATISTICS)
				h->coll_reloc++;
		}

		objtable[lower_bits] = object;
		h->table[hash] = set_lower(objtable, lower_bits + 1);

		return;
	}

	/*
	 * Existing collision entry with embedded collisions that must
	 * be converted to a collision entry where the number of
	 * entries is stored in the collision table. So we need to
	 * add two words instead of the usual one.
	 * 
	 * We are moving from using 7 words of pointers to objects
	 * to 8 words of pointers to objects plus 1 word for the number
	 * of collisions.
	 */
	{
		void **ncp;

		ncp = coll_alloc(h, 7 + 2);
		if (!ncp)
			goto extend_hash;

		memcpy(ncp + 1, cp, 7 * sizeof(void *));
		memset(cp, 0, 7 * sizeof(void *));

		ncp[8] = object;
		set_u64(ncp, 8);
		h->table[hash] = set_lower(ncp, COLL_COUNT_IN_TABLE);

		if (h->flags & HASH_FLAG_STATISTICS)
			h->coll_reloc++;

		return;
	}

extend_hash:
	/* Too many collisions. Table reorg needed */
	if (!(h->flags & HASH_FLAG_REORG_RUNNING)) {
		hash_expand(h);
		hash_add(h, object);
	}

	/* This reorg is not going to work out */
	h->flags |= HASH_FLAG_REORG_FAIL;
}

void hash_del(struct hash *h, void *object)
{
	unsigned hash = hash_calculate(h, object + h->key_offset);
	void *x;
	unsigned lower_bits;	/* From the hash table entry */
	void **objtable;	/* Pointer to the start of the table of object pointers */
	void **cp;		/* Pointer from the hash table into the collision area */
	unsigned collisions;
	unsigned i;

	x = h->table[hash];
	lower_bits = get_lower(x);

	if (!lower_bits) {

		if (hash_keycomp_oo(h, object, x))
			goto no_key;

		h->table[hash] = NULL;
		return;
	}

	cp = clear_lower(x);

	if (lower_bits == COLL_COUNT_IN_TABLE) {
		/* Collision count in collision area */
		collisions = get_u64(cp);
		objtable = cp + 1;
	} else {
		/* Collision count from hash entry */
		collisions = lower_bits;
		objtable = cp;
	}

	/* Find the key in the list of collision entries */
	for(i = 0; i < collisions; i++) {
		if (hash_keycomp_oo(h, object, objtable[i]) == 0)
			break;
	}
	
	if (i >= collisions)
		goto no_key;

	collisions--;
	if (collisions == 1) {
		/*
		 * There will only be one entry left.
		 * We need to move things back to the hash entry
		 */
		h->table[hash] = objtable[i^1];	/* Keep the other entry */

		if (lower_bits == 1)
			/* Clear # in the collision table */
			*cp = NULL;
	
		/* Clear pointers to objects */
		memset(objtable, 0, 2 * sizeof(void *));
		return;
	}

	/* Ok we have two or more entries left after removing this one */
	if (i < collisions) {
		/* The ith entry needs to be dropped */
		void **ith = objtable + i;

		/* This could get expensive if we have a large number of collisions */
		memcpy(ith, ith + 1, (collisions - i) *sizeof(void *));
	}

	/* The last entry is no longer needed */
	objtable[collisions] = NULL;

	if (lower_bits == COLL_COUNT_IN_TABLE)
		/* 
		 * If the count goes down to less than 8 we could reinsert
		 * the collision info into the hash table but lets just
		 * skip it. The next reorg will take care of this
		 * or we will do this when the number of pointers
		 * reaches one. See above.
		 */
		set_u64(cp, collisions);
	else
		h->table[hash] = set_lower(cp, collisions);

	return;
	
no_key:
	/* Key not present in chain. Ewwwwh */
	printf("Key does not exist on hash_del()\n");
	abort();
}

void *hash_find(struct hash *h, void *key)
{
	unsigned hash = hash_calculate(h, key);
	void *x;
	unsigned lower_bits;
	void **ct;	/* Pointer to collision entries */
	unsigned ci;		/* Number of collision entries */
	unsigned i;

	x = h->table[hash];

	if (!x)
		goto not_found;

	lower_bits = get_lower(x);

	if (!lower_bits) {
	        if (hash_keycomp_ko(h, key, x) == 0)
			return x;

		goto not_found;
	}

	x = clear_lower(x);
	/* Consult collision table */
	ct = (void **)x;

	if (lower_bits == COLL_COUNT_IN_TABLE) {
		ci = get_u64(ct);
		ct++;
	} else
		ci = lower_bits;

	for(i = 0; i < ci; i++) {
		if (hash_keycomp_ko(h, key, ct[i]) == 0)
			return ct[i];
	}

not_found:
	return NULL;
}

/* Read N objects starting at the mths one */
unsigned int hash_get_objects(struct hash *h, unsigned first, unsigned number, void **objects)
{
	unsigned i,j;
	unsigned items = 0;
	unsigned stored = 0;
	
	for(i = 0; i < (1 << h->hash_bits); i++) {
		void *o = h->table[i];
		unsigned lower_bits = get_lower(o);

		if (o) {
			unsigned nr;
			void **p;

			if (!lower_bits) {

				nr = 1;
				p = (void **)h->table + i;

			} else if (lower_bits != COLL_COUNT_IN_TABLE) {

				/* N entries in colltable. NR in hash */
				nr = lower_bits;
				p = (void **)clear_lower(o);

			} else {
				/* N entries in colltable. NR in colltable */
				p = (void **)clear_lower(o);
				nr = get_u64(p);
				p++;
			}

			for(j = 0; j < nr; j++) {
				if (items >= first) {
					objects[stored++] = *p++;
					items++;
					if (items >= number)
						goto out;
				} else
					items += nr;
			}
		}
	}
out:
	return stored;
}

unsigned int hash_items(struct hash *h)
{
	unsigned i;
	unsigned items = 0;
	
	for(i = 0; i < (1 << h->hash_bits); i++) {
		void *o = h->table[i];
		unsigned lower_bits = get_lower(o);

		if (o) {
			if (!lower_bits)
				/* Single entry in Hashtable */
				items++;
			else if (lower_bits != COLL_COUNT_IN_TABLE)
				/* N entries in colltable. NR in hash */
				items += lower_bits;
			else {
				/* N entries in colltable. NR in colltable */
				void **p = (void **)clear_lower(o);

				items += get_u64(p);
			}
		}
	}
	return items;
}

static unsigned coll_avail(struct hash *h)
{
	void **ct = h->table + (1 << h->hash_bits);
	void **ce = ct + (1 << h->coll_bits);
	void **p;
	unsigned coll_contig = 0;
	unsigned coll_free = 0;

	for (p = ct; p < ce; p += h->coll_unit) {

		if (!*p) {
			void **q = p + 1;
			unsigned length;

			coll_free++;
			length = 1;

			while (q < ce && !*q++ && length < MAX_COLLISIONS)
				length++;

			if (length > coll_contig)
				coll_contig = length;
		}

	}

	if (h->flags & HASH_FLAG_STATISTICS) {
		h->coll_contig = coll_contig;
		h->coll_free = coll_free;
	}

	return coll_free;
}


static unsigned int hash_colls(struct hash *h)
{
	unsigned i;
	unsigned collisions = 0;
	unsigned items = 0;
	unsigned hash_free = 0;
	unsigned coll_max = 0;
	unsigned coll[8] = { 0, };

	for(i = 0; i < (1 << h->hash_bits); i++) {
		void *o = h->table[i];
		int nr;
		unsigned lower_bits = get_lower(o);

		if (!o) {
			hash_free++;
			continue;
		}

		if (!lower_bits) {
			coll[1]++;
			items++;
			continue;
		}

		if (lower_bits != COLL_COUNT_IN_TABLE)
			/* N entries in colltable. NR in hash */
			nr = lower_bits;
		else {
			/* N entries in colltable. NR in colltable */
			void **p = (void **)clear_lower(o);
			nr = get_u64(p);
		}

		collisions += nr;
		items+= nr;

		if (nr > coll_max)
			coll_max = nr;

		if (nr < 8)
			coll[nr]++;
		else
			coll[0]++;	/* Use 0 for extremely large chains */
	}

	/* Analyse overflow area */

	if (h->flags & HASH_FLAG_STATISTICS) {
		h->collisions = collisions;
		h->items = items;
		h->hash_free = hash_free;
		h->coll_max = coll_max;
		memcpy(h->coll, coll, sizeof(coll));
	}
	return collisions;
}

static unsigned int hash_check(struct hash *h)
{
	unsigned i,j;
	int errors = 0;

	for(i = 0; i < (1 << h->hash_bits); i++) {
		void *o = h->table[i];
		int nr;
		void **cp;
		unsigned lower_bits = get_lower(o);

		if (!o)
			continue;

		if (!lower_bits)
			continue;

		cp = clear_lower(o);
		if (lower_bits != COLL_COUNT_IN_TABLE)

			/* N entries in colltable. NR in hash */
			nr = lower_bits;

		else {
			/* N entries in colltable. NR in colltable */
			nr = get_u64(cp);

			if (nr > MAX_COLLISIONS) {
				printf("Entry %d(%d) with # objects corrupted. Value %p. Pointer=%p\n", i, lower_bits, *cp, h->table[i]);
				errors++;
				continue;
			}
			cp++;
		}

		for (j = 0; j < nr; j++)
			if (!cp[j]) {
				printf("Entry %d(%d) object=%d == NULL\n", i, lower_bits, j);
				errors++;
			}
	}
	return errors;
}

static unsigned hash_size(struct hash *h)
{
	unsigned words = (1 << h->hash_bits) + (1 << h->coll_bits);

	return words * sizeof(void *);
}	

static const char *coll_str[9] = {
	"More >8 Cl",
	"No Collis ",
	"Duplicate ",
	"Triplicate",
	"4 Objects ",
	"5 Objects ",
	"6 Objects ",
	"7 Objects ",
	"8 Objects "
};

static void hash_expand(struct hash *h)
{
	struct hash old = *h;
	unsigned oldsize = 1 << h->hash_bits;
	unsigned n;
	unsigned i;
	unsigned long size;

	if (h->flags & HASH_FLAG_REORG_RUNNING)
		return;

	h->flags |= HASH_FLAG_REORG_RUNNING;

	if (h->flags & HASH_FLAG_VERBOSE) {

		printf("Expanding Hash. Bits=%d/%d Size=%d bytes\n", h->hash_bits, h->coll_bits, hash_size(h));
		if (h->flags & HASH_FLAG_STATISTICS) {
			printf("Items= %d/%d Longest CollChain=%d FreeCollEntries==%d Relocations=%d\n",
					h->items, h->collisions, h->coll_max, h->hash_free,  h->coll_reloc);
			for(i=0; i < 9; i++) if (h->coll[i])
				printf("%s  = %d\n", coll_str[i], h->coll[i]);
		}
	}
redo:
	h->flags &= ~HASH_FLAG_REORG_FAIL;

	n = 0;
	if (!(h->flags & HASH_FLAG_STATISTICS)) {
		if (!(h->flags & HASH_FLAG_LOCAL)) {
			/*
			 * First hash_expand will clear FLAG_LOCAL.
			 * Second hash_expand will start giving us statistics
			 * Only then can we begin to make decisions on how to
			 * expand the hash. So the first two expansions will
			 * always double the size of the hash table and leave
			 * the collision table alone.
			 */
			h->flags |= HASH_FLAG_STATISTICS;
		}
		h->hash_bits++;

	} else {
		/* Have statistics. Make some intelligent decisions here */
		if (old.items < oldsize / 2)
			/* Not too dense of a HASH. Increase the collision table size */
			h->coll_bits++;
		else
			h->hash_bits++;

		/* Zap stats */
		memset(h->local, 0, sizeof(h->local));
	}


	if (h->hash_bits > 30) {
		printf("Hash Cannot grow to have a hash bit size of more than 30 bits\n");
		abort();
	}

	size = hash_size(h);
	h->table = calloc(1, size);
	if (!h->table) {
		printf("Hash cannot allocate %lu bytes of memory\n", size);
		abort();
	}	       

	for(i = 0; i < oldsize; i++) {
		void *o = old.table[i];
		unsigned lower_bits = get_lower(o);

		if (o) {
			if (!lower_bits) {
				n++;
				hash_add(h, o);
			} else {
				unsigned nr;
				unsigned j;
				void **ct = (void **)clear_lower(o);

				if (lower_bits == 1) {
					nr = get_u64(ct);
					ct++;
				} else
					nr = lower_bits;

				for (j = 0; j < nr; j++) {
					if (!ct[j]) {
						printf("NULL in collision chain. Hash integrity is broken\n");
						h->flags |= HASH_FLAG_CORRUPTED;
					} else
						hash_add(h, ct[j]);

					if (h->flags & HASH_FLAG_REORG_FAIL)
						goto redo;

				}

				n += nr;
			}
		}
		if (h->flags & HASH_FLAG_STATISTICS) {
			coll_avail(h);
			/*
			 * More than half of the collision area used after a reorg.
			 * If so retry.
			 */
			if (h->coll_free < (1 << (h->coll_bits - 1))/ h->coll_unit) {
			       free(h->table);
			       goto redo;
			}
		}
	}

	if (old.table != h->local)
		free(old.table);
	else {
		h->flags &= ~HASH_FLAG_LOCAL;
	}

	if (h->flags & HASH_FLAG_VERBOSE) {
		coll_avail(h);
		printf("Hash Reorg Complete: Size=%d Bits=%d/%d Items %d/%d. Capacity %d/%d.  OccRate =%d %% Reloc=%d CollAvail=%d LargestContigAvail=%d\n",
			hash_size(h), h->hash_bits, h->coll_bits, hash_items(h), hash_colls(h), 1 << h->hash_bits, 1 << h->coll_bits,
			hash_items(h) * 100 / (1 << h->hash_bits), h->coll_reloc, h->coll_free, h->coll_contig);
	}

	h->flags &= ~HASH_FLAG_REORG_RUNNING;
}

void hash_test(void)
{
	struct hash *h;
	unsigned long i;
	unsigned long seed = time(NULL);
	unsigned int max;
	unsigned int mod = 3;
	void *list[50];
	unsigned n = 0;

	srand(seed);
	max = rand() % 100000;
	printf("Hash Test with %d items\n", max);
	h = hash_create(0, sizeof(unsigned long));

	h->flags |= HASH_FLAG_VERBOSE;

	for(i = 0; i < max; i++) {
		struct entry {
			unsigned long key;
		} *e;

		e = malloc(sizeof(struct entry));
		e->key = i;
		hash_add(h, e);
		n++;

		if ((i % mod) == 0) {
			hash_del(h, e);
			n--;
		}
		if ((i % 100) == 0)
			mod = 1 + (rand() & 0x3);

//		if (hash_check(h))
//			abort();
	}

	printf("%u(%u) Hash items left after awhile. Freeing them\n", hash_items(h), n);

	while ((i = hash_get_objects(h, 0, 50, list))) {
		int j;

		for(j = 0; j < i; j++) {
			hash_del(h, list[j]);
//			if (hash_check(h))
//				abort();
		}

		n -= i;
	}

	if (hash_items(h) == 0 && hash_check(h) == 0)
		printf("Hash testing complete. Everything ok.\n");
	else
		printf("Hash test failed\n");
}

