/*
 * HASH handling for IB2ROCE
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

#include "hash.h"
#include "errno.h"

/*
 * Dynamic Hash that reorganizes itself to fit the load
 */

#define COLL_COUNT_IN_TABLE 1
#define NO_COLLISION 0

#define MAX_COLLISIONS 200

static void hash_expand(struct hash *h);

/*
 * The collision area is terminated with END_MAGIC. This
 * ensures that there are no zeros at the end which could
 * lead to the expansion of the object beyond the end of
 * the collision area.
 *
 * This also means we need to set the END_MAGIC when the
 * size of the collision area changes
 */
#define END_MAGIC (void *)0xDEADBEEFAAAAAAAA

static void set_endmarker(struct hash *h)
{
	/* Set endmarker so that the functions do not write beyond the end of the data */
	h->table[(1 << h->hash_bits) + (1 << h->coll_bits) - 1] = END_MAGIC;
}

static void clear_endmarker(struct hash *h)
{
	/* Clear endmarker so we can expand the collision table */
	h->table[(1 << h->hash_bits) + (1 << h->coll_bits) - 1] = NULL;
}

struct hash *hash_create(unsigned offset, unsigned length)
{
	struct hash *h = calloc(1, sizeof(struct hash));

	h->key_offset = offset;
	h->key_length = length;
	h->table = h->local;
	h->flags = HASH_FLAG_LOCAL;
	h->hash_bits = HASH_INIT_BITS;
	h->coll_bits = HASH_COLL_INIT_BITS;
	h->coll_ubits = 1;	/* Yields about 8 doublett collision entries on the initial config */
	set_endmarker(h);
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
	void **collt = h->table + (1 << h->hash_bits);
	unsigned collt_size = 1 << h->coll_bits;
	unsigned next = h->coll_next;
	unsigned end = collt_size;
	unsigned o,p;

retry:
	for (o = next; o < end; o += (1 << h->coll_ubits)) {

		for (p = 0; p < words; p++)
			if (collt[o + p])
				break;

		if (p >= words) {
			next = o + p;
			goto done;
		}
	}

	if (next) {
		/* Search the beginning */
		end = next;
		next = 0;
		goto retry;
	}

	/* Out of Collision space */
	return NULL;

done:
	h->coll_next = next;
	return collt + o;

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

static unsigned hash_size(struct hash *h)
{
	unsigned words = (1 << h->hash_bits) + (1 << h->coll_bits);

	return words * sizeof(void *);
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

		if (!nr || nr + 1 >= MAX_COLLISIONS) {
			printf("Number of collisions incorrect &%d=%ds.\n", hash, nr);
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

			if (!(h->flags & HASH_FLAG_LOCAL))
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
			if (!(h->flags & HASH_FLAG_LOCAL))
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

		if (!(h->flags & HASH_FLAG_LOCAL))
			h->coll_reloc++;

		return;
	}

extend_hash:
	/* Too many collisions. Table reorg needed */
	if (h->flags & HASH_FLAG_REORG_RUNNING)	{
		/*
		 * This reorg is not going to work out
		 * and we cannot recursively expand
		 * the collision table
		 */
		h->flags |= HASH_FLAG_REORG_FAIL;
		return;
	}

	if (h->flags & HASH_FLAG_LOCAL)
		goto expand;


	unsigned avail = 0;
	unsigned i;
	unsigned hashsize = 1 << h->hash_bits;

	for(i = 0; i < hashsize; i++)
		if (!h->table[i])
			avail++;	
	
	if (avail > hashsize / 2) {
		unsigned old_size = hash_size(h);

		clear_endmarker(h);
		h->coll_bits++;
		/* Ran out of collision table. Just increase it */
		if (mremap(h->table, old_size, hash_size(h), 0) == h->table) {
			set_endmarker(h);
			goto exit;
		}

		/* Restore prior situation and let hash_expand handle it */
		h->coll_bits--;
		set_endmarker(h);
	}

expand:

	hash_expand(h);

exit:
	hash_add(h, object);
	return;
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

static unsigned int hash_check(struct hash *h, bool fast)
{
	unsigned i,j;
	int errors = 0;
	uint8_t *ckc = NULL;
	void **collt = h->table + (1 << h->hash_bits);
	unsigned items = 0;
	unsigned hash_free = 0;
	unsigned coll_free = 0;
	unsigned collisions = 0;
	unsigned coll_max = 0;
	unsigned coll[8] = { 0, };

	unsigned long *p;

	if (!fast)
		ckc = calloc(1, 1 << h->coll_bits);

	for(i = 0; i < (1 << h->hash_bits); i++) {
		void *o = h->table[i];
		int nr;
		unsigned collindex;
		void **cp;
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

		items += nr;
		collisions += nr;
		if (nr > coll_max)
			coll_max = nr;

		if (nr < 8)
			coll[nr]++;
		else
			coll[0]++;	/* Use 0 for extremely large chains */

		if (fast)
			continue;

		collindex = cp - collt;
		for (j = 0; j < nr; j++) {
			unsigned long val  = (unsigned long)cp[j];

			if (val < 0x1000000) {
				printf("Entry %u(%u) object#%u invalid coll cell contents %lx.\n", i, lower_bits, j, val);
				errors++;
			}

			if (val && ckc[collindex + j]++) {
				printf("Entry %u(%u) object#%u points to coll cell (%u) used before (%u times).\n",
					       i, lower_bits, j, collindex + j , ckc[collindex +j]);
				errors++;
			}
		}
	}

	if (fast) {
		for(i = (1 << h->hash_bits); i < (1 << h->hash_bits) + (1 << h->coll_bits) - 1; i++)
			if (!h->table[i])
				coll_free++;

	} else {
		for(i = 0; i < (1 << h->coll_bits) - 1; i++) {
			uint8_t ck = ckc[i];
			void *o = h->table[(1 << h->hash_bits) + i];

			if (!o) {
       				if (ck) {
					printf("Reference to zero Coll Cell %u. References %u\n", i, ck);
					errors++;
				} else
					coll_free++;

			} else {
				if (!ck) {
					printf("Coll Cell %u has contents without a reference to it.\n", i);
					errors++;
				}
			}
		}
		free(ckc);
	}

	if (!(h->flags & HASH_FLAG_LOCAL)) {
		p = h->table[(1 << h->hash_bits) + (1 << h->coll_bits) - 1];
		if (p != END_MAGIC) {
			printf("Endmarker not valid. Value found is %p", p);
			errors++;
		}
	}

	if (!(h->flags & HASH_FLAG_LOCAL)) {
		h->coll_free = coll_free;
		h->collisions = collisions;
		h->items = items;
		h->hash_free = hash_free;
		h->coll_max = coll_max;
		memcpy(h->coll, coll, sizeof(coll));
	}

	if (errors)
		printf("Hash Check Bits=%d/%d Capacity=%u/%u collubits=%u items=%u coll_free=%u errors=%u\n",
			h->hash_bits, h->coll_bits, 1 << h->hash_bits, 1 << h->coll_bits, h->coll_ubits, items, coll_free, errors);
	return errors;
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
	struct hash new = *h;
	unsigned n;
	unsigned i;
	unsigned long size;

	if (h->flags & HASH_FLAG_REORG_RUNNING)
		abort();

	new.flags |= HASH_FLAG_REORG_RUNNING;

	if (new.flags & HASH_FLAG_VERBOSE) {

		printf("Expanding Hash. Bits=%d/%d Size=%d bytes\n", h->hash_bits, h->coll_bits, hash_size(h));
		if (!(h->flags & HASH_FLAG_LOCAL)) {
			printf("Items= %d/%d Longest CollChain=%d FreeCollEntries==%d Relocations=%d\n",
					h->items, h->collisions, h->coll_max, h->hash_free,  h->coll_reloc);
			for(i=0; i < 9; i++) if (h->coll[i])
				printf("%s  = %d\n", coll_str[i], h->coll[i]);
		}
	}
redo:
	new.flags &= ~HASH_FLAG_REORG_FAIL;
	new.flags &= ~HASH_FLAG_LOCAL;

	if (h->flags & HASH_FLAG_LOCAL) {
		/*
		 * First hash_expand will clear FLAG_LOCAL.
		 * Second hash_expand will start giving us statistics
		 * Only then can we begin to make decisions on how to
		 * expand the hash. So the first two expansions will
		 * always double the size of the hash table and leave
		 * the collision table alone.
		 */

		/* Use one 4k pages for this stage of the buildout */
		new.coll_bits = 8;
		new.hash_bits = 8;

	} else
		new.hash_bits++;


	/* Avoid craziness */
	if (new.hash_bits > 30) {
		printf("Hash Cannot grow to have a hash bit size of more than 30 bits\n");
		abort();
	}

	n = 0;
	/* Zap stats */
	memset(new.local, 0, sizeof(new.local));
	size = hash_size(&new);
	new.coll_next = 0;
	new.table =  mmap(0, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
	if (new.table == MAP_FAILED) {
		printf("Hash cannot allocate %lu bytes of memory\n", size);
		abort();
	}	       

	set_endmarker(&new);

	for(i = 0; i < (1 << h->hash_bits); i++) {
		void *o = h->table[i];
		unsigned lower_bits = get_lower(o);

		if (o) {
			if (!lower_bits) {
				n++;
				hash_add(&new, o);
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
						new.flags |= HASH_FLAG_CORRUPTED;
					} else
						hash_add(&new, ct[j]);

					if (new.flags & HASH_FLAG_REORG_FAIL)
						goto redo;

				}

				n += nr;
			}
		}
	}

	new.flags &= ~HASH_FLAG_REORG_RUNNING;

	if (hash_check(&new, false))	/* Update statistics */
		abort();

	if (h->table != h->local)
		munmap(h->table, hash_size(h));

	*h = new;

	if (h->flags & HASH_FLAG_VERBOSE) {

		printf("Hash Reorg Complete: Size=%d Bits=%d/%d Items %d = %d/%d. Capacity %d/%d.  OccRate =%d %% Reloc=%d CollAvail=%u\n",
			hash_size(h), h->hash_bits, h->coll_bits, n, h->items, h->collisions, 1 << h->hash_bits, 1 << h->coll_bits,
			h->items * 100 / (1 << h->hash_bits), h->coll_reloc, h->coll_free);
	}

}

void hash_test(void)
{
	struct hash *h;
	unsigned i;
	unsigned long seed = time(NULL);
//	unsigned long seed = 123;
	unsigned int max;
	unsigned int mod = 3;
	void *list[50];
	unsigned n = 0;

	srand(seed);
	max = rand() % 100000;
	printf("Hash Test with %d items\n", max);
	h = hash_create(0, sizeof(unsigned long));

	h->flags |= HASH_FLAG_VERBOSE;

	if (hash_check(h, false)) {
		printf("Initial check failed\n");
		abort();
	}

	for(i = 0; i < max; i++) {
		struct entry {
			unsigned long key;
		} *e;

		e = malloc(sizeof(struct entry));
		e->key = i;
		hash_add(h, e);
		if (hash_check(h, false)) {
			printf("hash_add %u failed\n", i);
			abort();
		}
		n++;

		if ((i % mod) == 0) {
			hash_del(h, e);
			if (hash_check(h, false)) {
				printf("Hash del %u check failed\n", i);
				abort();
			}
			n--;
		}
		if ((i % 100) == 0)
			mod = 1 + (rand() & 0x3);

	}

	printf("%u(%u) Hash items left after awhile. Freeing them\n", h->items, n);

	while ((i = hash_get_objects(h, 0, 50, list))) {
		int j;

		for(j = 0; j < i; j++) {
			hash_del(h, list[j]);
			if (hash_check(h, false)) {
				printf("Fail while deleting all objects\n");
				abort();
			}
		}

		n -= i;
	}

	if (hash_check(h, false) == 0 && h->items == 0 && n == 0)
		printf("Hash testing complete. Everything ok.\n");
	else
		printf("Hash test failed n=%u items=%u\n", n, h->items);
}

