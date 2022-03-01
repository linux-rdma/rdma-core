#ifndef IB2ROCE_HASH
#define IB2ROCE_HASH

/*
 * unsigned long values in the tables are representing the address
 * of the object in the hash. The 3 lower bits are usually not used
 * since objects are aligned to 8 byte boundaries.
 *
 * The lower 3 bits are used to indicate collisions. Lookups
 * can then store the colliding points in overflow areas.
 *
 * 000 Pointer to the hashed object
 * 001 Number of collision entries at this address followed by the pointers
 * 010 2 Collision entries at the address pointed to.
 * 011 3
 * ...
 * 111 7 Collision entries at the indicated address
 *
 */
#define HASH_COLL_INIT_BITS 4
#define HASH_INIT_BITS 4

#define HASH_FLAG_LOCAL (1 << 1)		/* Local array is being used. No Malloc */
#define HASH_FLAG_REORG_RUNNING (1 << 2)	/* A Reorg of the hash is in progress */
#define HASH_FLAG_REORG_FAIL (1 << 3 )		/* Abort the unsuccessful reorg */
#define HASH_FLAG_CORRUPTED (1 << 4)		/* Unrecoverable Metadata consistency issue */
#define HASH_FLAG_VERBOSE (1 << 5)		/* Show statistics during reorg */

struct hash {
	unsigned short key_offset;
	unsigned short key_length;
	unsigned char hash_bits;		/* Bits of the 32 bit hash to use */
	unsigned char coll_bits;		/* 1 << N size of collision area */
	unsigned char coll_ubits;		/* 2^ubits allocations size in words */
	unsigned char flags;			/* Flags */
	unsigned coll_next;			/* Next free unit in coll area */
	void **table;				/* Colltable follows hash table */
	union {
		void *local[(1 << HASH_INIT_BITS) + (1 << HASH_COLL_INIT_BITS)];
		struct {
			unsigned collisions;
			unsigned hash_free;	/* Unused entries */
			unsigned items;		/* How many items in the table */
			unsigned coll_free;	/* How many unit blocks are still available */
			unsigned coll_max;	/* Maximum Collisions per hash entry */
			unsigned coll_reloc;	/* Relocation of free list */
			unsigned coll[8];	/* Statistics for collision sizes. 0 = larger collisions */
		};
	};
};

struct hash *hash_create(unsigned offset, unsigned length);
void hash_add(struct hash *h, void *object);
void hash_del(struct hash *h, void *object);
void *hash_find(struct hash *h, void *key);

/* Read N objects starting at the mths one */
unsigned int hash_get_objects(struct hash *h, unsigned first, unsigned number, void **objects);
unsigned int hash_items(struct hash *h);
void hash_test(void);

#endif

