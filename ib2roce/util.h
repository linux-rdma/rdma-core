#ifndef IB2ROCE_UTILS
#define IB2ROCE_UTILS

/*
 * FIFO list management
 */

struct fifo {
	unsigned first;	/* Pointer to first item with data */
	unsigned free;	/* Pointer to first item that is unused */
	unsigned size;	/* Number of items in the fifo */
	void **list;	/* Pointers to the items in the fifo */
	void *init_list[12];	/*
				 * Initial list to get to 2 cache lines
       				 * and avoid malloc
				 */
};

static inline bool fifo_empty(struct fifo *f)
{
	return f->free == f->first;
}

/* Return true if it is the first item */
bool fifo_put(struct fifo *f, void *new);
void *fifo_get(struct fifo *f);
void fifo_init(struct fifo *f);
void *fifo_first(struct fifo *f);
int fifo_items(struct fifo *f);

void fifo_test(void);

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

#define HASH_FLAG_STATISTICS (1 << 0)		/* Statistics are enable */
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
	unsigned char coll_unit;		/* Size in words of a single allocation */
	unsigned char flags;			/* Flags */
	void **table;				/* Colltable follows hash table */
	union {
		void *local[(1 << HASH_INIT_BITS) + (1 << HASH_COLL_INIT_BITS)];
		struct {
			unsigned coll_last;	/* Last point of allocation */
			unsigned collisions;
			unsigned hash_free;	/* Unused entries */
			unsigned items;		/* How many items in the table */
			unsigned coll_free;	/* How many unit blocks are still available */
			unsigned coll_max;	/* Maximum Collisions per hash entry */
			unsigned coll_contig;	/* Maximum Contiguous area in Collision table */
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

