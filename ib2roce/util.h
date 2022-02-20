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
 * The lower 3 bits indicate which of the 7 collision avoidance
 * areas are to be used.
 *
 * The unsigned longs in the collisions avoidance area can also
 * have indications in the lower 3 bits indicating more collision
 * handling to be done
 */
#define HASH_COLL_BITS 0x7ULL
#define HASH_INIT_BITS 4

struct hash {
	unsigned short key_offset;
	unsigned short key_length;
	unsigned short hash_bits;
	unsigned short flags;
	unsigned long *table;
	unsigned long coll[HASH_COLL_BITS + 1];
	unsigned long local_table[1 << HASH_INIT_BITS];
};

struct hash *hash_create(unsigned offset, unsigned length);
void hash_add(struct hash *h, void *object);
void hash_del(struct hash *h, void *object);
void *hash_find(struct hash *h, void *key);

/* Read N objects starting at the mths one */
int hash_get_objects(struct hash *h, unsigned first, unsigned number, void **objects);
unsigned long hash_items(struct hash *h);
void hash_test(void);

#endif

