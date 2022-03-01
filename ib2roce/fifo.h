#ifndef IB2ROCE_FIFO
#define IB2ROCE_FIFO

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

#endif

