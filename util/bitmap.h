/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */

#ifndef UTIL_BITMAP_H
#define UTIL_BITMAP_H

#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#include "util.h"

#define BMP_DECLARE(name, nbits) \
	unsigned long (name)[BITS_TO_LONGS((nbits))]

unsigned long bitmap_find_first_bit(const unsigned long *bmp,
				    unsigned long start, unsigned long end);

void bitmap_zero_region(unsigned long *bmp, unsigned long start,
			unsigned long end);

void bitmap_fill_region(unsigned long *bmp, unsigned long start,
			unsigned long end);

unsigned long bitmap_find_free_region(unsigned long *bmp,
				      unsigned long nbits,
				      unsigned long region_size);

static inline void bitmap_fill(unsigned long *bmp, unsigned long nbits)
{
	unsigned long size = BITS_TO_LONGS(nbits) * sizeof(unsigned long);

	memset(bmp, 0xff, size);
}

static inline void bitmap_zero(unsigned long *bmp, unsigned long nbits)
{
	unsigned long size = BITS_TO_LONGS(nbits) * sizeof(unsigned long);

	memset(bmp, 0, size);
}

static inline bool bitmap_empty(const unsigned long *bmp, unsigned long nbits)
{
	unsigned long i;
	unsigned long mask = ULONG_MAX;

	assert(nbits);

	for (i = 0; i < BITS_TO_LONGS(nbits) - 1; i++) {
		if (bmp[i] != 0)
			return false;
	}

	if (nbits % BITS_PER_LONG)
		mask = (1UL << (nbits % BITS_PER_LONG)) - 1;

	return (bmp[i] & mask) ? false : true;
}

static inline bool bitmap_full(const unsigned long *bmp, unsigned long nbits)
{
	unsigned long i;
	unsigned long mask = ULONG_MAX;

	assert(nbits);

	for (i = 0; i < BITS_TO_LONGS(nbits) - 1; i++) {
		if (bmp[i] != -1UL)
			return false;
	}

	if (nbits % BITS_PER_LONG)
		mask = (1UL << (nbits % BITS_PER_LONG)) - 1;

	return ((bmp[i] & mask) ^ (mask)) ? false : true;
}

static inline void bitmap_set_bit(unsigned long *bmp, unsigned long idx)
{
	bmp[(idx / BITS_PER_LONG)] |= (1UL << (idx % BITS_PER_LONG));
}

static inline void bitmap_clear_bit(unsigned long *bmp, unsigned long idx)
{
	bmp[(idx / BITS_PER_LONG)] &= ~(1UL << (idx % BITS_PER_LONG));
}

static inline bool bitmap_test_bit(const unsigned long *bmp, unsigned long idx)
{
	return !!(bmp[(idx / BITS_PER_LONG)] &
		 (1UL << (idx % BITS_PER_LONG)));
}

static inline unsigned long *bitmap_alloc0(unsigned long size)
{
	unsigned long *bmp;

	bmp = calloc(BITS_TO_LONGS(size), sizeof(long));
	if (!bmp)
		return NULL;

	return bmp;
}

static inline unsigned long *bitmap_alloc1(unsigned long size)
{
	unsigned long *bmp;

	bmp = bitmap_alloc0(size);
	if (!bmp)
		return NULL;

	bitmap_fill(bmp, size);

	return bmp;
}

#endif
