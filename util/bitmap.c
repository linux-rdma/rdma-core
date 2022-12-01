/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */

#define _GNU_SOURCE
#include "bitmap.h"
#include <string.h>
#include <strings.h>
#include <ccan/minmax.h>

#define BMP_WORD_INDEX(n) ((n) / BITS_PER_LONG)
#define BMP_WORD_OFFSET(n) ((n) % BITS_PER_LONG)
#define BMP_FIRST_WORD_MASK(start) (~0UL << BMP_WORD_OFFSET(start))
#define BMP_LAST_WORD_MASK(end) (BMP_WORD_OFFSET(end) == 0 ? ~0UL : \
				 ~BMP_FIRST_WORD_MASK(end))

/*
 * Finds the first set bit in the bitmap starting from
 * 'start' bit until ('end'-1) bit.
 *
 * Returns the set bit index if found, otherwise returns 'end'.
 */
unsigned long bitmap_find_first_bit(const unsigned long *bmp,
				    unsigned long start, unsigned long end)
{
	unsigned long curr_offset = BMP_WORD_OFFSET(start);
	unsigned long curr_idx = BMP_WORD_INDEX(start);

	assert(start <= end);

	for (; start < end; curr_idx++) {
		unsigned long bit = ffsl(bmp[curr_idx] >> curr_offset);

		if (bit)
			return min(end, start + bit - 1);
		start += BITS_PER_LONG - curr_offset;
		curr_offset = 0;
	}

	return end;
}

/*
 * Zeroes bitmap bits in the following range: [start,end-1]
 */
void bitmap_zero_region(unsigned long *bmp, unsigned long start,
			unsigned long end)
{
	unsigned long start_mask;
	unsigned long last_mask;
	unsigned long curr_idx = BMP_WORD_INDEX(start);
	unsigned long last_idx = BMP_WORD_INDEX(end - 1);

	assert(start <= end);

	if (start >= end)
		return;

	start_mask = BMP_FIRST_WORD_MASK(start);
	last_mask = BMP_LAST_WORD_MASK(end);

	if (curr_idx == last_idx) {
		bmp[curr_idx] &= ~(start_mask & last_mask);
		return;
	}

	bmp[curr_idx] &= ~start_mask;

	for (curr_idx++; curr_idx < last_idx; curr_idx++)
		bmp[curr_idx] = 0;

	bmp[curr_idx] &= ~last_mask;
}

/*
 * Sets bitmap bits in the following range: [start,end-1]
 */
void bitmap_fill_region(unsigned long *bmp, unsigned long start,
			unsigned long end)
{
	unsigned long start_mask;
	unsigned long last_mask;
	unsigned long curr_idx = BMP_WORD_INDEX(start);
	unsigned long last_idx = BMP_WORD_INDEX(end - 1);

	assert(start <= end);

	if (start >= end)
		return;

	start_mask = BMP_FIRST_WORD_MASK(start);
	last_mask = BMP_LAST_WORD_MASK(end);

	if (curr_idx == last_idx) {
		bmp[curr_idx] |= (start_mask & last_mask);
		return;
	}

	bmp[curr_idx] |= start_mask;

	for (curr_idx++; curr_idx < last_idx; curr_idx++)
		bmp[curr_idx] = ULONG_MAX;

	bmp[curr_idx] |= last_mask;
}

/*
 * Checks whether the contiguous region of region_size bits starting from
 * start is free.
 *
 * Returns true if the said region is free, otherwise returns false.
 */
static bool bitmap_is_free_region(unsigned long *bmp, unsigned long start,
				  unsigned long region_size)
{
	unsigned long curr_idx;
	unsigned long last_idx;
	unsigned long last_mask;
	unsigned long start_mask;

	curr_idx = BMP_WORD_INDEX(start);
	start_mask = BMP_FIRST_WORD_MASK(start);
	last_idx = BMP_WORD_INDEX(start + region_size - 1);
	last_mask = BMP_LAST_WORD_MASK(start + region_size);

	if (curr_idx == last_idx)
		return !(bmp[curr_idx] & start_mask & last_mask);

	if (bmp[curr_idx] & start_mask)
		return false;

	for (curr_idx++; curr_idx < last_idx; curr_idx++) {
		if (bmp[curr_idx])
			return false;
	}

	return !(bmp[curr_idx] & last_mask);
}

/*
 * Finds a contiguous region with the size of region_size
 * in the bitmap that is not set.
 *
 * Returns first index of such region if found,
 * otherwise returns nbits.
 */
unsigned long bitmap_find_free_region(unsigned long *bmp,
				      unsigned long nbits,
				      unsigned long region_size)
{
	unsigned long start;

	if (!region_size)
		return 0;

	for (start = 0; start + region_size <= nbits; start++) {
		if (bitmap_test_bit(bmp, start))
			continue;

		if (bitmap_is_free_region(bmp, start, region_size))
			return start;
	}

	return nbits;
}

