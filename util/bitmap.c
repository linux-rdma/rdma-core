/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */

#include "bitmap.h"

#define BMP_WORD_INDEX(n) (BITS_TO_LONGS((n) + 1) - 1)
#define BMP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BMP_LAST_WORD_MASK(end) (~BMP_FIRST_WORD_MASK(end))

static unsigned long __word_ffs(const unsigned long *word)
{
	unsigned long i;

	for (i = 0; i < BITS_PER_LONG; i++) {
		if (bitmap_test_bit(word, i))
			return i;
	}

	return i;
}

static unsigned long word_ffs(const unsigned long *word,
			      unsigned long bmp_index, unsigned long end)
{
	unsigned long set_bit;

	set_bit = __word_ffs(word);
	set_bit += bmp_index * BITS_PER_LONG;
	if (set_bit >= end)
		return end;

	return set_bit;
}

/*
 * Finds the first set bit in the bitmap starting from
 * 'start' bit until ('end'-1) bit.
 *
 * Returns the set bit index if found, otherwise returns 'end'.
 */
unsigned long bitmap_find_first_bit(const unsigned long *bmp,
				    unsigned long start, unsigned long end)
{
	unsigned long mask;
	unsigned long first_word;
	unsigned long curr_idx = BMP_WORD_INDEX(start);
	unsigned long end_idx = BMP_WORD_INDEX(end);

	assert(start <= end);

	mask = BMP_FIRST_WORD_MASK(start);

	first_word = bmp[curr_idx] & mask;
	if (first_word)
		return word_ffs(&first_word, curr_idx, end);

	for (curr_idx++; curr_idx <= end_idx; curr_idx++) {
		if (!bmp[curr_idx])
			continue;

		return word_ffs(&bmp[curr_idx], curr_idx, end);
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
	unsigned long end_idx = BMP_WORD_INDEX(end);

	assert(start <= end);

	start_mask = BMP_FIRST_WORD_MASK(start);
	last_mask = BMP_LAST_WORD_MASK(end);

	if (curr_idx == end_idx) {
		bmp[curr_idx] &= ~(start_mask & last_mask);
		return;
	}

	bmp[curr_idx] &= ~start_mask;

	for (curr_idx++; curr_idx < end_idx; curr_idx++)
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
	unsigned long end_idx = BMP_WORD_INDEX(end);

	assert(start <= end);

	start_mask = BMP_FIRST_WORD_MASK(start);
	last_mask = BMP_LAST_WORD_MASK(end);

	if (curr_idx == end_idx) {
		bmp[curr_idx] |= (start_mask & last_mask);
		return;
	}

	bmp[curr_idx] |= start_mask;

	for (curr_idx++; curr_idx < end_idx; curr_idx++)
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
	last_idx = BMP_WORD_INDEX(start + region_size);
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

	for (start = 0; start + region_size <= nbits; start++) {
		if (bitmap_test_bit(bmp, start))
			continue;

		if (bitmap_is_free_region(bmp, start, region_size))
			return start;
	}

	return nbits;
}

