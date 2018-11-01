/* Licensed under LGPLv2.1+ - see LICENSE file for details */

#include "config.h"

#include <ccan/bitmap.h>

#include <assert.h>

#define BIT_ALIGN_DOWN(n)	((n) & ~(BITMAP_WORD_BITS - 1))
#define BIT_ALIGN_UP(n)		BIT_ALIGN_DOWN((n) + BITMAP_WORD_BITS - 1)

void bitmap_zero_range(bitmap *bmap, unsigned long n, unsigned long m)
{
	unsigned long an = BIT_ALIGN_UP(n);
	unsigned long am = BIT_ALIGN_DOWN(m);
	bitmap_word headmask = -1ULL >> (n % BITMAP_WORD_BITS);
	bitmap_word tailmask = ~(-1ULL >> (m % BITMAP_WORD_BITS));

	assert(m >= n);

	if (am < an) {
		BITMAP_WORD(bmap, n) &= ~bitmap_bswap(headmask & tailmask);
		return;
	}

	if (an > n)
		BITMAP_WORD(bmap, n) &= ~bitmap_bswap(headmask);

	if (am > an)
		memset(&BITMAP_WORD(bmap, an), 0,
		       (am - an) / BITMAP_WORD_BITS * sizeof(bitmap_word));

	if (m > am)
		BITMAP_WORD(bmap, m) &= ~bitmap_bswap(tailmask);
}

void bitmap_fill_range(bitmap *bmap, unsigned long n, unsigned long m)
{
	unsigned long an = BIT_ALIGN_UP(n);
	unsigned long am = BIT_ALIGN_DOWN(m);
	bitmap_word headmask = -1ULL >> (n % BITMAP_WORD_BITS);
	bitmap_word tailmask = ~(-1ULL >> (m % BITMAP_WORD_BITS));

	assert(m >= n);

	if (am < an) {
		BITMAP_WORD(bmap, n) |= bitmap_bswap(headmask & tailmask);
		return;
	}

	if (an > n)
		BITMAP_WORD(bmap, n) |= bitmap_bswap(headmask);

	if (am > an)
		memset(&BITMAP_WORD(bmap, an), 0xff,
		       (am - an) / BITMAP_WORD_BITS * sizeof(bitmap_word));

	if (m > am)
		BITMAP_WORD(bmap, m) |= bitmap_bswap(tailmask);
}

static int bitmap_clz(bitmap_word w)
{
#if HAVE_BUILTIN_CLZL
	return __builtin_clzl(w);
#else
	int lz = 0;
	bitmap_word mask = 1UL << (BITMAP_WORD_BITS - 1);

	while (!(w & mask)) {
		lz++;
		mask >>= 1;
	}

	return lz;
#endif
}

unsigned long bitmap_ffs(const bitmap *bmap,
			 unsigned long n, unsigned long m)
{
	unsigned long an = BIT_ALIGN_UP(n);
	unsigned long am = BIT_ALIGN_DOWN(m);
	bitmap_word headmask = -1ULL >> (n % BITMAP_WORD_BITS);
	bitmap_word tailmask = ~(-1ULL >> (m % BITMAP_WORD_BITS));

	assert(m >= n);

	if (am < an) {
		bitmap_word w = bitmap_bswap(BITMAP_WORD(bmap, n));

		w &= (headmask & tailmask);

		return w ? am + bitmap_clz(w) : m;
	}

	if (an > n) {
		bitmap_word w = bitmap_bswap(BITMAP_WORD(bmap, n));

		w &= headmask;

		if (w)
			return BIT_ALIGN_DOWN(n) + bitmap_clz(w);
	}

	while (an < am) {
		bitmap_word w = bitmap_bswap(BITMAP_WORD(bmap, an));

		if (w)
			return an + bitmap_clz(w);

		an += BITMAP_WORD_BITS;
	}

	if (m > am) {
		bitmap_word w = bitmap_bswap(BITMAP_WORD(bmap, m));

		w &= tailmask;

		if (w)
			return am + bitmap_clz(w);
	}

	return m;
}
