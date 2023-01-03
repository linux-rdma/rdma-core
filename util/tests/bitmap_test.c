// SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
#include <stdio.h>
#include <stdbool.h>
#include <valgrind/memcheck.h>
#include <ccan/array_size.h>
#include <util/bitmap.h>

static int failed_tests;

#define EXPECT_EQ(expected, actual) \
	({ \
		typeof(expected) _expected = (expected); \
		typeof(actual) _actual = (actual); \
		if (_expected != _actual) { \
			printf("  FAIL at line %d: %s not %s\n", __LINE__, \
				#expected, #actual); \
			printf("\tExpected: %ld\n", (long) _expected); \
			printf("\t  Actual: %ld\n", (long) _actual); \
			failed_tests++; \
		} \
	})

#define EXPECT_TRUE(actual) EXPECT_EQ(true, actual)
#define EXPECT_FALSE(actual) EXPECT_EQ(false, actual)

static void test_bitmap_empty(unsigned long *bmp, const int nbits)
{
	for (int i = 1; i < nbits; i++) {
		bitmap_zero(bmp, nbits);
		EXPECT_TRUE(bitmap_empty(bmp, nbits));
		bitmap_set_bit(bmp, i);
		EXPECT_TRUE(bitmap_empty(bmp, i));
		EXPECT_FALSE(bitmap_empty(bmp, i + 1));
	}
}

static void test_bitmap_find_first_bit(unsigned long *bmp, const int nbits)
{
	bitmap_zero(bmp, nbits);

	for (int i = 0; i < nbits; i++) {
		EXPECT_EQ(nbits, bitmap_find_first_bit(bmp, 0, nbits));
		bitmap_set_bit(bmp, i);
		EXPECT_EQ(i, bitmap_find_first_bit(bmp, 0, nbits));
		EXPECT_EQ(i, bitmap_find_first_bit(bmp, i, nbits));
		EXPECT_EQ(i, bitmap_find_first_bit(bmp, 0, i + 1));
		EXPECT_EQ(i, bitmap_find_first_bit(bmp, 0, i));
		EXPECT_EQ(nbits, bitmap_find_first_bit(bmp, i + 1, nbits));
		bitmap_clear_bit(bmp, i);
	}
}

static void test_bitmap_zero_region(unsigned long *bmp, const int nbits)
{
	for (int end = 0; end <= nbits; end++) {
		int bit = end / 2;

		bitmap_fill(bmp, nbits);
		bitmap_zero_region(bmp, bit, end);

		for (int i = 0; i < nbits; i++) {
			bool expected = i < bit || i >= end;

			EXPECT_EQ(expected, bitmap_test_bit(bmp, i));
		}
	}
}

static void test_bitmap_fill_region(unsigned long *bmp, const int nbits)
{
	for (int end = 0; end <= nbits; end++) {
		int bit = end / 2;

		bitmap_zero(bmp, nbits);
		bitmap_fill_region(bmp, bit, end);

		for (int i = 0; i < nbits; i++) {
			bool expected = i >= bit && i < end;

			EXPECT_EQ(expected, bitmap_test_bit(bmp, i));
		}
	}
}

static void test_bitmap_find_free_region(unsigned long *bmp, const int nbits)
{
	for (int region_size = 1; region_size <= nbits; region_size++) {
		int start = nbits - region_size;

		bitmap_zero(bmp, nbits);
		EXPECT_EQ(0, bitmap_find_free_region(bmp, nbits, region_size));

		if (start > region_size)
			bitmap_fill_region(bmp, region_size - 1, start);
		else
			bitmap_fill_region(bmp, 0, start);
		EXPECT_EQ(start, bitmap_find_free_region(bmp, nbits, region_size));
	}
}

int main(int argc, char **argv)
{
	int all_failed_tests = 0;
	int nbitsv[] = {
		BITS_PER_LONG,
		BITS_PER_LONG - 1,
		BITS_PER_LONG + 1,
		BITS_PER_LONG / 2,
		BITS_PER_LONG * 2,
	};

	for (int i = 0; i < ARRAY_SIZE(nbitsv); i++) {
		int nbits = nbitsv[i];
		unsigned long *bmp = bitmap_alloc0(nbits);

	#define TEST(func_name) do { \
		VALGRIND_MAKE_MEM_UNDEFINED(bmp, BITS_TO_LONGS(nbits) * sizeof(long)); \
		failed_tests = 0; \
		(func_name)(bmp, nbits); \
		printf("%6s %s(nbits=%d)\n", failed_tests ? "FAILED" : "OK", #func_name, \
		       nbits); \
		all_failed_tests += failed_tests; \
		} while (0)

		TEST(test_bitmap_empty);
		TEST(test_bitmap_find_first_bit);
		TEST(test_bitmap_zero_region);
		TEST(test_bitmap_fill_region);
		TEST(test_bitmap_find_free_region);

	#undef TEST
		printf("\n");
		free(bmp);
	}

	if (all_failed_tests) {
		printf("%d tests failed\n", all_failed_tests);
		return 1;
	}

	return 0;
}
