/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005, 2006, 2007, 2008 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2006, 2007 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2019, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *	Redistribution and use in source and binary forms, with or
 *	without modification, are permitted provided that the following
 *	conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <ccan/bitmap.h>
#include "mlx5dv_dr.h"

struct dr_icm_pool;
struct dr_icm_buddy_mem;

static int dr_find_first_bit(const bitmap *set_addr,
			     const bitmap *addr,
			     unsigned int size)
{
	unsigned int set_size = (size - 1) / BITS_PER_LONG + 1;
	unsigned long set_idx;

	/* find the first free in the first level */
	set_idx =  bitmap_ffs(set_addr, 0, set_size);
	/* find the next level */
	return bitmap_ffs(addr, set_idx * BITS_PER_LONG, size);
}

int dr_buddy_init(struct dr_icm_buddy_mem *buddy, uint32_t max_order)
{
	int i, s;

	buddy->max_order = max_order;

	list_node_init(&buddy->list_node);
	list_head_init(&buddy->used_list);
	list_head_init(&buddy->hot_list);

	buddy->bits = calloc(buddy->max_order + 1, sizeof(long *));
	if (!buddy->bits) {
		errno = ENOMEM;
		return ENOMEM;
	}

	buddy->num_free = calloc(buddy->max_order + 1, sizeof(*buddy->num_free));
	if (!buddy->num_free)
		goto err_out_free_bits;

	buddy->set_bit = calloc(buddy->max_order + 1, sizeof(long *));
	if (!buddy->set_bit)
		goto err_out_free_num_free;

	/* Allocating max_order bitmaps, one for each order.
	 * only the bitmap for the maximum size will be available for use and
	 * the first bit there will be set.
	 */
	for (i = 0; i <= buddy->max_order; ++i) {
		s = 1 << (buddy->max_order - i);
		buddy->bits[i] = bitmap_alloc0(s);
		if (!buddy->bits[i])
			goto err_out_free_each_bit_per_order;
	}

	for (i = 0; i <= buddy->max_order; ++i) {
		s = BITS_TO_LONGS(1 << (buddy->max_order - i));
		buddy->set_bit[i] = bitmap_alloc0(s);
		if (!buddy->set_bit[i])
			goto err_out_free_set;
	}

	bitmap_set_bit(buddy->bits[buddy->max_order], 0);
	bitmap_set_bit(buddy->set_bit[buddy->max_order], 0);

	buddy->num_free[buddy->max_order] = 1;

	return 0;

err_out_free_set:
	for (i = 0; i <= buddy->max_order; ++i)
		free(buddy->set_bit[i]);

err_out_free_each_bit_per_order:
	free(buddy->set_bit);

	for (i = 0; i <= buddy->max_order; ++i)
		free(buddy->bits[i]);

err_out_free_num_free:
	free(buddy->num_free);

err_out_free_bits:
	free(buddy->bits);
	errno = ENOMEM;
	return ENOMEM;
}

void dr_buddy_cleanup(struct dr_icm_buddy_mem *buddy)
{
	int i;

	list_del(&buddy->list_node);

	for (i = 0; i <= buddy->max_order; ++i) {
		free(buddy->bits[i]);
		free(buddy->set_bit[i]);
	}

	free(buddy->set_bit);
	free(buddy->num_free);
	free(buddy->bits);
}

/*
 * Find the borders (high and low) of specific seg (segment location)
 * of the lower level of the bitmap in order to mark the upper layer
 * of bitmap.
 */
static void dr_buddy_get_seg_borders(uint32_t seg,
				     uint32_t *low,
				     uint32_t *high)
{
	*low = (seg / BITS_PER_LONG) * BITS_PER_LONG;
	*high = ((seg / BITS_PER_LONG) + 1) * BITS_PER_LONG;
}

/*
 * We have two layers of searching in the bitmaps, so when needed update the
 * second layer of search.
 */
static void dr_buddy_update_upper_bitmap(struct dr_icm_buddy_mem *buddy,
					 uint32_t seg, int order)
{
	uint32_t h, l, m;

	/* clear upper layer of search if needed */
	dr_buddy_get_seg_borders(seg, &l, &h);
	m = bitmap_ffs(buddy->bits[order], l, h);
	if (m == h) /* nothing in the long that includes seg */
		bitmap_clear_bit(buddy->set_bit[order], seg / BITS_PER_LONG);
}

/*
 * This function finds the first area of the managed memory by the buddy.
 * It uses the data structures of the buddy-system in order to find the first
 * area of free place, starting from the current order till the maximum order
 * in the system.
 * The function returns the location (seg) in the whole buddy memory area, this
 * indicates the place of the memory to use, it is the index of the mem segment.
 */
int dr_buddy_alloc_mem(struct dr_icm_buddy_mem *buddy, int order)
{
	int seg;
	int o, m;

	for (o = order; o <= buddy->max_order; ++o)
		if (buddy->num_free[o]) {
			m = 1 << (buddy->max_order - o);
			seg = dr_find_first_bit(buddy->set_bit[o], buddy->bits[o], m);
			if (m <= seg) {
				/* not found free mem, but there are free mem */
				assert(false);
				return -1;
			}
			goto found;
		}

	return -1;

found:
	bitmap_clear_bit(buddy->bits[o], seg);
	/* clear upper layer of search if needed */
	dr_buddy_update_upper_bitmap(buddy, seg, o);
	--buddy->num_free[o];
	/* if we find free memory in some order that it is bigger than the
	 * required order, we need to devied each order between the required to
	 * the found one to 2, and mark accordingly.
	 */
	while (o > order) {
		--o;
		seg <<= 1;
		bitmap_set_bit(buddy->bits[o], seg ^ 1);
		bitmap_set_bit(buddy->set_bit[o], (seg ^ 1) / BITS_PER_LONG);

		++buddy->num_free[o];
	}

	seg <<= order;

	return seg;
}

void
dr_buddy_free_mem(struct dr_icm_buddy_mem *buddy, uint32_t seg, int order)
{
	seg >>= order;

	/* whenever a segment is free, the mem is added to the buddy that gave it */
	while (bitmap_test_bit(buddy->bits[order], seg ^ 1)) {
		bitmap_clear_bit(buddy->bits[order], seg ^ 1);
		dr_buddy_update_upper_bitmap(buddy, seg ^ 1, order);
		--buddy->num_free[order];
		seg >>= 1;
		++order;
	}
	bitmap_set_bit(buddy->bits[order], seg);
	bitmap_set_bit(buddy->set_bit[order], seg / BITS_PER_LONG);

	++buddy->num_free[order];
}

