/*
 * Copyright (c) 2012-2016 VMware, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of EITHER the GNU General Public License
 * version 2 as published by the Free Software Foundation or the BSD
 * 2-Clause License. This program is distributed in the hope that it
 * will be useful, but WITHOUT ANY WARRANTY; WITHOUT EVEN THE IMPLIED
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License version 2 for more details at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program in the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 * The BSD 2-Clause License
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __PVRDMA_RING_H__
#define __PVRDMA_RING_H__

#include <linux/types.h>

#define PVRDMA_INVALID_IDX	-1	/* Invalid index. */

/*
 * Rings are shared with the device, so read/write access must be atomic.
 * PVRDMA is x86 only, and since 32-bit access is atomic on x86, using
 * regular uint32_t is safe.
 */

struct pvrdma_ring {
	uint32_t prod_tail;	/* Producer tail. */
	uint32_t cons_head;	/* Consumer head. */
};

struct pvrdma_ring_state {
	struct pvrdma_ring tx;	/* Tx ring. */
	struct pvrdma_ring rx;	/* Rx ring. */
};

static inline int pvrdma_idx_valid(uint32_t idx, uint32_t max_elems)
{
	/* Generates fewer instructions than a less-than. */
	return (idx & ~((max_elems << 1) - 1)) == 0;
}

static inline int32_t pvrdma_idx(uint32_t *var, uint32_t max_elems)
{
	const uint32_t idx = *var;

	if (pvrdma_idx_valid(idx, max_elems))
		return idx & (max_elems - 1);
	return PVRDMA_INVALID_IDX;
}

static inline void pvrdma_idx_ring_inc(uint32_t *var, uint32_t max_elems)
{
	uint32_t idx = (*var) + 1;		/* Increment. */

	idx &= (max_elems << 1) - 1;		/* Modulo size, flip gen. */
	*var = idx;
}

static inline int32_t pvrdma_idx_ring_has_space(const struct pvrdma_ring *r,
						uint32_t max_elems,
						uint32_t *out_tail)
{
	const uint32_t tail = r->prod_tail;
	const uint32_t head = r->cons_head;

	if (pvrdma_idx_valid(tail, max_elems) &&
	    pvrdma_idx_valid(head, max_elems)) {
		*out_tail = tail & (max_elems - 1);
		return tail != (head ^ max_elems);
	}
	return PVRDMA_INVALID_IDX;
}

static inline int32_t pvrdma_idx_ring_has_data(const struct pvrdma_ring *r,
					       uint32_t max_elems,
					       uint32_t *out_head)
{
	const uint32_t tail = r->prod_tail;
	const uint32_t head = r->cons_head;

	if (pvrdma_idx_valid(tail, max_elems) &&
	    pvrdma_idx_valid(head, max_elems)) {
		*out_head = head & (max_elems - 1);
		return tail != head;
	}
	return PVRDMA_INVALID_IDX;
}

static inline int32_t pvrdma_idx_ring_is_valid_idx(const struct pvrdma_ring *r,
						   uint32_t max_elems,
						   uint32_t *idx)
{
	const uint32_t tail = r->prod_tail;
	const uint32_t head = r->cons_head;

	if (pvrdma_idx_valid(tail, max_elems) &&
	    pvrdma_idx_valid(head, max_elems) &&
	    pvrdma_idx_valid(*idx, max_elems)) {
		if (tail > head && (*idx < tail && *idx >= head))
			return 1;
		else if (head > tail && (*idx >= head || *idx < tail))
			return 1;
	}
	return 0;
}

#endif /* __PVRDMA_RING_H__ */
