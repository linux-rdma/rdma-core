/*
 * Copyright (c) 2015-2016  QLogic Corporation
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
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
 *        disclaimer in the documentation and /or other materials
 *        provided with the distribution.
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

#ifndef __QELR_CHAIN_H__
#define __QELR_CHAIN_H__

#include <stddef.h>
#include <stdint.h>

struct qelr_chain {
	void		*first_addr;	/* Address of first element in chain */
	void		*last_addr;	/* Address of last element in chain */

	/* Point to next element to produce/consume */
	void		*p_prod_elem;
	void		*p_cons_elem;

	uint32_t	prod_idx;
	uint32_t	cons_idx;

	uint32_t	n_elems;
	uint32_t	size;
	uint16_t	elem_size;
};

/* fast path functions are inline */

static inline uint32_t qelr_chain_get_cons_idx_u32(struct qelr_chain *p_chain)
{
	return p_chain->cons_idx;
}

static inline void *qelr_chain_produce(struct qelr_chain *p_chain)
{
	void *p_ret = NULL;

	p_chain->prod_idx++;

	p_ret = p_chain->p_prod_elem;

	if (p_chain->p_prod_elem == p_chain->last_addr)
		p_chain->p_prod_elem = p_chain->first_addr;
	else
		p_chain->p_prod_elem = (void *)(((uint8_t *)p_chain->p_prod_elem) +
				       p_chain->elem_size);

	return p_ret;
}

static inline void *qelr_chain_produce_n(struct qelr_chain *p_chain, int n)
{
	void *p_ret = NULL;
	int n_wrap;

	p_chain->prod_idx++;
	p_ret = p_chain->p_prod_elem;

	n_wrap = p_chain->prod_idx % p_chain->n_elems;
	if (n_wrap < n)
		p_chain->p_prod_elem = (void *)
				       (((uint8_t *)p_chain->first_addr) +
					(p_chain->elem_size * n_wrap));
	else
		p_chain->p_prod_elem = (void *)(((uint8_t *)p_chain->p_prod_elem) +
				       (p_chain->elem_size * n));

	return p_ret;
}

static inline void *qelr_chain_consume(struct qelr_chain *p_chain)
{
	void *p_ret = NULL;

	p_chain->cons_idx++;

	p_ret = p_chain->p_cons_elem;

	if (p_chain->p_cons_elem == p_chain->last_addr)
		p_chain->p_cons_elem = p_chain->first_addr;
	else
		p_chain->p_cons_elem	= (void *)
					  (((uint8_t *)p_chain->p_cons_elem) +
					   p_chain->elem_size);

	return p_ret;
}

static inline void *qelr_chain_consume_n(struct qelr_chain *p_chain, int n)
{
	void *p_ret = NULL;
	int n_wrap;

	p_chain->cons_idx += n;
	p_ret = p_chain->p_cons_elem;

	n_wrap = p_chain->cons_idx % p_chain->n_elems;
	if (n_wrap < n)
		p_chain->p_cons_elem = (void *)
				       (((uint8_t *)p_chain->first_addr) +
					(p_chain->elem_size * n_wrap));
	else
		p_chain->p_cons_elem = (void *)(((uint8_t *)p_chain->p_cons_elem) +
				       (p_chain->elem_size * n));

	return p_ret;
}

static inline uint32_t qelr_chain_get_elem_left_u32(struct qelr_chain *p_chain)
{
	uint32_t used;

	used = (uint32_t)(((uint64_t)((uint64_t) ~0U) + 1 +
			  (uint64_t)(p_chain->prod_idx)) -
			  (uint64_t)p_chain->cons_idx);

	return p_chain->n_elems - used;
}

static inline uint8_t qelr_chain_is_full(struct qelr_chain *p_chain)
{
	return qelr_chain_get_elem_left_u32(p_chain) == p_chain->n_elems;
}

static inline void qelr_chain_set_prod(
		struct qelr_chain *p_chain,
		uint32_t prod_idx,
		void *p_prod_elem)
{
	p_chain->prod_idx = prod_idx;
	p_chain->p_prod_elem = p_prod_elem;
}

void *qelr_chain_get_last_elem(struct qelr_chain *p_chain);
void qelr_chain_reset(struct qelr_chain *p_chain);
int qelr_chain_alloc(struct qelr_chain *chain, int chain_size, int page_size,
		     uint16_t elem_size);
void qelr_chain_free(struct qelr_chain *buf);

#endif /* __QELR_CHAIN_H__ */
