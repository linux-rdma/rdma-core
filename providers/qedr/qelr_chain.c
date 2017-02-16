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

#include <sys/types.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <errno.h>

#include "qelr.h"

void *qelr_chain_get_last_elem(struct qelr_chain *p_chain)
{
	void			*p_virt_addr	= NULL;
	uint32_t		size;

	if (!p_chain->first_addr)
		goto out;

	size		= p_chain->elem_size * (p_chain->n_elems - 1);
	p_virt_addr	= ((uint8_t *)p_chain->first_addr + size);
out:
	return p_virt_addr;
}

void qelr_chain_reset(struct qelr_chain *p_chain)
{
	p_chain->prod_idx	= 0;
	p_chain->cons_idx	= 0;

	p_chain->p_cons_elem	= p_chain->first_addr;
	p_chain->p_prod_elem	= p_chain->first_addr;
}

#define QELR_ANON_FD		(-1)	/* MAP_ANONYMOUS => file desc.= -1  */
#define QELR_ANON_OFFSET	(0)	/* MAP_ANONYMOUS => offset    = d/c */

int qelr_chain_alloc(struct qelr_chain *chain, int chain_size, int page_size,
		     uint16_t elem_size)
{
	int ret, a_chain_size;
	void *addr;

	/* alloc aligned page aligned chain */
	a_chain_size = (chain_size + page_size - 1) & ~(page_size - 1);
	addr = mmap(NULL, a_chain_size, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, QELR_ANON_FD,
			 QELR_ANON_OFFSET);
	if (addr == MAP_FAILED)
		return errno;

	ret = ibv_dontfork_range(addr, a_chain_size);
	if (ret) {
		munmap(addr, a_chain_size);
		return ret;
	}

	/* init chain */
	memset(chain, 0, sizeof(*chain));
	chain->first_addr = addr;
	chain->size = a_chain_size;
	chain->p_cons_elem = chain->first_addr;
	chain->p_prod_elem = chain->first_addr;
	chain->elem_size = elem_size;
	chain->n_elems = chain->size / elem_size;
	chain->last_addr = (void *)
			((uint8_t *)addr + (elem_size * (chain->n_elems -1)));

	/* Note: since we are using MAP_ANONYMOUS the chain is zeroed for us */

	return 0;
}

void qelr_chain_free(struct qelr_chain *chain)
{
	if (chain->size) {
		ibv_dofork_range(chain->first_addr, chain->size);
		munmap(chain->first_addr, chain->size);
	}
}
