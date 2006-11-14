/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
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
 *        disclaimer in the documentation and/or other materials
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

#include "ibverbs.h"

/*
 * We keep a linked list of page ranges that have been locked along with a
 * reference count to manage overlapping registrations, etc.
 *
 * Eventually we should turn this into an RB-tree or something similar
 * to avoid the O(n) cost of registering/unregistering memory.
 */

struct ibv_mem_node {
	struct ibv_mem_node *prev, *next;
	uintptr_t            start, end;
	int                  refcnt;
};

static struct {
	struct ibv_mem_node *first;
	pthread_mutex_t      mutex;
	uintptr_t            page_size;
} mem_map;

int ibv_init_mem_map(void)
{
	struct ibv_mem_node *node = NULL;

	node = malloc(sizeof *node);
	if (!node)
		goto fail;

	node->prev   = node->next = NULL;
	node->start  = 0;
	node->end    = UINTPTR_MAX;
	node->refcnt = 0;

	mem_map.first = node;

	mem_map.page_size = sysconf(_SC_PAGESIZE);
	if (mem_map.page_size < 0)
		goto fail;

	if (pthread_mutex_init(&mem_map.mutex, NULL))
		goto fail;

	return 0;

fail:
	if (node)
		free(node);

	return -1;
}

static struct ibv_mem_node *__mm_find_first(uintptr_t start, uintptr_t end)
{
	struct ibv_mem_node *node = mem_map.first;

	while (node) {
		if ((node->start <= start && node->end >= start) ||
		    (node->start <= end   && node->end >= end))
			break;
		node = node->next;
	}

	return node;
}

static struct ibv_mem_node *__mm_prev(struct ibv_mem_node *node)
{
	return node->prev;
}

static struct ibv_mem_node *__mm_next(struct ibv_mem_node *node)
{
	return node->next;
}

static void __mm_add(struct ibv_mem_node *node,
		     struct ibv_mem_node *new)
{
	new->prev  = node;
	new->next  = node->next;
	node->next = new;
	if (new->next)
		new->next->prev = new;
}

static void __mm_remove(struct ibv_mem_node *node)
{
	/* Never have to remove the first node, so we can use prev */
	node->prev->next = node->next;
	if (node->next)
		node->next->prev = node->prev;
}

int ibv_lock_range(void *base, size_t size)
{
	uintptr_t start, end;
	struct ibv_mem_node *node, *tmp;
	int ret = 0;

	if (!size)
		return 0;

	start = (uintptr_t) base & ~(mem_map.page_size - 1);
	end   = ((uintptr_t) (base + size + mem_map.page_size - 1) &
		 ~(mem_map.page_size - 1)) - 1;

	pthread_mutex_lock(&mem_map.mutex);

	node = __mm_find_first(start, end);

	if (node->start < start) {
		tmp = malloc(sizeof *tmp);
		if (!tmp) {
			ret = -1;
			goto out;
		}

		tmp->start  = start;
		tmp->end    = node->end;
		tmp->refcnt = node->refcnt;
		node->end   = start - 1;

		__mm_add(node, tmp);
		node = tmp;
	}

	while (node->start <= end) {
		if (node->end > end) {
			tmp = malloc(sizeof *tmp);
			if (!tmp) {
				ret = -1;
				goto out;
			}

			tmp->start  = end + 1;
			tmp->end    = node->end;
			tmp->refcnt = node->refcnt;
			node->end   = end;

			__mm_add(node, tmp);
		}


		if (node->refcnt++ == 0) {
			ret = mlock((void *) node->start,
				    node->end - node->start + 1);
			if (ret)
				goto out;
		}

		node = __mm_next(node);
	}

out:
	pthread_mutex_unlock(&mem_map.mutex);

	return ret;
}

int ibv_unlock_range(void *base, size_t size)
{
	uintptr_t start, end;
	struct ibv_mem_node *node, *tmp;
	int ret = 0;

	if (!size)
		return 0;

	start = (uintptr_t) base & ~(mem_map.page_size - 1);
	end   = ((uintptr_t) (base + size + mem_map.page_size - 1) &
		 ~(mem_map.page_size - 1)) - 1;

	pthread_mutex_lock(&mem_map.mutex);

	node = __mm_find_first(start, end);

	if (node->start != start) {
		ret = -1;
		goto out;
	}

	while (node && node->end <= end) {
		if (--node->refcnt == 0) {
			ret = munlock((void *) node->start,
				      node->end - node->start + 1);
		}

		if (__mm_prev(node) && node->refcnt == __mm_prev(node)->refcnt) {
			__mm_prev(node)->end = node->end;
			tmp = __mm_prev(node);
			__mm_remove(node);
			node = tmp;
		}

		node = __mm_next(node);
	}

	if (node && node->refcnt == __mm_prev(node)->refcnt) {
		__mm_prev(node)->end = node->end;
		tmp = __mm_prev(node);
		__mm_remove(node);
	}

	if (node->end != end) {
		ret = -1;
		goto out;
	}

out:
	pthread_mutex_unlock(&mem_map.mutex);

	return ret;
}
