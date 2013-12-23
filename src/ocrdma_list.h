/*
 * Copyright (C) 2008-2013 Emulex.  All rights reserved.
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT  LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __OCRDMA_LIST_H__
#define __OCRDMA_LIST_H__

struct ocrdma_list_node {
	struct ocrdma_list_node *next, *prev;
};

struct ocrdma_list_head {
	struct ocrdma_list_node node;
	pthread_mutex_t lock;
};

#define DBLY_LIST_HEAD_INIT(name) { { &(name.node), &(name.node) } , \
                        PTHREAD_MUTEX_INITIALIZER }

#define DBLY_LIST_HEAD(name) \
	struct ocrdma_list_head name = DBLY_LIST_HEAD_INIT(name); \

#define INIT_DBLY_LIST_NODE(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

#define INIT_DBLY_LIST_HEAD(ptr) INIT_DBLY_LIST_NODE(ptr.node)

static inline void __list_add_node(struct ocrdma_list_node *new,
				       struct ocrdma_list_node *prev,
				       struct ocrdma_list_node *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add_node_tail(struct ocrdma_list_node *new,
					  struct ocrdma_list_head *head)
{
	__list_add_node(new, head->node.prev, &head->node);
}

static inline void __list_del_node(struct ocrdma_list_node *prev,
				       struct ocrdma_list_node *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del_node(struct ocrdma_list_node *entry)
{
	__list_del_node(entry->prev, entry->next);
	entry->next = entry->prev = 0;
}

#define list_lock(head) pthread_mutex_lock(&((head)->lock))
#define list_unlock(head) pthread_mutex_unlock(&((head)->lock))

#define list_node(ptr, type, member) \
    ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

/**
 * list_for_each_node_safe	-	iterate over a list safe against removal of list entry
 * @pos:	the &struct ocrdma_list_head to use as a loop counter.
 * @n:		another &struct ocrdma_list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define list_for_each_node_safe(pos, n, head) \
	for (pos = (head)->node.next, n = pos->next; pos != &((head)->node); \
		pos = n, n = pos->next)

#endif				/* __OCRDMA_LIST_H__ */
