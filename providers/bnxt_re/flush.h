/*
 * Broadcom NetXtreme-E User Space RoCE driver
 *
 * Copyright (c) 2015-2017, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Description: A few wrappers for flush queue management
 */

#ifndef __FLUSH_H__
#define __FLUSH_H__

#include <ccan/list.h>

struct bnxt_re_fque_node {
	uint8_t valid;
	struct list_node list;
};

static inline void fque_init_node(struct bnxt_re_fque_node *node)
{
	list_node_init(&node->list);
	node->valid = false;
}

static inline void fque_add_node_tail(struct list_head *head,
				      struct bnxt_re_fque_node *new)
{
	list_add_tail(head, &new->list);
	new->valid = true;
}

static inline void fque_del_node(struct bnxt_re_fque_node *entry)
{
	entry->valid = false;
	list_del(&entry->list);
}

static inline uint8_t _fque_node_valid(struct bnxt_re_fque_node *node)
{
	return node->valid;
}

static inline void bnxt_re_fque_add_node(struct list_head *head,
					 struct bnxt_re_fque_node *node)
{
	if (!_fque_node_valid(node))
		fque_add_node_tail(head, node);
}

static inline void bnxt_re_fque_del_node(struct bnxt_re_fque_node *node)
{
	if (_fque_node_valid(node))
		fque_del_node(node);
}
#endif	/* __FLUSH_H__ */
