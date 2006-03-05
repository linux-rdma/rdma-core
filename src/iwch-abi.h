/*
 * Copyright (c) 2006 Chelsio, Inc. All rights reserved.
 * Copyright (c) 2006 Open Grid Computing, Inc. All rights reserved.
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
#ifndef IWCH_ABI_H
#define IWCH_ABI_H

#include <infiniband/kern-abi.h>

struct iwch_alloc_ucontext_resp {
	struct ibv_get_context_resp ibv_resp;
};

struct iwch_alloc_pd_resp {
	struct ibv_alloc_pd_resp ibv_resp;
};

struct iwch_create_cq {
	struct ibv_create_cq ibv_cmd;
};


struct iwch_create_cq_resp {
	struct ibv_create_cq_resp ibv_resp;
	__u32 cqid;
	__u32 entries;
	__u64 physaddr;		/* library mmaps this to get addressability */
	__u64 queue;
};

struct iwch_create_qp {
	struct ibv_create_qp ibv_cmd;
};

struct iwch_create_qp_resp {
	struct ibv_create_qp_resp ibv_resp;
	__u32 qpid;
	__u32 entries;		/* actual number of entries after creation */
	__u64 physaddr;		/* library mmaps this to get addressability */
	__u64 physsize;		/* library mmaps this to get addressability */
	__u64 queue;
};


struct t3_cqe {
	__u32 header:32;
	__u32 len:32;
	__u32 wrid_hi_stag:32;
	__u32 wrid_low_msn:32;
};

#endif				/* IWCH_ABI_H */
