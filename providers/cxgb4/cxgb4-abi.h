/*
 * Copyright (c) 2006-2016 Chelsio, Inc. All rights reserved.
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

#include <stdint.h>
#include <infiniband/kern-abi.h>
#include <rdma/cxgb4-abi.h>
#include <kernel-abi/cxgb4-abi.h>

/* compat for ABI version 0 */
#define _c4iw_create_qp_resp_v0                                                \
	{                                                                      \
		__u64 sq_key;                                                  \
		__u64 rq_key;                                                  \
		__u64 sq_db_gts_key;                                           \
		__u64 rq_db_gts_key;                                           \
		__u64 sq_memsize;                                              \
		__u64 rq_memsize;                                              \
		__u32 sqid;                                                    \
		__u32 rqid;                                                    \
		__u32 sq_size;                                                 \
		__u32 rq_size;                                                 \
		__u32 qid_mask;                                                \
	};
struct c4iw_create_qp_resp_v0 _c4iw_create_qp_resp_v0;
#define _STRUCT_c4iw_create_qp_resp_v0 struct _c4iw_create_qp_resp_v0

DECLARE_DRV_CMD(uc4iw_alloc_pd, IB_USER_VERBS_CMD_ALLOC_PD,
		empty, c4iw_alloc_pd_resp);
DECLARE_DRV_CMD(uc4iw_create_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		c4iw_create_cq, c4iw_create_cq_resp);
DECLARE_DRV_CMD(uc4iw_create_srq, IB_USER_VERBS_CMD_CREATE_SRQ,
		empty, c4iw_create_srq_resp);
DECLARE_DRV_CMD(uc4iw_create_qp, IB_USER_VERBS_CMD_CREATE_QP,
		empty, c4iw_create_qp_resp);
DECLARE_DRV_CMD(uc4iw_create_qp_v0, IB_USER_VERBS_CMD_CREATE_QP,
		empty, c4iw_create_qp_resp_v0);
DECLARE_DRV_CMD(uc4iw_alloc_ucontext, IB_USER_VERBS_CMD_GET_CONTEXT,
		empty, c4iw_alloc_ucontext_resp);

#endif				/* IWCH_ABI_H */
