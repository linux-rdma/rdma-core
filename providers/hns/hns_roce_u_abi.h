/*
 * Copyright (c) 2016 Hisilicon Limited.
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

#ifndef _HNS_ROCE_U_ABI_H
#define _HNS_ROCE_U_ABI_H

#include <infiniband/kern-abi.h>

struct hns_roce_alloc_ucontext_resp {
	struct ibv_get_context_resp	ibv_resp;
	__u32				qp_tab_size;
};

struct hns_roce_alloc_pd_resp {
	struct ibv_alloc_pd_resp	ibv_resp;
	__u32				pdn;
	__u32				reserved;
};

struct hns_roce_create_cq {
	struct ibv_create_cq		ibv_cmd;
	__u64				buf_addr;
	__u64				db_addr;
};

struct hns_roce_create_cq_resp {
	struct ibv_create_cq_resp	ibv_resp;
	__u32				cqn;
	__u32				reserved;
};

struct hns_roce_create_qp {
	struct ibv_create_qp		ibv_cmd;
	__u64				buf_addr;
	__u8				log_sq_bb_count;
	__u8				log_sq_stride;
	__u8				reserved[5];
};

#endif /* _HNS_ROCE_U_ABI_H */
