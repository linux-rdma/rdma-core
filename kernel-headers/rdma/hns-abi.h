/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
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

#ifndef HNS_ABI_USER_H
#define HNS_ABI_USER_H

#include <linux/types.h>

struct hns_roce_ib_create_cq {
	__aligned_u64 buf_addr;
	__aligned_u64 db_addr;
	__u32 cqe_size;
	__u32 reserved;
};

enum hns_roce_cq_cap_flags {
	HNS_ROCE_CQ_FLAG_RECORD_DB = 1 << 0,
};

struct hns_roce_ib_create_cq_resp {
	__aligned_u64 cqn; /* Only 32 bits used, 64 for compat */
	__aligned_u64 cap_flags;
};

struct hns_roce_ib_create_srq {
	__aligned_u64 buf_addr;
	__aligned_u64 db_addr;
	__aligned_u64 que_addr;
};

struct hns_roce_ib_create_srq_resp {
	__u32	srqn;
	__u32	reserved;
};

struct hns_roce_ib_create_qp {
	__aligned_u64 buf_addr;
	__aligned_u64 db_addr;
	__u8    log_sq_bb_count;
	__u8    log_sq_stride;
	__u8    sq_no_prefetch;
	__u8    reserved[5];
	__aligned_u64 sdb_addr;
};

enum hns_roce_qp_cap_flags {
	HNS_ROCE_QP_CAP_RQ_RECORD_DB = 1 << 0,
	HNS_ROCE_QP_CAP_SQ_RECORD_DB = 1 << 1,
	HNS_ROCE_QP_CAP_OWNER_DB = 1 << 2,
	HNS_ROCE_QP_CAP_DYNAMIC_CTX_ATTACH = 1 << 4,
	HNS_ROCE_QP_CAP_DYNAMIC_CTX_DETACH = 1 << 6,
};

struct hns_roce_ib_create_qp_resp {
	__aligned_u64 cap_flags;
};

enum {
	HNS_ROCE_ALLOC_UCTX_COMP_DCA_MAX_QPS = 1 << 0,
};

struct hns_roce_ib_alloc_ucontext {
	__u32 comp;
	__u32 dca_max_qps;
};

enum {
	HNS_ROCE_CAP_FLAG_DCA_MODE = 1 << 15,
};

struct hns_roce_ib_alloc_ucontext_resp {
	__u32	qp_tab_size;
	__u32	cqe_size;
	__u32	srq_tab_size;
	__u32	reserved;
	__aligned_u64 cap_flags;
	__u32	dca_qps;
	__u32	dca_mmap_size;
};

struct hns_roce_ib_alloc_pd_resp {
	__u32 pdn;
};

enum {
	HNS_ROCE_MMAP_REGULAR_PAGE,
	HNS_ROCE_MMAP_DCA_PAGE,
};

struct hns_roce_ib_modify_qp_resp {
	__u32	dcan;
	__u32	reserved;
};

#define UVERBS_ID_NS_MASK 0xF000
#define UVERBS_ID_NS_SHIFT 12

enum hns_ib_objects {
	HNS_IB_OBJECT_DCA_MEM = (1U << UVERBS_ID_NS_SHIFT),
};

enum hns_ib_dca_mem_methods {
	HNS_IB_METHOD_DCA_MEM_REG = (1U << UVERBS_ID_NS_SHIFT),
	HNS_IB_METHOD_DCA_MEM_DEREG,
	HNS_IB_METHOD_DCA_MEM_SHRINK,
	HNS_IB_METHOD_DCA_MEM_ATTACH,
	HNS_IB_METHOD_DCA_MEM_DETACH,
	HNS_IB_METHOD_DCA_MEM_QUERY,
};

enum hns_ib_dca_mem_reg_attrs {
	HNS_IB_ATTR_DCA_MEM_REG_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	HNS_IB_ATTR_DCA_MEM_REG_LEN,
	HNS_IB_ATTR_DCA_MEM_REG_ADDR,
	HNS_IB_ATTR_DCA_MEM_REG_KEY,
};

enum hns_ib_dca_mem_dereg_attrs {
	HNS_IB_ATTR_DCA_MEM_DEREG_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
};

enum hns_ib_dca_mem_shrink_attrs {
	HNS_IB_ATTR_DCA_MEM_SHRINK_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	HNS_IB_ATTR_DCA_MEM_SHRINK_RESERVED_SIZE,
	HNS_IB_ATTR_DCA_MEM_SHRINK_OUT_FREE_KEY,
	HNS_IB_ATTR_DCA_MEM_SHRINK_OUT_FREE_MEMS,
};

#define HNS_IB_ATTACH_FLAGS_NEW_BUFFER 1U

enum hns_ib_dca_mem_attach_attrs {
	HNS_IB_ATTR_DCA_MEM_ATTACH_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	HNS_IB_ATTR_DCA_MEM_ATTACH_SQ_OFFSET,
	HNS_IB_ATTR_DCA_MEM_ATTACH_SGE_OFFSET,
	HNS_IB_ATTR_DCA_MEM_ATTACH_RQ_OFFSET,
	HNS_IB_ATTR_DCA_MEM_ATTACH_OUT_ALLOC_FLAGS,
	HNS_IB_ATTR_DCA_MEM_ATTACH_OUT_ALLOC_PAGES,
};

enum hns_ib_dca_mem_detach_attrs {
	HNS_IB_ATTR_DCA_MEM_DETACH_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	HNS_IB_ATTR_DCA_MEM_DETACH_SQ_INDEX,
};

enum hns_ib_dca_mem_query_attrs {
	HNS_IB_ATTR_DCA_MEM_QUERY_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	HNS_IB_ATTR_DCA_MEM_QUERY_PAGE_INDEX,
	HNS_IB_ATTR_DCA_MEM_QUERY_OUT_KEY,
	HNS_IB_ATTR_DCA_MEM_QUERY_OUT_OFFSET,
	HNS_IB_ATTR_DCA_MEM_QUERY_OUT_PAGE_COUNT,
};

#endif /* HNS_ABI_USER_H */
