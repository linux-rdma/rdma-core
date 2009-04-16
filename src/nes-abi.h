/*
 * Copyright (c) 2006 - 2009 Intel-NE, Inc.  All rights reserved.
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

#ifndef nes_ABI_H
#define nes_ABI_H

#include <infiniband/kern-abi.h>

#define NES_ABI_USERSPACE_VER 1
#define NES_ABI_KERNEL_VER 1

struct nes_get_context {
	struct ibv_get_context cmd;
	__u32 reserved32;
	__u8 userspace_ver;
	__u8 reserved8[3];
};


struct nes_ualloc_ucontext_resp {
	struct ibv_get_context_resp ibv_resp;
	__u32 max_pds; 	/* maximum pds allowed for this user process */
	__u32 max_qps; 	/* maximum qps allowed for this user process */
	__u32 wq_size; 	/* defines the size of the WQs (sq+rq) allocated to the mmaped area */
	__u8 virtwq;
	__u8 kernel_ver;
	__u8 reserved[2];
};

struct nes_ualloc_pd_resp {
	struct ibv_alloc_pd_resp ibv_resp;
	__u32 pd_id;
	__u32 db_index;
};

struct nes_ucreate_cq {
	struct ibv_create_cq ibv_cmd;
	__u64 user_cq_buffer;
	__u32 mcrqf;
	__u8 reserved[4];
};

struct nes_ucreate_cq_resp {
	struct ibv_create_cq_resp ibv_resp;
	__u32 cq_id;
	__u32 cq_size;
	__u32 mmap_db_index;
	__u32 reserved;
};

enum nes_umemreg_type {
	NES_UMEMREG_TYPE_MEM = 0x0000,
	NES_UMEMREG_TYPE_QP = 0x0001,
	NES_UMEMREG_TYPE_CQ = 0x0002,
};

struct nes_ureg_mr {
	struct ibv_reg_mr ibv_cmd;
	__u32 reg_type;	/* indicates if id is memory, QP or CQ */
	__u32 reserved;
};

struct nes_ucreate_qp {
	struct ibv_create_qp ibv_cmd;
	__u64	user_sq_buffer;
};

struct nes_ucreate_qp_resp {
	struct ibv_create_qp_resp ibv_resp;
	__u32 qp_id;
	__u32 actual_sq_size;
	__u32 actual_rq_size;
	__u32 mmap_sq_db_index;
	__u32 mmap_rq_db_index;
	__u32 nes_drv_opt;
};

struct nes_cqe {
	__u32 header;
	__u32 len;
	__u32 wrid_hi_stag;
	__u32 wrid_low_msn;
};

#endif			/* nes_ABI_H */
