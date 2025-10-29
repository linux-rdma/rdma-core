/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_ABI_USER_H
#define XSC_ABI_USER_H

#include <linux/types.h>
#include <linux/if_ether.h>	/* For ETH_ALEN. */
#include <rdma/ib_user_ioctl_verbs.h>

/* Make sure that all structs defined in this file remain laid out so
 * that they pack the same way on 32-bit and 64-bit architectures (to
 * avoid incompatibility between 32-bit userspace and 64-bit kernels).
 * In particular do not use pointer types -- pass pointers in __u64
 * instead.
 */

struct xsc_ib_alloc_ucontext_resp {
	__u32	qp_tab_size;
	__u32	cache_line_size;
	__u16	max_sq_desc_sz;
	__u16	max_rq_desc_sz;
	__u32	max_send_wr;
	__u32	max_recv_wr;
	__u16	num_ports;
	__u16	device_id;
	__aligned_u64	qpm_tx_db;
	__aligned_u64	qpm_rx_db;
	__aligned_u64	cqm_next_cid_reg;
	__aligned_u64	cqm_armdb;
	__u32	send_ds_num;
	__u32	recv_ds_num;
	__u32	resv;
};

struct xsc_ib_create_qp {
	__aligned_u64 buf_addr;
	__aligned_u64 db_addr;
	__u32	sq_wqe_count;
	__u32	rq_wqe_count;
	__u32	rq_wqe_shift;
	__u32	flags;
	__u32	resv;
};

struct xsc_ib_create_qp_resp {
	__u32   bfreg_index;
	__u32   resv;
};

struct xsc_ib_create_cq {
	__aligned_u64 buf_addr;
	__u32	cqe_size;
};

struct xsc_ib_create_cq_resp {
	__u32	cqn;
	__u32	reserved;
};

struct xsc_ib_create_ah_resp {
	__u32	response_length;
	__u8	dmac[ETH_ALEN];
	__u8	reserved[6];
};

struct xsc_ib_alloc_pd_resp {
	__u32	pdn;
};

#endif /* XSC_ABI_USER_H */
