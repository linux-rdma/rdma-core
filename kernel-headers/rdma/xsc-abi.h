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

enum {
	XSC_HW_FEATURE_FLAG_SUPPORT_CQE64 = 1 << 0,
};

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

struct xsc_ib_alloc_pd_resp {
	__u32	pdn;
};

struct xsc_ib_create_cq {
	__aligned_u64 buf_addr;
	__aligned_u64 db_addr;
	__u32	cqe_size;

	int	dmabuf_fd;
	size_t	dmabuf_sz;
};

struct xsc_ib_create_cq_resp {
	__u32	cqn;
	__u32	reserved;
};

struct xsc_ib_resize_cq {
	__aligned_u64 buf_addr;
	__u16	cqe_size;
	__u16	reserved0;
	__u32	reserved1;
};

enum xsc_ib_mmap_cmd {
	XSC_IB_MMAP_REGULAR_PAGE               = 0,
	XSC_IB_MMAP_GET_CONTIGUOUS_PAGES       = 1,
	XSC_IB_MMAP_WC_PAGE                    = 2,
	XSC_IB_MMAP_NC_PAGE                    = 3,
	XSC_IB_MMAP_CORE_CLOCK                 = 5,
	XSC_IB_MMAP_ALLOC_WC                   = 6,
	XSC_IB_MMAP_CLOCK_INFO                 = 7,
	XSC_IB_MMAP_DEVICE_MEM                 = 8,
};

#endif /* XSC_ABI_USER_H */
