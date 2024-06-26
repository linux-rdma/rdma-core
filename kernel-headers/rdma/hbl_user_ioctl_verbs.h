/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) */
/*
 * Copyright 2022-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#ifndef HBL_IB_USER_IOCTL_VERBS_H
#define HBL_IB_USER_IOCTL_VERBS_H

#include <linux/types.h>

#define HBL_IB_MAX_BP_OFFS		16

enum hbl_ib_wq_array_type {
	HBL_IB_WQ_ARRAY_TYPE_GENERIC,
	HBL_IB_WQ_ARRAY_TYPE_RESERVED1,
	HBL_IB_WQ_ARRAY_TYPE_RESERVED2,
	HBL_IB_WQ_ARRAY_TYPE_RESERVED3,
	HBL_IB_WQ_ARRAY_TYPE_RESERVED4,
	HBL_IB_WQ_ARRAY_TYPE_MAX,
};

struct hbl_wq_array_attr {
	__u32 max_num_of_wqs;
	__u32 max_num_of_wqes_in_wq;
	__u8 mem_id;
	__u8 swq_granularity;
	__u8 reserved0[6];
	__aligned_u64 reserved1[2];
};

struct hbl_uapi_usr_fifo_create_in {
	__u32 port_num;
	__u32 reserved0;
	__u32 reserved1;
	__u32 usr_fifo_num_hint;
	__u8 mode;
	__u8 reserved2;
	__u8 reserved3[6];
};

struct hbl_uapi_usr_fifo_create_out {
	__aligned_u64 ci_handle;
	__aligned_u64 regs_handle;
	__u32 usr_fifo_num;
	__u32 regs_offset;
	__u32 size;
	__u32 bp_thresh;
};

struct hbl_uapi_set_port_ex_in {
	struct hbl_wq_array_attr wq_arr_attr[HBL_IB_WQ_ARRAY_TYPE_MAX];
	/* Pointer to u32 array */
	__aligned_u64 qp_wq_bp_offs;
	__u32 qp_wq_bp_offs_cnt;
	__u32 port_num;
	__aligned_u64 reserved0;
	__u32 reserved1;
	__u8 reserved2;
	__u8 advanced;
	__u8 adaptive_timeout_en;
	__u8 reserved3;
};

struct hbl_uapi_query_port_in {
	__u32 port_num;
	__u32 reserved;
};

struct hbl_uapi_query_port_out {
	__u32 max_num_of_qps;
	__u32 num_allocated_qps;
	__u32 max_allocated_qp_num;
	__u32 max_cq_size;
	__u32 reserved0;
	__u32 reserved1;
	__u32 reserved2;
	__u32 reserved3;
	__u32 reserved4;
	__u8 advanced;
	__u8 max_num_of_cqs;
	__u8 max_num_of_usr_fifos;
	__u8 max_num_of_encaps;
	__u8 nic_macro_idx;
	__u8 nic_phys_port_idx;
	__u8 reserved[6];
};

struct hbl_uapi_encap_create_in {
	__aligned_u64 tnl_hdr_ptr;
	__u32 tnl_hdr_size;
	__u32 port_num;
	__u32 ipv4_addr;
	__u16 udp_dst_port;
	__u16 ip_proto;
	__u8 encap_type;
	__u8 reserved[7];
};

struct hbl_uapi_encap_create_out {
	__u32 encap_num;
	__u32 reserved;
};

#endif /* HBL_IB_USER_IOCTL_VERBS_H */
