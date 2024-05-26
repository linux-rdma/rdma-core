/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) */
/*
 * Copyright 2022-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#ifndef HBL_IB_ABI_USER_H
#define HBL_IB_ABI_USER_H

#include <linux/types.h>

/* Increment this value if any changes that break userspace ABI compatibility are made. */
#define HBL_IB_UVERBS_ABI_VERSION	1

#define HBL_IB_MTU_8192			6

/**
 * struct hbl_ibv_alloc_ucontext_req - Request udata for alloc ucontext.
 * @ports_mask: Mask of ports associated with this context. 0 is for all available ports.
 * @core_fd: Core device file descriptor.
 * @use_dvs: Indicates if we're going to use our DVs.
 */
struct hbl_ibv_alloc_ucontext_req {
	__aligned_u64 ports_mask;
	__s32 core_fd;
	__u8 use_dvs;
	__u8 reserved[3];
};

/**
 * enum hbl_ibv_ucontext_cap - Device capabilities.
 * @HBL_UCONTEXT_CAP_MMAP_UMR: User memory region.
 * @HBL_UCONTEXT_CAP_CC: Congestion control.
 */
enum hbl_ibv_ucontext_cap {
	HBL_UCONTEXT_CAP_MMAP_UMR = 1 << 0,
	HBL_UCONTEXT_CAP_CC = 1 << 1,
};

/**
 * struct hbl_ibv_alloc_ucontext_resp - Response udata for alloc ucontext.
 * @ports_mask: Mask of ports associated with this context.
 * @cap_mask: Capabilities mask.
 */
struct hbl_ibv_alloc_ucontext_resp {
	__aligned_u64 ports_mask;
	__aligned_u64 cap_mask;
};

/**
 * struct hbl_ibv_alloc_pd_resp - Response udata for alloc PD.
 * @pdn: PD number.
 */
struct hbl_ibv_alloc_pd_resp {
	__u32 pdn;
	__u32 reserved;
};

/**
 * enum hbl_ibv_qp_wq_types - QP WQ types.
 * @HBL_WQ_WRITE: WRITE or "native" SEND operations are allowed on this QP.
 *                NOTE: the last is not supported!
 * @HBL_WQ_RECV_RDV: RECEIVE-RDV or WRITE operations are allowed on this QP.
 *                   NOTE: posting all operations at the same time is not supported!
 * @HBL_WQ_READ_RDV: READ-RDV or WRITE operations are allowed on this QP.
 *                   NOTE: posting all operations at the same time is not supported!
 * @HBL_WQ_SEND_RDV: SEND-RDV operation is allowed on this QP.
 * @HBL_WQ_READ_RDV_ENDP: No operation is allowed on this endpoint QP!
 */
enum hbl_ibv_qp_wq_types {
	HBL_WQ_WRITE = 0x1,
	HBL_WQ_RECV_RDV = 0x2,
	HBL_WQ_READ_RDV = 0x4,
	HBL_WQ_SEND_RDV = 0x8,
	HBL_WQ_READ_RDV_ENDP = 0x10,
};

/**
 * struct hbl_ibv_modify_qp_req - Request udata for modify QP.
 * @local_key: Unique key for local memory access.
 * @remote_key: Unique key for remote memory access.
 * @congestion_wnd: Congestion-Window size.
 * @dest_wq_size: Number of WQEs on the destination.
 * @priority: Requester/responder QP priority.
 * @wq_type: WQ type. e.g. write, rdv etc
 * @loopback: QP loopback enable/disable.
 * @congestion_en: Congestion-control enable/disable.
 * @compression_en: Compression enable/disable.
 * @encap_en: Encapsulation enable flag.
 * @encap_num: Encapsulation number.
 * @wq_granularity: WQ granularity [0 for 32B or 1 for 64B].
 */
struct hbl_ibv_modify_qp_req {
	__u32 local_key;
	__u32 remote_key;
	__u32 congestion_wnd;
	__u32 reserved0;
	__u32 dest_wq_size;
	__u8 priority;
	__u8 wq_type;
	__u8 loopback;
	__u8 congestion_en;
	__u8 reserved1;
	__u8 reserved2;
	__u8 compression_en;
	__u8 reserved3;
	__u8 encap_en;
	__u8 encap_num;
	__u8 reserved4;
	__u8 wq_granularity;
	__u8 reserved5;
	__u8 reserved6[5];
};

/**
 * struct hbl_ibv_modify_qp_resp - Response udata for modify QP.
 * @swq_mem_handle: Send WQ mmap handle.
 * @rwq_mem_handle: Receive WQ mmap handle.
 * @swq_mem_size: Send WQ mmap size.
 * @rwq_mem_size: Receive WQ mmap size.
 * @qp_num: HBL QP num.
 */
struct hbl_ibv_modify_qp_resp {
	__aligned_u64 swq_mem_handle;
	__aligned_u64 rwq_mem_handle;
	__u32 swq_mem_size;
	__u32 rwq_mem_size;
	__u32 qp_num;
	__u32 reserved;
};

/**
 * enum hbl_ibv_cq_type - CQ types, used during allocation of CQs.
 * @HBL_CQ_TYPE_QP: Standard CQ used for completion of a operation for a QP.
 * @HBL_CQ_TYPE_CC: Congestion control CQ.
 */
enum hbl_ibv_cq_type {
	HBL_CQ_TYPE_QP,
	HBL_CQ_TYPE_CC,
};

/**
 * hbl_ibv_cq_req_flags - CQ req flag used for distinguision between CQ based on attributes.
 * @CQ_FLAG_NATIVE: Bit 1 is set, it represents the CQ is called for native create CQ.
 */
enum hbl_ibv_cq_req_flags {
	CQ_FLAG_NATIVE = 1 << 0,
};

/**
 * struct hbl_ibv_create_cq_req - Request udata for create CQ.
 * @port_num: IB Port number.
 * @cq_type: Type of CQ resource as mentioned in hbl_ibv_cq_type.
 * @flags: CQ req flag used for cq attributes.
 */
struct hbl_ibv_create_cq_req {
	__u32 port_num;
	__u8 cq_type;
	__u8 flags;
	__u8 reserved[2];
};

/**
 * struct hbl_ibv_port_create_cq_resp - Response udata for create CQ.
 * @mem_handle: Handle for the CQ buffer.
 * @pi_handle: Handle for the Pi memory.
 * @regs_handle: Handle for the CQ UMR register.
 * @regs_offset: Register offset of CQ UMR register.
 * @cq_num: CQ number that is allocated.
 * @cq_size: Size of the CQ.
 */
struct hbl_ibv_port_create_cq_resp {
	__aligned_u64 mem_handle;
	__aligned_u64 pi_handle;
	__aligned_u64 regs_handle;
	__u32 regs_offset;
	__u32 cq_num;
	__u32 cq_size;
	__u32 reserved;
};

/**
 * struct hbl_ibv_create_cq_resp - Response udata for create CQ.
 * @mem_handle: Handle for the CQ buffer.
 * @pi_handle: Handle for the Pi memory.
 * @regs_handle: Handle for the CQ UMR register.
 * @regs_offset: Register offset of CQ UMR register.
 * @cq_num: CQ number that is allocated.
 * @cq_size: Size of the CQ.
 * @port_cq_resp: response data for create CQ per port.
 */
struct hbl_ibv_create_cq_resp {
	__aligned_u64 mem_handle;
	__aligned_u64 pi_handle;
	__aligned_u64 regs_handle;
	__u32 regs_offset;
	__u32 cq_num;
	__u32 cq_size;
	__u32 reserved;
	struct hbl_ibv_port_create_cq_resp port_cq_resp[];
};

#endif /* HBL_IB_ABI_USER_H */
