/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * Copyright (c) 2017-2018, Mellanox Technologies inc.  All rights reserved.
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

#ifndef IB_USER_IOCTL_VERBS_H
#define IB_USER_IOCTL_VERBS_H

#include <linux/types.h>
#include <rdma/ib_user_verbs.h>

#ifndef RDMA_UAPI_PTR
#define RDMA_UAPI_PTR(_type, _name)	__aligned_u64 _name
#endif

#define IB_UVERBS_ACCESS_OPTIONAL_FIRST (1 << 20)
#define IB_UVERBS_ACCESS_OPTIONAL_LAST (1 << 29)

enum ib_uverbs_core_support {
	IB_UVERBS_CORE_SUPPORT_OPTIONAL_MR_ACCESS = 1 << 0,
	IB_UVERBS_CORE_SUPPORT_ROBUST_UDATA = 1 << 1,
};

enum ib_uverbs_access_flags {
	IB_UVERBS_ACCESS_LOCAL_WRITE = 1 << 0,
	IB_UVERBS_ACCESS_REMOTE_WRITE = 1 << 1,
	IB_UVERBS_ACCESS_REMOTE_READ = 1 << 2,
	IB_UVERBS_ACCESS_REMOTE_ATOMIC = 1 << 3,
	IB_UVERBS_ACCESS_MW_BIND = 1 << 4,
	IB_UVERBS_ACCESS_ZERO_BASED = 1 << 5,
	IB_UVERBS_ACCESS_ON_DEMAND = 1 << 6,
	IB_UVERBS_ACCESS_HUGETLB = 1 << 7,
	IB_UVERBS_ACCESS_FLUSH_GLOBAL = 1 << 8,
	IB_UVERBS_ACCESS_FLUSH_PERSISTENT = 1 << 9,

	IB_UVERBS_ACCESS_RELAXED_ORDERING = IB_UVERBS_ACCESS_OPTIONAL_FIRST,
	IB_UVERBS_ACCESS_OPTIONAL_RANGE =
		((IB_UVERBS_ACCESS_OPTIONAL_LAST << 1) - 1) &
		~(IB_UVERBS_ACCESS_OPTIONAL_FIRST - 1)
};

enum ib_uverbs_srq_type {
	IB_UVERBS_SRQT_BASIC,
	IB_UVERBS_SRQT_XRC,
	IB_UVERBS_SRQT_TM,
};

enum ib_uverbs_wq_type {
	IB_UVERBS_WQT_RQ,
};

enum ib_uverbs_wq_flags {
	IB_UVERBS_WQ_FLAGS_CVLAN_STRIPPING = 1 << 0,
	IB_UVERBS_WQ_FLAGS_SCATTER_FCS = 1 << 1,
	IB_UVERBS_WQ_FLAGS_DELAY_DROP = 1 << 2,
	IB_UVERBS_WQ_FLAGS_PCI_WRITE_END_PADDING = 1 << 3,
};

enum ib_uverbs_qp_type {
	IB_UVERBS_QPT_RC = 2,
	IB_UVERBS_QPT_UC,
	IB_UVERBS_QPT_UD,
	IB_UVERBS_QPT_RAW_PACKET = 8,
	IB_UVERBS_QPT_XRC_INI,
	IB_UVERBS_QPT_XRC_TGT,
	IB_UVERBS_QPT_RU,
	IB_UVERBS_QPT_DRIVER = 0xFF,
};

enum ib_uverbs_qp_create_flags {
	IB_UVERBS_QP_CREATE_BLOCK_MULTICAST_LOOPBACK = 1 << 1,
	IB_UVERBS_QP_CREATE_SCATTER_FCS = 1 << 8,
	IB_UVERBS_QP_CREATE_CVLAN_STRIPPING = 1 << 9,
	IB_UVERBS_QP_CREATE_PCI_WRITE_END_PADDING = 1 << 11,
	IB_UVERBS_QP_CREATE_SQ_SIG_ALL = 1 << 12,
};

enum ib_uverbs_query_port_cap_flags {
	IB_UVERBS_PCF_SM = 1 << 1,
	IB_UVERBS_PCF_NOTICE_SUP = 1 << 2,
	IB_UVERBS_PCF_TRAP_SUP = 1 << 3,
	IB_UVERBS_PCF_OPT_IPD_SUP = 1 << 4,
	IB_UVERBS_PCF_AUTO_MIGR_SUP = 1 << 5,
	IB_UVERBS_PCF_SL_MAP_SUP = 1 << 6,
	IB_UVERBS_PCF_MKEY_NVRAM = 1 << 7,
	IB_UVERBS_PCF_PKEY_NVRAM = 1 << 8,
	IB_UVERBS_PCF_LED_INFO_SUP = 1 << 9,
	IB_UVERBS_PCF_SM_DISABLED = 1 << 10,
	IB_UVERBS_PCF_SYS_IMAGE_GUID_SUP = 1 << 11,
	IB_UVERBS_PCF_PKEY_SW_EXT_PORT_TRAP_SUP = 1 << 12,
	IB_UVERBS_PCF_EXTENDED_SPEEDS_SUP = 1 << 14,
	IB_UVERBS_PCF_CM_SUP = 1 << 16,
	IB_UVERBS_PCF_SNMP_TUNNEL_SUP = 1 << 17,
	IB_UVERBS_PCF_REINIT_SUP = 1 << 18,
	IB_UVERBS_PCF_DEVICE_MGMT_SUP = 1 << 19,
	IB_UVERBS_PCF_VENDOR_CLASS_SUP = 1 << 20,
	IB_UVERBS_PCF_DR_NOTICE_SUP = 1 << 21,
	IB_UVERBS_PCF_CAP_MASK_NOTICE_SUP = 1 << 22,
	IB_UVERBS_PCF_BOOT_MGMT_SUP = 1 << 23,
	IB_UVERBS_PCF_LINK_LATENCY_SUP = 1 << 24,
	IB_UVERBS_PCF_CLIENT_REG_SUP = 1 << 25,
	/*
	 * IsOtherLocalChangesNoticeSupported is aliased by IP_BASED_GIDS and
	 * is inaccessible
	 */
	IB_UVERBS_PCF_LINK_SPEED_WIDTH_TABLE_SUP = 1 << 27,
	IB_UVERBS_PCF_VENDOR_SPECIFIC_MADS_TABLE_SUP = 1 << 28,
	IB_UVERBS_PCF_MCAST_PKEY_TRAP_SUPPRESSION_SUP = 1 << 29,
	IB_UVERBS_PCF_MCAST_FDB_TOP_SUP = 1 << 30,
	IB_UVERBS_PCF_HIERARCHY_INFO_SUP = 1ULL << 31,

	/* NOTE this is an internal flag, not an IBA flag */
	IB_UVERBS_PCF_IP_BASED_GIDS = 1 << 26,
};

enum ib_uverbs_query_port_flags {
	IB_UVERBS_QPF_GRH_REQUIRED = 1 << 0,
};

enum ib_uverbs_flow_action_esp_keymat {
	IB_UVERBS_FLOW_ACTION_ESP_KEYMAT_AES_GCM,
};

enum ib_uverbs_flow_action_esp_keymat_aes_gcm_iv_algo {
	IB_UVERBS_FLOW_ACTION_IV_ALGO_SEQ,
};

struct ib_uverbs_flow_action_esp_keymat_aes_gcm {
	__aligned_u64	iv;
	__u32		iv_algo; /* Use enum ib_uverbs_flow_action_esp_keymat_aes_gcm_iv_algo */

	__u32		salt;
	__u32		icv_len;

	__u32		key_len;
	__u32		aes_key[256 / 32];
};

enum ib_uverbs_flow_action_esp_replay {
	IB_UVERBS_FLOW_ACTION_ESP_REPLAY_NONE,
	IB_UVERBS_FLOW_ACTION_ESP_REPLAY_BMP,
};

struct ib_uverbs_flow_action_esp_replay_bmp {
	__u32	size;
};

enum ib_uverbs_flow_action_esp_flags {
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_INLINE_CRYPTO	= 0UL << 0,	/* Default */
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_FULL_OFFLOAD	= 1UL << 0,

	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_TUNNEL		= 0UL << 1,	/* Default */
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_TRANSPORT	= 1UL << 1,

	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_DECRYPT		= 0UL << 2,	/* Default */
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_ENCRYPT		= 1UL << 2,

	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_ESN_NEW_WINDOW	= 1UL << 3,
};

struct ib_uverbs_flow_action_esp_encap {
	/* This struct represents a list of pointers to flow_xxxx_filter that
	 * encapsulates the payload in ESP tunnel mode.
	 */
	RDMA_UAPI_PTR(void *, val_ptr); /* pointer to a flow_xxxx_filter */
	RDMA_UAPI_PTR(struct ib_uverbs_flow_action_esp_encap *, next_ptr);
	__u16	len;		/* Len of the filter struct val_ptr points to */
	__u16	type;		/* Use flow_spec_type enum */
};

struct ib_uverbs_flow_action_esp {
	__u32		spi;
	__u32		seq;
	__u32		tfc_pad;
	__u32		flags;
	__aligned_u64	hard_limit_pkts;
};

enum ib_uverbs_read_counters_flags {
	/* prefer read values from driver cache */
	IB_UVERBS_READ_COUNTERS_PREFER_CACHED = 1 << 0,
};

enum ib_uverbs_advise_mr_advice {
	IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH,
	IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE,
	IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_NO_FAULT,
};

enum ib_uverbs_advise_mr_flag {
	IB_UVERBS_ADVISE_MR_FLAG_FLUSH = 1 << 0,
};

struct ib_uverbs_query_port_resp_ex {
	struct ib_uverbs_query_port_resp legacy_resp;
	__u16 port_cap_flags2;
	__u8  reserved[2];
	__u32 active_speed_ex;
};

struct ib_uverbs_qp_cap {
	__u32 max_send_wr;
	__u32 max_recv_wr;
	__u32 max_send_sge;
	__u32 max_recv_sge;
	__u32 max_inline_data;
};

enum rdma_driver_id {
	RDMA_DRIVER_UNKNOWN,
	RDMA_DRIVER_MLX5,
	RDMA_DRIVER_MLX4,
	RDMA_DRIVER_CXGB3,
	RDMA_DRIVER_CXGB4,
	RDMA_DRIVER_MTHCA,
	RDMA_DRIVER_BNXT_RE,
	RDMA_DRIVER_OCRDMA,
	RDMA_DRIVER_NES,
	RDMA_DRIVER_I40IW,
	RDMA_DRIVER_IRDMA = RDMA_DRIVER_I40IW,
	RDMA_DRIVER_VMW_PVRDMA,
	RDMA_DRIVER_QEDR,
	RDMA_DRIVER_HNS,
	RDMA_DRIVER_USNIC,
	RDMA_DRIVER_RXE,
	RDMA_DRIVER_HFI1,
	RDMA_DRIVER_QIB,
	RDMA_DRIVER_EFA,
	RDMA_DRIVER_SIW,
	RDMA_DRIVER_ERDMA,
	RDMA_DRIVER_MANA,
	RDMA_DRIVER_IONIC,
};

enum ib_uverbs_gid_type {
	IB_UVERBS_GID_TYPE_IB,
	IB_UVERBS_GID_TYPE_ROCE_V1,
	IB_UVERBS_GID_TYPE_ROCE_V2,
	IB_UVERBS_GID_TYPE_UET_UDP,
	IB_UVERBS_GID_TYPE_UET_IP,
};

struct ib_uverbs_gid_entry {
	__aligned_u64 gid[2];
	__u32 gid_index;
	__u32 port_num;
	__u32 gid_type;
	__u32 netdev_ifindex; /* It is 0 if there is no netdev associated with it */
};

enum ib_uverbs_buffer_type {
	IB_UVERBS_BUFFER_TYPE_DMABUF,
	IB_UVERBS_BUFFER_TYPE_VA,
};

/*
 * Describes a single buffer backed by dma-buf or user virtual address.
 * Used as the payload of a per-attribute UVERBS_ATTR_UMEM-typed attribute.
 *
 * @type: buffer type from enum ib_uverbs_buffer_type
 * @fd: dma-buf file descriptor (valid for IB_UVERBS_BUFFER_TYPE_DMABUF)
 * @flags: required flags; the kernel rejects the call with -EINVAL if any
 *         bit is not understood. No bits are defined yet.
 * @optional_flags: advisory flags; bits the kernel does not understand are
 *                  silently ignored. No bits are defined yet.
 * @addr: offset within dma-buf, or user virtual address for VA
 * @length: buffer length in bytes
 */
struct ib_uverbs_buffer_desc {
	__u32 type;
	__s32 fd;
	__u32 flags;
	__u32 optional_flags;
	__aligned_u64 addr;
	__aligned_u64 length;
};

/* Extended memory registration, for devices whose memory keys are 64 bits
 * wide and may be bound to a job. See UVERBS_ATTR_REG_MR_FLAGS.
 */
enum ib_uverbs_reg_mr_flags {
	/* REQ_RKEY64 carries the key, rather than the device assigning one */
	IB_UVERBS_REG_MR_USER_RKEY		= 1 << 0,
	/* the region tolerates a replayed idempotent operation */
	IB_UVERBS_REG_MR_IDEMPOTENT_SAFE	= 1 << 1,
};

/* A UET reliable unconnected queue pair number uses all 32 bits:
 *
 *	[ absolute 1b | reserved 7b | resource index 12b | PIDonFEP 12b ]
 *
 * An absolute pair is named by its number alone. A relative one is named
 * within a job, so it must carry a job key when it is created. The reserved
 * bits are zero.
 */
#define IB_UVERBS_QPN_UET_PID_ON_FEP_MASK	0x00000fff
#define IB_UVERBS_QPN_UET_PID_ON_FEP_SHIFT	0
#define IB_UVERBS_QPN_UET_RI_MASK		0x00fff000
#define IB_UVERBS_QPN_UET_RI_SHIFT		12
#define IB_UVERBS_QPN_UET_RESERVED_MASK		0x7f000000
#define IB_UVERBS_QPN_UET_ABSOLUTE_ADDR_BIT	0x80000000

enum ib_uverbs_qp_semantics_mask {
	IB_UVERBS_QP_SEMANTICS_MASK_MSG_ORDER	= 1 << 0,
	IB_UVERBS_QP_SEMANTICS_MASK_RAW		= 1 << 1,
	IB_UVERBS_QP_SEMANTICS_MASK_WAR		= 1 << 2,
	IB_UVERBS_QP_SEMANTICS_MASK_WAW		= 1 << 3,
	IB_UVERBS_QP_SEMANTICS_MASK_PDU		= 1 << 4,
	IB_UVERBS_QP_SEMANTICS_MASK_IMM		= 1 << 5,
	IB_UVERBS_QP_SEMANTICS_MASK_USAGE	= 1 << 6,
};

/* Ordering guarantees between operations on one QP. "X after Y" means an
 * X may not pass a Y posted before it. A bit that is clear means the pair
 * does not order that combination, and an application that needs it must
 * wait for the earlier completion.
 */
enum ib_uverbs_qp_msg_order {
	/* atomic after atomic */
	IB_UVERBS_QP_ORDER_ATOMIC_RAR	= 1 << 0,
	IB_UVERBS_QP_ORDER_ATOMIC_RAW	= 1 << 1,
	IB_UVERBS_QP_ORDER_ATOMIC_WAR	= 1 << 2,
	IB_UVERBS_QP_ORDER_ATOMIC_WAW	= 1 << 3,
	/* rma after rma */
	IB_UVERBS_QP_ORDER_RDMA_RAR	= 1 << 4,
	IB_UVERBS_QP_ORDER_RDMA_RAW	= 1 << 5,
	IB_UVERBS_QP_ORDER_RDMA_WAR	= 1 << 6,
	IB_UVERBS_QP_ORDER_RDMA_WAW	= 1 << 7,
	/* send against atomic and rma */
	IB_UVERBS_QP_ORDER_RAS		= 1 << 8,
	IB_UVERBS_QP_ORDER_SAR		= 1 << 9,
	IB_UVERBS_QP_ORDER_SAS		= 1 << 10,
	IB_UVERBS_QP_ORDER_SAW		= 1 << 11,
	IB_UVERBS_QP_ORDER_WAS		= 1 << 12,
	/* rma and atomic, either kind, against each other */
	IB_UVERBS_QP_ORDER_RAR		= 1 << 13,
	IB_UVERBS_QP_ORDER_RAW		= 1 << 14,
	IB_UVERBS_QP_ORDER_WAR		= 1 << 15,
	IB_UVERBS_QP_ORDER_WAW		= 1 << 16,
};

enum ib_uverbs_qp_usage_flags {
	/* immediate data consumes a posted receive */
	IB_UVERBS_QP_USAGE_IMM_DATA_RQ	= 1 << 0,
};

/* An address handle that names a peer using both transport+network addresses.
 * Used for reliable unconnected QPs in both work request address handles and
 * a Job address table.
 */
struct ib_uverbs_ah_attr_ex {
	struct ib_uverbs_ah_attr ah_attr;
	__u32 remote_qpn;
};

struct ib_uverbs_qp_semantics {
	__u32 comp_mask;		/* enum ib_uverbs_qp_semantics_mask */
	__u32 msg_order;		/* enum ib_uverbs_qp_msg_order */
	/*
	 * Data ordering: the largest transfer, in bytes, for which the target
	 * memory reflects the order of the pair under its RDMA_ and plain
	 * msg_order bits. 0 if not provided, and those bits are then clear.
	 * There is no read-after-read size, as two reads leave memory
	 * unchanged.
	 */
	__u32 max_rdma_raw_size;	/* read after write */
	__u32 max_rdma_war_size;	/* write after read */
	__u32 max_rdma_waw_size;	/* write after write */
	__u32 max_pdu;			/* largest packet, bytes */
	__u32 usage_flags;		/* enum ib_uverbs_qp_usage_flags */
	__u8  imm_data_size;		/* widest immediate, in bits */
	__u8  reserved[3];
};

enum ib_uverbs_comp_cntr_entry {
	IB_UVERBS_COMP_CNTR_ENTRY_COMP,
	IB_UVERBS_COMP_CNTR_ENTRY_ERR,
};

enum ib_uverbs_comp_cntr_modify_op {
	IB_UVERBS_COMP_CNTR_MODIFY_OP_SET,
	IB_UVERBS_COMP_CNTR_MODIFY_OP_INC,
};

enum ib_uverbs_qp_attach_comp_cntr_op {
	IB_UVERBS_QP_ATTACH_COMP_CNTR_OP_SEND = 1 << 0,
	IB_UVERBS_QP_ATTACH_COMP_CNTR_OP_RECV = 1 << 1,
	IB_UVERBS_QP_ATTACH_COMP_CNTR_OP_RDMA_READ = 1 << 2,
	IB_UVERBS_QP_ATTACH_COMP_CNTR_OP_REMOTE_RDMA_READ = 1 << 3,
	IB_UVERBS_QP_ATTACH_COMP_CNTR_OP_RDMA_WRITE = 1 << 4,
	IB_UVERBS_QP_ATTACH_COMP_CNTR_OP_REMOTE_RDMA_WRITE = 1 << 5,
};

#endif
