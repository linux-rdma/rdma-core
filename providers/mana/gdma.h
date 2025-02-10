/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2024, Microsoft Corporation. All rights reserved.
 */
#ifndef _GDMA_H_
#define _GDMA_H_

#include <stdio.h>
#include <linux/types.h>
#include <endian.h>
#include <infiniband/verbs.h>
#include <sys/mman.h>
#include <util/util.h>

#define GDMA_QUEUE_OFFSET_WIDTH 27
#define GDMA_QUEUE_OFFSET_MASK ((1 << GDMA_QUEUE_OFFSET_WIDTH) - 1)

#define GDMA_COMP_DATA_SIZE 60

#define IB_SYNDROME_ACK(credits) (0x00 + (credits))
#define IB_SYNDROME_RNR_NAK(timer) (0x20 + (timer))
#define IB_SYNDROME_NAK(code) (0x60 + (code))
#define IB_IS_ACK(syndrome) (((syndrome) & 0xE0) == IB_SYNDROME_ACK(0))

enum gdma_work_req_flags {
	GDMA_WORK_REQ_NONE = 0,
	GDMA_WORK_REQ_OOB_IN_SGL = BIT(0),
	GDMA_WORK_REQ_SGL_DIRECT = BIT(1),
	GDMA_WORK_REQ_CONSUME_CREDIT = BIT(2),
	GDMA_WORK_REQ_FENCE = BIT(3),
	GDMA_WORK_REQ_CHECK_SN = BIT(4),
	GDMA_WORK_REQ_PAD_DATA_BY_FIRST_SGE_SIZE = BIT(5),
	GDMA_WORK_REQ_EXTRA_LARGE_OOB = BIT(5),
};

union gdma_oob {
	struct {
		uint32_t num_padding_sgls:5;
		uint32_t reserved1:19;
		uint32_t last_vbytes:8;
		uint32_t num_sgl_entries:8;
		uint32_t inline_client_oob_size:3;
		uint32_t client_oob_in_sgl:1;
		uint32_t consume_credit:1;
		uint32_t fence:1;
		uint32_t reserved2:2;
		uint32_t client_data_unit:14;
		uint32_t check_sn:1;
		uint32_t sgl_direct:1;
	} tx;
	struct {
		uint32_t reserved1;
		uint32_t num_sgl_entries:8;
		uint32_t inline_client_oob_size:3;
		uint32_t reserved2:19;
		uint32_t check_sn:1;
		uint32_t reserved3:1;
	} rx;
}; /* HW DATA */

/* The 16-byte struct is part of the GDMA work queue entry (WQE). */
struct gdma_sge {
	uint64_t address;
	uint32_t mem_key;
	uint32_t size;
}; /* HW DATA */

struct rdma_recv_oob {
	uint32_t psn_start:24;
	uint32_t reserved1:8;
	uint32_t psn_range:24;
	uint32_t reserved2:8;
}; /* HW DATA */

struct extra_large_wqe {
	__le32 immediate;
	uint32_t reserved;
	uint64_t padding;
}; /* HW DATA */

struct rdma_send_oob {
	uint32_t wqe_type:5;
	uint32_t fence:1;
	uint32_t signaled:1;
	uint32_t solicited:1;
	uint32_t psn:24;

	uint32_t ssn:24; // also remote_qpn
	uint32_t reserved1:8;
	union {
		uint32_t req_details[4];
		union {
			__le32 immediate;
			uint32_t invalidate_key;
		} send;
		struct {
			uint32_t address_hi;
			uint32_t address_low;
			uint32_t rkey;
			uint32_t dma_len;
		} rdma;
	};
}; /* HW DATA */

struct gdma_wqe {
	// in units of 32-byte blocks, masked by GDMA_QUEUE_OFFSET_MASK.
	uint32_t unmasked_wqe_index;
	uint32_t size_in_bu;

	// Client oob is either 8 bytes or 24 bytes, so DmaOob + ClientOob will never wrap.
	union gdma_oob *gdma_oob;
	void *client_oob;
	uint32_t client_oob_size;

	struct gdma_sge *sgl1;
	uint32_t num_sge1;
	// In case SGL wraps in the queue buffer.
	struct gdma_sge *sgl2;
	uint32_t num_sge2;
};

enum wqe_opcode_types {
	WQE_TYPE_UD_SEND = 0,
	WQE_TYPE_UD_SEND_IMM = 1,
	WQE_TYPE_RC_SEND = 2,
	WQE_TYPE_RC_SEND_IMM = 3,
	WQE_TYPE_RC_SEND_INV = 4,
	WQE_TYPE_WRITE = 5,
	WQE_TYPE_WRITE_IMM = 6,
	WQE_TYPE_READ = 7,
	WQE_TYPE_UD_RECV = 8,
	WQE_TYPE_RC_RECV = 9,
	WQE_TYPE_LOCAL_INV = 10,
	WQE_TYPE_REG_MR = 11,
	WQE_TYPE_MAX,
}; /* HW DATA */

static inline enum wqe_opcode_types
	convert_wr_to_hw_opcode(enum ibv_wr_opcode opcode)
{
	switch (opcode) {
	case IBV_WR_RDMA_WRITE:
		return WQE_TYPE_WRITE;
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		return WQE_TYPE_WRITE_IMM;
	case IBV_WR_SEND:
		return WQE_TYPE_RC_SEND;
	case IBV_WR_SEND_WITH_IMM:
		return WQE_TYPE_RC_SEND_IMM;
	case IBV_WR_RDMA_READ:
		return WQE_TYPE_READ;
	default:
		return WQE_TYPE_MAX;
	}
}

enum {
	CQE_TYPE_NOP = 0,
	CQE_TYPE_UD_SEND = 1,
	CQE_TYPE_UD_SEND_IMM = 2,
	CQE_TYPE_RC_SEND = 3,
	CQE_TYPE_RC_SEND_IMM = 4,
	CQE_TYPE_RC_SEND_INV = 5,
	CQE_TYPE_RC_WRITE_IMM = 6,
	CQE_TYPE_ARMED_CMPL = 7,
	CQE_TYPE_LWR = 8,
	CQE_TYPE_ERROR = 34,
}; /* HW DATA */

union mana_rdma_cqe {
	struct {
		uint8_t cqe_type;
		uint8_t data[GDMA_COMP_DATA_SIZE - 1];
	};
	struct {
		uint32_t cqe_type	: 8;
		uint32_t reserved1	: 24;
		uint32_t msg_len;
		uint32_t psn		: 24;
		uint32_t reserved2	: 8;
		uint32_t imm_data;
		uint32_t rx_wqe_offset;
	} rc_recv;
	struct {
		uint32_t cqe_type	: 8;
		uint32_t vendor_error	: 9;
		uint32_t reserved1	: 15;
		uint32_t sge_offset	: 5;
		uint32_t tx_wqe_offset	: 27;
	} ud_send;
	struct {
		uint32_t cqe_type	: 8;
		uint32_t reserved1	: 24;
		uint32_t msg_len;
		uint32_t src_qpn	: 24;
		uint32_t reserved2	: 8;
		uint32_t imm_data;
		uint32_t rx_wqe_offset;
	} ud_recv;
	struct {
		uint32_t cqe_type	: 8;
		uint32_t vendor_error	: 10;
		uint32_t reserved1	: 14;
		uint32_t msn		: 24;
		uint32_t syndrome	: 8;
		uint32_t psn		: 24;
		uint32_t opcode		: 8;
		uint32_t rsp_msn	: 24;
		uint32_t reserved2	: 8;
		uint32_t rsp_psn	: 24;
		uint32_t reserved3	: 8;
	} error;
	struct {
		uint32_t cqe_type	: 8;
		uint32_t reserved1	: 24;
		uint32_t msn		: 24;
		uint32_t syndrome	: 8;
		uint32_t psn		: 24;
		uint32_t reserved2	: 8;
	} rc_armed_completion;
}; /* HW DATA */
static_assert(sizeof(union mana_rdma_cqe) == GDMA_COMP_DATA_SIZE, "bad size");

struct gdma_cqe {
	union mana_rdma_cqe rdma_cqe;
	uint32_t wqid	: 24;
	uint32_t is_sq	: 1;
	uint32_t reserved	: 4;
	uint32_t owner_bits	: 3;
}; /* HW DATA */

enum mana_error_code {
	VENDOR_ERR_OK					= 0x0,
	VENDOR_ERR_RX_OP_REQ                            = 0x03,
	VENDOR_ERR_RX_PKT_LEN                           = 0x05,
	VENDOR_ERR_RX_ATB_RKEY_MISCONFIG_ERR            = 0x43,
	VENDOR_ERR_RX_ATB_RKEY_ADDR_RIGHT               = 0x83,
	VENDOR_ERR_RX_ATB_RKEY_ADDR_RANGE               = 0xc3,
	VENDOR_ERR_RX_MSG_LEN_OVFL                      = 0x102,
	VENDOR_ERR_RX_MISBEHAVING_CLIENT                = 0x108,
	VENDOR_ERR_RX_MALFORMED_WQE                     = 0x109,
	VENDOR_ERR_RX_CLIENT_ID                         = 0x10a,
	VENDOR_ERR_RX_GFID                              = 0x10b,
	VENDOR_ERR_RX_READRESP_LEN_MISMATCH             = 0x10f,
	VENDOR_ERR_RX_PCIE                              = 0x10c,
	VENDOR_ERR_RX_NO_AVAIL_WQE                      = 0x111,
	VENDOR_ERR_RX_ATB_SGE_MISSCONFIG                = 0x143,
	VENDOR_ERR_RX_ATB_WQE_MISCONFIG                 = 0x145,
	VENDOR_ERR_RX_INVALID_REQ_NAK			= 0x161,
	VENDOR_ERR_RX_REMOTE_ACCESS_NAK			= 0x162,
	VENDOR_ERR_RX_REMOTE_OP_ERR_NAK			= 0x163,
	VENDOR_ERR_RX_ATB_SGE_ADDR_RIGHT                = 0x183,
	VENDOR_ERR_RX_ATB_WQE_ADDR_RIGHT                = 0x185,
	VENDOR_ERR_RX_ATB_SGE_ADDR_RANGE                = 0x1c3,
	VENDOR_ERR_RX_ATB_WQE_ADDR_RANGE                = 0x1c5,
	VENDOR_ERR_RX_NOT_EMPTY_ON_DISABLE              = 0x1c7,
	VENDOR_ERR_TX_GDMA_CORRUPTED_WQE                = 0x201,
	VENDOR_ERR_TX_ATB_WQE_ACCESS_VIOLATION          = 0x202,
	VENDOR_ERR_TX_ATB_WQE_ADDR_RANGE                = 0x203,
	VENDOR_ERR_TX_ATB_WQE_CONFIG_ERR                = 0x204,
	VENDOR_ERR_TX_PCIE_WQE                          = 0x205,
	VENDOR_ERR_TX_ATB_MSG_ACCESS_VIOLATION          = 0x206,
	VENDOR_ERR_TX_ATB_MSG_ADDR_RANGE                = 0x207,
	VENDOR_ERR_TX_ATB_MSG_CONFIG_ERR                = 0x208,
	VENDOR_ERR_TX_PCIE_MSG                          = 0x209,
	VENDOR_ERR_TX_GDMA_INVALID_STATE                = 0x20a,
	VENDOR_ERR_TX_MISBEHAVING_CLIENT                = 0x20b,
	VENDOR_ERR_TX_RDMA_MALFORMED_WQE_SIZE           = 0x210,
	VENDOR_ERR_TX_RDMA_MALFORMED_WQE_FIELD          = 0x211,
	VENDOR_ERR_TX_RDMA_INVALID_STATE                = 0x212,
	VENDOR_ERR_TX_RDMA_INVALID_NPT                  = 0x213,
	VENDOR_ERR_TX_RDMA_INVALID_SGID                 = 0x214,
	VENDOR_ERR_TX_RDMA_WQE_UNSUPPORTED              = 0x215,
	VENDOR_ERR_TX_RDMA_WQE_LEN_ERR                  = 0x216,
	VENDOR_ERR_TX_RDMA_MTU_ERR                      = 0x217,
	VENDOR_ERR_TX_RDMA_VFID_MISMATCH                = 0x218,
	VENDOR_ERR_TX_RDMA_ATB_CMD_MISS                 = 0x220,
	VENDOR_ERR_TX_RDMA_ATB_CMD_IDX_ERROR            = 0x221,
	VENDOR_ERR_TX_RDMA_ATB_CMD_TAG_MISMATCH_ERROR   = 0x222,
	VENDOR_ERR_TX_RDMA_ATB_CMD_PDID_MISMATCH_ERROR  = 0x223,
	VENDOR_ERR_TX_RDMA_ATB_CMD_AR_ERROR             = 0x224,
	VENDOR_ERR_TX_RDMA_ATB_CMD_PT_OVF               = 0x225,
	VENDOR_ERR_TX_RDMA_ATB_CMD_PT_LENGHT_MISMATCH   = 0x226,
	VENDOR_ERR_TX_RDMA_ATB_CMD_ILLEGAL_CMD          = 0x227,
	VENDOR_ERR_HW_MAX                               = 0x3ff,
	/* SW vendor errors */
	VENDOR_ERR_SW_FLUSHED				= 0xfff,
};

#endif //_GDMA_H_
