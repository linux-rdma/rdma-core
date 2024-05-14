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
	CQE_TYPE_RC_FENCE = 9,
	CQE_TYPE_MAX
}; /* HW DATA */

struct mana_rdma_cqe {
	uint32_t cqe_type	: 8;
	uint32_t vendor_error	: 8;
	uint32_t reserved1	: 16;
	union {
		uint32_t data[GDMA_COMP_DATA_SIZE / sizeof(uint32_t) - 4];
		struct {
			uint32_t msg_len;
			uint32_t psn	: 24;
			uint32_t reserved	: 8;
			uint32_t imm_data;
			uint32_t rx_wqe_offset;
		} rc_recv;
		struct {
			uint32_t sge_offset	: 5;
			uint32_t rx_wqe_offset	: 27;
			uint32_t sge_byte_offset;
		} ud_send;
		struct {
			uint32_t msg_len;
			uint32_t src_qpn	: 24;
			uint32_t reserved	: 8;
			uint32_t imm_data;
			uint32_t rx_wqe_offset;
		} ud_recv;

		struct {
			uint32_t reserved1;
			uint32_t psn	: 24;
			uint32_t reserved2	: 8;
			uint32_t imm_data;
			uint32_t rx_wqe_offset;
		} rc_write_with_imm;
		struct {
			uint32_t msn	: 24;
			uint32_t syndrome	: 8;
			uint32_t psn	: 24;
			uint32_t reserved	: 8;
			uint32_t read_resp_psn	: 24;
		} rc_armed_completion;
	};
	uint32_t timestamp_hi;
	uint32_t timestamp_lo;
	uint32_t reserved3;
}; /* HW DATA */

struct gdma_cqe {
	union {
		uint8_t data[GDMA_COMP_DATA_SIZE];
		struct mana_rdma_cqe rdma_cqe;
	};
	uint32_t wqid	: 24;
	uint32_t is_sq	: 1;
	uint32_t reserved	: 4;
	uint32_t owner_bits	: 3;
}; /* HW DATA */

#endif //_GDMA_H_
