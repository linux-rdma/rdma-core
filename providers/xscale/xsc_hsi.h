/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_HSI_H__
#define __XSC_HSI_H__

#include <linux/types.h>
#include <endian.h>

#include "util/util.h"
#include "xscale.h"

/* message opcode */
enum {
	XSC_MSG_OPCODE_SEND = 0,
	XSC_MSG_OPCODE_RDMA_WRITE = 1,
	XSC_MSG_OPCODE_RDMA_READ = 2,
	XSC_MSG_OPCODE_MAD = 3,
	XSC_MSG_OPCODE_RDMA_ACK = 4,
	XSC_MSG_OPCODE_RDMA_ACK_READ = 5,
	XSC_MSG_OPCODE_RDMA_CNP = 6,
	XSC_MSG_OPCODE_RAW = 7,
	XSC_MSG_OPCODE_VIRTIO_NET = 8,
	XSC_MSG_OPCODE_VIRTIO_BLK = 9,
	XSC_MSG_OPCODE_RAW_TPE = 10,
	XSC_MSG_OPCODE_INIT_QP_REQ = 11,
	XSC_MSG_OPCODE_INIT_QP_RSP = 12,
	XSC_MSG_OPCODE_INIT_PATH_REQ = 13,
	XSC_MSG_OPCODE_INIT_PATH_RSP = 14,
};

enum {
	XSC_REQ = 0,
	XSC_RSP = 1,
};

enum {
	XSC_WITHOUT_IMMDT = 0,
	XSC_WITH_IMMDT = 1,
};

enum {
	XSC_ERR_CODE_NAK_RETRY = 0x40,
	XSC_ERR_CODE_NAK_OPCODE = 0x41,
	XSC_ERR_CODE_NAK_MR = 0x42,
	XSC_ERR_CODE_NAK_OPERATION = 0x43,
	XSC_ERR_CODE_NAK_RNR = 0x44,
	XSC_ERR_CODE_LOCAL_MR = 0x45,
	XSC_ERR_CODE_LOCAL_LEN = 0x46,
	XSC_ERR_CODE_LOCAL_OPCODE = 0x47,
	XSC_ERR_CODE_CQ_OVER_FLOW = 0x48,
	XSC_ERR_CODE_STRG_ACC_GEN_CQE = 0x4b,
	XSC_ERR_CODE_STRG_ACC = 0x4c,
	XSC_ERR_CODE_CQE_ACC = 0x4d,
	XSC_ERR_CODE_FLUSH = 0x4e,
	XSC_ERR_CODE_MALF_WQE_HOST = 0x50,
	XSC_ERR_CODE_MALF_WQE_INFO = 0x51,
	XSC_ERR_CODE_MR_NON_NAK = 0x52,
	XSC_ERR_CODE_OPCODE_GEN_CQE = 0x61,
	XSC_ERR_CODE_MANY_READ = 0x62,
	XSC_ERR_CODE_LEN_GEN_CQE = 0x63,
	XSC_ERR_CODE_MR = 0x65,
	XSC_ERR_CODE_MR_GEN_CQE = 0x66,
	XSC_ERR_CODE_OPERATION = 0x67,
	XSC_ERR_CODE_MALF_WQE_INFO_GEN_NAK = 0x68,
};

enum {
	XSC_OPCODE_RDMA_REQ_SEND = 0,
	XSC_OPCODE_RDMA_REQ_SEND_IMMDT = 1,
	XSC_OPCODE_RDMA_RSP_RECV = 2,
	XSC_OPCODE_RDMA_RSP_RECV_IMMDT = 3,
	XSC_OPCODE_RDMA_REQ_WRITE = 4,
	XSC_OPCODE_RDMA_REQ_WRITE_IMMDT = 5,
	XSC_OPCODE_RDMA_RSP_WRITE_IMMDT = 6,
	XSC_OPCODE_RDMA_REQ_READ = 7,
	XSC_OPCODE_RDMA_REQ_ERROR = 8,
	XSC_OPCODE_RDMA_RSP_ERROR = 9,
	XSC_OPCODE_RDMA_CQE_ERROR = 10,
};

enum {
	XSC_BASE_WQE_SHIFT = 4,
};

/*
 * Descriptors that are allocated by SW and accessed by HW, 32-byte aligned
 */
#define CTRL_SEG_WQE_HDR_MSG_OPCODE_MASK GENMASK(7, 0)
#define CTRL_SEG_WQE_HDR_WITH_IMMDT_MASK BIT(8)
#define CTRL_SEG_WQE_HDR_DS_NUM_MASK GENMASK(15, 11)
#define CTRL_SEG_WQE_HDR_WQE_ID_MASK GENMASK(31, 16)
#define CTRL_SEG_DATA0_SE_MASK BIT(0)
#define CTRL_SEG_DATA0_CE_MASK BIT(1)
#define CTRL_SEG_DATA0_IN_LINE_MASK BIT(2)

struct xsc_send_wqe_ctrl_seg {
	__le32 wqe_hdr;
	__le32 msg_len;
	__le32 opcode_data;
	__le32 data0;
};

#define DATA_SEG_DATA0_SEG_LEN_MASK GENMASK(31, 1)

struct xsc_wqe_data_seg {
	union {
		struct {
			__le32 data0;
			__le32 mkey;
			__le64 va;
		};
		struct {
			u8 in_line_data[16];
		};
	};
};

#define CQE_DATA0_MSG_OPCODE_ANDES_MASK	GENMASK(7, 0)
#define CQE_DATA0_ERROR_CODE_ANDES_MASK	GENMASK(6, 0)
#define CQE_DATA0_IS_ERR_MASK		BIT(7)
#define CQE_DATA0_QP_ID_MASK		GENMASK(22, 8)
#define CQE_DATA0_SE_MASK		BIT(24)
#define CQE_DATA0_HAS_PPH_MASK		BIT(25)
#define CQE_DATA0_TYPE_MASK		BIT(26)
#define CQE_DATA0_WITH_IMMDT_MASK	BIT(27)
#define CQE_DATA0_CSUM_ERR_MASK		GENMASK(31, 28)
#define CQE_DATA1_TS_MASK		GENMASK_ULL(47, 0)
#define CQE_DATA1_WQE_ID_MASK		GENMASK_ULL(63, 48)
#define CQE_DATA2_OWNER_MASK		BIT(31)

struct xsc_cqe {
	__le32 data0;
	__le32 imm_data;
	__le32 msg_len;
	__le32 vni;
	__le64 data1;
	__le32 rsv;
	__le32 data2;
};

#define ANDES_SEND_DB_NEXT_PID_MASK	GENMASK(15, 0)
#define ANDES_SEND_DB_QP_ID_MASK	GENMASK(30, 16)
#define ANDES_RECV_DB_NEXT_PID_MASK	GENMASK(12, 0)
#define ANDES_RECV_DB_QP_ID_MASK	GENMASK(27, 13)
#define ANDES_CQ_DB_NEXT_CID_MASK	GENMASK(15, 0)
#define ANDES_CQ_DB_CQ_ID_MASK		GENMASK(30, 16)
#define ANDES_CQ_DB_ARM_MASK		BIT(31)

struct xsc_hw_ops {
	void (*ring_tx_doorbell)(void *db, u32 sqn, u32 next_pid);
	void (*ring_rx_doorbell)(void *db, u32 rqn, u32 next_pid);
	void (*update_cq_db)(void *db, u32 cqn, u32 next_cid,
			     u8 solicited);
	void (*set_cq_ci)(void *db, u32 cqn, u32 next_cid);
	bool (*is_err_cqe)(struct xsc_cqe *cqe);
	u8 (*get_cqe_error_code)(struct xsc_cqe *cqe);
	u8 (*get_cqe_msg_opcode)(struct xsc_cqe *cqe);
};

/* Size of CQE */
#define XSC_CQE_SIZE sizeof(struct xsc_cqe)

#define XSC_SEND_WQE_RING_DEPTH_MIN 16
#define XSC_CQE_RING_DEPTH_MIN 2

void xsc_init_hw_ops(struct xsc_context *ctx);
static inline bool xsc_get_cqe_sw_own(struct xsc_cqe *cqe, int cid,
				      int ring_sz) ALWAYS_INLINE;

static inline bool xsc_get_cqe_sw_own(struct xsc_cqe *cqe, int cid, int ring_sz)
{
	return FIELD_GET(CQE_DATA2_OWNER_MASK, le32toh(cqe->data2)) == ((cid >> ring_sz) & 1);
}
#endif /* __XSC_HSI_H__ */
