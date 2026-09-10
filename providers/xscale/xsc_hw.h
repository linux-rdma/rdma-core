// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */
#ifndef _XSC_HW_H_
#define _XSC_HW_H_

#include <util/mmio.h>
#include <util/util.h>
#include "xsc_hsi.h"

struct andes_send_wqe_ctrl_seg {
	uint8_t		msg_opcode;
	uint8_t		data0;
#define XSC_ANDES_WQE_CTRL_SEG_WITH_IMMDT_MASK		BIT(0)
#define XSC_ANDES_WQE_CTRL_SEG_CSUM_EN_MASK		GENMASK(1, 2)
#define XSC_ANDES_WQE_CTRL_SEG_DS_DATA_NUM_MASK		GENMASK(7, 3)
	__le16		wqe_id;
	__le32		msg_len;
	__le32		opcode_data;
	uint8_t		data1;
#define XSC_ANDES_WQE_CTRL_SEG_SE_MASK			BIT(0)
#define XSC_ANDES_WQE_CTRL_SEG_CE_MASK			BIT(1)
#define XSC_ANDES_WQE_CTRL_SEG_IN_LINE_MASK		BIT(2)
#define XSC_ANDES_WQE_CTRL_SEG_FENCE_MODE_MASK		GENMASK(4, 3)
#define XSC_ANDES_WQE_CTRL_SEG_MASK_MASK		GENMASK(6, 5)
	uint8_t		rsv[3];
};

struct xsc_andes_cqe {
	union {
		uint8_t		msg_opcode;
		uint8_t		data0;
#define XSC_ANDES_CQE_ERR_CODE_MASK			GENMASK(6, 0)
#define XSC_ANDES_CQE_IS_ERR_MASK			BIT(7)
	};
	__le32		data1;
#define XSC_ANDES_CQE_QP_ID_MASK			GENMASK(14, 0)
#define XSC_ANDES_CQE_SE_MASK				BIT(1)
#define XSC_ANDES_CQE_HAS_PPH_MASK			BIT(2)
#define XSC_ANDES_CQE_TYPE_MASK				BIT(3)
#define XSC_ANDES_CQE_WITH_IMMDT_MASK			BIT(4)
#define XSC_ANDES_CQE_CSUM_ERR_MASK			GENMASK(8, 5)
	__le32		imm_data;
	__le32		msg_len;
	__le32		vni;
	__le64		data2;
#define XSC_ANDES_CQE_TS_MASK				GENMASK_ULL(47, 0)
	__le16		wqe_id;
	__le16		rsv[3];
	__le16		data3;
#define XSC_ANDES_CQE_OWNER_MASK			BIT(15)
};

struct xsc_andes_cq_doorbell {
	__le32 raw;
#define XSC_ANDES_CQ_DOORBELL_CQ_NEXT_CID_MASK		GENMASK(15, 0)
#define XSC_ANDES_CQ_DOORBELL_CQ_ID_MASK		GENMASK(30, 16)
#define XSC_ANDES_CQ_DOORBELL_ARM_MASK			BIT(31)
};

struct xsc_andes_send_doorbell {
	__le32 raw;
#define XSC_ANDES_SEND_DOORBELL_NEXT_PID_MASK		GENMASK(15, 0)
#define XSC_ANDES_SEND_DOORBELL_QP_ID_MASK		GENMASK(30, 16)
};

struct xsc_andes_recv_doorbell {
	__le32 raw;
#define XSC_ANDES_RECV_DOORBELL_NEXT_PID_MASK		GENMASK(12, 0)
#define XSC_ANDES_RECV_DOORBELL_QP_ID_MASK		GENMASK(27, 13)
};

struct xsc_andes_data_seg {
	__le32 data0;
#define XSC_ANDES_DATA_SEG_LENGTH_MASK			GENMASK(31, 1)
	__le32 key;
	__le64 addr;
};

struct diamond_send_wqe_ctrl_seg {
	uint8_t		msg_opcode;
	uint8_t		data0;
#define XSC_DIAMOND_WQE_CTRL_SEG_WITH_IMMDT_MASK	BIT(0)
#define XSC_DIAMOND_WQE_CTRL_SEG_CSUM_EN_MASK		GENMASK(1, 2)
#define XSC_DIAMOND_WQE_CTRL_SEG_DS_DATA_NUM_MASK	GENMASK(7, 3)
	__le16		rsv1;
	__le32		msg_len;
	__le32		opcode_data;
	__le32		data1;
#define XSC_DIAMOND_WQE_CTRL_SEG_SE_MASK		BIT(0)
#define XSC_DIAMOND_WQE_CTRL_SEG_CE_MASK		BIT(1)
#define XSC_DIAMOND_WQE_CTRL_SEG_IN_LINE_MASK		BIT(2)
#define XSC_DIAMOND_WQE_CTRL_SEG_FENCE_MODE_MASK	GENMASK(4, 3)
#define XSC_DIAMOND_WQE_CTRL_SEG_MASK_MASK		GENMASK(6, 5)
#define XSC_DIAMOND_WQE_CTRL_SEG_WQE_ID_MASK		GENMASK(31, 12)
};

struct xsc_diamond_cqe {
	uint8_t		error_code;
	__le32		data0;
#define XSC_DIAMOND_CQE_QP_ID_MASK			GENMASK(14, 0)
#define XSC_DIAMOND_CQE_SE_MASK				BIT(16)
#define XSC_DIAMOND_CQE_HAS_PPH_MASK			BIT(17)
#define XSC_DIAMOND_CQE_TYPE_MASK			BIT(18)
#define XSC_DIAMOND_CQE_WITH_IMMDT_MASK			BIT(19)
#define XSC_DIAMOND_CQE_CSUM_ERR_MASK			GENMASK(23, 20)
	__le32		imm_data;
	__le32		msg_len;
	__le32		vni;
	__le64		data1;
#define XSC_DIAMOND_CQE_TS_MASK				GENMASK_ULL(47, 0)
	__le32		data2;
#define XSC_DIAMOND_CQE_MSG_OPCODE_MASK			GENMASK(7, 0)
#define XSC_DIAMOND_CQE_WQE_ID_MASK			GENMASK(31, 12)
	__le32		data3;
#define XSC_DIAMOND_CQE_OWNER_MASK			BIT(31)
};

struct xsc_diamond_cq_doorbell {
	__le64 raw;
#define XSC_DIAMOND_CQ_DOORBELL_CQ_NEXT_CID_MASK	GENMASK_ULL(22, 0)
#define XSC_DIAMOND_CQ_DOORBELL_CQ_ID_MASK		GENMASK_ULL(38, 23)
#define XSC_DIAMOND_CQ_DOORBELL_CQ_STA_MASK		GENMASK_ULL(40, 39)
};

struct xsc_diamond_recv_doorbell {
	__le64 raw;
#define XSC_DIAMOND_RECV_DOORBELL_NEXT_PID_MASK		GENMASK_ULL(17, 0)
#define XSC_DIAMOND_RECV_DOORBELL_QP_ID_MASK		GENMASK_ULL(33, 18)
};

struct xsc_diamond_send_doorbell {
	__le64 raw;
#define XSC_DIAMOND_SEND_DOORBELL_NEXT_PID_MASK		GENMASK_ULL(20, 0)
#define XSC_DIAMOND_SEND_DOORBELL_QP_ID_MASK		GENMASK_ULL(36, 21)
};

struct xsc_diamond_data_seg {
	__le32 length;
	__le32 key;
	__le64 addr;
};

struct xsc_diamond_atomic_seg {
	__le64 swap_add;
	__le64 compare;
};

struct xsc_diamond_next_cq_doorbell {
	__le64 raw;
#define XSC_DIAMOND_NEXT_CQ_DOORBELL_CQ_NEXT_CID_MASK	GENMASK_ULL(22, 0)
#define XSC_DIAMOND_NEXT_CQ_DOORBELL_CQ_ID_MASK		GENMASK_ULL(38, 23)
#define XSC_DIAMOND_NEXT_CQ_DOORBELL_CQ_STA_MASK	GENMASK_ULL(40, 39)
};

struct xsc_diamond_next_send_doorbell {
	__le64 raw;
#define XSC_DIAMOND_NEXT_SEND_DOORBELL_NEXT_PID_MASK	GENMASK_ULL(16, 0)
#define XSC_DIAMOND_NEXT_SEND_DOORBELL_QP_ID_MASK	GENMASK_ULL(32, 17)
};

struct xsc_diamond_next_recv_doorbell {
	__le64 raw;
#define XSC_DIAMOND_NEXT_RECV_DOORBELL_NEXT_PID_MASK	GENMASK_ULL(13, 0)
#define XSC_DIAMOND_NEXT_RECV_DOORBELL_QP_ID_MASK	GENMASK_ULL(29, 14)
};

enum {
	XSC_CQ_STAT_FIRED,
	XSC_CQ_STAT_KEEP,
	XSC_CQ_STAT_ARM_NEXT,
	XSC_CQ_STAT_ARM_SOLICITED,
};

static inline uint8_t xsc_diamond_get_cqe_msg_opcode(void *cqe)
{
	return FIELD_GET(XSC_DIAMOND_CQE_MSG_OPCODE_MASK,
			 le32toh(((struct xsc_diamond_cqe *)cqe)->data2));
}

static inline uint8_t xsc_andes_get_cqe_msg_opcode(void *cqe)
{
	return ((struct xsc_andes_cqe *)cqe)->msg_opcode;
}

static inline uint8_t xsc_hw_get_cqe_msg_opcode(uint16_t device_id, void *cqe)
{
	switch (device_id) {
	case XSC_MS_PF_DEV_ID:
	case XSC_MS_VF_DEV_ID:
		return xsc_andes_get_cqe_msg_opcode(cqe);
	case XSC_MC_PF_DEV_ID_DIAMOND:
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		return xsc_diamond_get_cqe_msg_opcode(cqe);
	default:
		return xsc_andes_get_cqe_msg_opcode(cqe);
	}
}

static inline uint32_t xsc_hw_get_wqe_id(uint16_t device_id, void *cqe)
{
	switch (device_id) {
	case XSC_MS_PF_DEV_ID:
	case XSC_MS_VF_DEV_ID:
		return RD_LE_16(((struct xsc_andes_cqe *)cqe)->wqe_id);
	case XSC_MC_PF_DEV_ID_DIAMOND:
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		return FIELD_GET(XSC_DIAMOND_CQE_WQE_ID_MASK,
				 le32toh(((struct xsc_diamond_cqe *)cqe)->data2));
	default:
		return RD_LE_16(((struct xsc_andes_cqe *)cqe)->wqe_id);
	}
}

static inline void xsc_hw_set_wqe_id(uint16_t device_id, void *cseg, uint32_t wqe_id)
{
	uint16_t wqe_id16 = wqe_id;

	switch (device_id) {
	case XSC_MS_PF_DEV_ID:
	case XSC_MS_VF_DEV_ID:
		WR_LE_16(((struct andes_send_wqe_ctrl_seg *)cseg)->wqe_id, wqe_id16);
		break;
	case XSC_MC_PF_DEV_ID_DIAMOND:
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		((struct diamond_send_wqe_ctrl_seg *)cseg)->data1 |=
			htole32(FIELD_PREP(XSC_DIAMOND_WQE_CTRL_SEG_WQE_ID_MASK, wqe_id));
		break;
	default:
		WR_LE_16(((struct andes_send_wqe_ctrl_seg *)cseg)->wqe_id, wqe_id16);
		break;
	}
}

static inline bool xsc_diamond_is_err_cqe(void *cqe)
{
	return !!((struct xsc_diamond_cqe *)cqe)->error_code;
}

static inline bool xsc_andes_is_err_cqe(void *cqe)
{
	return FIELD_GET(XSC_ANDES_CQE_IS_ERR_MASK,
			 ((struct xsc_andes_cqe *)cqe)->data0);
}

static inline bool xsc_hw_is_err_cqe(uint16_t device_id, void *cqe)
{
	switch (device_id) {
	case XSC_MS_PF_DEV_ID:
	case XSC_MS_VF_DEV_ID:
		return xsc_andes_is_err_cqe(cqe);
	case XSC_MC_PF_DEV_ID_DIAMOND:
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		return xsc_diamond_is_err_cqe(cqe);
	default:
		return xsc_andes_is_err_cqe(cqe);
	}
}

static inline uint8_t xsc_diamond_get_cqe_err_code(void *cqe)
{
	return ((struct xsc_diamond_cqe *)cqe)->error_code;
}

static inline uint8_t xsc_andes_get_cqe_err_code(void *cqe)
{
	return FIELD_GET(XSC_ANDES_CQE_ERR_CODE_MASK,
		  ((struct xsc_andes_cqe *)cqe)->data0);
}

static inline uint8_t xsc_hw_get_cqe_err_code(uint16_t device_id, void *cqe)
{
	switch (device_id) {
	case XSC_MS_PF_DEV_ID:
	case XSC_MS_VF_DEV_ID:
		return xsc_andes_get_cqe_err_code(cqe);
	case XSC_MC_PF_DEV_ID_DIAMOND:
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		return xsc_diamond_get_cqe_err_code(cqe);
	default:
		return xsc_andes_get_cqe_err_code(cqe);
	}
}

static inline enum ibv_wc_status xsc_andes_cqe_err_code(uint8_t error_code)
{
	switch (error_code) {
	case XSC_ANDES_ERR_CODE_NAK_RETRY:
		return IBV_WC_RETRY_EXC_ERR;
	case XSC_ANDES_ERR_CODE_NAK_OPCODE:
		return IBV_WC_REM_INV_REQ_ERR;
	case XSC_ANDES_ERR_CODE_NAK_MR:
		return IBV_WC_REM_ACCESS_ERR;
	case XSC_ANDES_ERR_CODE_NAK_OPERATION:
		return IBV_WC_REM_OP_ERR;
	case XSC_ANDES_ERR_CODE_NAK_RNR:
		return IBV_WC_RNR_RETRY_EXC_ERR;
	case XSC_ANDES_ERR_CODE_LOCAL_MR:
		return IBV_WC_LOC_PROT_ERR;
	case XSC_ANDES_ERR_CODE_LOCAL_LEN:
		return IBV_WC_LOC_LEN_ERR;
	case XSC_ANDES_ERR_CODE_LEN_GEN_CQE:
		return IBV_WC_LOC_LEN_ERR;
	case XSC_ANDES_ERR_CODE_OPERATION:
		return IBV_WC_LOC_ACCESS_ERR;
	case XSC_ANDES_ERR_CODE_FLUSH:
		return IBV_WC_WR_FLUSH_ERR;
	case XSC_ANDES_ERR_CODE_MALF_WQE_HOST:
	case XSC_ANDES_ERR_CODE_STRG_ACC_GEN_CQE:
	case XSC_ANDES_ERR_CODE_STRG_ACC:
		return IBV_WC_FATAL_ERR;
	case XSC_ANDES_ERR_CODE_MR_GEN_CQE:
		return IBV_WC_LOC_PROT_ERR;
	case XSC_ANDES_ERR_CODE_LOCAL_OPERATION_WQE:
		return IBV_WC_LOC_QP_OP_ERR;
	case XSC_ANDES_ERR_CODE_OPCODE_GEN_CQE:
	case XSC_ANDES_ERR_CODE_LOCAL_OPCODE:
	default:
		return IBV_WC_GENERAL_ERR;
	}
}

static inline enum ibv_wc_status xsc_diamond_cqe_err_code(uint8_t error_code)
{
	switch (error_code) {
	case XSC_DIAMOND_ERR_CODE_READ_DROP:
	case XSC_DIAMOND_ERR_CODE_NAK_SEQ_ERR:
	case XSC_DIAMOND_ERR_CODE_RTO_REQ:
	case XSC_DIAMOND_ERR_CODE_SV_RTO_RSP:
		return IBV_WC_RETRY_EXC_ERR;
	case XSC_DIAMOND_ERR_CODE_NAK_INV_REQ:
	case XSC_DIAMOND_ERR_CODE_OPCODE_SEQ_GEN_CQE:
	case XSC_DIAMOND_ERR_CODE_OPCODE_SEQ:
	case XSC_DIAMOND_ERR_CODE_ATOMIC_VA_REQ:
	case XSC_DIAMOND_ERR_CODE_ATOMIC_VA_REQ_BDT:
	case XSC_DIAMOND_ERR_CODE_ACC_TYPE_MR:
	case XSC_DIAMOND_ERR_CODE_ACC_TYPE_MR_GEN_CQE:
		return IBV_WC_REM_INV_REQ_ERR;
	case XSC_DIAMOND_ERR_CODE_NAK_MR:
		return IBV_WC_REM_ACCESS_ERR;
	case XSC_DIAMOND_ERR_CODE_NAK_REMOTE_OPER_ERR:
		return IBV_WC_REM_OP_ERR;
	case XSC_DIAMOND_ERR_CODE_LOCAL_MR_REQ:
	case XSC_DIAMOND_ERR_CODE_LOCAL_MR_REQ_BDT:
	case XSC_DIAMOND_ERR_CODE_LOCAL_MR_RSP:
	case XSC_DIAMOND_ERR_CODE_ATOMIC_VA_RSP:
		return IBV_WC_LOC_PROT_ERR;
	case XSC_DIAMOND_ERR_CODE_READ_RSP_LEN:
	case XSC_DIAMOND_ERR_CODE_READ_RSP_LEN_BDT:
	case XSC_DIAMOND_ERR_CODE_SND_WQE_LEN:
	case XSC_DIAMOND_ERR_CODE_LEN:
	case XSC_DIAMOND_ERR_CODE_LEN_GEN_CQE:
	case XSC_DIAMOND_ERR_CODE_RCV_WQE_SIZE_RC:
		return IBV_WC_LOC_LEN_ERR;
	case XSC_DIAMOND_ERR_CODE_READ_RSP_OPCODE:
	case XSC_DIAMOND_ERR_CODE_READ_RSP_OPCODE_BDT:
		return IBV_WC_BAD_RESP_ERR;
	case XSC_DIAMOND_ERR_CODE_NAK_FLUSH:
	case XSC_DIAMOND_ERR_CODE_FLUSH:
		return IBV_WC_WR_FLUSH_ERR;
	case XSC_DIAMOND_ERR_CODE_QPM_CFG:
	case XSC_DIAMOND_ERR_CODE_MET_CFG:
	case XSC_DIAMOND_ERR_CODE_PPE_CFG:
	case XSC_DIAMOND_ERR_CODE_PG_CFG:
	case XSC_DIAMOND_ERR_CODE_SV_CFG:
	case XSC_DIAMOND_ERR_CODE_QPM:
	case XSC_DIAMOND_ERR_CODE_SV:
	case XSC_DIAMOND_ERR_CODE_MET:
	case XSC_DIAMOND_ERR_CODE_PPE:
	case XSC_DIAMOND_ERR_CODE_PG:
	case XSC_DIAMOND_ERR_CODE_CEM:
	case XSC_DIAMOND_ERR_CODE_RCV_WQE_DMA:
	case XSC_DIAMOND_ERR_CODE_DATA_DMA_RD_REQ:
	case XSC_DIAMOND_ERR_CODE_DATA_DMA_WR_REQ:
	case XSC_DIAMOND_ERR_CODE_DATA_DMA_WR_RSP_GEN_CQE:
	case XSC_DIAMOND_ERR_CODE_DATA_DMA_WR_RSP:
	case XSC_DIAMOND_ERR_CODE_DATA_DMA_RD_RSP:
	case XSC_DIAMOND_ERR_CODE_READ_RSP_WQE_DMA_RD:
	case XSC_DIAMOND_ERR_CODE_RO_DMA_RD:
	case XSC_DIAMOND_ERR_CODE_REQ_MTT_DMA_RD:
	case XSC_DIAMOND_ERR_CODE_REQ_MTT_DMA_RD_BDT:
	case XSC_DIAMOND_ERR_CODE_RSP_MTT_DMA_RD:
	case XSC_DIAMOND_ERR_CODE_RSP_MTT_DMA_RD_GEN_CQE:
		return IBV_WC_FATAL_ERR;
	case XSC_DIAMOND_ERR_CODE_SND_WQE_FORMAT:
	case XSC_DIAMOND_ERR_CODE_SND_WQE_DMA:
	case XSC_DIAMOND_ERR_CODE_SND_WQE_STATUS:
	case XSC_DIAMOND_ERR_CODE_RCV_WQE_STATUS:
		return IBV_WC_LOC_QP_OP_ERR;
	case XSC_DIAMOND_ERR_CODE_REMOTE_MR:
	case XSC_DIAMOND_ERR_CODE_REMOTE_MR_GEN_CQE:
		return IBV_WC_LOC_ACCESS_ERR;
	case XSC_DIAMOND_ERR_CODE_NAK_RNR:
		return IBV_WC_RNR_RETRY_EXC_ERR;
	default:
		return IBV_WC_GENERAL_ERR;
	}
}

static inline enum ibv_wc_status xsc_hw_cqe_err_status(uint16_t device_id,
							      void *cqe)
{
	switch (device_id) {
	case XSC_MS_PF_DEV_ID:
	case XSC_MS_VF_DEV_ID:
		return xsc_andes_cqe_err_code(xsc_andes_get_cqe_err_code(cqe));
	case XSC_MC_PF_DEV_ID_DIAMOND:
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		return xsc_diamond_cqe_err_code(xsc_diamond_get_cqe_err_code(cqe));
	default:
		return xsc_andes_cqe_err_code(xsc_andes_get_cqe_err_code(cqe));
	}
}

static inline void xsc_diamond_set_data_seg(void *data_seg,
						   uint64_t addr, uint32_t key,
						   uint32_t length)
{
	struct xsc_diamond_data_seg *seg = data_seg;

	seg->length = htole32(length);
	seg->key = htole32(key);
	seg->addr = htole64(addr);
}

static inline void xsc_diamond_set_atomic_seg(void *atomic_seg, int opcode,
						     uint64_t swap, uint64_t compare_add)
{
	struct xsc_diamond_atomic_seg *aseg = (struct xsc_diamond_atomic_seg *)atomic_seg;

	if (opcode == IBV_WR_ATOMIC_CMP_AND_SWP) {
		aseg->swap_add = htole64(swap);
		aseg->compare = htole64(compare_add);
	} else {
		aseg->swap_add = htole64(compare_add);
	}
}

static inline void xsc_andes_set_data_seg(void *data_seg,
						 uint64_t addr, uint32_t key,
						 uint32_t length)
{
	struct xsc_andes_data_seg *seg = data_seg;

	seg->data0 |= htole32(FIELD_PREP(XSC_ANDES_DATA_SEG_LENGTH_MASK, length));
	seg->key = htole32(key);
	seg->addr = htole64(addr);
}

static inline void xsc_hw_set_data_seg(uint16_t device_id, void *data_seg,
					      uint64_t addr, uint32_t key, uint32_t length)
{
	switch (device_id) {
	case XSC_MS_PF_DEV_ID:
	case XSC_MS_VF_DEV_ID:
		xsc_andes_set_data_seg(data_seg, addr, key, length);
		break;
	case XSC_MC_PF_DEV_ID_DIAMOND:
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		xsc_diamond_set_data_seg(data_seg, addr, key, length);
		break;
	default:
		xsc_andes_set_data_seg(data_seg, addr, key, length);
	}
}

static inline void xsc_hw_set_atomic_seg(uint16_t device_id, void *atomic_seg,
						int opcode, uint64_t swap, uint64_t compare_add)
{
	switch (device_id) {
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		xsc_diamond_set_atomic_seg(atomic_seg, opcode, swap, compare_add);
		break;
	default:
		xsc_diamond_set_atomic_seg(atomic_seg, opcode, swap, compare_add);
		break;
	}
}

static inline void xsc_diamond_set_cq_ci(void *db_addr,
						uint32_t cqn, uint32_t next_cid)
{
	struct xsc_diamond_cq_doorbell db;

	db.raw = htole64(FIELD_PREP(XSC_DIAMOND_CQ_DOORBELL_CQ_ID_MASK, cqn) |
			 FIELD_PREP(XSC_DIAMOND_CQ_DOORBELL_CQ_NEXT_CID_MASK, next_cid) |
			 FIELD_PREP(XSC_DIAMOND_CQ_DOORBELL_CQ_STA_MASK, XSC_CQ_STAT_KEEP));
	udma_to_device_barrier();
	mmio_write64_le(db_addr, db.raw);
}

static inline void xsc_diamond_next_set_cq_ci(void *db_addr,
						     uint32_t cqn, uint32_t next_cid)
{
	struct xsc_diamond_next_cq_doorbell db;

	db.raw = htole64(FIELD_PREP(XSC_DIAMOND_NEXT_CQ_DOORBELL_CQ_ID_MASK, cqn) |
			 FIELD_PREP(XSC_DIAMOND_NEXT_CQ_DOORBELL_CQ_NEXT_CID_MASK, next_cid) |
			 FIELD_PREP(XSC_DIAMOND_NEXT_CQ_DOORBELL_CQ_STA_MASK, XSC_CQ_STAT_KEEP));
	udma_to_device_barrier();
	mmio_write64_le(db_addr, db.raw);
}

static inline void xsc_andes_set_cq_ci(void *db_addr,
					      uint32_t cqn, uint32_t next_cid)
{
	struct xsc_andes_cq_doorbell db;

	db.raw = htole32(FIELD_PREP(XSC_ANDES_CQ_DOORBELL_CQ_ID_MASK, cqn) |
			 FIELD_PREP(XSC_ANDES_CQ_DOORBELL_CQ_NEXT_CID_MASK, next_cid) |
			 FIELD_PREP(XSC_ANDES_CQ_DOORBELL_ARM_MASK, XSC_CQ_STAT_FIRED));
	udma_to_device_barrier();
	mmio_write32_le(db_addr, db.raw);
}


static inline void xsc_hw_set_cq_ci(uint16_t device_id, void *db_addr,
					   uint32_t cqn, uint32_t next_cid)
{
	switch (device_id) {
	case XSC_MS_PF_DEV_ID:
	case XSC_MS_VF_DEV_ID:
		xsc_andes_set_cq_ci(db_addr, cqn, next_cid);
		break;
	case XSC_MC_PF_DEV_ID_DIAMOND:
		xsc_diamond_set_cq_ci(db_addr, cqn, next_cid);
		break;
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		xsc_diamond_next_set_cq_ci(db_addr, cqn, next_cid);
		break;
	default:
		xsc_andes_set_cq_ci(db_addr, cqn, next_cid);
	}
}

static inline void xsc_diamond_update_cq_db(void *db_addr,
						   uint32_t cqn, uint32_t next_cid,
						   uint8_t solicited)
{
	struct xsc_diamond_cq_doorbell db;

	db.raw = htole64(FIELD_PREP(XSC_DIAMOND_CQ_DOORBELL_CQ_ID_MASK, cqn) |
			 FIELD_PREP(XSC_DIAMOND_CQ_DOORBELL_CQ_NEXT_CID_MASK, next_cid) |
			 FIELD_PREP(XSC_DIAMOND_CQ_DOORBELL_CQ_STA_MASK,
				    solicited ? XSC_CQ_STAT_ARM_SOLICITED : XSC_CQ_STAT_ARM_NEXT));
	udma_to_device_barrier();
	mmio_wc_start();
	mmio_write64_le(db_addr, db.raw);
	mmio_flush_writes();
}

static inline void xsc_diamond_next_update_cq_db(void *db_addr,
							uint32_t cqn, uint32_t next_cid,
							uint8_t solicited)
{
	struct xsc_diamond_next_cq_doorbell db;

	db.raw = htole64(FIELD_PREP(XSC_DIAMOND_NEXT_CQ_DOORBELL_CQ_ID_MASK, cqn) |
			 FIELD_PREP(XSC_DIAMOND_NEXT_CQ_DOORBELL_CQ_NEXT_CID_MASK, next_cid) |
			 FIELD_PREP(XSC_DIAMOND_NEXT_CQ_DOORBELL_CQ_STA_MASK,
				    solicited ? XSC_CQ_STAT_ARM_SOLICITED : XSC_CQ_STAT_ARM_NEXT));
	udma_to_device_barrier();
	mmio_wc_start();
	mmio_write64_le(db_addr, db.raw);
	mmio_flush_writes();
}

static inline void xsc_andes_update_cq_db(void *db_addr,
						 uint32_t cqn, uint32_t next_cid,
						 uint8_t solicited)
{
	struct xsc_andes_cq_doorbell db;

	db.raw = htole32(FIELD_PREP(XSC_ANDES_CQ_DOORBELL_CQ_ID_MASK, cqn) |
			 FIELD_PREP(XSC_ANDES_CQ_DOORBELL_CQ_NEXT_CID_MASK, next_cid) |
			 FIELD_PREP(XSC_ANDES_CQ_DOORBELL_ARM_MASK,
				    solicited ? XSC_CQ_STAT_ARM_SOLICITED : XSC_CQ_STAT_ARM_NEXT));
	udma_to_device_barrier();
	mmio_wc_start();
	mmio_write32_le(db_addr, db.raw);
	mmio_flush_writes();
}

static inline void xsc_hw_update_cq_db(uint16_t device_id, void *db_addr,
					      uint32_t cqn, uint32_t next_cid,
					      uint8_t solicited)
{
	switch (device_id) {
	case XSC_MS_PF_DEV_ID:
	case XSC_MS_VF_DEV_ID:
		xsc_andes_update_cq_db(db_addr, cqn, next_cid, solicited);
		break;
	case XSC_MC_PF_DEV_ID_DIAMOND:
		xsc_diamond_update_cq_db(db_addr, cqn, next_cid, solicited);
		break;
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		xsc_diamond_next_update_cq_db(db_addr, cqn, next_cid, solicited);
		break;
	default:
		xsc_andes_update_cq_db(db_addr, cqn, next_cid, solicited);
	}
}

static inline void xsc_diamond_ring_rx_doorbell(void *db_addr,
						       uint32_t rqn, uint32_t next_pid)
{
	struct xsc_diamond_recv_doorbell db;

	db.raw = htole64(FIELD_PREP(XSC_DIAMOND_RECV_DOORBELL_QP_ID_MASK, rqn) |
			 FIELD_PREP(XSC_DIAMOND_RECV_DOORBELL_NEXT_PID_MASK, next_pid));
	udma_to_device_barrier();
	mmio_write64_le(db_addr, db.raw);
}


static inline void xsc_diamond_next_ring_rx_doorbell(void *db_addr,
							    uint32_t rqn, uint32_t next_pid)
{
	struct xsc_diamond_next_recv_doorbell db;

	db.raw = htole64(FIELD_PREP(XSC_DIAMOND_NEXT_RECV_DOORBELL_QP_ID_MASK, rqn) |
			 FIELD_PREP(XSC_DIAMOND_NEXT_RECV_DOORBELL_NEXT_PID_MASK, next_pid));
	udma_to_device_barrier();
	mmio_write64_le(db_addr, db.raw);
}

static inline void xsc_andes_ring_rx_doorbell(void *db_addr,
						     uint32_t rqn, uint32_t next_pid)
{
	struct xsc_andes_recv_doorbell db;

	db.raw = htole32(FIELD_PREP(XSC_ANDES_RECV_DOORBELL_QP_ID_MASK, rqn) |
			 FIELD_PREP(XSC_ANDES_RECV_DOORBELL_NEXT_PID_MASK, next_pid));
	udma_to_device_barrier();
	mmio_write32_le(db_addr, db.raw);
}

static inline void xsc_hw_ring_rx_doorbell(uint16_t device_id,
						  void *db_addr,
						  uint32_t rqn, uint32_t next_pid)
{
	switch (device_id) {
	case XSC_MS_PF_DEV_ID:
	case XSC_MS_VF_DEV_ID:
		xsc_andes_ring_rx_doorbell(db_addr, rqn, next_pid);
		break;
	case XSC_MC_PF_DEV_ID_DIAMOND:
		xsc_diamond_ring_rx_doorbell(db_addr, rqn, next_pid);
		break;
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		xsc_diamond_next_ring_rx_doorbell(db_addr, rqn, next_pid);
		break;
	default:
		xsc_andes_ring_rx_doorbell(db_addr, rqn, next_pid);
	}
}

static inline void xsc_diamond_ring_tx_doorbell(void *db_addr,
						       uint32_t rqn, uint32_t next_pid)
{
	struct xsc_diamond_send_doorbell db;

	db.raw = htole64(FIELD_PREP(XSC_DIAMOND_SEND_DOORBELL_QP_ID_MASK, rqn) |
			 FIELD_PREP(XSC_DIAMOND_SEND_DOORBELL_NEXT_PID_MASK, next_pid));

	udma_to_device_barrier();
	mmio_write64_le(db_addr, db.raw);
}


static inline void xsc_diamond_next_ring_tx_doorbell(void *db_addr,
							    uint32_t rqn, uint32_t next_pid)
{
	struct xsc_diamond_next_send_doorbell db;

	db.raw = htole64(FIELD_PREP(XSC_DIAMOND_NEXT_SEND_DOORBELL_QP_ID_MASK, rqn) |
			 FIELD_PREP(XSC_DIAMOND_NEXT_SEND_DOORBELL_NEXT_PID_MASK, next_pid));

	udma_to_device_barrier();
	mmio_write64_le(db_addr, db.raw);
}

static inline void xsc_andes_ring_tx_doorbell(void *db_addr,
							    uint32_t rqn, uint32_t next_pid)
{
	struct xsc_andes_send_doorbell db;

	db.raw = htole32(FIELD_PREP(XSC_ANDES_SEND_DOORBELL_QP_ID_MASK, rqn) |
			 FIELD_PREP(XSC_ANDES_SEND_DOORBELL_NEXT_PID_MASK, next_pid));

	udma_to_device_barrier();
	mmio_write32_le(db_addr, db.raw);
}

static inline void xsc_hw_ring_tx_doorbell(uint16_t device_id,
						  void *db_addr,
						  uint32_t sqn, uint32_t next_pid)
{
	switch (device_id) {
	case XSC_MS_PF_DEV_ID:
	case XSC_MS_VF_DEV_ID:
		xsc_andes_ring_tx_doorbell(db_addr, sqn, next_pid);
		break;
	case XSC_MC_PF_DEV_ID_DIAMOND:
		xsc_diamond_ring_tx_doorbell(db_addr, sqn, next_pid);
		break;
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		xsc_diamond_next_ring_tx_doorbell(db_addr, sqn, next_pid);
		break;
	default:
		xsc_andes_ring_tx_doorbell(db_addr, sqn, next_pid);
	}
}

static inline int xsc_get_recv_ds_shift(struct xsc_context *ctx, int qp_type)
{
	uint16_t device_id = ctx->device_id;

	switch (device_id) {
	case XSC_MC_PF_DEV_ID_DIAMOND:
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		return (qp_type == IBV_QPT_RAW_PACKET) ? 2 : ctx->recv_ds_shift;
	default:
		return ctx->recv_ds_shift;
	}
}

static inline int xsc_check_cqe_msg_opcode(struct xsc_context *ctx, int msg_opcode)
{
	uint16_t device_id = ctx->device_id;

	switch (device_id) {
	case XSC_MC_PF_DEV_ID_DIAMOND:
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		return (msg_opcode > XSC_MSG_OPCODE_SEND_DIAMOND_NEXT &&
			msg_opcode != XSC_MSG_OPCODE_RDMA_ATOMIC_CMP_AND_SWAP &&
			msg_opcode != XSC_MSG_OPCODE_RDMA_ATOMIC_FETCH_AND_ADD &&
			msg_opcode != XSC_MSG_OPCODE_RDMA_ATOMIC_8B_MSK_CMP_AND_SWAP &&
			msg_opcode != XSC_MSG_OPCODE_RDMA_ATOMIC_8B_MSK_FETCH_AND_ADD &&
			msg_opcode != XSC_MSG_OPCODE_RDMA_ATOMIC_4B_MSK_CMP_AND_SWAP &&
			msg_opcode != XSC_MSG_OPCODE_RDMA_ATOMIC_4B_MSK_FETCH_AND_ADD);
	default:
		return (msg_opcode > XSC_MSG_OPCODE_RDMA_READ &&
			msg_opcode != XSC_MSG_OPCODE_RDMA_ATOMIC_CMP_AND_SWAP &&
			msg_opcode != XSC_MSG_OPCODE_RDMA_ATOMIC_FETCH_AND_ADD &&
			msg_opcode != XSC_MSG_OPCODE_RDMA_ATOMIC_8B_MSK_CMP_AND_SWAP &&
			msg_opcode != XSC_MSG_OPCODE_RDMA_ATOMIC_8B_MSK_FETCH_AND_ADD &&
			msg_opcode != XSC_MSG_OPCODE_RDMA_ATOMIC_4B_MSK_CMP_AND_SWAP &&
			msg_opcode != XSC_MSG_OPCODE_RDMA_ATOMIC_4B_MSK_FETCH_AND_ADD);
	}
}

static inline bool xsc_need_modify_qp_to_err(uint16_t device_id, void *cqe)
{
	switch (device_id) {
	case XSC_MC_PF_DEV_ID_DIAMOND:
	case XSC_MC_PF_DEV_ID_DIAMOND_NEXT:
		return xsc_diamond_get_cqe_err_code(cqe) == XSC_DIAMOND_ERR_CODE_NAK_FLUSH ?
			false : true;
	default:
		return true;
	}
}

#endif /* _XSC_HW_H_ */
