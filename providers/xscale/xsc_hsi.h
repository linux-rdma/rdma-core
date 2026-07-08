/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_HSI_H__
#define __XSC_HSI_H__

#include <linux/types.h>
#include <asm/byteorder.h>
#include <util/util.h>

#define upper_32_bits(n) ((uint32_t)(((n) >> 16) >> 16))
#define lower_32_bits(n) ((uint32_t)(n))

#define DMA_LO_LE(x)		__cpu_to_le32(lower_32_bits(x))
#define DMA_HI_LE(x)		__cpu_to_le32(upper_32_bits(x))
#define DMA_REGPAIR_LE(x, val)	do { \
					(x).hi = DMA_HI_LE((val)); \
					(x).lo = DMA_LO_LE((val)); \
				} while (0)

#define WR_LE_16(x, val)	do { (x) = __cpu_to_le16(val); } while (0)
#define WR_LE_32(x, val)	do { (x) = __cpu_to_le32(val); } while (0)
#define WR_LE_64(x, val)	do { (x) = __cpu_to_le64(val); } while (0)
#define WR_LE_R64(x, val)	DMA_REGPAIR_LE(x, val)
#define WR_BE_32(x, val)	do { (x) = __cpu_to_be32(val); } while (0)

#define RD_LE_16(x)		__le16_to_cpu(x)
#define RD_LE_32(x)		__le32_to_cpu(x)
#define RD_BE_32(x)		__be32_to_cpu(x)
#define RD_BE_64(x)		__be64_to_cpu(x)

#define WR_REG(addr, val)	mmio_write32_le(addr, val)
#define RD_REG(addr)		mmio_read32_le(addr)

/* message opcode */
enum {
	XSC_MSG_OPCODE_SEND		= 0,
	XSC_MSG_OPCODE_RDMA_WRITE	= 1,
	XSC_MSG_OPCODE_RDMA_READ	= 2,
	XSC_MSG_OPCODE_MAD		= 3,
	XSC_MSG_OPCODE_RDMA_ACK		= 4,
	XSC_MSG_OPCODE_RDMA_ACK_READ	= 5,
	XSC_MSG_OPCODE_RDMA_CNP		= 6,
	XSC_MSG_OPCODE_RAW		= 7,
	XSC_MSG_OPCODE_VIRTIO_NET	= 8,
	XSC_MSG_OPCODE_VIRTIO_BLK	= 9,
	XSC_MSG_OPCODE_RAW_TPE		= 10,
	XSC_MSG_OPCODE_INIT_QP_REQ	= 11,
	XSC_MSG_OPCODE_INIT_QP_RSP	= 12,
	XSC_MSG_OPCODE_INIT_PATH_REQ	= 13,
	XSC_MSG_OPCODE_INIT_PATH_RSP	= 14,
	XSC_MSG_OPCODE_SO_WRITE		= 22,
	XSC_MSG_OPCODE_RDMA_ATOMIC_CMP_AND_SWAP	= 26,
	XSC_MSG_OPCODE_RDMA_ATOMIC_FETCH_AND_ADD = 27,

	XSC_MSG_OPCODE_RDMA_ATOMIC_8B_MSK_CMP_AND_SWAP = 31,
	XSC_MSG_OPCODE_RDMA_ATOMIC_8B_MSK_FETCH_AND_ADD = 32,
	XSC_MSG_OPCODE_RDMA_ATOMIC_4B_MSK_CMP_AND_SWAP = 33,
	XSC_MSG_OPCODE_RDMA_ATOMIC_4B_MSK_FETCH_AND_ADD = 34,

	XSC_MSG_OPCODE_MAX,
};

enum {
	XSC_MSG_OPCODE_SEND_DIAMOND_NEXT = 3,
};

enum {
	XSC_REQ		= 0,
	XSC_RSP		= 1,
};

enum {
	XSC_WITHOUT_IMMDT	= 0,
	XSC_WITH_IMMDT		= 1,
};

enum {
	XSC_ANDES_ERR_CODE_NAK_RETRY			= 0x40,
	XSC_ANDES_ERR_CODE_NAK_OPCODE			= 0x41,
	XSC_ANDES_ERR_CODE_NAK_MR			= 0x42,
	XSC_ANDES_ERR_CODE_NAK_OPERATION		= 0x43,
	XSC_ANDES_ERR_CODE_NAK_RNR			= 0x44,
	XSC_ANDES_ERR_CODE_LOCAL_MR			= 0x45,
	XSC_ANDES_ERR_CODE_LOCAL_LEN			= 0x46,
	XSC_ANDES_ERR_CODE_LOCAL_OPCODE			= 0x47,
	XSC_ANDES_ERR_CODE_CQ_OVER_FLOW			= 0x48,
	XSC_ANDES_ERR_CODE_LOCAL_OPERATION_WQE		= 0x49,
	XSC_ANDES_ERR_CODE_STRG_ACC_GEN_CQE		= 0x4b,
	XSC_ANDES_ERR_CODE_STRG_ACC			= 0x4c,
	XSC_ANDES_ERR_CODE_CQE_ACC			= 0x4d,
	XSC_ANDES_ERR_CODE_FLUSH			= 0x4e,
	XSC_ANDES_ERR_CODE_MALF_WQE_HOST		= 0x50,
	XSC_ANDES_ERR_CODE_MALF_WQE_INFO		= 0x51,
	XSC_ANDES_ERR_CODE_MR_NON_NAK			= 0x52,
	XSC_ANDES_ERR_CODE_OPCODE_GEN_CQE		= 0x61,
	XSC_ANDES_ERR_CODE_MANY_READ			= 0x62,
	XSC_ANDES_ERR_CODE_LEN_GEN_CQE			= 0x63,
	XSC_ANDES_ERR_CODE_MR				= 0x65,
	XSC_ANDES_ERR_CODE_MR_GEN_CQE			= 0x66,
	XSC_ANDES_ERR_CODE_OPERATION			= 0x67,
	XSC_ANDES_ERR_CODE_MALF_WQE_INFO_GEN_NAK	= 0x68,
};

enum {
	XSC_DIAMOND_ERR_CODE_NAK_FLUSH			= 0x1f,
	XSC_DIAMOND_ERR_CODE_CEM			= 0x28,
	XSC_DIAMOND_ERR_CODE_QPM_CFG			= 0x80,
	XSC_DIAMOND_ERR_CODE_MET_CFG			= 0x81,
	XSC_DIAMOND_ERR_CODE_PPE_CFG			= 0x82,
	XSC_DIAMOND_ERR_CODE_PG_CFG			= 0x83,
	XSC_DIAMOND_ERR_CODE_SV_CFG			= 0x84,
	XSC_DIAMOND_ERR_CODE_ATOMIC_VA_REQ		= 0x89,
	XSC_DIAMOND_ERR_CODE_SND_WQE_LEN		= 0x9f,
	XSC_DIAMOND_ERR_CODE_NAK_SEQ_ERR		= 0xa0,
	XSC_DIAMOND_ERR_CODE_READ_DROP			= 0xa1,
	XSC_DIAMOND_ERR_CODE_RTO_REQ			= 0xa2,
	XSC_DIAMOND_ERR_CODE_NAK_RNR			= 0xa3,
	XSC_DIAMOND_ERR_CODE_NAK_INV_REQ		= 0xa4,
	XSC_DIAMOND_ERR_CODE_NAK_MR			= 0xa5,
	XSC_DIAMOND_ERR_CODE_NAK_REMOTE_OPER_ERR	= 0xa6,
	XSC_DIAMOND_ERR_CODE_LOCAL_MR_REQ		= 0xa7,
	XSC_DIAMOND_ERR_CODE_READ_RSP_LEN		= 0xa8,
	XSC_DIAMOND_ERR_CODE_READ_RSP_OPCODE		= 0xaa,
	XSC_DIAMOND_ERR_CODE_SND_WQE_FORMAT		= 0xab,
	XSC_DIAMOND_ERR_CODE_SND_WQE_DMA		= 0xac,
	XSC_DIAMOND_ERR_CODE_SND_WQE_STATUS		= 0xad,
	XSC_DIAMOND_ERR_CODE_SV_RTO_RSP			= 0xae,
	XSC_DIAMOND_ERR_CODE_RCV_WQE_DMA		= 0xaf,
	XSC_DIAMOND_ERR_CODE_DATA_DMA_RD_REQ		= 0xb2,
	XSC_DIAMOND_ERR_CODE_DATA_DMA_WR_REQ		= 0xb3,
	XSC_DIAMOND_ERR_CODE_DATA_DMA_WR_RSP_GEN_CQE	= 0xb4,
	XSC_DIAMOND_ERR_CODE_DATA_DMA_WR_RSP		= 0xb5,
	XSC_DIAMOND_ERR_CODE_DATA_DMA_RD_RSP		= 0xb6,
	XSC_DIAMOND_ERR_CODE_NO_CLASSIFIED		= 0xb7,
	XSC_DIAMOND_ERR_CODE_RCV_WQE_STATUS		= 0xb9,
	XSC_DIAMOND_ERR_CODE_QPM			= 0xba,
	XSC_DIAMOND_ERR_CODE_SV				= 0xbb,
	XSC_DIAMOND_ERR_CODE_MET			= 0xbc,
	XSC_DIAMOND_ERR_CODE_PPE			= 0xbd,
	XSC_DIAMOND_ERR_CODE_PG				= 0xbe,
	XSC_DIAMOND_ERR_CODE_REQ_MTT_DMA_RD		= 0xbf,
	XSC_DIAMOND_ERR_CODE_RCV_WQE_SIZE_RC		= 0xc0,
	XSC_DIAMOND_ERR_CODE_OPCODE_SEQ_GEN_CQE		= 0xc1,
	XSC_DIAMOND_ERR_CODE_OPCODE_SEQ			= 0xc2,
	XSC_DIAMOND_ERR_CODE_LEN_GEN_CQE		= 0xc4,
	XSC_DIAMOND_ERR_CODE_LEN			= 0xc5,
	XSC_DIAMOND_ERR_CODE_READ_RSP_ATOMIC_MSN_BDT	= 0xc8,
	XSC_DIAMOND_ERR_CODE_EMSN_GEN_CQE		= 0xca,
	XSC_DIAMOND_ERR_CODE_RQ_EMSN_GEN_CQE		= 0xcb,
	XSC_DIAMOND_ERR_CODE_READ_RSP_WQE_DMA_RD	= 0xcc,
	XSC_DIAMOND_ERR_CODE_RO_DMA_RD			= 0xcd,
	XSC_DIAMOND_ERR_CODE_RSP_MTT_DMA_RD		= 0xce,
	XSC_DIAMOND_ERR_CODE_ATOMIC_VA_REQ_BDT		= 0xcf,
	XSC_DIAMOND_ERR_CODE_ATOMIC_VA_RSP		= 0xd0,
	XSC_DIAMOND_ERR_CODE_RSP_MTT_DMA_RD_GEN_CQE	= 0xd1,
	XSC_DIAMOND_ERR_CODE_REMOTE_MR			= 0xd4,
	XSC_DIAMOND_ERR_CODE_REMOTE_MR_GEN_CQE		= 0xd5,
	XSC_DIAMOND_ERR_CODE_LOCAL_MR_RSP		= 0xd6,
	XSC_DIAMOND_ERR_CODE_ACC_TYPE_MR		= 0xd7,
	XSC_DIAMOND_ERR_CODE_ACC_TYPE_MR_GEN_CQE	= 0xd8,
	XSC_DIAMOND_ERR_CODE_LOCAL_MR_REQ_BDT		= 0xd9,
	XSC_DIAMOND_ERR_CODE_READ_RSP_LEN_BDT		= 0xda,
	XSC_DIAMOND_ERR_CODE_READ_RSP_OPCODE_BDT	= 0xdb,
	XSC_DIAMOND_ERR_CODE_REQ_MTT_DMA_RD_BDT		= 0xdc,
	XSC_DIAMOND_ERR_CODE_MSN_GEN_CQE		= 0xdd,
	XSC_DIAMOND_ERR_CODE_MSN			= 0xde,
	XSC_DIAMOND_ERR_CODE_FLUSH			= 0xff,
};

/* TODO: sw cqe opcode*/
enum {
	XSC_OPCODE_RDMA_REQ_SEND	= 0,
	XSC_OPCODE_RDMA_REQ_SEND_IMMDT	= 1,
	XSC_OPCODE_RDMA_RSP_RECV	= 2,
	XSC_OPCODE_RDMA_RSP_RECV_IMMDT	= 3,
	XSC_OPCODE_RDMA_REQ_WRITE	= 4,
	XSC_OPCODE_RDMA_REQ_WRITE_IMMDT	= 5,
	XSC_OPCODE_RDMA_RSP_WRITE_IMMDT	= 6,
	XSC_OPCODE_RDMA_REQ_READ	= 7,
	XSC_OPCODE_RDMA_REQ_ERROR	= 8,
	XSC_OPCODE_RDMA_RSP_ERROR	= 9,
	XSC_OPCODE_RDMA_CQE_ERROR	= 10,
	XSC_OPCODE_RDMA_MAD_REQ_SEND    = 11,
	XSC_OPCODE_RDMA_MAD_RSP_RECV    = 12,
	XSC_OPCODE_RDMA_CQE_RAW_SNF	= 13,
	XSC_OPCODE_RDMA_REQ_ATOMIC_CMP_AND_SWAP = 14,
	XSC_OPCODE_RDMA_REQ_ATOMIC_FETCH_AND_ADD = 15,
	XSC_OPCODE_RDMA_REQ_ATOMIC_8B_MASK_CS = 16,
	XSC_OPCODE_RDMA_REQ_ATOMIC_8B_MASK_FA = 17,
	XSC_OPCODE_RDMA_REQ_ATOMIC_4B_MASK_CS = 18,
	XSC_OPCODE_RDMA_REQ_ATOMIC_4B_MASK_FA = 19,
};

enum {
	XSC_BASE_WQE_SHIFT		= 4,
};

/*
 * Descriptors that are allocated by SW and accessed by HW, 32-byte aligned
 */
/* this is to keep descriptor structures packed */
struct regpair {
	__le32	lo;
	__le32	hi;
};

struct xsc_send_wqe_ctrl_seg {
	uint8_t		msg_opcode;
	uint8_t		data0;
#define XSC_SWQE_CTRL_SEG_WITH_IMMDT_MASK		BIT(0)
#define XSC_SWQE_CTRL_SEG_CSUM_EN_MASK			GENMASK(2, 1)
#define XSC_SWQE_CTRL_SEG_DS_DATA_NUM_MASK		GENMASK(7, 3)
	__le16		wqe_id;
	__le32		msg_len;
	__le32		opcode_data;
	uint8_t		data1;
#define XSC_SWQE_CTRL_SEG_SE_MASK			BIT(0)
#define XSC_SWQE_CTRL_SEG_CE_MASK			BIT(1)
#define XSC_SWQE_CTRL_SEG_IN_LINE_MASK		BIT(2)
#define XSC_SWQE_CTRL_SEG_FENCE_MODE_MASK		GENMASK(4, 3)
#define XSC_SWQE_CTRL_SEG_MASK_MASK		GENMASK(6, 5)
	uint8_t		rsv[3];
};


struct xsc_wqe_data_seg {
	union {
		struct {
			uint32_t	data0;
#define XSC_WQE_DATA_SEG_LENGTH_MASK			GENMASK(31, 1)
			__le32		mkey;
			__le64		va;
		};
		struct {
			uint8_t		in_line_data[16];
		};
	};
};

struct xsc_cqe {
	uint8_t		placeholder1;
	__le32		data1;
#define XSC_CQE_QP_ID_MASK			GENMASK(14, 0)
#define XSC_CQE_SE_MASK				BIT(1)
#define XSC_CQE_HAS_PPH_MASK			BIT(2)
#define XSC_CQE_TYPE_MASK				BIT(3)
#define XSC_CQE_WITH_IMMDT_MASK			BIT(4)
#define XSC_CQE_CSUM_ERR_MASK			GENMASK(8, 5)
	__le32		imm_data;
	__le32		msg_len;
	__le32		vni;
	__le64		data2;
#define XSC_CQE_TS_MASK				GENMASK_ULL(47, 0)
	__le16		wqe_id;
	uint8_t		placeholder2;
	uint8_t		rsv1;
	__le16		rsv2[2];
	__le16		data3;
#define XSC_CQE_OWNER_MASK			BIT(15)
};

struct xsc_cqe64 {
	struct xsc_cqe	cqe;
	uint8_t		padding[32];
};

/* Size of CQE */
#define XSC_CQE_SIZE sizeof(struct xsc_cqe)
#define XSC_CQE_SIZE64 sizeof(struct xsc_cqe64)

#define XSC_SEND_WQE_RING_DEPTH_MIN	16
#define XSC_CQE_RING_DEPTH_MIN		2

/*
 * Registers that are allocated by HW and accessed by SW in 4-byte granularity
 */
/* MMT table (32 bytes) */
struct xsc_mmt_tbl {
	struct regpair	pa;
	struct regpair	va;
	__le32		size;
#define XSC_MMT_TBL_PD_MASK		0x00FFFFFF
#define XSC_MMT_TBL_KEY_MASK		0xFF000000
	__le32		key_pd;
#define XSC_MMT_TBL_ACC_MASK		0x0000000F
	__le32		acc;
	uint8_t		padding[4];
};

/* QP Context (16 bytes) */
struct xsc_qp_context {
#define XSC_QP_CONTEXT_STATE_MASK	0x00000007
#define XSC_QP_CONTEXT_FUNC_MASK	0x00000018
#define XSC_QP_CONTEXT_DSTID_MASK	0x000000E0
#define XSC_QP_CONTEXT_PD_MASK		0xFFFFFF00
	__le32		pd_dstid_func_state;
#define XSC_QP_CONTEXT_DSTQP_MASK	0x00FFFFFF
#define XSC_QP_CONTEXT_RCQIDL_MASK	0xFF000000
	__le32		rcqidl_dstqp;
#define XSC_QP_CONTEXT_RCQIDH_MASK	0x0000FFFF
#define XSC_QP_CONTEXT_SCQIDL_MASK	0xFFFF0000
	__le32		scqidl_rcqidh;
#define XSC_QP_CONTEXT_SCQIDH_MASK	0x000000FF
	__le32		scqidh;
};

static inline bool xsc_get_cqe_sw_own(struct xsc_cqe *cqe,
				      int cid, int ring_sz) ALWAYS_INLINE;

static inline void xsc_set_cqe_sw_own(struct xsc_cqe *cqe,
				      int pid, int ring_sz) ALWAYS_INLINE;

static inline bool xsc_get_cqe_sw_own(struct xsc_cqe *cqe, int cid, int ring_sz)
{
	return FIELD_GET(XSC_CQE_OWNER_MASK, cqe->data3)  == ((cid >> ring_sz) & 1);
}

static inline void xsc_set_cqe_sw_own(struct xsc_cqe *cqe, int pid, int ring_sz)
{
	cqe->data3 |= FIELD_PREP(XSC_CQE_OWNER_MASK, ((pid >> ring_sz) & 1));
}
#endif /* __XSC_HSI_H__ */
