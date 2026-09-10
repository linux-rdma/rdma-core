/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef _XSCDV_H_
#define _XSCDV_H_

#include <stdio.h>
#include <linux/types.h> /* For the __be64 type */
#include <sys/types.h>
#include <endian.h>
#if defined(__SSE3__)
#include <limits.h>
#include <emmintrin.h>
#include <tmmintrin.h>
#endif /* defined(__SSE3__) */

#include <infiniband/verbs.h>
#include <infiniband/tm_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XSC_BITS_PER_LONG	   (8 * sizeof(long))
#define XSC_BITS_PER_LONG_LONG (8 * sizeof(long long))
#define XSC_BITS_TO_LONGS(nr)  (((nr) + XSC_BITS_PER_LONG - 1) / XSC_BITS_PER_LONG)

#define XSC_GENMASK(h, l) \
	(((~0UL) - (1UL << (l)) + 1) & (~0UL >> (XSC_BITS_PER_LONG - 1 - (h))))
#define XSC_GENMASK_ULL(h, l) \
	(((~0ULL) << (l)) & (~0ULL >> (XSC_BITS_PER_LONG_LONG - 1 - (h))))

#define XSC_BIT(nr)     (1UL << (nr))
#define XSC_BIT_ULL(nr) (1ULL << (nr))

#define __xsc_bf_shf(x) (__builtin_ffsll(x) - 1)

#define XSC_FIELD_PREP(_mask, _val)                                                \
	({                                                                     \
		((typeof(_mask))(_val) << __xsc_bf_shf(_mask)) & (_mask);          \
	})

#define XSC_FIELD_GET(_mask, _reg)                                                 \
	({                                                                     \
		(typeof(_mask))(((_reg) & (_mask)) >> __xsc_bf_shf(_mask));        \
	})

enum xscdv_cq_init_attr_mask {
	XSCDV_CQ_INIT_ATTR_MASK_COMPRESSED_CQE	= 1 << 0,
	XSCDV_CQ_INIT_ATTR_MASK_FLAGS		= 1 << 1,
	XSCDV_CQ_INIT_ATTR_MASK_CQE_SIZE = 1 << 2,
};

struct xscdv_cq_init_attr {
	uint64_t comp_mask; /* Use enum xscdv_cq_init_attr_mask */
	uint8_t cqe_comp_res_format; /* Use enum xscdv_cqe_comp_res_format */
	uint32_t flags;
	uint16_t cqe_size; /* when XSCDV_CQ_INIT_ATTR_MASK_CQE_SIZE set */
};

enum xscdv_wq_init_attr_mask {
	XSCDV_WQ_INIT_ATTR_MASK_STRIDING_RQ	= 1 << 0,
};

enum xscdv_qp_create_flags {
	XSCDV_QP_CREATE_TUNNEL_OFFLOADS = 1 << 0,
	XSCDV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_UC = 1 << 1,
	XSCDV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_MC = 1 << 2,
	XSCDV_QP_CREATE_DISABLE_SCATTER_TO_CQE = 1 << 3,
	XSCDV_QP_CREATE_ALLOW_SCATTER_TO_CQE = 1 << 4,
};

enum xscdv_qp_init_attr_mask {
	XSCDV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS	= 1 << 0,
	XSCDV_QP_INIT_ATTR_MASK_DC			= 1 << 1,
};

enum xscdv_dc_type {
	XSCDV_DCTYPE_DCT     = 1,
	XSCDV_DCTYPE_DCI,
};

struct xscdv_dc_init_attr {
	enum xscdv_dc_type	dc_type;
	uint64_t dct_access_key;
};

struct xscdv_qp_init_attr {
	uint64_t comp_mask;	/* Use enum xscdv_qp_init_attr_mask */
	uint32_t create_flags;	/* Use enum xsc_qp_create_flags */
	struct xscdv_dc_init_attr  dc_init_attr;
};

struct xsc_wqe_atomic_seg {
	__be64		swap_add;
	__be64		compare;
};

struct xscdv_ctx_allocators {
	void *(*alloc)(size_t size, void *priv_data);
	void (*free)(void *ptr, void *priv_data);
	void *data;
};

enum xscdv_msg_type {
	XSCDV_MSG_OPCODE_SEND		= 0,
	XSCDV_MSG_OPCODE_RDMA_WRITE	= 1,
	XSCDV_MSG_OPCODE_RDMA_READ	= 2,
	XSCDV_MSG_OPCODE_MAD		= 3,
	XSCDV_MSG_OPCODE_RDMA_ACK		= 4,
	XSCDV_MSG_OPCODE_RDMA_ACK_READ	= 5,
	XSCDV_MSG_OPCODE_RDMA_CNP		= 6,
	XSCDV_MSG_OPCODE_RAW		= 7,
	XSCDV_MSG_OPCODE_VIRTIO_NET	= 8,
	XSCDV_MSG_OPCODE_VIRTIO_BLK	= 9,
	XSCDV_MSG_OPCODE_RAW_TPE		= 10,
	XSCDV_MSG_OPCODE_INIT_QP_REQ	= 11,
	XSCDV_MSG_OPCODE_INIT_QP_RSP	= 12,
	XSCDV_MSG_OPCODE_INIT_PATH_REQ	= 13,
	XSCDV_MSG_OPCODE_INIT_PATH_RSP	= 14,
	XSCDV_MSG_OPCODE_SO_WRITE	= 22,

	XSCDV_MSG_OPCODE_RDMA_ATOMIC_CMP_AND_SWAP  = 26,
	XSCDV_MSG_OPCODE_RDMA_ATOMIC_FETCH_AND_ADD = 27,

	XSCDV_MSG_OPCODE_RDMA_ATOMIC_8B_MSK_CMP_AND_SWAP = 31,
	XSCDV_MSG_OPCODE_RDMA_ATOMIC_8B_MSK_FETCH_AND_ADD = 32,
	XSCDV_MSG_OPCODE_RDMA_ATOMIC_4B_MSK_CMP_AND_SWAP = 33,
	XSCDV_MSG_OPCODE_RDMA_ATOMIC_4B_MSK_FETCH_AND_ADD = 34,
};

enum {
	XSCDV_MSG_OPCODE_SEND_DIAMOND_NEXT = 3,
};

struct xscdv_wqe_atomic_64_masked_cs_seg {
	__be64		swap_add;
	__be64		compare;
};

struct xscdv_wqe_atomic_64_masked_fa_seg {
	__be64		add_data;
	__be64		field_boundary;
};

struct xscdv_wqe_atomic_32_masked_cs_seg {
	__be32		swap_data;
	__be32		compare_data;
	__be32		swap_mask;
	__be32		compare_mask;
};

struct xscdv_wqe_atomic_32_masked_fa_seg {
	__be32		add_data;
	__be32		field_boundary;
	__be64		reserved;
};

struct xscdv_cqe {
	uint8_t		placeholder1;
	__le32		data1;
#define XSCDV_CQE_QP_ID_MASK			XSC_GENMASK(14, 0)
#define XSCDV_CQE_SE_MASK			XSC_BIT(1)
#define XSCDV_CQE_HAS_PPH_MASK			XSC_BIT(2)
#define XSCDV_CQE_TYPE_MASK			XSC_BIT(3)
#define XSCDV_CQE_WITH_IMMDT_MASK		XSC_BIT(4)
#define XSCDV_CQE_CSUM_ERR_MASK			XSC_GENMASK(8, 5)
	__le32		imm_data;
	__le32		msg_len;
	__le32		vni;
	__le64		data2;
#define XSCDV_CQE_TS_MASK			XSC_GENMASK_ULL(47, 0)
	__le16		wqe_id;
	uint8_t		placeholder2;
	uint8_t		rsv1;
	__le16		rsv2[2];
	__le16		data3;
#define XSCDV_CQE_OWNER_MASK			XSC_BIT(15)
};

struct xscdv_cqe64 {
	struct xscdv_cqe	cqe;
	uint8_t		padding[32];
};


struct xscdv_wqe_ctrl_seg {
	uint8_t		msg_opcode;
	uint8_t		data0;
#define XSCDV_SWQE_CTRL_SEG_WITH_IMMDT_MASK		XSC_BIT(0)
#define XSCDV_SWQE_CTRL_SEG_CSUM_EN_MASK		XSC_GENMASK(2, 1)
#define XSCDV_SWQE_CTRL_SEG_DS_DATA_NUM_MASK		XSC_GENMASK(7, 3)
	__le16		wqe_id;
	__le32		msg_len;
	__le32		opcode_data;
	uint8_t		data1;
#define XSCDV_SWQE_CTRL_SEG_SE_MASK			XSC_BIT(0)
#define XSCDV_SWQE_CTRL_SEG_CE_MASK			XSC_BIT(1)
#define XSCDV_SWQE_CTRL_SEG_IN_LINE_MASK		XSC_BIT(2)
#define XSCDV_SWQE_CTRL_SEG_FENCE_MODE_MASK		XSC_GENMASK(4, 3)
#define XSCDV_SWQE_CTRL_SEG_MASK_MASK			XSC_GENMASK(6, 5)
	uint8_t		rsv[3];
};

struct xscdv_diamond_wqe_ctrl_seg {
	uint8_t		msg_opcode;
	uint8_t		data0;
#define XSCDV_DIAMOND_SWQE_CTRL_SEG_WITH_IMMDT_MASK	XSC_BIT(0)
#define XSCDV_DIAMOND_SWQE_CTRL_SEG_CSUM_EN_MASK	XSC_GENMASK(2, 1)
#define XSCDV_DIAMOND_SWQE_CTRL_SEG_DS_DATA_NUM_MASK	XSC_GENMASK(7, 3)
	__le16		rsv1;
	__le32		msg_len;
	__le32		opcode_data;
	__le32		data1;
#define XSCDV_DIAMOND_SWQE_CTRL_SEG_SE_MASK		XSC_BIT(0)
#define XSCDV_DIAMOND_SWQE_CTRL_SEG_CE_MASK		XSC_BIT(1)
#define XSCDV_DIAMOND_SWQE_CTRL_SEG_IN_LINE_MASK	XSC_BIT(2)
#define XSCDV_DIAMOND_SWQE_CTRL_SEG_FENCE_MODE_MASK	XSC_GENMASK(4, 3)
#define XSCDV_DIAMOND_SWQE_CTRL_SEG_MASK_MASK		XSC_GENMASK(6, 5)
#define XSCDV_DIAMOND_SWQE_CTRL_SEG_WQE_ID_MASK		XSC_GENMASK(31, 12)
};

struct xscdv_wqe_data_seg {
	union {
		struct {
			uint32_t	data0;
#define XSCDV_WQE_DATA_SEG_LENGTH_MASK			XSC_GENMASK(31, 1)
			__le32		mkey;
			__le64		va;
		};
		struct {
			uint8_t		in_line_data[16];
		};
	};
};

enum xscdv_devx_umem_in_mask {
	XSCDV_UMEM_MASK_DMABUF = 1 << 0,
};

struct xscdv_devx_umem_in {
	void *addr;
	size_t size;
	uint32_t access;
	uint64_t pgsz_bitmap;
	uint64_t comp_mask;
	int dmabuf_fd;
};

struct xscdv_devx_uar {
	__le32	*cq_db;
	__le32	*cq_armdb;
	__le32	*sq_db;
	__le32	*rq_db;
};

struct xscdv_devx_sq_uar {
	void	*sq_db;
	uint32_t dedicated;
};

struct xscdv_andes_cq_doorbell {
	uint32_t raw;
#define XSCDV_ANDES_CQ_DOORBELL_CQ_NEXT_CID_MASK	XSC_GENMASK(15, 0)
#define XSCDV_ANDES_CQ_DOORBELL_CQ_ID_MASK		XSC_GENMASK(30, 16)
#define XSCDV_ANDES_CQ_DOORBELL_ARM_MASK		XSC_BIT(31)
};

struct xscdv_andes_send_doorbell {
	uint32_t raw;
#define XSCDV_ANDES_SEND_DOORBELL_NEXT_PID_MASK		XSC_GENMASK(15, 0)
#define XSCDV_ANDES_SEND_DOORBELL_QP_ID_MASK		XSC_GENMASK(30, 16)
};

union xscdv_andes_recv_doorbell {
	uint32_t raw;
#define XSCDV_ANDES_RECV_DOORBELL_NEXT_PID_MASK		XSC_GENMASK(12, 0)
#define XSCDV_ANDES_RECV_DOORBELL_QP_ID_MASK		XSC_GENMASK(27, 13)
};

struct xscdv_diamond_cqe {
	uint32_t	flags_qp_id_err_code;
#define XSCDV_DIAMOND_CQE_ERR_CODE_MASK		XSC_GENMASK(7, 0)
#define XSCDV_DIAMOND_CQE_QP_ID_MASK		XSC_GENMASK(22, 8)
#define XSCDV_DIAMOND_CQE_FLAGS_MASK		XSC_GENMASK(31, 23)
	uint32_t	imm_data;
	uint32_t	msg_len;
	uint32_t	vni;
	uint32_t	ts_l;
	uint32_t	ts_h;
	uint32_t	wqe_id_rsv_opcode;
#define XSCDV_DIAMOND_CQE_OPCODE_MASK		XSC_GENMASK(7, 0)
#define XSCDV_DIAMOND_CQE_WQE_ID_MASK		XSC_GENMASK(31, 12)
	uint32_t	owner_rsv;
#define XSCDV_DIAMOND_CQE_OWNER_MASK		XSC_BIT(31)
};

struct xscdv_diamond_cqe64 {
	struct xscdv_diamond_cqe	cqe;
	uint8_t		padding[32];
};

struct xscdv_diamond_data_seg {
	uint32_t length;
	uint32_t key;
	uint64_t addr;
};

struct xscdv_diamond_next_cq_doorbell {
	uint64_t raw;
#define XSCDV_DIAMOND_NEXT_CQ_DOORBELL_NEXT_CID_MASK	XSC_GENMASK(22, 0)
#define XSCDV_DIAMOND_NEXT_CQ_DOORBELL_NEXT_CQ_ID_MASK	XSC_GENMASK(38, 23)
#define XSCDV_DIAMOND_NEXT_CQ_DOORBELL_CQ_STA_MASK	XSC_GENMASK(40, 39)
};

struct xscdv_diamond_next_send_doorbell {
	uint64_t raw;
#define XSCDV_DIAMOND_NEXT_SEND_DOORBELL_NEXT_PID_MASK	XSC_GENMASK(20, 0)
#define XSCDV_DIAMOND_NEXT_SEND_DOORBELL_QP_ID_MASK	XSC_GENMASK(36, 21)
};

struct xscdv_diamond_next_recv_doorbell {
	struct {
		uint64_t next_pid:18;
		uint64_t qp_id:16;
	};
	uint64_t raw;
#define XSCDV_DIAMOND_NEXT_RECV_DOORBELL_NEXT_PID_MASK	XSC_GENMASK(17, 0)
#define XSCDV_DIAMOND_NEXT_RECV_DOORBELL_QP_ID_MASK	XSC_GENMASK(33, 18)
};

enum {
	XSCDV_BASE_WQE_SHIF	= 4,
	XSCDV_CQE_SHIFT		= 5,
	XSCDV_RCV_WQE_SHIFT	= 6,
	XSCDV_SND_WQE_SHIFT	= 7,
};

struct xscdv_exp_cmp_swap {
	uint64_t	compare_mask;
	uint64_t	compare_val;
	uint64_t	swap_val;
	uint64_t	swap_mask;
};

struct xscdv_exp_fetch_add {
	uint64_t	add_val;
	uint64_t	field_boundary;
};

struct xscdv_exp_send_wr {
	uint64_t		wr_id;
	struct xscdv_exp_send_wr     *next;
	struct ibv_sge	       *sg_list;
	int			num_sge;
	enum xscdv_msg_type	opcode;
	unsigned int		send_flags;
	/* When opcode is *_WITH_IMM: Immediate data in network byte order.
	 * When opcode is *_INV: Stores the rkey to invalidate
	 */
	union {
		__be32		imm_data;
		uint32_t	invalidate_rkey;
	};
	union {
		struct {
			uint64_t	remote_addr;
			uint32_t	rkey;
		} rdma;
		struct {
			uint64_t	remote_addr;
			uint64_t	compare_add;
			uint64_t	swap;
			uint32_t	rkey;
		} atomic;
		struct {
			struct ibv_ah  *ah;
			uint32_t	remote_qpn;
			uint32_t	remote_qkey;
		} ud;
	} wr;
	union {
		struct {
			uint32_t	remote_srqn;
		} xrc;
	} qp_type;
	union {
		struct {
			struct ibv_mw	*mw;
			uint32_t	rkey;
			struct ibv_mw_bind_info	bind_info;
		} bind_mw;
		struct {
			void		*hdr;
			uint16_t	hdr_sz;
			uint16_t	mss;
		} tso;
	};

	union {
		struct {
			uint32_t        log_arg_sz;
			uint64_t        remote_addr;
			uint32_t        rkey;
			union {
				struct {
					union {
						struct xscdv_exp_cmp_swap cmp_swap;
						struct xscdv_exp_fetch_add fetch_add;
					} op;
				} inline_data;
			} wr_data;
		} masked_atomics;
	} ext_op;
};


#define XSCDV_MS_PF_DEV_ID		0x1111
#define XSCDV_MS_VF_DEV_ID		0x1112
#define XSCDV_MC_PF_DEV_ID_DIAMOND	0x1021
#define XSCDV_MC_PF_DEV_ID_DIAMOND_NEXT	0x1023

static inline
uint8_t xscdv_get_cqe_owner(struct xscdv_cqe *cqe)
{
	return XSC_FIELD_GET(XSCDV_CQE_OWNER_MASK, cqe->data3);
}

static inline
void xscdv_set_cqe_owner(struct xscdv_cqe *cqe, uint8_t val)
{
	cqe->data3 |= XSC_FIELD_PREP(XSCDV_CQE_OWNER_MASK, val & 0x1);
}

struct ibv_cq *xscdv_devx_create_cq(struct ibv_context *context,
				    const struct ibv_cq_init_attr_ex *cq_attr,
				    struct xscdv_devx_umem_in *umem_in);
struct ibv_qp *xscdv_devx_create_qp(struct ibv_context *context,
				    struct ibv_qp_init_attr_ex *attr,
				    struct xscdv_devx_umem_in *umem_in);

int xscdv_devx_destroy_qp(struct ibv_qp *ibqp);
int xscdv_devx_destroy_cq(struct ibv_cq *cq);
struct xscdv_devx_uar *xscdv_devx_alloc_uar(struct ibv_context *context, uint32_t flags);
void xscdv_devx_free_uar(struct xscdv_devx_uar *dv_devx_uar);
int xscdv_devx_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask);
uint32_t xscdv_devx_get_device_id(struct ibv_qp *qp);
struct xscdv_devx_sq_uar *xscdv_devx_alloc_sq_uar(struct ibv_context *context, uint32_t qpn);
void xscdv_devx_free_sq_uar(struct xscdv_devx_sq_uar *uar);
int xscdv_devx_exp_post_send(struct ibv_qp *ibqp,
			struct xscdv_exp_send_wr *wr,
			struct xscdv_exp_send_wr **bad_wr);


#ifdef __cplusplus
}
#endif

#endif /* _XSCDV_H_ */
