/*
 * Copyright (c) 2006-2007 Chelsio, Inc. All rights reserved.
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
#ifndef __CXIO_WR_H__
#define __CXIO_WR_H__

#include <stddef.h>
#include <stdint.h>
#include <endian.h>
#include <util/udma_barrier.h>
#include "firmware_exports.h"

#define T3_MAX_NUM_QP (1<<15)
#define T3_MAX_NUM_CQ (1<<15)
#define T3_MAX_NUM_PD (1<<15)
#define T3_MAX_NUM_STAG (1<<15)
#define T3_MAX_SGE      4
#define T3_MAX_INLINE  64

#define Q_EMPTY(rptr,wptr) ((rptr)==(wptr))
#define Q_FULL(rptr,wptr,size_log2)  ( (((wptr)-(rptr))>>(size_log2)) && \
				       ((rptr)!=(wptr)) )
#define Q_GENBIT(ptr,size_log2) (!(((ptr)>>size_log2)&0x1))
#define Q_FREECNT(rptr,wptr,size_log2) ((1UL<<size_log2)-((wptr)-(rptr)))
#define Q_COUNT(rptr,wptr) ((wptr)-(rptr))
#define Q_PTR2IDX(ptr,size_log2) (ptr & ((1UL<<size_log2)-1))

/* FIXME: Move me to a generic PCI mmio accessor */
#define cpu_to_pci32(val) htole32(val)

#define RING_DOORBELL(doorbell, QPID) { \
	*doorbell = cpu_to_pci32(QPID); \
}

#define SEQ32_GE(x,y) (!( (((uint32_t) (x)) - ((uint32_t) (y))) & 0x80000000 ))

enum t3_wr_flags {
	T3_COMPLETION_FLAG = 0x01,
	T3_NOTIFY_FLAG = 0x02,
	T3_SOLICITED_EVENT_FLAG = 0x04,
	T3_READ_FENCE_FLAG = 0x08,
	T3_LOCAL_FENCE_FLAG = 0x10
} __attribute__ ((packed));

enum t3_wr_opcode {
	T3_WR_BP = FW_WROPCODE_RI_BYPASS,
	T3_WR_SEND = FW_WROPCODE_RI_SEND,
	T3_WR_WRITE = FW_WROPCODE_RI_RDMA_WRITE,
	T3_WR_READ = FW_WROPCODE_RI_RDMA_READ,
	T3_WR_INV_STAG = FW_WROPCODE_RI_LOCAL_INV,
	T3_WR_BIND = FW_WROPCODE_RI_BIND_MW,
	T3_WR_RCV = FW_WROPCODE_RI_RECEIVE,
	T3_WR_INIT = FW_WROPCODE_RI_RDMA_INIT,
	T3_WR_QP_MOD = FW_WROPCODE_RI_MODIFY_QP
} __attribute__ ((packed));

enum t3_rdma_opcode {
	T3_RDMA_WRITE,		/* IETF RDMAP v1.0 ... */
	T3_READ_REQ,
	T3_READ_RESP,
	T3_SEND,
	T3_SEND_WITH_INV,
	T3_SEND_WITH_SE,
	T3_SEND_WITH_SE_INV,
	T3_TERMINATE,
	T3_RDMA_INIT,		/* CHELSIO RI specific ... */
	T3_BIND_MW,
	T3_FAST_REGISTER,
	T3_LOCAL_INV,
	T3_QP_MOD,
	T3_BYPASS
} __attribute__ ((packed));

static inline enum t3_rdma_opcode wr2opcode(enum t3_wr_opcode wrop)
{
	switch (wrop) {
		case T3_WR_BP: return T3_BYPASS;
		case T3_WR_SEND: return T3_SEND;
		case T3_WR_WRITE: return T3_RDMA_WRITE;
		case T3_WR_READ: return T3_READ_REQ;
		case T3_WR_INV_STAG: return T3_LOCAL_INV;
		case T3_WR_BIND: return T3_BIND_MW;
		case T3_WR_INIT: return T3_RDMA_INIT;
		case T3_WR_QP_MOD: return T3_QP_MOD;
		default: break;
	}
	return -1;
}


/* Work request id */
union t3_wrid {
	struct {
		uint32_t hi:32;
		uint32_t low:32;
	} id0;
	uint64_t id1;
};

#define WRID(wrid)      	(wrid.id1)
#define WRID_GEN(wrid)		(wrid.id0.wr_gen)
#define WRID_IDX(wrid)		(wrid.id0.wr_idx)
#define WRID_LO(wrid)		(wrid.id0.wr_lo)

struct fw_riwrh {
	uint32_t op_seop_flags;
	uint32_t gen_tid_len;
};

#define S_FW_RIWR_OP		24
#define M_FW_RIWR_OP		0xff
#define V_FW_RIWR_OP(x)		((x) << S_FW_RIWR_OP)
#define G_FW_RIWR_OP(x)   	((((x) >> S_FW_RIWR_OP)) & M_FW_RIWR_OP)

#define S_FW_RIWR_SOPEOP	22
#define M_FW_RIWR_SOPEOP	0x3
#define V_FW_RIWR_SOPEOP(x)	((x) << S_FW_RIWR_SOPEOP)

#define S_FW_RIWR_FLAGS		8
#define M_FW_RIWR_FLAGS		0x3fffff
#define V_FW_RIWR_FLAGS(x)	((x) << S_FW_RIWR_FLAGS)
#define G_FW_RIWR_FLAGS(x)   	((((x) >> S_FW_RIWR_FLAGS)) & M_FW_RIWR_FLAGS)

#define S_FW_RIWR_TID		8
#define V_FW_RIWR_TID(x)	((x) << S_FW_RIWR_TID)

#define S_FW_RIWR_LEN		0
#define V_FW_RIWR_LEN(x)	((x) << S_FW_RIWR_LEN)

#define S_FW_RIWR_GEN           31
#define V_FW_RIWR_GEN(x)        ((x)  << S_FW_RIWR_GEN)

struct t3_sge {
	uint32_t stag;
	uint32_t len;
	uint64_t to;
};

/* If num_sgle is zero, flit 5+ contains immediate data.*/
struct t3_send_wr {
	struct fw_riwrh wrh;	/* 0 */
	union t3_wrid wrid;	/* 1 */

	enum t3_rdma_opcode rdmaop:8;
	uint32_t reserved:24;	/* 2 */
	uint32_t rem_stag;	/* 2 */
	uint32_t plen;		/* 3 */
	uint32_t num_sgle;
	struct t3_sge sgl[T3_MAX_SGE];	/* 4+ */
};

struct t3_local_inv_wr {
	struct fw_riwrh wrh;	/* 0 */
	union t3_wrid wrid;	/* 1 */
	uint32_t stag;		/* 2 */
	uint32_t reserved3;
};

struct t3_rdma_write_wr {
	struct fw_riwrh wrh;	/* 0 */
	union t3_wrid wrid;	/* 1 */
	enum t3_rdma_opcode rdmaop:8;	/* 2 */
	uint32_t reserved:24;	/* 2 */
	uint32_t stag_sink;
	uint64_t to_sink;	/* 3 */
	uint32_t plen;		/* 4 */
	uint32_t num_sgle;
	struct t3_sge sgl[T3_MAX_SGE];	/* 5+ */
};

struct t3_rdma_read_wr {
	struct fw_riwrh wrh;	/* 0 */
	union t3_wrid wrid;	/* 1 */
	enum t3_rdma_opcode rdmaop:8;	/* 2 */
	uint32_t reserved:24;
	uint32_t rem_stag;
	uint64_t rem_to;	/* 3 */
	uint32_t local_stag;	/* 4 */
	uint32_t local_len;
	uint64_t local_to;	/* 5 */
};

enum t3_addr_type {
	T3_VA_BASED_TO = 0x0,
	T3_ZERO_BASED_TO = 0x1
} __attribute__ ((packed));

enum t3_mem_perms {
	T3_MEM_ACCESS_LOCAL_READ = 0x1,
	T3_MEM_ACCESS_LOCAL_WRITE = 0x2,
	T3_MEM_ACCESS_REM_READ = 0x4,
	T3_MEM_ACCESS_REM_WRITE = 0x8
} __attribute__ ((packed));

struct t3_bind_mw_wr {
	struct fw_riwrh wrh;	/* 0 */
	union t3_wrid wrid;	/* 1 */
	uint32_t reserved:16;
	enum t3_addr_type type:8;
	enum t3_mem_perms perms:8;	/* 2 */
	uint32_t mr_stag;
	uint32_t mw_stag;	/* 3 */
	uint32_t mw_len;
	uint64_t mw_va;		/* 4 */
	uint32_t mr_pbl_addr;	/* 5 */
	uint32_t reserved2:24;
	uint32_t mr_pagesz:8;
};

struct t3_receive_wr {
	struct fw_riwrh wrh;	/* 0 */
	union t3_wrid wrid;	/* 1 */
	uint8_t pagesz[T3_MAX_SGE];
	uint32_t num_sgle;		/* 2 */
	struct t3_sge sgl[T3_MAX_SGE];	/* 3+ */
	uint32_t pbl_addr[T3_MAX_SGE];
};

struct t3_bypass_wr {
	struct fw_riwrh wrh;
	union t3_wrid wrid;	/* 1 */
};

struct t3_modify_qp_wr {
	struct fw_riwrh wrh;	/* 0 */
	union t3_wrid wrid;	/* 1 */
	uint32_t flags;		/* 2 */
	uint32_t quiesce;	/* 2 */
	uint32_t max_ird;	/* 3 */
	uint32_t max_ord;	/* 3 */
	uint64_t sge_cmd;	/* 4 */
	uint64_t ctx1;		/* 5 */
	uint64_t ctx0;		/* 6 */
};

enum t3_modify_qp_flags {
	MODQP_QUIESCE  = 0x01,
	MODQP_MAX_IRD  = 0x02,
	MODQP_MAX_ORD  = 0x04,
	MODQP_WRITE_EC = 0x08,
	MODQP_READ_EC  = 0x10,
};
	

enum t3_mpa_attrs {
	uP_RI_MPA_RX_MARKER_ENABLE = 0x1,
	uP_RI_MPA_TX_MARKER_ENABLE = 0x2,
	uP_RI_MPA_CRC_ENABLE = 0x4,
	uP_RI_MPA_IETF_ENABLE = 0x8
} __attribute__ ((packed));

enum t3_qp_caps {
	uP_RI_QP_RDMA_READ_ENABLE = 0x01,
	uP_RI_QP_RDMA_WRITE_ENABLE = 0x02,
	uP_RI_QP_BIND_ENABLE = 0x04,
	uP_RI_QP_FAST_REGISTER_ENABLE = 0x08,
	uP_RI_QP_STAG0_ENABLE = 0x10
} __attribute__ ((packed));

struct t3_rdma_init_attr {
	uint32_t tid;
	uint32_t qpid;
	uint32_t pdid;
	uint32_t scqid;
	uint32_t rcqid;
	uint32_t rq_addr;
	uint32_t rq_size;
	enum t3_mpa_attrs mpaattrs;
	enum t3_qp_caps qpcaps;
	uint16_t tcp_emss;
	uint32_t ord;
	uint32_t ird;
	uint64_t qp_dma_addr;
	uint32_t qp_dma_size;
	uint8_t rqes_posted;
};

struct t3_rdma_init_wr {
	struct fw_riwrh wrh;	/* 0 */
	union t3_wrid wrid;	/* 1 */
	uint32_t qpid;		/* 2 */
	uint32_t pdid;
	uint32_t scqid;		/* 3 */
	uint32_t rcqid;
	uint32_t rq_addr;	/* 4 */
	uint32_t rq_size;
	enum t3_mpa_attrs mpaattrs:8;	/* 5 */
	enum t3_qp_caps qpcaps:8;
	uint32_t ulpdu_size:16;
	uint32_t rqes_posted;	/* bits 31-1 - reservered */
				/* bit     0 - set if RECV posted */
	uint32_t ord;		/* 6 */
	uint32_t ird;
	uint64_t qp_dma_addr;	/* 7 */
	uint32_t qp_dma_size;	/* 8 */
	uint32_t rsvd;
};

union t3_wr {
	struct t3_send_wr send;
	struct t3_rdma_write_wr write;
	struct t3_rdma_read_wr read;
	struct t3_receive_wr recv;
	struct t3_local_inv_wr local_inv;
	struct t3_bind_mw_wr bind;
	struct t3_bypass_wr bypass;
	struct t3_rdma_init_wr init;
	struct t3_modify_qp_wr qp_mod;
	uint64_t flit[16];
};

#define T3_SQ_CQE_FLIT 	  13
#define T3_SQ_COOKIE_FLIT 14

#define T3_RQ_COOKIE_FLIT 13
#define T3_RQ_CQE_FLIT 	  14

static inline void build_fw_riwrh(struct fw_riwrh *wqe, enum t3_wr_opcode op,
				  enum t3_wr_flags flags, uint8_t genbit, 
				  uint32_t tid, uint8_t len)
{
	wqe->op_seop_flags = htobe32(V_FW_RIWR_OP(op) |
				   V_FW_RIWR_SOPEOP(M_FW_RIWR_SOPEOP) |
				   V_FW_RIWR_FLAGS(flags));
	udma_to_device_barrier();
	wqe->gen_tid_len = htobe32(V_FW_RIWR_GEN(genbit) | V_FW_RIWR_TID(tid) |
				 V_FW_RIWR_LEN(len));
	/* 2nd gen bit... */
        ((union t3_wr *)wqe)->flit[15] = htobe64(genbit);
}

/*
 * T3 ULP2_TX commands
 */
enum t3_utx_mem_op {
	T3_UTX_MEM_READ = 2,
	T3_UTX_MEM_WRITE = 3
};

/* T3 MC7 RDMA TPT entry format */

enum tpt_mem_type {
	TPT_NON_SHARED_MR = 0x0,
	TPT_SHARED_MR = 0x1,
	TPT_MW = 0x2,
	TPT_MW_RELAXED_PROTECTION = 0x3
};

enum tpt_addr_type {
	TPT_ZBTO = 0,
	TPT_VATO = 1
};

enum tpt_mem_perm {
	TPT_LOCAL_READ = 0x8,
	TPT_LOCAL_WRITE = 0x4,
	TPT_REMOTE_READ = 0x2,
	TPT_REMOTE_WRITE = 0x1
};

struct tpt_entry {
	uint32_t valid_stag_pdid;
	uint32_t flags_pagesize_qpid;

	uint32_t rsvd_pbl_addr;
	uint32_t len;
	uint32_t va_hi;
	uint32_t va_low_or_fbo;

	uint32_t rsvd_bind_cnt_or_pstag;
	uint32_t rsvd_pbl_size;
};

#define S_TPT_VALID		31
#define V_TPT_VALID(x)		((x) << S_TPT_VALID)
#define F_TPT_VALID		V_TPT_VALID(1U)

#define S_TPT_STAG_KEY		23
#define M_TPT_STAG_KEY		0xFF
#define V_TPT_STAG_KEY(x)	((x) << S_TPT_STAG_KEY)
#define G_TPT_STAG_KEY(x)	(((x) >> S_TPT_STAG_KEY) & M_TPT_STAG_KEY)

#define S_TPT_STAG_STATE	22
#define V_TPT_STAG_STATE(x)	((x) << S_TPT_STAG_STATE)
#define F_TPT_STAG_STATE	V_TPT_STAG_STATE(1U)

#define S_TPT_STAG_TYPE		20
#define M_TPT_STAG_TYPE		0x3
#define V_TPT_STAG_TYPE(x)	((x) << S_TPT_STAG_TYPE)
#define G_TPT_STAG_TYPE(x)	(((x) >> S_TPT_STAG_TYPE) & M_TPT_STAG_TYPE)

#define S_TPT_PDID		0
#define M_TPT_PDID		0xFFFFF
#define V_TPT_PDID(x)		((x) << S_TPT_PDID)
#define G_TPT_PDID(x)		(((x) >> S_TPT_PDID) & M_TPT_PDID)

#define S_TPT_PERM		28
#define M_TPT_PERM		0xF
#define V_TPT_PERM(x)		((x) << S_TPT_PERM)
#define G_TPT_PERM(x)		(((x) >> S_TPT_PERM) & M_TPT_PERM)

#define S_TPT_REM_INV_DIS	27
#define V_TPT_REM_INV_DIS(x)	((x) << S_TPT_REM_INV_DIS)
#define F_TPT_REM_INV_DIS	V_TPT_REM_INV_DIS(1U)

#define S_TPT_ADDR_TYPE		26
#define V_TPT_ADDR_TYPE(x)	((x) << S_TPT_ADDR_TYPE)
#define F_TPT_ADDR_TYPE		V_TPT_ADDR_TYPE(1U)

#define S_TPT_MW_BIND_ENABLE	25
#define V_TPT_MW_BIND_ENABLE(x)	((x) << S_TPT_MW_BIND_ENABLE)
#define F_TPT_MW_BIND_ENABLE    V_TPT_MW_BIND_ENABLE(1U)

#define S_TPT_PAGE_SIZE		20
#define M_TPT_PAGE_SIZE		0x1F
#define V_TPT_PAGE_SIZE(x)	((x) << S_TPT_PAGE_SIZE)
#define G_TPT_PAGE_SIZE(x)	(((x) >> S_TPT_PAGE_SIZE) & M_TPT_PAGE_SIZE)

#define S_TPT_PBL_ADDR		0
#define M_TPT_PBL_ADDR		0x1FFFFFFF
#define V_TPT_PBL_ADDR(x)	((x) << S_TPT_PBL_ADDR)
#define G_TPT_PBL_ADDR(x)       (((x) >> S_TPT_PBL_ADDR) & M_TPT_PBL_ADDR)

#define S_TPT_QPID		0
#define M_TPT_QPID		0xFFFFF
#define V_TPT_QPID(x)		((x) << S_TPT_QPID)
#define G_TPT_QPID(x)		(((x) >> S_TPT_QPID) & M_TPT_QPID)

#define S_TPT_PSTAG		0
#define M_TPT_PSTAG		0xFFFFFF
#define V_TPT_PSTAG(x)		((x) << S_TPT_PSTAG)
#define G_TPT_PSTAG(x)		(((x) >> S_TPT_PSTAG) & M_TPT_PSTAG)

#define S_TPT_PBL_SIZE		0
#define M_TPT_PBL_SIZE		0xFFFFF
#define V_TPT_PBL_SIZE(x)	((x) << S_TPT_PBL_SIZE)
#define G_TPT_PBL_SIZE(x)	(((x) >> S_TPT_PBL_SIZE) & M_TPT_PBL_SIZE)

/*
 * CQE defs
 */
struct t3_cqe {
	uint32_t header:32;
	uint32_t len:32;
	uint32_t wrid_hi_stag:32;
	uint32_t wrid_low_msn:32;
};

#define S_CQE_OOO	  31
#define M_CQE_OOO	  0x1
#define G_CQE_OOO(x)	  ((((x) >> S_CQE_OOO)) & M_CQE_OOO)
#define V_CEQ_OOO(x)	  ((x)<<S_CQE_OOO)

#define S_CQE_QPID        12
#define M_CQE_QPID        0x7FFFF
#define G_CQE_QPID(x)     ((((x) >> S_CQE_QPID)) & M_CQE_QPID)
#define V_CQE_QPID(x) 	  ((x)<<S_CQE_QPID)

#define S_CQE_SWCQE       11
#define M_CQE_SWCQE       0x1
#define G_CQE_SWCQE(x)    ((((x) >> S_CQE_SWCQE)) & M_CQE_SWCQE)
#define V_CQE_SWCQE(x) 	  ((x)<<S_CQE_SWCQE)

#define S_CQE_GENBIT      10
#define M_CQE_GENBIT      0x1
#define G_CQE_GENBIT(x)   (((x) >> S_CQE_GENBIT) & M_CQE_GENBIT)
#define V_CQE_GENBIT(x)	  ((x)<<S_CQE_GENBIT)

#define S_CQE_STATUS      5
#define M_CQE_STATUS      0x1F
#define G_CQE_STATUS(x)   ((((x) >> S_CQE_STATUS)) & M_CQE_STATUS)
#define V_CQE_STATUS(x)   ((x)<<S_CQE_STATUS)

#define S_CQE_TYPE        4
#define M_CQE_TYPE        0x1
#define G_CQE_TYPE(x)     ((((x) >> S_CQE_TYPE)) & M_CQE_TYPE)
#define V_CQE_TYPE(x)     ((x)<<S_CQE_TYPE)

#define S_CQE_OPCODE      0
#define M_CQE_OPCODE      0xF
#define G_CQE_OPCODE(x)   ((((x) >> S_CQE_OPCODE)) & M_CQE_OPCODE)
#define V_CQE_OPCODE(x)   ((x)<<S_CQE_OPCODE)

#define SW_CQE(x)         (G_CQE_SWCQE(be32toh((x).header)))
#define CQE_OOO(x)        (G_CQE_OOO(be32toh((x).header)))
#define CQE_QPID(x)       (G_CQE_QPID(be32toh((x).header)))
#define CQE_GENBIT(x)     (G_CQE_GENBIT(be32toh((x).header)))
#define CQE_TYPE(x)       (G_CQE_TYPE(be32toh((x).header)))
#define SQ_TYPE(x)	  (CQE_TYPE((x)))
#define RQ_TYPE(x)	  (!CQE_TYPE((x)))
#define CQE_STATUS(x)     (G_CQE_STATUS(be32toh((x).header)))
#define CQE_OPCODE(x)     (G_CQE_OPCODE(be32toh((x).header)))

#define CQE_LEN(x)        (be32toh((x).len))

#define CQE_WRID_HI(x)    (be32toh((x).wrid_hi_stag))
#define CQE_WRID_LOW(x)   (be32toh((x).wrid_low_msn))

/* used for RQ completion processing */
#define CQE_WRID_STAG(x)  (be32toh((x).wrid_hi_stag))
#define CQE_WRID_MSN(x)   (be32toh((x).wrid_low_msn))

/* used for SQ completion processing */
#define CQE_WRID_SQ_WPTR(x)	((x).wrid_hi_stag)
#define CQE_WRID_WPTR(x)   	((x).wrid_low_msn)

#define TPT_ERR_SUCCESS                     0x0
#define TPT_ERR_STAG                        0x1	 /* STAG invalid: either the */
						 /* STAG is offlimt, being 0, */
						 /* or STAG_key mismatch */
#define TPT_ERR_PDID                        0x2	 /* PDID mismatch */
#define TPT_ERR_QPID                        0x3	 /* QPID mismatch */
#define TPT_ERR_ACCESS                      0x4	 /* Invalid access right */
#define TPT_ERR_WRAP                        0x5	 /* Wrap error */
#define TPT_ERR_BOUND                       0x6	 /* base and bounds voilation */
#define TPT_ERR_INVALIDATE_SHARED_MR        0x7	 /* attempt to invalidate a  */
						 /* shared memory region */
#define TPT_ERR_INVALIDATE_MR_WITH_MW_BOUND 0x8	 /* attempt to invalidate a  */
						 /* shared memory region */
#define TPT_ERR_ECC                         0x9	 /* ECC error detected */
#define TPT_ERR_ECC_PSTAG                   0xA	 /* ECC error detected when  */
						 /* reading PSTAG for a MW  */
						 /* Invalidate */
#define TPT_ERR_PBL_ADDR_BOUND              0xB	 /* pbl addr out of bounds:  */
						 /* software error */
#define TPT_ERR_SWFLUSH			    0xC	 /* SW FLUSHED */
#define TPT_ERR_CRC                         0x10 /* CRC error */
#define TPT_ERR_MARKER                      0x11 /* Marker error */
#define TPT_ERR_PDU_LEN_ERR                 0x12 /* invalid PDU length */
#define TPT_ERR_OUT_OF_RQE                  0x13 /* out of RQE */
#define TPT_ERR_DDP_VERSION                 0x14 /* wrong DDP version */
#define TPT_ERR_RDMA_VERSION                0x15 /* wrong RDMA version */
#define TPT_ERR_OPCODE                      0x16 /* invalid rdma opcode */
#define TPT_ERR_DDP_QUEUE_NUM               0x17 /* invalid ddp queue number */
#define TPT_ERR_MSN                         0x18 /* MSN error */
#define TPT_ERR_TBIT                        0x19 /* tag bit not set correctly */
#define TPT_ERR_MO                          0x1A /* MO not 0 for TERMINATE  */
						 /* or READ_REQ */
#define TPT_ERR_MSN_GAP                     0x1B
#define TPT_ERR_MSN_RANGE                   0x1C
#define TPT_ERR_IRD_OVERFLOW                0x1D
#define TPT_ERR_RQE_ADDR_BOUND              0x1E /* RQE addr out of bounds:  */
						 /* software error */
#define TPT_ERR_INTERNAL_ERR                0x1F /* internal error (opcode  */
						 /* mismatch) */

struct t3_swsq {
	uint64_t 		wr_id;
	struct t3_cqe 		cqe;
	uint32_t		sq_wptr;
	uint32_t		read_len;
	int 			opcode;
	int			complete;
	int			signaled;	
};

/*
 * A T3 WQ implements both the SQ and RQ.
 */
struct t3_wq {
	union t3_wr *queue;		/* DMA Mapped work queue */
	uint32_t error;			/* 1 once we go to ERROR */
	uint32_t qpid;
	uint32_t wptr;			/* idx to next available WR slot */
	uint32_t size_log2;		/* total wq size */
	struct t3_swsq *sq;		/* SW SQ */
	struct t3_swsq *oldest_read;	/* tracks oldest pending read */
	uint32_t sq_wptr;		/* sq_wptr - sq_rptr == count of */
	uint32_t sq_rptr;		/* pending wrs */
	uint32_t sq_size_log2;		/* sq size */
	uint64_t *rq;			/* SW RQ (holds consumer wr_ids) */
	uint32_t rq_wptr;		/* rq_wptr - rq_rptr == count of */
	uint32_t rq_rptr;		/* pending wrs */
	uint32_t rq_size_log2;		/* rq size */
	volatile uint32_t *doorbell;	/* mapped adapter doorbell register */
	int flushed;
};

struct t3_cq {
	uint32_t cqid;
	uint32_t rptr;
	uint32_t wptr;
	uint32_t size_log2;
	struct t3_cqe *queue;
	struct t3_cqe *sw_queue;
	uint32_t sw_rptr;
	uint32_t sw_wptr;
	uint32_t memsize;
};

static inline unsigned t3_wq_depth(struct t3_wq *wq)
{
	return (1UL<<wq->size_log2);
}

static inline unsigned t3_sq_depth(struct t3_wq *wq)
{
	return (1UL<<wq->sq_size_log2);
}

static inline unsigned t3_rq_depth(struct t3_wq *wq)
{
	return (1UL<<wq->rq_size_log2);
}

static inline unsigned t3_cq_depth(struct t3_cq *cq)
{
	return (1UL<<cq->size_log2);
}

extern unsigned long iwch_page_size;
extern unsigned long iwch_page_shift;
extern unsigned long iwch_page_mask;

#define PAGE_ALIGN(x) (((x) + iwch_page_mask) & ~iwch_page_mask)

static inline unsigned t3_wq_memsize(struct t3_wq *wq)
{
	return PAGE_ALIGN((1UL<<wq->size_log2) * sizeof (union t3_wr));
}

static inline unsigned t3_cq_memsize(struct t3_cq *cq)
{
	return cq->memsize;
}

static inline unsigned t3_mmid(uint32_t stag)
{
	return (stag>>8);
}

struct t3_cq_status_page {
	uint32_t cq_err;
};

static inline int t3_cq_in_error(struct t3_cq *cq)
{
	return ((struct t3_cq_status_page *)
	       &cq->queue[1 << cq->size_log2])->cq_err;
}

static inline void t3_set_cq_in_error(struct t3_cq *cq)
{
	((struct t3_cq_status_page *)
		&cq->queue[1 << cq->size_log2])->cq_err = 1;
}

static inline void t3_reset_cq_in_error(struct t3_cq *cq)
{
	((struct t3_cq_status_page *)
		&cq->queue[1 << cq->size_log2])->cq_err = 0;
}

static inline int t3_wq_in_error(struct t3_wq *wq)
{
	/*
	 * The kernel sets bit 0 in the first WR of the WQ memory
	 * when the QP moves out of RTS...
	 */
        return (wq->queue->flit[13] & 1);
}

static inline void t3_set_wq_in_error(struct t3_wq *wq)
{
        wq->queue->flit[13] |= 1;
}

static inline int t3_wq_db_enabled(struct t3_wq *wq)
{
	return !(wq->queue->flit[13] & 2);
}

#define CQ_VLD_ENTRY(ptr,size_log2,cqe) (Q_GENBIT(ptr,size_log2) == \
					 CQE_GENBIT(*cqe))

static inline struct t3_cqe *cxio_next_hw_cqe(struct t3_cq *cq)
{
	struct t3_cqe *cqe;

	cqe = cq->queue + (Q_PTR2IDX(cq->rptr, cq->size_log2));
	if (CQ_VLD_ENTRY(cq->rptr, cq->size_log2, cqe))
		return cqe;
	return NULL;
}

static inline struct t3_cqe *cxio_next_sw_cqe(struct t3_cq *cq)
{
	struct t3_cqe *cqe;

	if (!Q_EMPTY(cq->sw_rptr, cq->sw_wptr)) {
		cqe = cq->sw_queue + (Q_PTR2IDX(cq->sw_rptr, cq->size_log2));
		return cqe;
	}
	return NULL;
}

static inline struct t3_cqe *cxio_next_cqe(struct t3_cq *cq)
{
	struct t3_cqe *cqe;

	if (!Q_EMPTY(cq->sw_rptr, cq->sw_wptr)) {
		cqe = cq->sw_queue + (Q_PTR2IDX(cq->sw_rptr, cq->size_log2));
		return cqe;
	}
	cqe = cq->queue + (Q_PTR2IDX(cq->rptr, cq->size_log2));
	if (CQ_VLD_ENTRY(cq->rptr, cq->size_log2, cqe))
		return cqe;
	return NULL;
}

/*
 * Return a ptr to the next read wr in the SWSQ or NULL.
 */
static inline struct t3_swsq *next_read_wr(struct t3_wq *wq)
{
	uint32_t rptr = wq->oldest_read - wq->sq + 1;
	int count = Q_COUNT(rptr, wq->sq_wptr);
	struct t3_swsq *sqp;

	while (count--) {
		sqp = wq->sq + Q_PTR2IDX(rptr, wq->sq_size_log2);

		if (sqp->opcode == T3_READ_REQ)
			return sqp;

		rptr++;
	}
	return NULL;
}
#endif
