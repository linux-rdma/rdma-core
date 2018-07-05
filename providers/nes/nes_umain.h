/*
 * Copyright (c) 2006 - 2010 Intel Corporation.  All rights reserved.
 * Copyright (c) 2006 Open Grid Computing, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * gpl-2.0.txt in the main directory of this source tree, or the
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

#ifndef nes_umain_H
#define nes_umain_H

#include <inttypes.h>
#include <stddef.h>
#include <endian.h>
#include <util/compiler.h>

#include <infiniband/driver.h>
#include <util/udma_barrier.h>

#define PFX	"libnes: "

#define  NES_QP_MMAP		1
#define  NES_QP_VMAP		2

#define NES_DRV_OPT_NO_INLINE_DATA	0x00000080
#define NES_DRV_OPT_NO_DB_READ		0x00001000

#define NES_DEBUG
/* debug levels */
/* must match kernel */
#define NES_DBG_HW          0x00000001
#define NES_DBG_INIT        0x00000002
#define NES_DBG_ISR         0x00000004
#define NES_DBG_PHY         0x00000008
#define NES_DBG_NETDEV      0x00000010
#define NES_DBG_CM          0x00000020
#define NES_DBG_CM1         0x00000040
#define NES_DBG_NIC_RX      0x00000080
#define NES_DBG_NIC_TX      0x00000100
#define NES_DBG_CQP         0x00000200
#define NES_DBG_MMAP        0x00000400
#define NES_DBG_MR          0x00000800
#define NES_DBG_PD          0x00001000
#define NES_DBG_CQ          0x00002000
#define NES_DBG_QP          0x00004000
#define NES_DBG_MOD_QP      0x00008000
#define NES_DBG_AEQ         0x00010000
#define NES_DBG_IW_RX       0x00020000
#define NES_DBG_IW_TX       0x00040000
#define NES_DBG_SHUTDOWN    0x00080000
#define NES_DBG_UD          0x00100000
#define NES_DBG_RSVD1       0x10000000
#define NES_DBG_RSVD2       0x20000000
#define NES_DBG_RSVD3       0x40000000
#define NES_DBG_RSVD4       0x80000000
#define NES_DBG_ALL         0xffffffff

extern unsigned int nes_debug_level;
#ifdef NES_DEBUG
#define nes_debug(level, fmt, args...) \
	if (level & nes_debug_level) \
		fprintf(stderr, PFX "%s[%u]: " fmt, __FUNCTION__, __LINE__, ##args)
#else
#define nes_debug(level, fmt, args...)
#endif

enum nes_cqe_opcode_bits {
	NES_CQE_STAG_VALID = (1<<6),
	NES_CQE_ERROR = (1<<7),
	NES_CQE_SQ = (1<<8),
	NES_CQE_SE = (1<<9),
	NES_CQE_PSH = (1<<29),
	NES_CQE_FIN = (1<<30),
	NES_CQE_VALID = (1<<31),
};

enum nes_cqe_word_idx {
	NES_CQE_PAYLOAD_LENGTH_IDX = 0,
	NES_CQE_COMP_COMP_CTX_LOW_IDX = 2,
	NES_CQE_COMP_COMP_CTX_HIGH_IDX = 3,
	NES_CQE_INV_STAG_IDX = 4,
	NES_CQE_QP_ID_IDX = 5,
	NES_CQE_ERROR_CODE_IDX = 6,
	NES_CQE_OPCODE_IDX = 7,
};

enum nes_cqe_allocate_bits {
	NES_CQE_ALLOC_INC_SELECT = (1<<28),
	NES_CQE_ALLOC_NOTIFY_NEXT = (1<<29),
	NES_CQE_ALLOC_NOTIFY_SE = (1<<30),
	NES_CQE_ALLOC_RESET = (1<<31),
};

enum nes_iwarp_sq_wqe_word_idx {
	NES_IWARP_SQ_WQE_MISC_IDX = 0,
	NES_IWARP_SQ_WQE_TOTAL_PAYLOAD_IDX = 1,
	NES_IWARP_SQ_WQE_COMP_CTX_LOW_IDX = 2,
	NES_IWARP_SQ_WQE_COMP_CTX_HIGH_IDX = 3,
	NES_IWARP_SQ_WQE_COMP_SCRATCH_LOW_IDX = 4,
	NES_IWARP_SQ_WQE_COMP_SCRATCH_HIGH_IDX = 5,
	NES_IWARP_SQ_WQE_INV_STAG_LOW_IDX = 7,
	NES_IWARP_SQ_WQE_RDMA_TO_LOW_IDX = 8,
	NES_IWARP_SQ_WQE_RDMA_TO_HIGH_IDX = 9,
	NES_IWARP_SQ_WQE_RDMA_LENGTH_IDX = 10,
	NES_IWARP_SQ_WQE_RDMA_STAG_IDX = 11,
	NES_IWARP_SQ_WQE_IMM_DATA_START_IDX = 12,
	NES_IWARP_SQ_WQE_FRAG0_LOW_IDX = 16,
	NES_IWARP_SQ_WQE_FRAG0_HIGH_IDX = 17,
	NES_IWARP_SQ_WQE_LENGTH0_IDX = 18,
	NES_IWARP_SQ_WQE_STAG0_IDX = 19,
	NES_IWARP_SQ_WQE_FRAG1_LOW_IDX = 20,
	NES_IWARP_SQ_WQE_FRAG1_HIGH_IDX = 21,
	NES_IWARP_SQ_WQE_LENGTH1_IDX = 22,
	NES_IWARP_SQ_WQE_STAG1_IDX = 23,
	NES_IWARP_SQ_WQE_FRAG2_LOW_IDX = 24,
	NES_IWARP_SQ_WQE_FRAG2_HIGH_IDX = 25,
	NES_IWARP_SQ_WQE_LENGTH2_IDX = 26,
	NES_IWARP_SQ_WQE_STAG2_IDX = 27,
	NES_IWARP_SQ_WQE_FRAG3_LOW_IDX = 28,
	NES_IWARP_SQ_WQE_FRAG3_HIGH_IDX = 29,
	NES_IWARP_SQ_WQE_LENGTH3_IDX = 30,
	NES_IWARP_SQ_WQE_STAG3_IDX = 31,
};

enum nes_iwarp_rq_wqe_word_idx {
	NES_IWARP_RQ_WQE_TOTAL_PAYLOAD_IDX = 1,
	NES_IWARP_RQ_WQE_COMP_CTX_LOW_IDX = 2,
	NES_IWARP_RQ_WQE_COMP_CTX_HIGH_IDX = 3,
	NES_IWARP_RQ_WQE_COMP_SCRATCH_LOW_IDX = 4,
	NES_IWARP_RQ_WQE_COMP_SCRATCH_HIGH_IDX = 5,
	NES_IWARP_RQ_WQE_FRAG0_LOW_IDX = 8,
	NES_IWARP_RQ_WQE_FRAG0_HIGH_IDX = 9,
	NES_IWARP_RQ_WQE_LENGTH0_IDX = 10,
	NES_IWARP_RQ_WQE_STAG0_IDX = 11,
	NES_IWARP_RQ_WQE_FRAG1_LOW_IDX = 12,
	NES_IWARP_RQ_WQE_FRAG1_HIGH_IDX = 13,
	NES_IWARP_RQ_WQE_LENGTH1_IDX = 14,
	NES_IWARP_RQ_WQE_STAG1_IDX = 15,
	NES_IWARP_RQ_WQE_FRAG2_LOW_IDX = 16,
	NES_IWARP_RQ_WQE_FRAG2_HIGH_IDX = 17,
	NES_IWARP_RQ_WQE_LENGTH2_IDX = 18,
	NES_IWARP_RQ_WQE_STAG2_IDX = 19,
	NES_IWARP_RQ_WQE_FRAG3_LOW_IDX = 20,
	NES_IWARP_RQ_WQE_FRAG3_HIGH_IDX = 21,
	NES_IWARP_RQ_WQE_LENGTH3_IDX = 22,
	NES_IWARP_RQ_WQE_STAG3_IDX = 23,
};

enum nes_iwarp_sq_opcodes {
	NES_IWARP_SQ_WQE_STREAMING = (1<<23),
	NES_IWARP_SQ_WQE_IMM_DATA = (1<<28),
	NES_IWARP_SQ_WQE_READ_FENCE = (1<<29),
	NES_IWARP_SQ_WQE_LOCAL_FENCE = (1<<30),
	NES_IWARP_SQ_WQE_SIGNALED_COMPL = (1<<31),
};

enum nes_iwarp_sq_wqe_bits {
	NES_IWARP_SQ_OP_RDMAW = 0,
	NES_IWARP_SQ_OP_RDMAR = 1,
	NES_IWARP_SQ_OP_SEND = 3,
	NES_IWARP_SQ_OP_SENDINV = 4,
	NES_IWARP_SQ_OP_SENDSE = 5,
	NES_IWARP_SQ_OP_SENDSEINV = 6,
	NES_IWARP_SQ_OP_BIND = 8,
	NES_IWARP_SQ_OP_FAST_REG = 9,
	NES_IWARP_SQ_OP_LOCINV = 10,
	NES_IWARP_SQ_OP_RDMAR_LOCINV = 11,
	NES_IWARP_SQ_OP_NOP = 12,
};

enum nes_nic_cqe_word_idx {
	NES_NIC_CQE_ACCQP_ID_IDX = 0,
	NES_NIC_CQE_TAG_PKT_TYPE_IDX = 2,
	NES_NIC_CQE_MISC_IDX = 3,
};

#define NES_NIC_CQE_ERRV_SHIFT 16
enum nes_nic_ev_bits {
	NES_NIC_ERRV_BITS_MODE = (1<<0),
	NES_NIC_ERRV_BITS_IPV4_CSUM_ERR = (1<<1),
	NES_NIC_ERRV_BITS_TCPUDP_CSUM_ERR = (1<<2),
	NES_NIC_ERRV_BITS_WQE_OVERRUN = (1<<3),
	NES_NIC_ERRV_BITS_IPH_ERR = (1<<4),
};

enum nes_nic_cqe_bits {
	NES_NIC_CQE_ERRV_MASK = (0xff<<NES_NIC_CQE_ERRV_SHIFT),
	NES_NIC_CQE_SQ = (1<<24),
	NES_NIC_CQE_ACCQP_PORT = (1<<28),
	NES_NIC_CQE_ACCQP_VALID = (1<<29),
	NES_NIC_CQE_TAG_VALID = (1<<30),
	NES_NIC_CQE_VALID = (1<<31),
};
struct nes_hw_nic_cqe {
	uint32_t cqe_words[4];
};

enum nes_iwarp_cqe_major_code {
	NES_IWARP_CQE_MAJOR_FLUSH = 1,
	NES_IWARP_CQE_MAJOR_DRV = 0x8000
};

enum nes_iwarp_cqe_minor_code {
	NES_IWARP_CQE_MINOR_FLUSH = 1
};

struct nes_hw_qp_wqe {
	uint32_t wqe_words[32];
};

struct nes_hw_cqe {
	uint32_t cqe_words[8];
};

enum nes_uhca_type {
	NETEFFECT_nes
};

struct nes_user_doorbell {
	uint32_t wqe_alloc;
	uint32_t reserved[3];
	uint32_t cqe_alloc;
};

struct nes_udevice {
	struct verbs_device ibv_dev;
	enum nes_uhca_type hca_type;
	int page_size;
};

struct nes_upd {
	struct ibv_pd ibv_pd;
	struct nes_user_doorbell volatile *udoorbell;
	uint32_t pd_id;
	uint32_t db_index;
};

struct nes_uvcontext {
	struct verbs_context ibv_ctx;
	struct nes_upd *nesupd;
	uint32_t max_pds; /* maximum pds allowed for this user process */
	uint32_t max_qps; /* maximum qps allowed for this user process */
	uint32_t wq_size; /* size of the WQs (sq+rq) allocated to the mmaped area */
	uint32_t mcrqf;
	uint8_t virtwq ; /*  flag if to use virt wqs or not */
	uint8_t reserved[3];
};

struct nes_uqp;

struct nes_ucq {
	struct ibv_cq ibv_cq;
	struct nes_hw_cqe volatile *cqes;
	struct verbs_mr vmr;
	pthread_spinlock_t lock;
	uint32_t cq_id;
	uint16_t size;
	uint16_t head;
	uint16_t polled_completions;
	uint8_t is_armed;
	uint8_t skip_arm;
	int arm_sol;
	int skip_sol;
	int comp_vector;
	struct nes_uqp *udqp;
};

struct nes_uqp {
	struct ibv_qp ibv_qp;
	struct nes_hw_qp_wqe volatile *sq_vbase;
	struct nes_hw_qp_wqe volatile *rq_vbase;
	uint32_t qp_id;
	struct nes_ucq *send_cq;
	struct nes_ucq *recv_cq;
	struct	verbs_mr vmr;
	uint32_t nes_drv_opt;
	pthread_spinlock_t lock;
	uint16_t sq_db_index;
	uint16_t sq_head;
	uint16_t sq_tail;
	uint16_t sq_size;
	uint16_t sq_sig_all;
	uint16_t rq_db_index;
	uint16_t rq_head;
	uint16_t rq_tail;
	uint16_t rq_size;
	uint16_t rdma0_msg;
	uint16_t mapping;
	uint16_t qperr;
	uint16_t rsvd;
	uint32_t pending_rcvs;
	struct ibv_recv_wr *pend_rx_wr;
	int nes_ud_sksq_fd;
	void *sksq_shared_ctxt;
	uint64_t send_wr_id[512]; /* IMA send wr_id ring content */
	uint64_t recv_wr_id[512]; /* IMA receive wr_id ring content */
};

#define to_nes_uxxx(xxx, type)                                                 \
	container_of(ib##xxx, struct nes_u##type, ibv_##xxx)

static inline struct nes_udevice *to_nes_udev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct nes_udevice, ibv_dev.device);
}

static inline struct nes_uvcontext *to_nes_uctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct nes_uvcontext, ibv_ctx.context);
}

static inline struct nes_upd *to_nes_upd(struct ibv_pd *ibpd)
{
	return to_nes_uxxx(pd, pd);
}

static inline struct nes_ucq *to_nes_ucq(struct ibv_cq *ibcq)
{
	return to_nes_uxxx(cq, cq);
}

static inline struct nes_uqp *to_nes_uqp(struct ibv_qp *ibqp)
{
	return to_nes_uxxx(qp, qp);
}


/* nes_uverbs.c */
int nes_uquery_device(struct ibv_context *, struct ibv_device_attr *);
int nes_uquery_port(struct ibv_context *, uint8_t, struct ibv_port_attr *);
struct ibv_pd *nes_ualloc_pd(struct ibv_context *);
int nes_ufree_pd(struct ibv_pd *);
struct ibv_mr *nes_ureg_mr(struct ibv_pd *, void *, size_t, int);
int nes_udereg_mr(struct verbs_mr *vmr);
struct ibv_cq *nes_ucreate_cq(struct ibv_context *, int, struct ibv_comp_channel *, int);
int nes_uresize_cq(struct ibv_cq *, int);
int nes_udestroy_cq(struct ibv_cq *);
int nes_upoll_cq(struct ibv_cq *, int, struct ibv_wc *);
int nes_upoll_cq_no_db_read(struct ibv_cq *, int, struct ibv_wc *);
int nes_uarm_cq(struct ibv_cq *, int);
void nes_cq_event(struct ibv_cq *);
struct ibv_srq *nes_ucreate_srq(struct ibv_pd *, struct ibv_srq_init_attr *);
int nes_umodify_srq(struct ibv_srq *, struct ibv_srq_attr *, int);
int nes_udestroy_srq(struct ibv_srq *);
int nes_upost_srq_recv(struct ibv_srq *, struct ibv_recv_wr *, struct ibv_recv_wr **);
struct ibv_qp *nes_ucreate_qp(struct ibv_pd *, struct ibv_qp_init_attr *);
int nes_uquery_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		  int, struct ibv_qp_init_attr *init_attr);
int nes_umodify_qp(struct ibv_qp *, struct ibv_qp_attr *, int);
int nes_udestroy_qp(struct ibv_qp *);
int nes_upost_send(struct ibv_qp *, struct ibv_send_wr *, struct ibv_send_wr **);
int nes_upost_recv(struct ibv_qp *, struct ibv_recv_wr *, struct ibv_recv_wr **);
struct ibv_ah *nes_ucreate_ah(struct ibv_pd *, struct ibv_ah_attr *);
int nes_udestroy_ah(struct ibv_ah *);
int nes_uattach_mcast(struct ibv_qp *, const union ibv_gid *, uint16_t);
int nes_udetach_mcast(struct ibv_qp *, const union ibv_gid *, uint16_t);
void nes_async_event(struct ibv_async_event *event);

extern long int page_size;

#endif				/* nes_umain_H */
