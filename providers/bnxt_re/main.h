/*
 * Broadcom NetXtreme-E User Space RoCE driver
 *
 * Copyright (c) 2015-2017, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Description: Basic device data structures needed for book-keeping
 */

#ifndef __MAIN_H__
#define __MAIN_H__

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <endian.h>
#include <pthread.h>
#include <sys/param.h>

#include <util/mmio.h>
#include <util/util.h>
#include <infiniband/driver.h>
#include <util/udma_barrier.h>

#include "bnxt_re-abi.h"
#include "memory.h"
#include "flush.h"

#define DEV	"bnxt_re : "

#define BNXT_RE_UD_QP_HW_STALL	0x400000

#define CHIP_NUM_57508		0x1750
#define CHIP_NUM_57504		0x1751
#define CHIP_NUM_57502		0x1752
#define CHIP_NUM_58818          0xd818
#define CHIP_NUM_57608          0x1760

#define BNXT_RE_MAX_DO_PACING	0xFFFF
#define BNXT_NSEC_PER_SEC	1000000000UL
#define BNXT_RE_PAGE_MASK(pg_size) (~((__u64)(pg_size) - 1))

struct bnxt_re_chip_ctx {
	__u16 chip_num;
	__u8 chip_rev;
	__u8 chip_metal;
	__u8 gen_p5_p7;
	__u8 gen_p7;
};

struct bnxt_re_dpi {
	__u32 dpindx;
	__u32 wcdpi;
	__u64 *dbpage;
	__u64 *wcdbpg;
};

struct bnxt_re_pd {
	struct ibv_pd ibvpd;
	uint32_t pdid;
};

struct bnxt_re_cq {
	struct ibv_cq ibvcq;
	uint32_t cqid;
	struct bnxt_re_context *cntx;
	struct bnxt_re_queue *cqq;
	struct bnxt_re_dpi *udpi;
	struct bnxt_re_mem *mem;
	struct bnxt_re_mem *resize_mem;
	struct list_head sfhead;
	struct list_head rfhead;
	struct list_head prev_cq_head;
	uint32_t cqe_size;
	uint8_t  phase;
	struct xorshift32_state rand;
	uint32_t mem_handle;
	void *toggle_map;
	uint32_t toggle_size;
	uint8_t resize_tog;
	bool deffered_db_sup;
	uint32_t hw_cqes;
};

struct bnxt_re_push_buffer {
	uintptr_t pbuf; /*push wc buffer */
	uintptr_t  *wqe; /* hwqe addresses */
	uintptr_t ucdb;
	__u32 st_idx;
	__u32 qpid;
	__u16 wcdpi;
	__u16 nbit;
	__u32 tail;
};

enum bnxt_re_push_info_mask {
	BNXT_RE_PUSH_SIZE_MASK  = 0x1FUL,
	BNXT_RE_PUSH_SIZE_SHIFT = 0x18UL
};

struct bnxt_re_db_ppp_hdr {
	struct bnxt_re_db_hdr db_hdr;
	__u64 rsv_psz_pidx;
};

struct bnxt_re_push_rec {
	struct bnxt_re_dpi *udpi;
	struct bnxt_re_push_buffer *pbuf;
	__u32 pbmap; /* only 16 bits in use */
};

struct bnxt_re_wrid {
	struct bnxt_re_psns_ext *psns_ext;
	struct bnxt_re_psns *psns;
	uint64_t wrid;
	uint32_t bytes;
	int next_idx;
	uint32_t st_slot_idx;
	uint8_t slots;
	uint8_t sig;
	uint8_t wc_opcd;
};

struct bnxt_re_qpcap {
	uint32_t max_swr;
	uint32_t max_rwr;
	uint32_t max_ssge;
	uint32_t max_rsge;
	uint32_t max_inline;
	uint8_t	sqsig;
	uint8_t is_atomic_cap;
};

struct bnxt_re_srq {
	struct ibv_srq ibvsrq;
	struct ibv_srq_attr cap;
	struct bnxt_re_context *cntx;
	struct bnxt_re_queue *srqq;
	struct bnxt_re_wrid *srwrid;
	struct bnxt_re_dpi *udpi;
	struct xorshift32_state rand;
	struct bnxt_re_mem *mem;
	uint32_t srqid;
	int start_idx;
	int last_idx;
	bool arm_req;
	uint32_t mem_handle;
	uint32_t toggle_size;
	void *toggle_map;
};

struct bnxt_re_joint_queue {
	struct bnxt_re_context *cntx;
	struct bnxt_re_queue *hwque;
	struct bnxt_re_wrid *swque;
	uint32_t start_idx;
	uint32_t last_idx;
};

/* WR API post send data */
struct bnxt_re_wr_send_qp {
	struct bnxt_re_bsqe     *cur_hdr;
	struct bnxt_re_send     *cur_sqe;
	uint32_t                cur_wqe_cnt;
	uint32_t                cur_slot_cnt;
	uint32_t                cur_swq_idx;
	uint8_t                 cur_opcode;
	bool                    cur_push_wqe;
	unsigned int            cur_push_size;
	int                     error;
};

#define STATIC_WQE_NUM_SLOTS	8
#define SEND_SGE_MIN_SLOTS	3
#define MSG_LEN_ADJ_TO_BYTES	15
#define SLOTS_RSH_TO_NUM_WQE	4

struct bnxt_re_qp {
	struct verbs_qp vqp;
	struct ibv_qp *ibvqp;
	struct bnxt_re_chip_ctx *cctx;
	struct bnxt_re_context *cntx;
	struct xorshift32_state rand;
	struct bnxt_re_joint_queue *jsqq;
	struct bnxt_re_joint_queue *jrqq;
	struct bnxt_re_srq *srq;
	struct bnxt_re_cq *scq;
	struct bnxt_re_cq *rcq;
	struct bnxt_re_dpi *udpi;
	struct bnxt_re_qpcap cap;
	struct bnxt_re_fque_node snode;
	struct bnxt_re_fque_node rnode;
	uint32_t qpid;
	uint32_t tbl_indx;
	uint32_t sq_psn;
	uint32_t pending_db;
	void *pbuf;
	uint64_t wqe_cnt;
	uint16_t mtu;
	uint16_t qpst;
	uint32_t qpmode;
	uint8_t push_st_en;
	uint16_t max_push_sz;
	uint8_t qptyp;
	struct bnxt_re_mem *mem;
	struct bnxt_re_wr_send_qp wr_sq;
};

struct bnxt_re_mr {
	struct verbs_mr vmr;
};

struct bnxt_re_ah {
	struct ibv_ah ibvah;
	uint32_t avid;
};

struct bnxt_re_dev {
	struct verbs_device vdev;
	uint8_t abi_version;
	uint32_t pg_size;

	uint32_t cqe_size;
	uint32_t max_cq_depth;
	struct ibv_device_attr devattr;
};

struct bnxt_re_context {
	struct verbs_context ibvctx;
	struct bnxt_re_dev *rdev;
	uint32_t dev_id;
	uint32_t max_qp;
	struct bnxt_re_chip_ctx cctx;
	uint64_t comp_mask;
	uint32_t max_srq;
	struct bnxt_re_dpi udpi;
	void *shpg;
	uint32_t wqe_mode;
	pthread_mutex_t shlock;
	struct bnxt_re_push_rec *pbrec;
	uint32_t wc_handle;
	void *dbr_page;
	void *bar_map;
};

struct bnxt_re_pacing_data {
	uint32_t do_pacing;
	uint32_t pacing_th;
	uint32_t alarm_th;
	uint32_t fifo_max_depth;
	uint32_t fifo_room_mask;
	uint32_t fifo_room_shift;
	uint32_t grc_reg_offset;
};

struct bnxt_re_mmap_info {
	__u32 type;
	__u32 dpi;
	__u64 alloc_offset;
	__u32 alloc_size;
	__u32 pg_offset;
	__u32 res_id;
};

/* DB ring functions used internally*/
void bnxt_re_ring_rq_db(struct bnxt_re_qp *qp);
void bnxt_re_ring_sq_db(struct bnxt_re_qp *qp);
void bnxt_re_ring_srq_arm(struct bnxt_re_srq *srq);
void bnxt_re_ring_srq_db(struct bnxt_re_srq *srq);
void bnxt_re_ring_cq_db(struct bnxt_re_cq *cq);
void bnxt_re_ring_cq_arm_db(struct bnxt_re_cq *cq, uint8_t aflag);

void bnxt_re_ring_pstart_db(struct bnxt_re_qp *qp,
			    struct bnxt_re_push_buffer *pbuf);
void bnxt_re_ring_pend_db(struct bnxt_re_qp *qp,
			  struct bnxt_re_push_buffer *pbuf);
void bnxt_re_fill_push_wcb(struct bnxt_re_qp *qp,
			   struct bnxt_re_push_buffer *pbuf,
			   uint32_t idx);

int bnxt_re_init_pbuf_list(struct bnxt_re_context *cntx);
void bnxt_re_destroy_pbuf_list(struct bnxt_re_context *cntx);
struct bnxt_re_push_buffer *bnxt_re_get_pbuf(uint8_t *push_st_en,
					     struct bnxt_re_context *cntx);
void bnxt_re_put_pbuf(struct bnxt_re_context *cntx,
		      struct bnxt_re_push_buffer *pbuf);
int bnxt_re_alloc_page(struct ibv_context *ibvctx,
		       struct bnxt_re_mmap_info *minfo,
		       uint32_t *page_handle);
int bnxt_re_notify_drv(struct ibv_context *ibvctx);
int bnxt_re_get_toggle_mem(struct ibv_context *ibvctx,
			   struct bnxt_re_mmap_info *minfo,
			   uint32_t *page_handle);

/* pointer conversion functions*/
static inline struct bnxt_re_dev *to_bnxt_re_dev(struct ibv_device *ibvdev)
{
	return container_of(ibvdev, struct bnxt_re_dev, vdev.device);
}

static inline struct bnxt_re_context *to_bnxt_re_context(
		struct ibv_context *ibvctx)
{
	return container_of(ibvctx, struct bnxt_re_context, ibvctx.context);
}

static inline struct bnxt_re_pd *to_bnxt_re_pd(struct ibv_pd *ibvpd)
{
	return container_of(ibvpd, struct bnxt_re_pd, ibvpd);
}

static inline struct bnxt_re_cq *to_bnxt_re_cq(struct ibv_cq *ibvcq)
{
	return container_of(ibvcq, struct bnxt_re_cq, ibvcq);
}

static inline struct bnxt_re_qp *to_bnxt_re_qp(struct ibv_qp *ibvqp)
{
	struct verbs_qp *vqp = (struct verbs_qp *)ibvqp;

	return container_of(vqp, struct bnxt_re_qp, vqp);
}

static inline struct bnxt_re_srq *to_bnxt_re_srq(struct ibv_srq *ibvsrq)
{
	return container_of(ibvsrq, struct bnxt_re_srq, ibvsrq);
}

static inline struct bnxt_re_ah *to_bnxt_re_ah(struct ibv_ah *ibvah)
{
        return container_of(ibvah, struct bnxt_re_ah, ibvah);
}

static inline uint32_t bnxt_re_get_sqe_sz(void)
{
	return sizeof(struct bnxt_re_bsqe) +
	       sizeof(struct bnxt_re_send) +
	       BNXT_RE_MAX_INLINE_SIZE;
}

static inline uint32_t bnxt_re_get_sqe_hdr_sz(void)
{
	return sizeof(struct bnxt_re_bsqe) + sizeof(struct bnxt_re_send);
}

static inline uint32_t bnxt_re_get_rqe_sz(void)
{
	return sizeof(struct bnxt_re_brqe) +
	       sizeof(struct bnxt_re_rqe) +
	       BNXT_RE_MAX_INLINE_SIZE;
}

static inline uint32_t bnxt_re_get_rqe_hdr_sz(void)
{
	return sizeof(struct bnxt_re_brqe) + sizeof(struct bnxt_re_rqe);
}

static inline uint32_t bnxt_re_get_srqe_sz(void)
{
	return sizeof(struct bnxt_re_brqe) +
	       sizeof(struct bnxt_re_srqe) +
	       BNXT_RE_MAX_INLINE_SIZE;
}

static inline uint32_t bnxt_re_get_srqe_hdr_sz(void)
{
	return sizeof(struct bnxt_re_brqe) + sizeof(struct bnxt_re_srqe);
}

static inline uint32_t bnxt_re_get_cqe_sz(void)
{
	return sizeof(struct bnxt_re_req_cqe) + sizeof(struct bnxt_re_bcqe);
}

static inline uint8_t bnxt_re_ibv_to_bnxt_wr_opcd(uint8_t ibv_opcd)
{
	uint8_t bnxt_opcd;

	switch (ibv_opcd) {
	case IBV_WR_SEND:
		bnxt_opcd = BNXT_RE_WR_OPCD_SEND;
		break;
	case IBV_WR_SEND_WITH_IMM:
		bnxt_opcd = BNXT_RE_WR_OPCD_SEND_IMM;
		break;
	case IBV_WR_RDMA_WRITE:
		bnxt_opcd = BNXT_RE_WR_OPCD_RDMA_WRITE;
		break;
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		bnxt_opcd = BNXT_RE_WR_OPCD_RDMA_WRITE_IMM;
		break;
	case IBV_WR_RDMA_READ:
		bnxt_opcd = BNXT_RE_WR_OPCD_RDMA_READ;
		break;
	case IBV_WR_ATOMIC_CMP_AND_SWP:
		bnxt_opcd = BNXT_RE_WR_OPCD_ATOMIC_CS;
		break;
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		bnxt_opcd = BNXT_RE_WR_OPCD_ATOMIC_FA;
		break;
		/* TODO: Add other opcodes */
	default:
		bnxt_opcd = BNXT_RE_WR_OPCD_INVAL;
		break;
	};

	return bnxt_opcd;
}

static inline uint8_t bnxt_re_ibv_wr_to_wc_opcd(uint8_t wr_opcd)
{
	uint8_t wc_opcd;

	switch (wr_opcd) {
	case IBV_WR_SEND_WITH_IMM:
	case IBV_WR_SEND:
		wc_opcd = IBV_WC_SEND;
		break;
	case IBV_WR_RDMA_WRITE_WITH_IMM:
	case IBV_WR_RDMA_WRITE:
		wc_opcd = IBV_WC_RDMA_WRITE;
		break;
	case IBV_WR_RDMA_READ:
		wc_opcd = IBV_WC_RDMA_READ;
		break;
	case IBV_WR_ATOMIC_CMP_AND_SWP:
		wc_opcd = IBV_WC_COMP_SWAP;
		break;
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		wc_opcd = IBV_WC_FETCH_ADD;
		break;
	default:
		wc_opcd = 0xFF;
		break;
	}

	return wc_opcd;
}

static inline uint8_t bnxt_re_to_ibv_wc_status(uint8_t bnxt_wcst,
					       uint8_t is_req)
{
	uint8_t ibv_wcst;

	if (is_req) {
		switch (bnxt_wcst) {
		case BNXT_RE_REQ_ST_BAD_RESP:
			ibv_wcst = IBV_WC_BAD_RESP_ERR;
			break;
		case BNXT_RE_REQ_ST_LOC_LEN:
			ibv_wcst = IBV_WC_LOC_LEN_ERR;
			break;
		case BNXT_RE_REQ_ST_LOC_QP_OP:
			ibv_wcst = IBV_WC_LOC_QP_OP_ERR;
			break;
		case BNXT_RE_REQ_ST_PROT:
			ibv_wcst = IBV_WC_LOC_PROT_ERR;
			break;
		case BNXT_RE_REQ_ST_MEM_OP:
			ibv_wcst = IBV_WC_MW_BIND_ERR;
			break;
		case BNXT_RE_REQ_ST_REM_INVAL:
			ibv_wcst = IBV_WC_REM_INV_REQ_ERR;
			break;
		case BNXT_RE_REQ_ST_REM_ACC:
			ibv_wcst = IBV_WC_REM_ACCESS_ERR;
			break;
		case BNXT_RE_REQ_ST_REM_OP:
			ibv_wcst = IBV_WC_REM_OP_ERR;
			break;
		case BNXT_RE_REQ_ST_RNR_NAK_XCED:
			ibv_wcst = IBV_WC_RNR_RETRY_EXC_ERR;
			break;
		case BNXT_RE_REQ_ST_TRNSP_XCED:
			ibv_wcst = IBV_WC_RETRY_EXC_ERR;
			break;
		case BNXT_RE_REQ_ST_WR_FLUSH:
			ibv_wcst = IBV_WC_WR_FLUSH_ERR;
			break;
		default:
			ibv_wcst = IBV_WC_GENERAL_ERR;
			break;
		}
	} else {
		switch (bnxt_wcst) {
		case BNXT_RE_RSP_ST_LOC_ACC:
			ibv_wcst = IBV_WC_LOC_ACCESS_ERR;
			break;
		case BNXT_RE_RSP_ST_LOC_LEN:
			ibv_wcst = IBV_WC_LOC_LEN_ERR;
			break;
		case BNXT_RE_RSP_ST_LOC_PROT:
			ibv_wcst = IBV_WC_LOC_PROT_ERR;
			break;
		case BNXT_RE_RSP_ST_LOC_QP_OP:
			ibv_wcst = IBV_WC_LOC_QP_OP_ERR;
			break;
		case BNXT_RE_RSP_ST_MEM_OP:
			ibv_wcst = IBV_WC_MW_BIND_ERR;
			break;
		case BNXT_RE_RSP_ST_REM_INVAL:
			ibv_wcst = IBV_WC_REM_INV_REQ_ERR;
			break;
		case BNXT_RE_RSP_ST_WR_FLUSH:
			ibv_wcst = IBV_WC_WR_FLUSH_ERR;
			break;
		case BNXT_RE_RSP_ST_HW_FLUSH:
			ibv_wcst = IBV_WC_FATAL_ERR;
			break;
		default:
			ibv_wcst = IBV_WC_GENERAL_ERR;
			break;
		}
	}

	return ibv_wcst;
}

static inline uint8_t bnxt_re_is_cqe_valid(struct bnxt_re_cq *cq,
					   struct bnxt_re_bcqe *hdr)
{
	uint8_t valid = 0;

	valid = ((le32toh(hdr->flg_st_typ_ph) &
		  BNXT_RE_BCQE_PH_MASK) == cq->phase);
	udma_from_device_barrier();

	return valid;
}

static inline void bnxt_re_change_cq_phase(struct bnxt_re_cq *cq)
{
	if (!cq->cqq->head)
		cq->phase = (~cq->phase & BNXT_RE_BCQE_PH_MASK);
}

static inline void *bnxt_re_get_swqe(struct bnxt_re_joint_queue *jqq,
				     uint32_t *wqe_idx)
{
	if (wqe_idx)
		*wqe_idx = jqq->start_idx;
	return &jqq->swque[jqq->start_idx];
}

static inline void bnxt_re_jqq_mod_start(struct bnxt_re_joint_queue *jqq,
					 uint32_t idx)
{
	jqq->start_idx = jqq->swque[idx].next_idx;
}

static inline void bnxt_re_jqq_mod_last(struct bnxt_re_joint_queue *jqq,
					uint32_t idx)
{
	jqq->last_idx = jqq->swque[idx].next_idx;
}

static inline uint32_t bnxt_re_init_depth(uint32_t ent, uint64_t cmask)
{
	return cmask & BNXT_RE_COMP_MASK_UCNTX_POW2_DISABLED ?
		ent : roundup_pow_of_two(ent);
}

/* Helper function to copy to push buffers */
static inline void bnxt_re_copy_data_to_pb(struct bnxt_re_push_buffer *pbuf,
					   uint8_t offset, uint32_t idx)
{
	uintptr_t *src;
	uintptr_t *dst;
	int indx;

	for (indx = 0; indx < idx; indx++) {
		dst = (uintptr_t *)(pbuf->pbuf) + 2 * indx + offset;
		src = (uintptr_t *)(pbuf->wqe[indx]);
		mmio_write64(dst, *src);

		dst++;
		src++;
		mmio_write64(dst, *src);
	}
}

static void timespec_sub(const struct timespec *a, const struct timespec *b,
			 struct timespec *res)
{
	res->tv_sec = a->tv_sec - b->tv_sec;
	res->tv_nsec = a->tv_nsec - b->tv_nsec;
	if (res->tv_nsec < 0) {
		res->tv_sec--;
		res->tv_nsec += BNXT_NSEC_PER_SEC;
	}
}

/*
 * Function waits in a busy loop for a given nano seconds
 * The maximum wait period allowed is less than one second
 */
static inline void bnxt_re_sub_sec_busy_wait(uint32_t nsec)
{
	struct timespec start, cur, res;

	if (nsec >= BNXT_NSEC_PER_SEC)
		return;

	if (clock_gettime(CLOCK_REALTIME, &start))
		return;

	while (1) {
		if (clock_gettime(CLOCK_REALTIME, &cur))
			return;
		timespec_sub(&cur, &start, &res);
		if (res.tv_nsec >= nsec)
			break;
	}
}

#define BNXT_RE_MSN_TBL_EN(a) ((a)->comp_mask & BNXT_RE_COMP_MASK_UCNTX_MSN_TABLE_ENABLED)
#endif
