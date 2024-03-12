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
 * Description: Doorbell handling functions.
 */

#include <util/mmio.h>
#include <ccan/minmax.h>
#include <stdlib.h>
#include "main.h"

static uint16_t rnd(struct xorshift32_state *state, uint16_t range)
{
	/* range must be a power of 2 - 1 */
	return (xorshift32(state) & range);
}

static int calculate_fifo_occupancy(struct bnxt_re_context *cntx)
{
	struct bnxt_re_pacing_data *pacing_data =
		(struct bnxt_re_pacing_data *)cntx->dbr_page;
	struct bnxt_re_dev *rdev = cntx->rdev;
	uint32_t read_val, fifo_occup;
	uint64_t fifo_reg_off;
	uint64_t *dbr_map;

	fifo_reg_off =  pacing_data->grc_reg_offset & ~(BNXT_RE_PAGE_MASK(rdev->pg_size));
	dbr_map = cntx->bar_map + fifo_reg_off;

	read_val = *dbr_map;
	fifo_occup = pacing_data->fifo_max_depth -
		((read_val & pacing_data->fifo_room_mask) >>
		 pacing_data->fifo_room_shift);

	return fifo_occup;
}

static void bnxt_re_do_pacing(struct bnxt_re_context *cntx, struct xorshift32_state *state)
{
	struct bnxt_re_pacing_data *pacing_data =
		(struct bnxt_re_pacing_data *)cntx->dbr_page;
	uint32_t fifo_occup;
	int wait_time = 1;

	if (!pacing_data)
		return;

	if (rnd(state, BNXT_RE_MAX_DO_PACING) < pacing_data->do_pacing) {
		while ((fifo_occup = calculate_fifo_occupancy(cntx))
				>  pacing_data->pacing_th) {
			uint32_t usec_wait;

			if (pacing_data->alarm_th && fifo_occup > pacing_data->alarm_th)
				bnxt_re_notify_drv(&cntx->ibvctx.context);

			usec_wait = rnd(state, wait_time - 1);
			if (usec_wait)
				bnxt_re_sub_sec_busy_wait(usec_wait * 1000);
			/* wait time capped at 128 us */
			wait_time = min(wait_time * 2, 128);
		}
	}
}

static void bnxt_re_ring_db(struct bnxt_re_dpi *dpi,
			    struct bnxt_re_db_hdr *hdr)
{
	__le64 *dbval;

	dbval = (__le64 *)&hdr->indx;
	mmio_wc_start();
	mmio_write64_le(dpi->dbpage, *dbval);
	mmio_flush_writes();
}

static void bnxt_re_init_db_hdr(struct bnxt_re_db_hdr *hdr, uint32_t indx,
				uint32_t qid, uint32_t toggle, uint32_t typ)
{
	hdr->indx = htole32(indx | toggle << BNXT_RE_DB_TOGGLE_SHIFT);
	hdr->typ_qid = htole32(qid & BNXT_RE_DB_QID_MASK);
	hdr->typ_qid |= htole32(((typ & BNXT_RE_DB_TYP_MASK) <<
				 BNXT_RE_DB_TYP_SHIFT) | (0x1UL << BNXT_RE_DB_VALID_SHIFT));
}

void bnxt_re_ring_rq_db(struct bnxt_re_qp *qp)
{
	struct bnxt_re_db_hdr hdr;
	uint32_t epoch;
	uint32_t tail;

	bnxt_re_do_pacing(qp->cntx, &qp->rand);
	tail = *qp->jrqq->hwque->dbtail;
	epoch = (qp->jrqq->hwque->flags &  BNXT_RE_FLAG_EPOCH_TAIL_MASK) <<
		BNXT_RE_DB_EPOCH_TAIL_SHIFT;
	bnxt_re_init_db_hdr(&hdr, tail | epoch,
			    qp->qpid, 0, BNXT_RE_QUE_TYPE_RQ);
	bnxt_re_ring_db(qp->udpi, &hdr);
}

void bnxt_re_ring_sq_db(struct bnxt_re_qp *qp)
{
	struct bnxt_re_db_hdr hdr;
	uint32_t epoch;
	uint32_t tail;

	bnxt_re_do_pacing(qp->cntx, &qp->rand);
	tail = *qp->jsqq->hwque->dbtail;
	epoch = (qp->jsqq->hwque->flags & BNXT_RE_FLAG_EPOCH_TAIL_MASK) <<
		BNXT_RE_DB_EPOCH_TAIL_SHIFT;
	bnxt_re_init_db_hdr(&hdr, tail | epoch, qp->qpid, 0, BNXT_RE_QUE_TYPE_SQ);
	bnxt_re_ring_db(qp->udpi, &hdr);
}

void bnxt_re_ring_srq_db(struct bnxt_re_srq *srq)
{
	struct bnxt_re_db_hdr hdr;
	uint32_t epoch;

	bnxt_re_do_pacing(srq->cntx, &srq->rand);
	epoch = (srq->srqq->flags & BNXT_RE_FLAG_EPOCH_TAIL_MASK) <<
		BNXT_RE_DB_EPOCH_TAIL_SHIFT;
	bnxt_re_init_db_hdr(&hdr, srq->srqq->tail | epoch, srq->srqid, 0, BNXT_RE_QUE_TYPE_SRQ);
	bnxt_re_ring_db(srq->udpi, &hdr);
}

void bnxt_re_ring_srq_arm(struct bnxt_re_srq *srq)
{
	struct bnxt_re_db_hdr hdr;

	bnxt_re_do_pacing(srq->cntx, &srq->rand);
	bnxt_re_init_db_hdr(&hdr, srq->cap.srq_limit, srq->srqid, 0,
			    BNXT_RE_QUE_TYPE_SRQ_ARM);
	bnxt_re_ring_db(srq->udpi, &hdr);
}

void bnxt_re_ring_cq_db(struct bnxt_re_cq *cq)
{
	struct bnxt_re_db_hdr hdr;
	uint32_t epoch;

	bnxt_re_do_pacing(cq->cntx, &cq->rand);
	epoch = (cq->cqq->flags & BNXT_RE_FLAG_EPOCH_HEAD_MASK) << BNXT_RE_DB_EPOCH_HEAD_SHIFT;
	bnxt_re_init_db_hdr(&hdr, cq->cqq->head | epoch, cq->cqid, 0, BNXT_RE_QUE_TYPE_CQ);
	bnxt_re_ring_db(cq->udpi, &hdr);
}

void bnxt_re_ring_cq_arm_db(struct bnxt_re_cq *cq, uint8_t aflag)
{
	uint32_t epoch, toggle = 0;
	struct bnxt_re_db_hdr hdr;
	uint32_t *pgptr;

	if (aflag == BNXT_RE_QUE_TYPE_CQ_CUT_ACK) {
		toggle = cq->resize_tog;
	} else {
		pgptr = (uint32_t *)cq->toggle_map;
		if (pgptr)
			toggle = *pgptr;
	}

	bnxt_re_do_pacing(cq->cntx, &cq->rand);
	epoch = (cq->cqq->flags & BNXT_RE_FLAG_EPOCH_HEAD_MASK) <<  BNXT_RE_DB_EPOCH_HEAD_SHIFT;
	bnxt_re_init_db_hdr(&hdr, cq->cqq->head | epoch, cq->cqid, toggle, aflag);
	bnxt_re_ring_db(cq->udpi, &hdr);
}

void bnxt_re_ring_pstart_db(struct bnxt_re_qp *qp,
			    struct bnxt_re_push_buffer *pbuf)
{
	uint64_t key;

	bnxt_re_do_pacing(qp->cntx, &qp->rand);
	key = ((((pbuf->wcdpi & BNXT_RE_DB_PIHI_MASK) <<
		  BNXT_RE_DB_PIHI_SHIFT) | (pbuf->qpid & BNXT_RE_DB_QID_MASK)) |
	       ((BNXT_RE_PUSH_TYPE_START & BNXT_RE_DB_TYP_MASK) <<
		 BNXT_RE_DB_TYP_SHIFT) | (0x1UL << BNXT_RE_DB_VALID_SHIFT));
	key <<= 32;
	key |= ((((__u32)pbuf->wcdpi & BNXT_RE_DB_PILO_MASK) <<
		  BNXT_RE_DB_PILO_SHIFT) | (pbuf->st_idx &
					    BNXT_RE_DB_INDX_MASK));
	udma_to_device_barrier();
	mmio_write64((uintptr_t *)pbuf->ucdb, key);
}

void bnxt_re_ring_pend_db(struct bnxt_re_qp *qp,
			  struct bnxt_re_push_buffer *pbuf)
{
	uint64_t key;

	bnxt_re_do_pacing(qp->cntx, &qp->rand);
	key = ((((pbuf->wcdpi & BNXT_RE_DB_PIHI_MASK) <<
		  BNXT_RE_DB_PIHI_SHIFT) | (pbuf->qpid & BNXT_RE_DB_QID_MASK)) |
	       ((BNXT_RE_PUSH_TYPE_END & BNXT_RE_DB_TYP_MASK) <<
		 BNXT_RE_DB_TYP_SHIFT) | (0x1UL << BNXT_RE_DB_VALID_SHIFT));
	key <<= 32;
	key |= ((((__u32)pbuf->wcdpi & BNXT_RE_DB_PILO_MASK) <<
		  BNXT_RE_DB_PILO_SHIFT) | (pbuf->tail &
					    BNXT_RE_DB_INDX_MASK));
	udma_to_device_barrier();
	mmio_write64((uintptr_t *)pbuf->ucdb, key);
}

void bnxt_re_fill_push_wcb(struct bnxt_re_qp *qp,
			   struct bnxt_re_push_buffer *pbuf, uint32_t idx)
{
	bnxt_re_ring_pstart_db(qp, pbuf);
	mmio_wc_start();
	bnxt_re_copy_data_to_pb(pbuf, 0, idx);
	/* Flush WQE write before push end db. */
	mmio_flush_writes();
	bnxt_re_ring_pend_db(qp, pbuf);
}

int bnxt_re_init_pbuf_list(struct bnxt_re_context *ucntx)
{
	struct bnxt_re_push_buffer *pbuf;
	int indx, wqesz;
	int size, offt;
	uint64_t wcpage;
	uint64_t dbpage;
	void *base;

	size = (sizeof(*ucntx->pbrec) +
		16 * (sizeof(*ucntx->pbrec->pbuf) +
		      sizeof(struct bnxt_re_push_wqe)));
	ucntx->pbrec = calloc(1, size);
	if (!ucntx->pbrec)
		goto out;

	offt = sizeof(*ucntx->pbrec);
	base = ucntx->pbrec;
	ucntx->pbrec->pbuf = (base + offt);
	ucntx->pbrec->pbmap = ~0x00;
	ucntx->pbrec->pbmap &= ~0x7fff; /* 15 bits */
	ucntx->pbrec->udpi = &ucntx->udpi;

	wqesz = sizeof(struct bnxt_re_push_wqe);
	wcpage = (uintptr_t)(ucntx->udpi.wcdbpg);
	dbpage = (uintptr_t)(ucntx->udpi.dbpage);
	offt = sizeof(*ucntx->pbrec->pbuf) * 16;
	base = (char *)ucntx->pbrec->pbuf + offt;
	for (indx = 0; indx < 16; indx++) {
		pbuf = &ucntx->pbrec->pbuf[indx];
		pbuf->wqe = base + indx * wqesz;
		pbuf->pbuf = (uintptr_t)(wcpage + indx * wqesz);
		pbuf->ucdb = (uintptr_t)(dbpage + (indx + 1) * sizeof(uint64_t));
		pbuf->wcdpi = ucntx->udpi.wcdpi;
	}

	return 0;
out:
	return -ENOMEM;
}

struct bnxt_re_push_buffer *bnxt_re_get_pbuf(uint8_t *push_st_en,
					     struct bnxt_re_context *cntx)
{
	struct bnxt_re_push_buffer *pbuf = NULL;
	__u32 old;
	int bit;

	old = cntx->pbrec->pbmap;
	while ((bit = __builtin_ffs(~cntx->pbrec->pbmap)) != 0) {
		if (__sync_bool_compare_and_swap
				(&cntx->pbrec->pbmap,
				 old,
				 (old | 0x01 << (bit - 1))))
			break;
		old = cntx->pbrec->pbmap;
	}

	if (bit) {
		pbuf = &cntx->pbrec->pbuf[bit];
		pbuf->nbit = bit;
	}
	return pbuf;
}

void bnxt_re_put_pbuf(struct bnxt_re_context *cntx,
		      struct bnxt_re_push_buffer *pbuf)
{
	struct bnxt_re_push_rec *pbrec;
	__u32 old;
	int bit;

	pbrec = cntx->pbrec;

	if (pbuf->nbit) {
		bit = pbuf->nbit;
		pbuf->nbit = 0;
		old = pbrec->pbmap;
		while (!__sync_bool_compare_and_swap(&pbrec->pbmap, old,
						     (old & (~(0x01 <<
							       (bit - 1))))))
			old = pbrec->pbmap;
	}
}

void bnxt_re_destroy_pbuf_list(struct bnxt_re_context *cntx)
{
	free(cntx->pbrec);
}
