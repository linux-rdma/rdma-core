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
#include <stdlib.h>
#include "main.h"

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
				uint32_t qid, uint32_t typ)
{
	hdr->indx = htole32(indx & BNXT_RE_DB_INDX_MASK);
	hdr->typ_qid = htole32(qid & BNXT_RE_DB_QID_MASK);
	hdr->typ_qid |= htole32(((typ & BNXT_RE_DB_TYP_MASK) <<
				  BNXT_RE_DB_TYP_SHIFT));
}

void bnxt_re_ring_rq_db(struct bnxt_re_qp *qp)
{
	struct bnxt_re_db_hdr hdr;
	uint32_t tail;

	tail = *qp->jrqq->hwque->dbtail;
	bnxt_re_init_db_hdr(&hdr, tail, qp->qpid, BNXT_RE_QUE_TYPE_RQ);
	bnxt_re_ring_db(qp->udpi, &hdr);
}

void bnxt_re_ring_sq_db(struct bnxt_re_qp *qp)
{
	struct bnxt_re_db_hdr hdr;
	uint32_t tail;

	tail = *qp->jsqq->hwque->dbtail;
	bnxt_re_init_db_hdr(&hdr, tail, qp->qpid, BNXT_RE_QUE_TYPE_SQ);
	bnxt_re_ring_db(qp->udpi, &hdr);
}

void bnxt_re_ring_srq_db(struct bnxt_re_srq *srq)
{
	struct bnxt_re_db_hdr hdr;

	bnxt_re_init_db_hdr(&hdr, srq->srqq->tail, srq->srqid,
			    BNXT_RE_QUE_TYPE_SRQ);
	bnxt_re_ring_db(srq->udpi, &hdr);
}

void bnxt_re_ring_srq_arm(struct bnxt_re_srq *srq)
{
	struct bnxt_re_db_hdr hdr;

	bnxt_re_init_db_hdr(&hdr, srq->cap.srq_limit, srq->srqid,
			    BNXT_RE_QUE_TYPE_SRQ_ARM);
	bnxt_re_ring_db(srq->udpi, &hdr);
}

void bnxt_re_ring_cq_db(struct bnxt_re_cq *cq)
{
	struct bnxt_re_db_hdr hdr;

	bnxt_re_init_db_hdr(&hdr, cq->cqq.head, cq->cqid, BNXT_RE_QUE_TYPE_CQ);
	bnxt_re_ring_db(cq->udpi, &hdr);
}

void bnxt_re_ring_cq_arm_db(struct bnxt_re_cq *cq, uint8_t aflag)
{
	struct bnxt_re_db_hdr hdr;

	bnxt_re_init_db_hdr(&hdr, cq->cqq.head, cq->cqid, aflag);
	bnxt_re_ring_db(cq->udpi, &hdr);
}

void bnxt_re_ring_pstart_db(struct bnxt_re_qp *qp,
			    struct bnxt_re_push_buffer *pbuf)
{
	__u64 key;

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
	__u64 key;

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
	__u64 wcpage;
	__u64 dbpage;
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
		pbuf->ucdb = (uintptr_t)(dbpage + (indx + 1) * sizeof(__u64));
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
