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

	bnxt_re_init_db_hdr(&hdr, qp->rqq->tail, qp->qpid, BNXT_RE_QUE_TYPE_RQ);
	bnxt_re_ring_db(qp->udpi, &hdr);
}

void bnxt_re_ring_sq_db(struct bnxt_re_qp *qp)
{
	struct bnxt_re_db_hdr hdr;

	bnxt_re_init_db_hdr(&hdr, qp->sqq->tail, qp->qpid, BNXT_RE_QUE_TYPE_SQ);
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
