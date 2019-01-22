/*
 * Copyright (c) 2006-2016 Chelsio, Inc. All rights reserved.
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
#include <config.h>

#include <stdio.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/errno.h>
#include <infiniband/opcode.h>
#include <util/compiler.h>
#include "libcxgb4.h"
#include "cxgb4-abi.h"

static void insert_recv_cqe(struct t4_wq *wq, struct t4_cq *cq, u32 srqidx)
{
	union t4_cqe cqe = {};
	__be64 *gen = GEN_ADDR(&cqe);

	PDBG("%s wq %p cq %p sw_cidx %u sw_pidx %u\n", __func__,
	     wq, cq, cq->sw_cidx, cq->sw_pidx);
	cqe.com.header = htobe32(V_CQE_STATUS(T4_ERR_SWFLUSH) |
			         V_CQE_OPCODE(FW_RI_SEND) |
				 V_CQE_TYPE(0) |
				 V_CQE_SWCQE(1) |
				 V_CQE_QPID(wq->sq.qid));
	*gen = htobe64(V_CQE_GENBIT((u64)cq->gen));
	if (srqidx)
		cqe.b64.u.srcqe.abs_rqe_idx = htobe32(srqidx);

	memcpy(Q_ENTRY(cq->sw_queue, cq->sw_pidx), &cqe, CQE_SIZE(&cqe));
	t4_swcq_produce(cq);
}

int c4iw_flush_rq(struct t4_wq *wq, struct t4_cq *cq, int count)
{
	int flushed = 0;
	int in_use = wq->rq.in_use - count;

	BUG_ON(in_use < 0);
	PDBG("%s wq %p cq %p rq.in_use %u skip count %u\n", __func__,
	     wq, cq, wq->rq.in_use, count);
	while (in_use--) {
		insert_recv_cqe(wq, cq, 0);
		flushed++;
	}
	return flushed;
}

static void insert_sq_cqe(struct t4_wq *wq, struct t4_cq *cq,
		          struct t4_swsqe *swcqe)
{
	union t4_cqe cqe = {};
	__be64 *gen = GEN_ADDR(&cqe);

	PDBG("%s wq %p cq %p sw_cidx %u sw_pidx %u\n", __func__,
	     wq, cq, cq->sw_cidx, cq->sw_pidx);
	cqe.com.header = htobe32(V_CQE_STATUS(T4_ERR_SWFLUSH) |
			         V_CQE_OPCODE(swcqe->opcode) |
			         V_CQE_TYPE(1) |
			         V_CQE_SWCQE(1) |
			         V_CQE_QPID(wq->sq.qid));
	CQE_WRID_SQ_IDX(&cqe.com) = swcqe->idx;
	*gen = htobe64(V_CQE_GENBIT((u64)cq->gen));
	memcpy(Q_ENTRY(cq->sw_queue, cq->sw_pidx), &cqe, CQE_SIZE(&cqe));
	t4_swcq_produce(cq);
}

static void advance_oldest_read(struct t4_wq *wq);

void c4iw_flush_sq(struct c4iw_qp *qhp)
{
	unsigned short flushed = 0;
	struct t4_wq *wq = &qhp->wq;
	struct c4iw_cq *chp = to_c4iw_cq(qhp->ibv_qp.send_cq);
	struct t4_cq *cq = &chp->cq;
	int idx;
	struct t4_swsqe *swsqe;
	
	if (wq->sq.flush_cidx == -1)
		wq->sq.flush_cidx = wq->sq.cidx;
	idx = wq->sq.flush_cidx;
	BUG_ON(idx >= wq->sq.size);
	while (idx != wq->sq.pidx) {
		swsqe = &wq->sq.sw_sq[idx];
		BUG_ON(swsqe->flushed);
		swsqe->flushed = 1;
		insert_sq_cqe(wq, cq, swsqe);
		if (wq->sq.oldest_read == swsqe) {
			BUG_ON(swsqe->opcode != FW_RI_READ_REQ);
			advance_oldest_read(wq);
		}
		flushed++;
		if (++idx == wq->sq.size)
			idx = 0;
	}
	wq->sq.flush_cidx += flushed;
	if (wq->sq.flush_cidx >= wq->sq.size)
		wq->sq.flush_cidx -= wq->sq.size;
}

static void flush_completed_wrs(struct t4_wq *wq, struct t4_cq *cq)
{
	struct t4_swsqe *swsqe;
	unsigned short cidx;
 
	if (wq->sq.flush_cidx == -1)
		wq->sq.flush_cidx = wq->sq.cidx;
	cidx = wq->sq.flush_cidx;
	BUG_ON(cidx >= wq->sq.size);

	while (cidx != wq->sq.pidx) {
		swsqe = &wq->sq.sw_sq[cidx];
		if (!swsqe->signaled) {
			if (++cidx == wq->sq.size)
				cidx = 0;
		} else if (swsqe->complete) {

			BUG_ON(swsqe->flushed);

			/*
			 * Insert this completed cqe into the swcq.
			 */
			PDBG("%s moving cqe into swcq sq idx %u cq idx %u\n",
			     __func__, cidx, cq->sw_pidx);

			swsqe->cqe.com.header |= htobe32(V_CQE_SWCQE(1));
			memcpy(Q_ENTRY(cq->sw_queue, cq->sw_pidx),
			       &swsqe->cqe, CQE_SIZE(&swsqe->cqe));
			t4_swcq_produce(cq);
			swsqe->flushed = 1;
			if (++cidx == wq->sq.size)
				cidx = 0;
			wq->sq.flush_cidx = cidx;
		} else
			break;
	}
}

static void create_read_req_cqe(struct t4_wq *wq, union t4_cqe *hw_cqe,
				union t4_cqe *read_cqe)
{
	__be64 *gen = GEN_ADDR(read_cqe);

	memset(read_cqe, 0, sizeof(*read_cqe));
	read_cqe->com.u.scqe.cidx = wq->sq.oldest_read->idx;
	read_cqe->com.len = be32toh(wq->sq.oldest_read->read_len);
	read_cqe->com.header = htobe32(V_CQE_QPID(CQE_QPID(&hw_cqe->com)) |
				 V_CQE_SWCQE(SW_CQE(&hw_cqe->com)) |
				 V_CQE_OPCODE(FW_RI_READ_REQ) |
				 V_CQE_TYPE(1));
	*gen = GEN_BIT(hw_cqe);
}

static void advance_oldest_read(struct t4_wq *wq)
{

	u32 rptr = wq->sq.oldest_read - wq->sq.sw_sq + 1;

	if (rptr == wq->sq.size)
		rptr = 0;
	while (rptr != wq->sq.pidx) {
		wq->sq.oldest_read = &wq->sq.sw_sq[rptr];

		if (wq->sq.oldest_read->opcode == FW_RI_READ_REQ)
			return;
		if (++rptr == wq->sq.size)
			rptr = 0;
	}
	wq->sq.oldest_read = NULL;
}

/*
 * Move all CQEs from the HWCQ into the SWCQ.
 * Deal with out-of-order and/or completions that complete
 * prior unsignalled WRs.
 */
void c4iw_flush_hw_cq(struct c4iw_cq *chp, struct c4iw_qp *flush_qhp)
{
	union t4_cqe *hw_cqe, *swcqe, read_cqe;
	struct t4_cqe_common *com;
	struct c4iw_qp *qhp;
	struct t4_swsqe *swsqe;
	int ret;

	PDBG("%s  cqid 0x%x\n", __func__, chp->cq.cqid);
	ret = t4_next_hw_cqe(&chp->cq, &hw_cqe);
	com = &hw_cqe->com;

	/*
	 * This logic is similar to poll_cq(), but not quite the same
	 * unfortunately.  Need to move pertinent HW CQEs to the SW CQ but
	 * also do any translation magic that poll_cq() normally does.
	 */
	while (!ret) {
		qhp = get_qhp(chp->rhp, CQE_QPID(com));

		/*
		 * drop CQEs with no associated QP
		 */
		if (qhp == NULL)
			goto next_cqe;

		if (flush_qhp != qhp) {
			pthread_spin_lock(&qhp->lock);

			if (qhp->wq.flushed == 1) {
				goto next_cqe;
			}
		}

		if (CQE_OPCODE(com) == FW_RI_TERMINATE)
			goto next_cqe;

		if (CQE_OPCODE(com) == FW_RI_READ_RESP) {

			/*
			 * If we have reached here because of async
			 * event or other error, and have egress error
			 * then drop
			 */
			if (CQE_TYPE(com) == 1) {
				syslog(LOG_CRIT, "%s: got egress error in \
					read-response, dropping!\n", __func__);
				goto next_cqe;
			}

			/*
			 * drop peer2peer RTR reads.
			 */
			if (CQE_WRID_STAG(com) == 1)
				goto next_cqe;

			/*
			 * Eat completions for unsignaled read WRs.
			 */
			if (!qhp->wq.sq.oldest_read->signaled) {
				advance_oldest_read(&qhp->wq);
				goto next_cqe;
			}

			/*
			 * Don't write to the HWCQ, create a new read req CQE
			 * in local memory and move it into the swcq.
			 */
			create_read_req_cqe(&qhp->wq, hw_cqe, &read_cqe);
			hw_cqe = &read_cqe;
			com = &hw_cqe->com;
			advance_oldest_read(&qhp->wq);
		}

		/* if its a SQ completion, then do the magic to move all the
		 * unsignaled and now in-order completions into the swcq.
		 */
		if (SQ_TYPE(com)) {
			int idx = CQE_WRID_SQ_IDX(com);

			BUG_ON(idx >= qhp->wq.sq.size);
			swsqe = &qhp->wq.sq.sw_sq[idx];
			swsqe->cqe = *hw_cqe;
			swsqe->complete = 1;
			flush_completed_wrs(&qhp->wq, &chp->cq);
		} else {
			swcqe = Q_ENTRY(chp->cq.sw_queue, chp->cq.sw_pidx);
			memcpy(swcqe, hw_cqe, CQE_SIZE(hw_cqe));
			swcqe->com.header |= htobe32(V_CQE_SWCQE(1));
			t4_swcq_produce(&chp->cq);
		}
next_cqe:
		t4_hwcq_consume(&chp->cq);
		ret = t4_next_hw_cqe(&chp->cq, &hw_cqe);
		if (qhp && flush_qhp != qhp)
			pthread_spin_unlock(&qhp->lock);
	}
}

static int cqe_completes_wr(union t4_cqe *cqe, struct t4_wq *wq)
{
	struct t4_cqe_common *com = &cqe->com;

	if (CQE_OPCODE(com) == FW_RI_TERMINATE)
		return 0;

	if ((CQE_OPCODE(com) == FW_RI_RDMA_WRITE) && RQ_TYPE(com))
		return 0;

	if ((CQE_OPCODE(com) == FW_RI_READ_RESP) && SQ_TYPE(com))
		return 0;

	if (CQE_SEND_OPCODE(com) && RQ_TYPE(com) && t4_rq_empty(wq))
		return 0;
	return 1;
}

void c4iw_count_rcqes(struct t4_cq *cq, struct t4_wq *wq, int *count)
{
	struct t4_cqe_common *com;
	union t4_cqe *cqe;
	u32 ptr;

	*count = 0;
	ptr = cq->sw_cidx;
	BUG_ON(ptr >= cq->size);
	while (ptr != cq->sw_pidx) {
		cqe = Q_ENTRY(cq->sw_queue, ptr);
		com = &cqe->com;
		if (RQ_TYPE(com) && (CQE_OPCODE(com) != FW_RI_READ_RESP) &&
		    (CQE_QPID(com) == wq->sq.qid) && cqe_completes_wr(cqe, wq))
			(*count)++;
		if (++ptr == cq->size)
			ptr = 0;
	}
	PDBG("%s cq %p count %d\n", __func__, cq, *count);
}

static void dump_cqe(void *arg)
{
	u64 *p = arg;
	syslog(LOG_NOTICE, "cxgb4 err cqe %016llx %016llx %016llx %016llx\n",
	       (long long)be64toh(p[0]),
	       (long long)be64toh(p[1]),
	       (long long)be64toh(p[2]),
	       (long long)be64toh(p[3]));
	if (is_64b_cqe)
		syslog(LOG_NOTICE,
		       "cxgb4 err cqe %016llx %016llx %016llx %016llx\n",
		       (long long)be64toh(p[4]),
		       (long long)be64toh(p[5]),
		       (long long)be64toh(p[6]),
		       (long long)be64toh(p[7]));

}

static void post_pending_srq_wrs(struct t4_srq *srq)
{
	struct t4_srq_pending_wr *pwr;
	u16 idx = 0;

	while (srq->pending_in_use) {

		assert(!srq->sw_rq[srq->pidx].valid);

		pwr = &srq->pending_wrs[srq->pending_cidx];
		srq->sw_rq[srq->pidx].wr_id = pwr->wr_id;
		srq->sw_rq[srq->pidx].valid = 1;

		PDBG("%s posting pending cidx %u pidx %u wq_pidx %u in_use %u rq_size %u wr_id %llx\n",
		      __func__,	srq->cidx, srq->pidx, srq->wq_pidx,
		      srq->in_use, srq->size, (unsigned long long)pwr->wr_id);

		c4iw_copy_wr_to_srq(srq, &pwr->wqe, pwr->len16);
		t4_srq_consume_pending_wr(srq);
		t4_srq_produce(srq, pwr->len16);
		idx += DIV_ROUND_UP(pwr->len16*16, T4_EQ_ENTRY_SIZE);
	}

	if (idx) {
		t4_ring_srq_db(srq, idx, pwr->len16, &pwr->wqe);
		srq->queue[srq->size].status.host_wq_pidx =
			srq->wq_pidx;
	}
}

static u64 reap_srq_cqe(union t4_cqe *hw_cqe, struct t4_srq *srq)
{
	int rel_idx = CQE_ABS_RQE_IDX(&hw_cqe->b64) - srq->rqt_abs_idx;
	u64 wr_id;

	BUG_ON(rel_idx >= srq->size);

	assert(srq->sw_rq[rel_idx].valid);
	srq->sw_rq[rel_idx].valid = 0;
	wr_id = srq->sw_rq[rel_idx].wr_id;

	if (rel_idx == srq->cidx) {
		PDBG("%s in order cqe rel_idx %u cidx %u pidx %u wq_pidx %u in_use %u rq_size %u wr_id %llx\n",
		     __func__, rel_idx, srq->cidx, srq->pidx,
		     srq->wq_pidx, srq->in_use, srq->size,
		     (unsigned long long)srq->sw_rq[rel_idx].wr_id);
		t4_srq_consume(srq);
		while (srq->ooo_count && !srq->sw_rq[srq->cidx].valid) {
			PDBG("%s eat ooo cidx %u pidx %u wq_pidx %u in_use %u rq_size %u ooo_count %u wr_id %llx\n",
			     __func__, srq->cidx, srq->pidx, srq->wq_pidx,
			     srq->in_use, srq->size, srq->ooo_count,
			     (unsigned long long)srq->sw_rq[srq->cidx].wr_id);
			t4_srq_consume_ooo(srq);
		}
		if (srq->ooo_count == 0 && srq->pending_in_use)
			post_pending_srq_wrs(srq);
	} else {
		BUG_ON(srq->in_use == 0);
		PDBG("%s ooo cqe rel_idx %u cidx %u pidx %u wq_pidx %u in_use %u rq_size %u ooo_count %u wr_id %llx\n",
		     __func__, rel_idx, srq->cidx, srq->pidx,
		     srq->wq_pidx, srq->in_use, srq->size, srq->ooo_count,
		     (unsigned long long)srq->sw_rq[rel_idx].wr_id);
		t4_srq_produce_ooo(srq);
	}
	return wr_id;
}

/*
 * poll_cq
 *
 * Caller must:
 *     check the validity of the first CQE,
 *     supply the wq assicated with the qpid.
 *
 * credit: cq credit to return to sge.
 * cqe_flushed: 1 iff the CQE is flushed.
 * cqe: copy of the polled CQE.
 *
 * return value:
 *    0		    CQE returned ok.
 *    -EAGAIN       CQE skipped, try again.
 *    -EOVERFLOW    CQ overflow detected.
 */
static int poll_cq(struct t4_wq *wq, struct t4_cq *cq,
		   union t4_cqe *cqe, u8 *cqe_flushed,
		   u64 *cookie, u32 *credit, struct t4_srq *srq)
{
	int ret = 0;
	union t4_cqe *hw_cqe, read_cqe;
	struct t4_cqe_common *com;

	*cqe_flushed = 0;
	*credit = 0;

	ret = t4_next_cqe(cq, &hw_cqe);
	if (ret)
		return ret;

	com = &hw_cqe->com;

	PDBG("%s CQE OVF %u qpid 0x%0x genbit %u type %u status 0x%0x"
	     " opcode 0x%0x len 0x%0x wrid_hi_stag 0x%x wrid_low_msn 0x%x\n",
	     __func__,
	     is_64b_cqe ? CQE_OVFBIT(&hw_cqe->b64) : CQE_OVFBIT(&hw_cqe->b32),
	     CQE_QPID(com),
	     is_64b_cqe ? CQE_GENBIT(&hw_cqe->b64) : CQE_GENBIT(&hw_cqe->b32),
	     CQE_TYPE(com), CQE_STATUS(com), CQE_OPCODE(com), CQE_LEN(com),
	     CQE_WRID_HI(com), CQE_WRID_LOW(com));

	/*
	 * skip cqe's not affiliated with a QP.
	 */
	if (wq == NULL) {
		ret = -EAGAIN;
		goto skip_cqe;
	}

	/*
	 * skip HW cqe's if wq is already flushed.
	 */
	if (wq->flushed && !SW_CQE(com)) {
		ret = -EAGAIN;
		goto skip_cqe;
	}

	/*
	 * Gotta tweak READ completions:
	 *	1) the cqe doesn't contain the sq_wptr from the wr.
	 *	2) opcode not reflected from the wr.
	 *	3) read_len not reflected from the wr.
	 *	4) T4 HW (for now) inserts target read response failures which
	 * 	   need to be skipped.
	 */
	if (CQE_OPCODE(com) == FW_RI_READ_RESP) {

		/*
		 * If we have reached here because of async
		 * event or other error, and have egress error
		 * then drop
		 */
		if (CQE_TYPE(com) == 1) {
			syslog(LOG_CRIT, "%s: got egress error in \
				read-response, dropping!\n", __func__);
			if (CQE_STATUS(com))
				t4_set_wq_in_error(wq);
			ret = -EAGAIN;
			goto skip_cqe;
		}

		/*
		 * If this is an unsolicited read response, then the read
		 * was generated by the kernel driver as part of peer-2-peer
		 * connection setup, or a target read response failure.
		 * So skip the completion.
		 */
		if (CQE_WRID_STAG(com) == 1) {
			if (CQE_STATUS(com))
				t4_set_wq_in_error(wq);
			ret = -EAGAIN;
			goto skip_cqe;
		}

		/*
		 * Eat completions for unsignaled read WRs.
		 */
		if (!wq->sq.oldest_read->signaled) {
			advance_oldest_read(wq);
			ret = -EAGAIN;
			goto skip_cqe;
		}

		/*
		 * Don't write to the HWCQ, so create a new read req CQE
		 * in local memory.
		 */
		create_read_req_cqe(wq, hw_cqe, &read_cqe);
		hw_cqe = &read_cqe;
		com = &hw_cqe->com;
		advance_oldest_read(wq);
	}

	if (CQE_OPCODE(com) == FW_RI_TERMINATE) {
		ret = -EAGAIN;
		goto skip_cqe;
	}

	if (CQE_STATUS(com) || t4_wq_in_error(wq)) {
		*cqe_flushed = (CQE_STATUS(com) == T4_ERR_SWFLUSH);
		wq->error = 1;

		if (!*cqe_flushed && CQE_STATUS(com))
			dump_cqe(hw_cqe);

		assert(!((*cqe_flushed == 0) && !SW_CQE(com)));
		goto proc_cqe;
	}

	/*
	 * RECV completion.
	 */
	if (RQ_TYPE(com)) {

		/*
		 * HW only validates 4 bits of MSN.  So we must validate that
		 * the MSN in the SEND is the next expected MSN.  If its not,
		 * then we complete this with T4_ERR_MSN and mark the wq in
		 * error.
		 */

		if (srq ? t4_srq_empty(srq) : t4_rq_empty(wq)) {
			t4_set_wq_in_error(wq);
			ret = -EAGAIN;
			goto skip_cqe;
		}
		if (unlikely((CQE_WRID_MSN(com) != (wq->rq.msn)))) {
			t4_set_wq_in_error(wq);
			hw_cqe->com.header |= htobe32(V_CQE_STATUS(T4_ERR_MSN));
			goto proc_cqe;
		}
		goto proc_cqe;
	}

	/*
	 * If we get here its a send completion.
	 *
	 * Handle out of order completion. These get stuffed
	 * in the SW SQ. Then the SW SQ is walked to move any
	 * now in-order completions into the SW CQ.  This handles
	 * 2 cases:
	 *	1) reaping unsignaled WRs when the first subsequent
	 *	   signaled WR is completed.
	 *	2) out of order read completions.
	 */
	if (!SW_CQE(com) && (CQE_WRID_SQ_IDX(com) != wq->sq.cidx)) {
		struct t4_swsqe *swsqe;
		int idx =  CQE_WRID_SQ_IDX(com);

		PDBG("%s out of order completion going in sw_sq at idx %u\n",
		     __func__, idx);
		BUG_ON(idx >= wq->sq.size);
		swsqe = &wq->sq.sw_sq[idx];
		swsqe->cqe = *hw_cqe;
		swsqe->complete = 1;
		ret = -EAGAIN;
		goto flush_wq;
	}

proc_cqe:
	*cqe = *hw_cqe;

	/*
	 * Reap the associated WR(s) that are freed up with this
	 * completion.
	 */
	if (SQ_TYPE(com)) {
		int idx = CQE_WRID_SQ_IDX(com);
		BUG_ON(idx >= wq->sq.size);

		/*
		 * Account for any unsignaled completions completed by
		 * this signaled completion.  In this case, cidx points
		 * to the first unsignaled one, and idx points to the
		 * signaled one.  So adjust in_use based on this delta.
		 * if this is not completing any unsigned wrs, then the
		 * delta will be 0. Handle wrapping also!
		 */
		if (idx < wq->sq.cidx)
			wq->sq.in_use -= wq->sq.size + idx - wq->sq.cidx;
		else
			wq->sq.in_use -= idx - wq->sq.cidx;
		BUG_ON(wq->sq.in_use <= 0 || wq->sq.in_use >= wq->sq.size);

		wq->sq.cidx = (u16)idx;
		PDBG("%s completing sq idx %u\n", __func__, wq->sq.cidx);
		*cookie = wq->sq.sw_sq[wq->sq.cidx].wr_id;
		t4_sq_consume(wq);
	} else {
		if (!srq) {
			PDBG("%s completing rq idx %u\n",
			     __func__, wq->rq.cidx);
			BUG_ON(wq->rq.cidx >= wq->rq.size);
			*cookie = wq->rq.sw_rq[wq->rq.cidx].wr_id;
			BUG_ON(t4_rq_empty(wq));
			t4_rq_consume(wq);
		} else
			*cookie = reap_srq_cqe(hw_cqe, srq);
		wq->rq.msn++;
		goto skip_cqe;
	}

flush_wq:
	/*
	 * Flush any completed cqes that are now in-order.
	 */
	flush_completed_wrs(wq, cq);

skip_cqe:
	if (SW_CQE(com)) {
		PDBG("%s cq %p cqid 0x%x skip sw cqe cidx %u\n",
		     __func__, cq, cq->cqid, cq->sw_cidx);
		t4_swcq_consume(cq);
	} else {
		PDBG("%s cq %p cqid 0x%x skip hw cqe cidx %u\n",
		     __func__, cq, cq->cqid, cq->cidx);
		t4_hwcq_consume(cq);
	}
	return ret;
}

static void generate_srq_limit_event(struct c4iw_srq *srq)
{
	struct ibv_modify_srq cmd;
	struct ibv_srq_attr attr = {};
	int ret;

	srq->armed = 0;
	ret = ibv_cmd_modify_srq(&srq->ibv_srq, &attr, 0, &cmd, sizeof(cmd));
	if (ret)
		fprintf(stderr,
			"Failure to send srq_limit event - ret %d errno %d\n",
			ret, errno);
}

/*
 * Get one cq entry from c4iw and map it to openib.
 *
 * Returns:
 *	0			cqe returned
 *	-ENODATA		EMPTY;
 *	-EAGAIN			caller must try again
 *	any other -errno	fatal error
 */
static int c4iw_poll_cq_one(struct c4iw_cq *chp, struct ibv_wc *wc)
{
	struct c4iw_qp *qhp = NULL;
	struct c4iw_srq *srq = NULL;
	struct t4_cqe_common *com;
	union t4_cqe uninitialized_var(cqe), *rd_cqe;
	struct t4_wq *wq;
	u32 credit = 0;
	u8 cqe_flushed;
	u64 cookie = 0;
	int ret;

	ret = t4_next_cqe(&chp->cq, &rd_cqe);

	if (ret) {
#ifdef STALL_DETECTION
		if (ret == -ENODATA && stall_to && !chp->dumped) {
			struct timeval t;

			gettimeofday(&t, NULL);
			if ((t.tv_sec - chp->time.tv_sec) > stall_to) {
				dump_state();
				chp->dumped = 1;
			}
		}
#endif
		return ret;
	}

#ifdef STALL_DETECTION
	gettimeofday(&chp->time, NULL);
#endif

	qhp = get_qhp(chp->rhp, CQE_QPID(&rd_cqe->com));
	if (!qhp)
		wq = NULL;
	else {
		pthread_spin_lock(&qhp->lock);
		wq = &(qhp->wq);
		srq = qhp->srq;
		if (srq)
			pthread_spin_lock(&srq->lock);
	}
	ret = poll_cq(wq, &(chp->cq), &cqe, &cqe_flushed, &cookie, &credit,
		      srq ? &srq->wq : NULL);
	if (ret)
		goto out;

	com = &cqe.com;
	INC_STAT(cqe);
	wc->wr_id = cookie;
	wc->qp_num = qhp->wq.sq.qid;
	wc->vendor_err = CQE_STATUS(com);
	wc->wc_flags = 0;

	/*
	 * Simulate a SRQ_LIMIT_REACHED HW notification if required.
	 */
	if (srq && !(srq->flags & T4_SRQ_LIMIT_SUPPORT) && srq->armed &&
			srq->wq.in_use < srq->srq_limit)
		generate_srq_limit_event(srq);

	PDBG("%s qpid 0x%x type %d opcode %d status 0x%x wrid hi 0x%x "
	     "lo 0x%x cookie 0x%llx\n", __func__,
	     CQE_QPID(com), CQE_TYPE(com),
	     CQE_OPCODE(com), CQE_STATUS(com), CQE_WRID_HI(com),
	     CQE_WRID_LOW(com), (unsigned long long)cookie);

	if (CQE_TYPE(com) == 0) {
		if (!CQE_STATUS(com))
			wc->byte_len = CQE_LEN(com);
		else
			wc->byte_len = 0;

		switch (CQE_OPCODE(com)) {
		case FW_RI_SEND:
			wc->opcode = IBV_WC_RECV;
			break;
		case FW_RI_SEND_WITH_INV:
		case FW_RI_SEND_WITH_SE_INV:
			wc->opcode = IBV_WC_RECV;
			wc->wc_flags |= IBV_WC_WITH_INV;
			wc->invalidated_rkey = CQE_WRID_STAG(com);
			break;
		case FW_RI_WRITE_IMMEDIATE:
			wc->opcode = IBV_WC_RECV_RDMA_WITH_IMM;
			wc->imm_data = CQE_IMM_DATA(&cqe.b64);
			wc->wc_flags |= IBV_WC_WITH_IMM;
			break;
		default:
			PDBG("Unexpected opcode %d in the CQE received for QPID=0x%0x\n",
			     CQE_OPCODE(com), CQE_QPID(com));
			ret = -EINVAL;
			goto out;
		}
	} else {
		switch (CQE_OPCODE(com)) {
		case FW_RI_RDMA_WRITE:
		case FW_RI_WRITE_IMMEDIATE:
			wc->opcode = IBV_WC_RDMA_WRITE;
			break;
		case FW_RI_READ_REQ:
			wc->opcode = IBV_WC_RDMA_READ;
			wc->byte_len = CQE_LEN(com);
			break;
		case FW_RI_SEND:
		case FW_RI_SEND_WITH_SE:
			wc->opcode = IBV_WC_SEND;
			break;
		case FW_RI_SEND_WITH_INV:
		case FW_RI_SEND_WITH_SE_INV:
			wc->wc_flags |= IBV_WC_WITH_INV;
			wc->opcode = IBV_WC_SEND;
			break;
		case FW_RI_BIND_MW:
			wc->opcode = IBV_WC_BIND_MW;
			break;
		default:
			PDBG("Unexpected opcode %d "
			     "in the CQE received for QPID=0x%0x\n",
			     CQE_OPCODE(com), CQE_QPID(com));
			ret = -EINVAL;
			goto out;
		}
	}

	if (cqe_flushed)
		wc->status = IBV_WC_WR_FLUSH_ERR;
	else {

		switch (CQE_STATUS(com)) {
		case T4_ERR_SUCCESS:
			wc->status = IBV_WC_SUCCESS;
			break;
		case T4_ERR_STAG:
			wc->status = IBV_WC_LOC_ACCESS_ERR;
			break;
		case T4_ERR_PDID:
			wc->status = IBV_WC_LOC_PROT_ERR;
			break;
		case T4_ERR_QPID:
		case T4_ERR_ACCESS:
			wc->status = IBV_WC_LOC_ACCESS_ERR;
			break;
		case T4_ERR_WRAP:
			wc->status = IBV_WC_GENERAL_ERR;
			break;
		case T4_ERR_BOUND:
			wc->status = IBV_WC_LOC_LEN_ERR;
			break;
		case T4_ERR_INVALIDATE_SHARED_MR:
		case T4_ERR_INVALIDATE_MR_WITH_MW_BOUND:
			wc->status = IBV_WC_MW_BIND_ERR;
			break;
		case T4_ERR_CRC:
		case T4_ERR_MARKER:
		case T4_ERR_PDU_LEN_ERR:
		case T4_ERR_OUT_OF_RQE:
		case T4_ERR_DDP_VERSION:
		case T4_ERR_RDMA_VERSION:
		case T4_ERR_DDP_QUEUE_NUM:
		case T4_ERR_MSN:
		case T4_ERR_TBIT:
		case T4_ERR_MO:
		case T4_ERR_MSN_RANGE:
		case T4_ERR_IRD_OVERFLOW:
		case T4_ERR_OPCODE:
		case T4_ERR_INTERNAL_ERR:
			wc->status = IBV_WC_FATAL_ERR;
			break;
		case T4_ERR_SWFLUSH:
			wc->status = IBV_WC_WR_FLUSH_ERR;
			break;
		default:
			PDBG("Unexpected cqe_status 0x%x for QPID=0x%0x\n",
			     CQE_STATUS(com), CQE_QPID(com));
			wc->status = IBV_WC_FATAL_ERR;
		}
	}
	if (wc->status && wc->status != IBV_WC_WR_FLUSH_ERR)
		syslog(LOG_NOTICE, "cxgb4 app err cqid %u qpid %u "
			"type %u opcode %u status 0x%x\n",
			chp->cq.cqid, CQE_QPID(com), CQE_TYPE(com),
			CQE_OPCODE(com), CQE_STATUS(com));
out:
	if (wq) {
		pthread_spin_unlock(&qhp->lock);
		if (srq)
			pthread_spin_unlock(&srq->lock);
	}
	return ret;
}

int c4iw_poll_cq(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc)
{
	struct c4iw_cq *chp;
	int npolled;
	int err = 0;

	chp = to_c4iw_cq(ibcq);

	if (t4_cq_in_error(&chp->cq)) {
		t4_reset_cq_in_error(&chp->cq);
		c4iw_flush_qps(chp->rhp);
	}

	if (!num_entries)
		return t4_cq_notempty(&chp->cq);

	pthread_spin_lock(&chp->lock);
	for (npolled = 0; npolled < num_entries; ++npolled) {
		do {
			err = c4iw_poll_cq_one(chp, wc + npolled);
		} while (err == -EAGAIN);
		if (err)
			break;
	}
	pthread_spin_unlock(&chp->lock);
	return !err || err == -ENODATA ? npolled : err;
}

int c4iw_arm_cq(struct ibv_cq *ibcq, int solicited)
{
	struct c4iw_cq *chp;
	int ret;

	INC_STAT(arm);
	chp = to_c4iw_cq(ibcq);
	pthread_spin_lock(&chp->lock);
	ret = t4_arm_cq(&chp->cq, solicited);
	pthread_spin_unlock(&chp->lock);
	return ret;
}

void c4iw_flush_srqidx(struct c4iw_qp *qhp, u32 srqidx)
{
	struct c4iw_cq *rchp = to_c4iw_cq(qhp->ibv_qp.recv_cq);

	/* create a SRQ RECV CQE for srqidx */
	insert_recv_cqe(&qhp->wq, &rchp->cq, srqidx);
}
