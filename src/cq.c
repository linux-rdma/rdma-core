/*
 * Copyright (c) 2006 Chelsio, Inc. All rights reserved.
 * Copyright (c) 2006 Open Grid Computing, Inc. All rights reserved.
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
#if HAVE_CONFIG_H
#  include <config.h>
#endif				/* HAVE_CONFIG_H */

#include <stdio.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/errno.h>

#include <infiniband/opcode.h>

#include "iwch.h"
#include "iwch-abi.h"

int iwch_arm_cq(struct ibv_cq *ibcq, int solicited)
{
	int ret;
	struct iwch_cq *chp = to_iwch_cq(ibcq);
	struct iwch_req_notify_cq cmd;

	pthread_spin_lock(&chp->lock);
	cmd.rptr = chp->cq.rptr;
	ret = ibv_cmd_req_notify_cq(ibcq, solicited, &cmd.ibv_cmd, sizeof cmd);
	pthread_spin_unlock(&chp->lock);

	return ret;
}

static inline void create_read_req_cqe(struct t3_rdma_read_wr *wr, 
				       struct t3_cqe *response_cqe, 
			               struct t3_cqe *read_cqe)
{
	PDBG("%s %d enter\n", __FUNCTION__, __LINE__);

	/* 
	 * Now that we found the read response cqe,
	 * we build a proper read request sq cqe to
	 * return to the user, using the read request WR
	 * and bits of the read response cqe.
	 */
	read_cqe->header = 
		V_CQE_STATUS(CQE_STATUS(*response_cqe)) |
		V_CQE_OPCODE(T3_READ_REQ) |
		V_CQE_TYPE(1) |
		V_CQE_QPID(CQE_QPID(*response_cqe));
	read_cqe->header = htonl(read_cqe->header);
	CQE_WRID_SQ_WPTR(*read_cqe) = wr->wrid.id0.hi;
	CQE_WRID_WPTR(*read_cqe) = wr->wrid.id0.low;
	read_cqe->len = wr->local_len;	/* XXX Violates RDMAC but matches IB */
}

static inline int cxio_poll_cq(struct t3_wq *wq, struct t3_cq *cq,
		   struct t3_cqe *cqe, __u8 * cqe_flushed,
		   __u64 * cookie)
{
	int ret = 0;
	struct t3_cqe *rd_cqe, *peek_cqe, read_cqe;
	__u32 peekptr;
	int dontskip = 0;

	*cqe_flushed = 0;
	rd_cqe = cxio_next_cqe(cq);

	PDBG("%s rd_cqe %p\n", __FUNCTION__, rd_cqe);

	/* 
	 * skip cqe's not affiliated with a QP.
	 */
	if (wq == NULL) {
		ret = -1;
		goto skip_cqe;
	}

	/*
	 * If this CQE was already returned (out of order completion)
	 * then silently toss it.
	 */
	if (CQE_OPCODE(*rd_cqe) == T3_READ_RESP && 
	    (!wq->sq_oldest_wr || 
	     (wq->sq_oldest_wr->send.rdmaop != T3_READ_REQ))) {
		PDBG("%s %d dropping old read response cqe\n", 
		    __FUNCTION__, __LINE__);
		ret = -1;
		goto skip_cqe;
	}

	if (CQE_OPCODE(*rd_cqe) == T3_TERMINATE) {
		ret = -1;
		t3_set_wq_in_error(wq);
		goto skip_cqe;
	}

	if (CQE_STATUS(*rd_cqe) || t3_wq_in_error(wq)) {
		ret = 0;
		*cqe_flushed = t3_wq_in_error(wq);
		t3_set_wq_in_error(wq);
	
		/* 
		 * T3A inserts errors into the CQE.  We cannot return 
	 	 * these as work completions.
	 	 */
		/* incoming write failures */
		if ((CQE_OPCODE(*rd_cqe) == T3_RDMA_WRITE) 
		     && RQ_TYPE(*rd_cqe)) {
			ret = -1;
			goto skip_cqe;
		}
		/* incoming read request failures */
		if ((CQE_OPCODE(*rd_cqe) == T3_READ_RESP) && SQ_TYPE(*rd_cqe)) {
			ret = -1;
			goto skip_cqe;
		}

		/* incoming SEND with no receive posted failures */
		if ((CQE_OPCODE(*rd_cqe) == T3_SEND) && RQ_TYPE(*rd_cqe) &&
		    Q_EMPTY(wq->rq_rptr, wq->rq_wptr)) {
			ret = -1;
			goto skip_cqe;
		}
		goto proc_cqe;
	}

	/*
	 * RECV completions.
	 */
	if (RQ_TYPE(*rd_cqe) && (CQE_OPCODE(*rd_cqe) == T3_SEND)) {
		ret = 0;

		/* 
		 * HW only validates 4 bits of MSN.  So we must validate that
		 * the MSN in the SEND is the next expected MSN.  If its not,
		 * then we complete this with TPT_ERR_MSN and mark the wq in 
		 * error.
		 */
		if ((CQE_WRID_MSN(*rd_cqe) != (wq->rq_rptr + 1))) {
			t3_set_wq_in_error(wq);
			(*rd_cqe).header = htonl(htonl((*rd_cqe).header) | 
					         V_CQE_STATUS(TPT_ERR_MSN));
			goto proc_cqe;
		}
		goto proc_cqe;
	}

	/*
	 * If this WQ's oldest pending SQ WR is a read request, then we
	 * must try and find the RQ Read Response which might not
	 * be the next CQE for that WQ on the CQ (reads can complete
	 * out of order). If its not in the CQ yet, then we must return 
	 * "empty".  This ensures we don't complete a subsequent WR 
	 * out of order...
	 */

	/*
	 * XXX This stalls the CQ for all QPs.  Need to redesign this later
	 * to only stall the WQ in question.  
	 */
	if (wq->sq_oldest_wr && 
	    (wq->sq_oldest_wr->send.rdmaop == T3_READ_REQ)) {
		PDBG("%s %d oldest wr is read!\n", __FUNCTION__, __LINE__);
		peekptr = cq->rptr;
		peek_cqe = cq->queue + Q_PTR2IDX(peekptr, cq->size_log2);

		/* 
		 * see if the read response is here already. 
		 */
		while (CQ_VLD_ENTRY(peekptr, cq->size_log2, peek_cqe)) {
			if ((RQ_TYPE(*peek_cqe)) &&
			    (CQE_OPCODE(*peek_cqe) == T3_READ_RESP) &&
			    (CQE_QPID(*peek_cqe) == wq->qpid)) {
				create_read_req_cqe(&wq->sq_oldest_wr->read, 
						    peek_cqe, &read_cqe);
				rd_cqe = &read_cqe;
				if (peekptr != cq->rptr) 
					dontskip = 1;
				ret = 0;
				goto proc_cqe;
			} else {
				++peekptr;
				peek_cqe = cq->queue +
				    Q_PTR2IDX(peekptr, cq->size_log2);
			}
			if (peekptr == cq->rptr) {	/* CQ full */
				t3_set_wq_in_error(wq);
				*cqe_flushed = 1;
				ret = 0;
				goto proc_cqe;
			}
		}

		/*
	 	 * The read response hasn't happened, so we cannot return
		 * any other completion event for this WQ.
	 	 */
		ret = -1;
		goto ret_cqe;
	}
	
proc_cqe:
	*cqe = *rd_cqe;

	/*
	 * Reap the associated WR(s) that are freed up with this
	 * completion.
	 */
	if (SQ_TYPE(*rd_cqe)) {
		wq->sq_rptr = CQE_WRID_SQ_WPTR(*rd_cqe) + 1;
		*cookie = wq->queue[Q_PTR2IDX(CQE_WRID_WPTR(*rd_cqe), 
					      wq->size_log2)
				   ].flit[T3_SQ_COOKIE_FLIT];
		wq->sq_oldest_wr = next_sq_wr(wq, wq->sq_oldest_wr);
	} else {
		*cookie = wq->rq[Q_PTR2IDX(wq->rq_rptr, wq->rq_size_log2)];
		++(wq->rq_rptr);
	}

	if (dontskip)
		goto ret_cqe;
skip_cqe:
	if (SW_CQE(*rd_cqe)) {
		PDBG("skip sw cqe sw_rptr %x\n", cq->sw_rptr);
		++cq->sw_rptr;
	} else {
		PDBG("cq %p cqid %d skip hw cqe rptr %x\n", cq, cq->cqid, 
		    cq->rptr);
		++cq->rptr;
	}

ret_cqe:
	return ret;
}

#ifdef DEBUG
static inline void dump_cqe(struct t3_cqe *wce)
{
	__u64 *data = (__u64 *)wce;
	int size = sizeof(*wce);

	while (size > 0) {
		PDBG("WCE %p: %016" PRIx64"\n", data, ntohll(*data));
		size -= 8;
		data++;
	}
}
#endif

/*
 * Get one cq entry from cxio and map it to openib.
 *
 * Returns:
 * 	0 			EMPTY;
 *	1			cqe returned
 *	-EAGAIN 		caller must try again
 * 	any other -errno	fatal error
 */
int iwch_poll_cq_one(struct iwch_device *rhp, struct iwch_cq *chp,
		     struct ibv_wc *wc)
{
	struct iwch_qp *qhp = NULL;
	struct t3_cqe cqe, *rd_cqe;
	struct t3_wq *wq;
	__u8 cqe_flushed;
	__u64 cookie;
	int ret = 1;

	rd_cqe = cxio_next_cqe(&chp->cq);

	if (!rd_cqe)
		return 0;

	qhp = rhp->qpid2hlp[CQE_QPID(*rd_cqe)];
	if (!qhp)
		wq = NULL;
	else {
		pthread_spin_lock(&qhp->lock);
		wq = &(qhp->wq);
	}
	ret = cxio_poll_cq(wq, &(chp->cq), &cqe, &cqe_flushed, &cookie);
	if (ret) {
		ret = -EAGAIN;
		goto out;
	}
	ret = 1;

	wc->wr_id = cookie;
	wc->qp_num = qhp->wq.qpid;

	PDBG("%s qpid 0x%x type %d opcode %d status 0x%d wrid hi 0x%x "
	     "lo %x cookie %llx\n", __FUNCTION__, CQE_QPID(cqe), CQE_TYPE(cqe),
	     CQE_OPCODE(cqe), CQE_STATUS(cqe), CQE_WRID_HI(cqe),
	     CQE_WRID_LOW(cqe), cookie);

	if (CQE_TYPE(cqe) == 0) {
		if (!CQE_STATUS(cqe))
			wc->byte_len = CQE_LEN(cqe);
		else
			wc->byte_len = 0;
		wc->opcode = IBV_WC_RECV;
	} else {
		switch (CQE_OPCODE(cqe)) {
		case T3_RDMA_WRITE:
			wc->opcode = IBV_WC_RDMA_WRITE;
			break;
		case T3_READ_REQ:
			wc->opcode = IBV_WC_RDMA_READ;
			wc->byte_len = CQE_LEN(cqe);
			break;
		case T3_SEND:
		case T3_SEND_WITH_SE:
			wc->opcode = IBV_WC_SEND;
			break;
		case T3_BIND_MW:
			wc->opcode = IBV_WC_BIND_MW;
			break;

		/* these aren't supported yet */
		case T3_SEND_WITH_INV:
		case T3_SEND_WITH_SE_INV:
		case T3_LOCAL_INV:
		case T3_FAST_REGISTER:
		default:
			PDBG("unexpected opcode(0x%0x) in the CQE received "
			     "for QPID=0x%0x\n", CQE_OPCODE(cqe), 
			     CQE_QPID(cqe));
			ret = -EINVAL;
			goto out;
		}
	}

	if (cqe_flushed) {
		wc->status = IBV_WC_WR_FLUSH_ERR;
	} else {
		
		switch (CQE_STATUS(cqe)) {
		case TPT_ERR_SUCCESS:
			wc->status = IBV_WC_SUCCESS;
			break;
		case TPT_ERR_STAG:
			wc->status = IBV_WC_LOC_ACCESS_ERR;
			break;
		case TPT_ERR_PDID:
			wc->status = IBV_WC_LOC_PROT_ERR;
			break;
		case TPT_ERR_QPID:
		case TPT_ERR_ACCESS:
			wc->status = IBV_WC_LOC_ACCESS_ERR;
			break;
		case TPT_ERR_WRAP:
			wc->status = IBV_WC_GENERAL_ERR;
			break;
		case TPT_ERR_BOUND:
			wc->status = IBV_WC_LOC_LEN_ERR;
			break;
		case TPT_ERR_INVALIDATE_SHARED_MR:
		case TPT_ERR_INVALIDATE_MR_WITH_MW_BOUND:
			wc->status = IBV_WC_MW_BIND_ERR;
			break;
		case TPT_ERR_CRC:
		case TPT_ERR_MARKER:
		case TPT_ERR_PDU_LEN_ERR:
		case TPT_ERR_OUT_OF_RQE:
		case TPT_ERR_DDP_VERSION:
		case TPT_ERR_RDMA_VERSION:
		case TPT_ERR_DDP_QUEUE_NUM:
		case TPT_ERR_MSN:
		case TPT_ERR_TBIT:
		case TPT_ERR_MO:
		case TPT_ERR_MSN_RANGE:
		case TPT_ERR_IRD_OVERFLOW:
		case TPT_ERR_OPCODE:
			wc->status = IBV_WC_FATAL_ERR;
			break;
		case TPT_ERR_SWFLUSH:
			wc->status = IBV_WC_WR_FLUSH_ERR;
			break;
		default:
			PDBG("unexpected cqe_status(0x%0x) for QPID=0x(%0x)\n",
			     CQE_STATUS(cqe), CQE_QPID(cqe));
			ret = -EINVAL;
		}
	}
out:
	if (wq)
		pthread_spin_unlock(&qhp->lock);
	return ret;
}

int t3b_poll_cq(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc)
{
	struct iwch_device *rhp;
	struct iwch_cq *chp;
	int npolled;
	int err = 0;

	chp = to_iwch_cq(ibcq);
	rhp = chp->rhp;

	pthread_spin_lock(&chp->lock);
	for (npolled = 0; npolled < num_entries; ++npolled) {

		/*
	 	 * Because T3 can post CQEs that are _not_ associated
	 	 * with a WR, we might have to poll again after removing
	 	 * one of these.  
		 */
		do {
			err = iwch_poll_cq_one(rhp, chp, wc + npolled);
		} while (err == -EAGAIN);
		if (err <= 0)
			break;
	}
	pthread_spin_unlock(&chp->lock);

	if (err < 0)
		return err;
	else {
		return npolled;
	}
}

int t3a_poll_cq(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc)
{
	int ret;
	struct iwch_cq *chp = to_iwch_cq(ibcq);
	
	pthread_spin_lock(&chp->lock);
	ret = ibv_cmd_poll_cq(ibcq, num_entries, wc);
	pthread_spin_unlock(&chp->lock);
	return ret;
}
