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

#include <stdlib.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>

#include "iwch.h"
#include <stdio.h>

static inline int iwch_build_rdma_send(union t3_wr *wqe, struct ibv_send_wr *wr,
				       __u8 *flit_cnt)
{
	int i;
	switch (wr->opcode) {
	case IBV_WR_SEND:
	case IBV_WR_SEND_WITH_IMM:
		if (wr->send_flags & IBV_SEND_SOLICITED)
			wqe->send.rdmaop = T3_SEND_WITH_SE;
		else
			wqe->send.rdmaop = T3_SEND;
		wqe->send.rem_stag = 0;
		break;
#if 0				/* Not currently supported */
	case TYPE_SEND_INVALIDATE:
	case TYPE_SEND_INVALIDATE_IMMEDIATE:
		wqe->send.rdmaop = T3_SEND_WITH_INV;
		wqe->send.rem_stag = htonl(wr->wr.rdma.rkey);
		break;
	case TYPE_SEND_SE_INVALIDATE:
		wqe->send.rdmaop = T3_SEND_WITH_SE_INV;
		wqe->send.rem_stag = htonl(wr->wr.rdma.rkey);
		break;
#endif
	default:
		break;
	}
	if (wr->num_sge > T3_MAX_SGE)
		return -1;
	wqe->send.reserved = 0;
	if (wr->opcode == IBV_WR_SEND_WITH_IMM) {
		wqe->send.plen = 4;
		wqe->send.sgl[0].stag = wr->imm_data;
		wqe->send.sgl[0].len = 0;
		wqe->send.num_sgle = 0;
		*flit_cnt = 5;
	} else {
		wqe->send.plen = 0;
		for (i = 0; i < wr->num_sge; i++) {
			if ((wqe->send.plen + wr->sg_list[i].length) < 
			    wqe->send.plen) {
				return -1;
			}
			wqe->send.plen += wr->sg_list[i].length;
			wqe->send.sgl[i].stag =
			    htonl(wr->sg_list[i].lkey);
			wqe->send.sgl[i].len =
			    htonl(wr->sg_list[i].length);
			wqe->send.sgl[i].to = htonll(wr->sg_list[i].addr);
		}
		wqe->send.plen = htonl(wqe->send.plen);
		wqe->send.num_sgle = htonl(wr->num_sge);
		*flit_cnt = 4 + ((wr->num_sge) << 1);
	}
	return 0;
}

static inline int iwch_build_rdma_write(union t3_wr *wqe, 
					struct ibv_send_wr *wr,
					__u8 *flit_cnt)
{
	int i;
	if (wr->num_sge > T3_MAX_SGE)
		return -1;
	wqe->write.rdmaop = T3_RDMA_WRITE;
	wqe->write.reserved = 0;
	wqe->write.stag_sink = htonl(wr->wr.rdma.rkey);
	wqe->write.to_sink = htonll(wr->wr.rdma.remote_addr);

	wqe->write.num_sgle = wr->num_sge;

	if (wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM) {
		wqe->write.plen = htonl(4);
		wqe->write.sgl[0].stag = htonl(wr->imm_data);
		wqe->write.sgl[0].len = 0;
		wqe->write.num_sgle = 0;
		*flit_cnt = 6;
	} else {
		wqe->write.plen = 0;
		for (i = 0; i < wr->num_sge; i++) {
			if ((wqe->send.plen + wr->sg_list[i].length) < 
			    wqe->send.plen) {
				return -1;
			}
			wqe->write.plen += wr->sg_list[i].length;
			wqe->write.sgl[i].stag =
			    htonl(wr->sg_list[i].lkey);
			wqe->write.sgl[i].len =
			    htonl(wr->sg_list[i].length);
			wqe->write.sgl[i].to =
			    htonll(wr->sg_list[i].addr);
		}
		wqe->write.plen = htonl(wqe->write.plen);
		wqe->write.num_sgle = htonl(wr->num_sge);
		*flit_cnt = 5 + ((wr->num_sge) << 1);
	}
	return 0;
}

static inline int iwch_build_rdma_read(union t3_wr *wqe, struct ibv_send_wr *wr,
				       __u8 *flit_cnt)
{
	if (wr->num_sge > 1)
		return -1;
	wqe->read.rdmaop = T3_READ_REQ;
	wqe->read.reserved = 0;
	wqe->read.rem_stag = htonl(wr->wr.rdma.rkey);
	wqe->read.rem_to = htonll(wr->wr.rdma.remote_addr);
	wqe->read.local_stag = htonl(wr->sg_list[0].lkey);
	wqe->read.local_len = htonl(wr->sg_list[0].length);
	wqe->read.local_to = htonll(wr->sg_list[0].addr);
	*flit_cnt = sizeof(struct t3_rdma_read_wr) >> 3;
	return 0;
}

int t3b_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr, 
		   struct ibv_send_wr **bad_wr)
{
	int err = 0;
	__u8 t3_wr_flit_cnt;
	enum t3_wr_opcode t3_wr_opcode = 0;
	enum t3_wr_flags t3_wr_flags;
	struct iwch_qp *qhp;
	__u32 idx;
	union t3_wr *wqe;
	__u32 num_wrs;

	qhp = to_iwch_qp(ibqp);
	pthread_spin_lock(&qhp->lock);
	if (t3_wq_in_error(&qhp->wq)) {
		iwch_flush_qp(qhp);
		pthread_spin_unlock(&qhp->lock);
		return -1;
	}
	num_wrs = Q_FREECNT(qhp->wq.sq_rptr, qhp->wq.sq_wptr, 
		  qhp->wq.sq_size_log2);
	if (num_wrs <= 0) {
		pthread_spin_unlock(&qhp->lock);
		return -1;
	}
	while (wr) {
		if (num_wrs == 0) {
			err = -1;
			*bad_wr = wr;
			break;
		}
		idx = Q_PTR2IDX(qhp->wq.wptr, qhp->wq.size_log2);
		wqe = (union t3_wr *) (qhp->wq.queue + idx);
		t3_wr_flags = 0;
		if (wr->send_flags & IBV_SEND_SOLICITED)
			t3_wr_flags |= T3_SOLICITED_EVENT_FLAG;
		if (wr->send_flags & IBV_SEND_FENCE)
			t3_wr_flags |= T3_READ_FENCE_FLAG;
		if (wr->send_flags & IBV_SEND_SIGNALED)
			t3_wr_flags |= T3_COMPLETION_FLAG;
		switch (wr->opcode) {
		case IBV_WR_SEND:
		case IBV_WR_SEND_WITH_IMM:
			t3_wr_opcode = T3_WR_SEND;
			err = iwch_build_rdma_send(wqe, wr, &t3_wr_flit_cnt);
			break;
		case IBV_WR_RDMA_WRITE:
		case IBV_WR_RDMA_WRITE_WITH_IMM:
			t3_wr_opcode = T3_WR_WRITE;
			err = iwch_build_rdma_write(wqe, wr, &t3_wr_flit_cnt);
			break;
		case IBV_WR_RDMA_READ:
			PDBG("%s %d - read sq_wptr %u wptr %u cookie %llx\n",
				__FUNCTION__, __LINE__, qhp->wq.sq_wptr,
				qhp->wq.wptr, wr->wr_id);
			t3_wr_opcode = T3_WR_READ;
			t3_wr_flags = 0; /* XXX */
			err = iwch_build_rdma_read(wqe, wr, &t3_wr_flit_cnt);
			break;
		default:
			PDBG("iwch_post_sendq: post of type=0x%0x TBD!\n",
			     wr->opcode);
			err = -1;
		}
		if (err) {
			*bad_wr = wr;
			break;
		}
		wqe->send.wrid.id0.hi = qhp->wq.sq_wptr;
		wqe->send.wrid.id0.low = qhp->wq.wptr;
		wqe->flit[T3_SQ_COOKIE_FLIT] = wr->wr_id;
		build_fw_riwrh((void *) wqe, t3_wr_opcode, t3_wr_flags,
			       Q_GENBIT(qhp->wq.wptr, qhp->wq.size_log2),
			       0, t3_wr_flit_cnt);
		PDBG("%s %d cookie %llx idx 0x%x sq_wptr %x sw_rptr "
		     "%x wqe %p opcode %d\n", 
		     __FUNCTION__, __LINE__, wr->wr_id, idx, 
		     qhp->wq.sq_wptr, qhp->wq.sq_rptr, wqe, t3_wr_opcode);
		if (!qhp->wq.sq_oldest_wr) {
			qhp->wq.sq_oldest_wr = wqe;
			PDBG("%s %d sq_oldest_wr %p\n", __FUNCTION__, __LINE__,
				qhp->wq.sq_oldest_wr);
		}
		wr = wr->next;
		num_wrs--;
		++(qhp->wq.wptr);
		++(qhp->wq.sq_wptr);
	}
	pthread_spin_unlock(&qhp->lock);
	RING_DOORBELL(qhp->wq.doorbell, qhp->wq.qpid);
	return err;
}

int t3a_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr, 
		   struct ibv_send_wr **bad_wr)
{
	int ret;
	struct iwch_qp *qhp = to_iwch_qp(ibqp);

	pthread_spin_lock(&qhp->lock);
	ret = ibv_cmd_post_send(ibqp, wr, bad_wr);
	pthread_spin_unlock(&qhp->lock);
	return ret;
}

/* 
 * XXX: this is going to be moved to firmware. 
 *      Missing pdid/qpid check for now.
 */
static inline int iwch_sgl2pbl_map(struct iwch_device *rhp,
				   struct ibv_sge *sg_list, __u32 num_sgle,
				   __u32 *pbl_addr, __u8 *page_size)
{
	int i;
	struct iwch_mr *mhp;
	__u32 offset;
	for (i = 0; i < num_sgle; i++) {

		mhp = rhp->stag2hlp[t3_stag_index(sg_list[i].lkey)];
		if (!mhp) {
			PDBG("%s %d\n", __FUNCTION__, __LINE__);
			return -1;
		}
#if 0
		if (!mhp->attr.state)
			return -1;
		if (mhp->attr.zbva) 
			return -1;
#endif

		if (sg_list[i].addr < mhp->va_fbo) {
			PDBG("%s %d\n", __FUNCTION__, __LINE__);
			return -1;
		}
		if (sg_list[i].addr + ((__u64) sg_list[i].length) <
		    sg_list[i].addr) {
			PDBG("%s %d\n", __FUNCTION__, __LINE__);
			return -1;
		}
		if (sg_list[i].addr + ((__u64) sg_list[i].length) >
		    mhp->va_fbo + ((__u64) mhp->len)) {
			PDBG("%s %d\n", __FUNCTION__, __LINE__);
			return -1;
		}
		offset = sg_list[i].addr - mhp->va_fbo;
		offset += ((__u32) mhp->va_fbo) %
		    (1UL << (12 + mhp->page_size));
		pbl_addr[i] = mhp->pbl_addr +
		    (offset >> (12 + mhp->page_size));
		page_size[i] = mhp->page_size;
	}
	return 0;
}

static inline int iwch_build_rdma_recv(struct iwch_device *rhp,
				       union t3_wr *wqe, 
				       struct ibv_recv_wr *wr)
{
	int i, err = 0;
	__u32 pbl_addr[4];
	__u8 page_size[4];

	if (wr->num_sge > T3_MAX_SGE)
		return -1;

	err = iwch_sgl2pbl_map(rhp, wr->sg_list, wr->num_sge, pbl_addr, 
			       page_size);
	if (err)
		return err;
	wqe->recv.pagesz[0] = page_size[0];
	wqe->recv.pagesz[1] = page_size[1];
	wqe->recv.pagesz[2] = page_size[2];
	wqe->recv.pagesz[3] = page_size[3];
	wqe->recv.num_sgle = htonl(wr->num_sge);
	for (i = 0; i < wr->num_sge; i++) {
		wqe->recv.sgl[i].stag = htonl(wr->sg_list[i].lkey);
		wqe->recv.sgl[i].len = htonl(wr->sg_list[i].length);
		
		/* to in the WQE == the offset into the page */
		wqe->recv.sgl[i].to = htonll(((__u32) wr->sg_list[i].addr) %
				(1UL << (12 + page_size[i])));

		/* pbl_addr is the adapters address in the PBL */
		wqe->recv.pbl_addr[i] = htonl(pbl_addr[i]);
	}
	for (; i < T3_MAX_SGE; i++) {
		wqe->recv.sgl[i].stag = 0;
		wqe->recv.sgl[i].len = 0;
		wqe->recv.sgl[i].to = 0;
		wqe->recv.pbl_addr[i] = 0;
	}
	return 0;
}

static void insert_recv_cqe(struct t3_wq *wq, struct t3_cq *cq)
{
	struct t3_cqe cqe;

	PDBG("%s %d wq %p cq %p sw_rptr %x sw_wptr %x\n", __FUNCTION__, 
	    __LINE__, wq, cq, cq->sw_rptr, cq->sw_wptr);
	memset(&cqe, 0, sizeof(cqe));
	cqe.header = V_CQE_STATUS(TPT_ERR_SWFLUSH) | 
		     V_CQE_OPCODE(T3_SEND) | 
		     V_CQE_TYPE(0) |
		     V_CQE_SWCQE(1) |
		     V_CQE_QPID(wq->qpid) | 
		     V_CQE_GENBIT(Q_GENBIT(cq->sw_wptr, cq->size_log2));
	cqe.header = htonl(cqe.header);
	*(cq->sw_queue + Q_PTR2IDX(cq->sw_wptr, cq->size_log2)) = cqe;
	cq->sw_wptr++;
}

static void flush_rq(struct t3_wq *wq, struct t3_cq *cq, int count)
{
	__u32 ptr;

	PDBG("%s %d wq %p cq %p\n", __FUNCTION__, __LINE__, wq, cq);

	/* flush RQ */
	PDBG("%s rq_rptr %u rq_wptr %u skip count %u\n", __FUNCTION__, 
	    wq->rq_rptr, wq->rq_wptr, count);
	ptr = wq->rq_rptr + count;
	while (ptr++ != wq->rq_wptr) {
		insert_recv_cqe(wq, cq);
	}
}

static void insert_sq_cqe(struct t3_wq *wq, struct t3_cq *cq, union t3_wr *wr)
{
	struct t3_cqe cqe;
	enum t3_rdma_opcode op;

	PDBG("%s %d wq %p cq %p sw_rptr %x sw_wptr %x\n", __FUNCTION__, 
	    __LINE__, wq, cq, cq->sw_rptr, cq->sw_wptr);
	memset(&cqe, 0, sizeof(cqe));
	op = wr2opcode(G_FW_RIWR_OP(ntohl(wr->send.wrh.op_seop_flags)));
	if (op == T3_SEND && wr->send.rdmaop == T3_TERMINATE) {
		op = T3_TERMINATE;
	}
	PDBG("%s op %x\n", __FUNCTION__, op);
	cqe.header = V_CQE_STATUS(TPT_ERR_SWFLUSH) | 
		     V_CQE_OPCODE(op) |
		     V_CQE_TYPE(1) |
		     V_CQE_SWCQE(1) |
		     V_CQE_QPID(wq->qpid) | 
		     V_CQE_GENBIT(Q_GENBIT(cq->sw_wptr, cq->size_log2));
	cqe.header = htonl(cqe.header);
	PDBG("%s header be %x\n", __FUNCTION__, cqe.header);
	CQE_WRID_SQ_WPTR(cqe) = wr->send.wrid.id0.hi;
	CQE_WRID_WPTR(cqe) = wr->send.wrid.id0.low;
	*(cq->sw_queue + Q_PTR2IDX(cq->sw_wptr, cq->size_log2)) = cqe;
	cq->sw_wptr++;
}

static void flush_sq(struct t3_wq *wq, struct t3_cq *cq, int count)
{
	__u32 ptr;
	union t3_wr *wr = wq->sq_oldest_wr;

	PDBG("%s %d wq %p cq %p oldest wr %p\n", __FUNCTION__, __LINE__, 
	     wq, cq, wr);

	/* flush SQ */
	PDBG("%s sq_rptr %u sq_wptr %u skip count %u\n", __FUNCTION__, 
	    wq->sq_rptr, wq->sq_wptr, count);
	ptr = wq->sq_rptr + count;
	wr += count;
	while (ptr != wq->sq_wptr) {
		PDBG("%s ptr %u wr %p\n", __FUNCTION__, ptr, wr);
		insert_sq_cqe(wq, cq, wr);
		wr = next_sq_wr(wq, wr);
		ptr++;

	}
}

/* 
 * Move all CQEs from the HWCQ into the SWCQ.
 */
static void flush_hw_cq(struct t3_cq *cq)
{
	struct t3_cqe *cqe, *swcqe;

	PDBG("%s enter cq %p\n", __FUNCTION__, cq);
	cqe = cxio_next_hw_cqe(cq);
	while (cqe) {
		PDBG("%s flushing hwcq rptr %u to swcq wptr %u\n", 
		     __FUNCTION__, cq->rptr, cq->sw_wptr);
		swcqe = cq->sw_queue + Q_PTR2IDX(cq->sw_wptr, cq->size_log2);
		*swcqe = *cqe;
		swcqe->header |= htonl(V_CQE_SWCQE(1));
		cq->sw_wptr++;
		cq->rptr++;
		cqe = cxio_next_hw_cqe(cq);
	}
}

static int cqe_completes_wr(struct t3_cqe *cqe, struct t3_wq *wq)
{
	if (CQE_OPCODE(*cqe) == T3_READ_RESP && 
	    (!wq->sq_oldest_wr || 
	     (wq->sq_oldest_wr->send.rdmaop != T3_READ_REQ)))
		return 0;

	if (CQE_OPCODE(*cqe) == T3_TERMINATE) 
		return 0;

	if ((CQE_OPCODE(*cqe) == T3_RDMA_WRITE) && RQ_TYPE(*cqe))
		return 0;

	if ((CQE_OPCODE(*cqe) == T3_READ_RESP) && SQ_TYPE(*cqe))
		return 0;

	if ((CQE_OPCODE(*cqe) == T3_SEND) && RQ_TYPE(*cqe) &&
	    Q_EMPTY(wq->rq_rptr, wq->rq_wptr))
		return 0;

	return 1;
}

static void count_scqes(struct t3_cq *cq, struct t3_wq *wq, int *count)
{
	struct t3_cqe *cqe;
	__u32 ptr;

	*count = 0;
	PDBG("%s count zero %d\n", __FUNCTION__, *count);
	ptr = cq->sw_rptr;
	while (!Q_EMPTY(ptr, cq->sw_wptr)) {
		cqe = cq->sw_queue + (Q_PTR2IDX(ptr, cq->size_log2));
		if (SQ_TYPE(*cqe) && (CQE_QPID(*cqe) == wq->qpid) &&
		    cqe_completes_wr(cqe, wq))
			(*count)++;
		ptr++;
	}	
	PDBG("%s count %d\n", __FUNCTION__, *count);
}

static void count_rcqes(struct t3_cq *cq, struct t3_wq *wq, int *count)
{
	struct t3_cqe *cqe;
	__u32 ptr;

	*count = 0;
	PDBG("%s count zero %d\n", __FUNCTION__, *count);
	ptr = cq->sw_rptr;
	while (!Q_EMPTY(ptr, cq->sw_wptr)) {
		PDBG("%s ptr %u\n", __FUNCTION__, ptr);
		cqe = cq->sw_queue + (Q_PTR2IDX(ptr, cq->size_log2));
		if (!SQ_TYPE(*cqe) && (CQE_QPID(*cqe) == wq->qpid) &&
		    cqe_completes_wr(cqe, wq))
			(*count)++;
		ptr++;
	}	
	PDBG("%s count %d\n", __FUNCTION__, *count);
}

/*
 * Assumes qhp lock is held.
 */
void iwch_flush_qp(struct iwch_qp *qhp)
{
	struct iwch_cq *rchp, *schp;
	int count;

	rchp = qhp->rhp->cqid2hlp[to_iwch_cq(qhp->ibv_qp.recv_cq)->cq.cqid];
	schp = qhp->rhp->cqid2hlp[to_iwch_cq(qhp->ibv_qp.send_cq)->cq.cqid];
	
	PDBG("%s qhp %p rchp %p schp %p\n", __FUNCTION__, qhp, rchp, schp);

#ifdef notyet
	/* take a ref on the qhp since we must release the lock */
	atomic_inc(&qhp->refcnt);
#endif
	pthread_spin_unlock(&qhp->lock);

	/* locking heirarchy: cq lock first, then qp lock. */
	pthread_spin_lock(&rchp->lock);
	pthread_spin_lock(&qhp->lock);
	flush_hw_cq(&rchp->cq);
	count_rcqes(&rchp->cq, &qhp->wq, &count);
	flush_rq(&qhp->wq, &rchp->cq, count);
	pthread_spin_unlock(&qhp->lock);
	pthread_spin_unlock(&rchp->lock);

	/* locking heirarchy: cq lock first, then qp lock. */
	pthread_spin_lock(&schp->lock);
	pthread_spin_lock(&qhp->lock);
	flush_hw_cq(&schp->cq);
	count_scqes(&schp->cq, &qhp->wq, &count);
	flush_sq(&qhp->wq, &schp->cq, count);
	pthread_spin_unlock(&qhp->lock);
	pthread_spin_unlock(&schp->lock);

#ifdef notyet
	/* deref */
	if (atomic_dec_and_test(&qhp->refcnt))
                wake_up(&qhp->wait);
#endif
	pthread_spin_lock(&qhp->lock);
}

int t3b_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		   struct ibv_recv_wr **bad_wr)
{
	int err = 0;
	struct iwch_qp *qhp;
	__u32 idx;
	union t3_wr *wqe;
	__u32 num_wrs;

	qhp = to_iwch_qp(ibqp);
	pthread_spin_lock(&qhp->lock);
	if (t3_wq_in_error(&qhp->wq)) {
		iwch_flush_qp(qhp);
		pthread_spin_unlock(&qhp->lock);
		return -1;
	}
	num_wrs = Q_FREECNT(qhp->wq.rq_rptr, qhp->wq.rq_wptr, 
			    qhp->wq.rq_size_log2) - 1;
	if (!wr) {
		pthread_spin_unlock(&qhp->lock);
		return -1;
	}
	while (wr) {
		idx = Q_PTR2IDX(qhp->wq.wptr, qhp->wq.size_log2);
		wqe = (union t3_wr *) (qhp->wq.queue + idx);
		if (num_wrs)
			err = iwch_build_rdma_recv(qhp->rhp, wqe, wr);
		else
			err = -1;
		if (err) {
			*bad_wr = wr;
			break;
		}
		qhp->wq.rq[Q_PTR2IDX(qhp->wq.rq_wptr, qhp->wq.rq_size_log2)] = 
			wr->wr_id;
		build_fw_riwrh((void *) wqe, T3_WR_RCV, T3_COMPLETION_FLAG,
			       Q_GENBIT(qhp->wq.wptr, qhp->wq.size_log2),
			       0, sizeof(struct t3_receive_wr) >> 3);
		PDBG("%s %d cookie %llx idx 0x%x rq_wptr %x rw_rptr %x "
		     "wqe %p \n", __FUNCTION__, __LINE__, wr->wr_id, idx, 
		     qhp->wq.rq_wptr, qhp->wq.rq_rptr, wqe);
		++(qhp->wq.rq_wptr);
		++(qhp->wq.wptr);
		wr = wr->next;
		num_wrs--;
	}
	pthread_spin_unlock(&qhp->lock);
	RING_DOORBELL(qhp->wq.doorbell, qhp->wq.qpid);
	return err;
}

int t3a_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		   struct ibv_recv_wr **bad_wr)
{
	int ret;
	struct iwch_qp *qhp = to_iwch_qp(ibqp);

	pthread_spin_lock(&qhp->lock);
	ret = ibv_cmd_post_recv(ibqp, wr, bad_wr);
	pthread_spin_unlock(&qhp->lock);
	return ret;
}
