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
#include <config.h>

#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "iwch.h"
#include <stdio.h>

#define ROUNDUP8(a) (((a) + 7) & ~7)

static inline int iwch_build_rdma_send(union t3_wr *wqe, struct ibv_send_wr *wr,
				       uint8_t *flit_cnt)
{
	int i;

	if (wr->num_sge > T3_MAX_SGE)
		return -1;
	if (wr->send_flags & IBV_SEND_SOLICITED)
		wqe->send.rdmaop = T3_SEND_WITH_SE;
	else
		wqe->send.rdmaop = T3_SEND;
	wqe->send.rem_stag = 0;
	wqe->send.reserved = 0;
	if ((wr->send_flags & IBV_SEND_INLINE) || wr->num_sge == 0) {
		uint8_t *datap;

		wqe->send.plen = 0;
		datap = (uint8_t *)&wqe->send.sgl[0];
		wqe->send.num_sgle = 0;	/* indicates in-line data */
		for (i = 0; i < wr->num_sge; i++) {
			if ((wqe->send.plen + wr->sg_list[i].length) > 
			    T3_MAX_INLINE)
				return -1;
			wqe->send.plen += wr->sg_list[i].length;
			memcpy(datap, 
			       (void *)(unsigned long)wr->sg_list[i].addr, 
			       wr->sg_list[i].length);
			datap += wr->sg_list[i].length;
		}
		*flit_cnt = 4 + (ROUNDUP8(wqe->send.plen) >> 3);
		wqe->send.plen = htobe32(wqe->send.plen);
	} else {
		wqe->send.plen = 0;
		for (i = 0; i < wr->num_sge; i++) {
			if ((wqe->send.plen + wr->sg_list[i].length) < 
			    wqe->send.plen) {
				return -1;
			}
			wqe->send.plen += wr->sg_list[i].length;
			wqe->send.sgl[i].stag =
			    htobe32(wr->sg_list[i].lkey);
			wqe->send.sgl[i].len =
			    htobe32(wr->sg_list[i].length);
			wqe->send.sgl[i].to = htobe64(wr->sg_list[i].addr);
		}
		wqe->send.plen = htobe32(wqe->send.plen);
		wqe->send.num_sgle = htobe32(wr->num_sge);
		*flit_cnt = 4 + ((wr->num_sge) << 1);
	}
	return 0;
}

static inline int iwch_build_rdma_write(union t3_wr *wqe, 
					struct ibv_send_wr *wr,
					uint8_t *flit_cnt)
{
	int i;

	if (wr->num_sge > T3_MAX_SGE)
		return -1;
	wqe->write.rdmaop = T3_RDMA_WRITE;
	wqe->write.reserved = 0;
	wqe->write.stag_sink = htobe32(wr->wr.rdma.rkey);
	wqe->write.to_sink = htobe64(wr->wr.rdma.remote_addr);

	wqe->write.num_sgle = wr->num_sge;

	if ((wr->send_flags & IBV_SEND_INLINE) || wr->num_sge == 0) {
		uint8_t *datap;

		wqe->write.plen = 0;
		datap = (uint8_t *)&wqe->write.sgl[0];
		wqe->write.num_sgle = 0;	/* indicates in-line data */
		for (i = 0; i < wr->num_sge; i++) {
			if ((wqe->write.plen + wr->sg_list[i].length) >
			    T3_MAX_INLINE)
				return -1;
			wqe->write.plen += wr->sg_list[i].length;
			memcpy(datap, 
			       (void *)(unsigned long)wr->sg_list[i].addr, 
			       wr->sg_list[i].length);
			datap += wr->sg_list[i].length;
		}
		*flit_cnt = 5 + (ROUNDUP8(wqe->write.plen) >> 3);
		wqe->write.plen = htobe32(wqe->write.plen);
	} else {
		wqe->write.plen = 0;
		for (i = 0; i < wr->num_sge; i++) {
			if ((wqe->write.plen + wr->sg_list[i].length) < 
			    wqe->write.plen) {
				return -1;
			}
			wqe->write.plen += wr->sg_list[i].length;
			wqe->write.sgl[i].stag =
			    htobe32(wr->sg_list[i].lkey);
			wqe->write.sgl[i].len =
			    htobe32(wr->sg_list[i].length);
			wqe->write.sgl[i].to =
			    htobe64(wr->sg_list[i].addr);
		}
		wqe->write.plen = htobe32(wqe->write.plen);
		wqe->write.num_sgle = htobe32(wr->num_sge);
		*flit_cnt = 5 + ((wr->num_sge) << 1);
	}
	return 0;
}

static inline int iwch_build_rdma_read(union t3_wr *wqe, struct ibv_send_wr *wr,
				       uint8_t *flit_cnt)
{
	if (wr->num_sge > 1)
		return -1;
	wqe->read.rdmaop = T3_READ_REQ;
	wqe->read.reserved = 0;
	if (wr->num_sge == 1 && wr->sg_list[0].length > 0) {
		wqe->read.rem_stag = htobe32(wr->wr.rdma.rkey);
		wqe->read.rem_to = htobe64(wr->wr.rdma.remote_addr);
		wqe->read.local_stag = htobe32(wr->sg_list[0].lkey);
		wqe->read.local_len = htobe32(wr->sg_list[0].length);
		wqe->read.local_to = htobe64(wr->sg_list[0].addr);
	} else {

		/* build passable 0B read request */
		wqe->read.rem_stag = 2;
		wqe->read.rem_to = 2;
		wqe->read.local_stag = 2;
		wqe->read.local_len = 0;
		wqe->read.local_to = 2;
	}
	*flit_cnt = sizeof(struct t3_rdma_read_wr) >> 3;
	return 0;
}

int t3b_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr, 
		  struct ibv_send_wr **bad_wr)
{
	int err = 0;
	uint8_t t3_wr_flit_cnt;
	enum t3_wr_opcode t3_wr_opcode = 0;
	enum t3_wr_flags t3_wr_flags;
	struct iwch_qp *qhp;
	uint32_t idx;
	union t3_wr *wqe;
	uint32_t num_wrs;
	struct t3_swsq *sqp;

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
		if ((wr->send_flags & IBV_SEND_SIGNALED) || qhp->sq_sig_all)
			t3_wr_flags |= T3_COMPLETION_FLAG;
		sqp = qhp->wq.sq + 
		      Q_PTR2IDX(qhp->wq.sq_wptr, qhp->wq.sq_size_log2);
		switch (wr->opcode) {
		case IBV_WR_SEND:
			t3_wr_opcode = T3_WR_SEND;
			err = iwch_build_rdma_send(wqe, wr, &t3_wr_flit_cnt);
			break;
		case IBV_WR_RDMA_WRITE:
			t3_wr_opcode = T3_WR_WRITE;
			err = iwch_build_rdma_write(wqe, wr, &t3_wr_flit_cnt);
			break;
		case IBV_WR_RDMA_READ:
			t3_wr_opcode = T3_WR_READ;
			t3_wr_flags = 0;
			err = iwch_build_rdma_read(wqe, wr, &t3_wr_flit_cnt);
			if (err)
				break;
			sqp->read_len = wqe->read.local_len;
			if (!qhp->wq.oldest_read)
				qhp->wq.oldest_read = sqp;
			break;
		default:
			PDBG("%s post of type=%d TBD!\n", __FUNCTION__, 
			     wr->opcode);
			err = -1;
		}
		if (err) {
			*bad_wr = wr;
			break;
		}
		wqe->send.wrid.id0.hi = qhp->wq.sq_wptr;
		sqp->wr_id = wr->wr_id;
		sqp->opcode = wr2opcode(t3_wr_opcode);
		sqp->sq_wptr = qhp->wq.sq_wptr;
		sqp->complete = 0;
		sqp->signaled = (wr->send_flags & IBV_SEND_SIGNALED);

		build_fw_riwrh((void *) wqe, t3_wr_opcode, t3_wr_flags,
			       Q_GENBIT(qhp->wq.wptr, qhp->wq.size_log2),
			       0, t3_wr_flit_cnt);
		PDBG("%s cookie 0x%" PRIx64 
		     " wq idx 0x%x swsq idx %ld opcode %d\n", 
		     __FUNCTION__, wr->wr_id, idx, 
		     Q_PTR2IDX(qhp->wq.sq_wptr, qhp->wq.sq_size_log2),
		     sqp->opcode);
		wr = wr->next;
		num_wrs--;
		++(qhp->wq.wptr);
		++(qhp->wq.sq_wptr);
	}
	pthread_spin_unlock(&qhp->lock);
	if (t3_wq_db_enabled(&qhp->wq))
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

static inline int iwch_build_rdma_recv(struct iwch_device *rhp,
				       union t3_wr *wqe, 
				       struct ibv_recv_wr *wr)
{
	int i;
	if (wr->num_sge > T3_MAX_SGE)
		return -1;

	wqe->recv.num_sgle = htobe32(wr->num_sge);
	for (i = 0; i < wr->num_sge; i++) {
		wqe->recv.sgl[i].stag = htobe32(wr->sg_list[i].lkey);
		wqe->recv.sgl[i].len = htobe32(wr->sg_list[i].length);
		wqe->recv.sgl[i].to = htobe64(wr->sg_list[i].addr);
	}
	for (; i < T3_MAX_SGE; i++) {
		wqe->recv.sgl[i].stag = 0;
		wqe->recv.sgl[i].len = 0;
		wqe->recv.sgl[i].to = 0;
	}
	return 0;
}

static void insert_recv_cqe(struct t3_wq *wq, struct t3_cq *cq)
{
	struct t3_cqe cqe;

	PDBG("%s wq %p cq %p sw_rptr 0x%x sw_wptr 0x%x\n", __FUNCTION__, 
	     wq, cq, cq->sw_rptr, cq->sw_wptr);
	memset(&cqe, 0, sizeof(cqe));
	cqe.header = V_CQE_STATUS(TPT_ERR_SWFLUSH) | 
		     V_CQE_OPCODE(T3_SEND) | 
		     V_CQE_TYPE(0) |
		     V_CQE_SWCQE(1) |
		     V_CQE_QPID(wq->qpid) | 
		     V_CQE_GENBIT(Q_GENBIT(cq->sw_wptr, cq->size_log2));
	cqe.header = htobe32(cqe.header);
	*(cq->sw_queue + Q_PTR2IDX(cq->sw_wptr, cq->size_log2)) = cqe;
	cq->sw_wptr++;
}

static void flush_rq(struct t3_wq *wq, struct t3_cq *cq, int count)
{
	uint32_t ptr;

	/* flush RQ */
	PDBG("%s rq_rptr 0x%x rq_wptr 0x%x skip count %u\n", __FUNCTION__, 
	     wq->rq_rptr, wq->rq_wptr, count);
	ptr = wq->rq_rptr + count;
	while (ptr++ != wq->rq_wptr) {
		insert_recv_cqe(wq, cq);
	}
}

static void insert_sq_cqe(struct t3_wq *wq, struct t3_cq *cq, 
		          struct t3_swsq *sqp)
{
	struct t3_cqe cqe;

	PDBG("%s wq %p cq %p sw_rptr 0x%x sw_wptr 0x%x\n", __FUNCTION__, 
	     wq, cq, cq->sw_rptr, cq->sw_wptr);
	memset(&cqe, 0, sizeof(cqe));
	cqe.header = V_CQE_STATUS(TPT_ERR_SWFLUSH) | 
		     V_CQE_OPCODE(sqp->opcode) |
		     V_CQE_TYPE(1) |
		     V_CQE_SWCQE(1) |
		     V_CQE_QPID(wq->qpid) | 
		     V_CQE_GENBIT(Q_GENBIT(cq->sw_wptr, cq->size_log2));
	cqe.header = htobe32(cqe.header);
	CQE_WRID_SQ_WPTR(cqe) = sqp->sq_wptr;

	*(cq->sw_queue + Q_PTR2IDX(cq->sw_wptr, cq->size_log2)) = cqe;
	cq->sw_wptr++;
}

static void flush_sq(struct t3_wq *wq, struct t3_cq *cq, int count)
{
	uint32_t ptr;
	struct t3_swsq *sqp;

	ptr = wq->sq_rptr + count;
	sqp = wq->sq + Q_PTR2IDX(ptr, wq->sq_size_log2);
	while (ptr != wq->sq_wptr) {
		insert_sq_cqe(wq, cq, sqp);
		ptr++;
		sqp = wq->sq + Q_PTR2IDX(ptr, wq->sq_size_log2);
	}
}

/* 
 * Move all CQEs from the HWCQ into the SWCQ.
 */
static void flush_hw_cq(struct t3_cq *cq)
{
	struct t3_cqe *cqe, *swcqe;

	PDBG("%s cq %p cqid 0x%x\n", __FUNCTION__, cq, cq->cqid);
	cqe = cxio_next_hw_cqe(cq);
	while (cqe) {
		PDBG("%s flushing hwcq rptr 0x%x to swcq wptr 0x%x\n", 
		     __FUNCTION__, cq->rptr, cq->sw_wptr);
		swcqe = cq->sw_queue + Q_PTR2IDX(cq->sw_wptr, cq->size_log2);
		*swcqe = *cqe;
		swcqe->header |= htobe32(V_CQE_SWCQE(1));
		cq->sw_wptr++;
		cq->rptr++;
		cqe = cxio_next_hw_cqe(cq);
	}
}

static void count_scqes(struct t3_cq *cq, struct t3_wq *wq, int *count)
{
	struct t3_cqe *cqe;
	uint32_t ptr;

	*count = 0;
	ptr = cq->sw_rptr;
	while (!Q_EMPTY(ptr, cq->sw_wptr)) {
		cqe = cq->sw_queue + (Q_PTR2IDX(ptr, cq->size_log2));
		if ((SQ_TYPE(*cqe) || 
		     (CQE_OPCODE(*cqe) == T3_READ_RESP && CQE_WRID_STAG(*cqe) != 1)) &&
		    (CQE_QPID(*cqe) == wq->qpid))
			(*count)++;
		ptr++;
	}	
	PDBG("%s cq %p count %d\n", __FUNCTION__, cq, *count);
}

static void count_rcqes(struct t3_cq *cq, struct t3_wq *wq, int *count)
{
	struct t3_cqe *cqe;
	uint32_t ptr;

	*count = 0;
	ptr = cq->sw_rptr;
	while (!Q_EMPTY(ptr, cq->sw_wptr)) {
		cqe = cq->sw_queue + (Q_PTR2IDX(ptr, cq->size_log2));
		if (RQ_TYPE(*cqe) && (CQE_OPCODE(*cqe) != T3_READ_RESP) && 
		    (CQE_QPID(*cqe) == wq->qpid))
			(*count)++;
		ptr++;
	}	
	PDBG("%s cq %p count %d\n", __FUNCTION__, cq, *count);
}

/*
 * Assumes qhp lock is held.
 */
void iwch_flush_qp(struct iwch_qp *qhp)
{
	struct iwch_cq *rchp, *schp;
	int count;

	if (qhp->wq.flushed)
		return;

	rchp = qhp->rhp->cqid2ptr[to_iwch_cq(qhp->ibv_qp.recv_cq)->cq.cqid];
	schp = qhp->rhp->cqid2ptr[to_iwch_cq(qhp->ibv_qp.send_cq)->cq.cqid];
	
	PDBG("%s qhp %p rchp %p schp %p\n", __FUNCTION__, qhp, rchp, schp);
	qhp->wq.flushed = 1;

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

void iwch_flush_qps(struct iwch_device *dev)
{
	int i;

	pthread_spin_lock(&dev->lock);
	for (i=0; i < T3_MAX_NUM_QP; i++) {
		struct iwch_qp *qhp = dev->qpid2ptr[i];
		if (qhp) {
			if (!qhp->wq.flushed && t3_wq_in_error(&qhp->wq)) {
				pthread_spin_lock(&qhp->lock);
				iwch_flush_qp(qhp);
				pthread_spin_unlock(&qhp->lock);
			}
		}
	}
	pthread_spin_unlock(&dev->lock);

}

int t3b_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		   struct ibv_recv_wr **bad_wr)
{
	int err = 0;
	struct iwch_qp *qhp;
	uint32_t idx;
	union t3_wr *wqe;
	uint32_t num_wrs;

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
		PDBG("%s cookie 0x%" PRIx64 
		     " idx 0x%x rq_wptr 0x%x rw_rptr 0x%x "
		     "wqe %p \n", __FUNCTION__, wr->wr_id, idx, 
		     qhp->wq.rq_wptr, qhp->wq.rq_rptr, wqe);
		++(qhp->wq.rq_wptr);
		++(qhp->wq.wptr);
		wr = wr->next;
		num_wrs--;
	}
	pthread_spin_unlock(&qhp->lock);
	if (t3_wq_db_enabled(&qhp->wq))
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
