/*
 * Copyright (c) 2012-2017 VMware, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of EITHER the GNU General Public License
 * version 2 as published by the Free Software Foundation or the BSD
 * 2-Clause License. This program is distributed in the hope that it
 * will be useful, but WITHOUT ANY WARRANTY; WITHOUT EVEN THE IMPLIED
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License version 2 for more details at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program available in the file COPYING in the main
 * directory of this source tree.
 *
 * The BSD 2-Clause License
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <util/udma_barrier.h>

#include "pvrdma.h"

int pvrdma_alloc_qp_buf(struct pvrdma_device *dev, struct ibv_qp_cap *cap,
			enum ibv_qp_type type, struct pvrdma_qp *qp)
{
	qp->sq.wrid = calloc(qp->sq.wqe_cnt, sizeof(uint64_t));
	if (!qp->sq.wrid)
		return -1;

	/* Align page size for sq */
	qp->sbuf.length = align(qp->sq.offset +
				qp->sq.wqe_cnt * qp->sq.wqe_size,
				dev->page_size);

	if (pvrdma_alloc_buf(&qp->sbuf, qp->sbuf.length, dev->page_size)) {
		free(qp->sq.wrid);
		return -1;
	}

	memset(qp->sbuf.buf, 0, qp->sbuf.length);

	if (!qp->is_srq) {
		qp->rq.wrid = calloc(qp->rq.wqe_cnt, sizeof(uint64_t));
		if (!qp->rq.wrid) {
			pvrdma_free_buf(&qp->sbuf);
			free(qp->sq.wrid);
			return -1;
		}

		/* Align page size for rq */
		qp->rbuf.length = align(qp->rq.offset +
					qp->rq.wqe_cnt * qp->rq.wqe_size,
					dev->page_size);

		if (pvrdma_alloc_buf(&qp->rbuf, qp->rbuf.length,
				     dev->page_size)) {
			free(qp->sq.wrid);
			free(qp->rq.wrid);
			pvrdma_free_buf(&qp->sbuf);
			return -1;
		}
		memset(qp->rbuf.buf, 0, qp->rbuf.length);
	} else {
		qp->rbuf.buf = NULL;
		qp->rbuf.length = 0;
	}

	qp->buf_size = qp->rbuf.length + qp->sbuf.length;

	return 0;
}

void pvrdma_init_srq_queue(struct pvrdma_srq *srq)
{
	srq->ring_state->rx.cons_head = 0;
	srq->ring_state->rx.prod_tail = 0;
}

struct ibv_srq *pvrdma_create_srq(struct ibv_pd *pd,
				  struct ibv_srq_init_attr *attr)
{
	struct pvrdma_device *dev = to_vdev(pd->context->device);
	struct user_pvrdma_create_srq cmd;
	struct user_pvrdma_create_srq_resp resp;
	struct pvrdma_srq *srq;
	int ret;

	attr->attr.max_wr = align_next_power2(max_t(uint32_t, 1U, attr->attr.max_wr));
	attr->attr.max_sge = max_t(uint32_t, 1U, attr->attr.max_sge);

	srq = malloc(sizeof(*srq));
	if (!srq)
		return NULL;

	if (pthread_spin_init(&srq->lock, PTHREAD_PROCESS_PRIVATE))
		goto err;

	srq->wqe_cnt = attr->attr.max_wr;
	srq->max_gs = attr->attr.max_sge;
	srq->wqe_size = align_next_power2(sizeof(struct pvrdma_rq_wqe_hdr) +
					  sizeof(struct ibv_sge) *
					  srq->max_gs);
	/* Page reserved for queue metadata */
	srq->offset = dev->page_size;

	if (pvrdma_alloc_srq_buf(dev, &attr->attr, srq))
		goto err_spinlock;

	srq->ring_state = srq->buf.buf;
	pvrdma_init_srq_queue(srq);

	memset(&cmd, 0, sizeof(cmd));
	cmd.buf_addr = (uintptr_t) srq->buf.buf;
	cmd.buf_size = srq->buf.length;

	ret = ibv_cmd_create_srq(pd, &srq->ibv_srq, attr,
				 &cmd.ibv_cmd, sizeof(cmd),
				 &resp.ibv_resp, sizeof(resp));

	if (ret)
		goto err_free;

	srq->srqn = resp.srqn;

	return &srq->ibv_srq;

err_free:
	free(srq->wrid);
	pvrdma_free_buf(&srq->buf);
err_spinlock:
	pthread_spin_destroy(&srq->lock);
err:
	free(srq);

	return NULL;
}

int pvrdma_modify_srq(struct ibv_srq *srq,
		      struct ibv_srq_attr *attr,
		      int attr_mask)
{
	struct ibv_modify_srq cmd;

	return ibv_cmd_modify_srq(srq, attr, attr_mask, &cmd, sizeof(cmd));
}

int pvrdma_query_srq(struct ibv_srq *srq,
		     struct ibv_srq_attr *attr)
{
	struct ibv_query_srq cmd;

	return ibv_cmd_query_srq(srq, attr, &cmd, sizeof(cmd));
}

int pvrdma_destroy_srq(struct ibv_srq *ibsrq)
{
	struct pvrdma_srq *srq = to_vsrq(ibsrq);
	int ret;

	ret = ibv_cmd_destroy_srq(ibsrq);
	if (ret)
		return ret;

	pthread_spin_destroy(&srq->lock);
	pvrdma_free_buf(&srq->buf);
	free(srq->wrid);
	free(srq);

	return 0;
}

static void pvrdma_init_qp_queue(struct pvrdma_qp *qp)
{
	qp->sq.ring_state->cons_head = 0;
	qp->sq.ring_state->prod_tail = 0;
	if (qp->rq.ring_state) {
		qp->rq.ring_state->cons_head = 0;
		qp->rq.ring_state->prod_tail = 0;
	}
}

struct ibv_qp *pvrdma_create_qp(struct ibv_pd *pd,
				struct ibv_qp_init_attr *attr)
{
	struct pvrdma_device *dev = to_vdev(pd->context->device);
	struct user_pvrdma_create_qp cmd;
	struct user_pvrdma_create_qp_resp resp = {};
	struct pvrdma_qp *qp;
	int is_srq = !!(attr->srq);

	attr->cap.max_send_sge = max_t(uint32_t, 1U, attr->cap.max_send_sge);
	attr->cap.max_send_wr =
		align_next_power2(max_t(uint32_t, 1U, attr->cap.max_send_wr));

	if (!is_srq) {
		attr->cap.max_recv_sge = max_t(uint32_t, 1U, attr->cap.max_recv_sge);
		attr->cap.max_recv_wr =
			align_next_power2(max_t(uint32_t, 1U, attr->cap.max_recv_wr));
	} else {
		attr->cap.max_recv_sge = 0;
		attr->cap.max_recv_wr = 0;
	}

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	qp->is_srq = is_srq;

	qp->sq.max_gs = attr->cap.max_send_sge;
	qp->sq.wqe_cnt = attr->cap.max_send_wr;
	/* Extra page for shared ring state */
	qp->sq.offset = dev->page_size;
	qp->sq.wqe_size = align_next_power2(sizeof(struct pvrdma_sq_wqe_hdr) +
					    sizeof(struct ibv_sge) *
					    qp->sq.max_gs);

	if (!is_srq) {
		qp->rq.max_gs = attr->cap.max_recv_sge;
		qp->rq.wqe_cnt = attr->cap.max_recv_wr;
		qp->rq.offset = 0;
		qp->rq.wqe_size = align_next_power2(sizeof(struct pvrdma_rq_wqe_hdr) +
						    sizeof(struct ibv_sge) *
						    qp->rq.max_gs);
	} else {
		qp->rq.max_gs = 0;
		qp->rq.wqe_cnt = 0;
		qp->rq.offset = 0;
		qp->rq.wqe_size = 0;
	}

	/* Allocate [rq][sq] memory */
	if (pvrdma_alloc_qp_buf(dev, &attr->cap, attr->qp_type, qp))
		goto err;

	qp->sq.ring_state = qp->sbuf.buf;
	if (pthread_spin_init(&qp->sq.lock, PTHREAD_PROCESS_PRIVATE))
		goto err_free;

	if (!is_srq) {
		qp->rq.ring_state = (struct pvrdma_ring *)&qp->sq.ring_state[1];
		if (pthread_spin_init(&qp->rq.lock, PTHREAD_PROCESS_PRIVATE))
			goto err_free;
	} else {
		qp->rq.ring_state = NULL;
	}

	pvrdma_init_qp_queue(qp);

	memset(&cmd, 0, sizeof(cmd));
	cmd.sbuf_addr = (uintptr_t)qp->sbuf.buf;
	cmd.sbuf_size = qp->sbuf.length;
	cmd.rbuf_addr = (uintptr_t)qp->rbuf.buf;
	cmd.rbuf_size = qp->rbuf.length;
	cmd.qp_addr = (uintptr_t) qp;

	if (ibv_cmd_create_qp(pd, &qp->ibv_qp, attr, &cmd.ibv_cmd, sizeof(cmd),
			      &resp.ibv_resp, sizeof(resp)))
		goto err_free;

	if (resp.drv_payload.qp_handle != 0)
		qp->qp_handle = resp.drv_payload.qp_handle;
	else
		qp->qp_handle = qp->ibv_qp.qp_num;

	to_vctx(pd->context)->qp_tbl[qp->qp_handle & 0xFFFF] = qp;

	/* If set, each WR submitted to the SQ generate a completion entry */
	if (attr->sq_sig_all)
		qp->sq_signal_bits = htobe32(PVRDMA_WQE_CTRL_CQ_UPDATE);
	else
		qp->sq_signal_bits = 0;

	return &qp->ibv_qp;

err_free:
	if (qp->sq.wqe_cnt)
		free(qp->sq.wrid);
	if (qp->rq.wqe_cnt)
		free(qp->rq.wrid);
	pvrdma_free_buf(&qp->rbuf);
	pvrdma_free_buf(&qp->sbuf);
err:
	free(qp);

	return NULL;
}

int pvrdma_query_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
		    int attr_mask,
		    struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;
	struct pvrdma_qp *qp = to_vqp(ibqp);
	int ret;

	ret = ibv_cmd_query_qp(ibqp, attr, attr_mask, init_attr,
			       &cmd, sizeof(cmd));
	if (ret)
		return ret;

	/* Passing back */
	init_attr->cap.max_send_wr     = qp->sq.wqe_cnt;
	init_attr->cap.max_send_sge    = qp->sq.max_gs;
	init_attr->cap.max_inline_data = qp->max_inline_data;

	attr->cap = init_attr->cap;

	return 0;
}

int pvrdma_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
		     int attr_mask)
{
	struct ibv_modify_qp cmd;
	struct pvrdma_qp *qp = to_vqp(ibqp);
	int ret;

	/* Sanity check */
	if (!attr_mask)
		return 0;

	ret = ibv_cmd_modify_qp(ibqp, attr, attr_mask, &cmd, sizeof(cmd));

	if (!ret &&
	    (attr_mask & IBV_QP_STATE) &&
	    attr->qp_state == IBV_QPS_RESET) {
		pvrdma_cq_clean(to_vcq(ibqp->recv_cq), qp->qp_handle);
		if (ibqp->send_cq != ibqp->recv_cq)
			pvrdma_cq_clean(to_vcq(ibqp->send_cq), qp->qp_handle);
		pvrdma_init_qp_queue(qp);
	}

	return ret;
}

static void pvrdma_lock_cqs(struct ibv_qp *qp)
{
	struct pvrdma_cq *send_cq = to_vcq(qp->send_cq);
	struct pvrdma_cq *recv_cq = to_vcq(qp->recv_cq);

	if (send_cq == recv_cq) {
		pthread_spin_lock(&send_cq->lock);
	} else if (send_cq->cqn < recv_cq->cqn) {
		pthread_spin_lock(&send_cq->lock);
		pthread_spin_lock(&recv_cq->lock);
	} else {
		pthread_spin_lock(&recv_cq->lock);
		pthread_spin_lock(&send_cq->lock);
	}
}

static void pvrdma_unlock_cqs(struct ibv_qp *qp)
{
	struct pvrdma_cq *send_cq = to_vcq(qp->send_cq);
	struct pvrdma_cq *recv_cq = to_vcq(qp->recv_cq);

	if (send_cq == recv_cq) {
		pthread_spin_unlock(&send_cq->lock);
	} else if (send_cq->cqn < recv_cq->cqn) {
		pthread_spin_unlock(&recv_cq->lock);
		pthread_spin_unlock(&send_cq->lock);
	} else {
		pthread_spin_unlock(&send_cq->lock);
		pthread_spin_unlock(&recv_cq->lock);
	}
}

int pvrdma_destroy_qp(struct ibv_qp *ibqp)
{
	struct pvrdma_context *ctx = to_vctx(ibqp->context);
	struct pvrdma_qp *qp = to_vqp(ibqp);
	int ret;

	ret = ibv_cmd_destroy_qp(ibqp);
	if (ret) {
		return ret;
	}

	pvrdma_lock_cqs(ibqp);
	/* Dump cqs */
	pvrdma_cq_clean_int(to_vcq(ibqp->recv_cq), qp->qp_handle);

	if (ibqp->send_cq != ibqp->recv_cq)
		pvrdma_cq_clean_int(to_vcq(ibqp->send_cq), qp->qp_handle);
	pvrdma_unlock_cqs(ibqp);

	free(qp->sq.wrid);
	free(qp->rq.wrid);
	pvrdma_free_buf(&qp->rbuf);
	pvrdma_free_buf(&qp->sbuf);
	ctx->qp_tbl[qp->qp_handle & 0xFFFF] = NULL;
	free(qp);

	return 0;
}

static void *get_srq_wqe(struct pvrdma_srq *srq, int n)
{
	return srq->buf.buf + srq->offset + (n * srq->wqe_size);
}

static void *get_rq_wqe(struct pvrdma_qp *qp, int n)
{
	return qp->rbuf.buf + qp->rq.offset + (n * qp->rq.wqe_size);
}

static void *get_sq_wqe(struct pvrdma_qp *qp, int n)
{
	return qp->sbuf.buf + qp->sq.offset + (n * qp->sq.wqe_size);
}

int pvrdma_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		     struct ibv_send_wr **bad_wr)
{
	struct pvrdma_context *ctx = to_vctx(ibqp->context);
	struct pvrdma_qp *qp = to_vqp(ibqp);
	int ind;
	int nreq = 0;
	struct pvrdma_sq_wqe_hdr *wqe_hdr;
	struct ibv_sge *sge;
	int ret = 0;
	int i;

	/*
	 * In states lower than RTS, we can fail immediately. In other states,
	 * just post and let the device figure it out.
	 */
	if (ibqp->state < IBV_QPS_RTS) {
		*bad_wr = wr;
		return EINVAL;
	}

	pthread_spin_lock(&qp->sq.lock);
	ind = pvrdma_idx(&(qp->sq.ring_state->prod_tail), qp->sq.wqe_cnt);
	if (ind < 0) {
		pthread_spin_unlock(&qp->sq.lock);
		ret = EINVAL;
		goto out;
	}

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		unsigned int tail;

		if (pvrdma_idx_ring_has_space(qp->sq.ring_state,
					      qp->sq.wqe_cnt, &tail) <= 0) {
			ret = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (wr->num_sge > qp->sq.max_gs) {
			ret = EINVAL;
			*bad_wr = wr;
			goto out;
		}

		wqe_hdr = (struct pvrdma_sq_wqe_hdr *)get_sq_wqe(qp, ind);
		wqe_hdr->wr_id = wr->wr_id;
		wqe_hdr->num_sge = wr->num_sge;
		wqe_hdr->opcode = ibv_wr_opcode_to_pvrdma(wr->opcode);
		wqe_hdr->send_flags = ibv_send_flags_to_pvrdma(wr->send_flags);
		if (wr->opcode == IBV_WR_SEND_WITH_IMM ||
		    wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
			wqe_hdr->ex.imm_data = wr->imm_data;

		switch (ibqp->qp_type) {
		case IBV_QPT_UD:
			wqe_hdr->wr.ud.remote_qpn = wr->wr.ud.remote_qpn;
			wqe_hdr->wr.ud.remote_qkey = wr->wr.ud.remote_qkey;
			wqe_hdr->wr.ud.av = to_vah(wr->wr.ud.ah)->av;
			break;
		case IBV_QPT_RC:
			switch (wr->opcode) {
			case IBV_WR_RDMA_READ:
			case IBV_WR_RDMA_WRITE:
			case IBV_WR_RDMA_WRITE_WITH_IMM:
				wqe_hdr->wr.rdma.remote_addr =
					wr->wr.rdma.remote_addr;
				wqe_hdr->wr.rdma.rkey = wr->wr.rdma.rkey;
				break;
			case IBV_WR_ATOMIC_CMP_AND_SWP:
			case IBV_WR_ATOMIC_FETCH_AND_ADD:
				wqe_hdr->wr.atomic.remote_addr = wr->wr.atomic.remote_addr;
				wqe_hdr->wr.atomic.rkey = wr->wr.atomic.rkey;
				wqe_hdr->wr.atomic.compare_add = wr->wr.atomic.compare_add;
				if (wr->opcode == IBV_WR_ATOMIC_CMP_AND_SWP)
					wqe_hdr->wr.atomic.swap = wr->wr.atomic.swap;
				break;
			default:
				/* No extra segments required for sends */
				break;
			}
			break;
		default:
			fprintf(stderr, PFX "invalid post send opcode\n");
			ret = EINVAL;
			*bad_wr = wr;
			goto out;
		}

		/* Write each segment */
		sge = (struct ibv_sge *)&wqe_hdr[1];
		for (i = 0; i < wr->num_sge; i++) {
			sge->addr = wr->sg_list[i].addr;
			sge->length = wr->sg_list[i].length;
			sge->lkey = wr->sg_list[i].lkey;
			sge++;
		}

		udma_to_device_barrier();
		pvrdma_idx_ring_inc(&(qp->sq.ring_state->prod_tail),
				    qp->sq.wqe_cnt);

		qp->sq.wrid[ind] = wr->wr_id;
		++ind;
		if (ind >= qp->sq.wqe_cnt)
			ind = 0;
	}

out:
	if (nreq) {
		udma_to_device_barrier();
		pvrdma_write_uar_qp(ctx->uar,
				    PVRDMA_UAR_QP_SEND | qp->qp_handle);
	}

	pthread_spin_unlock(&qp->sq.lock);

	return ret;
}

int pvrdma_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		     struct ibv_recv_wr **bad_wr)
{
	struct pvrdma_context *ctx = to_vctx(ibqp->context);
	struct pvrdma_qp *qp = to_vqp(ibqp);
	struct pvrdma_rq_wqe_hdr *wqe_hdr;
	struct ibv_sge *sge;
	int nreq;
	int ind;
	int i;
	int ret = 0;

	if (qp->is_srq)
		return EINVAL;

	if (!wr || !bad_wr)
		return EINVAL;

	/*
	 * In the RESET state, we can fail immediately. For other states,
	 * just post and let the device figure it out.
	 */
	if (ibqp->state == IBV_QPS_RESET) {
		*bad_wr = wr;
		return EINVAL;
	}

	pthread_spin_lock(&qp->rq.lock);

	ind = pvrdma_idx(&(qp->rq.ring_state->prod_tail), qp->rq.wqe_cnt);
	if (ind < 0) {
		pthread_spin_unlock(&qp->rq.lock);
		*bad_wr = wr;
		return EINVAL;
	}

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		unsigned int tail;

		if (pvrdma_idx_ring_has_space(qp->rq.ring_state,
					      qp->rq.wqe_cnt, &tail) <= 0) {
			ret = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (wr->num_sge > qp->rq.max_gs) {
			ret = EINVAL;
			*bad_wr = wr;
			goto out;
		}

		/* Fetch wqe */
		wqe_hdr = (struct pvrdma_rq_wqe_hdr *)get_rq_wqe(qp, ind);
		wqe_hdr->wr_id = wr->wr_id;
		wqe_hdr->num_sge = wr->num_sge;

		sge = (struct ibv_sge *)(wqe_hdr + 1);
		for (i = 0; i < wr->num_sge; ++i) {
			sge->addr = (uint64_t)wr->sg_list[i].addr;
			sge->length = wr->sg_list[i].length;
			sge->lkey = wr->sg_list[i].lkey;
			sge++;
		}

		pvrdma_idx_ring_inc(&qp->rq.ring_state->prod_tail,
				    qp->rq.wqe_cnt);

		qp->rq.wrid[ind] = wr->wr_id;
		ind = (ind + 1) & (qp->rq.wqe_cnt - 1);
	}

out:
	if (nreq)
		pvrdma_write_uar_qp(ctx->uar,
				    PVRDMA_UAR_QP_RECV | qp->qp_handle);

	pthread_spin_unlock(&qp->rq.lock);
	return ret;
}

int pvrdma_post_srq_recv(struct ibv_srq *ibsrq,
			 struct ibv_recv_wr *wr,
			 struct ibv_recv_wr **bad_wr)
{
	struct pvrdma_context *ctx = to_vctx(ibsrq->context);
	struct pvrdma_srq *srq = to_vsrq(ibsrq);
	struct pvrdma_rq_wqe_hdr *wqe_hdr;
	struct ibv_sge *sge;
	int nreq;
	int ind;
	int i;
	int ret = 0;

	if (!wr || !bad_wr)
		return EINVAL;

	pthread_spin_lock(&srq->lock);

	ind = pvrdma_idx(&(srq->ring_state->rx.prod_tail), srq->wqe_cnt);
	if (ind < 0) {
		pthread_spin_unlock(&srq->lock);
		*bad_wr = wr;
		return EINVAL;
	}

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		unsigned int tail;

		if (pvrdma_idx_ring_has_space(&srq->ring_state->rx,
					      srq->wqe_cnt, &tail) <= 0) {
			ret = ENOMEM;
			*bad_wr = wr;
			break;
		}

		if (wr->num_sge > srq->max_gs) {
			ret = EINVAL;
			*bad_wr = wr;
			break;
		}

		/* Fetch wqe */
		wqe_hdr = (struct pvrdma_rq_wqe_hdr *)get_srq_wqe(srq, ind);
		wqe_hdr->wr_id = wr->wr_id;
		wqe_hdr->num_sge = wr->num_sge;

		sge = (struct ibv_sge *)(wqe_hdr + 1);
		for (i = 0; i < wr->num_sge; ++i) {
			sge->addr = (uint64_t)wr->sg_list[i].addr;
			sge->length = wr->sg_list[i].length;
			sge->lkey = wr->sg_list[i].lkey;
			sge++;
		}

		pvrdma_idx_ring_inc(&srq->ring_state->rx.prod_tail,
				    srq->wqe_cnt);

		srq->wrid[ind] = wr->wr_id;
		ind = (ind + 1) & (srq->wqe_cnt - 1);
	}

	if (nreq)
		pvrdma_write_uar_srq(ctx->uar,
				     PVRDMA_UAR_SRQ_RECV | srq->srqn);

	pthread_spin_unlock(&srq->lock);

	return ret;
}

int pvrdma_alloc_srq_buf(struct pvrdma_device *dev,
			 struct ibv_srq_attr *attr,
			 struct pvrdma_srq *srq)
{
	srq->wrid = calloc(srq->wqe_cnt, sizeof(uint64_t));
	if (!srq->wrid)
		return -1;

	srq->buf.length = align(srq->offset, dev->page_size);
	srq->buf.length += 2 * align(srq->wqe_cnt * srq->wqe_size, dev->page_size);

	if (pvrdma_alloc_buf(&srq->buf, srq->buf.length, dev->page_size)) {
		free(srq->wrid);
		return -1;
	}

	memset(srq->buf.buf, 0, srq->buf.length);

	return 0;
}
