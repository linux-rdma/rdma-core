/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies Ltd.  All rights reserved.
 * Copyright (c) 2007 Cisco, Inc.  All rights reserved.
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
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>

#include "mlx4.h"
#include "doorbell.h"
#include "wqe.h"

static const uint32_t mlx4_ib_opcode[] = {
	[IBV_WR_SEND]			= MLX4_OPCODE_SEND,
	[IBV_WR_SEND_WITH_IMM]		= MLX4_OPCODE_SEND_IMM,
	[IBV_WR_RDMA_WRITE]		= MLX4_OPCODE_RDMA_WRITE,
	[IBV_WR_RDMA_WRITE_WITH_IMM]	= MLX4_OPCODE_RDMA_WRITE_IMM,
	[IBV_WR_RDMA_READ]		= MLX4_OPCODE_RDMA_READ,
	[IBV_WR_ATOMIC_CMP_AND_SWP]	= MLX4_OPCODE_ATOMIC_CS,
	[IBV_WR_ATOMIC_FETCH_AND_ADD]	= MLX4_OPCODE_ATOMIC_FA,
};

static void *get_recv_wqe(struct mlx4_qp *qp, int n)
{
	return qp->buf.buf + qp->rq.offset + (n << qp->rq.wqe_shift);
}

static void *get_send_wqe(struct mlx4_qp *qp, int n)
{
	return qp->buf.buf + qp->sq.offset + (n << qp->sq.wqe_shift);
}

void mlx4_init_qp_indices(struct mlx4_qp *qp)
{
	qp->sq.head	 = 0;
	qp->sq.tail	 = 0;
	qp->rq.head	 = 0;
	qp->rq.tail	 = 0;
}

static int wq_overflow(struct mlx4_wq *wq, int nreq, struct mlx4_cq *cq)
{
	unsigned cur;

	cur = wq->head - wq->tail;
	if (cur + nreq < wq->max)
		return 0;

	pthread_spin_lock(&cq->lock);
	cur = wq->head - wq->tail;
	pthread_spin_unlock(&cq->lock);

	return cur + nreq >= wq->max;
}

int mlx4_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
			  struct ibv_send_wr **bad_wr)
{
	struct mlx4_context *ctx;
	struct mlx4_qp *qp = to_mqp(ibqp);
	void *wqe;
	struct mlx4_wqe_ctrl_seg *ctrl;
	int ind;
	int nreq;
	int inl = 0;
	int ret = 0;
	int size;
	int i;

	pthread_spin_lock(&qp->sq.lock);

	/* XXX check that state is OK to post send */

	ind = qp->sq.head;

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (wq_overflow(&qp->sq, nreq, to_mcq(qp->ibv_qp.send_cq))) {
			ret = -1;
			*bad_wr = wr;
			goto out;
		}

		if (wr->num_sge > qp->sq.max_gs) {
			ret = -1;
			*bad_wr = wr;
			goto out;
		}

		if (wr->opcode >= sizeof mlx4_ib_opcode / sizeof mlx4_ib_opcode[0]) {
			ret = -1;
			*bad_wr = wr;
			goto out;
		}

		ctrl = wqe = get_send_wqe(qp, ind & (qp->sq.max - 1));
		qp->sq.wrid[ind & (qp->sq.max - 1)] = wr->wr_id;

		ctrl->srcrb_flags =
			(wr->send_flags & IBV_SEND_SIGNALED ?
			 htonl(MLX4_WQE_CTRL_CQ_UPDATE) : 0) |
			(wr->send_flags & IBV_SEND_SOLICITED ?
			 htonl(MLX4_WQE_CTRL_SOLICIT) : 0)   |
			qp->sq_signal_bits;

		if (wr->opcode == IBV_WR_SEND_WITH_IMM ||
		    wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
			ctrl->imm = wr->imm_data;
		else
			ctrl->imm = 0;

		wqe += sizeof *ctrl;
		size = sizeof *ctrl / 16;

		switch (ibqp->qp_type) {
		case IBV_QPT_RC:
		case IBV_QPT_UC:
			switch (wr->opcode) {
			case IBV_WR_ATOMIC_CMP_AND_SWP:
			case IBV_WR_ATOMIC_FETCH_AND_ADD:
				((struct mlx4_wqe_raddr_seg *) wqe)->raddr =
					htonll(wr->wr.atomic.remote_addr);
				((struct mlx4_wqe_raddr_seg *) wqe)->rkey =
					htonl(wr->wr.atomic.rkey);
				((struct mlx4_wqe_raddr_seg *) wqe)->reserved = 0;

				wqe  += sizeof (struct mlx4_wqe_raddr_seg);

				if (wr->opcode == IBV_WR_ATOMIC_CMP_AND_SWP) {
					((struct mlx4_wqe_atomic_seg *) wqe)->swap_add =
						htonll(wr->wr.atomic.swap);
					((struct mlx4_wqe_atomic_seg *) wqe)->compare =
						htonll(wr->wr.atomic.compare_add);
				} else {
					((struct mlx4_wqe_atomic_seg *) wqe)->swap_add =
						htonll(wr->wr.atomic.compare_add);
					((struct mlx4_wqe_atomic_seg *) wqe)->compare = 0;
				}

				wqe  += sizeof (struct mlx4_wqe_atomic_seg);
				size += (sizeof (struct mlx4_wqe_raddr_seg) +
					 sizeof (struct mlx4_wqe_atomic_seg)) / 16;

				break;

			case IBV_WR_RDMA_WRITE:
			case IBV_WR_RDMA_WRITE_WITH_IMM:
			case IBV_WR_RDMA_READ:
				((struct mlx4_wqe_raddr_seg *) wqe)->raddr =
					htonll(wr->wr.rdma.remote_addr);
				((struct mlx4_wqe_raddr_seg *) wqe)->rkey =
					htonl(wr->wr.rdma.rkey);
				((struct mlx4_wqe_raddr_seg *) wqe)->reserved = 0;

				wqe  += sizeof (struct mlx4_wqe_raddr_seg);
				size += sizeof (struct mlx4_wqe_raddr_seg) / 16;

				break;

			default:
				/* No extra segments required for sends */
				break;
			}
			break;

		case IBV_QPT_UD:
			memcpy(((struct mlx4_wqe_datagram_seg *) wqe)->av,
			       &to_mah(wr->wr.ud.ah)->av, sizeof (struct mlx4_av));
			((struct mlx4_wqe_datagram_seg *) wqe)->dqpn =
				htonl(wr->wr.ud.remote_qpn);
			((struct mlx4_wqe_datagram_seg *) wqe)->qkey =
				htonl(wr->wr.ud.remote_qkey);

			wqe  += sizeof (struct mlx4_wqe_datagram_seg);
			size += sizeof (struct mlx4_wqe_datagram_seg) / 16;
			break;

		default:
			break;
		}

		if (wr->send_flags & IBV_SEND_INLINE) {
			if (wr->num_sge) {
				struct mlx4_wqe_inline_seg *seg = wqe;

				inl = 0;
				wqe += sizeof *seg;
				for (i = 0; i < wr->num_sge; ++i) {
					uint32_t len = wr->sg_list[i].length;

					inl += len;

					if (inl > qp->max_inline_data) {
						ret = -1;
						*bad_wr = wr;
						goto out;
					}

					memcpy(wqe,
					       (void *) (intptr_t) wr->sg_list[i].addr,
					       len);
					wqe += len;
				}

				seg->byte_count = htonl(MLX4_INLINE_SEG | inl);
				size += (inl + sizeof *seg + 15) / 16;
			}
		} else {
			struct mlx4_wqe_data_seg *seg = wqe;

			for (i = 0; i < wr->num_sge; ++i) {
				seg[i].byte_count = htonl(wr->sg_list[i].length);
				seg[i].lkey       = htonl(wr->sg_list[i].lkey);
				seg[i].addr       = htonll(wr->sg_list[i].addr);
			}

			size += wr->num_sge * (sizeof *seg / 16);
		}

		ctrl->fence_size = (wr->send_flags & IBV_SEND_FENCE ?
				    MLX4_WQE_CTRL_FENCE : 0) | size;

		/*
		 * Make sure descriptor is fully written before
		 * setting ownership bit (because HW can start
		 * executing as soon as we do).
		 */
		wmb();

		ctrl->owner_opcode = htonl(mlx4_ib_opcode[wr->opcode]) |
			(ind & qp->sq.max ? htonl(1 << 31) : 0);

		++ind;
	}

out:
	ctx = to_mctx(ibqp->context);

	if (nreq == 1 && inl && size > 1 && size < ctx->bf_buf_size / 16) {
		ctrl->owner_opcode |= htonl((qp->sq.head & 0xffff) << 8);
		*(uint32_t *) ctrl->reserved |= qp->doorbell_qpn;
		/*
		 * Make sure that descriptor is written to memory
		 * before writing to BlueFlame page.
		 */
		wmb();

		++qp->sq.head;

		pthread_spin_lock(&ctx->bf_lock);
		memcpy(ctx->bf_page + ctx->bf_offset, ctrl, align(size * 16, 64));
		/* FIXME flush wc buffers */
		ctx->bf_offset ^= ctx->bf_buf_size;
		pthread_spin_unlock(&ctx->bf_lock);
	} else if (nreq) {
		qp->sq.head += nreq;

		/*
		 * Make sure that descriptors are written before
		 * doorbell record.
		 */
		wmb();

		*(uint32_t *) (ctx->uar + MLX4_SEND_DOORBELL) = qp->doorbell_qpn;
	}

	pthread_spin_unlock(&qp->sq.lock);

	return ret;
}

int mlx4_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		   struct ibv_recv_wr **bad_wr)
{
	struct mlx4_qp *qp = to_mqp(ibqp);
	struct mlx4_wqe_data_seg *scat;
	int ret = 0;
	int nreq;
	int ind;
	int i;

	pthread_spin_lock(&qp->rq.lock);

	/* XXX check that state is OK to post receive */

	ind = qp->rq.head & (qp->rq.max - 1);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (wq_overflow(&qp->rq, nreq, to_mcq(qp->ibv_qp.recv_cq))) {
			ret = -1;
			*bad_wr = wr;
			goto out;
		}

		if (wr->num_sge > qp->rq.max_gs) {
			ret = -1;
			*bad_wr = wr;
			goto out;
		}

		scat = get_recv_wqe(qp, ind);

		for (i = 0; i < wr->num_sge; ++i) {
			scat[i].byte_count = htonl(wr->sg_list[i].length);
			scat[i].lkey       = htonl(wr->sg_list[i].lkey);
			scat[i].addr       = htonll(wr->sg_list[i].addr);
		}

		if (i < qp->rq.max_gs) {
			scat[i].byte_count = 0;
			scat[i].lkey       = htonl(MLX4_INVALID_LKEY);
			scat[i].addr       = 0;
		}

		qp->rq.wrid[ind] = wr->wr_id;

		ind = (ind + 1) & (qp->rq.max - 1);
	}

out:
	if (nreq) {
		qp->rq.head += nreq;

		/*
		 * Make sure that descriptors are written before
		 * doorbell record.
		 */
		wmb();

		*qp->db = htonl(qp->rq.head & 0xffff);
	}

	pthread_spin_unlock(&qp->rq.lock);

	return ret;
}

int mlx4_alloc_qp_buf(struct ibv_pd *pd, struct ibv_qp_cap *cap,
		       enum ibv_qp_type type, struct mlx4_qp *qp)
{
	struct mlx4_wqe_ctrl_seg *ctrl;
	int size;
	int max_sq_sge;
	int i;

	qp->rq.max_gs	 = cap->max_recv_sge;
	qp->sq.max_gs	 = cap->max_send_sge;
	max_sq_sge	 = align(cap->max_inline_data + sizeof (struct mlx4_wqe_inline_seg),
				 sizeof (struct mlx4_wqe_data_seg)) / sizeof (struct mlx4_wqe_data_seg);
	if (max_sq_sge < cap->max_send_sge)
		max_sq_sge = cap->max_send_sge;

	qp->sq.wrid = malloc(qp->sq.max * sizeof (uint64_t));
	if (!qp->sq.wrid)
		return -1;

	qp->rq.wrid = malloc(qp->rq.max * sizeof (uint64_t));
	if (!qp->rq.wrid) {
		free(qp->sq.wrid);
		return -1;
	}

	size = qp->rq.max_gs * sizeof (struct mlx4_wqe_data_seg);

	for (qp->rq.wqe_shift = 4; 1 << qp->rq.wqe_shift < size;
	     qp->rq.wqe_shift++)
		; /* nothing */

	size = max_sq_sge * sizeof (struct mlx4_wqe_data_seg);
	switch (type) {
	case IBV_QPT_UD:
		size += sizeof (struct mlx4_wqe_datagram_seg);
		break;

	case IBV_QPT_UC:
		size += sizeof (struct mlx4_wqe_raddr_seg);
		break;

	case IBV_QPT_RC:
		size += sizeof (struct mlx4_wqe_raddr_seg);
		/*
		 * An atomic op will require an atomic segment, a
		 * remote address segment and one scatter entry.
		 */
		if (size < (sizeof (struct mlx4_wqe_atomic_seg) +
			    sizeof (struct mlx4_wqe_raddr_seg) +
			    sizeof (struct mlx4_wqe_data_seg)))
			size = (sizeof (struct mlx4_wqe_atomic_seg) +
				sizeof (struct mlx4_wqe_raddr_seg) +
				sizeof (struct mlx4_wqe_data_seg));
		break;

	default:
		break;
	}

	/* Make sure that we have enough space for a bind request */
	if (size < sizeof (struct mlx4_wqe_bind_seg))
		size = sizeof (struct mlx4_wqe_bind_seg);

	size += sizeof (struct mlx4_wqe_ctrl_seg);

	for (qp->sq.wqe_shift = 6; 1 << qp->sq.wqe_shift < size;
	     qp->sq.wqe_shift++)
		; /* nothing */

	qp->buf_size = (qp->rq.max << qp->rq.wqe_shift) +
		(qp->sq.max << qp->sq.wqe_shift);
	if (qp->rq.wqe_shift > qp->sq.wqe_shift) {
		qp->rq.offset = 0;
		qp->sq.offset = qp->rq.max << qp->rq.wqe_shift;
	} else {
		qp->rq.offset = qp->sq.max << qp->sq.wqe_shift;
		qp->sq.offset = 0;
	}

	if (mlx4_alloc_buf(&qp->buf,
			    align(qp->buf_size, to_mdev(pd->context->device)->page_size),
			    to_mdev(pd->context->device)->page_size)) {
		free(qp->sq.wrid);
		free(qp->rq.wrid);
		return -1;
	}

	memset(qp->buf.buf, 0, qp->buf_size);

	for (i = 0; i < qp->sq.max; ++i) {
		ctrl = get_send_wqe(qp, i);
		ctrl->owner_opcode = htonl(1 << 31);
	}

	return 0;
}

struct mlx4_qp *mlx4_find_qp(struct mlx4_context *ctx, uint32_t qpn)
{
	int tind = (qpn & (ctx->num_qps - 1)) >> ctx->qp_table_shift;

	if (ctx->qp_table[tind].refcnt)
		return ctx->qp_table[tind].table[qpn & ctx->qp_table_mask];
	else
		return NULL;
}

int mlx4_store_qp(struct mlx4_context *ctx, uint32_t qpn, struct mlx4_qp *qp)
{
	int tind = (qpn & (ctx->num_qps - 1)) >> ctx->qp_table_shift;
	int ret = 0;

	pthread_mutex_lock(&ctx->qp_table_mutex);

	if (!ctx->qp_table[tind].refcnt) {
		ctx->qp_table[tind].table = calloc(ctx->qp_table_mask + 1,
						   sizeof (struct mlx4_qp *));
		if (!ctx->qp_table[tind].table) {
			ret = -1;
			goto out;
		}
	}

	++ctx->qp_table[tind].refcnt;
	ctx->qp_table[tind].table[qpn & ctx->qp_table_mask] = qp;

out:
	pthread_mutex_unlock(&ctx->qp_table_mutex);
	return ret;
}

void mlx4_clear_qp(struct mlx4_context *ctx, uint32_t qpn)
{
	int tind = (qpn & (ctx->num_qps - 1)) >> ctx->qp_table_shift;

	pthread_mutex_lock(&ctx->qp_table_mutex);

	if (!--ctx->qp_table[tind].refcnt)
		free(ctx->qp_table[tind].table);
	else
		ctx->qp_table[tind].table[qpn & ctx->qp_table_mask] = NULL;

	pthread_mutex_unlock(&ctx->qp_table_mutex);
}
