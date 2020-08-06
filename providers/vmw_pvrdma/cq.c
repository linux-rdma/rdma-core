/*
 * Copyright (c) 2012-2016 VMware, Inc.  All rights reserved.
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

enum {
	CQ_OK =  0,
	CQ_EMPTY = -1,
	CQ_POLL_ERR = -2,
};

enum {
	PVRDMA_CQE_IS_SEND_MASK = 0x40,
	PVRDMA_CQE_OPCODE_MASK = 0x1f,
};

int pvrdma_alloc_cq_buf(struct pvrdma_device *dev, struct pvrdma_cq *cq,
			struct pvrdma_buf *buf, int entries)
{
	if (pvrdma_alloc_buf(buf, cq->offset +
			     entries * (sizeof(struct pvrdma_cqe)),
			     dev->page_size))
		return -1;
	memset(buf->buf, 0, buf->length);

	return 0;
}

static struct pvrdma_cqe *get_cqe(struct pvrdma_cq *cq, int entry)
{
	return cq->buf.buf + cq->offset +
	       entry * (sizeof(struct pvrdma_cqe));
}

static int pvrdma_poll_one(struct pvrdma_cq *cq,
			   struct pvrdma_qp **cur_qp,
			   struct ibv_wc *wc)
{
	struct pvrdma_context *ctx = to_vctx(cq->ibv_cq.context);
	int has_data;
	unsigned int head;
	int tried = 0;
	struct pvrdma_cqe *cqe;

retry:
	has_data = pvrdma_idx_ring_has_data(&cq->ring_state->rx,
					    cq->cqe_cnt, &head);
	if (has_data == 0) {
		unsigned int val;

		if (tried)
			return CQ_EMPTY;

		/* Pass down POLL to give physical HCA a chance to poll. */
		val = cq->cqn | PVRDMA_UAR_CQ_POLL;
		pvrdma_write_uar_cq(ctx->uar, val);

		tried = 1;
		goto retry;
	} else if (has_data == -1) {
		return CQ_POLL_ERR;
	}

	cqe = get_cqe(cq, head);
	if (!cqe)
		return CQ_EMPTY;

	udma_from_device_barrier();

	if (ctx->qp_tbl[cqe->qp & 0xFFFF])
		*cur_qp = (struct pvrdma_qp *)ctx->qp_tbl[cqe->qp & 0xFFFF];
	 else
		return CQ_POLL_ERR;

	wc->opcode = pvrdma_wc_opcode_to_ibv(cqe->opcode);
	wc->status = pvrdma_wc_status_to_ibv(cqe->status);
	wc->wr_id = cqe->wr_id;
	wc->qp_num = (*cur_qp)->ibv_qp.qp_num;
	wc->byte_len = cqe->byte_len;
	wc->imm_data = cqe->imm_data;
	wc->src_qp = cqe->src_qp;
	wc->wc_flags = cqe->wc_flags;
	wc->pkey_index = cqe->pkey_index;
	wc->slid = cqe->slid;
	wc->sl = cqe->sl;
	wc->dlid_path_bits = cqe->dlid_path_bits;
	wc->vendor_err = 0;

	/* Update shared ring state. */
	pvrdma_idx_ring_inc(&(cq->ring_state->rx.cons_head), cq->cqe_cnt);

	return CQ_OK;
}

int pvrdma_poll_cq(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc)
{
	struct pvrdma_cq *cq = to_vcq(ibcq);
	struct pvrdma_qp *qp;
	int npolled = 0;

	if (num_entries < 1 || wc == NULL)
		return 0;

	pthread_spin_lock(&cq->lock);

	for (npolled = 0; npolled < num_entries; ++npolled) {
		if (pvrdma_poll_one(cq, &qp, wc + npolled) != CQ_OK)
			break;
	}

	pthread_spin_unlock(&cq->lock);

	return npolled;
}

void pvrdma_cq_clean_int(struct pvrdma_cq *cq, uint32_t qp_handle)
{
	/* Flush CQEs from specified QP */
	int has_data;
	unsigned int head;

	/* Lock held */
	has_data = pvrdma_idx_ring_has_data(&cq->ring_state->rx,
					    cq->cqe_cnt, &head);

	if (unlikely(has_data > 0)) {
		int items;
		int curr;
		int tail = pvrdma_idx(&cq->ring_state->rx.prod_tail,
				      cq->cqe_cnt);
		struct pvrdma_cqe *cqe;
		struct pvrdma_cqe *curr_cqe;

		items = (tail > head) ? (tail - head) :
			(cq->cqe_cnt - head + tail);
		curr = --tail;
		while (items-- > 0) {
			if (curr < 0)
				curr = cq->cqe_cnt - 1;
			if (tail < 0)
				tail = cq->cqe_cnt - 1;
			curr_cqe = get_cqe(cq, curr);
			udma_from_device_barrier();
			if ((curr_cqe->qp & 0xFFFF) != qp_handle) {
				if (curr != tail) {
					cqe = get_cqe(cq, tail);
					udma_from_device_barrier();
					*cqe = *curr_cqe;
				}
				tail--;
			} else {
				pvrdma_idx_ring_inc(
					&cq->ring_state->rx.cons_head,
					cq->cqe_cnt);
			}
			curr--;
		}
	}
}

void pvrdma_cq_clean(struct pvrdma_cq *cq, uint32_t qp_handle)
{
	pthread_spin_lock(&cq->lock);
	pvrdma_cq_clean_int(cq, qp_handle);
	pthread_spin_unlock(&cq->lock);
}

struct ibv_cq *pvrdma_create_cq(struct ibv_context *context, int cqe,
				struct ibv_comp_channel *channel,
				int comp_vector)
{
	struct pvrdma_device *dev = to_vdev(context->device);
	struct user_pvrdma_create_cq cmd;
	struct user_pvrdma_create_cq_resp resp;
	struct pvrdma_cq *cq;
	int ret;

	if (cqe < 1)
		return NULL;

	cq = malloc(sizeof(*cq));
	if (!cq)
		return NULL;

	/* Extra page for shared ring state */
	cq->offset = dev->page_size;

	if (pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE))
		goto err;

	cqe = align_next_power2(cqe);

	if (pvrdma_alloc_cq_buf(dev, cq, &cq->buf, cqe))
		goto err;

	cq->ring_state = cq->buf.buf;

	cmd.buf_addr = (uintptr_t) cq->buf.buf;
	cmd.buf_size = cq->buf.length;
	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				&cq->ibv_cq, &cmd.ibv_cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp));
	if (ret)
		goto err_buf;

	cq->cqn = resp.cqn;
	cq->cqe_cnt = cq->ibv_cq.cqe;

	return &cq->ibv_cq;

err_buf:
	pvrdma_free_buf(&cq->buf);
err:
	free(cq);

	return NULL;
}

int pvrdma_destroy_cq(struct ibv_cq *cq)
{
	int ret;

	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		return ret;

	pvrdma_free_buf(&to_vcq(cq)->buf);
	free(to_vcq(cq));

	return 0;
}

int pvrdma_req_notify_cq(struct ibv_cq *ibcq, int solicited)
{
	struct pvrdma_context *ctx = to_vctx(ibcq->context);
	struct pvrdma_cq *cq = to_vcq(ibcq);
	unsigned int val = cq->cqn;

	val |= solicited ? PVRDMA_UAR_CQ_ARM_SOL : PVRDMA_UAR_CQ_ARM;
	pvrdma_write_uar_cq(ctx->uar, val);

	return 0;
}
