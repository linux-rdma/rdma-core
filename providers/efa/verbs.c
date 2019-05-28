// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <ccan/minmax.h>

#include <util/compiler.h>
#include <util/mmio.h>
#include <util/util.h>

#include "efa.h"
#include "efadv.h"
#include "verbs.h"

int efa_query_device(struct ibv_context *ibvctx,
		     struct ibv_device_attr *dev_attr)
{
	struct efa_context *ctx = to_efa_context(ibvctx);
	struct ibv_query_device cmd;
	uint8_t fw_ver[8];
	int err;

	err = ibv_cmd_query_device(ibvctx, dev_attr, (uint64_t *)&fw_ver,
				   &cmd, sizeof(cmd));
	if (err)
		return err;

	dev_attr->max_qp_wr = min_t(int, dev_attr->max_qp_wr,
				    ctx->max_llq_size / sizeof(struct efa_io_tx_wqe));
	snprintf(dev_attr->fw_ver, sizeof(dev_attr->fw_ver), "%u.%u.%u.%u",
		 fw_ver[0], fw_ver[1], fw_ver[2], fw_ver[3]);

	return 0;
}

int efa_query_port(struct ibv_context *ibvctx, uint8_t port,
		   struct ibv_port_attr *port_attr)
{
	struct ibv_query_port cmd;

	memset(port_attr, 0, sizeof(struct ibv_port_attr));
	return ibv_cmd_query_port(ibvctx, port, port_attr, &cmd, sizeof(cmd));
}

int efa_query_device_ex(struct ibv_context *context,
			const struct ibv_query_device_ex_input *input,
			struct ibv_device_attr_ex *attr,
			size_t attr_size)
{
	struct efa_context *ctx = to_efa_context(context);
	struct efa_dev *dev = to_efa_dev(context->device);
	int cmd_supp_uhw = ctx->cmds_supp_udata_mask &
			   EFA_USER_CMDS_SUPP_UDATA_QUERY_DEVICE;
	struct efa_query_device_ex_resp resp = {};
	struct ibv_query_device_ex cmd;
	struct ibv_device_attr *a;
	uint8_t fw_ver[8];
	int err;

	err = ibv_cmd_query_device_ex(
		context, input, attr, attr_size, (uint64_t *)&fw_ver, &cmd,
		sizeof(cmd), &resp.ibv_resp,
		cmd_supp_uhw ? sizeof(resp) : sizeof(resp.ibv_resp));
	if (err)
		return err;

	dev->max_sq_wr = resp.max_sq_wr;
	dev->max_rq_wr = resp.max_rq_wr;
	dev->max_sq_sge = resp.max_sq_sge;
	dev->max_rq_sge = resp.max_rq_sge;

	a = &attr->orig_attr;
	a->max_qp_wr = min_t(int, a->max_qp_wr,
			     ctx->max_llq_size / sizeof(struct efa_io_tx_wqe));
	snprintf(a->fw_ver, sizeof(a->fw_ver), "%u.%u.%u.%u",
		 fw_ver[0], fw_ver[1], fw_ver[2], fw_ver[3]);

	return 0;
}

struct ibv_pd *efa_alloc_pd(struct ibv_context *ibvctx)
{
	struct efa_alloc_pd_resp resp = {};
	struct ibv_alloc_pd cmd;
	struct efa_pd *pd;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(ibvctx, &pd->ibvpd, &cmd, sizeof(cmd),
			     &resp.ibv_resp, sizeof(resp)))
		goto out;

	pd->context = to_efa_context(ibvctx);
	pd->pdn = resp.pdn;

	return &pd->ibvpd;

out:
	free(pd);
	return NULL;
}

int efa_dealloc_pd(struct ibv_pd *ibvpd)
{
	struct efa_pd *pd = to_efa_pd(ibvpd);
	int err;

	err = ibv_cmd_dealloc_pd(ibvpd);
	if (err)
		return err;
	free(pd);

	return 0;
}

struct ibv_mr *efa_reg_mr(struct ibv_pd *ibvpd, void *sva, size_t len,
			  uint64_t hca_va, int access)
{
	struct ib_uverbs_reg_mr_resp resp;
	struct ibv_reg_mr cmd;
	struct efa_mr *mr;

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return NULL;

	if (ibv_cmd_reg_mr(ibvpd, sva, len, hca_va, access, &mr->vmr,
			   &cmd, sizeof(cmd), &resp, sizeof(resp))) {
		free(mr);
		return NULL;
	}

	return &mr->vmr.ibv_mr;
}

int efa_dereg_mr(struct verbs_mr *vmr)
{
	struct efa_mr *mr = container_of(vmr, struct efa_mr, vmr);
	int err;

	err = ibv_cmd_dereg_mr(vmr);
	if (err)
		return err;
	free(mr);

	return 0;
}

static uint32_t efa_sub_cq_get_current_index(struct efa_sub_cq *sub_cq)
{
	return sub_cq->consumed_cnt & sub_cq->qmask;
}

static int efa_cqe_is_pending(struct efa_io_cdesc_common *cqe_common,
				 int phase)
{
	return (cqe_common->flags & EFA_IO_CDESC_COMMON_PHASE_MASK) == phase;
}

static struct efa_io_cdesc_common *
efa_sub_cq_get_cqe(struct efa_sub_cq *sub_cq, int entry)
{
	return (struct efa_io_cdesc_common *)(sub_cq->buf +
					      (entry * sub_cq->cqe_size));
}

static void efa_sub_cq_initialize(struct efa_sub_cq *sub_cq, uint8_t *buf,
				     int sub_cq_size, int cqe_size)
{
	sub_cq->consumed_cnt = 0;
	sub_cq->phase = 1;
	sub_cq->buf = buf;
	sub_cq->qmask = sub_cq_size - 1;
	sub_cq->cqe_size = cqe_size;
	sub_cq->ref_cnt = 0;
}

struct ibv_cq *efa_create_cq(struct ibv_context *ibvctx, int ncqe,
			     struct ibv_comp_channel *channel, int vec)
{
	struct efa_context *ctx = to_efa_context(ibvctx);
	struct efa_create_cq_resp resp = {};
	struct efa_create_cq cmd = {};
	uint16_t num_sub_cqs;
	struct efa_cq *cq;
	int sub_buf_size;
	int sub_cq_size;
	uint8_t *buf;
	int i;

	cq = calloc(1, sizeof(*cq) +
		       sizeof(*cq->sub_cq_arr) * ctx->sub_cqs_per_cq);
	if (!cq)
		return NULL;

	num_sub_cqs = ctx->sub_cqs_per_cq;
	cmd.num_sub_cqs = num_sub_cqs;
	cmd.cq_entry_size = ctx->cqe_size;

	ncqe = roundup_pow_of_two(ncqe);
	if (ibv_cmd_create_cq(ibvctx, ncqe, channel, vec,
			      &cq->ibvcq, &cmd.ibv_cmd, sizeof(cmd),
			      &resp.ibv_resp, sizeof(resp)))
		goto err_free_cq;

	sub_cq_size = cq->ibvcq.cqe;
	cq->cqn = resp.cq_idx;
	cq->buf_size = resp.q_mmap_size;
	cq->num_sub_cqs = num_sub_cqs;
	cq->cqe_size = ctx->cqe_size;

	cq->buf = mmap(NULL, cq->buf_size, PROT_READ, MAP_SHARED,
		       ibvctx->cmd_fd, resp.q_mmap_key);
	if (cq->buf == MAP_FAILED)
		goto err_destroy_cq;

	buf = cq->buf;
	sub_buf_size = cq->cqe_size * sub_cq_size;
	for (i = 0; i < num_sub_cqs; i++) {
		efa_sub_cq_initialize(&cq->sub_cq_arr[i], buf, sub_cq_size,
				      cq->cqe_size);
		buf += sub_buf_size;
	}

	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);

	return &cq->ibvcq;

err_destroy_cq:
	ibv_cmd_destroy_cq(&cq->ibvcq);
err_free_cq:
	free(cq);
	return NULL;
}

int efa_destroy_cq(struct ibv_cq *ibvcq)
{
	struct efa_cq *cq = to_efa_cq(ibvcq);
	int err;

	munmap(cq->buf, cq->buf_size);

	pthread_spin_destroy(&cq->lock);

	err = ibv_cmd_destroy_cq(ibvcq);
	if (err)
		return err;

	free(cq);

	return 0;
}

static struct efa_io_cdesc_common *
cq_next_sub_cqe_get(struct efa_sub_cq *sub_cq)
{
	struct efa_io_cdesc_common *cqe;
	uint32_t current_index;

	current_index = efa_sub_cq_get_current_index(sub_cq);
	cqe = efa_sub_cq_get_cqe(sub_cq, current_index);
	if (efa_cqe_is_pending(cqe, sub_cq->phase)) {
		/* Do not read the rest of the completion entry before the
		 * phase bit has been validated.
		 */
		udma_from_device_barrier();
		sub_cq->consumed_cnt++;
		if (!efa_sub_cq_get_current_index(sub_cq))
			sub_cq->phase = 1 - sub_cq->phase;
		return cqe;
	}

	return NULL;
}

static enum ibv_wc_status to_ibv_status(enum efa_io_comp_status status)
{
	switch (status) {
	case EFA_IO_COMP_STATUS_OK:
		return IBV_WC_SUCCESS;
	case EFA_IO_COMP_STATUS_FLUSHED:
		return IBV_WC_WR_FLUSH_ERR;
	case EFA_IO_COMP_STATUS_LOCAL_ERROR_QP_INTERNAL_ERROR:
	case EFA_IO_COMP_STATUS_LOCAL_ERROR_INVALID_OP_TYPE:
	case EFA_IO_COMP_STATUS_LOCAL_ERROR_INVALID_AH:
		return IBV_WC_LOC_QP_OP_ERR;
	case EFA_IO_COMP_STATUS_LOCAL_ERROR_INVALID_LKEY:
		return IBV_WC_LOC_PROT_ERR;
	case EFA_IO_COMP_STATUS_LOCAL_ERROR_BAD_LENGTH:
		return IBV_WC_LOC_LEN_ERR;
	case EFA_IO_COMP_STATUS_REMOTE_ERROR_ABORT:
		return IBV_WC_REM_ABORT_ERR;
	case EFA_IO_COMP_STATUS_REMOTE_ERROR_RNR:
		return IBV_WC_RNR_RETRY_EXC_ERR;
	case EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_DEST_QPN:
		return IBV_WC_REM_INV_RD_REQ_ERR;
	case EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_STATUS:
		return IBV_WC_BAD_RESP_ERR;
	case EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_LENGTH:
		return IBV_WC_REM_INV_REQ_ERR;
	case EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_ADDRESS:
	default:
		return IBV_WC_GENERAL_ERR;
	}
}

static int efa_poll_sub_cq(struct efa_cq *cq, struct efa_sub_cq *sub_cq,
			   struct efa_qp **cur_qp, struct ibv_wc *wc)
{
	struct efa_context *ctx = to_efa_context(cq->ibvcq.context);
	struct efa_io_cdesc_common *cqe;
	uint32_t qpn, wrid_idx;
	struct efa_wq *wq;

	cqe = cq_next_sub_cqe_get(sub_cq);
	if (!cqe)
		return ENOMEM;

	qpn = cqe->qp_num;
	if (!*cur_qp || qpn != (*cur_qp)->ibvqp.qp_num) {
		/* We do not have to take the QP table lock here,
		 * because CQs will be locked while QPs are removed
		 * from the table.
		 */
		*cur_qp = ctx->qp_table[qpn];
		if (!*cur_qp)
			return EINVAL;
	}

	wrid_idx = cqe->req_id;
	wc->status = to_ibv_status(cqe->status);
	wc->vendor_err = cqe->status;
	if (get_efa_io_cdesc_common_q_type(cqe) == EFA_IO_SEND_QUEUE) {
		wq = &(*cur_qp)->sq.wq;
		wc->opcode = IBV_WC_SEND;
	} else {
		struct efa_io_rx_cdesc *rcqe =
			container_of(cqe, struct efa_io_rx_cdesc, common);

		wq = &(*cur_qp)->rq.wq;

		wc->byte_len = cqe->length;
		wc->opcode = IBV_WC_RECV;
		wc->src_qp = rcqe->src_qp_num;
		wc->sl = 0;
		wc->slid = 0;
	}

	wc->wc_flags = 0;
	wc->qp_num = qpn;
	wq->wrid_idx_pool_next--;
	wq->wrid_idx_pool[wq->wrid_idx_pool_next] = wrid_idx;
	wc->wr_id = wq->wrid[wrid_idx];
	wq->wqe_completed++;

	return 0;
}

static int efa_poll_sub_cqs(struct efa_cq *cq, struct ibv_wc *wc)
{
	uint16_t num_sub_cqs = cq->num_sub_cqs;
	struct efa_sub_cq *sub_cq;
	struct efa_qp *qp = NULL;
	uint16_t sub_cq_idx;
	int err = ENOMEM;

	for (sub_cq_idx = 0; sub_cq_idx < num_sub_cqs; sub_cq_idx++) {
		sub_cq = &cq->sub_cq_arr[cq->next_poll_idx++];
		cq->next_poll_idx %= num_sub_cqs;

		if (!sub_cq->ref_cnt)
			continue;

		err = efa_poll_sub_cq(cq, sub_cq, &qp, wc);
		if (err != ENOMEM)
			break;
	}

	return err;
}

int efa_poll_cq(struct ibv_cq *ibvcq, int nwc, struct ibv_wc *wc)
{
	struct efa_cq *cq = to_efa_cq(ibvcq);
	ssize_t ret = 0;
	int i;

	pthread_spin_lock(&cq->lock);
	for (i = 0; i < nwc; i++) {
		ret = efa_poll_sub_cqs(cq, &wc[i]);
		if (ret) {
			if (ret == ENOMEM)
				ret = 0;
			break;
		}
	}
	pthread_spin_unlock(&cq->lock);

	return i ?: -ret;
}

static void efa_cq_inc_ref_cnt(struct efa_cq *cq, uint8_t sub_cq_idx)
{
	cq->sub_cq_arr[sub_cq_idx].ref_cnt++;
}

static void efa_cq_dec_ref_cnt(struct efa_cq *cq, uint8_t sub_cq_idx)
{
	cq->sub_cq_arr[sub_cq_idx].ref_cnt--;
}

static void efa_wq_terminate(struct efa_wq *wq)
{
	pthread_spin_destroy(&wq->wqlock);
	free(wq->wrid_idx_pool);
	free(wq->wrid);
}

static int efa_wq_initialize(struct efa_wq *wq)
{
	int err;
	int i;

	wq->wrid = malloc(wq->wqe_cnt * sizeof(*wq->wrid));
	if (!wq->wrid)
		return ENOMEM;

	wq->wrid_idx_pool = malloc(wq->wqe_cnt * sizeof(uint32_t));
	if (!wq->wrid_idx_pool) {
		err = ENOMEM;
		goto err_free_wrid;
	}

	/* Initialize the wrid free indexes pool. */
	for (i = 0; i < wq->wqe_cnt; i++)
		wq->wrid_idx_pool[i] = i;

	pthread_spin_init(&wq->wqlock, PTHREAD_PROCESS_PRIVATE);

	return 0;

err_free_wrid:
	free(wq->wrid);

	return err;
}

static void efa_sq_terminate(struct efa_qp *qp)
{
	void *db_aligned;

	if (!qp->sq.wq.wrid)
		return;

	db_aligned = (void *)((uintptr_t)qp->sq.db & ~(qp->page_size - 1));
	munmap(db_aligned, qp->page_size);
	munmap(qp->sq.desc - qp->sq.desc_offset, qp->sq.desc_ring_mmap_size);

	efa_wq_terminate(&qp->sq.wq);
}

static int efa_sq_initialize(struct efa_qp *qp, struct efa_create_qp_resp *resp)
{
	size_t desc_ring_size;
	uint8_t *db_base;
	int err;

	if (!qp->sq.wq.wqe_cnt)
		return 0;

	err = efa_wq_initialize(&qp->sq.wq);
	if (err)
		return err;

	qp->sq.desc_offset = resp->llq_desc_offset;
	desc_ring_size = qp->sq.wq.wqe_cnt * sizeof(struct efa_io_tx_wqe);
	qp->sq.desc_ring_mmap_size = align(desc_ring_size + qp->sq.desc_offset,
					   qp->page_size);
	qp->sq.max_inline_data = resp->ibv_resp.max_inline_data;

	qp->sq.desc = mmap(NULL, qp->sq.desc_ring_mmap_size, PROT_WRITE,
			   MAP_SHARED, qp->ibvqp.context->cmd_fd,
			   resp->llq_desc_mmap_key);
	if (qp->sq.desc == MAP_FAILED)
		goto err_terminate_wq;

	qp->sq.desc += qp->sq.desc_offset;

	db_base = mmap(NULL, qp->page_size, PROT_WRITE, MAP_SHARED,
		       qp->ibvqp.context->cmd_fd, resp->sq_db_mmap_key);
	if (db_base == MAP_FAILED)
		goto err_unmap_desc_ring;

	qp->sq.db = (uint32_t *)(db_base + resp->sq_db_offset);
	qp->sq.sub_cq_idx = resp->send_sub_cq_idx;

	return 0;

err_unmap_desc_ring:
	munmap(qp->sq.desc - qp->sq.desc_offset, qp->sq.desc_ring_mmap_size);
err_terminate_wq:
	efa_wq_terminate(&qp->sq.wq);
	return EINVAL;
}

static void efa_rq_terminate(struct efa_qp *qp)
{
	void *db_aligned;

	if (!qp->rq.wq.wrid)
		return;

	db_aligned = (void *)((uintptr_t)qp->rq.db & ~(qp->page_size - 1));
	munmap(db_aligned, qp->page_size);
	munmap(qp->rq.buf, qp->rq.buf_size);

	efa_wq_terminate(&qp->rq.wq);
}

static int efa_rq_initialize(struct efa_qp *qp, struct efa_create_qp_resp *resp)
{
	uint8_t *db_base;
	int err;

	if (!qp->rq.wq.wqe_cnt)
		return 0;

	err = efa_wq_initialize(&qp->rq.wq);
	if (err)
		return err;

	qp->rq.buf_size = resp->rq_mmap_size;
	qp->rq.buf = mmap(NULL, qp->rq.buf_size, PROT_WRITE, MAP_SHARED,
			  qp->ibvqp.context->cmd_fd, resp->rq_mmap_key);
	if (qp->rq.buf == MAP_FAILED)
		goto err_terminate_wq;

	db_base = mmap(NULL, qp->page_size, PROT_WRITE, MAP_SHARED,
		       qp->ibvqp.context->cmd_fd, resp->rq_db_mmap_key);
	if (db_base == MAP_FAILED)
		goto err_unmap_rq_buf;

	qp->rq.db = (uint32_t *)(db_base + resp->rq_db_offset);
	qp->rq.sub_cq_idx = resp->recv_sub_cq_idx;

	return 0;

err_unmap_rq_buf:
	munmap(qp->rq.buf, qp->rq.buf_size);
err_terminate_wq:
	efa_wq_terminate(&qp->rq.wq);
	return EINVAL;
}

static void efa_qp_init_indices(struct efa_qp *qp)
{
	qp->sq.wq.wqe_posted = 0;
	qp->sq.wq.wqe_completed = 0;
	qp->sq.wq.desc_idx = 0;
	qp->sq.wq.wrid_idx_pool_next = 0;

	qp->rq.wq.wqe_posted = 0;
	qp->rq.wq.wqe_completed = 0;
	qp->rq.wq.desc_idx = 0;
	qp->rq.wq.wrid_idx_pool_next = 0;
}

static void efa_setup_qp(struct efa_qp *qp,
			 struct ibv_qp_cap *cap,
			 size_t page_size)
{
	uint16_t rq_desc_cnt;

	efa_qp_init_indices(qp);

	qp->sq.wq.wqe_cnt = roundup_pow_of_two(cap->max_send_wr);
	qp->sq.wq.max_sge = cap->max_send_sge;
	qp->sq.wq.desc_mask = qp->sq.wq.wqe_cnt - 1;

	qp->rq.wq.max_sge = cap->max_recv_sge;
	rq_desc_cnt = roundup_pow_of_two(cap->max_recv_sge * cap->max_recv_wr);
	qp->rq.wq.desc_mask = rq_desc_cnt - 1;
	qp->rq.wq.wqe_cnt = rq_desc_cnt / qp->rq.wq.max_sge;

	qp->page_size = page_size;
}

static void efa_lock_cqs(struct ibv_qp *ibvqp)
{
	struct efa_cq *send_cq = to_efa_cq(ibvqp->send_cq);
	struct efa_cq *recv_cq = to_efa_cq(ibvqp->recv_cq);

	if (recv_cq == send_cq && recv_cq) {
		pthread_spin_lock(&recv_cq->lock);
	} else {
		if (recv_cq)
			pthread_spin_lock(&recv_cq->lock);
		if (send_cq)
			pthread_spin_lock(&send_cq->lock);
	}
}

static void efa_unlock_cqs(struct ibv_qp *ibvqp)
{
	struct efa_cq *send_cq = to_efa_cq(ibvqp->send_cq);
	struct efa_cq *recv_cq = to_efa_cq(ibvqp->recv_cq);

	if (recv_cq == send_cq && recv_cq) {
		pthread_spin_unlock(&recv_cq->lock);
	} else {
		if (recv_cq)
			pthread_spin_unlock(&recv_cq->lock);
		if (send_cq)
			pthread_spin_unlock(&send_cq->lock);
	}
}

static int efa_check_qp_attr(struct efa_dev *dev,
			     struct ibv_qp_init_attr *attr)
{
	if (!attr->recv_cq || !attr->send_cq)
		return EINVAL;

	if (attr->srq)
		return EINVAL;

	return 0;
}

static int efa_check_qp_limits(struct efa_dev *dev,
			       struct ibv_qp_init_attr *attr)
{
	if (attr->cap.max_send_sge > dev->max_sq_sge)
		return EINVAL;

	if (attr->cap.max_recv_sge > dev->max_rq_sge)
		return EINVAL;

	if (attr->cap.max_send_wr > dev->max_sq_wr)
		return EINVAL;

	if (attr->cap.max_recv_wr > dev->max_rq_wr)
		return EINVAL;

	return 0;
}

static struct ibv_qp *create_qp(struct ibv_pd *ibvpd,
				struct ibv_qp_init_attr *attr,
				uint32_t driver_qp_type)
{
	struct efa_context *ctx = to_efa_context(ibvpd->context);
	struct efa_dev *dev = to_efa_dev(ibvpd->context->device);
	struct efa_create_qp_resp resp = {};
	struct efa_create_qp req = {};
	struct efa_cq *send_cq;
	struct efa_cq *recv_cq;
	struct efa_qp *qp;
	int err;

	err = efa_check_qp_attr(dev, attr);
	if (err)
		return NULL;

	err = efa_check_qp_limits(dev, attr);
	if (err)
		return NULL;

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	efa_setup_qp(qp, &attr->cap, dev->pg_sz);

	attr->cap.max_send_wr = qp->sq.wq.wqe_cnt;
	attr->cap.max_recv_wr = qp->rq.wq.wqe_cnt;

	req.rq_ring_size = (qp->rq.wq.desc_mask + 1) *
		sizeof(struct efa_io_rx_desc);
	req.sq_ring_size = (attr->cap.max_send_wr) *
		sizeof(struct efa_io_tx_wqe);
	if (attr->qp_type == IBV_QPT_DRIVER)
		req.driver_qp_type = driver_qp_type;

	if (ibv_cmd_create_qp(ibvpd, &qp->ibvqp, attr, &req.ibv_cmd,
			      sizeof(req), &resp.ibv_resp, sizeof(resp)))
		goto err_free_qp;

	qp->ibvqp.state = IBV_QPS_RESET;
	qp->sq_sig_all = attr->sq_sig_all;
	qp->ctx = ctx;

	err = efa_rq_initialize(qp, &resp);
	if (err)
		goto err_destroy_qp;

	err = efa_sq_initialize(qp, &resp);
	if (err)
		goto err_terminate_rq;

	pthread_spin_lock(&ctx->qp_table_lock);
	ctx->qp_table[qp->ibvqp.qp_num] = qp;
	pthread_spin_unlock(&ctx->qp_table_lock);

	if (attr->send_cq) {
		send_cq = to_efa_cq(attr->send_cq);
		qp->scq = send_cq;
		pthread_spin_lock(&send_cq->lock);
		efa_cq_inc_ref_cnt(send_cq, resp.send_sub_cq_idx);
		pthread_spin_unlock(&send_cq->lock);
	}

	if (attr->recv_cq) {
		recv_cq = to_efa_cq(attr->recv_cq);
		qp->rcq = recv_cq;
		pthread_spin_lock(&recv_cq->lock);
		efa_cq_inc_ref_cnt(recv_cq, resp.recv_sub_cq_idx);
		pthread_spin_unlock(&recv_cq->lock);
	}

	return &qp->ibvqp;

err_terminate_rq:
	efa_rq_terminate(qp);
err_destroy_qp:
	ibv_cmd_destroy_qp(&qp->ibvqp);
err_free_qp:
	free(qp);
	return NULL;
}

struct ibv_qp *efa_create_qp(struct ibv_pd *ibvpd,
			     struct ibv_qp_init_attr *attr)
{
	if (attr->qp_type != IBV_QPT_UD)
		return NULL;

	return create_qp(ibvpd, attr, 0);
}

struct ibv_qp *efadv_create_driver_qp(struct ibv_pd *ibvpd,
				      struct ibv_qp_init_attr *attr,
				      uint32_t driver_qp_type)
{
	if (!is_efa_dev(ibvpd->context->device) ||
	    attr->qp_type != IBV_QPT_DRIVER)
		return NULL;

	return create_qp(ibvpd, attr, driver_qp_type);
}

int efa_modify_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr,
		  int attr_mask)
{
	struct efa_qp *qp = to_efa_qp(ibvqp);
	struct ibv_modify_qp cmd;
	int err;

	err = ibv_cmd_modify_qp(ibvqp, attr, attr_mask, &cmd, sizeof(cmd));
	if (err)
		return err;

	if (attr_mask & IBV_QP_STATE) {
		qp->ibvqp.state = attr->qp_state;
		/* transition to reset */
		if (qp->ibvqp.state == IBV_QPS_RESET)
			efa_qp_init_indices(qp);
	}

	return 0;
}

int efa_query_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr,
		 int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	return ibv_cmd_query_qp(ibvqp, attr, attr_mask, init_attr,
				&cmd, sizeof(cmd));
}

int efa_destroy_qp(struct ibv_qp *ibvqp)
{
	struct efa_context *ctx = to_efa_context(ibvqp->context);
	struct efa_qp *qp = to_efa_qp(ibvqp);
	int err;

	pthread_spin_lock(&ctx->qp_table_lock);
	efa_lock_cqs(ibvqp);

	if (ibvqp->send_cq)
		efa_cq_dec_ref_cnt(to_efa_cq(ibvqp->send_cq),
				   qp->sq.sub_cq_idx);

	if (ibvqp->recv_cq)
		efa_cq_dec_ref_cnt(to_efa_cq(ibvqp->recv_cq),
				   qp->rq.sub_cq_idx);

	ctx->qp_table[ibvqp->qp_num] = NULL;

	efa_unlock_cqs(ibvqp);
	pthread_spin_unlock(&ctx->qp_table_lock);

	efa_sq_terminate(qp);
	efa_rq_terminate(qp);

	err = ibv_cmd_destroy_qp(ibvqp);
	if (err)
		return err;

	free(qp);
	return 0;
}

static void efa_post_send_sgl(struct ibv_send_wr *wr,
			      struct efa_io_tx_wqe *tx_wqe,
			      int *desc_size)
{
	struct efa_io_tx_buf_desc *tx_buf;
	struct ibv_sge *sge;
	uintptr_t addr;
	size_t i;

	for (i = 0; i < wr->num_sge; i++) {
		sge = &wr->sg_list[i];
		tx_buf = &tx_wqe->data.sgl[i];
		addr = sge->addr;

		/* Set TX buffer desc from SGE */
		tx_buf->length = sge->length;
		tx_buf->lkey = sge->lkey;
		tx_buf->buf_addr_lo = addr & 0xffffffff;
		tx_buf->buf_addr_hi = (uint64_t)addr >> 32;
	}

	*desc_size += sizeof(*tx_buf) * wr->num_sge;
}

static void efa_post_send_inline_data(const struct ibv_send_wr *wr,
				      struct efa_io_tx_wqe *tx_wqe,
				      int *desc_size)
{
	const struct ibv_sge *sgl = wr->sg_list;
	uint32_t total_length = 0;
	uint32_t length;
	size_t i;

	for (i = 0; i < wr->num_sge; i++) {
		length = sgl[i].length;

		memcpy(tx_wqe->data.inline_data + total_length,
		       (void *)(uintptr_t)sgl[i].addr, length);
		total_length += length;
	}

	*desc_size += total_length;

	set_efa_io_tx_meta_desc_inline_msg(&tx_wqe->common, 1);
	tx_wqe->common.length = total_length;
}

static size_t efa_sge_total_bytes(const struct ibv_send_wr *wr)
{
	size_t bytes = 0;
	size_t i;

	for (i = 0; i < wr->num_sge; i++)
		bytes += wr->sg_list[i].length;

	return bytes;
}

static ssize_t efa_post_send_validate(struct efa_qp *qp,
				      const struct ibv_send_wr *wr)
{
	if (unlikely(qp->ibvqp.state != IBV_QPS_RTS &&
		     qp->ibvqp.state != IBV_QPS_SQD))
		return EINVAL;

	if (unlikely(wr->opcode != IBV_WR_SEND))
		return EINVAL;

	if (unlikely(!qp->scq))
		return EINVAL;

	if (unlikely(wr->num_sge > qp->sq.wq.max_sge))
		return EINVAL;

	if (unlikely(!(wr->send_flags & IBV_SEND_SIGNALED) && !qp->sq_sig_all))
		return EINVAL;

	if (unlikely(wr->send_flags & ~(IBV_SEND_SIGNALED | IBV_SEND_INLINE)))
		return EINVAL;

	if (unlikely(wr->send_flags & IBV_SEND_INLINE &&
		     efa_sge_total_bytes(wr) > qp->sq.max_inline_data))
		return EINVAL;

	if (unlikely(qp->sq.wq.wqe_posted - qp->sq.wq.wqe_completed ==
		     qp->sq.wq.wqe_cnt))
		return ENOMEM;

	return 0;
}

int efa_post_send(struct ibv_qp *ibvqp, struct ibv_send_wr *wr,
		  struct ibv_send_wr **bad)
{
	struct efa_io_tx_meta_desc *meta_desc;
	struct efa_qp *qp = to_efa_qp(ibvqp);
	uint32_t sq_desc_offset, wrid_idx;
	struct efa_io_tx_wqe tx_wqe;
	struct efa_ah *ah;
	int desc_size;
	int err = 0;

	pthread_spin_lock(&qp->sq.wq.wqlock);
	while (wr) {
		desc_size = sizeof(tx_wqe.common) + sizeof(tx_wqe.u);

		err = efa_post_send_validate(qp, wr);
		if (err) {
			*bad = wr;
			goto ring_db;
		}

		memset(&tx_wqe, 0, sizeof(tx_wqe));
		meta_desc = &tx_wqe.common;
		ah = to_efa_ah(wr->wr.ud.ah);

		if (efa_sge_total_bytes(wr) <= qp->ctx->inline_buf_size) {
			efa_post_send_inline_data(wr, &tx_wqe, &desc_size);
		} else {
			meta_desc->length = wr->num_sge;
			efa_post_send_sgl(wr, &tx_wqe, &desc_size);
		}

		/* Get the next wrid to be used from the index pool */
		wrid_idx = qp->sq.wq.wrid_idx_pool[qp->sq.wq.wrid_idx_pool_next];
		qp->sq.wq.wrid[wrid_idx] = wr->wr_id;
		meta_desc->req_id = wrid_idx;
		qp->sq.wq.wqe_posted++;

		/* Will never overlap, as efa_post_send_validate() succeeded */
		qp->sq.wq.wrid_idx_pool_next++;
		assert(qp->sq.wq.wrid_idx_pool_next <= qp->sq.wq.wqe_cnt);

		/* Set rest of the descriptor fields */
		set_efa_io_tx_meta_desc_meta_desc(meta_desc, 1);
		set_efa_io_tx_meta_desc_phase(meta_desc, qp->sq.wq.phase);
		set_efa_io_tx_meta_desc_first(meta_desc, 1);
		set_efa_io_tx_meta_desc_last(meta_desc, 1);
		meta_desc->dest_qp_num = wr->wr.ud.remote_qpn;
		set_efa_io_tx_meta_desc_comp_req(meta_desc, 1);
		meta_desc->ah = ah->efa_ah;
		tx_wqe.u.ud.qkey = wr->wr.ud.remote_qkey;

		/* Copy descriptor */
		sq_desc_offset = (qp->sq.wq.desc_idx & qp->sq.wq.desc_mask) *
				 sizeof(tx_wqe);
		memcpy(qp->sq.desc + sq_desc_offset, &tx_wqe, desc_size);

		/* advance index and change phase */
		qp->sq.wq.desc_idx++;
		if (!(qp->sq.wq.desc_idx & qp->sq.wq.desc_mask))
			qp->sq.wq.phase++;

		wr = wr->next;
	}

ring_db:
	udma_to_device_barrier();
	mmio_write32(qp->sq.db, qp->sq.wq.desc_idx);

	pthread_spin_unlock(&qp->sq.wq.wqlock);
	return err;
}

static ssize_t efa_post_recv_validate(struct efa_qp *qp, struct ibv_recv_wr *wr)
{
	if (unlikely(qp->ibvqp.state == IBV_QPS_RESET ||
		     qp->ibvqp.state == IBV_QPS_ERR))
		return EINVAL;

	if (unlikely(!qp->rcq))
		return EINVAL;

	if (unlikely(wr->num_sge > qp->rq.wq.max_sge))
		return EINVAL;

	if (unlikely(qp->rq.wq.wqe_posted - qp->rq.wq.wqe_completed ==
		     qp->rq.wq.wqe_cnt))
		return ENOMEM;

	return 0;
}

int efa_post_recv(struct ibv_qp *ibvqp, struct ibv_recv_wr *wr,
		  struct ibv_recv_wr **bad)
{
	struct efa_qp *qp = to_efa_qp(ibvqp);
	uint32_t wqe_index, rq_desc_offset;
	struct efa_io_rx_desc rx_buf;
	uintptr_t addr;
	int err = 0;
	size_t i;

	pthread_spin_lock(&qp->rq.wq.wqlock);
	while (wr) {
		err = efa_post_recv_validate(qp, wr);
		if (err) {
			*bad = wr;
			goto ring_db;
		}

		memset(&rx_buf, 0, sizeof(rx_buf));

		/* Save wrid */
		/* Get the next wrid to be used from the index pool */
		wqe_index = qp->rq.wq.wrid_idx_pool[qp->rq.wq.wrid_idx_pool_next];
		qp->rq.wq.wrid[wqe_index] = wr->wr_id;
		rx_buf.req_id = wqe_index;
		qp->rq.wq.wqe_posted++;

		/* Will never overlap, as efa_post_recv_validate() succeeded */
		qp->rq.wq.wrid_idx_pool_next++;
		assert(qp->rq.wq.wrid_idx_pool_next <= qp->rq.wq.wqe_cnt);

		/* Default init of the rx buffer */
		set_efa_io_rx_desc_first(&rx_buf, 1);
		set_efa_io_rx_desc_last(&rx_buf, 0);

		for (i = 0; i < wr->num_sge; i++) {
			/* Set last indication if need) */
			if (i == wr->num_sge - 1)
				set_efa_io_rx_desc_last(&rx_buf, 1);

			addr = wr->sg_list[i].addr;

			/* Set RX buffer desc from SGE */
			rx_buf.length = wr->sg_list[i].length;
			set_efa_io_rx_desc_lkey(&rx_buf, wr->sg_list[i].lkey);
			rx_buf.buf_addr_lo = addr;
			rx_buf.buf_addr_hi = (uint64_t)addr >> 32;

			/* Copy descriptor to RX ring */
			rq_desc_offset = (qp->rq.wq.desc_idx & qp->rq.wq.desc_mask) * sizeof(rx_buf);
			memcpy(qp->rq.buf + rq_desc_offset, &rx_buf, sizeof(rx_buf));

			/* Wrap rx descriptor index */
			qp->rq.wq.desc_idx++;
			if (!(qp->rq.wq.desc_idx & qp->rq.wq.desc_mask))
				qp->rq.wq.phase++;

			/* reset descriptor for next iov */
			memset(&rx_buf, 0, sizeof(rx_buf));
		}
		wr = wr->next;
	}

ring_db:
	udma_to_device_barrier();
	mmio_write32(qp->rq.db, qp->rq.wq.desc_idx);

	pthread_spin_unlock(&qp->rq.wq.wqlock);
	return err;
}

struct ibv_ah *efa_create_ah(struct ibv_pd *ibvpd, struct ibv_ah_attr *attr)
{
	struct efa_create_ah_resp resp = {};
	struct efa_ah *ah;
	int err;

	ah = calloc(1, sizeof(*ah));
	if (!ah)
		return NULL;

	err = ibv_cmd_create_ah(ibvpd, &ah->ibvah, attr,
				&resp.ibv_resp, sizeof(resp));
	if (err) {
		free(ah);
		return NULL;
	}

	ah->efa_ah = resp.efa_address_handle;

	return &ah->ibvah;
}

int efa_destroy_ah(struct ibv_ah *ibvah)
{
	struct efa_ah *ah;
	int err;

	ah = to_efa_ah(ibvah);
	err = ibv_cmd_destroy_ah(ibvah);
	if (err)
		return err;
	free(ah);

	return 0;
}
