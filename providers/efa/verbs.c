// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright 2019-2023 Amazon.com, Inc. or its affiliates. All rights reserved.
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
#include "efa_io_regs_defs.h"
#include "efadv.h"
#include "verbs.h"

#define EFA_DEV_CAP(ctx, cap) \
	((ctx)->device_caps & EFA_QUERY_DEVICE_CAPS_##cap)

static bool is_buf_cleared(void *buf, size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (((uint8_t *)buf)[i])
			return false;
	}

	return true;
}

#define min3(a, b, c) \
	({ \
		typeof(a) _tmpmin = min(a, b); \
		min(_tmpmin, c); \
	})

#define is_ext_cleared(ptr, inlen) \
	is_buf_cleared((uint8_t *)ptr + sizeof(*ptr), inlen - sizeof(*ptr))

#define is_reserved_cleared(reserved) is_buf_cleared(reserved, sizeof(reserved))

struct efa_wq_init_attr {
	uint64_t db_mmap_key;
	uint32_t db_off;
	int cmd_fd;
	int pgsz;
	uint16_t sub_cq_idx;
};

int efa_query_port(struct ibv_context *ibvctx, uint8_t port,
		   struct ibv_port_attr *port_attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(ibvctx, port, port_attr, &cmd, sizeof(cmd));
}

int efa_query_device_ex(struct ibv_context *context,
			const struct ibv_query_device_ex_input *input,
			struct ibv_device_attr_ex *attr,
			size_t attr_size)
{
	struct efa_context *ctx = to_efa_context(context);
	struct ibv_device_attr *a = &attr->orig_attr;
	struct efa_query_device_ex_resp resp = {};
	size_t resp_size = (ctx->cmds_supp_udata_mask &
			    EFA_USER_CMDS_SUPP_UDATA_QUERY_DEVICE) ?
				   sizeof(resp) :
				   sizeof(resp.ibv_resp);
	uint8_t fw_ver[8];
	int err;

	err = ibv_cmd_query_device_any(context, input, attr, attr_size,
				       &resp.ibv_resp, &resp_size);
	if (err) {
		verbs_err(verbs_get_ctx(context), "ibv_cmd_query_device_any failed\n");
		return err;
	}

	a->max_qp_wr = min_t(int, a->max_qp_wr,
			     ctx->max_llq_size / sizeof(struct efa_io_tx_wqe));
	memcpy(fw_ver, &resp.ibv_resp.base.fw_ver,
	       sizeof(resp.ibv_resp.base.fw_ver));
	snprintf(a->fw_ver, sizeof(a->fw_ver), "%u.%u.%u.%u",
		 fw_ver[0], fw_ver[1], fw_ver[2], fw_ver[3]);

	return 0;
}

int efa_query_device_ctx(struct efa_context *ctx)
{
	struct efa_query_device_ex_resp resp = {};
	struct ibv_device_attr_ex attr;
	size_t resp_size = sizeof(resp);
	unsigned int qp_table_sz;
	int err;

	if (ctx->cmds_supp_udata_mask & EFA_USER_CMDS_SUPP_UDATA_QUERY_DEVICE) {
		err = ibv_cmd_query_device_any(&ctx->ibvctx.context, NULL,
					       &attr, sizeof(attr),
					       &resp.ibv_resp, &resp_size);
		if (err) {
			verbs_err(&ctx->ibvctx,
				  "ibv_cmd_query_device_any failed\n");
			return err;
		}

		ctx->device_caps = resp.device_caps;
		ctx->max_sq_wr = resp.max_sq_wr;
		ctx->max_rq_wr = resp.max_rq_wr;
		ctx->max_sq_sge = resp.max_sq_sge;
		ctx->max_rq_sge = resp.max_rq_sge;
		ctx->max_rdma_size = resp.max_rdma_size;
	} else {
		err = ibv_cmd_query_device_any(&ctx->ibvctx.context, NULL,
					       &attr, sizeof(attr.orig_attr),
					       NULL, NULL);
		if (err) {
			verbs_err(&ctx->ibvctx,
				  "ibv_cmd_query_device_any failed\n");
			return err;
		}
	}

	ctx->max_wr_rdma_sge = attr.orig_attr.max_sge_rd;
	qp_table_sz = roundup_pow_of_two(attr.orig_attr.max_qp);
	ctx->qp_table_sz_m1 = qp_table_sz - 1;
	ctx->qp_table = calloc(qp_table_sz, sizeof(*ctx->qp_table));
	if (!ctx->qp_table)
		return ENOMEM;
	return 0;
}

int efadv_query_device(struct ibv_context *ibvctx,
		       struct efadv_device_attr *attr,
		       uint32_t inlen)
{
	struct efa_context *ctx = to_efa_context(ibvctx);
	uint64_t comp_mask_out = 0;

	if (!is_efa_dev(ibvctx->device)) {
		verbs_err(verbs_get_ctx(ibvctx), "Not an EFA device\n");
		return EOPNOTSUPP;
	}

	if (!vext_field_avail(typeof(*attr), inline_buf_size, inlen)) {
		verbs_err(verbs_get_ctx(ibvctx), "Compatibility issues\n");
		return EINVAL;
	}

	memset(attr, 0, inlen);
	attr->max_sq_wr = ctx->max_sq_wr;
	attr->max_rq_wr = ctx->max_rq_wr;
	attr->max_sq_sge = ctx->max_sq_sge;
	attr->max_rq_sge = ctx->max_rq_sge;
	attr->inline_buf_size = ctx->inline_buf_size;

	if (vext_field_avail(typeof(*attr), device_caps, inlen)) {
		if (EFA_DEV_CAP(ctx, RNR_RETRY))
			attr->device_caps |= EFADV_DEVICE_ATTR_CAPS_RNR_RETRY;

		if (EFA_DEV_CAP(ctx, CQ_WITH_SGID))
			attr->device_caps |= EFADV_DEVICE_ATTR_CAPS_CQ_WITH_SGID;
	}

	if (vext_field_avail(typeof(*attr), max_rdma_size, inlen)) {
		attr->max_rdma_size = ctx->max_rdma_size;

		if (EFA_DEV_CAP(ctx, RDMA_READ))
			attr->device_caps |= EFADV_DEVICE_ATTR_CAPS_RDMA_READ;

		if (EFA_DEV_CAP(ctx, RDMA_WRITE))
			attr->device_caps |= EFADV_DEVICE_ATTR_CAPS_RDMA_WRITE;
	}

	attr->comp_mask = comp_mask_out;

	return 0;
}

struct ibv_pd *efa_alloc_pd(struct ibv_context *ibvctx)
{
	struct efa_alloc_pd_resp resp = {};
	struct ibv_alloc_pd cmd;
	struct efa_pd *pd;
	int err;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	err = ibv_cmd_alloc_pd(ibvctx, &pd->ibvpd, &cmd, sizeof(cmd),
			       &resp.ibv_resp, sizeof(resp));
	if (err) {
		verbs_err(verbs_get_ctx(ibvctx), "Failed to allocate PD\n");
		goto out;
	}

	pd->pdn = resp.pdn;

	return &pd->ibvpd;

out:
	free(pd);
	errno = err;
	return NULL;
}

int efa_dealloc_pd(struct ibv_pd *ibvpd)
{
	struct efa_pd *pd = to_efa_pd(ibvpd);
	int err;

	err = ibv_cmd_dealloc_pd(ibvpd);
	if (err) {
		verbs_err(verbs_get_ctx(ibvpd->context),
			  "Failed to deallocate PD\n");
		return err;
	}
	free(pd);

	return 0;
}

struct ibv_mr *efa_reg_dmabuf_mr(struct ibv_pd *ibvpd, uint64_t offset,
				 size_t length, uint64_t iova, int fd, int acc)
{
	struct efa_mr *mr;
	int err;

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return NULL;

	err = ibv_cmd_reg_dmabuf_mr(ibvpd, offset, length, iova, fd, acc,
				    &mr->vmr);
	if (err) {
		free(mr);
		errno = err;
		return NULL;
	}

	return &mr->vmr.ibv_mr;
}

struct ibv_mr *efa_reg_mr(struct ibv_pd *ibvpd, void *sva, size_t len,
			  uint64_t hca_va, int access)
{
	struct ib_uverbs_reg_mr_resp resp;
	struct ibv_reg_mr cmd;
	struct efa_mr *mr;
	int err;

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return NULL;

	err = ibv_cmd_reg_mr(ibvpd, sva, len, hca_va, access, &mr->vmr,
			     &cmd, sizeof(cmd), &resp, sizeof(resp));
	if (err) {
		verbs_err(verbs_get_ctx(ibvpd->context),
			  "Failed to register MR\n");
		free(mr);
		errno = err;
		return NULL;
	}

	return &mr->vmr.ibv_mr;
}

int efa_dereg_mr(struct verbs_mr *vmr)
{
	struct efa_mr *mr = container_of(vmr, struct efa_mr, vmr);
	int err;

	err = ibv_cmd_dereg_mr(vmr);
	if (err) {
		verbs_err(verbs_get_ctx(vmr->ibv_mr.context),
			  "Failed to deregister MR\n");
		return err;
	}
	free(mr);

	return 0;
}

static uint32_t efa_wq_get_next_wrid_idx_locked(struct efa_wq *wq,
						uint64_t wr_id)
{
	uint32_t wrid_idx;

	/* Get the next wrid to be used from the index pool */
	wrid_idx = wq->wrid_idx_pool[wq->wrid_idx_pool_next];
	wq->wrid[wrid_idx] = wr_id;

	/* Will never overlap, as validate function succeeded */
	wq->wrid_idx_pool_next++;
	assert(wq->wrid_idx_pool_next <= wq->wqe_cnt);

	return wrid_idx;
}

static void efa_wq_put_wrid_idx_unlocked(struct efa_wq *wq, uint32_t wrid_idx)
{
	pthread_spin_lock(&wq->wqlock);
	wq->wrid_idx_pool_next--;
	wq->wrid_idx_pool[wq->wrid_idx_pool_next] = wrid_idx;
	wq->wqe_completed++;
	pthread_spin_unlock(&wq->wqlock);
}

static uint32_t efa_sub_cq_get_current_index(struct efa_sub_cq *sub_cq)
{
	return sub_cq->consumed_cnt & sub_cq->qmask;
}

static int efa_cqe_is_pending(struct efa_io_cdesc_common *cqe_common,
			      int phase)
{
	return EFA_GET(&cqe_common->flags, EFA_IO_CDESC_COMMON_PHASE) == phase;
}

static struct efa_io_cdesc_common *
efa_sub_cq_get_cqe(struct efa_sub_cq *sub_cq, int entry)
{
	return (struct efa_io_cdesc_common *)(sub_cq->buf +
					      (entry * sub_cq->cqe_size));
}

static void efa_update_cq_doorbell(struct efa_cq *cq, bool arm)
{
	uint32_t db = 0;

	EFA_SET(&db, EFA_IO_REGS_CQ_DB_CONSUMER_INDEX, cq->cc);
	EFA_SET(&db, EFA_IO_REGS_CQ_DB_CMD_SN, cq->cmd_sn & 0x3);
	EFA_SET(&db, EFA_IO_REGS_CQ_DB_ARM, arm);

	mmio_write32(cq->db, db);
}

void efa_cq_event(struct ibv_cq *ibvcq)
{
	to_efa_cq(ibvcq)->cmd_sn++;
}

int efa_arm_cq(struct ibv_cq *ibvcq, int solicited_only)
{
	if (unlikely(solicited_only))
		return EOPNOTSUPP;

	efa_update_cq_doorbell(to_efa_cq(ibvcq), true);
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
	case EFA_IO_COMP_STATUS_LOCAL_ERROR_UNRESP_REMOTE:
		return IBV_WC_RESP_TIMEOUT_ERR;
	case EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_ADDRESS:
	default:
		return IBV_WC_GENERAL_ERR;
	}
}

static void efa_process_cqe(struct efa_cq *cq, struct ibv_wc *wc,
			    struct efa_qp *qp)
{
	struct efa_io_cdesc_common *cqe = cq->cur_cqe;
	enum efa_io_send_op_type op_type;
	uint32_t wrid_idx;

	wc->status = to_ibv_status(cqe->status);
	wc->vendor_err = cqe->status;
	wc->wc_flags = 0;
	wc->qp_num = cqe->qp_num;

	op_type = EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_OP_TYPE);

	if (EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_Q_TYPE) ==
	    EFA_IO_SEND_QUEUE) {
		cq->cur_wq = &qp->sq.wq;
		if (op_type == EFA_IO_RDMA_WRITE)
			wc->opcode = IBV_WC_RDMA_WRITE;
		else
			wc->opcode = IBV_WC_SEND;
	} else {
		struct efa_io_rx_cdesc_ex *rcqe =
			container_of(cqe, struct efa_io_rx_cdesc_ex, base.common);

		cq->cur_wq = &qp->rq.wq;

		wc->byte_len = rcqe->base.length;

		if (op_type == EFA_IO_RDMA_WRITE) {
			wc->byte_len |= ((uint32_t)rcqe->u.rdma_write.length_hi << 16);
			wc->opcode = IBV_WC_RECV_RDMA_WITH_IMM;
		} else {
			wc->opcode = IBV_WC_RECV;
		}

		wc->src_qp = rcqe->base.src_qp_num;
		wc->sl = 0;
		wc->slid = rcqe->base.ah;

		if (EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_HAS_IMM)) {
			wc->imm_data = htobe32(rcqe->base.imm);
			wc->wc_flags |= IBV_WC_WITH_IMM;
		}
	}

	wrid_idx = cqe->req_id;
	/* We do not have to take the WQ lock here,
	 * because this wrid index has not been freed yet,
	 * so there is no contention on this index.
	 */
	wc->wr_id = cq->cur_wq->wrid[wrid_idx];
}

static void efa_process_ex_cqe(struct efa_cq *cq, struct efa_qp *qp)
{
	struct ibv_cq_ex *ibvcqx = &cq->verbs_cq.cq_ex;
	struct efa_io_cdesc_common *cqe = cq->cur_cqe;
	uint32_t wrid_idx;

	wrid_idx = cqe->req_id;

	if (EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_Q_TYPE) ==
		    EFA_IO_SEND_QUEUE) {
		cq->cur_wq = &qp->sq.wq;
	} else {
		cq->cur_wq = &qp->rq.wq;
	}

	ibvcqx->wr_id = cq->cur_wq->wrid[wrid_idx];
	ibvcqx->status = to_ibv_status(cqe->status);
}

static inline int efa_poll_sub_cq(struct efa_cq *cq, struct efa_sub_cq *sub_cq,
				  struct efa_qp **cur_qp, struct ibv_wc *wc,
				  bool extended) ALWAYS_INLINE;
static inline int efa_poll_sub_cq(struct efa_cq *cq, struct efa_sub_cq *sub_cq,
				  struct efa_qp **cur_qp, struct ibv_wc *wc,
				  bool extended)
{
	struct efa_context *ctx = to_efa_context(cq->verbs_cq.cq.context);
	uint32_t qpn;

	cq->cur_cqe = cq_next_sub_cqe_get(sub_cq);
	if (!cq->cur_cqe)
		return ENOENT;

	qpn = cq->cur_cqe->qp_num;
	if (!*cur_qp || qpn != (*cur_qp)->verbs_qp.qp.qp_num) {
		/* We do not have to take the QP table lock here,
		 * because CQs will be locked while QPs are removed
		 * from the table.
		 */
		*cur_qp = ctx->qp_table[qpn & ctx->qp_table_sz_m1];
		if (!*cur_qp) {
			verbs_err(&ctx->ibvctx,
				  "QP[%u] does not exist in QP table\n",
				  qpn);
			return EINVAL;
		}
	}

	if (extended) {
		efa_process_ex_cqe(cq, *cur_qp);
	} else {
		efa_process_cqe(cq, wc, *cur_qp);
		efa_wq_put_wrid_idx_unlocked(cq->cur_wq, cq->cur_cqe->req_id);
	}

	return 0;
}

static inline int efa_poll_sub_cqs(struct efa_cq *cq, struct ibv_wc *wc,
				   bool extended) ALWAYS_INLINE;
static inline int efa_poll_sub_cqs(struct efa_cq *cq, struct ibv_wc *wc,
				   bool extended)
{
	uint16_t num_sub_cqs = cq->num_sub_cqs;
	struct efa_sub_cq *sub_cq;
	struct efa_qp *qp = NULL;
	uint16_t sub_cq_idx;
	int err = ENOENT;

	for (sub_cq_idx = 0; sub_cq_idx < num_sub_cqs; sub_cq_idx++) {
		sub_cq = &cq->sub_cq_arr[cq->next_poll_idx++];
		cq->next_poll_idx %= num_sub_cqs;

		if (!sub_cq->ref_cnt)
			continue;

		err = efa_poll_sub_cq(cq, sub_cq, &qp, wc, extended);
		if (err != ENOENT) {
			cq->cc++;
			break;
		}
	}

	return err;
}

int efa_poll_cq(struct ibv_cq *ibvcq, int nwc, struct ibv_wc *wc)
{
	struct efa_cq *cq = to_efa_cq(ibvcq);
	int ret = 0;
	int i;

	pthread_spin_lock(&cq->lock);
	for (i = 0; i < nwc; i++) {
		ret = efa_poll_sub_cqs(cq, &wc[i], false);
		if (ret) {
			if (ret == ENOENT)
				ret = 0;
			break;
		}
	}

	if (i && cq->db)
		efa_update_cq_doorbell(cq, false);
	pthread_spin_unlock(&cq->lock);

	return i ?: -ret;
}

static int efa_start_poll(struct ibv_cq_ex *ibvcqx,
			  struct ibv_poll_cq_attr *attr)
{
	struct efa_cq *cq = to_efa_cq_ex(ibvcqx);
	int ret;

	if (unlikely(attr->comp_mask)) {
		verbs_err(verbs_get_ctx(ibvcqx->context),
			  "Invalid comp_mask %u\n",
			  attr->comp_mask);
		return EINVAL;
	}

	pthread_spin_lock(&cq->lock);

	ret = efa_poll_sub_cqs(cq, NULL, true);
	if (ret)
		pthread_spin_unlock(&cq->lock);

	return ret;
}

static int efa_next_poll(struct ibv_cq_ex *ibvcqx)
{
	struct efa_cq *cq = to_efa_cq_ex(ibvcqx);
	int ret;

	efa_wq_put_wrid_idx_unlocked(cq->cur_wq, cq->cur_cqe->req_id);
	ret = efa_poll_sub_cqs(cq, NULL, true);

	return ret;
}

static void efa_end_poll(struct ibv_cq_ex *ibvcqx)
{
	struct efa_cq *cq = to_efa_cq_ex(ibvcqx);

	if (cq->cur_cqe) {
		efa_wq_put_wrid_idx_unlocked(cq->cur_wq, cq->cur_cqe->req_id);
		if (cq->db)
			efa_update_cq_doorbell(cq, false);
	}

	pthread_spin_unlock(&cq->lock);
}

static enum ibv_wc_opcode efa_wc_read_opcode(struct ibv_cq_ex *ibvcqx)
{
	struct efa_cq *cq = to_efa_cq_ex(ibvcqx);
	enum efa_io_send_op_type op_type;
	struct efa_io_cdesc_common *cqe;

	cqe = cq->cur_cqe;
	op_type = EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_OP_TYPE);

	if (EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_Q_TYPE) ==
		    EFA_IO_SEND_QUEUE) {
		if (op_type == EFA_IO_RDMA_WRITE)
			return IBV_WC_RDMA_WRITE;

		return IBV_WC_SEND;
	}

	if (op_type == EFA_IO_RDMA_WRITE)
		return IBV_WC_RECV_RDMA_WITH_IMM;

	return IBV_WC_RECV;
}

static uint32_t efa_wc_read_vendor_err(struct ibv_cq_ex *ibvcqx)
{
	struct efa_cq *cq = to_efa_cq_ex(ibvcqx);

	return cq->cur_cqe->status;
}

static unsigned int efa_wc_read_wc_flags(struct ibv_cq_ex *ibvcqx)
{
	struct efa_cq *cq = to_efa_cq_ex(ibvcqx);
	unsigned int wc_flags = 0;

	if (EFA_GET(&cq->cur_cqe->flags, EFA_IO_CDESC_COMMON_HAS_IMM))
		wc_flags |= IBV_WC_WITH_IMM;

	return wc_flags;
}

static uint32_t efa_wc_read_byte_len(struct ibv_cq_ex *ibvcqx)
{
	struct efa_cq *cq = to_efa_cq_ex(ibvcqx);
	struct efa_io_cdesc_common *cqe;
	struct efa_io_rx_cdesc_ex *rcqe;
	uint32_t length;

	cqe = cq->cur_cqe;

	if (EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_Q_TYPE) != EFA_IO_RECV_QUEUE)
		return 0;

	rcqe = container_of(cqe, struct efa_io_rx_cdesc_ex, base.common);

	length = rcqe->base.length;
	if (EFA_GET(&cqe->flags, EFA_IO_CDESC_COMMON_OP_TYPE) == EFA_IO_RDMA_WRITE)
		length |= ((uint32_t)rcqe->u.rdma_write.length_hi << 16);

	return length;
}

static __be32 efa_wc_read_imm_data(struct ibv_cq_ex *ibvcqx)
{
	struct efa_cq *cq = to_efa_cq_ex(ibvcqx);
	struct efa_io_rx_cdesc *rcqe;

	rcqe = container_of(cq->cur_cqe, struct efa_io_rx_cdesc, common);

	return htobe32(rcqe->imm);
}

static uint32_t efa_wc_read_qp_num(struct ibv_cq_ex *ibvcqx)
{
	struct efa_cq *cq = to_efa_cq_ex(ibvcqx);

	return cq->cur_cqe->qp_num;
}

static uint32_t efa_wc_read_src_qp(struct ibv_cq_ex *ibvcqx)
{
	struct efa_cq *cq = to_efa_cq_ex(ibvcqx);
	struct efa_io_rx_cdesc *rcqe;

	rcqe = container_of(cq->cur_cqe, struct efa_io_rx_cdesc, common);

	return rcqe->src_qp_num;
}

static uint32_t efa_wc_read_slid(struct ibv_cq_ex *ibvcqx)
{
	struct efa_cq *cq = to_efa_cq_ex(ibvcqx);
	struct efa_io_rx_cdesc *rcqe;

	rcqe = container_of(cq->cur_cqe, struct efa_io_rx_cdesc, common);

	return rcqe->ah;
}

static uint8_t efa_wc_read_sl(struct ibv_cq_ex *ibvcqx)
{
	return 0;
}

static uint8_t efa_wc_read_dlid_path_bits(struct ibv_cq_ex *ibvcqx)
{
	return 0;
}

static int efa_wc_read_sgid(struct efadv_cq *efadv_cq, union ibv_gid *sgid)
{
	struct efa_cq *cq = efadv_cq_to_efa_cq(efadv_cq);
	struct efa_io_rx_cdesc_ex *rcqex;

	rcqex = container_of(cq->cur_cqe, struct efa_io_rx_cdesc_ex,
			     base.common);
	if (rcqex->base.ah != 0xFFFF) {
		/* SGID is only available if AH is unknown. */
		return -ENOENT;
	}
	memcpy(sgid->raw, rcqex->u.src_addr, sizeof(sgid->raw));

	return 0;
}

static void efa_cq_fill_pfns(struct efa_cq *cq,
			     struct ibv_cq_init_attr_ex *attr,
			     struct efadv_cq_init_attr *efa_attr)
{
	struct ibv_cq_ex *ibvcqx = &cq->verbs_cq.cq_ex;

	ibvcqx->start_poll = efa_start_poll;
	ibvcqx->end_poll = efa_end_poll;
	ibvcqx->next_poll = efa_next_poll;

	ibvcqx->read_opcode = efa_wc_read_opcode;
	ibvcqx->read_vendor_err = efa_wc_read_vendor_err;
	ibvcqx->read_wc_flags = efa_wc_read_wc_flags;

	if (attr->wc_flags & IBV_WC_EX_WITH_BYTE_LEN)
		ibvcqx->read_byte_len = efa_wc_read_byte_len;
	if (attr->wc_flags & IBV_WC_EX_WITH_IMM)
		ibvcqx->read_imm_data = efa_wc_read_imm_data;
	if (attr->wc_flags & IBV_WC_EX_WITH_QP_NUM)
		ibvcqx->read_qp_num = efa_wc_read_qp_num;
	if (attr->wc_flags & IBV_WC_EX_WITH_SRC_QP)
		ibvcqx->read_src_qp = efa_wc_read_src_qp;
	if (attr->wc_flags & IBV_WC_EX_WITH_SLID)
		ibvcqx->read_slid = efa_wc_read_slid;
	if (attr->wc_flags & IBV_WC_EX_WITH_SL)
		ibvcqx->read_sl = efa_wc_read_sl;
	if (attr->wc_flags & IBV_WC_EX_WITH_DLID_PATH_BITS)
		ibvcqx->read_dlid_path_bits = efa_wc_read_dlid_path_bits;

	if (efa_attr && (efa_attr->wc_flags & EFADV_WC_EX_WITH_SGID))
		cq->dv_cq.wc_read_sgid = efa_wc_read_sgid;
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

static struct ibv_cq_ex *create_cq(struct ibv_context *ibvctx,
				   struct ibv_cq_init_attr_ex *attr,
				   struct efadv_cq_init_attr *efa_attr)
{
	struct efa_context *ctx = to_efa_context(ibvctx);
	uint16_t cqe_size = ctx->ex_cqe_size;
	struct efa_create_cq_resp resp = {};
	struct efa_create_cq cmd = {};
	uint16_t num_sub_cqs;
	struct efa_cq *cq;
	int sub_buf_size;
	int sub_cq_size;
	uint8_t *buf;
	int err;
	int i;

	if (!check_comp_mask(attr->comp_mask, 0) ||
	    !check_comp_mask(attr->wc_flags, IBV_WC_STANDARD_FLAGS)) {
		verbs_err(verbs_get_ctx(ibvctx),
			  "Invalid comp_mask or wc_flags\n");
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (attr->channel &&
	    !EFA_DEV_CAP(ctx, CQ_NOTIFICATIONS)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	cq = calloc(1, sizeof(*cq) +
		       sizeof(*cq->sub_cq_arr) * ctx->sub_cqs_per_cq);
	if (!cq)
		return NULL;

	if (efa_attr && (efa_attr->wc_flags & EFADV_WC_EX_WITH_SGID))
		cmd.flags |= EFA_CREATE_CQ_WITH_SGID;

	num_sub_cqs = ctx->sub_cqs_per_cq;
	cmd.num_sub_cqs = num_sub_cqs;
	cmd.cq_entry_size = cqe_size;
	if (attr->channel)
		cmd.flags |= EFA_CREATE_CQ_WITH_COMPLETION_CHANNEL;

	attr->cqe = roundup_pow_of_two(attr->cqe);
	err = ibv_cmd_create_cq_ex(ibvctx, attr, &cq->verbs_cq,
				   &cmd.ibv_cmd, sizeof(cmd),
				   &resp.ibv_resp, sizeof(resp), 0);
	if (err) {
		errno = err;
		goto err_free_cq;
	}

	sub_cq_size = cq->verbs_cq.cq.cqe;
	cq->cqn = resp.cq_idx;
	cq->buf_size = resp.q_mmap_size;
	cq->num_sub_cqs = num_sub_cqs;
	cq->cqe_size = cqe_size;

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

	if (resp.comp_mask & EFA_CREATE_CQ_RESP_DB_OFF) {
		cq->db = mmap(NULL,
			      to_efa_dev(ibvctx->device)->pg_sz, PROT_WRITE,
			      MAP_SHARED, ibvctx->cmd_fd, resp.db_mmap_key);
		if (cq->db == MAP_FAILED)
			goto err_unmap_cq;

		cq->db = (uint32_t *)((uint8_t *)cq->db + resp.db_off);
	}

	efa_cq_fill_pfns(cq, attr, efa_attr);
	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);

	return &cq->verbs_cq.cq_ex;

err_unmap_cq:
	munmap(cq->buf, cq->buf_size);
err_destroy_cq:
	ibv_cmd_destroy_cq(&cq->verbs_cq.cq);
err_free_cq:
	free(cq);
	verbs_err(verbs_get_ctx(ibvctx), "Failed to create CQ\n");
	return NULL;
}

struct ibv_cq *efa_create_cq(struct ibv_context *ibvctx, int ncqe,
			     struct ibv_comp_channel *channel, int vec)
{
	struct ibv_cq_init_attr_ex attr_ex = {
		.cqe = ncqe,
		.channel = channel,
		.comp_vector = vec
	};
	struct ibv_cq_ex *ibvcqx;

	ibvcqx = create_cq(ibvctx, &attr_ex, NULL);

	return ibvcqx ? ibv_cq_ex_to_cq(ibvcqx) : NULL;
}

struct ibv_cq_ex *efa_create_cq_ex(struct ibv_context *ibvctx,
				   struct ibv_cq_init_attr_ex *attr_ex)
{
	return create_cq(ibvctx, attr_ex, NULL);
}

struct ibv_cq_ex *efadv_create_cq(struct ibv_context *ibvctx,
				  struct ibv_cq_init_attr_ex *attr_ex,
				  struct efadv_cq_init_attr *efa_attr,
				  uint32_t inlen)
{
	struct efa_context *ctx;
	uint64_t supp_wc_flags;

	if (!is_efa_dev(ibvctx->device)) {
		verbs_err(verbs_get_ctx(ibvctx), "Not an EFA device\n");
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (!vext_field_avail(struct efadv_cq_init_attr, wc_flags, inlen) ||
	    efa_attr->comp_mask ||
	    (inlen > sizeof(efa_attr) && !is_ext_cleared(efa_attr, inlen))) {
		verbs_err(verbs_get_ctx(ibvctx), "Compatibility issues\n");
		errno = EINVAL;
		return NULL;
	}

	ctx = to_efa_context(ibvctx);
	supp_wc_flags = EFA_DEV_CAP(ctx, CQ_WITH_SGID) ? EFADV_WC_EX_WITH_SGID : 0;
	if (!check_comp_mask(efa_attr->wc_flags, supp_wc_flags)) {
		verbs_err(verbs_get_ctx(ibvctx),
			  "Invalid EFA wc_flags[%#lx]\n", efa_attr->wc_flags);
		errno = EOPNOTSUPP;
		return NULL;
	}

	return create_cq(ibvctx, attr_ex, efa_attr);
}

struct efadv_cq *efadv_cq_from_ibv_cq_ex(struct ibv_cq_ex *ibvcqx)
{
	struct efa_cq *cq = to_efa_cq_ex(ibvcqx);

	return &cq->dv_cq;
}

int efa_destroy_cq(struct ibv_cq *ibvcq)
{
	struct efa_cq *cq = to_efa_cq(ibvcq);
	int err;

	munmap(cq->db, to_efa_dev(cq->verbs_cq.cq.context->device)->pg_sz);
	munmap(cq->buf, cq->buf_size);

	pthread_spin_destroy(&cq->lock);

	err = ibv_cmd_destroy_cq(ibvcq);
	if (err) {
		verbs_err(verbs_get_ctx(ibvcq->context),
			  "Failed to destroy CQ[%u]\n", cq->cqn);
		return err;
	}

	free(cq);

	return 0;
}

static void efa_cq_inc_ref_cnt(struct efa_cq *cq, uint8_t sub_cq_idx)
{
	cq->sub_cq_arr[sub_cq_idx].ref_cnt++;
}

static void efa_cq_dec_ref_cnt(struct efa_cq *cq, uint8_t sub_cq_idx)
{
	cq->sub_cq_arr[sub_cq_idx].ref_cnt--;
}

static void efa_wq_terminate(struct efa_wq *wq, int pgsz)
{
	void *db_aligned;

	pthread_spin_destroy(&wq->wqlock);

	db_aligned = (void *)((uintptr_t)wq->db & ~(pgsz - 1));
	munmap(db_aligned, pgsz);

	free(wq->wrid_idx_pool);
	free(wq->wrid);
}

static int efa_wq_initialize(struct efa_wq *wq, struct efa_wq_init_attr *attr)
{
	uint8_t *db_base;
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

	db_base = mmap(NULL, attr->pgsz, PROT_WRITE, MAP_SHARED, attr->cmd_fd,
		       attr->db_mmap_key);
	if (db_base == MAP_FAILED) {
		err = errno;
		goto err_free_wrid_idx_pool;
	}

	wq->db = (uint32_t *)(db_base + attr->db_off);

	/* Initialize the wrid free indexes pool. */
	for (i = 0; i < wq->wqe_cnt; i++)
		wq->wrid_idx_pool[i] = i;

	pthread_spin_init(&wq->wqlock, PTHREAD_PROCESS_PRIVATE);

	wq->sub_cq_idx = attr->sub_cq_idx;

	return 0;

err_free_wrid_idx_pool:
	free(wq->wrid_idx_pool);
err_free_wrid:
	free(wq->wrid);
	return err;
}

static void efa_sq_terminate(struct efa_qp *qp)
{
	struct efa_sq *sq = &qp->sq;

	if (!sq->wq.wqe_cnt)
		return;

	munmap(sq->desc - sq->desc_offset, sq->desc_ring_mmap_size);
	free(sq->local_queue);

	efa_wq_terminate(&sq->wq, qp->page_size);
}

static int efa_sq_initialize(struct efa_qp *qp,
			     const struct ibv_qp_init_attr_ex *attr,
			     struct efa_create_qp_resp *resp)
{
	struct efa_context *ctx = to_efa_context(qp->verbs_qp.qp.context);
	struct efa_wq_init_attr wq_attr;
	struct efa_sq *sq = &qp->sq;
	size_t desc_ring_size;
	int err;

	if (!sq->wq.wqe_cnt)
		return 0;

	wq_attr = (struct efa_wq_init_attr) {
		.db_mmap_key = resp->sq_db_mmap_key,
		.db_off = resp->sq_db_offset,
		.cmd_fd = qp->verbs_qp.qp.context->cmd_fd,
		.pgsz = qp->page_size,
		.sub_cq_idx = resp->send_sub_cq_idx,
	};

	err = efa_wq_initialize(&qp->sq.wq, &wq_attr);
	if (err) {
		verbs_err(&ctx->ibvctx, "SQ[%u] efa_wq_initialize failed\n",
			  qp->verbs_qp.qp.qp_num);
		return err;
	}

	sq->desc_offset = resp->llq_desc_offset;
	desc_ring_size = sq->wq.wqe_cnt * sizeof(struct efa_io_tx_wqe);
	sq->desc_ring_mmap_size = align(desc_ring_size + sq->desc_offset,
					qp->page_size);
	sq->max_inline_data = attr->cap.max_inline_data;

	sq->local_queue = malloc(desc_ring_size);
	if (!sq->local_queue) {
		err = ENOMEM;
		goto err_terminate_wq;
	}

	sq->desc = mmap(NULL, sq->desc_ring_mmap_size, PROT_WRITE,
			MAP_SHARED, qp->verbs_qp.qp.context->cmd_fd,
			resp->llq_desc_mmap_key);
	if (sq->desc == MAP_FAILED) {
		verbs_err(&ctx->ibvctx, "SQ buffer mmap failed\n");
		err = errno;
		goto err_free_local_queue;
	}

	sq->desc += sq->desc_offset;
	sq->max_wr_rdma_sge = min_t(uint16_t, ctx->max_wr_rdma_sge,
				    EFA_IO_TX_DESC_NUM_RDMA_BUFS);
	sq->max_batch_wr = ctx->max_tx_batch ?
		(ctx->max_tx_batch * 64) / sizeof(struct efa_io_tx_wqe) :
		UINT16_MAX;
	if (ctx->min_sq_wr) {
		/* The device can't accept a doorbell for the whole SQ at once,
		 * set the max batch to at least (SQ size - 1).
		 */
		sq->max_batch_wr = min_t(uint32_t, sq->max_batch_wr,
					 sq->wq.wqe_cnt - 1);
	}

	return 0;

err_free_local_queue:
	free(sq->local_queue);
err_terminate_wq:
	efa_wq_terminate(&sq->wq, qp->page_size);
	return err;
}

static void efa_rq_terminate(struct efa_qp *qp)
{
	struct efa_rq *rq = &qp->rq;

	if (!rq->wq.wqe_cnt)
		return;

	munmap(rq->buf, rq->buf_size);

	efa_wq_terminate(&rq->wq, qp->page_size);
}

static int efa_rq_initialize(struct efa_qp *qp, struct efa_create_qp_resp *resp)
{
	struct efa_wq_init_attr wq_attr;
	struct efa_rq *rq = &qp->rq;
	int err;

	if (!rq->wq.wqe_cnt)
		return 0;

	wq_attr = (struct efa_wq_init_attr) {
		.db_mmap_key = resp->rq_db_mmap_key,
		.db_off = resp->rq_db_offset,
		.cmd_fd = qp->verbs_qp.qp.context->cmd_fd,
		.pgsz = qp->page_size,
		.sub_cq_idx = resp->recv_sub_cq_idx,
	};

	err = efa_wq_initialize(&qp->rq.wq, &wq_attr);
	if (err) {
		verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			  "RQ efa_wq_initialize failed\n");
		return err;
	}

	rq->buf_size = resp->rq_mmap_size;
	rq->buf = mmap(NULL, rq->buf_size, PROT_WRITE, MAP_SHARED,
		       qp->verbs_qp.qp.context->cmd_fd, resp->rq_mmap_key);
	if (rq->buf == MAP_FAILED) {
		verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			  "RQ buffer mmap failed\n");
		err = errno;
		goto err_terminate_wq;
	}

	return 0;

err_terminate_wq:
	efa_wq_terminate(&rq->wq, qp->page_size);
	return err;
}

static void efa_qp_init_indices(struct efa_qp *qp)
{
	qp->sq.wq.wqe_posted = 0;
	qp->sq.wq.wqe_completed = 0;
	qp->sq.wq.pc = 0;
	qp->sq.wq.wrid_idx_pool_next = 0;

	qp->rq.wq.wqe_posted = 0;
	qp->rq.wq.wqe_completed = 0;
	qp->rq.wq.pc = 0;
	qp->rq.wq.wrid_idx_pool_next = 0;
}

static void efa_setup_qp(struct efa_context *ctx,
			 struct efa_qp *qp,
			 struct ibv_qp_cap *cap,
			 size_t page_size)
{
	uint16_t rq_desc_cnt;

	efa_qp_init_indices(qp);

	qp->sq.wq.wqe_cnt = roundup_pow_of_two(max_t(uint32_t, cap->max_send_wr,
						     ctx->min_sq_wr));
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

	if (recv_cq == send_cq) {
		pthread_spin_lock(&recv_cq->lock);
	} else {
		pthread_spin_lock(&recv_cq->lock);
		pthread_spin_lock(&send_cq->lock);
	}
}

static void efa_unlock_cqs(struct ibv_qp *ibvqp)
{
	struct efa_cq *send_cq = to_efa_cq(ibvqp->send_cq);
	struct efa_cq *recv_cq = to_efa_cq(ibvqp->recv_cq);

	if (recv_cq == send_cq) {
		pthread_spin_unlock(&recv_cq->lock);
	} else {
		pthread_spin_unlock(&recv_cq->lock);
		pthread_spin_unlock(&send_cq->lock);
	}
}

static void efa_qp_fill_wr_pfns(struct ibv_qp_ex *ibvqpx,
				struct ibv_qp_init_attr_ex *attr_ex);

static int efa_check_qp_attr(struct efa_context *ctx,
			     struct ibv_qp_init_attr_ex *attr,
			     struct efadv_qp_init_attr *efa_attr)
{
	uint64_t supp_send_ops_mask;
	uint64_t supp_ud_send_ops_mask = IBV_QP_EX_WITH_SEND |
		IBV_QP_EX_WITH_SEND_WITH_IMM;
	uint64_t supp_srd_send_ops_mask = IBV_QP_EX_WITH_SEND |
					  IBV_QP_EX_WITH_SEND_WITH_IMM;
	if (EFA_DEV_CAP(ctx, RDMA_READ))
		supp_srd_send_ops_mask |= IBV_QP_EX_WITH_RDMA_READ;
	if (EFA_DEV_CAP(ctx, RDMA_WRITE))
		supp_srd_send_ops_mask |= IBV_QP_EX_WITH_RDMA_WRITE |
					  IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM;

#define EFA_CREATE_QP_SUPP_ATTR_MASK \
	(IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_SEND_OPS_FLAGS)

	if (attr->qp_type == IBV_QPT_DRIVER &&
	    efa_attr->driver_qp_type != EFADV_QP_DRIVER_TYPE_SRD) {
		verbs_err(&ctx->ibvctx, "Driver QP type must be SRD\n");
		return EOPNOTSUPP;
	}

	if (!check_comp_mask(attr->comp_mask, EFA_CREATE_QP_SUPP_ATTR_MASK)) {
		verbs_err(&ctx->ibvctx,
			  "Unsupported comp_mask[%#x] supported[%#x]\n",
			  attr->comp_mask, EFA_CREATE_QP_SUPP_ATTR_MASK);
		return EOPNOTSUPP;
	}

	if (!(attr->comp_mask & IBV_QP_INIT_ATTR_PD)) {
		verbs_err(&ctx->ibvctx, "Does not support PD in init attr\n");
		return EINVAL;
	}

	if (attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS) {
		switch (attr->qp_type) {
		case IBV_QPT_UD:
			supp_send_ops_mask = supp_ud_send_ops_mask;
			break;
		case IBV_QPT_DRIVER:
			supp_send_ops_mask = supp_srd_send_ops_mask;
			break;
		default:
			verbs_err(&ctx->ibvctx, "Invalid QP type %u\n",
				  attr->qp_type);
			return EOPNOTSUPP;
		}

		if (!check_comp_mask(attr->send_ops_flags,
				     supp_send_ops_mask)) {
			verbs_err(&ctx->ibvctx,
				  "Unsupported send_ops_flags[%" PRIx64 "] supported [%" PRIx64 "]\n",
				  attr->send_ops_flags, supp_send_ops_mask);
			return EOPNOTSUPP;
		}
	}

	if (!attr->recv_cq || !attr->send_cq) {
		verbs_err(&ctx->ibvctx, "Send/Receive CQ not provided\n");
		return EINVAL;
	}

	if (attr->srq) {
		verbs_err(&ctx->ibvctx, "SRQ is not supported\n");
		return EINVAL;
	}

	return 0;
}

static int efa_check_qp_limits(struct efa_context *ctx,
			       struct ibv_qp_init_attr_ex *attr)
{
	if (attr->cap.max_send_sge > ctx->max_sq_sge) {
		verbs_err(&ctx->ibvctx,
			  "Max send SGE %u > %u\n", attr->cap.max_send_sge,
			  ctx->max_sq_sge);
		return EINVAL;
	}

	if (attr->cap.max_recv_sge > ctx->max_rq_sge) {
		verbs_err(&ctx->ibvctx,
			  "Max receive SGE %u > %u\n", attr->cap.max_recv_sge,
			  ctx->max_rq_sge);
		return EINVAL;
	}

	if (attr->cap.max_send_wr > ctx->max_sq_wr) {
		verbs_err(&ctx->ibvctx,
			  "Max send WR %u > %u\n", attr->cap.max_send_wr,
			  ctx->max_sq_wr);
		return EINVAL;
	}

	if (attr->cap.max_recv_wr > ctx->max_rq_wr) {
		verbs_err(&ctx->ibvctx,
			  "Max receive WR %u > %u\n", attr->cap.max_recv_wr,
			  ctx->max_rq_wr);
		return EINVAL;
	}

	return 0;
}

static struct ibv_qp *create_qp(struct ibv_context *ibvctx,
				struct ibv_qp_init_attr_ex *attr,
				struct efadv_qp_init_attr *efa_attr)
{
	struct efa_context *ctx = to_efa_context(ibvctx);
	struct efa_dev *dev = to_efa_dev(ibvctx->device);
	struct efa_create_qp_resp resp = {};
	struct efa_create_qp req = {};
	struct efa_cq *send_cq;
	struct efa_cq *recv_cq;
	struct ibv_qp *ibvqp;
	struct efa_qp *qp;
	int err;

	err = efa_check_qp_attr(ctx, attr, efa_attr);
	if (err)
		goto err_out;

	err = efa_check_qp_limits(ctx, attr);
	if (err)
		goto err_out;

	qp = calloc(1, sizeof(*qp));
	if (!qp) {
		err = ENOMEM;
		goto err_out;
	}

	efa_setup_qp(ctx, qp, &attr->cap, dev->pg_sz);

	attr->cap.max_send_wr = qp->sq.wq.wqe_cnt;
	attr->cap.max_recv_wr = qp->rq.wq.wqe_cnt;

	req.rq_ring_size = (qp->rq.wq.desc_mask + 1) *
		sizeof(struct efa_io_rx_desc);
	req.sq_ring_size = (attr->cap.max_send_wr) *
		sizeof(struct efa_io_tx_wqe);
	if (attr->qp_type == IBV_QPT_DRIVER)
		req.driver_qp_type = efa_attr->driver_qp_type;

	err = ibv_cmd_create_qp_ex(ibvctx, &qp->verbs_qp,
				   attr, &req.ibv_cmd, sizeof(req),
				   &resp.ibv_resp, sizeof(resp));
	if (err)
		goto err_free_qp;

	ibvqp = &qp->verbs_qp.qp;
	ibvqp->state = IBV_QPS_RESET;
	qp->sq_sig_all = attr->sq_sig_all;

	err = efa_rq_initialize(qp, &resp);
	if (err)
		goto err_destroy_qp;

	err = efa_sq_initialize(qp, attr, &resp);
	if (err)
		goto err_terminate_rq;

	pthread_spin_lock(&ctx->qp_table_lock);
	ctx->qp_table[ibvqp->qp_num & ctx->qp_table_sz_m1] = qp;
	pthread_spin_unlock(&ctx->qp_table_lock);

	send_cq = to_efa_cq(attr->send_cq);
	pthread_spin_lock(&send_cq->lock);
	efa_cq_inc_ref_cnt(send_cq, resp.send_sub_cq_idx);
	pthread_spin_unlock(&send_cq->lock);

	recv_cq = to_efa_cq(attr->recv_cq);
	pthread_spin_lock(&recv_cq->lock);
	efa_cq_inc_ref_cnt(recv_cq, resp.recv_sub_cq_idx);
	pthread_spin_unlock(&recv_cq->lock);

	if (attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS) {
		efa_qp_fill_wr_pfns(&qp->verbs_qp.qp_ex, attr);
		qp->verbs_qp.comp_mask |= VERBS_QP_EX;
	}

	return ibvqp;

err_terminate_rq:
	efa_rq_terminate(qp);
err_destroy_qp:
	ibv_cmd_destroy_qp(ibvqp);
err_free_qp:
	free(qp);
err_out:
	errno = err;
	verbs_err(verbs_get_ctx(ibvctx), "Failed to create QP\n");
	return NULL;
}

struct ibv_qp *efa_create_qp(struct ibv_pd *ibvpd,
			     struct ibv_qp_init_attr *attr)
{
	struct ibv_qp_init_attr_ex attr_ex = {};
	struct ibv_qp *ibvqp;

	if (attr->qp_type != IBV_QPT_UD) {
		verbs_err(verbs_get_ctx(ibvpd->context),
			  "Unsupported QP type %d\n", attr->qp_type);
		errno = EOPNOTSUPP;
		return NULL;
	}

	memcpy(&attr_ex, attr, sizeof(*attr));
	attr_ex.comp_mask = IBV_QP_INIT_ATTR_PD;
	attr_ex.pd = ibvpd;

	ibvqp = create_qp(ibvpd->context, &attr_ex, NULL);
	if (ibvqp)
		memcpy(attr, &attr_ex, sizeof(*attr));

	return ibvqp;
}

struct ibv_qp *efa_create_qp_ex(struct ibv_context *ibvctx,
				struct ibv_qp_init_attr_ex *attr_ex)
{
	if (attr_ex->qp_type != IBV_QPT_UD) {
		verbs_err(verbs_get_ctx(ibvctx), "Unsupported QP type\n");
		errno = EOPNOTSUPP;
		return NULL;
	}

	return create_qp(ibvctx, attr_ex, NULL);
}

struct ibv_qp *efadv_create_driver_qp(struct ibv_pd *ibvpd,
				      struct ibv_qp_init_attr *attr,
				      uint32_t driver_qp_type)
{
	struct ibv_qp_init_attr_ex attr_ex = {};
	struct efadv_qp_init_attr efa_attr = {};
	struct ibv_qp *ibvqp;

	if (!is_efa_dev(ibvpd->context->device)) {
		verbs_err(verbs_get_ctx(ibvpd->context), "Not an EFA device\n");
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (attr->qp_type != IBV_QPT_DRIVER) {
		verbs_err(verbs_get_ctx(ibvpd->context),
			  "QP type not IBV_QPT_DRIVER\n");
		errno = EINVAL;
		return NULL;
	}

	memcpy(&attr_ex, attr, sizeof(*attr));
	attr_ex.comp_mask = IBV_QP_INIT_ATTR_PD;
	attr_ex.pd = ibvpd;
	efa_attr.driver_qp_type = driver_qp_type;

	ibvqp = create_qp(ibvpd->context, &attr_ex, &efa_attr);
	if (ibvqp)
		memcpy(attr, &attr_ex, sizeof(*attr));

	return ibvqp;
}

struct ibv_qp *efadv_create_qp_ex(struct ibv_context *ibvctx,
				  struct ibv_qp_init_attr_ex *attr_ex,
				  struct efadv_qp_init_attr *efa_attr,
				  uint32_t inlen)
{
	if (!is_efa_dev(ibvctx->device)) {
		verbs_err(verbs_get_ctx(ibvctx), "Not an EFA device\n");
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (attr_ex->qp_type != IBV_QPT_DRIVER ||
	    !vext_field_avail(struct efadv_qp_init_attr,
			      driver_qp_type, inlen) ||
	    efa_attr->comp_mask ||
	    !is_reserved_cleared(efa_attr->reserved) ||
	    (inlen > sizeof(*efa_attr) && !is_ext_cleared(efa_attr, inlen))) {
		verbs_err(verbs_get_ctx(ibvctx), "Compatibility issues\n");
		errno = EINVAL;
		return NULL;
	}

	return create_qp(ibvctx, attr_ex, efa_attr);
}

int efa_modify_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr,
		  int attr_mask)
{
	struct efa_qp *qp = to_efa_qp(ibvqp);
	struct ibv_modify_qp cmd = {};
	int err;

	err = ibv_cmd_modify_qp(ibvqp, attr, attr_mask, &cmd, sizeof(cmd));
	if (err) {
		verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			  "Failed to modify QP[%u]\n", qp->verbs_qp.qp.qp_num);
		return err;
	}

	if (attr_mask & IBV_QP_STATE) {
		qp->verbs_qp.qp.state = attr->qp_state;
		/* transition to reset */
		if (qp->verbs_qp.qp.state == IBV_QPS_RESET)
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

int efa_query_qp_data_in_order(struct ibv_qp *ibvqp, enum ibv_wr_opcode op,
			       uint32_t flags)
{
	struct efa_context *ctx = to_efa_context(ibvqp->context);
	int caps = 0;

	if (EFA_DEV_CAP(ctx, DATA_POLLING_128))
		caps |= IBV_QUERY_QP_DATA_IN_ORDER_ALIGNED_128_BYTES;

	return caps;
}

int efa_destroy_qp(struct ibv_qp *ibvqp)
{
	struct efa_context *ctx = to_efa_context(ibvqp->context);
	struct efa_qp *qp = to_efa_qp(ibvqp);
	int err;

	pthread_spin_lock(&ctx->qp_table_lock);
	efa_lock_cqs(ibvqp);

	efa_cq_dec_ref_cnt(to_efa_cq(ibvqp->send_cq), qp->sq.wq.sub_cq_idx);
	efa_cq_dec_ref_cnt(to_efa_cq(ibvqp->recv_cq), qp->rq.wq.sub_cq_idx);

	ctx->qp_table[ibvqp->qp_num & ctx->qp_table_sz_m1] = NULL;

	efa_unlock_cqs(ibvqp);
	pthread_spin_unlock(&ctx->qp_table_lock);

	efa_sq_terminate(qp);
	efa_rq_terminate(qp);

	err = ibv_cmd_destroy_qp(ibvqp);
	if (err) {
		verbs_err(&ctx->ibvctx, "Failed to destroy QP[%u]\n",
			  ibvqp->qp_num);
		return err;
	}

	free(qp);
	return 0;
}

static void efa_set_tx_buf(struct efa_io_tx_buf_desc *tx_buf,
			   uint64_t addr, uint32_t lkey,
			   uint32_t length)
{
	tx_buf->length = length;
	EFA_SET(&tx_buf->lkey, EFA_IO_TX_BUF_DESC_LKEY, lkey);
	tx_buf->buf_addr_lo = addr & 0xffffffff;
	tx_buf->buf_addr_hi = addr >> 32;
}

static void efa_post_send_sgl(struct efa_io_tx_buf_desc *tx_bufs,
			      const struct ibv_sge *sg_list,
			      int num_sge)
{
	const struct ibv_sge *sge;
	size_t i;

	for (i = 0; i < num_sge; i++) {
		sge = &sg_list[i];
		efa_set_tx_buf(&tx_bufs[i], sge->addr, sge->lkey, sge->length);
	}
}

static void efa_post_send_inline_data(const struct ibv_send_wr *wr,
				      struct efa_io_tx_wqe *tx_wqe)
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

	EFA_SET(&tx_wqe->meta.ctrl1, EFA_IO_TX_META_DESC_INLINE_MSG, 1);
	tx_wqe->meta.length = total_length;
}

static size_t efa_sge_total_bytes(const struct ibv_sge *sg_list, int num_sge)
{
	size_t bytes = 0;
	size_t i;

	for (i = 0; i < num_sge; i++)
		bytes += sg_list[i].length;

	return bytes;
}

static size_t efa_buf_list_total_bytes(const struct ibv_data_buf *buf_list,
				       size_t num_buf)
{
	size_t bytes = 0;
	size_t i;

	for (i = 0; i < num_buf; i++)
		bytes += buf_list[i].length;

	return bytes;
}

static void efa_sq_advance_post_idx(struct efa_sq *sq)
{
	struct efa_wq *wq = &sq->wq;

	wq->wqe_posted++;
	wq->pc++;

	if (!(wq->pc & wq->desc_mask))
		wq->phase++;
}

static inline void efa_rq_ring_doorbell(struct efa_rq *rq, uint16_t pc)
{
	udma_to_device_barrier();
	mmio_write32(rq->wq.db, pc);
}

static inline void efa_sq_ring_doorbell(struct efa_sq *sq, uint16_t pc)
{
	mmio_write32(sq->wq.db, pc);
}

static void efa_set_common_ctrl_flags(struct efa_io_tx_meta_desc *desc,
				      struct efa_sq *sq,
				      enum efa_io_send_op_type op_type)
{
	EFA_SET(&desc->ctrl1, EFA_IO_TX_META_DESC_META_DESC, 1);
	EFA_SET(&desc->ctrl1, EFA_IO_TX_META_DESC_OP_TYPE, op_type);
	EFA_SET(&desc->ctrl2, EFA_IO_TX_META_DESC_PHASE, sq->wq.phase);
	EFA_SET(&desc->ctrl2, EFA_IO_TX_META_DESC_FIRST, 1);
	EFA_SET(&desc->ctrl2, EFA_IO_TX_META_DESC_LAST, 1);
	EFA_SET(&desc->ctrl2, EFA_IO_TX_META_DESC_COMP_REQ, 1);
}

static int efa_post_send_validate(struct efa_qp *qp,
				  unsigned int wr_flags)
{
	if (unlikely(qp->verbs_qp.qp.state != IBV_QPS_RTS &&
		     qp->verbs_qp.qp.state != IBV_QPS_SQD)) {
		verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			  "SQ[%u] is in invalid state\n",
			  qp->verbs_qp.qp.qp_num);
		return EINVAL;
	}

	if (unlikely(!(wr_flags & IBV_SEND_SIGNALED) && !qp->sq_sig_all)) {
		verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			  "SQ[%u] Non signaled WRs not supported\n",
			  qp->verbs_qp.qp.qp_num);
		return EINVAL;
	}

	if (unlikely(wr_flags & ~(IBV_SEND_SIGNALED | IBV_SEND_INLINE))) {
		verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			  "SQ[%u] Unsupported wr_flags[%#x] supported[%#x]\n",
			  qp->verbs_qp.qp.qp_num, wr_flags,
			  ~(IBV_SEND_SIGNALED | IBV_SEND_INLINE));
		return EINVAL;
	}

	if (unlikely(qp->sq.wq.wqe_posted - qp->sq.wq.wqe_completed ==
		     qp->sq.wq.wqe_cnt)) {
		verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			  "SQ[%u] is full wqe_posted[%u] wqe_completed[%u] wqe_cnt[%u]\n",
			  qp->verbs_qp.qp.qp_num, qp->sq.wq.wqe_posted,
			  qp->sq.wq.wqe_completed, qp->sq.wq.wqe_cnt);
		return ENOMEM;
	}

	return 0;
}

static int efa_post_send_validate_wr(struct efa_qp *qp,
				     const struct ibv_send_wr *wr)
{
	int err;

	err = efa_post_send_validate(qp, wr->send_flags);
	if (unlikely(err))
		return err;

	if (unlikely(wr->opcode != IBV_WR_SEND &&
		     wr->opcode != IBV_WR_SEND_WITH_IMM)) {
		verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			  "SQ[%u] unsupported opcode %d\n",
			  qp->verbs_qp.qp.qp_num, wr->opcode);
		return EINVAL;
	}

	if (wr->send_flags & IBV_SEND_INLINE) {
		if (unlikely(efa_sge_total_bytes(wr->sg_list, wr->num_sge) >
			     qp->sq.max_inline_data)) {
			verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
				  "SQ[%u] WR total bytes %zu > %zu\n",
				  qp->verbs_qp.qp.qp_num,
				  efa_sge_total_bytes(wr->sg_list,
						      wr->num_sge),
				  qp->sq.max_inline_data);
			return EINVAL;
		}
	} else {
		if (unlikely(wr->num_sge > qp->sq.wq.max_sge)) {
			verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
				  "SQ[%u] WR num_sge %d > %d\n",
				  qp->verbs_qp.qp.qp_num, wr->num_sge,
				  qp->sq.wq.max_sge);
			return EINVAL;
	}
	}

	return 0;
}

int efa_post_send(struct ibv_qp *ibvqp, struct ibv_send_wr *wr,
		  struct ibv_send_wr **bad)
{
	struct efa_io_tx_meta_desc *meta_desc;
	struct efa_qp *qp = to_efa_qp(ibvqp);
	struct efa_io_tx_wqe tx_wqe;
	struct efa_sq *sq = &qp->sq;
	struct efa_wq *wq = &sq->wq;
	uint32_t sq_desc_offset;
	uint32_t curbatch = 0;
	struct efa_ah *ah;
	int err = 0;

	mmio_wc_spinlock(&wq->wqlock);
	while (wr) {
		err = efa_post_send_validate_wr(qp, wr);
		if (err) {
			*bad = wr;
			goto ring_db;
		}

		memset(&tx_wqe, 0, sizeof(tx_wqe));
		meta_desc = &tx_wqe.meta;
		ah = to_efa_ah(wr->wr.ud.ah);

		if (wr->send_flags & IBV_SEND_INLINE) {
			efa_post_send_inline_data(wr, &tx_wqe);
		} else {
			meta_desc->length = wr->num_sge;
			efa_post_send_sgl(tx_wqe.data.sgl, wr->sg_list,
					  wr->num_sge);
		}

		if (wr->opcode == IBV_WR_SEND_WITH_IMM) {
			meta_desc->immediate_data = be32toh(wr->imm_data);
			EFA_SET(&meta_desc->ctrl1, EFA_IO_TX_META_DESC_HAS_IMM,
				1);
		}

		/* Set rest of the descriptor fields */
		efa_set_common_ctrl_flags(meta_desc, sq, EFA_IO_SEND);
		meta_desc->req_id = efa_wq_get_next_wrid_idx_locked(wq,
								    wr->wr_id);
		meta_desc->dest_qp_num = wr->wr.ud.remote_qpn;
		meta_desc->ah = ah->efa_ah;
		meta_desc->qkey = wr->wr.ud.remote_qkey;

		/* Copy descriptor */
		sq_desc_offset = (wq->pc & wq->desc_mask) *
				 sizeof(tx_wqe);
		mmio_memcpy_x64(sq->desc + sq_desc_offset, &tx_wqe,
				sizeof(tx_wqe));

		/* advance index and change phase */
		efa_sq_advance_post_idx(sq);
		curbatch++;

		if (curbatch == sq->max_batch_wr) {
			curbatch = 0;
			mmio_flush_writes();
			efa_sq_ring_doorbell(sq, wq->pc);
			mmio_wc_start();
		}

		wr = wr->next;
	}

ring_db:
	if (curbatch) {
		mmio_flush_writes();
		efa_sq_ring_doorbell(sq, wq->pc);
	}

	/*
	 * Not using mmio_wc_spinunlock as the doorbell write should be done
	 * inside the lock.
	 */
	pthread_spin_unlock(&wq->wqlock);
	return err;
}

static struct efa_io_tx_wqe *efa_send_wr_common(struct ibv_qp_ex *ibvqpx,
						enum efa_io_send_op_type op_type)
{
	struct efa_qp *qp = to_efa_qp_ex(ibvqpx);
	struct efa_sq *sq = &qp->sq;
	struct efa_io_tx_meta_desc *meta_desc;
	int err;

	if (unlikely(qp->wr_session_err))
		return NULL;

	err = efa_post_send_validate(qp, ibvqpx->wr_flags);
	if (unlikely(err)) {
		qp->wr_session_err = err;
		return NULL;
	}

	sq->curr_tx_wqe = (struct efa_io_tx_wqe *)sq->local_queue +
			  sq->num_wqe_pending;
	memset(sq->curr_tx_wqe, 0, sizeof(*sq->curr_tx_wqe));

	meta_desc = &sq->curr_tx_wqe->meta;
	efa_set_common_ctrl_flags(meta_desc, sq, op_type);
	meta_desc->req_id = efa_wq_get_next_wrid_idx_locked(&sq->wq,
							    ibvqpx->wr_id);

	/* advance index and change phase */
	efa_sq_advance_post_idx(sq);
	sq->num_wqe_pending++;

	return sq->curr_tx_wqe;
}

static void efa_send_wr_set_imm_data(struct efa_io_tx_wqe *tx_wqe, __be32 imm_data)
{
	struct efa_io_tx_meta_desc *meta_desc;

	meta_desc = &tx_wqe->meta;
	meta_desc->immediate_data = be32toh(imm_data);
	EFA_SET(&meta_desc->ctrl1, EFA_IO_TX_META_DESC_HAS_IMM, 1);
}

static void efa_send_wr_set_rdma_addr(struct efa_io_tx_wqe *tx_wqe, uint32_t rkey,
				      uint64_t remote_addr)
{
	struct efa_io_remote_mem_addr *remote_mem;

	remote_mem = &tx_wqe->data.rdma_req.remote_mem;
	remote_mem->rkey = rkey;
	remote_mem->buf_addr_lo = remote_addr & 0xFFFFFFFF;
	remote_mem->buf_addr_hi = remote_addr >> 32;
}

static void efa_send_wr_send(struct ibv_qp_ex *ibvqpx)
{
	efa_send_wr_common(ibvqpx, EFA_IO_SEND);
}

static void efa_send_wr_send_imm(struct ibv_qp_ex *ibvqpx, __be32 imm_data)
{
	struct efa_io_tx_wqe *tx_wqe;

	tx_wqe = efa_send_wr_common(ibvqpx, EFA_IO_SEND);
	if (unlikely(!tx_wqe))
		return;

	efa_send_wr_set_imm_data(tx_wqe, imm_data);
}

static void efa_send_wr_rdma_read(struct ibv_qp_ex *ibvqpx, uint32_t rkey,
				  uint64_t remote_addr)
{
	struct efa_io_tx_wqe *tx_wqe;

	tx_wqe = efa_send_wr_common(ibvqpx, EFA_IO_RDMA_READ);
	if (unlikely(!tx_wqe))
		return;

	efa_send_wr_set_rdma_addr(tx_wqe, rkey, remote_addr);
}

static void efa_send_wr_rdma_write(struct ibv_qp_ex *ibvqpx, uint32_t rkey,
				   uint64_t remote_addr)
{
	struct efa_io_tx_wqe *tx_wqe;

	tx_wqe = efa_send_wr_common(ibvqpx, EFA_IO_RDMA_WRITE);
	if (unlikely(!tx_wqe))
		return;

	efa_send_wr_set_rdma_addr(tx_wqe, rkey, remote_addr);
}

static void efa_send_wr_rdma_write_imm(struct ibv_qp_ex *ibvqpx, uint32_t rkey,
				       uint64_t remote_addr, __be32 imm_data)
{
	struct efa_io_tx_wqe *tx_wqe;

	tx_wqe = efa_send_wr_common(ibvqpx, EFA_IO_RDMA_WRITE);
	if (unlikely(!tx_wqe))
		return;

	efa_send_wr_set_rdma_addr(tx_wqe, rkey, remote_addr);
	efa_send_wr_set_imm_data(tx_wqe, imm_data);
}

static void efa_send_wr_set_sge(struct ibv_qp_ex *ibvqpx, uint32_t lkey,
				uint64_t addr, uint32_t length)
{
	struct efa_qp *qp = to_efa_qp_ex(ibvqpx);
	struct efa_io_tx_buf_desc *buf;
	struct efa_io_tx_wqe *tx_wqe;
	uint8_t op_type;

	if (unlikely(qp->wr_session_err))
		return;

	tx_wqe = qp->sq.curr_tx_wqe;
	tx_wqe->meta.length = 1;

	op_type = EFA_GET(&tx_wqe->meta.ctrl1, EFA_IO_TX_META_DESC_OP_TYPE);
	switch (op_type) {
	case EFA_IO_SEND:
		buf = &tx_wqe->data.sgl[0];
		break;
	case EFA_IO_RDMA_READ:
	case EFA_IO_RDMA_WRITE:
		tx_wqe->data.rdma_req.remote_mem.length = length;
		buf = &tx_wqe->data.rdma_req.local_mem[0];
		break;
	default:
		return;
	}

	efa_set_tx_buf(buf, addr, lkey, length);
}

static void efa_send_wr_set_sge_list(struct ibv_qp_ex *ibvqpx, size_t num_sge,
				     const struct ibv_sge *sg_list)
{
	struct efa_qp *qp = to_efa_qp_ex(ibvqpx);
	struct efa_io_rdma_req *rdma_req;
	struct efa_io_tx_wqe *tx_wqe;
	struct efa_sq *sq = &qp->sq;
	uint8_t op_type;

	if (unlikely(qp->wr_session_err))
		return;

	tx_wqe = sq->curr_tx_wqe;
	op_type = EFA_GET(&tx_wqe->meta.ctrl1, EFA_IO_TX_META_DESC_OP_TYPE);
	switch (op_type) {
	case EFA_IO_SEND:
		if (unlikely(num_sge > sq->wq.max_sge)) {
			verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
				  "SQ[%u] num_sge[%zu] > max_sge[%u]\n",
				  ibvqpx->qp_base.qp_num, num_sge,
				  sq->wq.max_sge);
			qp->wr_session_err = EINVAL;
			return;
		}
		efa_post_send_sgl(tx_wqe->data.sgl, sg_list, num_sge);
		break;
	case EFA_IO_RDMA_READ:
	case EFA_IO_RDMA_WRITE:
		if (unlikely(num_sge > sq->max_wr_rdma_sge)) {
			verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
				  "SQ[%u] num_sge[%zu] > max_rdma_sge[%zu]\n",
				  ibvqpx->qp_base.qp_num, num_sge,
				  sq->max_wr_rdma_sge);
			qp->wr_session_err = EINVAL;
			return;
		}
		rdma_req = &tx_wqe->data.rdma_req;
		rdma_req->remote_mem.length = efa_sge_total_bytes(sg_list,
								  num_sge);
		efa_post_send_sgl(rdma_req->local_mem, sg_list, num_sge);
		break;
	default:
		return;
	}

	tx_wqe->meta.length = num_sge;
}

static void efa_send_wr_set_inline_data(struct ibv_qp_ex *ibvqpx, void *addr,
					size_t length)
{
	struct efa_qp *qp = to_efa_qp_ex(ibvqpx);
	struct efa_io_tx_wqe *tx_wqe = qp->sq.curr_tx_wqe;

	if (unlikely(qp->wr_session_err))
		return;

	if (unlikely(length > qp->sq.max_inline_data)) {
		verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			  "SQ[%u] WR inline length %zu > %zu\n",
			  ibvqpx->qp_base.qp_num, length,
			  qp->sq.max_inline_data);
		qp->wr_session_err = EINVAL;
		return;
	}

	EFA_SET(&tx_wqe->meta.ctrl1, EFA_IO_TX_META_DESC_INLINE_MSG, 1);
	memcpy(tx_wqe->data.inline_data, addr, length);
	tx_wqe->meta.length = length;
}

static void
efa_send_wr_set_inline_data_list(struct ibv_qp_ex *ibvqpx,
				 size_t num_buf,
				 const struct ibv_data_buf *buf_list)
{
	struct efa_qp *qp = to_efa_qp_ex(ibvqpx);
	struct efa_io_tx_wqe *tx_wqe = qp->sq.curr_tx_wqe;
	uint32_t total_length = 0;
	uint32_t length;
	size_t i;

	if (unlikely(qp->wr_session_err))
		return;

	if (unlikely(efa_buf_list_total_bytes(buf_list, num_buf) >
		     qp->sq.max_inline_data)) {
		verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			  "SQ[%u] WR inline length %zu > %zu\n",
			  ibvqpx->qp_base.qp_num,
			  efa_buf_list_total_bytes(buf_list, num_buf),
			  qp->sq.max_inline_data);
		qp->wr_session_err = EINVAL;
		return;
	}

	for (i = 0; i < num_buf; i++) {
		length = buf_list[i].length;

		memcpy(tx_wqe->data.inline_data + total_length,
		       buf_list[i].addr, length);
		total_length += length;
	}

	EFA_SET(&tx_wqe->meta.ctrl1, EFA_IO_TX_META_DESC_INLINE_MSG, 1);
	tx_wqe->meta.length = total_length;
}

static void efa_send_wr_set_addr(struct ibv_qp_ex *ibvqpx,
				 struct ibv_ah *ibvah,
				 uint32_t remote_qpn, uint32_t remote_qkey)
{
	struct efa_qp *qp = to_efa_qp_ex(ibvqpx);
	struct efa_ah *ah = to_efa_ah(ibvah);
	struct efa_io_tx_wqe *tx_wqe = qp->sq.curr_tx_wqe;

	if (unlikely(qp->wr_session_err))
		return;

	tx_wqe->meta.dest_qp_num = remote_qpn;
	tx_wqe->meta.ah = ah->efa_ah;
	tx_wqe->meta.qkey = remote_qkey;
}

static void efa_send_wr_start(struct ibv_qp_ex *ibvqpx)
{
	struct efa_qp *qp = to_efa_qp_ex(ibvqpx);
	struct efa_sq *sq = &qp->sq;

	mmio_wc_spinlock(&qp->sq.wq.wqlock);
	qp->wr_session_err = 0;
	sq->num_wqe_pending = 0;
	sq->phase_rb = qp->sq.wq.phase;
}

static inline void efa_sq_roll_back(struct efa_sq *sq)
{
	struct efa_qp *qp = container_of(sq, struct efa_qp, sq);
	struct efa_wq *wq = &sq->wq;

	verbs_debug(verbs_get_ctx(qp->verbs_qp.qp.context),
		    "SQ[%u] Rollback num_wqe_pending = %u\n",
		    qp->verbs_qp.qp.qp_num, sq->num_wqe_pending);
	wq->wqe_posted -= sq->num_wqe_pending;
	wq->pc -= sq->num_wqe_pending;
	wq->wrid_idx_pool_next -= sq->num_wqe_pending;
	wq->phase = sq->phase_rb;
}

static int efa_send_wr_complete(struct ibv_qp_ex *ibvqpx)
{
	struct efa_qp *qp = to_efa_qp_ex(ibvqpx);
	struct efa_sq *sq = &qp->sq;
	uint32_t max_txbatch = sq->max_batch_wr;
	uint32_t num_wqe_to_copy;
	uint16_t local_idx = 0;
	uint16_t curbatch = 0;
	uint16_t sq_desc_idx;
	uint16_t pc;

	if (unlikely(qp->wr_session_err)) {
		efa_sq_roll_back(sq);
		goto out;
	}

	/*
	 * Copy local queue to device in chunks, handling wraparound and max
	 * doorbell batch.
	 */
	pc = sq->wq.pc - sq->num_wqe_pending;
	sq_desc_idx = pc & sq->wq.desc_mask;

	/* mmio_wc_start() comes from efa_send_wr_start() */
	while (sq->num_wqe_pending) {
		num_wqe_to_copy = min3(sq->num_wqe_pending,
				       sq->wq.wqe_cnt - sq_desc_idx,
				       max_txbatch - curbatch);
		mmio_memcpy_x64((struct efa_io_tx_wqe *)sq->desc +
							sq_desc_idx,
				(struct efa_io_tx_wqe *)sq->local_queue +
							local_idx,
				num_wqe_to_copy * sizeof(struct efa_io_tx_wqe));

		sq->num_wqe_pending -= num_wqe_to_copy;
		local_idx += num_wqe_to_copy;
		curbatch += num_wqe_to_copy;
		pc += num_wqe_to_copy;
		sq_desc_idx = (sq_desc_idx + num_wqe_to_copy) &
			      sq->wq.desc_mask;

		if (curbatch == max_txbatch) {
			mmio_flush_writes();
			efa_sq_ring_doorbell(sq, pc);
			curbatch = 0;
			mmio_wc_start();
		}
	}

	if (curbatch) {
		mmio_flush_writes();
		efa_sq_ring_doorbell(sq, sq->wq.pc);
	}
out:
	/*
	 * Not using mmio_wc_spinunlock as the doorbell write should be done
	 * inside the lock.
	 */
	pthread_spin_unlock(&sq->wq.wqlock);

	return qp->wr_session_err;
}

static void efa_send_wr_abort(struct ibv_qp_ex *ibvqpx)
{
	struct efa_sq *sq = &to_efa_qp_ex(ibvqpx)->sq;

	efa_sq_roll_back(sq);
	pthread_spin_unlock(&sq->wq.wqlock);
}

static void efa_qp_fill_wr_pfns(struct ibv_qp_ex *ibvqpx,
				struct ibv_qp_init_attr_ex *attr_ex)
{
	ibvqpx->wr_start = efa_send_wr_start;
	ibvqpx->wr_complete = efa_send_wr_complete;
	ibvqpx->wr_abort = efa_send_wr_abort;

	if (attr_ex->send_ops_flags & IBV_QP_EX_WITH_SEND)
		ibvqpx->wr_send = efa_send_wr_send;

	if (attr_ex->send_ops_flags & IBV_QP_EX_WITH_SEND_WITH_IMM)
		ibvqpx->wr_send_imm = efa_send_wr_send_imm;

	if (attr_ex->send_ops_flags & IBV_QP_EX_WITH_RDMA_READ)
		ibvqpx->wr_rdma_read = efa_send_wr_rdma_read;

	if (attr_ex->send_ops_flags & IBV_QP_EX_WITH_RDMA_WRITE)
		ibvqpx->wr_rdma_write = efa_send_wr_rdma_write;

	if (attr_ex->send_ops_flags & IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM)
		ibvqpx->wr_rdma_write_imm = efa_send_wr_rdma_write_imm;

	ibvqpx->wr_set_inline_data = efa_send_wr_set_inline_data;
	ibvqpx->wr_set_inline_data_list = efa_send_wr_set_inline_data_list;
	ibvqpx->wr_set_sge = efa_send_wr_set_sge;
	ibvqpx->wr_set_sge_list = efa_send_wr_set_sge_list;
	ibvqpx->wr_set_ud_addr = efa_send_wr_set_addr;
}

static int efa_post_recv_validate(struct efa_qp *qp, struct ibv_recv_wr *wr)
{
	if (unlikely(qp->verbs_qp.qp.state == IBV_QPS_RESET ||
		     qp->verbs_qp.qp.state == IBV_QPS_ERR)) {
		verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			  "RQ[%u] Invalid QP state\n",
			  qp->verbs_qp.qp.qp_num);
		return EINVAL;
	}

	if (unlikely(wr->num_sge > qp->rq.wq.max_sge)) {
		verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			  "RQ[%u] WR num_sge %d > %d\n",
			  qp->verbs_qp.qp.qp_num, wr->num_sge,
			  qp->rq.wq.max_sge);
		return EINVAL;
	}

	if (unlikely(qp->rq.wq.wqe_posted - qp->rq.wq.wqe_completed ==
		     qp->rq.wq.wqe_cnt)) {
		verbs_err(verbs_get_ctx(qp->verbs_qp.qp.context),
			  "RQ[%u] is full wqe_posted[%u] wqe_completed[%u] wqe_cnt[%u]\n",
			  qp->verbs_qp.qp.qp_num, qp->rq.wq.wqe_posted,
			  qp->rq.wq.wqe_completed, qp->rq.wq.wqe_cnt);
		return ENOMEM;
	}

	return 0;
}

int efa_post_recv(struct ibv_qp *ibvqp, struct ibv_recv_wr *wr,
		  struct ibv_recv_wr **bad)
{
	struct efa_qp *qp = to_efa_qp(ibvqp);
	struct efa_wq *wq = &qp->rq.wq;
	struct efa_io_rx_desc rx_buf;
	uint32_t rq_desc_offset;
	uintptr_t addr;
	int err = 0;
	size_t i;

	pthread_spin_lock(&wq->wqlock);
	while (wr) {
		err = efa_post_recv_validate(qp, wr);
		if (err) {
			*bad = wr;
			goto ring_db;
		}

		memset(&rx_buf, 0, sizeof(rx_buf));

		rx_buf.req_id = efa_wq_get_next_wrid_idx_locked(wq, wr->wr_id);
		wq->wqe_posted++;

		/* Default init of the rx buffer */
		EFA_SET(&rx_buf.lkey_ctrl, EFA_IO_RX_DESC_FIRST, 1);
		EFA_SET(&rx_buf.lkey_ctrl, EFA_IO_RX_DESC_LAST, 0);

		for (i = 0; i < wr->num_sge; i++) {
			/* Set last indication if need) */
			if (i == wr->num_sge - 1)
				EFA_SET(&rx_buf.lkey_ctrl, EFA_IO_RX_DESC_LAST,
					1);

			addr = wr->sg_list[i].addr;

			/* Set RX buffer desc from SGE */
			rx_buf.length = wr->sg_list[i].length;
			EFA_SET(&rx_buf.lkey_ctrl, EFA_IO_RX_DESC_LKEY,
				wr->sg_list[i].lkey);
			rx_buf.buf_addr_lo = addr;
			rx_buf.buf_addr_hi = (uint64_t)addr >> 32;

			/* Copy descriptor to RX ring */
			rq_desc_offset = (wq->pc & wq->desc_mask) *
					 sizeof(rx_buf);
			memcpy(qp->rq.buf + rq_desc_offset, &rx_buf, sizeof(rx_buf));

			/* Wrap rx descriptor index */
			wq->pc++;
			if (!(wq->pc & wq->desc_mask))
				wq->phase++;

			/* reset descriptor for next iov */
			memset(&rx_buf, 0, sizeof(rx_buf));
		}
		wr = wr->next;
	}

ring_db:
	efa_rq_ring_doorbell(&qp->rq, wq->pc);

	pthread_spin_unlock(&wq->wqlock);
	return err;
}

int efadv_query_ah(struct ibv_ah *ibvah, struct efadv_ah_attr *attr,
		   uint32_t inlen)
{
	uint64_t comp_mask_out = 0;

	if (!is_efa_dev(ibvah->context->device)) {
		verbs_err(verbs_get_ctx(ibvah->context), "Not an EFA device\n");
		return EOPNOTSUPP;
	}

	if (!vext_field_avail(typeof(*attr), ahn, inlen)) {
		verbs_err(verbs_get_ctx(ibvah->context),
			  "Compatibility issues\n");
		return EINVAL;
	}

	memset(attr, 0, inlen);
	attr->ahn = to_efa_ah(ibvah)->efa_ah;

	attr->comp_mask = comp_mask_out;

	return 0;
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
		verbs_err(verbs_get_ctx(ibvpd->context),
			  "Failed to create AH\n");
		free(ah);
		errno = err;
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
	if (err) {
		verbs_err(verbs_get_ctx(ibvah->context),
			  "Failed to destroy AH\n");
		return err;
	}
	free(ah);

	return 0;
}
