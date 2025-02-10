// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2022, Microsoft Corporation. All rights reserved.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <util/compiler.h>
#include <util/util.h>
#include <sys/mman.h>

#include <infiniband/driver.h>

#include <infiniband/kern-abi.h>
#include <rdma/mana-abi.h>
#include <kernel-abi/mana-abi.h>

#include "mana.h"
#include "rollback.h"
#include "doorbells.h"

DECLARE_DRV_CMD(mana_create_qp, IB_USER_VERBS_CMD_CREATE_QP, mana_ib_create_qp,
		mana_ib_create_qp_resp);

DECLARE_DRV_CMD(mana_create_qp_ex, IB_USER_VERBS_EX_CMD_CREATE_QP,
		mana_ib_create_qp_rss, mana_ib_create_qp_rss_resp);

DECLARE_DRV_CMD(mana_create_rc_qp, IB_USER_VERBS_CMD_CREATE_QP,
		mana_ib_create_rc_qp, mana_ib_create_rc_qp_resp);

static struct ibv_qp *mana_create_qp_raw(struct ibv_pd *ibpd,
					 struct ibv_qp_init_attr *attr)
{
	int ret;
	struct mana_cq *cq;
	struct mana_qp *qp;
	struct mana_pd *pd = container_of(ibpd, struct mana_pd, ibv_pd);
	struct mana_parent_domain *mpd;
	uint32_t port;

	struct mana_create_qp qp_cmd = {};
	struct mana_create_qp_resp qp_resp = {};
	struct mana_ib_create_qp *qp_cmd_drv;
	struct mana_ib_create_qp_resp *qp_resp_drv;

	struct mana_context *ctx = to_mctx(ibpd->context);

	/* This is a RAW QP, pd is a parent domain with port number */
	if (!pd->mprotection_domain) {
		verbs_err(verbs_get_ctx(ibpd->context),
			  "Create RAW QP should use parent domain\n");
		errno = EINVAL;
		return NULL;
	}

	mpd = container_of(pd, struct mana_parent_domain, mpd);
	port = (uint32_t)(uintptr_t)mpd->pd_context;

	cq = container_of(attr->send_cq, struct mana_cq, ibcq);

	if (!ctx->extern_alloc.alloc || !ctx->extern_alloc.free) {
		verbs_err(verbs_get_ctx(ibpd->context),
			  "RAW QP requires extern alloc for buffers\n");
		errno = EINVAL;
		return NULL;
	}

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	qp->raw_qp.send_buf_size =
		attr->cap.max_send_wr * get_wqe_size(attr->cap.max_send_sge);
	qp->raw_qp.send_buf_size = align_hw_size(qp->raw_qp.send_buf_size);

	qp->raw_qp.send_buf = ctx->extern_alloc.alloc(qp->raw_qp.send_buf_size,
						      ctx->extern_alloc.data);
	if (!qp->raw_qp.send_buf) {
		errno = ENOMEM;
		goto free_qp;
	}

	qp_cmd_drv = &qp_cmd.drv_payload;
	qp_resp_drv = &qp_resp.drv_payload;

	qp_cmd_drv->sq_buf_addr = (uintptr_t)qp->raw_qp.send_buf;
	qp_cmd_drv->sq_buf_size = qp->raw_qp.send_buf_size;
	qp_cmd_drv->port = port;

	ret = ibv_cmd_create_qp(ibpd, &qp->ibqp.qp, attr, &qp_cmd.ibv_cmd,
				sizeof(qp_cmd), &qp_resp.ibv_resp,
				sizeof(qp_resp));
	if (ret) {
		verbs_err(verbs_get_ctx(ibpd->context), "Create QP failed\n");
		ctx->extern_alloc.free(qp->raw_qp.send_buf, ctx->extern_alloc.data);
		errno = ret;
		goto free_qp;
	}

	qp->raw_qp.sqid = qp_resp_drv->sqid;
	qp->raw_qp.tx_vp_offset = qp_resp_drv->tx_vp_offset;
	qp->raw_qp.send_wqe_count = attr->cap.max_send_wr;

	cq->cqid = qp_resp_drv->cqid;

	return &qp->ibqp.qp;

free_qp:
	free(qp);
	return NULL;
}

static int mana_store_qid(struct mana_table *qp_table, struct mana_qp *qp, uint32_t qid)
{
	uint32_t tbl_idx, tbl_off;
	int ret = 0;

	tbl_idx = qid >> MANA_QP_TABLE_SHIFT;
	tbl_off = qid & MANA_QP_TABLE_MASK;

	if (qp_table[tbl_idx].refcnt == 0) {
		qp_table[tbl_idx].table =
			calloc(MANA_QP_TABLE_SIZE, sizeof(struct mana_qp *));
		if (!qp_table[tbl_idx].table) {
			ret = ENOMEM;
			goto out;
		}
	}

	if (qp_table[tbl_idx].table[tbl_off]) {
		ret = EBUSY;
		goto out;
	}

	qp_table[tbl_idx].table[tbl_off] = qp;
	qp_table[tbl_idx].refcnt++;

out:
	return ret;
}

static void mana_remove_qid(struct mana_table *qp_table, uint32_t qid)
{
	uint32_t tbl_idx, tbl_off;

	tbl_idx = qid >> MANA_QP_TABLE_SHIFT;
	tbl_off = qid & MANA_QP_TABLE_MASK;

	qp_table[tbl_idx].table[tbl_off] = NULL;
	qp_table[tbl_idx].refcnt--;

	if (qp_table[tbl_idx].refcnt == 0) {
		free(qp_table[tbl_idx].table);
		qp_table[tbl_idx].table = NULL;
	}
}

static int mana_store_qp(struct mana_context *ctx, struct mana_qp *qp)
{
	uint32_t sreq = qp->rc_qp.queues[USER_RC_SEND_QUEUE_REQUESTER].id;
	uint32_t srep = qp->rc_qp.queues[USER_RC_SEND_QUEUE_RESPONDER].id;
	uint32_t rreq = qp->rc_qp.queues[USER_RC_RECV_QUEUE_REQUESTER].id;
	uint32_t rrep = qp->rc_qp.queues[USER_RC_RECV_QUEUE_RESPONDER].id;
	int ret;

	pthread_mutex_lock(&ctx->qp_table_mutex);
	ret = mana_store_qid(ctx->qp_stable, qp, sreq);
	if (ret)
		goto error;
	ret = mana_store_qid(ctx->qp_stable, qp, srep);
	if (ret)
		goto remove_sreq;
	ret = mana_store_qid(ctx->qp_rtable, qp, rreq);
	if (ret)
		goto remove_srep;
	ret = mana_store_qid(ctx->qp_rtable, qp, rrep);
	if (ret)
		goto remove_rreq;

	pthread_mutex_unlock(&ctx->qp_table_mutex);
	return 0;

remove_rreq:
	mana_remove_qid(ctx->qp_rtable, rreq);
remove_srep:
	mana_remove_qid(ctx->qp_stable, srep);
remove_sreq:
	mana_remove_qid(ctx->qp_stable, sreq);
error:
	pthread_mutex_unlock(&ctx->qp_table_mutex);
	return ret;
}

static void mana_remove_qp(struct mana_context *ctx, struct mana_qp *qp)
{
	uint32_t sreq = qp->rc_qp.queues[USER_RC_SEND_QUEUE_REQUESTER].id;
	uint32_t srep = qp->rc_qp.queues[USER_RC_SEND_QUEUE_RESPONDER].id;
	uint32_t rreq = qp->rc_qp.queues[USER_RC_RECV_QUEUE_REQUESTER].id;
	uint32_t rrep = qp->rc_qp.queues[USER_RC_RECV_QUEUE_RESPONDER].id;

	pthread_mutex_lock(&ctx->qp_table_mutex);
	mana_remove_qid(ctx->qp_stable, sreq);
	mana_remove_qid(ctx->qp_stable, srep);
	mana_remove_qid(ctx->qp_rtable, rreq);
	mana_remove_qid(ctx->qp_rtable, rrep);
	pthread_mutex_unlock(&ctx->qp_table_mutex);
}

struct mana_qp *mana_get_qp(struct mana_context *ctx, uint32_t qid, bool is_sq)
{
	struct mana_table *qp_table = is_sq ? ctx->qp_stable : ctx->qp_rtable;
	uint32_t tbl_idx, tbl_off;

	tbl_idx = qid >> MANA_QP_TABLE_SHIFT;
	tbl_off = qid & MANA_QP_TABLE_MASK;

	if (!qp_table[tbl_idx].table)
		return NULL;

	return qp_table[tbl_idx].table[tbl_off];
}

static uint32_t get_queue_size(struct ibv_qp_init_attr *attr, enum user_queue_types type)
{
	uint32_t size = 0;
	uint32_t sges = 0;

	if (attr->qp_type == IBV_QPT_RC) {
		switch (type) {
		case USER_RC_SEND_QUEUE_REQUESTER:
			/* WQE must have at least one SGE */
			/* For write with imm we need one extra SGE */
			sges = max(1U, attr->cap.max_send_sge) + 1;
			size = attr->cap.max_send_wr * get_large_wqe_size(sges);
			break;
		case USER_RC_SEND_QUEUE_RESPONDER:
			size = MANA_PAGE_SIZE;
			break;
		case USER_RC_RECV_QUEUE_REQUESTER:
			size = MANA_PAGE_SIZE;
			break;
		case USER_RC_RECV_QUEUE_RESPONDER:
			/* WQE must have at least one SGE */
			sges = max(1U, attr->cap.max_recv_sge);
			size = attr->cap.max_recv_wr * get_wqe_size(sges);
			break;
		default:
			return 0;
		}
	}

	size = align_hw_size(size);

	if (attr->qp_type == IBV_QPT_RC && type == USER_RC_SEND_QUEUE_REQUESTER)
		size += sizeof(struct mana_ib_rollback_shared_mem);

	return size;
}

static struct ibv_qp *mana_create_qp_rc(struct ibv_pd *ibpd,
					struct ibv_qp_init_attr *attr)
{
	struct mana_cq *send_cq = container_of(attr->send_cq, struct mana_cq, ibcq);
	struct mana_cq *recv_cq = container_of(attr->recv_cq, struct mana_cq, ibcq);
	struct mana_context *ctx = to_mctx(ibpd->context);
	struct mana_ib_create_rc_qp_resp *qp_resp_drv;
	struct mana_create_rc_qp_resp qp_resp = {};
	struct mana_ib_create_rc_qp *qp_cmd_drv;
	struct mana_create_rc_qp qp_cmd = {};
	struct mana_qp *qp;
	int ret, i;

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	qp_cmd_drv = &qp_cmd.drv_payload;
	qp_resp_drv = &qp_resp.drv_payload;

	pthread_spin_init(&qp->sq_lock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&qp->rq_lock, PTHREAD_PROCESS_PRIVATE);
	qp->sq_sig_all = attr->sq_sig_all;

	if (create_shadow_queue(&qp->shadow_sq, attr->cap.max_send_wr,
				sizeof(struct rc_sq_shadow_wqe))) {
		verbs_err(verbs_get_ctx(ibpd->context), "Failed to alloc sq shadow queue\n");
		errno = ENOMEM;
		goto free_qp;
	}

	if (create_shadow_queue(&qp->shadow_rq, attr->cap.max_recv_wr,
				sizeof(struct rc_rq_shadow_wqe))) {
		verbs_err(verbs_get_ctx(ibpd->context), "Failed to alloc rc shadow queue\n");
		errno = ENOMEM;
		goto destroy_shadow_sq;
	}

	for (i = 0; i < USER_RC_QUEUE_TYPE_MAX; ++i) {
		qp->rc_qp.queues[i].db_page = ctx->db_page;
		qp->rc_qp.queues[i].size = get_queue_size(attr, i);
		qp->rc_qp.queues[i].buffer = mana_alloc_mem(qp->rc_qp.queues[i].size);

		if (!qp->rc_qp.queues[i].buffer) {
			verbs_err(verbs_get_ctx(ibpd->context),
				  "Failed to allocate memory for RC queue %d\n", i);
			errno = ENOMEM;
			goto destroy_queues;
		}

		qp_cmd_drv->queue_buf[i] = (uintptr_t)qp->rc_qp.queues[i].buffer;
		qp_cmd_drv->queue_size[i] = qp->rc_qp.queues[i].size;
	}

	mana_ib_init_rb_shmem(qp);

	ret = ibv_cmd_create_qp(ibpd, &qp->ibqp.qp, attr, &qp_cmd.ibv_cmd,
				sizeof(qp_cmd), &qp_resp.ibv_resp,
				sizeof(qp_resp));
	if (ret) {
		verbs_err(verbs_get_ctx(ibpd->context), "Create QP failed\n");
		errno = ret;
		goto free_rb;
	}

	for (i = 0; i < USER_RC_QUEUE_TYPE_MAX; ++i)
		qp->rc_qp.queues[i].id = qp_resp_drv->queue_id[i];

	qp->ibqp.qp.qp_num = qp->rc_qp.queues[USER_RC_RECV_QUEUE_RESPONDER].id;

	ret = mana_store_qp(ctx, qp);
	if (ret) {
		errno = ret;
		goto destroy_qp;
	}

	pthread_spin_lock(&send_cq->lock);
	list_add(&send_cq->send_qp_list, &qp->send_cq_node);
	pthread_spin_unlock(&send_cq->lock);

	pthread_spin_lock(&recv_cq->lock);
	list_add(&recv_cq->recv_qp_list, &qp->recv_cq_node);
	pthread_spin_unlock(&recv_cq->lock);

	return &qp->ibqp.qp;

destroy_qp:
	ibv_cmd_destroy_qp(&qp->ibqp.qp);
free_rb:
	mana_ib_deinit_rb_shmem(qp);
destroy_queues:
	while (i-- > 0)
		munmap(qp->rc_qp.queues[i].buffer, qp->rc_qp.queues[i].size);
	destroy_shadow_queue(&qp->shadow_rq);
destroy_shadow_sq:
	destroy_shadow_queue(&qp->shadow_sq);
free_qp:
	free(qp);
	return NULL;
}

struct ibv_qp *mana_create_qp(struct ibv_pd *ibpd,
			      struct ibv_qp_init_attr *attr)
{
	switch (attr->qp_type) {
	case IBV_QPT_RAW_PACKET:
		return mana_create_qp_raw(ibpd, attr);
	case IBV_QPT_RC:
		return mana_create_qp_rc(ibpd, attr);
	default:
		verbs_err(verbs_get_ctx(ibpd->context),
			  "QP type %u is not supported\n", attr->qp_type);
		errno = EOPNOTSUPP;
	}

	return NULL;
}

static void mana_ib_modify_rc_qp(struct mana_qp *qp, struct ibv_qp_attr *attr, int attr_mask)
{
	int i;

	if (attr_mask & IBV_QP_PATH_MTU)
		qp->mtu = attr->path_mtu;

	if (attr_mask & IBV_QP_STATE) {
		qp->ibqp.qp.state = attr->qp_state;
		switch (attr->qp_state) {
		case IBV_QPS_RESET:
			for (i = 0; i < USER_RC_QUEUE_TYPE_MAX; ++i) {
				qp->rc_qp.queues[i].prod_idx = 0;
				qp->rc_qp.queues[i].cons_idx = 0;
			}
			mana_ib_reset_rb_shmem(qp);
			reset_shadow_queue(&qp->shadow_rq);
			reset_shadow_queue(&qp->shadow_sq);
		case IBV_QPS_INIT:
			break;
		case IBV_QPS_RTR:
			break;
		case IBV_QPS_RTS:
			if (attr_mask & IBV_QP_SQ_PSN) {
				qp->rc_qp.sq_ssn = 1;
				qp->rc_qp.sq_psn = attr->sq_psn;
				gdma_arm_normal_cqe(&qp->rc_qp.queues[USER_RC_RECV_QUEUE_REQUESTER],
						    attr->sq_psn);
			}
			break;
		default:
			break;
		}
	}
}

int mana_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr, int attr_mask)
{
	struct mana_qp *qp = container_of(ibqp, struct mana_qp, ibqp.qp);
	struct ibv_modify_qp cmd = {};
	int err;

	if (ibqp->qp_type != IBV_QPT_RC)
		return EOPNOTSUPP;

	pthread_spin_lock(&qp->sq_lock);
	pthread_spin_lock(&qp->rq_lock);

	err = ibv_cmd_modify_qp(ibqp, attr, attr_mask, &cmd, sizeof(cmd));
	if (err) {
		verbs_err(verbs_get_ctx(ibqp->context), "Failed to modify qp\n");
		goto cleanup;
	}

	mana_ib_modify_rc_qp(qp, attr, attr_mask);

cleanup:
	pthread_spin_unlock(&qp->rq_lock);
	pthread_spin_unlock(&qp->sq_lock);
	return err;
}

static void mana_drain_cqes(struct mana_qp *qp)
{
	struct mana_cq *send_cq = container_of(qp->ibqp.qp.send_cq, struct mana_cq, ibcq);
	struct mana_cq *recv_cq = container_of(qp->ibqp.qp.recv_cq, struct mana_cq, ibcq);

	pthread_spin_lock(&send_cq->lock);
	list_del(&qp->send_cq_node);
	pthread_spin_unlock(&send_cq->lock);

	pthread_spin_lock(&recv_cq->lock);
	list_del(&qp->recv_cq_node);
	pthread_spin_unlock(&recv_cq->lock);
}

int mana_destroy_qp(struct ibv_qp *ibqp)
{
	struct mana_qp *qp = container_of(ibqp, struct mana_qp, ibqp.qp);
	struct mana_context *ctx = to_mctx(ibqp->context);
	int ret, i;

	if (ibqp->qp_type == IBV_QPT_RC) {
		mana_remove_qp(ctx, qp);
		mana_drain_cqes(qp);
	}

	ret = ibv_cmd_destroy_qp(ibqp);
	if (ret) {
		verbs_err(verbs_get_ctx(ibqp->context), "Destroy QP failed\n");
		return ret;
	}

	switch (ibqp->qp_type) {
	case IBV_QPT_RAW_PACKET:
		ctx->extern_alloc.free(qp->raw_qp.send_buf, ctx->extern_alloc.data);
		break;
	case IBV_QPT_RC:
		pthread_spin_destroy(&qp->sq_lock);
		pthread_spin_destroy(&qp->rq_lock);
		destroy_shadow_queue(&qp->shadow_sq);
		destroy_shadow_queue(&qp->shadow_rq);
		mana_ib_deinit_rb_shmem(qp);
		for (i = 0; i < USER_RC_QUEUE_TYPE_MAX; ++i)
			munmap(qp->rc_qp.queues[i].buffer, qp->rc_qp.queues[i].size);
		break;
	default:
		verbs_err(verbs_get_ctx(ibqp->context),
			  "QP type %u is not supported\n", ibqp->qp_type);
		errno = EINVAL;
	}
	free(qp);

	return 0;
}

static struct ibv_qp *mana_create_qp_ex_raw(struct ibv_context *context,
					    struct ibv_qp_init_attr_ex *attr)
{
	struct mana_create_qp_ex cmd = {};
	struct mana_ib_create_qp_rss *cmd_drv;
	struct mana_create_qp_ex_resp resp = {};
	struct mana_ib_create_qp_rss_resp *cmd_resp;
	struct mana_qp *qp;
	struct mana_pd *pd = container_of(attr->pd, struct mana_pd, ibv_pd);
	struct mana_parent_domain *mpd;
	uint32_t port;
	int ret;

	cmd_drv = &cmd.drv_payload;
	cmd_resp = &resp.drv_payload;

	/* For a RAW QP, pd is a parent domain with port number */
	if (!pd->mprotection_domain) {
		verbs_err(verbs_get_ctx(context),
			  "RAW QP needs to be on a parent domain\n");
		errno = EINVAL;
		return NULL;
	}

	if (attr->rx_hash_conf.rx_hash_key_len !=
	    MANA_IB_TOEPLITZ_HASH_KEY_SIZE_IN_BYTES) {
		verbs_err(verbs_get_ctx(context),
			  "Invalid RX hash key length\n");
		errno = EINVAL;
		return NULL;
	}

	mpd = container_of(pd, struct mana_parent_domain, mpd);
	port = (uint32_t)(uintptr_t)mpd->pd_context;

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	cmd_drv->rx_hash_fields_mask = attr->rx_hash_conf.rx_hash_fields_mask;
	cmd_drv->rx_hash_function = attr->rx_hash_conf.rx_hash_function;
	cmd_drv->rx_hash_key_len = attr->rx_hash_conf.rx_hash_key_len;
	if (cmd_drv->rx_hash_key_len)
		memcpy(cmd_drv->rx_hash_key, attr->rx_hash_conf.rx_hash_key,
		       cmd_drv->rx_hash_key_len);

	cmd_drv->port = port;

	ret = ibv_cmd_create_qp_ex2(context, &qp->ibqp, attr, &cmd.ibv_cmd,
				    sizeof(cmd), &resp.ibv_resp, sizeof(resp));
	if (ret) {
		verbs_err(verbs_get_ctx(context), "Create QP EX failed\n");
		free(qp);
		errno = ret;
		return NULL;
	}

	if (attr->rwq_ind_tbl) {
		struct mana_rwq_ind_table *ind_table =
			container_of(attr->rwq_ind_tbl,
				     struct mana_rwq_ind_table, ib_ind_table);
		for (int i = 0; i < ind_table->ind_tbl_size; i++) {
			struct mana_wq *wq = container_of(ind_table->ind_tbl[i],
							  struct mana_wq, ibwq);
			struct mana_cq *cq =
				container_of(wq->ibwq.cq, struct mana_cq, ibcq);
			wq->wqid = cmd_resp->entries[i].wqid;
			cq->cqid = cmd_resp->entries[i].cqid;
		}
	}

	return &qp->ibqp.qp;
}

struct ibv_qp *mana_create_qp_ex(struct ibv_context *context,
				 struct ibv_qp_init_attr_ex *attr)
{
	switch (attr->qp_type) {
	case IBV_QPT_RAW_PACKET:
		return mana_create_qp_ex_raw(context, attr);
	default:
		verbs_err(verbs_get_ctx(context),
			  "QP type %u is not supported\n", attr->qp_type);
		errno = EOPNOTSUPP;
	}

	return NULL;
}

void mana_qp_move_flush_err(struct ibv_qp *ibqp)
{
	struct ibv_qp_attr attr = {};

	attr.qp_state = IBV_QPS_ERR;
	mana_modify_qp(ibqp, &attr, IBV_QP_STATE);
}
