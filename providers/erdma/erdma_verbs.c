// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause

// Authors: Cheng Xu <chengyou@linux.alibaba.com>
// Copyright (c) 2020-2021, Alibaba Group.
// Authors: Bernard Metzler <bmt@zurich.ibm.com>
// Copyright (c) 2008-2019, IBM Corporation

#include <ccan/minmax.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <util/mmio.h>
#include <util/udma_barrier.h>
#include <util/util.h>

#include "erdma.h"
#include "erdma_abi.h"
#include "erdma_db.h"
#include "erdma_hw.h"
#include "erdma_verbs.h"

int erdma_query_device(struct ibv_context *ctx,
		       const struct ibv_query_device_ex_input *input,
		       struct ibv_device_attr_ex *attr, size_t attr_size)
{
	struct ib_uverbs_ex_query_device_resp resp;
	unsigned int major, minor, sub_minor;
	size_t resp_size = sizeof(resp);
	uint64_t raw_fw_ver;
	int rv;

	rv = ibv_cmd_query_device_any(ctx, input, attr, attr_size, &resp,
				      &resp_size);
	if (rv)
		return rv;

	raw_fw_ver = resp.base.fw_ver;
	major = (raw_fw_ver >> 32) & 0xffff;
	minor = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(attr->orig_attr.fw_ver, sizeof(attr->orig_attr.fw_ver),
		 "%d.%d.%d", major, minor, sub_minor);

	return 0;
}

int erdma_query_port(struct ibv_context *ctx, uint8_t port,
		     struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd = {};

	return ibv_cmd_query_port(ctx, port, attr, &cmd, sizeof(cmd));
}

int erdma_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		   struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd = {};

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr, &cmd,
				sizeof(cmd));
}

struct ibv_pd *erdma_alloc_pd(struct ibv_context *ctx)
{
	struct ib_uverbs_alloc_pd_resp resp;
	struct ibv_alloc_pd cmd = {};
	struct ibv_pd *pd;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(ctx, pd, &cmd, sizeof(cmd), &resp, sizeof(resp))) {
		free(pd);
		return NULL;
	}

	return pd;
}

int erdma_free_pd(struct ibv_pd *pd)
{
	int rv;

	rv = ibv_cmd_dealloc_pd(pd);
	if (rv)
		return rv;

	free(pd);
	return 0;
}

struct ibv_mr *erdma_reg_mr(struct ibv_pd *pd, void *addr, size_t len,
			    uint64_t hca_va, int access)
{
	struct ib_uverbs_reg_mr_resp resp;
	struct ibv_reg_mr cmd;
	struct verbs_mr *vmr;
	int ret;

	vmr = calloc(1, sizeof(*vmr));
	if (!vmr)
		return NULL;

	ret = ibv_cmd_reg_mr(pd, addr, len, hca_va, access, vmr, &cmd,
			     sizeof(cmd), &resp, sizeof(resp));
	if (ret) {
		free(vmr);
		return NULL;
	}

	return &vmr->ibv_mr;
}

int erdma_dereg_mr(struct verbs_mr *vmr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

	free(vmr);
	return 0;
}

int erdma_notify_cq(struct ibv_cq *ibcq, int solicited)
{
	struct erdma_cq *cq = to_ecq(ibcq);
	uint64_t db_data;
	int ret;

	ret = pthread_spin_lock(&cq->lock);
	if (ret)
		return ret;

	db_data = FIELD_PREP(ERDMA_CQDB_IDX_MASK, cq->db_index) |
		  FIELD_PREP(ERDMA_CQDB_CQN_MASK, cq->id) |
		  FIELD_PREP(ERDMA_CQDB_ARM_MASK, 1) |
		  FIELD_PREP(ERDMA_CQDB_SOL_MASK, solicited) |
		  FIELD_PREP(ERDMA_CQDB_CMDSN_MASK, cq->cmdsn) |
		  FIELD_PREP(ERDMA_CQDB_CI_MASK, cq->ci);

	*(__le64 *)cq->db_record = htole64(db_data);
	cq->db_index++;
	udma_to_device_barrier();
	mmio_write64_le(cq->db, htole64(db_data));

	pthread_spin_unlock(&cq->lock);

	return ret;
}

struct ibv_cq *erdma_create_cq(struct ibv_context *ctx, int num_cqe,
			       struct ibv_comp_channel *channel,
			       int comp_vector)
{
	struct erdma_context *ectx = to_ectx(ctx);
	struct erdma_cmd_create_cq_resp resp = {};
	struct erdma_cmd_create_cq cmd = {};
	uint64_t *db_records = NULL;
	struct erdma_cq *cq;
	size_t cq_size;
	int rv;

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	if (num_cqe < 64)
		num_cqe = 64;

	num_cqe = roundup_pow_of_two(num_cqe);
	cq_size = align(num_cqe * sizeof(struct erdma_cqe), ERDMA_PAGE_SIZE);

	rv = posix_memalign((void **)&cq->queue, ERDMA_PAGE_SIZE, cq_size);
	if (rv) {
		errno = rv;
		free(cq);
		return NULL;
	}

	rv = ibv_dontfork_range(cq->queue, cq_size);
	if (rv) {
		free(cq->queue);
		cq->queue = NULL;
		goto error_alloc;
	}

	memset(cq->queue, 0, cq_size);

	db_records = erdma_alloc_dbrecords(ectx);
	if (!db_records) {
		errno = ENOMEM;
		goto error_alloc;
	}

	cmd.db_record_va = (uintptr_t)db_records;
	cmd.qbuf_va = (uintptr_t)cq->queue;
	cmd.qbuf_len = cq_size;

	rv = ibv_cmd_create_cq(ctx, num_cqe, channel, comp_vector, &cq->base_cq,
			       &cmd.ibv_cmd, sizeof(cmd), &resp.ibv_resp,
			       sizeof(resp));
	if (rv) {
		errno = EIO;
		goto error_alloc;
	}

	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);

	*db_records = 0;
	cq->db_record = db_records;

	cq->id = resp.cq_id;
	cq->depth = resp.num_cqe;

	cq->db = ectx->cdb;
	cq->db_offset = (cq->id & (ERDMA_PAGE_SIZE / ERDMA_CQDB_SIZE - 1)) *
			ERDMA_CQDB_SIZE;
	cq->db += cq->db_offset;

	cq->comp_vector = comp_vector;

	return &cq->base_cq;

error_alloc:
	if (db_records)
		erdma_dealloc_dbrecords(ectx, db_records);

	if (cq->queue) {
		ibv_dofork_range(cq->queue, cq_size);
		free(cq->queue);
	}

	free(cq);

	return NULL;
}

int erdma_destroy_cq(struct ibv_cq *base_cq)
{
	struct erdma_context *ctx = to_ectx(base_cq->context);
	struct erdma_cq *cq = to_ecq(base_cq);
	int rv;

	pthread_spin_lock(&cq->lock);
	rv = ibv_cmd_destroy_cq(base_cq);
	if (rv) {
		pthread_spin_unlock(&cq->lock);
		errno = EIO;
		return rv;
	}
	pthread_spin_destroy(&cq->lock);

	if (cq->db_record)
		erdma_dealloc_dbrecords(ctx, cq->db_record);

	if (cq->queue) {
		ibv_dofork_range(cq->queue, cq->depth << CQE_SHIFT);
		free(cq->queue);
	}

	free(cq);

	return 0;
}

static void __erdma_alloc_dbs(struct erdma_qp *qp, struct erdma_context *ctx)
{
	uint32_t qpn = qp->id;
	uint32_t db_offset;

	if (ctx->sdb_type == ERDMA_SDB_ENTRY)
		db_offset = ctx->sdb_offset * ERDMA_NSDB_PER_ENTRY *
			    ERDMA_SQDB_SIZE;
	else
		db_offset = (qpn & ERDMA_SDB_ALLOC_QPN_MASK) * ERDMA_SQDB_SIZE;

	qp->sq.db = ctx->sdb + db_offset;
	/* qpn[6:0] as the index in this rq db page. */
	qp->rq.db = ctx->rdb +
		    (qpn & ERDMA_RDB_ALLOC_QPN_MASK) * ERDMA_RQDB_SPACE_SIZE;
}

static int erdma_store_qp(struct erdma_context *ctx, struct erdma_qp *qp)
{
	uint32_t tbl_idx, tbl_off;
	int rv = 0;

	pthread_mutex_lock(&ctx->qp_table_mutex);
	tbl_idx = qp->id >> ERDMA_QP_TABLE_SHIFT;
	tbl_off = qp->id & ERDMA_QP_TABLE_MASK;

	if (ctx->qp_table[tbl_idx].refcnt == 0) {
		ctx->qp_table[tbl_idx].table =
			calloc(ERDMA_QP_TABLE_SIZE, sizeof(struct erdma_qp *));
		if (!ctx->qp_table[tbl_idx].table) {
			rv = -ENOMEM;
			goto out;
		}
	}

	/* exist qp */
	if (ctx->qp_table[tbl_idx].table[tbl_off]) {
		rv = -EBUSY;
		goto out;
	}

	ctx->qp_table[tbl_idx].table[tbl_off] = qp;
	ctx->qp_table[tbl_idx].refcnt++;

out:
	pthread_mutex_unlock(&ctx->qp_table_mutex);

	return rv;
}

static void erdma_clear_qp(struct erdma_context *ctx, struct erdma_qp *qp)
{
	uint32_t tbl_idx, tbl_off;

	pthread_mutex_lock(&ctx->qp_table_mutex);
	tbl_idx = qp->id >> ERDMA_QP_TABLE_SHIFT;
	tbl_off = qp->id & ERDMA_QP_TABLE_MASK;

	ctx->qp_table[tbl_idx].table[tbl_off] = NULL;
	ctx->qp_table[tbl_idx].refcnt--;

	if (ctx->qp_table[tbl_idx].refcnt == 0) {
		free(ctx->qp_table[tbl_idx].table);
		ctx->qp_table[tbl_idx].table = NULL;
	}

	pthread_mutex_unlock(&ctx->qp_table_mutex);
}

static int erdma_alloc_qp_buf_and_db(struct erdma_context *ctx,
				     struct erdma_qp *qp,
				     struct ibv_qp_init_attr *attr)
{
	size_t queue_size;
	uint32_t nwqebb;
	int rv;

	nwqebb = roundup_pow_of_two(attr->cap.max_send_wr * MAX_WQEBB_PER_SQE);
	queue_size = align(nwqebb << SQEBB_SHIFT, ctx->page_size);
	nwqebb = roundup_pow_of_two(attr->cap.max_recv_wr);
	queue_size += align(nwqebb << RQE_SHIFT, ctx->page_size);

	qp->qbuf_size = queue_size;
	rv = posix_memalign(&qp->qbuf, ctx->page_size, queue_size);
	if (rv) {
		errno = ENOMEM;
		return -1;
	}

	rv = ibv_dontfork_range(qp->qbuf, queue_size);
	if (rv) {
		errno = rv;
		goto err_dontfork;
	}

	/* doorbell record allocation. */
	qp->db_records = erdma_alloc_dbrecords(ctx);
	if (!qp->db_records) {
		errno = ENOMEM;
		goto err_dbrec;
	}

	*qp->db_records = 0;
	*(qp->db_records + 1) = 0;
	qp->sq.db_record = qp->db_records;
	qp->rq.db_record = qp->db_records + 1;

	pthread_spin_init(&qp->sq_lock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&qp->rq_lock, PTHREAD_PROCESS_PRIVATE);

	return 0;

err_dbrec:
	ibv_dofork_range(qp->qbuf, queue_size);

err_dontfork:
	free(qp->qbuf);

	return -1;
}

static void erdma_free_qp_buf_and_db(struct erdma_context *ctx,
				     struct erdma_qp *qp)
{
	pthread_spin_destroy(&qp->sq_lock);
	pthread_spin_destroy(&qp->rq_lock);

	if (qp->db_records)
		erdma_dealloc_dbrecords(ctx, qp->db_records);

	ibv_dofork_range(qp->qbuf, qp->qbuf_size);
	free(qp->qbuf);
}

static int erdma_alloc_wrid_tbl(struct erdma_qp *qp)
{
	qp->rq.wr_tbl = calloc(qp->rq.depth, sizeof(uint64_t));
	if (!qp->rq.wr_tbl)
		return -ENOMEM;

	qp->sq.wr_tbl = calloc(qp->sq.depth, sizeof(uint64_t));
	if (!qp->sq.wr_tbl) {
		free(qp->rq.wr_tbl);
		return -ENOMEM;
	}

	return 0;
}

static void erdma_free_wrid_tbl(struct erdma_qp *qp)
{
	free(qp->sq.wr_tbl);
	free(qp->rq.wr_tbl);
}

struct ibv_qp *erdma_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct erdma_context *ctx = to_ectx(pd->context);
	struct erdma_cmd_create_qp_resp resp = {};
	struct erdma_cmd_create_qp cmd = {};
	struct erdma_qp *qp;
	int rv;

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	rv = erdma_alloc_qp_buf_and_db(ctx, qp, attr);
	if (rv)
		goto err;

	cmd.db_record_va = (uintptr_t)qp->db_records;
	cmd.qbuf_va = (uintptr_t)qp->qbuf;
	cmd.qbuf_len = (__u32)qp->qbuf_size;

	rv = ibv_cmd_create_qp(pd, &qp->base_qp, attr, &cmd.ibv_cmd,
			       sizeof(cmd), &resp.ibv_resp, sizeof(resp));
	if (rv)
		goto err_cmd;

	qp->id = resp.qp_id;
	qp->sq.qbuf = qp->qbuf;
	qp->rq.qbuf = qp->qbuf + resp.rq_offset;
	qp->sq.depth = resp.num_sqe;
	qp->rq.depth = resp.num_rqe;
	qp->sq_sig_all = attr->sq_sig_all;
	qp->sq.size = resp.num_sqe * SQEBB_SIZE;
	qp->rq.size = resp.num_rqe * sizeof(struct erdma_rqe);

	/* doorbell allocation. */
	__erdma_alloc_dbs(qp, ctx);

	rv = erdma_alloc_wrid_tbl(qp);
	if (rv)
		goto err_wrid_tbl;

	rv = erdma_store_qp(ctx, qp);
	if (rv) {
		errno = -rv;
		goto err_store;
	}

	return &qp->base_qp;

err_store:
	erdma_free_wrid_tbl(qp);
err_wrid_tbl:
	ibv_cmd_destroy_qp(&qp->base_qp);
err_cmd:
	erdma_free_qp_buf_and_db(ctx, qp);
err:
	free(qp);

	return NULL;
}

int erdma_modify_qp(struct ibv_qp *base_qp, struct ibv_qp_attr *attr,
		    int attr_mask)
{
	struct erdma_qp *qp = to_eqp(base_qp);
	struct ibv_modify_qp cmd = {};
	int rv;

	pthread_spin_lock(&qp->sq_lock);
	pthread_spin_lock(&qp->rq_lock);

	rv = ibv_cmd_modify_qp(base_qp, attr, attr_mask, &cmd, sizeof(cmd));

	pthread_spin_unlock(&qp->rq_lock);
	pthread_spin_unlock(&qp->sq_lock);

	return rv;
}

int erdma_destroy_qp(struct ibv_qp *base_qp)
{
	struct ibv_context *base_ctx = base_qp->pd->context;
	struct erdma_context *ctx = to_ectx(base_ctx);
	struct erdma_qp *qp = to_eqp(base_qp);
	int rv;

	erdma_clear_qp(ctx, qp);

	rv = ibv_cmd_destroy_qp(base_qp);
	if (rv)
		return rv;

	erdma_free_wrid_tbl(qp);
	erdma_free_qp_buf_and_db(ctx, qp);

	free(qp);

	return 0;
}

static int erdma_push_one_sqe(struct erdma_qp *qp, struct ibv_send_wr *wr,
			      uint16_t *sq_pi)
{
	uint32_t i, bytes, sgl_off, sgl_idx, wqebb_cnt, opcode, wqe_size = 0;
	struct erdma_atomic_sqe *atomic_sqe;
	struct erdma_readreq_sqe *read_sqe;
	struct erdma_write_sqe *write_sqe;
	struct erdma_send_sqe *send_sqe;
	struct erdma_sge *sgl_base;
	uint16_t tmp_pi = *sq_pi;
	__le32 *length_field;
	uint64_t sqe_hdr;
	void *sqe;

	sqe = get_sq_wqebb(qp, tmp_pi);
	/* Clear the first 8Byte of the wqe hdr. */
	*(uint64_t *)sqe = 0;

	qp->sq.wr_tbl[tmp_pi & (qp->sq.depth - 1)] = wr->wr_id;

	sqe_hdr = FIELD_PREP(ERDMA_SQE_HDR_QPN_MASK, qp->id) |
		  FIELD_PREP(ERDMA_SQE_HDR_CE_MASK,
			     wr->send_flags & IBV_SEND_SIGNALED ? 1 : 0) |
		  FIELD_PREP(ERDMA_SQE_HDR_CE_MASK, qp->sq_sig_all) |
		  FIELD_PREP(ERDMA_SQE_HDR_SE_MASK,
			     wr->send_flags & IBV_SEND_SOLICITED ? 1 : 0) |
		  FIELD_PREP(ERDMA_SQE_HDR_FENCE_MASK,
			     wr->send_flags & IBV_SEND_FENCE ? 1 : 0) |
		  FIELD_PREP(ERDMA_SQE_HDR_INLINE_MASK,
			     wr->send_flags & IBV_SEND_INLINE ? 1 : 0);

	switch (wr->opcode) {
	case IBV_WR_RDMA_WRITE:
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		if (wr->opcode == IBV_WR_RDMA_WRITE)
			opcode = ERDMA_OP_WRITE;
		else
			opcode = ERDMA_OP_WRITE_WITH_IMM;
		sqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_OPCODE_MASK, opcode);
		write_sqe = sqe;
		write_sqe->imm_data = wr->imm_data;
		write_sqe->sink_stag = htole32(wr->wr.rdma.rkey);
		write_sqe->sink_to_low =
			htole32(wr->wr.rdma.remote_addr & 0xFFFFFFFF);
		write_sqe->sink_to_high =
			htole32((wr->wr.rdma.remote_addr >> 32) & 0xFFFFFFFF);

		length_field = &write_sqe->length;
		/* sgl is at the start of next wqebb. */
		sgl_base = get_sq_wqebb(qp, tmp_pi + 1);
		sgl_off = 0;
		sgl_idx = tmp_pi + 1;
		wqe_size = sizeof(struct erdma_write_sqe);

		break;
	case IBV_WR_SEND:
	case IBV_WR_SEND_WITH_IMM:
		if (wr->opcode == IBV_WR_SEND)
			opcode = ERDMA_OP_SEND;
		else
			opcode = ERDMA_OP_SEND_WITH_IMM;
		sqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_OPCODE_MASK, opcode);
		send_sqe = sqe;
		send_sqe->imm_data = wr->imm_data;

		length_field = &send_sqe->length;
		/* sgl is in the half of current wqebb (offset 16Byte) */
		sgl_base = sqe;
		sgl_off = 16;
		sgl_idx = tmp_pi;
		wqe_size = sizeof(struct erdma_send_sqe);

		break;
	case IBV_WR_RDMA_READ:
		sqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_OPCODE_MASK, ERDMA_OP_READ);
		read_sqe = sqe;

		read_sqe->sink_to_low = htole32(wr->sg_list->addr & 0xFFFFFFFF);
		read_sqe->sink_to_high =
			htole32((wr->sg_list->addr >> 32) & 0xFFFFFFFF);
		read_sqe->sink_stag = htole32(wr->sg_list->lkey);
		read_sqe->length = htole32(wr->sg_list->length);

		sgl_base = get_sq_wqebb(qp, tmp_pi + 1);

		sgl_base->addr = htole64(wr->wr.rdma.remote_addr);
		sgl_base->length = htole32(wr->sg_list->length);
		sgl_base->key = htole32(wr->wr.rdma.rkey);

		wqe_size = sizeof(struct erdma_readreq_sqe);

		goto out;
	case IBV_WR_ATOMIC_CMP_AND_SWP:
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		atomic_sqe = (struct erdma_atomic_sqe *)sqe;

		if (wr->opcode == IBV_WR_ATOMIC_CMP_AND_SWP) {
			sqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_OPCODE_MASK,
					      ERDMA_OP_ATOMIC_CAS);
			atomic_sqe->fetchadd_swap_data =
				htole64(wr->wr.atomic.swap);
			atomic_sqe->cmp_data =
				htole64(wr->wr.atomic.compare_add);
		} else {
			sqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_OPCODE_MASK,
					      ERDMA_OP_ATOMIC_FAD);
			atomic_sqe->fetchadd_swap_data =
				htole64(wr->wr.atomic.compare_add);
		}

		sgl_base = (struct erdma_sge *)get_sq_wqebb(qp, tmp_pi + 1);
		/* remote SGL fields */
		sgl_base->addr = htole64(wr->wr.atomic.remote_addr);
		sgl_base->key = htole32(wr->wr.atomic.rkey);

		/* local SGL fields */
		sgl_base++;
		sgl_base->addr = htole64(wr->sg_list[0].addr);
		sgl_base->length = htole32(wr->sg_list[0].length);
		sgl_base->key = htole32(wr->sg_list[0].lkey);
		wqe_size = sizeof(struct erdma_atomic_sqe);
		goto out;
	default:
		return -EINVAL;
	}

	if (wr->send_flags & IBV_SEND_INLINE) {
		char *data = (char *)sgl_base;
		uint32_t remain_size;
		uint32_t copy_size;
		uint32_t data_off;

		i = 0;
		bytes = 0;

		/* Allow more than ERDMA_MAX_SGE, since content copied here */
		while (i < wr->num_sge) {
			bytes += wr->sg_list[i].length;
			if (bytes > (int)ERDMA_MAX_INLINE)
				return -EINVAL;

			remain_size = wr->sg_list[i].length;
			data_off = 0;

			while (1) {
				copy_size =
					min(remain_size, SQEBB_SIZE - sgl_off);
				memcpy(data + sgl_off,
				       (void *)(uintptr_t)wr->sg_list[i].addr +
					       data_off,
				       copy_size);
				remain_size -= copy_size;

				/* Update sgl_offset. */
				sgl_idx +=
					((sgl_off + copy_size) >> SQEBB_SHIFT);
				sgl_off = (sgl_off + copy_size) &
					  (SQEBB_SIZE - 1);
				data_off += copy_size;
				data = get_sq_wqebb(qp, sgl_idx);

				if (!remain_size)
					break;
			};

			i++;
		}

		*length_field = htole32(bytes);
		wqe_size += bytes;
		sqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_SGL_LEN_MASK, bytes);
	} else {
		char *sgl = (char *)sgl_base;

		if (wr->num_sge > ERDMA_MAX_SEND_SGE)
			return -EINVAL;

		i = 0;
		bytes = 0;

		while (i < wr->num_sge) {
			bytes += wr->sg_list[i].length;
			memcpy(sgl + sgl_off, &wr->sg_list[i],
			       sizeof(struct ibv_sge));

			if (sgl_off == 0)
				*(uint32_t *)(sgl + 28) = qp->id;

			sgl_idx += (sgl_off == sizeof(struct ibv_sge) ? 1 : 0);
			sgl = get_sq_wqebb(qp, sgl_idx);
			sgl_off = sizeof(struct ibv_sge) - sgl_off;

			i++;
		}

		*length_field = htole32(bytes);
		sqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_SGL_LEN_MASK, wr->num_sge);
		wqe_size += wr->num_sge * sizeof(struct ibv_sge);
	}

out:
	wqebb_cnt = SQEBB_COUNT(wqe_size);
	assert(wqebb_cnt <= MAX_WQEBB_PER_SQE);
	sqe_hdr |= FIELD_PREP(ERDMA_SQE_HDR_WQEBB_CNT_MASK, wqebb_cnt - 1);
	sqe_hdr |=
		FIELD_PREP(ERDMA_SQE_HDR_WQEBB_INDEX_MASK, tmp_pi + wqebb_cnt);

	*(__le64 *)sqe = htole64(sqe_hdr);
	*sq_pi = tmp_pi + wqebb_cnt;

	return 0;
}

int erdma_post_send(struct ibv_qp *base_qp, struct ibv_send_wr *wr,
		    struct ibv_send_wr **bad_wr)
{
	struct erdma_qp *qp = to_eqp(base_qp);
	int new_sqe = 0, rv = 0;
	uint16_t sq_pi;

	*bad_wr = NULL;

	if (base_qp->state == IBV_QPS_ERR) {
		*bad_wr = wr;
		return -EIO;
	}

	pthread_spin_lock(&qp->sq_lock);

	sq_pi = qp->sq.pi;

	while (wr) {
		if ((uint16_t)(sq_pi - qp->sq.ci) >= qp->sq.depth) {
			rv = -ENOMEM;
			*bad_wr = wr;
			break;
		}

		rv = erdma_push_one_sqe(qp, wr, &sq_pi);
		if (rv) {
			*bad_wr = wr;
			break;
		}

		new_sqe++;
		wr = wr->next;
	}

	if (new_sqe) {
		qp->sq.pi = sq_pi;
		__kick_sq_db(qp, sq_pi); /* normal doorbell. */
	}

	pthread_spin_unlock(&qp->sq_lock);

	return rv;
}

static int push_recv_wqe(struct erdma_qp *qp, struct ibv_recv_wr *wr)
{
	uint16_t rq_pi = qp->rq.pi;
	uint16_t idx = rq_pi & (qp->rq.depth - 1);
	struct erdma_rqe *rqe = (struct erdma_rqe *)qp->rq.qbuf + idx;

	if ((uint16_t)(rq_pi - qp->rq.ci) == qp->rq.depth)
		return -ENOMEM;

	rqe->qe_idx = htole16(rq_pi + 1);
	rqe->qpn = htole32(qp->id);
	qp->rq.wr_tbl[idx] = wr->wr_id;

	if (wr->num_sge == 0) {
		rqe->length = 0;
	} else if (wr->num_sge == 1) {
		rqe->stag = htole32(wr->sg_list[0].lkey);
		rqe->to = htole64(wr->sg_list[0].addr);
		rqe->length = htole32(wr->sg_list[0].length);
	} else {
		return -EINVAL;
	}

	*(__le64 *)qp->rq.db_record = *(__le64 *)rqe;
	udma_to_device_barrier();
	mmio_write64_le(qp->rq.db, *(__le64 *)rqe);

	qp->rq.pi = rq_pi + 1;

	return 0;
}

int erdma_post_recv(struct ibv_qp *base_qp, struct ibv_recv_wr *wr,
		    struct ibv_recv_wr **bad_wr)
{
	struct erdma_qp *qp = to_eqp(base_qp);
	int ret = 0;

	if (base_qp->state == IBV_QPS_ERR) {
		*bad_wr = wr;
		return -EIO;
	}

	pthread_spin_lock(&qp->rq_lock);

	while (wr) {
		ret = push_recv_wqe(qp, wr);
		if (ret) {
			*bad_wr = wr;
			break;
		}

		wr = wr->next;
	}

	pthread_spin_unlock(&qp->rq_lock);

	return ret;
}

void erdma_cq_event(struct ibv_cq *ibcq)
{
	struct erdma_cq *cq = to_ecq(ibcq);

	cq->cmdsn++;
}

static void *get_next_valid_cqe(struct erdma_cq *cq)
{
	struct erdma_cqe *cqe = cq->queue + (cq->ci & (cq->depth - 1));
	uint32_t owner = FIELD_GET(ERDMA_CQE_HDR_OWNER_MASK, be32toh(cqe->hdr));

	return owner ^ !!(cq->ci & cq->depth) ? cqe : NULL;
}

static const enum ibv_wc_opcode wc_mapping_table[ERDMA_NUM_OPCODES] = {
	[ERDMA_OP_WRITE] = IBV_WC_RDMA_WRITE,
	[ERDMA_OP_READ] = IBV_WC_RDMA_READ,
	[ERDMA_OP_SEND] = IBV_WC_SEND,
	[ERDMA_OP_SEND_WITH_IMM] = IBV_WC_SEND,
	[ERDMA_OP_RECEIVE] = IBV_WC_RECV,
	[ERDMA_OP_RECV_IMM] = IBV_WC_RECV_RDMA_WITH_IMM,
	[ERDMA_OP_RECV_INV] = IBV_WC_RECV,
	[ERDMA_OP_WRITE_WITH_IMM] = IBV_WC_RDMA_WRITE,
	[ERDMA_OP_INVALIDATE] = IBV_WC_LOCAL_INV,
	[ERDMA_OP_RSP_SEND_IMM] = IBV_WC_RECV,
	[ERDMA_OP_SEND_WITH_INV] = IBV_WC_SEND,
	[ERDMA_OP_READ_WITH_INV] = IBV_WC_RDMA_READ,
	[ERDMA_OP_ATOMIC_CAS] = IBV_WC_COMP_SWAP,
	[ERDMA_OP_ATOMIC_FAD] = IBV_WC_FETCH_ADD,
};

static const struct {
	enum erdma_wc_status erdma;
	enum ibv_wc_status base;
	enum erdma_vendor_err vendor;
} map_cqe_status[ERDMA_NUM_WC_STATUS] = {
	{ ERDMA_WC_SUCCESS, IBV_WC_SUCCESS, ERDMA_WC_VENDOR_NO_ERR },
	{ ERDMA_WC_GENERAL_ERR, IBV_WC_GENERAL_ERR, ERDMA_WC_VENDOR_NO_ERR },
	{ ERDMA_WC_RECV_WQE_FORMAT_ERR, IBV_WC_GENERAL_ERR,
	  ERDMA_WC_VENDOR_INVALID_RQE },
	{ ERDMA_WC_RECV_STAG_INVALID_ERR, IBV_WC_REM_ACCESS_ERR,
	  ERDMA_WC_VENDOR_RQE_INVALID_STAG },
	{ ERDMA_WC_RECV_ADDR_VIOLATION_ERR, IBV_WC_REM_ACCESS_ERR,
	  ERDMA_WC_VENDOR_RQE_ADDR_VIOLATION },
	{ ERDMA_WC_RECV_RIGHT_VIOLATION_ERR, IBV_WC_REM_ACCESS_ERR,
	  ERDMA_WC_VENDOR_RQE_ACCESS_RIGHT_ERR },
	{ ERDMA_WC_RECV_PDID_ERR, IBV_WC_REM_ACCESS_ERR,
	  ERDMA_WC_VENDOR_RQE_INVALID_PD },
	{ ERDMA_WC_RECV_WARRPING_ERR, IBV_WC_REM_ACCESS_ERR,
	  ERDMA_WC_VENDOR_RQE_WRAP_ERR },
	{ ERDMA_WC_SEND_WQE_FORMAT_ERR, IBV_WC_LOC_QP_OP_ERR,
	  ERDMA_WC_VENDOR_INVALID_SQE },
	{ ERDMA_WC_SEND_WQE_ORD_EXCEED, IBV_WC_GENERAL_ERR,
	  ERDMA_WC_VENDOR_ZERO_ORD },
	{ ERDMA_WC_SEND_STAG_INVALID_ERR, IBV_WC_LOC_ACCESS_ERR,
	  ERDMA_WC_VENDOR_SQE_INVALID_STAG },
	{ ERDMA_WC_SEND_ADDR_VIOLATION_ERR, IBV_WC_LOC_ACCESS_ERR,
	  ERDMA_WC_VENDOR_SQE_ADDR_VIOLATION },
	{ ERDMA_WC_SEND_RIGHT_VIOLATION_ERR, IBV_WC_LOC_ACCESS_ERR,
	  ERDMA_WC_VENDOR_SQE_ACCESS_ERR },
	{ ERDMA_WC_SEND_PDID_ERR, IBV_WC_LOC_ACCESS_ERR,
	  ERDMA_WC_VENDOR_SQE_INVALID_PD },
	{ ERDMA_WC_SEND_WARRPING_ERR, IBV_WC_LOC_ACCESS_ERR,
	  ERDMA_WC_VENDOR_SQE_WARP_ERR },
	{ ERDMA_WC_FLUSH_ERR, IBV_WC_WR_FLUSH_ERR, ERDMA_WC_VENDOR_NO_ERR },
	{ ERDMA_WC_RETRY_EXC_ERR, IBV_WC_RETRY_EXC_ERR,
	  ERDMA_WC_VENDOR_NO_ERR },
};

#define ERDMA_POLLCQ_NO_QP (-1)
#define ERDMA_POLLCQ_DUP_COMP (-2)
#define ERDMA_POLLCQ_WRONG_IDX (-3)

static int __erdma_poll_one_cqe(struct erdma_context *ctx, struct erdma_cq *cq,
				struct ibv_wc *wc)
{
	uint32_t cqe_hdr, opcode, syndrome, qpn;
	uint16_t depth, wqe_idx, old_ci, new_ci;
	uint64_t *sqe_hdr, *qeidx2wrid;
	uint32_t tbl_idx, tbl_off;
	struct erdma_cqe *cqe;
	struct erdma_qp *qp;

	cqe = get_next_valid_cqe(cq);
	if (!cqe)
		return -EAGAIN;

	cq->ci++;
	udma_from_device_barrier();

	cqe_hdr = be32toh(cqe->hdr);
	syndrome = FIELD_GET(ERDMA_CQE_HDR_SYNDROME_MASK, cqe_hdr);
	opcode = FIELD_GET(ERDMA_CQE_HDR_OPCODE_MASK, cqe_hdr);
	qpn = be32toh(cqe->qpn);
	wqe_idx = be32toh(cqe->qe_idx);

	tbl_idx = qpn >> ERDMA_QP_TABLE_SHIFT;
	tbl_off = qpn & ERDMA_QP_TABLE_MASK;

	if (!ctx->qp_table[tbl_idx].table ||
	    !ctx->qp_table[tbl_idx].table[tbl_off])
		return ERDMA_POLLCQ_NO_QP;

	qp = ctx->qp_table[tbl_idx].table[tbl_off];

	if (FIELD_GET(ERDMA_CQE_HDR_QTYPE_MASK, cqe_hdr) ==
	    ERDMA_CQE_QTYPE_SQ) {
		qeidx2wrid = qp->sq.wr_tbl;
		depth = qp->sq.depth;
		sqe_hdr = get_sq_wqebb(qp, wqe_idx);
		old_ci = qp->sq.ci;
		new_ci = wqe_idx +
			 FIELD_GET(ERDMA_SQE_HDR_WQEBB_CNT_MASK, *sqe_hdr) + 1;

		if ((uint16_t)(new_ci - old_ci) > depth)
			return ERDMA_POLLCQ_WRONG_IDX;
		else if (new_ci == old_ci)
			return ERDMA_POLLCQ_DUP_COMP;

		qp->sq.ci = new_ci;
	} else {
		qeidx2wrid = qp->rq.wr_tbl;
		depth = qp->rq.depth;
		qp->rq.ci++;
	}

	wc->wr_id = qeidx2wrid[wqe_idx & (depth - 1)];
	wc->byte_len = be32toh(cqe->size);
	wc->wc_flags = 0;

	wc->opcode = wc_mapping_table[opcode];
	if (opcode == ERDMA_OP_RECV_IMM || opcode == ERDMA_OP_RSP_SEND_IMM) {
		wc->imm_data = htobe32(le32toh(cqe->imm_data));
		wc->wc_flags |= IBV_WC_WITH_IMM;
	}

	if (syndrome >= ERDMA_NUM_WC_STATUS)
		syndrome = ERDMA_WC_GENERAL_ERR;

	wc->status = map_cqe_status[syndrome].base;
	wc->vendor_err = map_cqe_status[syndrome].vendor;
	wc->qp_num = qpn;

	return 0;
}

int erdma_poll_cq(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc)
{
	struct erdma_context *ctx = to_ectx(ibcq->context);
	struct erdma_cq *cq = to_ecq(ibcq);
	int ret, npolled = 0;

	pthread_spin_lock(&cq->lock);

	while (npolled < num_entries) {
		ret = __erdma_poll_one_cqe(ctx, cq, wc + npolled);
		if (ret == -EAGAIN) /* CQ is empty, break the loop. */
			break;
		else if (ret) /* We handle the polling error silently. */
			continue;
		npolled++;
	}

	pthread_spin_unlock(&cq->lock);

	return npolled;
}

void erdma_free_context(struct ibv_context *ibv_ctx)
{
	struct erdma_context *ctx = to_ectx(ibv_ctx);
	int i;

	munmap(ctx->sdb, ERDMA_PAGE_SIZE);
	munmap(ctx->rdb, ERDMA_PAGE_SIZE);
	munmap(ctx->cdb, ERDMA_PAGE_SIZE);

	pthread_mutex_lock(&ctx->qp_table_mutex);
	for (i = 0; i < ERDMA_QP_TABLE_SIZE; ++i) {
		if (ctx->qp_table[i].refcnt)
			free(ctx->qp_table[i].table);
	}

	pthread_mutex_unlock(&ctx->qp_table_mutex);
	pthread_mutex_destroy(&ctx->qp_table_mutex);

	verbs_uninit_context(&ctx->ibv_ctx);
	free(ctx);
}
