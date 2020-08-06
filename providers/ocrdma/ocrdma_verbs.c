/*
 * Copyright (C) 2008-2013 Emulex.  All rights reserved.
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT  LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>

#include <assert.h>
#include <endian.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#include <endian.h>

#include "ocrdma_main.h"
#include "ocrdma_abi.h"
#include <ccan/list.h>
#include <util/compiler.h>

static void ocrdma_ring_cq_db(struct ocrdma_cq *cq, uint32_t armed,
			      int solicited, uint32_t num_cqe);

static inline void ocrdma_swap_cpu_to_le(void *dst, uint32_t len)
{
	int i = 0;
        __le32 *src_ptr = dst;
	uint32_t *dst_ptr = dst;
	for (; i < (len / 4); i++)
		*dst_ptr++ = le32toh(*src_ptr++);
}

/*
 * ocrdma_query_device
 */
int ocrdma_query_device(struct ibv_context *context,
			struct ibv_device_attr *attr)
{
	struct ibv_query_device cmd;
	uint64_t fw_ver;
	struct ocrdma_device *dev = get_ocrdma_dev(context->device);
	int status;

	bzero(attr, sizeof *attr);
	status = ibv_cmd_query_device(context, attr, &fw_ver, &cmd, sizeof cmd);
	memcpy(attr->fw_ver, dev->fw_ver, sizeof(dev->fw_ver));
	return status;
}

/*
 * ocrdma_query_port
 */
int ocrdma_query_port(struct ibv_context *context, uint8_t port,
		      struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;
	int status;
	status = ibv_cmd_query_port(context, port, attr, &cmd, sizeof cmd);
	return status;
}

#define OCRDMA_INVALID_AH_IDX 0xffffffff
void ocrdma_init_ahid_tbl(struct ocrdma_devctx *ctx)
{
	int i;

	pthread_mutex_init(&ctx->tbl_lock, NULL);
	for (i = 0; i < (ctx->ah_tbl_len / sizeof(uint32_t)); i++)
		ctx->ah_tbl[i] = OCRDMA_INVALID_AH_IDX;
}

static int ocrdma_alloc_ah_tbl_id(struct ocrdma_devctx *ctx)
{
	int i;
	int status = -EINVAL;
	pthread_mutex_lock(&ctx->tbl_lock);

	for (i = 0; i < (ctx->ah_tbl_len / sizeof(uint32_t)); i++) {
		if (ctx->ah_tbl[i] == OCRDMA_INVALID_AH_IDX) {
			ctx->ah_tbl[i] = ctx->ah_tbl_len;
			status = i;
			break;
		}
	}
	pthread_mutex_unlock(&ctx->tbl_lock);
	return status;
}

static void ocrdma_free_ah_tbl_id(struct ocrdma_devctx *ctx, int idx)
{
	pthread_mutex_lock(&ctx->tbl_lock);
	ctx->ah_tbl[idx] = OCRDMA_INVALID_AH_IDX;
	pthread_mutex_unlock(&ctx->tbl_lock);
}

/*
 * ocrdma_alloc_pd
 */
struct ibv_pd *ocrdma_alloc_pd(struct ibv_context *context)
{
	struct uocrdma_alloc_pd cmd;
	struct uocrdma_alloc_pd_resp resp;
	struct ocrdma_pd *pd;
	uint64_t map_address = 0;

	pd = malloc(sizeof *pd);
	if (!pd)
		return NULL;
	bzero(pd, sizeof *pd);
	memset(&cmd, 0, sizeof(cmd));

	if (ibv_cmd_alloc_pd(context, &pd->ibv_pd, &cmd.ibv_cmd, sizeof(cmd),
			     &resp.ibv_resp, sizeof(resp))) {
		free(pd);
		return NULL;
	}
	pd->dev = get_ocrdma_dev(context->device);
	pd->uctx = get_ocrdma_ctx(context);

	if (resp.dpp_enabled) {
		map_address = ((uint64_t) resp.dpp_page_addr_hi << 32) |
		    resp.dpp_page_addr_lo;
		pd->dpp_va = mmap(NULL, OCRDMA_DPP_PAGE_SIZE, PROT_WRITE,
				  MAP_SHARED, context->cmd_fd, map_address);
		if (pd->dpp_va == MAP_FAILED) {
			ocrdma_free_pd(&pd->ibv_pd);
			return NULL;
		}
	}
	return &pd->ibv_pd;
}

/*
 * ocrdma_free_pd
 */
int ocrdma_free_pd(struct ibv_pd *ibpd)
{
	int status;
	struct ocrdma_pd *pd = get_ocrdma_pd(ibpd);

	status = ibv_cmd_dealloc_pd(ibpd);
	if (status)
		return status;

	if (pd->dpp_va)
		munmap((void *)pd->dpp_va, OCRDMA_DPP_PAGE_SIZE);
	free(pd);
	return 0;
}

/*
 * ocrdma_reg_mr
 */
struct ibv_mr *ocrdma_reg_mr(struct ibv_pd *pd, void *addr, size_t len,
			     uint64_t hca_va, int access)
{
	struct ocrdma_mr *mr;
	struct ibv_reg_mr cmd;
	struct uocrdma_reg_mr_resp resp;

	mr = malloc(sizeof *mr);
	if (!mr)
		return NULL;
	bzero(mr, sizeof *mr);

	if (ibv_cmd_reg_mr(pd, addr, len, hca_va, access, &mr->vmr, &cmd,
			   sizeof(cmd), &resp.ibv_resp, sizeof(resp))) {
		free(mr);
		return NULL;
	}
	return &mr->vmr.ibv_mr;
}

/*
 * ocrdma_dereg_mr
 */
int ocrdma_dereg_mr(struct verbs_mr *vmr)
{
	int status;
	status = ibv_cmd_dereg_mr(vmr);
	if (status)
		return status;
	free(vmr);
	return 0;
}

/*
 * ocrdma_create_cq
 */
static struct ibv_cq *ocrdma_create_cq_common(struct ibv_context *context,
					      int cqe,
					      struct ibv_comp_channel *channel,
					      int comp_vector, int dpp_cq)
{
	int status;
	struct uocrdma_create_cq cmd;
	struct uocrdma_create_cq_resp resp;
	struct ocrdma_cq *cq;
	struct ocrdma_device *dev = get_ocrdma_dev(context->device);
	void *map_addr;

	cq = malloc(sizeof *cq);
	if (!cq)
		return NULL;

	bzero(cq, sizeof *cq);
	cmd.dpp_cq = dpp_cq;
	status = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				   &cq->ibv_cq, &cmd.ibv_cmd, sizeof cmd,
				   &resp.ibv_resp, sizeof resp);
	if (status)
		goto cq_err1;

	pthread_spin_init(&cq->cq_lock, PTHREAD_PROCESS_PRIVATE);
	cq->dev = dev;
	cq->cq_id = resp.cq_id;
	cq->cq_dbid = resp.cq_id;
	cq->cq_mem_size = resp.page_size;
	cq->max_hw_cqe = resp.max_hw_cqe;
	cq->phase_change = resp.phase_change;
	cq->va = mmap(NULL, resp.page_size, PROT_READ | PROT_WRITE,
		      MAP_SHARED, context->cmd_fd, resp.page_addr[0]);
	if (cq->va == MAP_FAILED)
		goto cq_err2;

	map_addr = mmap(NULL, resp.db_page_size, PROT_WRITE,
			MAP_SHARED, context->cmd_fd, resp.db_page_addr);
	if (map_addr == MAP_FAILED)
		goto cq_err2;
	cq->db_va = map_addr;
	cq->db_size = resp.db_page_size;
	cq->phase = OCRDMA_CQE_VALID;
	cq->first_arm = 1;
	if (!dpp_cq) {
		ocrdma_ring_cq_db(cq, 0, 0, 0);
	}
	cq->ibv_cq.cqe = cqe;
	list_head_init(&cq->sq_head);
	list_head_init(&cq->rq_head);
	return &cq->ibv_cq;
cq_err2:
	(void)ibv_cmd_destroy_cq(&cq->ibv_cq);
cq_err1:
	free(cq);
	return NULL;
}

struct ibv_cq *ocrdma_create_cq(struct ibv_context *context, int cqe,
				struct ibv_comp_channel *channel,
				int comp_vector)
{
	return ocrdma_create_cq_common(context, cqe, channel, comp_vector, 0);
}

#ifdef DPP_CQ_SUPPORT
static struct ocrdma_cq *ocrdma_create_dpp_cq(struct ibv_context *context,
					      int cqe)
{
	struct ibv_cq *ibcq;
	ibcq = ocrdma_create_cq_common(context, cqe, 0, 0, 1);
	if (ibcq)
		return get_ocrdma_cq(ibcq);
	return NULL;
}
#endif

/*
 * ocrdma_resize_cq
 */
int ocrdma_resize_cq(struct ibv_cq *ibcq, int new_entries)
{
	int status;
	struct ibv_resize_cq cmd;
	struct ib_uverbs_resize_cq_resp resp;
	status = ibv_cmd_resize_cq(ibcq, new_entries,
				   &cmd, sizeof cmd, &resp, sizeof resp);
	if (status == 0)
		ibcq->cqe = new_entries;
	return status;
}

/*
 * ocrdma_destroy_cq
 */
int ocrdma_destroy_cq(struct ibv_cq *ibv_cq)
{
	struct ocrdma_cq *cq = get_ocrdma_cq(ibv_cq);
	int status;

	status = ibv_cmd_destroy_cq(ibv_cq);
	if (status)
		return status;

	if (cq->db_va)
		munmap((void *)cq->db_va, cq->db_size);
	if (cq->va)
		munmap((void*)cq->va, cq->cq_mem_size);

	free(cq);
	return 0;
}

static void ocrdma_add_qpn_map(struct ocrdma_device *dev, struct ocrdma_qp *qp)
{
	pthread_mutex_lock(&dev->dev_lock);
	dev->qp_tbl[qp->id] = qp;
	pthread_mutex_unlock(&dev->dev_lock);
}

static void _ocrdma_del_qpn_map(struct ocrdma_device *dev, struct ocrdma_qp *qp)
{
	dev->qp_tbl[qp->id] = NULL;
}

struct ibv_srq *ocrdma_create_srq(struct ibv_pd *pd,
				  struct ibv_srq_init_attr *init_attr)
{
	int status = 0;
	struct ocrdma_srq *srq;
	struct uocrdma_create_srq cmd;
	struct uocrdma_create_srq_resp resp;
	void *map_addr;

	srq = calloc(1, sizeof *srq);
	if (!srq)
		return NULL;

	pthread_spin_init(&srq->q_lock, PTHREAD_PROCESS_PRIVATE);
	status = ibv_cmd_create_srq(pd, &srq->ibv_srq, init_attr, &cmd.ibv_cmd,
				    sizeof cmd, &resp.ibv_resp, sizeof resp);
	if (status)
		goto cmd_err;

	srq->dev = get_ocrdma_pd(pd)->dev;
	srq->rq.dbid = resp.rq_dbid;
	srq->rq.max_sges = init_attr->attr.max_sge;
	srq->rq.max_cnt = resp.num_rqe_allocated;
	srq->rq.max_wqe_idx = resp.num_rqe_allocated - 1;
	srq->rq.entry_size = srq->dev->rqe_size;
	srq->rqe_wr_id_tbl = calloc(srq->rq.max_cnt, sizeof(uint64_t));
	if (srq->rqe_wr_id_tbl == NULL)
		goto map_err;

	srq->bit_fields_len =
	    (srq->rq.max_cnt / 32) + (srq->rq.max_cnt % 32 ? 1 : 0);
	srq->idx_bit_fields = malloc(srq->bit_fields_len * sizeof(uint32_t));
	if (srq->idx_bit_fields == NULL)
		goto map_err;
	memset(srq->idx_bit_fields, 0xff,
	       srq->bit_fields_len * sizeof(uint32_t));

	if (resp.num_rq_pages > 1)
		goto map_err;

	map_addr = mmap(NULL, resp.rq_page_size, PROT_READ | PROT_WRITE,
			MAP_SHARED, pd->context->cmd_fd, resp.rq_page_addr[0]);
	if (map_addr == MAP_FAILED)
		goto map_err;
	srq->rq.len = resp.rq_page_size;
	srq->rq.va = map_addr;

	map_addr = mmap(NULL, resp.db_page_size, PROT_WRITE,
			MAP_SHARED, pd->context->cmd_fd, resp.db_page_addr);
	if (map_addr == MAP_FAILED)
		goto map_err;
	srq->db_va = (uint8_t *) map_addr + resp.db_rq_offset;
	srq->db_shift = resp.db_shift;
	srq->db_size = resp.db_page_size;
	return &srq->ibv_srq;

map_err:
	ocrdma_destroy_srq(&srq->ibv_srq);
	return NULL;

cmd_err:
	pthread_spin_destroy(&srq->q_lock);
	free(srq);
	return NULL;
}

int ocrdma_modify_srq(struct ibv_srq *ibsrq,
		      struct ibv_srq_attr *attr, int attr_mask)
{
	struct ibv_modify_srq cmd;

	return ibv_cmd_modify_srq(ibsrq, attr, attr_mask, &cmd, sizeof cmd);
}

int ocrdma_query_srq(struct ibv_srq *ibsrq, struct ibv_srq_attr *attr)
{
	struct ibv_query_srq cmd;

	return ibv_cmd_query_srq(ibsrq, attr, &cmd, sizeof cmd);
}

int ocrdma_destroy_srq(struct ibv_srq *ibsrq)
{
	int status;
	struct ocrdma_srq *srq;
	srq = get_ocrdma_srq(ibsrq);

	status = ibv_cmd_destroy_srq(ibsrq);
	if (status)
		return status;

	if (srq->idx_bit_fields)
		free(srq->idx_bit_fields);
	if (srq->rqe_wr_id_tbl)
		free(srq->rqe_wr_id_tbl);
	if (srq->db_va) {
		munmap((void *)srq->db_va, srq->db_size);
		srq->db_va = NULL;
	}
	if (srq->rq.va) {
		munmap(srq->rq.va, srq->rq.len);
		srq->rq.va = NULL;
	}
	pthread_spin_destroy(&srq->q_lock);
	free(srq);
	return status;
}

/*
 * ocrdma_create_qp
 */
struct ibv_qp *ocrdma_create_qp(struct ibv_pd *pd,
				struct ibv_qp_init_attr *attrs)
{
	int status = 0;
	struct uocrdma_create_qp cmd;
	struct uocrdma_create_qp_resp resp;
	struct ocrdma_qp *qp;
	void *map_addr;
#ifdef DPP_CQ_SUPPORT
	struct ocrdma_dpp_cqe *dpp_cqe = NULL;
#endif

	qp = calloc(1, sizeof *qp);
	if (!qp)
		return NULL;
	memset(&cmd, 0, sizeof(cmd));

	qp->qp_type = attrs->qp_type;
	pthread_spin_init(&qp->q_lock, PTHREAD_PROCESS_PRIVATE);

#ifdef DPP_CQ_SUPPORT
	if (attrs->cap.max_inline_data) {
		qp->dpp_cq = ocrdma_create_dpp_cq(pd->context,
					OCRDMA_CREATE_QP_REQ_DPP_CREDIT_LIMIT);
		if (qp->dpp_cq) {
			cmd.enable_dpp_cq = 1;
			cmd.dpp_cq_id = qp->dpp_cq->cq_id;
			/* Write invalid index for the first entry */
			dpp_cqe = (struct ocrdma_dpp_cqe *)qp->dpp_cq->va;
			dpp_cqe->wqe_idx_valid = 0xFFFF;
			qp->dpp_prev_indx = 0xFFFF;
		}
	}
#endif
	status = ibv_cmd_create_qp(pd, &qp->ibv_qp, attrs, &cmd.ibv_cmd,
				   sizeof cmd, &resp.ibv_resp, sizeof resp);
	if (status)
		goto mbx_err;

	qp->dev = get_ocrdma_dev(pd->context->device);
	qp->id = resp.qp_id;

	ocrdma_add_qpn_map(qp->dev, qp);

	qp->sq.dbid = resp.sq_dbid;

	qp->sq.max_sges = attrs->cap.max_send_sge;
	qp->max_inline_data = attrs->cap.max_inline_data;

	qp->signaled = attrs->sq_sig_all;

	qp->sq.max_cnt = resp.num_wqe_allocated;
	qp->sq.max_wqe_idx = resp.num_wqe_allocated - 1;
	qp->sq.entry_size = qp->dev->wqe_size;
	if (attrs->srq)
		qp->srq = get_ocrdma_srq(attrs->srq);
	else {
		qp->rq.dbid = resp.rq_dbid;
		qp->rq.max_sges = attrs->cap.max_recv_sge;
		qp->rq.max_cnt = resp.num_rqe_allocated;
		qp->rq.max_wqe_idx = resp.num_rqe_allocated - 1;
		qp->rq.entry_size = qp->dev->rqe_size;
		qp->rqe_wr_id_tbl = calloc(qp->rq.max_cnt, sizeof(uint64_t));
		if (qp->rqe_wr_id_tbl == NULL)
			goto map_err;
	}

	qp->sq_cq = get_ocrdma_cq(attrs->send_cq);
	qp->rq_cq = get_ocrdma_cq(attrs->recv_cq);

	qp->wqe_wr_id_tbl = calloc(qp->sq.max_cnt, sizeof(*qp->wqe_wr_id_tbl));
	if (qp->wqe_wr_id_tbl == NULL)
		goto map_err;

	/* currently we support only one virtual page */
	if ((resp.num_sq_pages > 1) || (!attrs->srq && resp.num_rq_pages > 1))
		goto map_err;

	map_addr = mmap(NULL, resp.sq_page_size, PROT_READ | PROT_WRITE,
			MAP_SHARED, pd->context->cmd_fd, resp.sq_page_addr[0]);
	if (map_addr == MAP_FAILED)
		goto map_err;
	qp->sq.va = map_addr;
	qp->sq.len = resp.sq_page_size;
	qp->db_shift = resp.db_shift;

	if (!attrs->srq) {
		map_addr = mmap(NULL, resp.rq_page_size, PROT_READ | PROT_WRITE,
				MAP_SHARED, pd->context->cmd_fd,
				resp.rq_page_addr[0]);
		if (map_addr == MAP_FAILED)
			goto map_err;

		qp->rq.len = resp.rq_page_size;
		qp->rq.va = map_addr;
	}

	map_addr = mmap(NULL, resp.db_page_size, PROT_WRITE,
			MAP_SHARED, pd->context->cmd_fd, resp.db_page_addr);
	if (map_addr == MAP_FAILED)
		goto map_err;

	qp->db_va = map_addr;
	qp->db_sq_va = (uint8_t *) map_addr + resp.db_sq_offset;
	qp->db_rq_va = (uint8_t *) map_addr + resp.db_rq_offset;

	qp->db_size = resp.db_page_size;

	if (resp.dpp_credit) {
		struct ocrdma_pd *opd = get_ocrdma_pd(pd);
		map_addr = (uint8_t *) opd->dpp_va +
		    (resp.dpp_offset * qp->dev->wqe_size);
		qp->dpp_q.max_cnt = 1;	/* DPP is posted at the same offset */
		qp->dpp_q.free_cnt = resp.dpp_credit;
		qp->dpp_q.va = map_addr;
		qp->dpp_q.head = qp->dpp_q.tail = 0;
		qp->dpp_q.entry_size = qp->dev->dpp_wqe_size;
		qp->dpp_q.len = resp.dpp_credit * qp->dev->dpp_wqe_size;
		qp->dpp_enabled = 1;
	} else {
		if (qp->dpp_cq) {
			ocrdma_destroy_cq(&qp->dpp_cq->ibv_cq);
			qp->dpp_cq = NULL;
		}
	}
	qp->state = OCRDMA_QPS_RST;
	list_node_init(&qp->sq_entry);
	list_node_init(&qp->rq_entry);
	return &qp->ibv_qp;

map_err:
	ocrdma_destroy_qp(&qp->ibv_qp);
	return NULL;
mbx_err:
	pthread_spin_destroy(&qp->q_lock);
	free(qp);
	return NULL;
}

static enum ocrdma_qp_state get_ocrdma_qp_state(enum ibv_qp_state qps)
{
	switch (qps) {
	case IBV_QPS_RESET:
		return OCRDMA_QPS_RST;
	case IBV_QPS_INIT:
		return OCRDMA_QPS_INIT;
	case IBV_QPS_RTR:
		return OCRDMA_QPS_RTR;
	case IBV_QPS_RTS:
		return OCRDMA_QPS_RTS;
	case IBV_QPS_SQD:
		return OCRDMA_QPS_SQD;
	case IBV_QPS_SQE:
		return OCRDMA_QPS_SQE;
	case IBV_QPS_ERR:
		return OCRDMA_QPS_ERR;
	case IBV_QPS_UNKNOWN:
		break;
	default:
		break;
	};
	return OCRDMA_QPS_ERR;
}

static int ocrdma_is_qp_in_sq_flushlist(struct ocrdma_cq *cq,
					struct ocrdma_qp *qp)
{
	struct ocrdma_qp *list_qp;
	struct ocrdma_qp *list_qp_tmp;
	int found = 0;
	list_for_each_safe(&cq->sq_head, list_qp, list_qp_tmp, sq_entry) {
		if (qp == list_qp) {
			found = 1;
			break;
		}
	}
	return found;
}

static int ocrdma_is_qp_in_rq_flushlist(struct ocrdma_cq *cq,
					struct ocrdma_qp *qp)
{
	struct ocrdma_qp *list_qp;
	struct ocrdma_qp *list_qp_tmp;
	int found = 0;
	list_for_each_safe(&cq->rq_head, list_qp, list_qp_tmp, rq_entry) {
		if (qp == list_qp) {
			found = 1;
			break;
		}
	}
	return found;
}

static void ocrdma_init_hwq_ptr(struct ocrdma_qp *qp)
{
	qp->sq.head = qp->sq.tail = 0;
	qp->rq.head = qp->rq.tail = 0;
	qp->dpp_q.head = qp->dpp_q.tail = 0;
	qp->dpp_q.free_cnt = qp->dpp_q.max_cnt;
}

static void ocrdma_del_flush_qp(struct ocrdma_qp *qp)
{
	int found = 0;
	struct ocrdma_device *dev = qp->dev;
	/* sync with any active CQ poll */

	pthread_spin_lock(&dev->flush_q_lock);
	found = ocrdma_is_qp_in_sq_flushlist(qp->sq_cq, qp);
	if (found)
		list_del(&qp->sq_entry);
	if (!qp->srq) {
		found = ocrdma_is_qp_in_rq_flushlist(qp->rq_cq, qp);
		if (found)
			list_del(&qp->rq_entry);
	}
	pthread_spin_unlock(&dev->flush_q_lock);
}

static void ocrdma_flush_qp(struct ocrdma_qp *qp)
{
	int found;

	pthread_spin_lock(&qp->dev->flush_q_lock);
	found = ocrdma_is_qp_in_sq_flushlist(qp->sq_cq, qp);
	if (!found)
		list_add_tail(&qp->sq_cq->sq_head, &qp->sq_entry);
	if (!qp->srq) {
		found = ocrdma_is_qp_in_rq_flushlist(qp->rq_cq, qp);
		if (!found)
			list_add_tail(&qp->rq_cq->rq_head, &qp->rq_entry);
	}
	pthread_spin_unlock(&qp->dev->flush_q_lock);
}

static int ocrdma_qp_state_machine(struct ocrdma_qp *qp,
				   enum ibv_qp_state new_ib_state)
{
	int status = 0;
	enum ocrdma_qp_state new_state;
	new_state = get_ocrdma_qp_state(new_ib_state);

	pthread_spin_lock(&qp->q_lock);

	if (new_state == qp->state) {
		pthread_spin_unlock(&qp->q_lock);
		return 1;
	}

	switch (qp->state) {
	case OCRDMA_QPS_RST:
		switch (new_state) {
		case OCRDMA_QPS_RST:
			break;
		case OCRDMA_QPS_INIT:
			/* init pointers to place wqe/rqe at start of hw q */
			ocrdma_init_hwq_ptr(qp);
			/* detach qp from the CQ flush list */
			ocrdma_del_flush_qp(qp);
			break;
		default:
			status = EINVAL;
			break;
		};
		break;
	case OCRDMA_QPS_INIT:
		/* qps: INIT->XXX */
		switch (new_state) {
		case OCRDMA_QPS_INIT:
			break;
		case OCRDMA_QPS_RTR:
			break;
		case OCRDMA_QPS_ERR:
			ocrdma_flush_qp(qp);
			break;
		default:
			/* invalid state change. */
			status = EINVAL;
			break;
		};
		break;
	case OCRDMA_QPS_RTR:
		/* qps: RTS->XXX */
		switch (new_state) {
		case OCRDMA_QPS_RTS:
			break;
		case OCRDMA_QPS_ERR:
			ocrdma_flush_qp(qp);
			break;
		default:
			/* invalid state change. */
			status = EINVAL;
			break;
		};
		break;
	case OCRDMA_QPS_RTS:
		/* qps: RTS->XXX */
		switch (new_state) {
		case OCRDMA_QPS_SQD:
		case OCRDMA_QPS_SQE:
			break;
		case OCRDMA_QPS_ERR:
			ocrdma_flush_qp(qp);
			break;
		default:
			/* invalid state change. */
			status = EINVAL;
			break;
		};
		break;
	case OCRDMA_QPS_SQD:
		/* qps: SQD->XXX */
		switch (new_state) {
		case OCRDMA_QPS_RTS:
		case OCRDMA_QPS_SQE:
		case OCRDMA_QPS_ERR:
			break;
		default:
			/* invalid state change. */
			status = EINVAL;
			break;
		};
		break;
	case OCRDMA_QPS_SQE:
		switch (new_state) {
		case OCRDMA_QPS_RTS:
		case OCRDMA_QPS_ERR:
			break;
		default:
			/* invalid state change. */
			status = EINVAL;
			break;
		};
		break;
	case OCRDMA_QPS_ERR:
		/* qps: ERR->XXX */
		switch (new_state) {
		case OCRDMA_QPS_RST:
			break;
		default:
			status = EINVAL;
			break;
		};
		break;
	default:
		status = EINVAL;
		break;
	};
	if (!status)
		qp->state = new_state;

	pthread_spin_unlock(&qp->q_lock);
	return status;
}

/*
 * ocrdma_modify_qp
 */
int ocrdma_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
		     int attr_mask)
{
	struct ibv_modify_qp cmd = {};
	struct ocrdma_qp *qp = get_ocrdma_qp(ibqp);
	int status;

	status = ibv_cmd_modify_qp(ibqp, attr, attr_mask, &cmd, sizeof cmd);
	if ((!status) && (attr_mask & IBV_QP_STATE))
		ocrdma_qp_state_machine(qp, attr->qp_state);
	return status;
}

/*
 * ocrdma_query_qp
 */
int ocrdma_query_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
		    int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;
	struct ocrdma_qp *qp = get_ocrdma_qp(ibqp);
	int status;

	status = ibv_cmd_query_qp(ibqp, attr, attr_mask,
				  init_attr, &cmd, sizeof(cmd));

	if (!status)
		ocrdma_qp_state_machine(qp, attr->qp_state);

	return status;
}

static void ocrdma_srq_toggle_bit(struct ocrdma_srq *srq, int idx)
{
	int i = idx / 32;
	unsigned int mask = (1 << (idx % 32));

	if (srq->idx_bit_fields[i] & mask) {
		srq->idx_bit_fields[i] &= ~mask;
	} else {
		srq->idx_bit_fields[i] |= mask;
	}
}

static int ocrdma_srq_get_idx(struct ocrdma_srq *srq)
{
	int row = 0;
	int indx = 0;

	for (row = 0; row < srq->bit_fields_len; row++) {
		if (srq->idx_bit_fields[row]) {
			indx = ffs(srq->idx_bit_fields[row]);
			indx = (row * 32) + (indx - 1);
			if (indx >= srq->rq.max_cnt)
				assert(0);
			ocrdma_srq_toggle_bit(srq, indx);
			break;
		}
	}
	if (row == srq->bit_fields_len)
		assert(0);
	return indx + 1; /* Use the index from 1 */
}

static int ocrdma_dppq_credits(struct ocrdma_qp_hwq_info *q)
{
	return ((q->max_wqe_idx - q->head) + q->tail) % q->free_cnt;
}

static int ocrdma_hwq_free_cnt(struct ocrdma_qp_hwq_info *q)
{
	return ((q->max_wqe_idx - q->head) + q->tail) % q->max_cnt;
}

static int is_hw_sq_empty(struct ocrdma_qp *qp)
{
	return ((qp->sq.tail == qp->sq.head) ? 1 : 0);
}

static inline int is_hw_rq_empty(struct ocrdma_qp *qp)
{
	return ((qp->rq.head == qp->rq.tail) ? 1 : 0);
}

static inline void *ocrdma_hwq_head(struct ocrdma_qp_hwq_info *q)
{
	return q->va + (q->head * q->entry_size);
}

/*static inline void *ocrdma_wq_tail(struct ocrdma_qp_hwq_info *q)
{
	return q->va + (q->tail * q->entry_size);
}
*/

static inline void *ocrdma_hwq_head_from_idx(struct ocrdma_qp_hwq_info *q,
					     uint32_t idx)
{
	return q->va + (idx * q->entry_size);
}

static void ocrdma_hwq_inc_head(struct ocrdma_qp_hwq_info *q)
{
	q->head = (q->head + 1) & q->max_wqe_idx;
}

static void ocrdma_hwq_inc_tail(struct ocrdma_qp_hwq_info *q)
{
	q->tail = (q->tail + 1) & q->max_wqe_idx;
}

static inline void ocrdma_hwq_inc_tail_by_idx(struct ocrdma_qp_hwq_info *q,
					      int idx)
{
	q->tail = (idx + 1) & q->max_wqe_idx;
}

static int is_cqe_valid(struct ocrdma_cq *cq, struct ocrdma_cqe *cqe)
{
	int cqe_valid;
	cqe_valid = le32toh(cqe->flags_status_srcqpn) & OCRDMA_CQE_VALID;
	return (cqe_valid == cq->phase);
}

static int is_cqe_for_sq(struct ocrdma_cqe *cqe)
{
	return (le32toh(cqe->flags_status_srcqpn) &
		OCRDMA_CQE_QTYPE) ? 0 : 1;
}

static int is_cqe_imm(struct ocrdma_cqe *cqe)
{
	return (le32toh(cqe->flags_status_srcqpn) &
		OCRDMA_CQE_IMM) ? 1 : 0;
}

static int is_cqe_wr_imm(struct ocrdma_cqe *cqe)
{
	return (le32toh(cqe->flags_status_srcqpn) &
		OCRDMA_CQE_WRITE_IMM) ? 1 : 0;
}

static inline void ocrdma_srq_inc_tail(struct ocrdma_qp *qp,
				       struct ocrdma_cqe *cqe)
{
	int wqe_idx;

	wqe_idx = (le32toh(cqe->rq.buftag_qpn) >>
	    OCRDMA_CQE_BUFTAG_SHIFT) & qp->srq->rq.max_wqe_idx;

	if (wqe_idx < 1)
		assert(0);

	pthread_spin_lock(&qp->srq->q_lock);
	ocrdma_hwq_inc_tail(&qp->srq->rq);
	ocrdma_srq_toggle_bit(qp->srq, wqe_idx - 1);
	pthread_spin_unlock(&qp->srq->q_lock);
}

static void ocrdma_discard_cqes(struct ocrdma_qp *qp, struct ocrdma_cq *cq)
{
	int discard_cnt = 0;
	uint32_t cur_getp, stop_getp;
	struct ocrdma_cqe *cqe;
	uint32_t qpn = 0;
	int wqe_idx;

	pthread_spin_lock(&cq->cq_lock);

	/* traverse through the CQEs in the hw CQ,
	 * find the matching CQE for a given qp,
	 * mark the matching one discarded=1.
	 * discard the cqe.
	 * ring the doorbell in the poll_cq() as
	 * we don't complete out of order cqe.
	 */
	cur_getp = cq->getp;
	/* find up to when do we reap the cq.*/
	stop_getp = cur_getp;
	do {
		if (is_hw_sq_empty(qp) && (!qp->srq && is_hw_rq_empty(qp)))
			break;

		cqe = cq->va + cur_getp;
		/* if (a) no valid cqe, or (b) done reading full hw cq, or
		 *    (c) qp_xq becomes empty.
		 * then exit
		 */
		qpn = le32toh(cqe->cmn.qpn) & OCRDMA_CQE_QPN_MASK;
		/* if previously discarded cqe found, skip that too.
		 * check for matching qp
		 */
		if ((qpn == 0) || (qpn != qp->id))
			goto skip_cqe;

		/* mark cqe discarded so that it is not picked up later
		 * in the poll_cq().
		 */
		if (is_cqe_for_sq(cqe)) {
			wqe_idx = (le32toh(cqe->wq.wqeidx) &
			    OCRDMA_CQE_WQEIDX_MASK) & qp->sq.max_wqe_idx;
			ocrdma_hwq_inc_tail_by_idx(&qp->sq, wqe_idx);
		} else {
			if (qp->srq)
				ocrdma_srq_inc_tail(qp, cqe);
			else
				ocrdma_hwq_inc_tail(&qp->rq);
		}

		discard_cnt += 1;
		/* discard by marking qp_id = 0 */
		cqe->cmn.qpn = 0;
skip_cqe:
		cur_getp = (cur_getp + 1) % cq->max_hw_cqe;

	} while (cur_getp != stop_getp);
	pthread_spin_unlock(&cq->cq_lock);
}

/*
 * ocrdma_destroy_qp
 */
int ocrdma_destroy_qp(struct ibv_qp *ibqp)
{
	int status = 0;
	struct ocrdma_qp *qp;
	struct ocrdma_device *dev;

	qp = get_ocrdma_qp(ibqp);
	dev = qp->dev;
	/*
	 * acquire CQ lock while destroy is in progress, in order to
	 * protect against proessing in-flight CQEs for this QP.
	 */
	pthread_spin_lock(&qp->sq_cq->cq_lock);

	if (qp->rq_cq && (qp->rq_cq != qp->sq_cq))
		pthread_spin_lock(&qp->rq_cq->cq_lock);

	_ocrdma_del_qpn_map(qp->dev, qp);

	if (qp->rq_cq && (qp->rq_cq != qp->sq_cq))
		pthread_spin_unlock(&qp->rq_cq->cq_lock);

	pthread_spin_unlock(&qp->sq_cq->cq_lock);

	if (qp->db_va)
		munmap((void *)qp->db_va, qp->db_size);
	if (qp->rq.va)
		munmap(qp->rq.va, qp->rq.len);
	if (qp->sq.va)
		munmap(qp->sq.va, qp->sq.len);

	/* ensure that CQEs for newly created QP (whose id may be same with
	 * one which just getting destroyed are same), don't get
	 * discarded until the old CQEs are discarded.
	 */
	pthread_mutex_lock(&dev->dev_lock);
	status = ibv_cmd_destroy_qp(ibqp);

	ocrdma_discard_cqes(qp, qp->sq_cq);
	ocrdma_discard_cqes(qp, qp->rq_cq);
	pthread_mutex_unlock(&dev->dev_lock);

	ocrdma_del_flush_qp(qp);

	pthread_spin_destroy(&qp->q_lock);
	if (qp->rqe_wr_id_tbl)
		free(qp->rqe_wr_id_tbl);
	if (qp->wqe_wr_id_tbl)
		free(qp->wqe_wr_id_tbl);
	if (qp->dpp_cq)
		ocrdma_destroy_cq(&qp->dpp_cq->ibv_cq);
	free(qp);

	return status;
}

static void ocrdma_ring_sq_db(struct ocrdma_qp *qp)
{
	__le32 db_val = htole32((qp->sq.dbid | (1 << 16)));

	udma_to_device_barrier();
	*(__le32 *) (((uint8_t *) qp->db_sq_va)) = db_val;
}

static void ocrdma_ring_rq_db(struct ocrdma_qp *qp)
{
	__le32 db_val = htole32((qp->rq.dbid | (1 << qp->db_shift)));

	udma_to_device_barrier();
	*(__le32 *) ((uint8_t *) qp->db_rq_va) = db_val;
}

static void ocrdma_ring_srq_db(struct ocrdma_srq *srq)
{
	__le32 db_val = htole32(srq->rq.dbid | (1 << srq->db_shift));

	udma_to_device_barrier();
	*(__le32 *) (srq->db_va) = db_val;
}

static void ocrdma_ring_cq_db(struct ocrdma_cq *cq, uint32_t armed,
			      int solicited, uint32_t num_cqe)
{
	uint32_t val;

	val = cq->cq_dbid & OCRDMA_DB_CQ_RING_ID_MASK;
	val |= ((cq->cq_dbid & OCRDMA_DB_CQ_RING_ID_EXT_MASK) <<
		OCRDMA_DB_CQ_RING_ID_EXT_MASK_SHIFT);

	if (armed)
		val |= (1 << OCRDMA_DB_CQ_REARM_SHIFT);
	if (solicited)
		val |= (1 << OCRDMA_DB_CQ_SOLICIT_SHIFT);
	val |= (num_cqe << OCRDMA_DB_CQ_NUM_POPPED_SHIFT);

	udma_to_device_barrier();
	*(__le32 *) ((uint8_t *) (cq->db_va) + OCRDMA_DB_CQ_OFFSET) =
	    htole32(val);
}

static void ocrdma_build_ud_hdr(struct ocrdma_qp *qp,
				struct ocrdma_hdr_wqe *hdr,
				struct ibv_send_wr *wr)
{
	struct ocrdma_ewqe_ud_hdr *ud_hdr =
	    (struct ocrdma_ewqe_ud_hdr *)(hdr + 1);
	struct ocrdma_ah *ah = get_ocrdma_ah(wr->wr.ud.ah);

	ud_hdr->rsvd_dest_qpn = wr->wr.ud.remote_qpn;
	ud_hdr->qkey = wr->wr.ud.remote_qkey;
	ud_hdr->rsvd_ahid = ah->id;
	if (ah->isvlan)
		hdr->cw |= (OCRDMA_FLAG_AH_VLAN_PR <<
			    OCRDMA_WQE_FLAGS_SHIFT);
	ud_hdr->hdr_type = ah->hdr_type;
}

static void ocrdma_build_sges(struct ocrdma_hdr_wqe *hdr,
			      struct ocrdma_sge *sge, int num_sge,
			      struct ibv_sge *sg_list)
{
	int i;
	for (i = 0; i < num_sge; i++) {
		sge[i].lrkey = sg_list[i].lkey;
		sge[i].addr_lo = sg_list[i].addr;
		sge[i].addr_hi = sg_list[i].addr >> 32;
		sge[i].len = sg_list[i].length;
		hdr->total_len += sg_list[i].length;
	}
	if (num_sge == 0)
		memset(sge, 0, sizeof(*sge));
}


static inline uint32_t ocrdma_sglist_len(struct ibv_sge *sg_list, int num_sge)
{
	uint32_t total_len = 0, i;

	for (i = 0; i < num_sge; i++)
		total_len += sg_list[i].length;
	return total_len;
}

static inline int ocrdma_build_inline_sges(struct ocrdma_qp *qp,
					   struct ocrdma_hdr_wqe *hdr,
					   struct ocrdma_sge *sge,
					   struct ibv_send_wr *wr,
					   uint32_t wqe_size)
{
	int i;
	char *dpp_addr;

	if (wr->send_flags & IBV_SEND_INLINE && qp->qp_type != IBV_QPT_UD) {
		hdr->total_len = ocrdma_sglist_len(wr->sg_list, wr->num_sge);
		if (hdr->total_len > qp->max_inline_data) {
			ocrdma_err
			("%s() supported_len=0x%x, unsupported len req=0x%x\n",
			__func__, qp->max_inline_data, hdr->total_len);
			return EINVAL;
		}

		dpp_addr = (char *)sge;
		for (i = 0; i < wr->num_sge; i++) {
			memcpy(dpp_addr,
				(void *)(unsigned long)wr->sg_list[i].addr,
				wr->sg_list[i].length);
			dpp_addr += wr->sg_list[i].length;
		}

		wqe_size += ROUND_UP_X(hdr->total_len, OCRDMA_WQE_ALIGN_BYTES);
		if (0 == hdr->total_len)
			wqe_size += sizeof(struct ocrdma_sge);
		hdr->cw |= (OCRDMA_TYPE_INLINE << OCRDMA_WQE_TYPE_SHIFT);
	} else {
		ocrdma_build_sges(hdr, sge, wr->num_sge, wr->sg_list);
		if (wr->num_sge)
			wqe_size += (wr->num_sge * sizeof(struct ocrdma_sge));
		else
			wqe_size += sizeof(struct ocrdma_sge);
		hdr->cw |= (OCRDMA_TYPE_LKEY << OCRDMA_WQE_TYPE_SHIFT);
	}
	hdr->cw |= ((wqe_size / OCRDMA_WQE_STRIDE) << OCRDMA_WQE_SIZE_SHIFT);
	return 0;
}

static int ocrdma_build_send(struct ocrdma_qp *qp, struct ocrdma_hdr_wqe *hdr,
			     struct ibv_send_wr *wr)
{
	int status;
	struct ocrdma_sge *sge;
	uint32_t wqe_size = sizeof(*hdr);

	if (qp->qp_type == IBV_QPT_UD) {
		wqe_size += sizeof(struct ocrdma_ewqe_ud_hdr);
		ocrdma_build_ud_hdr(qp, hdr, wr);
		sge = (struct ocrdma_sge *)(hdr + 2);
	} else
		sge = (struct ocrdma_sge *)(hdr + 1);

	status = ocrdma_build_inline_sges(qp, hdr, sge, wr, wqe_size);

	return status;
}

static int ocrdma_build_write(struct ocrdma_qp *qp, struct ocrdma_hdr_wqe *hdr,
			      struct ibv_send_wr *wr)
{
	int status;
	struct ocrdma_sge *ext_rw = (struct ocrdma_sge *)(hdr + 1);
	struct ocrdma_sge *sge = ext_rw + 1;
	uint32_t wqe_size = sizeof(*hdr) + sizeof(*ext_rw);

	status = ocrdma_build_inline_sges(qp, hdr, sge, wr, wqe_size);
	if (status)
		return status;

	ext_rw->addr_lo = wr->wr.rdma.remote_addr;
	ext_rw->addr_hi = (wr->wr.rdma.remote_addr >> 32);
	ext_rw->lrkey = wr->wr.rdma.rkey;
	ext_rw->len = hdr->total_len;

	return 0;
}

static void ocrdma_build_read(struct ocrdma_qp *qp, struct ocrdma_hdr_wqe *hdr,
			      struct ibv_send_wr *wr)
{
	struct ocrdma_sge *ext_rw = (struct ocrdma_sge *)(hdr + 1);
	struct ocrdma_sge *sge = ext_rw + 1;
	uint32_t wqe_size = ((wr->num_sge + 1) * sizeof(*sge)) + sizeof(*hdr);

	hdr->cw |= (OCRDMA_TYPE_LKEY << OCRDMA_WQE_TYPE_SHIFT);
	hdr->cw |= ((wqe_size / OCRDMA_WQE_STRIDE) << OCRDMA_WQE_SIZE_SHIFT);
	hdr->cw |= (OCRDMA_READ << OCRDMA_WQE_OPCODE_SHIFT);

	ocrdma_build_sges(hdr, sge, wr->num_sge, wr->sg_list);

	ext_rw->addr_lo = wr->wr.rdma.remote_addr;
	ext_rw->addr_hi = (wr->wr.rdma.remote_addr >> 32);
	ext_rw->lrkey = wr->wr.rdma.rkey;
	ext_rw->len = hdr->total_len;

}

/* Dpp cq is single entry cq, we just need to read
 * wqe index from first 16 bits at 0th cqe index.
 */
static void ocrdma_poll_dpp_cq(struct ocrdma_qp *qp)
{
	struct ocrdma_cq *cq = qp->dpp_cq;
	struct ocrdma_dpp_cqe *cqe;
	int idx = 0;
	cqe = ((struct ocrdma_dpp_cqe *)cq->va);
	idx = cqe->wqe_idx_valid & OCRDMA_DPP_WQE_INDEX_MASK;

	if (idx != qp->dpp_prev_indx) {
		ocrdma_hwq_inc_tail_by_idx(&qp->dpp_q, idx);
		qp->dpp_prev_indx = idx;
	}
}

static uint32_t ocrdma_get_hdr_len(struct ocrdma_qp *qp,
				   struct ocrdma_hdr_wqe *hdr)
{
	uint32_t hdr_sz = sizeof(*hdr);
	if (qp->qp_type == IBV_QPT_UD)
		hdr_sz += sizeof(struct ocrdma_ewqe_ud_hdr);
	if (hdr->cw & (OCRDMA_WRITE << OCRDMA_WQE_OPCODE_SHIFT))
		hdr_sz += sizeof(struct ocrdma_sge);
	return hdr_sz / sizeof(uint32_t);
}

static void ocrdma_build_dpp_wqe(void *va, struct ocrdma_hdr_wqe *wqe,
				 uint32_t hdr_len)
{
	uint32_t pyld_len = (wqe->cw >> OCRDMA_WQE_SIZE_SHIFT) * 2;
	uint32_t i = 0;

	mmio_wc_start();

	/* convert WQE header to LE format */
	for (; i < hdr_len; i++)
		*((__le32 *) va + i) =
			htole32(*((uint32_t *) wqe + i));
	/* Convertion of data is done in HW */
	for (; i < pyld_len; i++)
		*((uint32_t *) va + i) = (*((uint32_t *) wqe + i));

	mmio_flush_writes();
}

static void ocrdma_post_dpp_wqe(struct ocrdma_qp *qp,
				struct ocrdma_hdr_wqe *hdr)
{
	if (qp->dpp_cq && ocrdma_dppq_credits(&qp->dpp_q) == 0)
		ocrdma_poll_dpp_cq(qp);
	if (!qp->dpp_cq || ocrdma_dppq_credits(&qp->dpp_q)) {
		ocrdma_build_dpp_wqe(qp->dpp_q.va, hdr,
				     ocrdma_get_hdr_len(qp, hdr));
		qp->wqe_wr_id_tbl[qp->sq.head].dpp_wqe = 1;
		qp->wqe_wr_id_tbl[qp->sq.head].dpp_wqe_idx = qp->dpp_q.head;
		/* if dpp cq is not enabled, we can post
		 * wqe as soon as we receive and adapter
		 * takes care of flow control.
		 */
		if (qp->dpp_cq)
			ocrdma_hwq_inc_head(&qp->dpp_q);
	} else
		qp->wqe_wr_id_tbl[qp->sq.head].dpp_wqe = 0;
}

/*
 * ocrdma_post_send
 */
int ocrdma_post_send(struct ibv_qp *ib_qp, struct ibv_send_wr *wr,
		     struct ibv_send_wr **bad_wr)
{
	int status = 0;
	struct ocrdma_qp *qp;
	struct ocrdma_hdr_wqe *hdr;

	qp = get_ocrdma_qp(ib_qp);

	pthread_spin_lock(&qp->q_lock);
	if (qp->state != OCRDMA_QPS_RTS && qp->state != OCRDMA_QPS_SQD) {
		pthread_spin_unlock(&qp->q_lock);
		*bad_wr = wr;
		return EINVAL;
	}

	while (wr) {

		if (qp->qp_type == IBV_QPT_UD && (wr->opcode != IBV_WR_SEND &&
		    wr->opcode != IBV_WR_SEND_WITH_IMM)) {
			*bad_wr = wr;
			status = EINVAL;
			break;
		}

		if (ocrdma_hwq_free_cnt(&qp->sq) == 0 ||
		    wr->num_sge > qp->sq.max_sges) {
			*bad_wr = wr;
			status = ENOMEM;
			break;
		}
		hdr = ocrdma_hwq_head(&qp->sq);
		hdr->cw = 0;
		hdr->total_len = 0;
		if (wr->send_flags & IBV_SEND_SIGNALED || qp->signaled)
			hdr->cw = (OCRDMA_FLAG_SIG << OCRDMA_WQE_FLAGS_SHIFT);
		if (wr->send_flags & IBV_SEND_FENCE)
			hdr->cw |=
			    (OCRDMA_FLAG_FENCE_L << OCRDMA_WQE_FLAGS_SHIFT);
		if (wr->send_flags & IBV_SEND_SOLICITED)
			hdr->cw |=
			    (OCRDMA_FLAG_SOLICIT << OCRDMA_WQE_FLAGS_SHIFT);

		qp->wqe_wr_id_tbl[qp->sq.head].wrid = wr->wr_id;
		switch (wr->opcode) {
		case IBV_WR_SEND_WITH_IMM:
			hdr->cw |= (OCRDMA_FLAG_IMM << OCRDMA_WQE_FLAGS_SHIFT);
			hdr->immdt = be32toh(wr->imm_data);
			SWITCH_FALLTHROUGH;
		case IBV_WR_SEND:
			hdr->cw |= (OCRDMA_SEND << OCRDMA_WQE_OPCODE_SHIFT);
			status = ocrdma_build_send(qp, hdr, wr);
			break;
		case IBV_WR_RDMA_WRITE_WITH_IMM:
			hdr->cw |= (OCRDMA_FLAG_IMM << OCRDMA_WQE_FLAGS_SHIFT);
			hdr->immdt = be32toh(wr->imm_data);
			SWITCH_FALLTHROUGH;
		case IBV_WR_RDMA_WRITE:
			hdr->cw |= (OCRDMA_WRITE << OCRDMA_WQE_OPCODE_SHIFT);
			status = ocrdma_build_write(qp, hdr, wr);
			break;
		case IBV_WR_RDMA_READ:
			ocrdma_build_read(qp, hdr, wr);
			break;
		default:
			status = EINVAL;
			break;
		}
		if (status) {
			*bad_wr = wr;
			break;
		}
		if (wr->send_flags & IBV_SEND_SIGNALED || qp->signaled)
			qp->wqe_wr_id_tbl[qp->sq.head].signaled = 1;
		else
			qp->wqe_wr_id_tbl[qp->sq.head].signaled = 0;

		if (qp->dpp_enabled && (wr->send_flags & IBV_SEND_INLINE))
			ocrdma_post_dpp_wqe(qp, hdr);

		ocrdma_swap_cpu_to_le(hdr, ((hdr->cw >> OCRDMA_WQE_SIZE_SHIFT) &
				      OCRDMA_WQE_SIZE_MASK) *
				      OCRDMA_WQE_STRIDE);

		ocrdma_ring_sq_db(qp);

		/* update pointer, counter for next wr */
		ocrdma_hwq_inc_head(&qp->sq);
		wr = wr->next;
	}
	pthread_spin_unlock(&qp->q_lock);

	return status;
}

static void ocrdma_build_rqe(struct ocrdma_hdr_wqe *rqe, struct ibv_recv_wr *wr,
			     uint16_t tag)
{
	struct ocrdma_sge *sge;
	uint32_t wqe_size;

	if (wr->num_sge)
		wqe_size = (wr->num_sge * sizeof(*sge)) + sizeof(*rqe);
	else
		wqe_size = sizeof(*sge) + sizeof(*rqe);

	rqe->cw = ((wqe_size / OCRDMA_WQE_STRIDE) << OCRDMA_WQE_SIZE_SHIFT);
	rqe->cw |= (OCRDMA_FLAG_SIG << OCRDMA_WQE_FLAGS_SHIFT);
	rqe->cw |= (OCRDMA_TYPE_LKEY << OCRDMA_WQE_TYPE_SHIFT);
	rqe->total_len = 0;
	rqe->rsvd_tag = tag;
	sge = (struct ocrdma_sge *)(rqe + 1);
	ocrdma_build_sges(rqe, sge, wr->num_sge, wr->sg_list);
	ocrdma_swap_cpu_to_le(rqe, wqe_size);
}

/*
 * ocrdma_post_recv
 */
int ocrdma_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		     struct ibv_recv_wr **bad_wr)
{
	int status = 0;
	struct ocrdma_qp *qp;
	struct ocrdma_hdr_wqe *rqe;

	qp = get_ocrdma_qp(ibqp);

	pthread_spin_lock(&qp->q_lock);
	if (qp->state == OCRDMA_QPS_RST || qp->state == OCRDMA_QPS_ERR) {
		pthread_spin_unlock(&qp->q_lock);
		*bad_wr = wr;
		return EINVAL;
	}

	while (wr) {
		if (ocrdma_hwq_free_cnt(&qp->rq) == 0 ||
		    wr->num_sge > qp->rq.max_sges) {
			status = ENOMEM;
			*bad_wr = wr;
			break;
		}
		rqe = ocrdma_hwq_head(&qp->rq);
		ocrdma_build_rqe(rqe, wr, 0);
		qp->rqe_wr_id_tbl[qp->rq.head] = wr->wr_id;
		ocrdma_ring_rq_db(qp);

		/* update pointer, counter for next wr */
		ocrdma_hwq_inc_head(&qp->rq);
		wr = wr->next;
	}
	pthread_spin_unlock(&qp->q_lock);

	return status;
}

static enum ibv_wc_status ocrdma_to_ibwc_err(uint16_t status)
{
	enum ibv_wc_status ibwc_status = IBV_WC_GENERAL_ERR;
	switch (status) {
	case OCRDMA_CQE_GENERAL_ERR:
		ibwc_status = IBV_WC_GENERAL_ERR;
		break;
	case OCRDMA_CQE_LOC_LEN_ERR:
		ibwc_status = IBV_WC_LOC_LEN_ERR;
		break;
	case OCRDMA_CQE_LOC_QP_OP_ERR:
		ibwc_status = IBV_WC_LOC_QP_OP_ERR;
		break;
	case OCRDMA_CQE_LOC_EEC_OP_ERR:
		ibwc_status = IBV_WC_LOC_EEC_OP_ERR;
		break;
	case OCRDMA_CQE_LOC_PROT_ERR:
		ibwc_status = IBV_WC_LOC_PROT_ERR;
		break;
	case OCRDMA_CQE_WR_FLUSH_ERR:
		ibwc_status = IBV_WC_WR_FLUSH_ERR;
		break;
	case OCRDMA_CQE_BAD_RESP_ERR:
		ibwc_status = IBV_WC_BAD_RESP_ERR;
		break;
	case OCRDMA_CQE_LOC_ACCESS_ERR:
		ibwc_status = IBV_WC_LOC_ACCESS_ERR;
		break;
	case OCRDMA_CQE_REM_INV_REQ_ERR:
		ibwc_status = IBV_WC_REM_INV_REQ_ERR;
		break;
	case OCRDMA_CQE_REM_ACCESS_ERR:
		ibwc_status = IBV_WC_REM_ACCESS_ERR;
		break;
	case OCRDMA_CQE_REM_OP_ERR:
		ibwc_status = IBV_WC_REM_OP_ERR;
		break;
	case OCRDMA_CQE_RETRY_EXC_ERR:
		ibwc_status = IBV_WC_RETRY_EXC_ERR;
		break;
	case OCRDMA_CQE_RNR_RETRY_EXC_ERR:
		ibwc_status = IBV_WC_RNR_RETRY_EXC_ERR;
		break;
	case OCRDMA_CQE_LOC_RDD_VIOL_ERR:
		ibwc_status = IBV_WC_LOC_RDD_VIOL_ERR;
		break;
	case OCRDMA_CQE_REM_INV_RD_REQ_ERR:
		ibwc_status = IBV_WC_REM_INV_RD_REQ_ERR;
		break;
	case OCRDMA_CQE_REM_ABORT_ERR:
		ibwc_status = IBV_WC_REM_ABORT_ERR;
		break;
	case OCRDMA_CQE_INV_EECN_ERR:
		ibwc_status = IBV_WC_INV_EECN_ERR;
		break;
	case OCRDMA_CQE_INV_EEC_STATE_ERR:
		ibwc_status = IBV_WC_INV_EEC_STATE_ERR;
		break;
	case OCRDMA_CQE_FATAL_ERR:
		ibwc_status = IBV_WC_FATAL_ERR;
		break;
	case OCRDMA_CQE_RESP_TIMEOUT_ERR:
		ibwc_status = IBV_WC_RESP_TIMEOUT_ERR;
		break;
	default:
		ibwc_status = IBV_WC_GENERAL_ERR;
		break;
	};
	return ibwc_status;
}

static void ocrdma_update_wc(struct ocrdma_qp *qp, struct ibv_wc *ibwc,
			     uint32_t wqe_idx)
{
	struct ocrdma_hdr_wqe_le *hdr;
	struct ocrdma_sge *rw;
	int opcode;

	hdr = ocrdma_hwq_head_from_idx(&qp->sq, wqe_idx);

	ibwc->wr_id = qp->wqe_wr_id_tbl[wqe_idx].wrid;

	/* Undo the hdr->cw swap */
	opcode = le32toh(hdr->cw) & OCRDMA_WQE_OPCODE_MASK;
	switch (opcode) {
	case OCRDMA_WRITE:
		ibwc->opcode = IBV_WC_RDMA_WRITE;
		break;
	case OCRDMA_READ:
		rw = (struct ocrdma_sge *)(hdr + 1);
		ibwc->opcode = IBV_WC_RDMA_READ;
		ibwc->byte_len = rw->len;
		break;
	case OCRDMA_SEND:
		ibwc->opcode = IBV_WC_SEND;
		break;
	default:
		ibwc->status = IBV_WC_GENERAL_ERR;
		ocrdma_err("%s() invalid opcode received = 0x%x\n",
			   __func__, le32toh(hdr->cw) & OCRDMA_WQE_OPCODE_MASK);
		break;
	};
}

static void ocrdma_set_cqe_status_flushed(struct ocrdma_qp *qp,
					  struct ocrdma_cqe *cqe)
{
	if (is_cqe_for_sq(cqe)) {
		cqe->flags_status_srcqpn =
		    htole32(le32toh(cqe->flags_status_srcqpn)
				     & ~OCRDMA_CQE_STATUS_MASK);
		cqe->flags_status_srcqpn =
		    htole32(le32toh(cqe->flags_status_srcqpn)
				     | (OCRDMA_CQE_WR_FLUSH_ERR <<
					OCRDMA_CQE_STATUS_SHIFT));
	} else {
		if (qp->qp_type == IBV_QPT_UD) {
			cqe->flags_status_srcqpn =
			    htole32(le32toh
					     (cqe->flags_status_srcqpn) &
					     ~OCRDMA_CQE_UD_STATUS_MASK);
			cqe->flags_status_srcqpn =
			    htole32(le32toh
					     (cqe->flags_status_srcqpn) |
					     (OCRDMA_CQE_WR_FLUSH_ERR <<
					      OCRDMA_CQE_UD_STATUS_SHIFT));
		} else {
			cqe->flags_status_srcqpn =
			    htole32(le32toh
					     (cqe->flags_status_srcqpn) &
					     ~OCRDMA_CQE_STATUS_MASK);
			cqe->flags_status_srcqpn =
			    htole32(le32toh
					     (cqe->flags_status_srcqpn) |
					     (OCRDMA_CQE_WR_FLUSH_ERR <<
					      OCRDMA_CQE_STATUS_SHIFT));
		}
	}
}

static int ocrdma_update_err_cqe(struct ibv_wc *ibwc, struct ocrdma_cqe *cqe,
				 struct ocrdma_qp *qp, int status)
{
	int expand = 0;

	ibwc->byte_len = 0;
	ibwc->qp_num = qp->id;
	ibwc->status = ocrdma_to_ibwc_err(status);

	ocrdma_flush_qp(qp);
	ocrdma_qp_state_machine(qp, IBV_QPS_ERR);

	/* if wqe/rqe pending for which cqe needs to be returned,
	 * trigger inflating it.
	 */
	if (!is_hw_rq_empty(qp) || !is_hw_sq_empty(qp)) {
		expand = 1;
		ocrdma_set_cqe_status_flushed(qp, cqe);
	}
	return expand;
}

static int ocrdma_update_err_rcqe(struct ibv_wc *ibwc, struct ocrdma_cqe *cqe,
				  struct ocrdma_qp *qp, int status)
{
	ibwc->opcode = IBV_WC_RECV;
	ibwc->wr_id = qp->rqe_wr_id_tbl[qp->rq.tail];
	ocrdma_hwq_inc_tail(&qp->rq);

	return ocrdma_update_err_cqe(ibwc, cqe, qp, status);
}

static int ocrdma_update_err_scqe(struct ibv_wc *ibwc, struct ocrdma_cqe *cqe,
				  struct ocrdma_qp *qp, int status)
{
	ocrdma_update_wc(qp, ibwc, qp->sq.tail);
	ocrdma_hwq_inc_tail(&qp->sq);

	return ocrdma_update_err_cqe(ibwc, cqe, qp, status);
}

static int ocrdma_poll_err_scqe(struct ocrdma_qp *qp,
				struct ocrdma_cqe *cqe, struct ibv_wc *ibwc,
				int *polled, int *stop)
{
	int expand;
	int status = (le32toh(cqe->flags_status_srcqpn) &
		      OCRDMA_CQE_STATUS_MASK) >> OCRDMA_CQE_STATUS_SHIFT;

	/* when hw sq is empty, but rq is not empty, so we continue
	 * to keep the cqe in order to get the cq event again.
	 */
	if (is_hw_sq_empty(qp) && !is_hw_rq_empty(qp)) {
		/* when cq for rq and sq is same, it is safe to return
		 * flush cqe for RQEs.
		 */
		if (!qp->srq && (qp->sq_cq == qp->rq_cq)) {
			*polled = 1;
			status = OCRDMA_CQE_WR_FLUSH_ERR;
			expand = ocrdma_update_err_rcqe(ibwc, cqe, qp, status);
		} else {
			*polled = 0;
			*stop = 1;
			expand = 0;
		}
	} else if (is_hw_sq_empty(qp)) {
		/* Do nothing */
		expand = 0;
		*polled = 0;
		*stop = 0;
	} else {
		*polled = 1;
		expand = ocrdma_update_err_scqe(ibwc, cqe, qp, status);
	}
	return expand;
}

static int ocrdma_poll_success_scqe(struct ocrdma_qp *qp,
				    struct ocrdma_cqe *cqe,
				    struct ibv_wc *ibwc, int *polled)
{
	int expand = 0;
	int tail = qp->sq.tail;
	uint32_t wqe_idx;

	if (!qp->wqe_wr_id_tbl[tail].signaled) {
		*polled = 0;	/* WC cannot be consumed yet */
	} else {
		ibwc->status = IBV_WC_SUCCESS;
		ibwc->wc_flags = 0;
		ibwc->qp_num = qp->id;
		ocrdma_update_wc(qp, ibwc, tail);
		*polled = 1;
	}

	wqe_idx = (le32toh(cqe->wq.wqeidx) &
	    OCRDMA_CQE_WQEIDX_MASK) & qp->sq.max_wqe_idx;
	if (tail != wqe_idx)	/* CQE cannot be consumed yet */
		expand = 1;	/* Coallesced CQE */

	ocrdma_hwq_inc_tail(&qp->sq);
	return expand;
}

static int ocrdma_poll_scqe(struct ocrdma_qp *qp, struct ocrdma_cqe *cqe,
			    struct ibv_wc *ibwc, int *polled, int *stop)
{
	int status, expand;

	status = (le32toh(cqe->flags_status_srcqpn) &
		  OCRDMA_CQE_STATUS_MASK) >> OCRDMA_CQE_STATUS_SHIFT;

	if (status == OCRDMA_CQE_SUCCESS)
		expand = ocrdma_poll_success_scqe(qp, cqe, ibwc, polled);
	else
		expand = ocrdma_poll_err_scqe(qp, cqe, ibwc, polled, stop);
	return expand;
}

static int ocrdma_update_ud_rcqe(struct ibv_wc *ibwc, struct ocrdma_cqe *cqe)
{
	int status;

	status = (le32toh(cqe->flags_status_srcqpn) &
		  OCRDMA_CQE_UD_STATUS_MASK) >> OCRDMA_CQE_UD_STATUS_SHIFT;
	ibwc->src_qp = le32toh(cqe->flags_status_srcqpn) &
	    OCRDMA_CQE_SRCQP_MASK;
	ibwc->pkey_index = le32toh(cqe->ud.rxlen_pkey) &
	    OCRDMA_CQE_PKEY_MASK;
	ibwc->wc_flags = IBV_WC_GRH;
	ibwc->byte_len = (le32toh(cqe->ud.rxlen_pkey) >>
			  OCRDMA_CQE_UD_XFER_LEN_SHIFT);
	return status;
}

static void ocrdma_update_free_srq_cqe(struct ibv_wc *ibwc,
				       struct ocrdma_cqe *cqe,
				       struct ocrdma_qp *qp)
{
	struct ocrdma_srq *srq = NULL;
	uint32_t wqe_idx;

	srq = get_ocrdma_srq(qp->ibv_qp.srq);
#if !defined(SKH_A0_WORKAROUND) /* BUG 113416 */
	wqe_idx = (le32toh(cqe->rq.buftag_qpn) >>
	    OCRDMA_CQE_BUFTAG_SHIFT) & srq->rq.max_wqe_idx;
#else
	wqe_idx = (le32toh(cqe->flags_status_srcqpn)) & 0xFFFF;
#endif
	if (wqe_idx < 1)
		assert(0);
	ibwc->wr_id = srq->rqe_wr_id_tbl[wqe_idx];

	pthread_spin_lock(&srq->q_lock);
	ocrdma_srq_toggle_bit(srq, wqe_idx - 1);
	pthread_spin_unlock(&srq->q_lock);

	ocrdma_hwq_inc_tail(&srq->rq);
}

static int ocrdma_poll_err_rcqe(struct ocrdma_qp *qp, struct ocrdma_cqe *cqe,
				struct ibv_wc *ibwc, int *polled, int *stop,
				int status)
{
	int expand;

	/* when hw_rq is empty, but wq is not empty, so continue
	 * to keep the cqe to get the cq event again.
	 */
	if (is_hw_rq_empty(qp) && !is_hw_sq_empty(qp)) {
		if (!qp->srq && (qp->sq_cq == qp->rq_cq)) {
			*polled = 1;
			status = OCRDMA_CQE_WR_FLUSH_ERR;
			expand = ocrdma_update_err_scqe(ibwc, cqe, qp, status);
		} else {
			*polled = 0;
			*stop = 1;
			expand = 0;
		}
	} else if (is_hw_rq_empty(qp)) {
		/* Do nothing */
		expand = 0;
		*polled = 0;
		*stop = 0;
	} else {
		*polled = 1;
		expand = ocrdma_update_err_rcqe(ibwc, cqe, qp, status);
	}
	return expand;
}

static void ocrdma_poll_success_rcqe(struct ocrdma_qp *qp,
				     struct ocrdma_cqe *cqe,
				     struct ibv_wc *ibwc)
{
	ibwc->opcode = IBV_WC_RECV;
	ibwc->qp_num = qp->id;
	ibwc->status = IBV_WC_SUCCESS;

	if (qp->qp_type == IBV_QPT_UD)
		ocrdma_update_ud_rcqe(ibwc, cqe);
	else
		ibwc->byte_len = le32toh(cqe->rq.rxlen);

	if (is_cqe_imm(cqe)) {
		ibwc->imm_data = htobe32(le32toh(cqe->rq.lkey_immdt));
		ibwc->wc_flags |= IBV_WC_WITH_IMM;
	} else if (is_cqe_wr_imm(cqe)) {
		ibwc->opcode = IBV_WC_RECV_RDMA_WITH_IMM;
		ibwc->imm_data = htobe32(le32toh(cqe->rq.lkey_immdt));
		ibwc->wc_flags |= IBV_WC_WITH_IMM;
	}
	if (qp->ibv_qp.srq)
		ocrdma_update_free_srq_cqe(ibwc, cqe, qp);
	else {
		ibwc->wr_id = qp->rqe_wr_id_tbl[qp->rq.tail];
		ocrdma_hwq_inc_tail(&qp->rq);
	}
}

static int ocrdma_poll_rcqe(struct ocrdma_qp *qp, struct ocrdma_cqe *cqe,
			    struct ibv_wc *ibwc, int *polled, int *stop)
{
	int status;
	int expand = 0;

	ibwc->wc_flags = 0;
	if (qp->qp_type == IBV_QPT_UD)
		status = (le32toh(cqe->flags_status_srcqpn) &
			  OCRDMA_CQE_UD_STATUS_MASK) >>
				OCRDMA_CQE_UD_STATUS_SHIFT;
	else
		status = (le32toh(cqe->flags_status_srcqpn) &
			  OCRDMA_CQE_STATUS_MASK) >> OCRDMA_CQE_STATUS_SHIFT;

	if (status == OCRDMA_CQE_SUCCESS) {
		*polled = 1;
		ocrdma_poll_success_rcqe(qp, cqe, ibwc);
	} else {
		expand = ocrdma_poll_err_rcqe(qp, cqe, ibwc, polled, stop,
					      status);
	}
	return expand;
}

static void ocrdma_change_cq_phase(struct ocrdma_cq *cq,
				   struct ocrdma_cqe *cqe, uint16_t cur_getp)
{
	if (cq->phase_change) {
		if (cur_getp == 0)
			cq->phase = (~cq->phase & OCRDMA_CQE_VALID);
	} else
		cqe->flags_status_srcqpn = 0;	/* clear valid bit */
}

static int ocrdma_poll_hwcq(struct ocrdma_cq *cq, int num_entries,
			    struct ibv_wc *ibwc)
{
	uint16_t qpn = 0;
	int i = 0;
	int expand = 0;
	int polled_hw_cqes = 0;
	struct ocrdma_qp *qp = NULL;
	struct ocrdma_device *dev = cq->dev;
	struct ocrdma_cqe *cqe;
	uint16_t cur_getp;
	int polled = 0;
	int stop = 0;

	cur_getp = cq->getp;
	while (num_entries) {
		cqe = cq->va + cur_getp;
		/* check whether valid cqe or not */
		if (!is_cqe_valid(cq, cqe))
			break;
		qpn = (le32toh(cqe->cmn.qpn) & OCRDMA_CQE_QPN_MASK);
		/* ignore discarded cqe */
		if (qpn == 0)
			goto skip_cqe;
		qp = dev->qp_tbl[qpn];
		if (qp == NULL) {
			ocrdma_err("%s() cqe for invalid qpn= 0x%x received.\n",
				   __func__, qpn);
			goto skip_cqe;
		}

		if (is_cqe_for_sq(cqe)) {
			expand = ocrdma_poll_scqe(qp, cqe, ibwc, &polled,
						  &stop);
		} else {
			expand = ocrdma_poll_rcqe(qp, cqe, ibwc, &polled,
						  &stop);
		}
		if (expand)
			goto expand_cqe;
		if (stop)
			goto stop_cqe;
		/* clear qpn to avoid duplicate processing by discard_cqe() */
		cqe->cmn.qpn = 0;
skip_cqe:
		polled_hw_cqes += 1;
		cur_getp = (cur_getp + 1) % cq->max_hw_cqe;
		ocrdma_change_cq_phase(cq, cqe, cur_getp);
expand_cqe:
		if (polled) {
			num_entries -= 1;
			i += 1;
			ibwc = ibwc + 1;
			polled = 0;
		}
	}
stop_cqe:
	cq->getp = cur_getp;
	if (cq->deferred_arm || polled_hw_cqes) {
		ocrdma_ring_cq_db(cq, cq->deferred_arm,
				  cq->deferred_sol, polled_hw_cqes);
		cq->deferred_arm = 0;
		cq->deferred_sol = 0;
	}

	return i;
}

static int ocrdma_add_err_cqe(struct ocrdma_cq *cq, int num_entries,
			      struct ocrdma_qp *qp, struct ibv_wc *ibwc)
{
	int err_cqes = 0;

	while (num_entries) {
		if (is_hw_sq_empty(qp) && is_hw_rq_empty(qp))
			break;
		if (!is_hw_sq_empty(qp) && qp->sq_cq == cq) {
			ocrdma_update_wc(qp, ibwc, qp->sq.tail);
			ocrdma_hwq_inc_tail(&qp->sq);
		} else if (!is_hw_rq_empty(qp) && qp->rq_cq == cq) {
			ibwc->wr_id = qp->rqe_wr_id_tbl[qp->rq.tail];
			ocrdma_hwq_inc_tail(&qp->rq);
		} else
			return err_cqes;
		ibwc->byte_len = 0;
		ibwc->status = IBV_WC_WR_FLUSH_ERR;
		ibwc = ibwc + 1;
		err_cqes += 1;
		num_entries -= 1;
	}
	return err_cqes;
}

/*
 * ocrdma_poll_cq
 */
int ocrdma_poll_cq(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc)
{
	struct ocrdma_cq *cq;
	int cqes_to_poll = num_entries;
	int num_os_cqe = 0, err_cqes = 0;
	struct ocrdma_qp *qp;
	struct ocrdma_qp *qp_tmp;

	cq = get_ocrdma_cq(ibcq);
	pthread_spin_lock(&cq->cq_lock);
	num_os_cqe = ocrdma_poll_hwcq(cq, num_entries, wc);
	pthread_spin_unlock(&cq->cq_lock);
	cqes_to_poll -= num_os_cqe;

	if (cqes_to_poll) {
		wc = wc + num_os_cqe;
		pthread_spin_lock(&cq->dev->flush_q_lock);
		list_for_each_safe(&cq->sq_head, qp, qp_tmp, sq_entry) {
			if (cqes_to_poll == 0)
				break;
			err_cqes = ocrdma_add_err_cqe(cq, cqes_to_poll, qp, wc);
			cqes_to_poll -= err_cqes;
			num_os_cqe += err_cqes;
			wc = wc + err_cqes;
		}
		pthread_spin_unlock(&cq->dev->flush_q_lock);
	}
	return num_os_cqe;
}

/*
 * ocrdma_arm_cq
 */
int ocrdma_arm_cq(struct ibv_cq *ibcq, int solicited)
{
	struct ocrdma_cq *cq;

	cq = get_ocrdma_cq(ibcq);
	pthread_spin_lock(&cq->cq_lock);

	if (cq->first_arm) {
		ocrdma_ring_cq_db(cq, 1, solicited, 0);
		cq->first_arm = 0;
	}

	cq->deferred_arm = 1;
	cq->deferred_sol = solicited;

	pthread_spin_unlock(&cq->cq_lock);

	return 0;
}

/*
 * ocrdma_post_srq_recv
 */
int ocrdma_post_srq_recv(struct ibv_srq *ibsrq, struct ibv_recv_wr *wr,
			 struct ibv_recv_wr **bad_wr)
{
	int status = 0;
	uint16_t tag;
	struct ocrdma_srq *srq;
	struct ocrdma_hdr_wqe *rqe;

	srq = get_ocrdma_srq(ibsrq);
	pthread_spin_lock(&srq->q_lock);
	while (wr) {
		if (ocrdma_hwq_free_cnt(&srq->rq) == 0 ||
		    wr->num_sge > srq->rq.max_sges) {
			status = ENOMEM;
			*bad_wr = wr;
			break;
		}
		rqe = ocrdma_hwq_head(&srq->rq);
		tag = ocrdma_srq_get_idx(srq);
		ocrdma_build_rqe(rqe, wr, tag);
		srq->rqe_wr_id_tbl[tag] = wr->wr_id;

		ocrdma_ring_srq_db(srq);

		/* update pointer, counter for next wr */
		ocrdma_hwq_inc_head(&srq->rq);
		wr = wr->next;
	}
	pthread_spin_unlock(&srq->q_lock);
	return status;
}

/*
 * ocrdma_create_ah
 */
struct ibv_ah *ocrdma_create_ah(struct ibv_pd *ibpd, struct ibv_ah_attr *attr)
{
	int status;
	int ahtbl_idx;
	struct ocrdma_pd *pd;
	struct ocrdma_ah *ah;
	struct ib_uverbs_create_ah_resp resp;

	pd = get_ocrdma_pd(ibpd);
	ah = malloc(sizeof *ah);
	if (!ah)
		return NULL;
	bzero(ah, sizeof *ah);
	ah->pd = pd;

	ahtbl_idx = ocrdma_alloc_ah_tbl_id(pd->uctx);
	if (ahtbl_idx < 0)
		goto tbl_err;
	attr->dlid = ahtbl_idx;
	memset(&resp, 0, sizeof(resp));
	status = ibv_cmd_create_ah(ibpd, &ah->ibv_ah, attr, &resp, sizeof(resp));
	if (status)
		goto cmd_err;

	ah->id = pd->uctx->ah_tbl[ahtbl_idx] & OCRDMA_AH_ID_MASK;
	ah->isvlan = (pd->uctx->ah_tbl[ahtbl_idx] >>
			OCRDMA_AH_VLAN_VALID_SHIFT);
	ah->hdr_type = ((pd->uctx->ah_tbl[ahtbl_idx] >> OCRDMA_AH_L3_TYPE_SHIFT)
			& OCRDMA_AH_L3_TYPE_MASK);

	return &ah->ibv_ah;
cmd_err:
	ocrdma_free_ah_tbl_id(pd->uctx, ahtbl_idx);
tbl_err:
	free(ah);
	return NULL;
}

/*
 * ocrdma_destroy_ah
 */
int ocrdma_destroy_ah(struct ibv_ah *ibah)
{
	int status;
	struct ocrdma_ah *ah;

	ah = get_ocrdma_ah(ibah);

	status = ibv_cmd_destroy_ah(ibah);
	ocrdma_free_ah_tbl_id(ah->pd->uctx, ah->id);
	free(ah);
	return status;
}

/*
 * ocrdma_attach_mcast
 */
int ocrdma_attach_mcast(struct ibv_qp *ibqp, const union ibv_gid *gid,
			uint16_t lid)
{
	return ibv_cmd_attach_mcast(ibqp, gid, lid);
}

/*
 * ocrdma_detach_mcast
 */
int ocrdma_detach_mcast(struct ibv_qp *ibqp, const union ibv_gid *gid,
			uint16_t lid)
{
	return ibv_cmd_detach_mcast(ibqp, gid, lid);
}
