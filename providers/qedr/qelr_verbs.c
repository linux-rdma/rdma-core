/*
 * Copyright (c) 2015-2016  QLogic Corporation
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
 *        disclaimer in the documentation and /or other materials
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
#include <stdbool.h>

#include "qelr.h"
#include "qelr_chain.h"
#include "qelr_verbs.h"
#include <util/compiler.h>
#include <util/util.h>
#include <util/mmio.h>
#include <stdio.h>
#include <stdlib.h>

#define QELR_SQE_ELEMENT_SIZE	(sizeof(struct rdma_sq_sge))
#define QELR_RQE_ELEMENT_SIZE	(sizeof(struct rdma_rq_sge))
#define QELR_CQE_SIZE		(sizeof(union rdma_cqe))

static void qelr_inc_sw_cons_u16(struct qelr_qp_hwq_info *info)
{
	info->cons = (info->cons + 1) % info->max_wr;
	info->wqe_cons++;
}

static void qelr_inc_sw_prod_u16(struct qelr_qp_hwq_info *info)
{
	info->prod = (info->prod + 1) % info->max_wr;
}

static inline int qelr_wq_is_full(struct qelr_qp_hwq_info *info)
{
	return (((info->prod + 1) % info->max_wr) == info->cons);
}

int qelr_query_device(struct ibv_context *context,
		      struct ibv_device_attr *attr)
{
	struct ibv_query_device cmd;
	uint64_t fw_ver;
	unsigned int major, minor, revision, eng;
	int status;

	bzero(attr, sizeof(*attr));
	status = ibv_cmd_query_device(context, attr, &fw_ver, &cmd,
				      sizeof(cmd));

	major = (fw_ver >> 24) & 0xff;
	minor = (fw_ver >> 16) & 0xff;
	revision = (fw_ver >> 8) & 0xff;
	eng = fw_ver & 0xff;

	snprintf(attr->fw_ver, sizeof(attr->fw_ver),
		 "%d.%d.%d.%d", major, minor, revision, eng);

	return status;
}

int qelr_query_port(struct ibv_context *context, uint8_t port,
		    struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;
	int status;

	status = ibv_cmd_query_port(context, port, attr, &cmd, sizeof(cmd));
	return status;
}

struct ibv_pd *qelr_alloc_pd(struct ibv_context *context)
{
	struct qelr_alloc_pd cmd;
	struct qelr_alloc_pd_resp resp;
	struct qelr_pd *pd;
	struct qelr_devctx *cxt = get_qelr_ctx(context);

	pd = malloc(sizeof(*pd));
	if (!pd)
		return NULL;

	bzero(pd, sizeof(*pd));
	memset(&cmd, 0, sizeof(cmd));

	if (ibv_cmd_alloc_pd(context, &pd->ibv_pd, &cmd.ibv_cmd, sizeof(cmd),
			     &resp.ibv_resp, sizeof(resp))) {
		free(pd);
		return NULL;
	}

	pd->pd_id = resp.pd_id;

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_INIT, "Allocated pd: %d\n", pd->pd_id);

	return &pd->ibv_pd;
}

int qelr_dealloc_pd(struct ibv_pd *ibpd)
{
	int rc = 0;
	struct qelr_pd *pd = get_qelr_pd(ibpd);
	struct qelr_devctx *cxt = get_qelr_ctx(ibpd->context);

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_INIT, "Deallocated pd: %d\n",
		   pd->pd_id);

	rc = ibv_cmd_dealloc_pd(ibpd);

	if (rc)
		return rc;

	free(pd);

	return rc;
}

struct ibv_mr *qelr_reg_mr(struct ibv_pd *ibpd, void *addr, size_t len,
			   uint64_t hca_va, int access)
{
	struct qelr_mr *mr;
	struct ibv_reg_mr cmd;
	struct qelr_reg_mr_resp resp;
	struct qelr_pd *pd = get_qelr_pd(ibpd);
	struct qelr_devctx *cxt = get_qelr_ctx(ibpd->context);

	mr = malloc(sizeof(*mr));
	if (!mr)
		return NULL;

	bzero(mr, sizeof(*mr));

	if (ibv_cmd_reg_mr(ibpd, addr, len, hca_va, access, &mr->vmr, &cmd,
			   sizeof(cmd), &resp.ibv_resp, sizeof(resp))) {
		free(mr);
		return NULL;
	}

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_MR,
		   "MR Register %p completed successfully pd_id=%d addr=%p len=%zu access=%d lkey=%x rkey=%x\n",
		   mr, pd->pd_id, addr, len, access, mr->vmr.ibv_mr.lkey,
		   mr->vmr.ibv_mr.rkey);

	return &mr->vmr.ibv_mr;
}

int qelr_dereg_mr(struct verbs_mr *vmr)
{
	struct qelr_devctx *cxt = get_qelr_ctx(vmr->ibv_mr.context);
	int rc;

	rc = ibv_cmd_dereg_mr(vmr);
	if (rc)
		return rc;

	free(vmr);

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_MR,
		   "MR DERegister %p completed successfully\n", vmr);
	return 0;
}

static void consume_cqe(struct qelr_cq *cq)
{
	if (cq->latest_cqe == cq->toggle_cqe)
		cq->chain_toggle ^= RDMA_CQE_REQUESTER_TOGGLE_BIT_MASK;

	cq->latest_cqe = qelr_chain_consume(&cq->chain);
}

static inline int qelr_cq_entries(int entries)
{
	/* FW requires an extra entry */
	return entries + 1;
}

struct ibv_cq *qelr_create_cq(struct ibv_context *context, int cqe,
			      struct ibv_comp_channel *channel,
			      int comp_vector)
{
	struct qelr_devctx *cxt = get_qelr_ctx(context);
	struct qelr_create_cq_resp resp = {};
	struct qelr_create_cq cmd;
	struct qelr_cq *cq;
	int chain_size;
	int rc;

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
		   "create cq: context=%p, cqe=%d, channel=%p, comp_vector=%d\n",
		   context, cqe, channel, comp_vector);

	if (!cqe || cqe > cxt->max_cqes) {
		DP_ERR(cxt->dbg_fp,
		       "create cq: failed. attempted to allocate %d cqes but valid range is 1...%d\n",
		       cqe, cqe > cxt->max_cqes);
		return NULL;
	}

	/* allocate CQ structure */
	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	/* allocate CQ buffer */
	chain_size = qelr_cq_entries(cqe) * QELR_CQE_SIZE;
	rc = qelr_chain_alloc(&cq->chain, chain_size, cxt->kernel_page_size,
			      QELR_CQE_SIZE);
	if (rc)
		goto err_0;

	cmd.addr = (uintptr_t) cq->chain.first_addr;
	cmd.len = cq->chain.size;
	rc = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
			       &cq->ibv_cq, &cmd.ibv_cmd, sizeof(cmd),
			       &resp.ibv_resp, sizeof(resp));
	if (rc) {
		DP_ERR(cxt->dbg_fp, "create cq: failed with rc = %d\n", rc);
		goto err_1;
	}

	/* map the doorbell and prepare its data */
	cq->db.data.icid = htole16(resp.icid);
	cq->db.data.params = DB_AGG_CMD_SET <<
		RDMA_PWM_VAL32_DATA_AGG_CMD_SHIFT;
	cq->db_addr = cxt->db_addr + resp.db_offset;

	if (resp.db_rec_addr) {
		cq->db_rec_map = mmap(NULL, cxt->kernel_page_size, PROT_WRITE,
				      MAP_SHARED, context->cmd_fd,
				      resp.db_rec_addr);
		if (cq->db_rec_map == MAP_FAILED) {
			int errsv = errno;

			DP_ERR(cxt->dbg_fp,
			       "alloc context: doorbell rec mapping failed resp.db_rec_addr = %llx size=%d context->cmd_fd=%d errno=%d\n",
			       resp.db_rec_addr, cxt->kernel_page_size,
			       context->cmd_fd, errsv);
			goto err_1;
		}
		cq->db_rec_addr = cq->db_rec_map;
	} else {
		/* Kernel doesn't support doorbell recovery. Point to dummy
		 * location instead
		 */
		cq->db_rec_addr = &cxt->db_rec_addr_dummy;
	}

	/* point to the very last element, passing this we will toggle */
	cq->toggle_cqe = qelr_chain_get_last_elem(&cq->chain);
	cq->chain_toggle = RDMA_CQE_REQUESTER_TOGGLE_BIT_MASK;
	cq->latest_cqe = NULL; /* must be different from chain_toggle */
	consume_cqe(cq);

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
		   "create cq: successfully created %p\n", cq);

	return &cq->ibv_cq;

err_1:
	qelr_chain_free(&cq->chain);
err_0:
	free(cq);

	return NULL;
}

int qelr_destroy_cq(struct ibv_cq *ibv_cq)
{
	struct qelr_devctx *cxt = get_qelr_ctx(ibv_cq->context);
	struct qelr_cq *cq = get_qelr_cq(ibv_cq);
	int rc;

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ, "destroy cq: %p\n", cq);

	rc = ibv_cmd_destroy_cq(ibv_cq);
	if (rc) {
		DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
		           "destroy cq: failed to destroy %p, got %d.\n", cq,
			   rc);
		return rc;
	}

	qelr_chain_free(&cq->chain);
	if (cq->db_rec_map)
		munmap(cq->db_rec_map, cxt->kernel_page_size);
	free(cq);

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
		   "destroy cq: successfully destroyed %p\n", cq);

	return 0;
}

int qelr_query_srq(struct ibv_srq *ibv_srq, struct ibv_srq_attr *attr)
{
	struct ibv_query_srq cmd;

	return ibv_cmd_query_srq(ibv_srq, attr, &cmd, sizeof(cmd));
}

int qelr_modify_srq(struct ibv_srq *srq, struct ibv_srq_attr *attr,
		    int attr_mask)
{
	struct ibv_modify_srq cmd;

	return ibv_cmd_modify_srq(srq, attr, attr_mask, &cmd, sizeof(cmd));

}

static void qelr_destroy_srq_buffers(struct ibv_srq *ibv_srq)
{
	struct qelr_srq *srq = get_qelr_srq(ibv_srq);
	uint32_t *virt_prod_pair_addr;
	uint32_t prod_size;

	qelr_chain_free(&srq->hw_srq.chain);

	virt_prod_pair_addr = srq->hw_srq.virt_prod_pair_addr;
	prod_size = sizeof(struct rdma_srq_producers);

	ibv_dofork_range(virt_prod_pair_addr, prod_size);
	munmap(virt_prod_pair_addr, prod_size);
}

int qelr_destroy_srq(struct ibv_srq *ibv_srq)
{
	struct qelr_srq *srq = get_qelr_srq(ibv_srq);
	int ret;

	ret = ibv_cmd_destroy_srq(ibv_srq);
	if (ret)
		return ret;

	qelr_destroy_srq_buffers(ibv_srq);
	free(srq);

	return 0;
}

static void qelr_create_srq_configure_req(struct qelr_srq *srq,
					  struct qelr_create_srq *req)
{
	req->srq_addr = (uintptr_t)srq->hw_srq.chain.first_addr;
	req->srq_len = srq->hw_srq.chain.size;
	req->prod_pair_addr = (uintptr_t)srq->hw_srq.virt_prod_pair_addr;
}

static int qelr_create_srq_buffers(struct qelr_devctx *cxt,
					  struct qelr_srq *srq,
					  struct ibv_srq_init_attr *attrs)
{
	uint32_t max_wr, max_sges;
	int chain_size, prod_size;
	void *addr;
	int rc;

	max_wr = attrs->attr.max_wr;
	if (!max_wr)
		return -EINVAL;

	max_wr = min_t(uint32_t, max_wr, cxt->max_srq_wr);
	max_sges = max_wr * (cxt->sges_per_srq_wr + 1); /* +1 for header */
	chain_size = max_sges * QELR_RQE_ELEMENT_SIZE;

	rc = qelr_chain_alloc(&srq->hw_srq.chain, chain_size,
			      cxt->kernel_page_size, QELR_RQE_ELEMENT_SIZE);
	if (rc) {
		DP_ERR(cxt->dbg_fp,
		       "create srq: failed to map srq, got %d", rc);
		return rc;
	}

	prod_size = sizeof(struct rdma_srq_producers);
	addr = mmap(NULL, prod_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1,
		    0);
	if (addr == MAP_FAILED) {
		DP_ERR(cxt->dbg_fp,
		       "create srq: failed to map producer, got %d", errno);
		qelr_chain_free(&srq->hw_srq.chain);
		return errno;
	}

	rc = ibv_dontfork_range(addr, prod_size);
	if (rc) {
		munmap(addr, prod_size);
		qelr_chain_free(&srq->hw_srq.chain);
		return rc;
	}

	srq->hw_srq.virt_prod_pair_addr = addr;
	srq->hw_srq.max_sges = cxt->sges_per_srq_wr;
	srq->hw_srq.max_wr = max_wr;

	return 0;
}

struct ibv_srq *qelr_create_srq(struct ibv_pd *pd,
				struct ibv_srq_init_attr *init_attr)
{
	struct qelr_devctx *cxt = get_qelr_ctx(pd->context);
	struct qelr_create_srq req;
	struct qelr_create_srq_resp resp;
	struct qelr_srq *srq;
	int ret;

	srq = calloc(1, sizeof(*srq));
	if (!srq)
		return NULL;

	ret = qelr_create_srq_buffers(cxt, srq, init_attr);
	if (ret) {
		free(srq);
		return NULL;
	}

	pthread_spin_init(&srq->lock, PTHREAD_PROCESS_PRIVATE);
	qelr_create_srq_configure_req(srq, &req);
	ret = ibv_cmd_create_srq(pd, &srq->ibv_srq, init_attr, &req.ibv_cmd,
				    sizeof(req), &resp.ibv_resp, sizeof(resp));
	if (ret) {
		qelr_destroy_srq_buffers(&srq->ibv_srq);
		free(srq);
		return NULL;
	}

	return &srq->ibv_srq;
}

static void qelr_free_rq(struct qelr_qp *qp)
{
	free(qp->rqe_wr_id);
}

static void qelr_free_sq(struct qelr_qp *qp)
{
	free(qp->wqe_wr_id);
}

static void qelr_chain_free_sq(struct qelr_qp *qp)
{
	qelr_chain_free(&qp->sq.chain);
}

static void qelr_chain_free_rq(struct qelr_qp *qp)
{
	qelr_chain_free(&qp->rq.chain);
}

static inline int qelr_create_qp_buffers_sq(struct qelr_devctx *cxt,
					    struct qelr_qp *qp,
					    struct ibv_qp_init_attr *attrs)
{
	uint32_t max_send_wr, max_send_sges, max_send_buf;
	int chain_size;
	int rc;

	/* SQ */
	max_send_wr = attrs->cap.max_send_wr;
	max_send_wr = max_t(uint32_t, max_send_wr, 1);
	max_send_wr = min_t(uint32_t, max_send_wr, cxt->max_send_wr);
	max_send_sges = max_send_wr * cxt->sges_per_send_wr;
	max_send_buf = max_send_sges * QELR_SQE_ELEMENT_SIZE;

	chain_size = max_send_buf;
	rc = qelr_chain_alloc(&qp->sq.chain, chain_size, cxt->kernel_page_size,
			      QELR_SQE_ELEMENT_SIZE);
	if (rc)
		DP_ERR(cxt->dbg_fp, "create qp: failed to map SQ chain, got %d", rc);

	qp->sq.max_wr = max_send_wr;
	qp->sq.max_sges = cxt->sges_per_send_wr;

	return rc;
}

static inline int qelr_create_qp_buffers_rq(struct qelr_devctx *cxt,
					    struct qelr_qp *qp,
					    struct ibv_qp_init_attr *attrs)
{
	uint32_t max_recv_wr, max_recv_sges, max_recv_buf;
	int chain_size;
	int rc;

	/* RQ */
	max_recv_wr = attrs->cap.max_recv_wr;
	max_recv_wr = max_t(uint32_t, max_recv_wr, 1);
	max_recv_wr = min_t(uint32_t, max_recv_wr, cxt->max_recv_wr);
	max_recv_sges = max_recv_wr * cxt->sges_per_recv_wr;
	max_recv_buf = max_recv_sges * QELR_RQE_ELEMENT_SIZE;

	chain_size = max_recv_buf;
	rc = qelr_chain_alloc(&qp->rq.chain, chain_size, cxt->kernel_page_size,
			      QELR_RQE_ELEMENT_SIZE);
	if (rc)
		DP_ERR(cxt->dbg_fp, "create qp: failed to map RQ chain, got %d", rc);

	qp->rq.max_wr = max_recv_wr;
	qp->rq.max_sges = cxt->sges_per_recv_wr;

	return rc;
}

static inline int qelr_create_qp_buffers(struct qelr_devctx *cxt,
					 struct qelr_qp *qp,
					 struct ibv_qp_init_attr *attrs)
{
	int rc;

	rc = qelr_create_qp_buffers_sq(cxt, qp, attrs);
	if (rc)
		return rc;

	rc = qelr_create_qp_buffers_rq(cxt, qp, attrs);
	if (rc) {
		qelr_chain_free_sq(qp);
		if (qp->sq.db_rec_map)
			munmap(qp->sq.db_rec_map, cxt->kernel_page_size);
		return rc;
	}

	return 0;
}

static inline int qelr_configure_qp_sq(struct qelr_devctx *cxt,
				       struct qelr_qp *qp,
				       struct ibv_qp_init_attr *attrs,
				       struct qelr_create_qp_resp *resp)
{
	qp->sq.icid = resp->sq_icid;
	qp->sq.db_data.data.icid = htole16(resp->sq_icid);
	qp->sq.prod = 0;
	qp->sq.db = cxt->db_addr + resp->sq_db_offset;
	qp->sq.edpm_db = cxt->db_addr;
	if (resp->sq_db_rec_addr) {
		qp->sq.db_rec_map = mmap(NULL, cxt->kernel_page_size,
					 PROT_WRITE, MAP_SHARED,
					 cxt->ibv_ctx.context.cmd_fd,
					 resp->sq_db_rec_addr);

		if (qp->sq.db_rec_map == MAP_FAILED) {
			int errsv = errno;

			DP_ERR(cxt->dbg_fp,
			       "alloc context: doorbell rec mapping failed resp.db_rec_addr = %llx size=%d context->cmd_fd=%d errno=%d\n",
			       resp->sq_db_rec_addr, cxt->kernel_page_size,
			       cxt->ibv_ctx.context.cmd_fd, errsv);
			return -ENOMEM;
		}
		qp->sq.db_rec_addr = qp->sq.db_rec_map;
	} else {
		/* Kernel doesn't support doorbell recovery. Point to dummy
		 * location instead
		 */
		qp->sq.db_rec_addr = &cxt->db_rec_addr_dummy;
	}

	/* shadow SQ */
	qp->sq.max_wr++;	/* prod/cons method requires N+1 elements */
	qp->wqe_wr_id = calloc(qp->sq.max_wr, sizeof(*qp->wqe_wr_id));
	if (!qp->wqe_wr_id) {
		DP_ERR(cxt->dbg_fp,
		       "create qp: failed shadow SQ memory allocation\n");
		return -ENOMEM;
	}
	return 0;
}

static inline int qelr_configure_qp_rq(struct qelr_devctx *cxt,
				       struct qelr_qp *qp,
				       struct ibv_qp_init_attr *attrs,
				       struct qelr_create_qp_resp *resp)
{
	/* RQ */
	qp->rq.icid = resp->rq_icid;
	qp->rq.db_data.data.icid = htole16(resp->rq_icid);
	qp->rq.db = cxt->db_addr + resp->rq_db_offset;
	qp->rq.iwarp_db2 = cxt->db_addr + resp->rq_db2_offset;
	qp->rq.iwarp_db2_data.data.icid = htole16(qp->rq.icid);
	qp->rq.iwarp_db2_data.data.value = htole16(DQ_TCM_IWARP_POST_RQ_CF_CMD);
	qp->rq.prod = 0;

	if (resp->rq_db_rec_addr) {
		qp->rq.db_rec_map = mmap(NULL, cxt->kernel_page_size,
					 PROT_WRITE, MAP_SHARED,
					 cxt->ibv_ctx.context.cmd_fd,
					 resp->rq_db_rec_addr);
		if (qp->rq.db_rec_map == MAP_FAILED) {
			int errsv = errno;

			DP_ERR(cxt->dbg_fp,
			       "alloc context: doorbell rec mapping failed resp.db_rec_addr = %llx size=%d context->cmd_fd=%d errno=%d\n",
			       resp->rq_db_rec_addr, cxt->kernel_page_size,
			       cxt->ibv_ctx.context.cmd_fd, errsv);
			return -ENOMEM;
		}
		qp->rq.db_rec_addr = qp->rq.db_rec_map;
	} else {
		/* Kernel doesn't support doorbell recovery. Point to dummy
		 * location instead
		 */
		qp->rq.db_rec_addr = &cxt->db_rec_addr_dummy;
	}

	/* shadow RQ */
	qp->rq.max_wr++;	/* prod/cons method requires N+1 elements */
	qp->rqe_wr_id = calloc(qp->rq.max_wr, sizeof(*qp->rqe_wr_id));
	if (!qp->rqe_wr_id) {
		DP_ERR(cxt->dbg_fp,
		       "create qp: failed shadow RQ memory allocation\n");
		return -ENOMEM;
	}

	return 0;
}

static inline int qelr_configure_qp(struct qelr_devctx *cxt, struct qelr_qp *qp,
				    struct ibv_qp_init_attr *attrs,
				    struct qelr_create_qp_resp *resp)
{
	int rc;

	/* general */
	pthread_spin_init(&qp->q_lock, PTHREAD_PROCESS_PRIVATE);
	qp->qp_id = resp->qp_id;
	qp->state = QELR_QPS_RST;
	qp->sq_sig_all = attrs->sq_sig_all;
	qp->atomic_supported = resp->atomic_supported;

	rc = qelr_configure_qp_sq(cxt, qp, attrs, resp);
	if (rc)
		return rc;
	rc = qelr_configure_qp_rq(cxt, qp, attrs, resp);
	if (rc)
		qelr_free_sq(qp);

	return rc;
}

static inline void qelr_print_qp_init_attr(
		struct qelr_devctx *cxt,
		struct ibv_qp_init_attr *attr)
{
	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_QP,
		   "create qp: send_cq=%p, recv_cq=%p, srq=%p, max_inline_data=%d, max_recv_sge=%d, max_recv_wr=%d, max_send_sge=%d, max_send_wr=%d, qp_type=%d, sq_sig_all=%d\n",
		   attr->send_cq, attr->recv_cq, attr->srq,
		   attr->cap.max_inline_data, attr->cap.max_recv_sge,
		   attr->cap.max_recv_wr, attr->cap.max_send_sge,
		   attr->cap.max_send_wr, attr->qp_type, attr->sq_sig_all);
}

static inline void
qelr_create_qp_configure_sq_req(struct qelr_qp *qp,
				struct qelr_create_qp *req)
{
	req->sq_addr = (uintptr_t)qp->sq.chain.first_addr;
	req->sq_len = qp->sq.chain.size;
}

static inline void
qelr_create_qp_configure_rq_req(struct qelr_qp *qp,
				struct qelr_create_qp *req)
{
	req->rq_addr = (uintptr_t)qp->rq.chain.first_addr;
	req->rq_len = qp->rq.chain.size;
}

static inline void
qelr_create_qp_configure_req(struct qelr_qp *qp,
			     struct qelr_create_qp *req)
{
	memset(req, 0, sizeof(*req));
	req->qp_handle_hi = U64_HI(qp);
	req->qp_handle_lo = U64_LO(qp);
	qelr_create_qp_configure_sq_req(qp, req);
	qelr_create_qp_configure_rq_req(qp, req);
}

struct ibv_qp *qelr_create_qp(struct ibv_pd *pd,
			      struct ibv_qp_init_attr *attrs)
{
	struct qelr_devctx *cxt = get_qelr_ctx(pd->context);
	struct qelr_create_qp_resp resp = {};
	struct qelr_create_qp req;
	struct qelr_qp *qp;
	int rc;

	qelr_print_qp_init_attr(cxt, attrs);

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	if (attrs->srq)
		qp->srq = get_qelr_srq(attrs->srq);

	rc = qelr_create_qp_buffers(cxt, qp, attrs);
	if (rc)
		goto err0;

	qelr_create_qp_configure_req(qp, &req);

	rc = ibv_cmd_create_qp(pd, &qp->ibv_qp, attrs, &req.ibv_cmd,
			       sizeof(req), &resp.ibv_resp, sizeof(resp));
	if (rc) {
		DP_ERR(cxt->dbg_fp,
		       "create qp: failed on ibv_cmd_create_qp with %d\n", rc);
		goto err1;
	}

	rc = qelr_configure_qp(cxt, qp, attrs, &resp);
	if (rc)
		goto err2;

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_QP,
		   "create qp: successfully created %p. handle_hi=%x handle_lo=%x\n",
		   qp, req.qp_handle_hi, req.qp_handle_lo);

	return &qp->ibv_qp;

err2:
	rc = ibv_cmd_destroy_qp(&qp->ibv_qp);
	if (rc)
		DP_ERR(cxt->dbg_fp, "create qp: fatal fault. rc=%d\n", rc);
err1:
	qelr_chain_free_sq(qp);
	qelr_chain_free_rq(qp);
err0:
	free(qp);

	return NULL;
}

static void qelr_print_ah_attr(struct qelr_devctx *cxt, struct ibv_ah_attr *attr)
{
	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_QP,
		   "grh.dgid=[%#" PRIx64 ":%#" PRIx64 "], grh.flow_label=%d, grh.sgid_index=%d, grh.hop_limit=%d, grh.traffic_class=%d, dlid=%d, sl=%d, src_path_bits=%d, static_rate = %d, port_num=%d\n",
		   be64toh(attr->grh.dgid.global.interface_id),
		   be64toh(attr->grh.dgid.global.subnet_prefix),
		   attr->grh.flow_label, attr->grh.hop_limit,
		   attr->grh.sgid_index, attr->grh.traffic_class, attr->dlid,
		   attr->sl, attr->src_path_bits,
		   attr->static_rate, attr->port_num);
}

static void qelr_print_qp_attr(struct qelr_devctx *cxt, struct ibv_qp_attr *attr)
{
	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_QP,
		   "\tqp_state=%d\tcur_qp_state=%d\tpath_mtu=%d\tpath_mig_state=%d\tqkey=%d\trq_psn=%d\tsq_psn=%d\tdest_qp_num=%d\tqp_access_flags=%d\tmax_inline_data=%d\tmax_recv_sge=%d\tmax_recv_wr=%d\tmax_send_sge=%d\tmax_send_wr=%d\tpkey_index=%d\talt_pkey_index=%d\ten_sqd_async_notify=%d\tsq_draining=%d\tmax_rd_atomic=%d\tmax_dest_rd_atomic=%d\tmin_rnr_timer=%d\tport_num=%d\ttimeout=%d\tretry_cnt=%d\trnr_retry=%d\talt_port_num=%d\talt_timeout=%d\n",
		   attr->qp_state, attr->cur_qp_state, attr->path_mtu,
		   attr->path_mig_state, attr->qkey, attr->rq_psn, attr->sq_psn,
		   attr->dest_qp_num, attr->qp_access_flags,
		   attr->cap.max_inline_data, attr->cap.max_recv_sge,
		   attr->cap.max_recv_wr, attr->cap.max_send_sge,
		   attr->cap.max_send_wr, attr->pkey_index,
		   attr->alt_pkey_index, attr->en_sqd_async_notify,
		   attr->sq_draining, attr->max_rd_atomic,
		   attr->max_dest_rd_atomic, attr->min_rnr_timer,
		   attr->port_num, attr->timeout, attr->retry_cnt,
		   attr->rnr_retry, attr->alt_port_num, attr->alt_timeout);

	qelr_print_ah_attr(cxt, &attr->ah_attr);
	qelr_print_ah_attr(cxt, &attr->alt_ah_attr);
}

int qelr_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		    int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;
	struct qelr_devctx *cxt = get_qelr_ctx(qp->context);
	int rc;

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_QP, "QP Query %p, attr_mask=0x%x\n",
		   get_qelr_qp(qp), attr_mask);

	rc = ibv_cmd_query_qp(qp, attr, attr_mask,
			      init_attr, &cmd, sizeof(cmd));

	qelr_print_qp_attr(cxt, attr);

	return rc;
}

static enum qelr_qp_state get_qelr_qp_state(enum ibv_qp_state qps)
{
	switch (qps) {
	case IBV_QPS_RESET:
		return QELR_QPS_RST;
	case IBV_QPS_INIT:
		return QELR_QPS_INIT;
	case IBV_QPS_RTR:
		return QELR_QPS_RTR;
	case IBV_QPS_RTS:
		return QELR_QPS_RTS;
	case IBV_QPS_SQD:
		return QELR_QPS_SQD;
	case IBV_QPS_SQE:
		return QELR_QPS_SQE;
	case IBV_QPS_ERR:
	default:
		return QELR_QPS_ERR;
	};
}

static void qelr_reset_qp_hwq_info(struct qelr_qp_hwq_info *q)
{
	qelr_chain_reset(&q->chain);
	q->prod = 0;
	q->cons = 0;
	q->wqe_cons = 0;
	q->db_data.data.value = 0;
}

static int qelr_update_qp_state(struct qelr_qp *qp,
				enum ibv_qp_state new_ib_state)
{
	int status = 0;
	enum qelr_qp_state new_state;

	/* iWARP states are updated implicitely by driver and don't have a
	 * real purpose in user-lib.
	 */
	if (IS_IWARP(qp->ibv_qp.context->device))
		return 0;

	new_state = get_qelr_qp_state(new_ib_state);

	pthread_spin_lock(&qp->q_lock);

	if (new_state == qp->state) {
		pthread_spin_unlock(&qp->q_lock);
		return 0;
	}

	switch (qp->state) {
	case QELR_QPS_RST:
		switch (new_state) {
		case QELR_QPS_INIT:
			qp->prev_wqe_size = 0;
			qelr_reset_qp_hwq_info(&qp->sq);
			qelr_reset_qp_hwq_info(&qp->rq);
			break;
		default:
			status = -EINVAL;
			break;
		};
		break;
	case QELR_QPS_INIT:
		/* INIT->XXX */
		switch (new_state) {
		case QELR_QPS_RTR:
			/* Update doorbell (in case post_recv was done before
			 * move to RTR)
			 */
			if (IS_ROCE(qp->ibv_qp.context->device)) {
				mmio_wc_start();
				writel(qp->rq.db_data.raw, qp->rq.db);
				mmio_flush_writes();
			}
			break;
		case QELR_QPS_ERR:
			break;
		default:
			/* invalid state change. */
			status = -EINVAL;
			break;
		};
		break;
	case QELR_QPS_RTR:
		/* RTR->XXX */
		switch (new_state) {
		case QELR_QPS_RTS:
			break;
		case QELR_QPS_ERR:
			break;
		default:
			/* invalid state change. */
			status = -EINVAL;
			break;
		};
		break;
	case QELR_QPS_RTS:
		/* RTS->XXX */
		switch (new_state) {
		case QELR_QPS_SQD:
		case QELR_QPS_SQE:
			break;
		case QELR_QPS_ERR:
			break;
		default:
			/* invalid state change. */
			status = -EINVAL;
			break;
		};
		break;
	case QELR_QPS_SQD:
		/* SQD->XXX */
		switch (new_state) {
		case QELR_QPS_RTS:
		case QELR_QPS_SQE:
		case QELR_QPS_ERR:
			break;
		default:
			/* invalid state change. */
			status = -EINVAL;
			break;
		};
		break;
	case QELR_QPS_SQE:
		switch (new_state) {
		case QELR_QPS_RTS:
		case QELR_QPS_ERR:
			break;
		default:
			/* invalid state change. */
			status = -EINVAL;
			break;
		};
		break;
	case QELR_QPS_ERR:
		/* ERR->XXX */
		switch (new_state) {
		case QELR_QPS_RST:
			break;
		default:
			status = -EINVAL;
			break;
		};
		break;
	default:
		status = -EINVAL;
		break;
	};
	if (!status)
		qp->state = new_state;

	pthread_spin_unlock(&qp->q_lock);

	return status;
}

int qelr_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
		     int attr_mask)
{
	struct ibv_modify_qp cmd = {};
	struct qelr_qp *qp = get_qelr_qp(ibqp);
	struct qelr_devctx *cxt = get_qelr_ctx(ibqp->context);
	union ibv_gid sgid, *p_dgid;
	int rc;

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_QP, "QP Modify %p, attr_mask=0x%x\n",
		   qp, attr_mask);

	qelr_print_qp_attr(cxt, attr);

	rc = ibv_cmd_modify_qp(ibqp, attr, attr_mask, &cmd, sizeof(cmd));
	if (rc) {
		DP_ERR(cxt->dbg_fp, "QP Modify: Failed command. rc=%d\n", rc);
		return rc;
	}

	if (attr_mask & IBV_QP_STATE) {
		rc = qelr_update_qp_state(qp, attr->qp_state);
		DP_VERBOSE(cxt->dbg_fp, QELR_MSG_QP,
			   "QP Modify state %d->%d, rc=%d\n", qp->state,
			   attr->qp_state, rc);
		if (rc) {
			DP_ERR(cxt->dbg_fp,
			       "QP Modify: Failed to update state. rc=%d\n",
			       rc);

			return rc;
		}
	}

	/* EDPM must be disabled if GIDs match */
	if (attr_mask & IBV_QP_AV) {
		rc = ibv_query_gid(ibqp->context, attr->ah_attr.port_num,
				   attr->ah_attr.grh.sgid_index, &sgid);

		if (!rc) {
			p_dgid = &attr->ah_attr.grh.dgid;
			qp->edpm_disabled = !memcmp(&sgid, p_dgid,
						    sizeof(sgid));
			DP_VERBOSE(cxt->dbg_fp, QELR_MSG_QP,
				   "QP Modify: %p, edpm_disabled=%d\n", qp,
				   qp->edpm_disabled);
		} else  {
			DP_ERR(cxt->dbg_fp,
			       "QP Modify: Failed querying GID. rc=%d\n",
			       rc);
		}
	}

	return 0;
}

int qelr_destroy_qp(struct ibv_qp *ibqp)
{
	struct qelr_devctx *cxt = get_qelr_ctx(ibqp->context);
	struct qelr_qp *qp = get_qelr_qp(ibqp);
	int rc = 0;

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_QP, "destroy qp: %p\n", qp);

	rc = ibv_cmd_destroy_qp(ibqp);
	if (rc) {
		DP_ERR(cxt->dbg_fp,
		       "destroy qp: failed to destroy %p, got %d.\n", qp, rc);
		return rc;
	}

	qelr_free_sq(qp);
	qelr_free_rq(qp);
	qelr_chain_free_sq(qp);
	qelr_chain_free_rq(qp);
	if (qp->sq.db_rec_map)
		munmap(qp->sq.db_rec_map, cxt->kernel_page_size);
	if (qp->rq.db_rec_map)
		munmap(qp->rq.db_rec_map, cxt->kernel_page_size);
	free(qp);

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_QP,
		   "destroy cq: successfully destroyed %p\n", qp);

	return 0;
}

static int sge_data_len(struct ibv_sge *sg_list, int num_sge)
{
	int i, len = 0;

	for (i = 0; i < num_sge; i++)
		len += sg_list[i].length;
	return len;
}

static void swap_wqe_data64(uint64_t *p)
{
	__be64 *bep=(__be64 *)p;
	int i;

	for (i = 0; i < ROCE_WQE_ELEM_SIZE / sizeof(uint64_t); i++, p++, bep++)
		*bep = htobe64(*p);
}

static inline void qelr_init_dpm_info(struct qelr_devctx *cxt,
				      struct qelr_qp *qp,
				      struct ibv_send_wr *wr,
				      struct qelr_dpm *dpm,
				      int data_size)
{
	dpm->is_edpm = 0;
	dpm->is_ldpm = 0;

	/* DPM only succeeds when transmit queues are empty */
	if (!qelr_chain_is_full(&qp->sq.chain))
		return;

	/* Check if edpm can be used */
	if (wr->send_flags & IBV_SEND_INLINE && !qp->edpm_disabled &&
	    cxt->dpm_flags & QELR_DPM_FLAGS_ENHANCED) {
		memset(dpm, 0, sizeof(*dpm));
		dpm->rdma_ext = (struct qelr_rdma_ext *)&dpm->payload;
		dpm->is_edpm = 1;
		return;
	}

	 /* Check if ldpm can be used - not inline and limited to ldpm_limit */
	if (cxt->dpm_flags & QELR_DPM_FLAGS_LEGACY &&
	    !(wr->send_flags & IBV_SEND_INLINE) &&
	    data_size <= cxt->ldpm_limit_size) {
		memset(dpm, 0, sizeof(*dpm));
		dpm->is_ldpm = 1;
	}
}

#define QELR_IB_OPCODE_SEND_ONLY                         0x04
#define QELR_IB_OPCODE_SEND_ONLY_WITH_IMMEDIATE          0x05
#define QELR_IB_OPCODE_RDMA_WRITE_ONLY                   0x0a
#define QELR_IB_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE    0x0b
#define QELR_IB_OPCODE_SEND_WITH_INV			 0x17
#define QELR_IS_IMM_OR_INV(opcode) \
	(((opcode) == QELR_IB_OPCODE_SEND_ONLY_WITH_IMMEDIATE) || \
	 ((opcode) == QELR_IB_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE) || \
	 ((opcode) == QELR_IB_OPCODE_SEND_WITH_INV))

static inline void qelr_edpm_set_msg_data(struct qelr_qp *qp,
					  struct qelr_dpm *dpm,
					  uint8_t opcode,
					  uint16_t length,
					  uint8_t se,
					  uint8_t comp)
{
	uint32_t wqe_size, dpm_size, params;

	params = 0;
	wqe_size = length + (QELR_IS_IMM_OR_INV(opcode) ? sizeof(uint32_t) : 0);
	dpm_size = wqe_size + sizeof(struct db_roce_dpm_data);

	SET_FIELD(params, DB_ROCE_DPM_PARAMS_DPM_TYPE, DPM_ROCE);
	SET_FIELD(params, DB_ROCE_DPM_PARAMS_OPCODE, opcode);
	SET_FIELD(params, DB_ROCE_DPM_PARAMS_WQE_SIZE, wqe_size);
	SET_FIELD(params, DB_ROCE_DPM_PARAMS_COMPLETION_FLG, comp ? 1 : 0);
	SET_FIELD(params, DB_ROCE_DPM_PARAMS_S_FLG, se ? 1 : 0);
	SET_FIELD(params, DB_ROCE_DPM_PARAMS_SIZE,
		  (dpm_size + sizeof(uint64_t) - 1) / sizeof(uint64_t));

	dpm->msg.data.params.params = htole32(params);
}

static inline void qelr_edpm_set_inv_imm(struct qelr_qp *qp,
					 struct qelr_dpm *dpm,
					 __be32 data)
{
	memcpy(&dpm->payload[dpm->payload_offset], &data, sizeof(data));

	dpm->payload_offset += sizeof(data);
	dpm->payload_size += sizeof(data);
}

static inline void qelr_edpm_set_rdma_ext(struct qelr_qp *qp,
					  struct qelr_dpm *dpm,
					  uint64_t remote_addr,
					  uint32_t rkey)
{
	dpm->rdma_ext->remote_va = htobe64(remote_addr);
	dpm->rdma_ext->remote_key = htobe32(rkey);
	dpm->payload_offset += sizeof(*dpm->rdma_ext);
	dpm->payload_size += sizeof(*dpm->rdma_ext);
}

static inline void qelr_edpm_set_payload(struct qelr_qp *qp,
					 struct qelr_dpm *dpm, char *buf,
					 uint32_t length)
{
	memcpy(&dpm->payload[dpm->payload_offset], buf, length);

	dpm->payload_offset += length;
}

static void qelr_prepare_sq_inline_data(struct qelr_qp *qp,
					    struct qelr_dpm *dpm,
					    int data_size,
					    uint8_t *wqe_size,
					    struct ibv_send_wr *wr,
					    uint8_t *bits, uint8_t bit)
{
	int i;
	uint32_t seg_siz;
	char *seg_prt, *wqe;

	if (!data_size)
		return;

	/* set the bit */
	*bits |= bit;

	seg_prt = NULL;
	wqe = NULL;
	seg_siz = 0;

	/* copy data inline */
	for (i = 0; i < wr->num_sge; i++) {
		uint32_t len = wr->sg_list[i].length;
		void *src = (void *)(uintptr_t)wr->sg_list[i].addr;

		if (dpm->is_edpm)
			qelr_edpm_set_payload(qp, dpm, src, len);

		while (len > 0) {
			uint32_t cur;

			/* new segment required */
			if (!seg_siz) {
				wqe = (char *)qelr_chain_produce(&qp->sq.chain);
				seg_prt = wqe;
				seg_siz = sizeof(struct rdma_sq_common_wqe);
				(*wqe_size)++;
			}

			/* calculate currently allowed length */
			cur = min(len, seg_siz);

			memcpy(seg_prt, src, cur);

			/* update segment variables */
			seg_prt += cur;
			seg_siz -= cur;
			/* update sge variables */
			src += cur;
			len -= cur;

			/* swap fully-completed segments */
			if (!seg_siz)
				swap_wqe_data64((uint64_t *)wqe);
		}
	}

	/* swap last not completed segment */
	if (seg_siz)
		swap_wqe_data64((uint64_t *)wqe);

	if (dpm->is_edpm) {
		dpm->payload_size += data_size;

		if (wr->opcode == IBV_WR_RDMA_WRITE ||
		    wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
			dpm->rdma_ext->dma_length = htobe32(data_size);
	}
}

static void qelr_prepare_sq_sges(struct qelr_qp *qp,
				 struct qelr_dpm *dpm,
				     uint8_t *wqe_size,
				     struct ibv_send_wr *wr)
{
	int i;

	for (i = 0; i < wr->num_sge; i++) {
		struct rdma_sq_sge *sge = qelr_chain_produce(&qp->sq.chain);

		TYPEPTR_ADDR_SET(sge, addr, wr->sg_list[i].addr);
		sge->l_key = htole32(wr->sg_list[i].lkey);
		sge->length = htole32(wr->sg_list[i].length);

		if (dpm->is_ldpm) {
			memcpy(&dpm->payload[dpm->payload_size], sge,
			       sizeof(*sge));
			dpm->payload_size += sizeof(*sge);
		}
	}

	if (wqe_size)
		*wqe_size += wr->num_sge;
}

static uint32_t qelr_prepare_sq_rdma_data(struct qelr_qp *qp,
					  struct qelr_dpm *dpm,
					  int data_size,
					  uint8_t *p_wqe_size,
					  struct rdma_sq_rdma_wqe_1st *rwqe,
					  struct rdma_sq_rdma_wqe_2nd *rwqe2,
					  struct ibv_send_wr *wr,
					  bool is_imm)
{
	memset(rwqe2, 0, sizeof(*rwqe2));
	rwqe2->r_key = htole32(wr->wr.rdma.rkey);
	TYPEPTR_ADDR_SET(rwqe2, remote_va, wr->wr.rdma.remote_addr);
	rwqe->length = htole32(data_size);

	if (is_imm)
		rwqe->imm_data = htole32(be32toh(wr->imm_data));

	if (wr->send_flags & IBV_SEND_INLINE &&
	    (wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM ||
	     wr->opcode == IBV_WR_RDMA_WRITE)) {
		uint8_t flags = 0;

		SET_FIELD2(flags, RDMA_SQ_RDMA_WQE_1ST_INLINE_FLG, 1);
		qelr_prepare_sq_inline_data(qp, dpm, data_size,
					    p_wqe_size, wr,
					    &rwqe->flags, flags);
		rwqe->wqe_size = *p_wqe_size;
	} else {
		if (dpm->is_ldpm)
			dpm->payload_size = sizeof(*rwqe) + sizeof(*rwqe2);
		qelr_prepare_sq_sges(qp, dpm, p_wqe_size, wr);
		rwqe->wqe_size = *p_wqe_size;

		if (dpm->is_ldpm) {
			memcpy(dpm->payload, rwqe, sizeof(*rwqe));
			memcpy(&dpm->payload[sizeof(*rwqe)], rwqe2,
			       sizeof(*rwqe2));
		}
	}

	return data_size;
}

static uint32_t qelr_prepare_sq_send_data(struct qelr_qp *qp,
					  struct qelr_dpm *dpm,
					  int data_size,
					  uint8_t *p_wqe_size,
					  struct rdma_sq_send_wqe_1st *swqe,
					  struct rdma_sq_send_wqe_2st *swqe2,
					  struct ibv_send_wr *wr,
					  bool is_imm)
{
	memset(swqe2, 0, sizeof(*swqe2));
	swqe->length = htole32(data_size);

	if (is_imm)
		swqe->inv_key_or_imm_data = htole32(be32toh(wr->imm_data));

	if (wr->send_flags & IBV_SEND_INLINE) {
		uint8_t flags = 0;

		SET_FIELD2(flags, RDMA_SQ_SEND_WQE_INLINE_FLG, 1);
		qelr_prepare_sq_inline_data(qp, dpm, data_size,
					    p_wqe_size, wr,
					    &swqe->flags, flags);
		swqe->wqe_size = *p_wqe_size;
	} else {
		if (dpm->is_ldpm)
			dpm->payload_size = sizeof(*swqe) + sizeof(*swqe2);

		qelr_prepare_sq_sges(qp, dpm, p_wqe_size, wr);
		swqe->wqe_size = *p_wqe_size;
		if (dpm->is_ldpm) {
			memcpy(dpm->payload, swqe, sizeof(*swqe));
			memcpy(&dpm->payload[sizeof(*swqe)], swqe2,
			       sizeof(*swqe2));
		}
	}

	return data_size;
}

static void qelr_prepare_sq_atom_data(struct qelr_qp *qp,
				      struct qelr_dpm *dpm,
				      struct rdma_sq_atomic_wqe_1st *awqe1,
				      struct rdma_sq_atomic_wqe_2nd *awqe2,
				      struct rdma_sq_atomic_wqe_3rd *awqe3,
				      struct ibv_send_wr *wr)
{
	if (dpm->is_ldpm) {
		memcpy(&dpm->payload[dpm->payload_size], awqe1, sizeof(*awqe1));
		dpm->payload_size += sizeof(*awqe1);
		memcpy(&dpm->payload[dpm->payload_size], awqe2, sizeof(*awqe2));
		dpm->payload_size += sizeof(*awqe2);
		memcpy(&dpm->payload[dpm->payload_size], awqe3, sizeof(*awqe3));
		dpm->payload_size += sizeof(*awqe3);
	}

	qelr_prepare_sq_sges(qp, dpm, NULL, wr);
}

static inline void qelr_ldpm_prepare_data(struct qelr_qp *qp,
					  struct qelr_dpm *dpm)
{
	uint32_t val, params;

	/* DPM size is given in 8 bytes so we round up */
	val = dpm->payload_size + sizeof(struct db_roce_dpm_data);
	val = DIV_ROUND_UP(val, sizeof(uint64_t));

	params = 0;
	SET_FIELD(params, DB_ROCE_DPM_PARAMS_SIZE, val);
	SET_FIELD(params, DB_ROCE_DPM_PARAMS_DPM_TYPE, DPM_LEGACY);

	dpm->msg.data.params.params = htole32(params);
}

static enum ibv_wc_opcode qelr_ibv_to_wc_opcode(enum ibv_wr_opcode opcode)
{
	switch (opcode) {
	case IBV_WR_RDMA_WRITE:
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		return IBV_WC_RDMA_WRITE;
	case IBV_WR_SEND_WITH_IMM:
	case IBV_WR_SEND:
	case IBV_WR_SEND_WITH_INV:
		return IBV_WC_SEND;
	case IBV_WR_RDMA_READ:
		return IBV_WC_RDMA_READ;
	case IBV_WR_ATOMIC_CMP_AND_SWP:
		return IBV_WC_COMP_SWAP;
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		return IBV_WC_FETCH_ADD;
	default:
		return IBV_WC_SEND;
	}
}

static inline void doorbell_qp(struct qelr_qp *qp)
{
	mmio_wc_start();
	writel(qp->sq.db_data.raw, qp->sq.db);
	/* copy value to doorbell recovery mechanism */
	qp->sq.db_rec_addr->db_data = qp->sq.db_data.raw;
	mmio_flush_writes();
}

static inline void doorbell_dpm_qp(struct qelr_devctx *cxt, struct qelr_qp *qp,
				   struct qelr_dpm *dpm)
{
	uint32_t offset = 0;
	uint64_t *payload = (uint64_t *)dpm->payload;
	uint32_t num_dwords;
	int bytes = 0;
	void *db_addr;

	mmio_wc_start();

	/* Write message header */
	dpm->msg.data.icid = qp->sq.db_data.data.icid;
	dpm->msg.data.prod_val = qp->sq.db_data.data.value;
	db_addr = qp->sq.edpm_db;
	writeq(dpm->msg.raw, db_addr);

	/* Write mesage body */
	bytes += sizeof(uint64_t);
	num_dwords = DIV_ROUND_UP(dpm->payload_size, sizeof(uint64_t));

	db_addr += sizeof(dpm->msg.data);

	if (bytes == cxt->edpm_trans_size) {
		mmio_flush_writes();
		bytes = 0;
	}

	while (offset < num_dwords) {
		/* endianity is different between FW and DORQ HW block */
		if (dpm->is_ldpm)
			mmio_write64_be(db_addr, htobe64(payload[offset]));
		else /* EDPM */
			mmio_write64(db_addr, payload[offset]);

		bytes += sizeof(uint64_t);
		db_addr += sizeof(uint64_t);

		/* Writing to a wc bar. We need to flush the writes every
		 * edpm transaction size otherwise the CPU could optimize away
		 * the duplicate stores.
		 */
		if (bytes == cxt->edpm_trans_size) {
			mmio_flush_writes();
			bytes = 0;
		}
		offset++;
	}

	mmio_flush_writes();
}

static inline int qelr_can_post_send(struct qelr_devctx *cxt,
				      struct qelr_qp *qp,
				      struct ibv_send_wr *wr,
				      int data_size)
{
	/* Invalid WR */
	if (wr->num_sge > qp->sq.max_sges) {
		DP_ERR(cxt->dbg_fp,
		       "error: WR is bad. Post send on QP %p failed\n",
		       qp);
		return -EINVAL;
	}

	/* WR overflow */
	if (qelr_wq_is_full(&qp->sq)) {
		DP_ERR(cxt->dbg_fp,
		       "error: WQ is full. Post send on QP %p failed (this error appears only once)\n",
		       qp);
		return -ENOMEM;
	}

	/* WQE overflow */
	if (qelr_chain_get_elem_left_u32(&qp->sq.chain) <
			QELR_MAX_SQ_WQE_SIZE) {
		DP_ERR(cxt->dbg_fp,
		       "error: WQ PBL is full. Post send on QP %p failed (this error appears only once)\n",
		       qp);
		return -ENOMEM;
	}

	if ((wr->opcode == IBV_WR_ATOMIC_CMP_AND_SWP ||
	     wr->opcode == IBV_WR_ATOMIC_FETCH_AND_ADD) &&
	    !qp->atomic_supported) {
		DP_ERR(cxt->dbg_fp, "Atomic not supported on this machine\n");
		return -EINVAL;
	}

	if ((wr->send_flags & IBV_SEND_INLINE) &&
	    (data_size > ROCE_REQ_MAX_INLINE_DATA_SIZE)) {
		DP_ERR(cxt->dbg_fp, "Too much inline data in WR: %d\n", data_size);
		return -EINVAL;
	}


	return 0;
}

static int __qelr_post_send(struct qelr_devctx *cxt, struct qelr_qp *qp,
			    struct ibv_send_wr *wr, int data_size,
			    int *normal_db_required)
{
	uint8_t se, comp, fence;
	struct rdma_sq_common_wqe *wqe;
	struct rdma_sq_send_wqe_1st *swqe;
	struct rdma_sq_send_wqe_2st *swqe2;
	struct rdma_sq_rdma_wqe_1st *rwqe;
	struct rdma_sq_rdma_wqe_2nd *rwqe2;
	struct rdma_sq_atomic_wqe_1st *awqe1;
	struct rdma_sq_atomic_wqe_2nd *awqe2;
	struct rdma_sq_atomic_wqe_3rd *awqe3;
	struct qelr_dpm dpm;
	uint32_t wqe_length;
	uint8_t wqe_size;
	uint16_t db_val;
	int rc = 0;

	qelr_init_dpm_info(cxt, qp, wr, &dpm, data_size);

	wqe = qelr_chain_produce(&qp->sq.chain);

	comp = (!!(wr->send_flags & IBV_SEND_SIGNALED)) ||
			(!!qp->sq_sig_all);
	qp->wqe_wr_id[qp->sq.prod].signaled = comp;

	/* common fields */
	wqe->flags = 0;
	se = !!(wr->send_flags & IBV_SEND_SOLICITED);
	fence = !!(wr->send_flags & IBV_SEND_FENCE);
	SET_FIELD2(wqe->flags, RDMA_SQ_COMMON_WQE_SE_FLG, se);
	SET_FIELD2(wqe->flags, RDMA_SQ_COMMON_WQE_COMP_FLG, comp);
	SET_FIELD2(wqe->flags, RDMA_SQ_COMMON_WQE_RD_FENCE_FLG, fence);
	wqe->prev_wqe_size = qp->prev_wqe_size;

	qp->wqe_wr_id[qp->sq.prod].opcode = qelr_ibv_to_wc_opcode(wr->opcode);

	switch (wr->opcode) {
	case IBV_WR_SEND_WITH_IMM:
		wqe->req_type = RDMA_SQ_REQ_TYPE_SEND_WITH_IMM;
		swqe = (struct rdma_sq_send_wqe_1st *)wqe;

		wqe_size = sizeof(struct rdma_sq_send_wqe) / RDMA_WQE_BYTES;
		swqe2 = (struct rdma_sq_send_wqe_2st *)qelr_chain_produce(&qp->sq.chain);

		if (dpm.is_edpm)
			qelr_edpm_set_inv_imm(qp, &dpm, wr->imm_data);

		wqe_length = qelr_prepare_sq_send_data(qp, &dpm, data_size,
						       &wqe_size, swqe, swqe2,
						       wr, 1 /* Imm */);

		if (dpm.is_edpm)
			qelr_edpm_set_msg_data(qp, &dpm,
					       QELR_IB_OPCODE_SEND_ONLY_WITH_IMMEDIATE,
					       wqe_length, se, comp);
		else if (dpm.is_ldpm)
			qelr_ldpm_prepare_data(qp, &dpm);

		qp->wqe_wr_id[qp->sq.prod].wqe_size = wqe_size;
		qp->prev_wqe_size = wqe_size;
		qp->wqe_wr_id[qp->sq.prod].bytes_len = wqe_length;
		break;

	case IBV_WR_SEND:
		wqe->req_type = RDMA_SQ_REQ_TYPE_SEND;
		swqe = (struct rdma_sq_send_wqe_1st *)wqe;

		wqe_size = sizeof(struct rdma_sq_send_wqe) / RDMA_WQE_BYTES;
		swqe2 = (struct rdma_sq_send_wqe_2st *)qelr_chain_produce(&qp->sq.chain);
		wqe_length = qelr_prepare_sq_send_data(qp, &dpm, data_size,
						       &wqe_size, swqe, swqe2,
						       wr, 0);
		if (dpm.is_edpm)
			qelr_edpm_set_msg_data(qp, &dpm,
					       QELR_IB_OPCODE_SEND_ONLY,
					       wqe_length, se, comp);
		else if (dpm.is_ldpm)
			qelr_ldpm_prepare_data(qp, &dpm);

		qp->wqe_wr_id[qp->sq.prod].wqe_size = wqe_size;
		qp->prev_wqe_size = wqe_size;
		qp->wqe_wr_id[qp->sq.prod].bytes_len = wqe_length;
		break;

	case IBV_WR_SEND_WITH_INV:
		wqe->req_type = RDMA_SQ_REQ_TYPE_SEND_WITH_INVALIDATE;
		swqe = (struct rdma_sq_send_wqe_1st *)wqe;

		wqe_size = sizeof(struct rdma_sq_send_wqe) / RDMA_WQE_BYTES;
		swqe2 = qelr_chain_produce(&qp->sq.chain);

		if (dpm.is_edpm)
			qelr_edpm_set_inv_imm(qp, &dpm,
					      htobe32(wr->invalidate_rkey));

		swqe->inv_key_or_imm_data = htole32(wr->invalidate_rkey);

		wqe_length = qelr_prepare_sq_send_data(qp, &dpm, data_size,
						       &wqe_size, swqe, swqe2,
						       wr, 0);

		if (dpm.is_edpm)
			qelr_edpm_set_msg_data(qp, &dpm,
					       QELR_IB_OPCODE_SEND_WITH_INV,
					       wqe_length, se, comp);
		else if (dpm.is_ldpm)
			qelr_ldpm_prepare_data(qp, &dpm);

		qp->wqe_wr_id[qp->sq.prod].wqe_size = wqe_size;
		qp->prev_wqe_size = wqe_size;
		qp->wqe_wr_id[qp->sq.prod].bytes_len = wqe_length;

		break;

	case IBV_WR_RDMA_WRITE_WITH_IMM:
		wqe->req_type = RDMA_SQ_REQ_TYPE_RDMA_WR_WITH_IMM;
		rwqe = (struct rdma_sq_rdma_wqe_1st *)wqe;

		wqe_size = sizeof(struct rdma_sq_rdma_wqe) / RDMA_WQE_BYTES;
		rwqe2 = (struct rdma_sq_rdma_wqe_2nd *)qelr_chain_produce(&qp->sq.chain);
		if (dpm.is_edpm) {
			qelr_edpm_set_rdma_ext(qp, &dpm, wr->wr.rdma.remote_addr,
					       wr->wr.rdma.rkey);
			qelr_edpm_set_inv_imm(qp, &dpm, wr->imm_data);
		}

		wqe_length = qelr_prepare_sq_rdma_data(qp, &dpm, data_size, &wqe_size,
						       rwqe, rwqe2, wr, 1 /* Imm */);
		if (dpm.is_edpm)
			qelr_edpm_set_msg_data(qp, &dpm,
					       QELR_IB_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE,
					       wqe_length + sizeof(*dpm.rdma_ext),
					       se, comp);
		else if (dpm.is_ldpm)
			qelr_ldpm_prepare_data(qp, &dpm);

		qp->wqe_wr_id[qp->sq.prod].wqe_size = wqe_size;
		qp->prev_wqe_size = wqe_size;
		qp->wqe_wr_id[qp->sq.prod].bytes_len = wqe_length;
		break;

	case IBV_WR_RDMA_WRITE:
		wqe->req_type = RDMA_SQ_REQ_TYPE_RDMA_WR;
		rwqe = (struct rdma_sq_rdma_wqe_1st *)wqe;

		wqe_size = sizeof(struct rdma_sq_rdma_wqe) / RDMA_WQE_BYTES;
		rwqe2 = (struct rdma_sq_rdma_wqe_2nd *)qelr_chain_produce(&qp->sq.chain);
		if (dpm.is_edpm)
			qelr_edpm_set_rdma_ext(qp, &dpm,
					       wr->wr.rdma.remote_addr,
					       wr->wr.rdma.rkey);

		wqe_length = qelr_prepare_sq_rdma_data(qp, &dpm, data_size, &wqe_size,
						       rwqe, rwqe2, wr, 0);
		if (dpm.is_edpm)
			qelr_edpm_set_msg_data(qp, &dpm,
					       QELR_IB_OPCODE_RDMA_WRITE_ONLY,
					       wqe_length +
					       sizeof(*dpm.rdma_ext),
					       se, comp);
		else if (dpm.is_ldpm)
			qelr_ldpm_prepare_data(qp, &dpm);

		qp->wqe_wr_id[qp->sq.prod].wqe_size = wqe_size;
		qp->prev_wqe_size = wqe_size;
		qp->wqe_wr_id[qp->sq.prod].bytes_len = wqe_length;
		break;

	case IBV_WR_RDMA_READ:
		wqe->req_type = RDMA_SQ_REQ_TYPE_RDMA_RD;
		rwqe = (struct rdma_sq_rdma_wqe_1st *)wqe;

		wqe_size = sizeof(struct rdma_sq_rdma_wqe) / RDMA_WQE_BYTES;
		rwqe2 = (struct rdma_sq_rdma_wqe_2nd *)qelr_chain_produce(&qp->sq.chain);
		wqe_length = qelr_prepare_sq_rdma_data(qp, &dpm, data_size, &wqe_size,
						       rwqe, rwqe2, wr, 0);
		if (dpm.is_ldpm)
			qelr_ldpm_prepare_data(qp, &dpm);

		qp->wqe_wr_id[qp->sq.prod].wqe_size = wqe_size;
		qp->prev_wqe_size = wqe_size;
		qp->wqe_wr_id[qp->sq.prod].bytes_len = wqe_length;
		break;

	case IBV_WR_ATOMIC_CMP_AND_SWP:
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		awqe1 = (struct rdma_sq_atomic_wqe_1st *)wqe;
		awqe1->wqe_size = 4;

		awqe2 = (struct rdma_sq_atomic_wqe_2nd *)qelr_chain_produce(&qp->sq.chain);
		TYPEPTR_ADDR_SET(awqe2, remote_va, wr->wr.atomic.remote_addr);
		awqe2->r_key = htole32(wr->wr.atomic.rkey);

		awqe3 = (struct rdma_sq_atomic_wqe_3rd *)qelr_chain_produce(&qp->sq.chain);

		if (wr->opcode == IBV_WR_ATOMIC_FETCH_AND_ADD) {
			wqe->req_type = RDMA_SQ_REQ_TYPE_ATOMIC_ADD;
			TYPEPTR_ADDR_SET(awqe3, swap_data, wr->wr.atomic.compare_add);
		} else {
			wqe->req_type = RDMA_SQ_REQ_TYPE_ATOMIC_CMP_AND_SWAP;
			TYPEPTR_ADDR_SET(awqe3, swap_data, wr->wr.atomic.swap);
			TYPEPTR_ADDR_SET(awqe3, cmp_data, wr->wr.atomic.compare_add);
		}

		qelr_prepare_sq_atom_data(qp, &dpm, awqe1, awqe2, awqe3, wr);
		if (dpm.is_ldpm)
			qelr_ldpm_prepare_data(qp, &dpm);
		qp->wqe_wr_id[qp->sq.prod].wqe_size = awqe1->wqe_size;
		qp->prev_wqe_size = awqe1->wqe_size;

		break;

	default:
		/* restore prod to its position before this WR was processed */
		qelr_chain_set_prod(&qp->sq.chain,
				    le16toh(qp->sq.db_data.data.value),
				    wqe);

		/* restore prev_wqe_size */
		qp->prev_wqe_size = wqe->prev_wqe_size;

		rc = -EINVAL;
		DP_ERR(cxt->dbg_fp,
		       "Invalid opcode %d in work request on QP %p\n",
		       wr->opcode, qp);
		break;
	}

	if (rc)
		return rc;

	qp->wqe_wr_id[qp->sq.prod].wr_id = wr->wr_id;
	qelr_inc_sw_prod_u16(&qp->sq);
	db_val = le16toh(qp->sq.db_data.data.value) + 1;
	qp->sq.db_data.data.value = htole16(db_val);

	if (dpm.is_edpm || dpm.is_ldpm) {
		doorbell_dpm_qp(cxt, qp, &dpm);
		*normal_db_required = 0;
	} else {
		*normal_db_required = 1;
	}

	return 0;
}

int qelr_post_send(struct ibv_qp *ib_qp, struct ibv_send_wr *wr,
		   struct ibv_send_wr **bad_wr)
{
	struct qelr_devctx *cxt = get_qelr_ctx(ib_qp->context);
	struct qelr_qp *qp = get_qelr_qp(ib_qp);
	int doorbell_required = 0;
	*bad_wr = NULL;
	int rc = 0;

	pthread_spin_lock(&qp->q_lock);

	if (IS_ROCE(ib_qp->context->device) &&
	    (qp->state != QELR_QPS_RTS && qp->state != QELR_QPS_ERR &&
	     qp->state != QELR_QPS_SQD)) {
		pthread_spin_unlock(&qp->q_lock);
		*bad_wr = wr;
		return -EINVAL;
	}

	while (wr) {
		int data_size = sge_data_len(wr->sg_list, wr->num_sge);

		rc = qelr_can_post_send(cxt, qp, wr, data_size);
		if (rc) {
			*bad_wr = wr;
			break;
		}

		rc = __qelr_post_send(cxt, qp, wr, data_size, &doorbell_required);
		if (rc) {
			*bad_wr = wr;
			break;
		}

		wr = wr->next;
	}

	if (doorbell_required)
		doorbell_qp(qp);

	pthread_spin_unlock(&qp->q_lock);

	return rc;
}

static uint32_t qelr_srq_elem_left(struct qelr_srq_hwq_info *hw_srq)
{
	uint32_t used;

	/* Calculate number of elements used based on producer
	 * count and consumer count and subtract it from max
	 * work request supported so that we get elements left.
	 */
	used = (uint32_t)(((uint64_t)((uint64_t)~0U) + 1 +
			  (uint64_t)(hw_srq->wr_prod_cnt)) -
			  (uint64_t)hw_srq->wr_cons_cnt);

	return hw_srq->max_wr - used;
}

int qelr_post_srq_recv(struct ibv_srq *ibsrq, struct ibv_recv_wr *wr,
		       struct ibv_recv_wr **bad_wr)
{
	struct qelr_devctx *cxt = get_qelr_ctx(ibsrq->context);
	struct qelr_srq *srq = get_qelr_srq(ibsrq);
	struct qelr_srq_hwq_info *hw_srq = &srq->hw_srq;
	struct qelr_chain *chain;
	int status = 0;

	pthread_spin_lock(&srq->lock);

	chain = &srq->hw_srq.chain;
	while (wr) {
		struct rdma_srq_wqe_header *hdr;
		int i;

		if (!qelr_srq_elem_left(hw_srq) ||
		    wr->num_sge > srq->hw_srq.max_sges) {
			DP_ERR(cxt->dbg_fp,
			       "Can't post WR  (%d,%d) || (%d > %d)\n",
			       hw_srq->wr_prod_cnt, hw_srq->wr_cons_cnt,
			       wr->num_sge,
			       srq->hw_srq.max_sges);
			status = -ENOMEM;
			*bad_wr = wr;
			break;
		}

		hdr = qelr_chain_produce(chain);

		SRQ_HDR_SET(hdr, wr->wr_id, wr->num_sge);

		hw_srq->wr_prod_cnt++;
		hw_srq->wqe_prod++;
		hw_srq->sge_prod++;

		DP_VERBOSE(cxt->dbg_fp, QELR_MSG_SRQ,
			   "SRQ WR: SGEs: %d with wr_id[%d] = %" PRIx64 "\n",
			    wr->num_sge, hw_srq->wqe_prod, wr->wr_id);

		for (i = 0; i < wr->num_sge; i++) {
			struct rdma_srq_sge *srq_sge;

			srq_sge = qelr_chain_produce(chain);
			SRQ_SGE_SET(srq_sge, wr->sg_list[i].addr,
				    wr->sg_list[i].length, wr->sg_list[i].lkey);

			DP_VERBOSE(cxt->dbg_fp, QELR_MSG_SRQ,
				   "[%d]: len %d key %x addr %x:%x\n",
				   i, srq_sge->length, srq_sge->l_key,
				   srq_sge->addr.hi, srq_sge->addr.lo);
			hw_srq->sge_prod++;
		}

		/* Make sure that descriptors are written before we update
		 * producers.
		 */

		udma_ordering_write_barrier();

		struct rdma_srq_producers *virt_prod;

		virt_prod = srq->hw_srq.virt_prod_pair_addr;
		virt_prod->sge_prod = htole32(hw_srq->sge_prod);
		virt_prod->wqe_prod = htole32(hw_srq->wqe_prod);

		wr = wr->next;
	}

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_SRQ,
		   "POST: Elements in SRQ: %d\n",
		   qelr_chain_get_elem_left_u32(chain));
	pthread_spin_unlock(&srq->lock);

	return status;
}

int qelr_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		   struct ibv_recv_wr **bad_wr)
{
	int status = 0;
	struct qelr_qp *qp =  get_qelr_qp(ibqp);
	struct qelr_devctx *cxt = get_qelr_ctx(ibqp->context);
	uint16_t db_val;
	uint8_t iwarp = IS_IWARP(ibqp->context->device);

	if (unlikely(qp->srq)) {
		DP_ERR(cxt->dbg_fp,
		       "QP is associated with SRQ, cannot post RQ buffers\n");
		*bad_wr = wr;
		return -EINVAL;
	}

	pthread_spin_lock(&qp->q_lock);

	if (!iwarp && qp->state == QELR_QPS_RST) {
		pthread_spin_unlock(&qp->q_lock);
		*bad_wr = wr;
		return -EINVAL;
	}

	while (wr) {
		int i;

		if (qelr_chain_get_elem_left_u32(&qp->rq.chain) <
		    QELR_MAX_RQ_WQE_SIZE || wr->num_sge > qp->rq.max_sges) {
			DP_ERR(cxt->dbg_fp,
			       "Can't post WR  (%d < %d) || (%d > %d)\n",
			       qelr_chain_get_elem_left_u32(&qp->rq.chain),
			       QELR_MAX_RQ_WQE_SIZE, wr->num_sge,
			       qp->rq.max_sges);
			status = -ENOMEM;
			*bad_wr = wr;
			break;
		}
		for (i = 0; i < wr->num_sge; i++) {
			uint32_t flags = 0;
			struct rdma_rq_sge *rqe;

			/* first one must include the number of SGE in the
			 * list
			 */
			if (!i)
				SET_FIELD(flags, RDMA_RQ_SGE_NUM_SGES,
					  wr->num_sge);

			SET_FIELD(flags, RDMA_RQ_SGE_L_KEY,
				  wr->sg_list[i].lkey);
			rqe = qelr_chain_produce(&qp->rq.chain);
			RQ_SGE_SET(rqe, wr->sg_list[i].addr,
				   wr->sg_list[i].length, flags);
		}
		/* Special case of no sges. FW requires between 1-4 sges...
		 * in this case we need to post 1 sge with length zero. this is
		 * because rdma write with immediate consumes an RQ.
		 */
		if (!wr->num_sge) {
			uint32_t flags = 0;
			struct rdma_rq_sge *rqe;

			/* first one must include the number of SGE in the
			 * list
			 */
			SET_FIELD(flags, RDMA_RQ_SGE_L_KEY, 0);
			SET_FIELD(flags, RDMA_RQ_SGE_NUM_SGES, 1);

			rqe = qelr_chain_produce(&qp->rq.chain);
			RQ_SGE_SET(rqe, 0, 0, flags);
			i = 1;
		}

		qp->rqe_wr_id[qp->rq.prod].wr_id = wr->wr_id;
		qp->rqe_wr_id[qp->rq.prod].wqe_size = i;

		qelr_inc_sw_prod_u16(&qp->rq);

		mmio_wc_start();

		db_val = le16toh(qp->rq.db_data.data.value) + 1;
		qp->rq.db_data.data.value = htole16(db_val);

		writel(qp->rq.db_data.raw, qp->rq.db);
		/* copy value to doorbell recovery mechanism */
		qp->rq.db_rec_addr->db_data = qp->rq.db_data.raw;
		mmio_flush_writes();

		if (iwarp) {
			writel(qp->rq.iwarp_db2_data.raw, qp->rq.iwarp_db2);
			mmio_flush_writes();
		}
		wr = wr->next;
	}

	pthread_spin_unlock(&qp->q_lock);

	return status;
}

static int is_valid_cqe(struct qelr_cq *cq, union rdma_cqe *cqe)
{
	struct rdma_cqe_requester *resp_cqe = &cqe->req;

	return (resp_cqe->flags & RDMA_CQE_REQUESTER_TOGGLE_BIT_MASK) ==
		cq->chain_toggle;
}

static enum rdma_cqe_type cqe_get_type(union rdma_cqe *cqe)
{
	struct rdma_cqe_requester *resp_cqe = &cqe->req;

	return GET_FIELD(resp_cqe->flags, RDMA_CQE_REQUESTER_TYPE);
}

static struct qelr_qp *cqe_get_qp(union rdma_cqe *cqe)
{
	struct regpair *qph = &cqe->req.qp_handle;

	return (struct qelr_qp *)HILO_U64(le32toh(qph->hi), le32toh(qph->lo));
}

static int process_req(struct qelr_qp *qp, struct qelr_cq *cq, int num_entries,
		       struct ibv_wc *wc, uint16_t hw_cons,
		       enum ibv_wc_status status, int force)
{
	struct qelr_devctx *cxt = get_qelr_ctx(qp->ibv_qp.context);
	uint16_t cnt = 0;

	while (num_entries && qp->sq.wqe_cons != hw_cons) {
		if (!qp->wqe_wr_id[qp->sq.cons].signaled && !force) {
			/* skip WC */
			goto next_cqe;
		}

		/* fill WC */
		wc->status = status;
		wc->wc_flags = 0;
		wc->qp_num = qp->qp_id;

		/* common section */
		wc->wr_id = qp->wqe_wr_id[qp->sq.cons].wr_id;
		wc->opcode = qp->wqe_wr_id[qp->sq.cons].opcode;

		switch (wc->opcode) {
		case IBV_WC_RDMA_WRITE:
			wc->byte_len = qp->wqe_wr_id[qp->sq.cons].bytes_len;
			DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
				   "POLL REQ CQ: IBV_WC_RDMA_WRITE byte_len=%d\n",
				   qp->wqe_wr_id[qp->sq.cons].bytes_len);
			break;
		case IBV_WC_COMP_SWAP:
		case IBV_WC_FETCH_ADD:
			wc->byte_len = 8;
			break;
		case IBV_WC_RDMA_READ:
		case IBV_WC_SEND:
		case IBV_WC_BIND_MW:
			wc->byte_len = qp->wqe_wr_id[qp->sq.cons].bytes_len;
			DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
				   "POLL REQ CQ: IBV_WC_RDMA_READ / IBV_WC_SEND\n");
			break;
		default:
			break;
		}

		num_entries--;
		wc++;
		cnt++;
next_cqe:
		while (qp->wqe_wr_id[qp->sq.cons].wqe_size--)
			qelr_chain_consume(&qp->sq.chain);
		qelr_inc_sw_cons_u16(&qp->sq);
	}

	return cnt;
}

static int qelr_poll_cq_req(struct qelr_qp *qp, struct qelr_cq *cq,
			    int num_entries, struct ibv_wc *wc,
			    struct rdma_cqe_requester *req)
{
	struct qelr_devctx *cxt = get_qelr_ctx(qp->ibv_qp.context);
	uint16_t sq_cons = le16toh(req->sq_cons);
	int cnt = 0;

	switch (req->status) {
	case RDMA_CQE_REQ_STS_OK:
		cnt = process_req(qp, cq, num_entries, wc, sq_cons,
				  IBV_WC_SUCCESS, 0);
		break;
	case RDMA_CQE_REQ_STS_WORK_REQUEST_FLUSHED_ERR:
		DP_ERR(cxt->dbg_fp,
		       "Error: POLL CQ with ROCE_CQE_REQ_STS_WORK_REQUEST_FLUSHED_ERR. QP icid=0x%x\n",
		       qp->sq.icid);
		cnt = process_req(qp, cq, num_entries, wc, sq_cons,
				  IBV_WC_WR_FLUSH_ERR, 1);
		break;
	default: /* other errors case */
		/* process all WQE before the consumer */
		qp->state = QELR_QPS_ERR;
		cnt = process_req(qp, cq, num_entries, wc, sq_cons - 1,
				  IBV_WC_SUCCESS, 0);
		wc += cnt;
		/* if we have extra WC fill it with actual error info */
		if (cnt < num_entries) {
			enum ibv_wc_status wc_status;

			switch (req->status) {
			case    RDMA_CQE_REQ_STS_BAD_RESPONSE_ERR:
				DP_ERR(cxt->dbg_fp,
				       "Error: POLL CQ with RDMA_CQE_REQ_STS_BAD_RESPONSE_ERR. QP icid=0x%x\n",
				       qp->sq.icid);
				wc_status = IBV_WC_BAD_RESP_ERR;
				break;
			case    RDMA_CQE_REQ_STS_LOCAL_LENGTH_ERR:
				DP_ERR(cxt->dbg_fp,
				       "Error: POLL CQ with RDMA_CQE_REQ_STS_LOCAL_LENGTH_ERR. QP icid=0x%x\n",
				       qp->sq.icid);
				wc_status = IBV_WC_LOC_LEN_ERR;
				break;
			case    RDMA_CQE_REQ_STS_LOCAL_QP_OPERATION_ERR:
				DP_ERR(cxt->dbg_fp,
				       "Error: POLL CQ with RDMA_CQE_REQ_STS_LOCAL_QP_OPERATION_ERR. QP icid=0x%x\n",
				       qp->sq.icid);
				wc_status = IBV_WC_LOC_QP_OP_ERR;
				break;
			case    RDMA_CQE_REQ_STS_LOCAL_PROTECTION_ERR:
				DP_ERR(cxt->dbg_fp,
				       "Error: POLL CQ with RDMA_CQE_REQ_STS_LOCAL_PROTECTION_ERR. QP icid=0x%x\n",
				       qp->sq.icid);
				wc_status = IBV_WC_LOC_PROT_ERR;
				break;
			case    RDMA_CQE_REQ_STS_MEMORY_MGT_OPERATION_ERR:
				DP_ERR(cxt->dbg_fp,
				       "Error: POLL CQ with RDMA_CQE_REQ_STS_MEMORY_MGT_OPERATION_ERR. QP icid=0x%x\n",
				       qp->sq.icid);
				wc_status = IBV_WC_MW_BIND_ERR;
				break;
			case    RDMA_CQE_REQ_STS_REMOTE_INVALID_REQUEST_ERR:
				DP_ERR(cxt->dbg_fp,
				       "Error: POLL CQ with RDMA_CQE_REQ_STS_REMOTE_INVALID_REQUEST_ERR. QP icid=0x%x\n",
				       qp->sq.icid);
				wc_status = IBV_WC_REM_INV_REQ_ERR;
				break;
			case    RDMA_CQE_REQ_STS_REMOTE_ACCESS_ERR:
				DP_ERR(cxt->dbg_fp,
				       "Error: POLL CQ with RDMA_CQE_REQ_STS_REMOTE_ACCESS_ERR. QP icid=0x%x\n",
				       qp->sq.icid);
				wc_status = IBV_WC_REM_ACCESS_ERR;
				break;
			case    RDMA_CQE_REQ_STS_REMOTE_OPERATION_ERR:
				DP_ERR(cxt->dbg_fp,
				       "Error: POLL CQ with RDMA_CQE_REQ_STS_REMOTE_OPERATION_ERR. QP icid=0x%x\n",
				       qp->sq.icid);
				wc_status = IBV_WC_REM_OP_ERR;
				break;
			case    RDMA_CQE_REQ_STS_RNR_NAK_RETRY_CNT_ERR:
				DP_ERR(cxt->dbg_fp,
				       "Error: POLL CQ with RDMA_CQE_REQ_STS_RNR_NAK_RETRY_CNT_ERR. QP icid=0x%x\n",
				       qp->sq.icid);
				wc_status = IBV_WC_RNR_RETRY_EXC_ERR;
				break;
			case    RDMA_CQE_REQ_STS_TRANSPORT_RETRY_CNT_ERR:
				DP_ERR(cxt->dbg_fp,
				       "RDMA_CQE_REQ_STS_TRANSPORT_RETRY_CNT_ERR. QP icid=0x%x\n",
				       qp->sq.icid);
				wc_status = IBV_WC_RETRY_EXC_ERR;
				break;
			default:
				DP_ERR(cxt->dbg_fp,
				       "IBV_WC_GENERAL_ERR. QP icid=0x%x\n",
				       qp->sq.icid);
				wc_status = IBV_WC_GENERAL_ERR;
			}

			cnt += process_req(qp, cq, 1, wc, sq_cons, wc_status,
					   1 /* force use of WC */);
		}
	}

	return cnt;
}

static void __process_resp_one(struct qelr_qp *qp, struct qelr_cq *cq,
			       struct ibv_wc *wc,
			       struct rdma_cqe_responder *resp, uint64_t wr_id)
{
	struct qelr_devctx *cxt = get_qelr_ctx(qp->ibv_qp.context);
	enum ibv_wc_status wc_status = IBV_WC_SUCCESS;
	uint8_t flags;

	wc->opcode = IBV_WC_RECV;
	wc->wr_id = wr_id;
	wc->wc_flags = 0;
	switch (resp->status) {
	case RDMA_CQE_RESP_STS_LOCAL_ACCESS_ERR:
		wc_status = IBV_WC_LOC_ACCESS_ERR;
		break;
	case RDMA_CQE_RESP_STS_LOCAL_LENGTH_ERR:
		wc_status = IBV_WC_LOC_LEN_ERR;
		break;
	case RDMA_CQE_RESP_STS_LOCAL_QP_OPERATION_ERR:
		wc_status = IBV_WC_LOC_QP_OP_ERR;
		break;
	case RDMA_CQE_RESP_STS_LOCAL_PROTECTION_ERR:
		wc_status = IBV_WC_LOC_PROT_ERR;
		break;
	case RDMA_CQE_RESP_STS_MEMORY_MGT_OPERATION_ERR:
		wc_status = IBV_WC_MW_BIND_ERR;
		break;
	case RDMA_CQE_RESP_STS_REMOTE_INVALID_REQUEST_ERR:
		wc_status = IBV_WC_REM_INV_RD_REQ_ERR;
		break;
	case RDMA_CQE_RESP_STS_OK:
		wc_status = IBV_WC_SUCCESS;
		wc->byte_len = le32toh(resp->length);

		flags = resp->flags & QELR_RESP_RDMA_IMM;

		switch (flags) {
		case QELR_RESP_RDMA_IMM:
			/* update opcode */
			wc->opcode = IBV_WC_RECV_RDMA_WITH_IMM;
			SWITCH_FALLTHROUGH;
		case QELR_RESP_IMM:
			wc->imm_data = htobe32(le32toh(resp->imm_data_or_inv_r_Key));
			wc->wc_flags |= IBV_WC_WITH_IMM;
			break;
		case QELR_RESP_INV:
			wc->invalidated_rkey = le32toh(resp->imm_data_or_inv_r_Key);
			wc->wc_flags |= IBV_WC_WITH_INV;
			break;
		case QELR_RESP_RDMA:
			DP_ERR(cxt->dbg_fp, "Invalid flags detected\n");
			break;
		default:
			/* valid configuration, but nothing to do here */
			break;
		}

		break;
	default:
		wc->status = IBV_WC_GENERAL_ERR;
		DP_ERR(cxt->dbg_fp, "Invalid CQE status detected\n");
	}

	/* fill WC */
	wc->status = wc_status;
	wc->qp_num = qp->qp_id;
}

static int process_resp_one_srq(struct qelr_qp *qp, struct qelr_cq *cq,
				struct ibv_wc *wc,
				struct rdma_cqe_responder *resp)
{
	struct qelr_srq_hwq_info *hw_srq = &qp->srq->hw_srq;
	uint64_t wr_id;

	wr_id = (((uint64_t)(le32toh(resp->srq_wr_id.hi))) << 32) +
		le32toh(resp->srq_wr_id.lo);

	if (resp->status == RDMA_CQE_RESP_STS_WORK_REQUEST_FLUSHED_ERR) {
		wc->byte_len = 0;
		wc->status = IBV_WC_WR_FLUSH_ERR;
		wc->qp_num = qp->qp_id;
		wc->wr_id = wr_id;
	} else {
		__process_resp_one(qp, cq, wc, resp, wr_id);
	}

	hw_srq->wr_cons_cnt++;

	return 1;
}

static int process_resp_one(struct qelr_qp *qp, struct qelr_cq *cq,
			    struct ibv_wc *wc, struct rdma_cqe_responder *resp)
{
	uint64_t wr_id = qp->rqe_wr_id[qp->rq.cons].wr_id;

	__process_resp_one(qp, cq, wc, resp, wr_id);

	while (qp->rqe_wr_id[qp->rq.cons].wqe_size--)
		qelr_chain_consume(&qp->rq.chain);

	qelr_inc_sw_cons_u16(&qp->rq);

	return 1;
}

static int process_resp_flush(struct qelr_qp *qp, struct qelr_cq *cq,
			      int num_entries, struct ibv_wc *wc,
			      uint16_t hw_cons)
{
	uint16_t cnt = 0;

	while (num_entries && qp->rq.wqe_cons != hw_cons) {
		/* fill WC */
		wc->status = IBV_WC_WR_FLUSH_ERR;
		wc->qp_num = qp->qp_id;
		wc->byte_len = 0;
		wc->wr_id = qp->rqe_wr_id[qp->rq.cons].wr_id;
		num_entries--;
		wc++;
		cnt++;
		while (qp->rqe_wr_id[qp->rq.cons].wqe_size--)
			qelr_chain_consume(&qp->rq.chain);
		qelr_inc_sw_cons_u16(&qp->rq);
	}

	return cnt;
}

/* return latest CQE (needs processing) */
static union rdma_cqe *get_cqe(struct qelr_cq *cq)
{
	return cq->latest_cqe;
}

static void try_consume_req_cqe(struct qelr_cq *cq, struct qelr_qp *qp,
				struct rdma_cqe_requester *req, int *update)
{
	uint16_t sq_cons = le16toh(req->sq_cons);

	if (sq_cons == qp->sq.wqe_cons) {
		consume_cqe(cq);
		*update |= 1;
	}
}

/* used with flush only, when resp->rq_cons is valid */
static void try_consume_resp_cqe(struct qelr_cq *cq, struct qelr_qp *qp,
				 uint16_t rq_cons, int *update)
{
	if (rq_cons == qp->rq.wqe_cons) {
		consume_cqe(cq);
		*update |= 1;
	}
}

static int qelr_poll_cq_resp_srq(struct qelr_qp *qp, struct qelr_cq *cq,
				 int num_entries, struct ibv_wc *wc,
				 struct rdma_cqe_responder *resp, int *update)
{
	int cnt;

	cnt = process_resp_one_srq(qp, cq, wc, resp);
	consume_cqe(cq);
	*update |= 1;

	return cnt;
}

static int qelr_poll_cq_resp(struct qelr_qp *qp, struct qelr_cq *cq,
			     int num_entries, struct ibv_wc *wc,
			     struct rdma_cqe_responder *resp, int *update)
{
	uint16_t rq_cons = le16toh(resp->rq_cons);
	int cnt;

	if (resp->status == RDMA_CQE_RESP_STS_WORK_REQUEST_FLUSHED_ERR) {
		cnt = process_resp_flush(qp, cq, num_entries, wc, rq_cons);
		try_consume_resp_cqe(cq, qp, rq_cons, update);
	} else {
		cnt = process_resp_one(qp, cq, wc, resp);
		consume_cqe(cq);
		*update |= 1;
	}

	return cnt;
}

static void doorbell_cq(struct qelr_cq *cq, uint32_t cons, uint8_t flags)
{
	mmio_wc_start();
	cq->db.data.agg_flags = flags;
	cq->db.data.value = htole32(cons);

	writeq(cq->db.raw, cq->db_addr);
	/* copy value to doorbell recovery mechanism */
	cq->db_rec_addr->db_data = cq->db.raw;
	mmio_flush_writes();
}

int qelr_poll_cq(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc)
{
	struct qelr_cq *cq = get_qelr_cq(ibcq);
	int done = 0;
	union rdma_cqe *cqe = get_cqe(cq);
	int update = 0;
	uint32_t db_cons;

	while (num_entries && is_valid_cqe(cq, cqe)) {
		int cnt = 0;
		struct qelr_qp *qp;

		/* prevent speculative reads of any field of CQE */
		udma_from_device_barrier();

		qp = cqe_get_qp(cqe);
		if (!qp) {
			DP_ERR(stderr,
			       "Error: CQE QP pointer is NULL. CQE=%p\n", cqe);
			break;
		}

		switch (cqe_get_type(cqe)) {
		case RDMA_CQE_TYPE_REQUESTER:
			cnt = qelr_poll_cq_req(qp, cq, num_entries, wc,
					       &cqe->req);
			try_consume_req_cqe(cq, qp, &cqe->req, &update);
			break;
		case RDMA_CQE_TYPE_RESPONDER_RQ:
			cnt = qelr_poll_cq_resp(qp, cq, num_entries, wc,
						&cqe->resp, &update);
			break;
		case RDMA_CQE_TYPE_RESPONDER_SRQ:
			cnt = qelr_poll_cq_resp_srq(qp, cq, num_entries, wc,
						    &cqe->resp, &update);
			break;
		case RDMA_CQE_TYPE_INVALID:
		default:
			printf("Error: invalid CQE type = %d\n",
			       cqe_get_type(cqe));
		}
		num_entries -= cnt;
		wc += cnt;
		done += cnt;

		cqe = get_cqe(cq);
	}

	db_cons = qelr_chain_get_cons_idx_u32(&cq->chain) - 1;
	if (update) {
		/* doorbell notifies about latest VALID entry,
		 * but chain already point to the next INVALID one
		 */
		doorbell_cq(cq, db_cons, cq->arm_flags);
	}

	return done;
}

void qelr_cq_event(struct ibv_cq *ibcq)
{
	/* Trigger received, can reset arm flags */
	struct qelr_cq *cq = get_qelr_cq(ibcq);

	cq->arm_flags = 0;
}

int qelr_arm_cq(struct ibv_cq *ibcq, int solicited)
{
	struct qelr_cq *cq = get_qelr_cq(ibcq);
	uint32_t db_cons;

	db_cons = qelr_chain_get_cons_idx_u32(&cq->chain) - 1;
	cq->arm_flags = solicited ? DQ_UCM_ROCE_CQ_ARM_SE_CF_CMD :
				    DQ_UCM_ROCE_CQ_ARM_CF_CMD;

	doorbell_cq(cq, db_cons, cq->arm_flags);

	return 0;
}

void qelr_async_event(struct ibv_context *context,
		      struct ibv_async_event *event)
{
	struct qelr_cq *cq = NULL;
	struct qelr_qp *qp = NULL;

	switch (event->event_type) {
	case IBV_EVENT_CQ_ERR:
		cq = get_qelr_cq(event->element.cq);
		break;
	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_REQ_ERR:
	case IBV_EVENT_QP_ACCESS_ERR:
	case IBV_EVENT_PATH_MIG_ERR:{
			qp = get_qelr_qp(event->element.qp);
			break;
		}
	case IBV_EVENT_SQ_DRAINED:
	case IBV_EVENT_PATH_MIG:
	case IBV_EVENT_COMM_EST:
	case IBV_EVENT_QP_LAST_WQE_REACHED:
		break;
	case IBV_EVENT_SRQ_LIMIT_REACHED:
	case IBV_EVENT_SRQ_ERR:
		return;
	case IBV_EVENT_PORT_ACTIVE:
	case IBV_EVENT_PORT_ERR:
		break;
	default:
		break;
	}

	fprintf(stderr, "qelr_async_event not implemented yet cq=%p qp=%p\n",
		cq, qp);
}
