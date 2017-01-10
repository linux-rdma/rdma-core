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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <malloc.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <unistd.h>

#include "qelr.h"
#include "qelr_abi.h"
#include "qelr_chain.h"
#include "qelr_verbs.h"

#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>

/* Fast path debug prints */
#define FP_DP_VERBOSE(...)
/* #define FP_DP_VERBOSE(...)	DP_VERBOSE(__VA_ARGS__) */

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
	struct qelr_alloc_pd_req cmd;
	struct qelr_alloc_pd_resp resp;
	struct qelr_pd *pd;
	struct qelr_devctx *cxt = get_qelr_ctx(context);

	pd = malloc(sizeof(*pd));
	if (!pd)
		return NULL;

	bzero(pd, sizeof(*pd));
	memset(&cmd, 0, sizeof(cmd));

	if (ibv_cmd_alloc_pd(context, &pd->ibv_pd, &cmd.cmd, sizeof(cmd),
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

struct ibv_mr *qelr_reg_mr(struct ibv_pd *ibpd, void *addr,
			   size_t len, int access)
{
	struct qelr_mr *mr;
	struct ibv_reg_mr cmd;
	struct qelr_reg_mr_resp resp;
	struct qelr_pd *pd = get_qelr_pd(ibpd);
	struct qelr_devctx *cxt = get_qelr_ctx(ibpd->context);

	uint64_t hca_va = (uintptr_t) addr;

	mr = malloc(sizeof(*mr));
	if (!mr)
		return NULL;

	bzero(mr, sizeof(*mr));

	if (ibv_cmd_reg_mr(ibpd, addr, len, hca_va,
			   access, &mr->ibv_mr, &cmd, sizeof(cmd),
			   &resp.ibv_resp, sizeof(resp))) {
		free(mr);
		return NULL;
	}

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_MR,
		   "MR Register %p completed succesfully pd_id=%d addr=%p len=%zu access=%d lkey=%x rkey=%x\n",
		   mr, pd->pd_id, addr, len, access, mr->ibv_mr.lkey,
		   mr->ibv_mr.rkey);

	return &mr->ibv_mr;
}

int qelr_dereg_mr(struct ibv_mr *mr)
{
	struct qelr_devctx *cxt = get_qelr_ctx(mr->context);
	int rc;

	rc = ibv_cmd_dereg_mr(mr);
	if (rc)
		return rc;

	free(mr);

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_MR,
		   "MR DERegister %p completed succesfully\n", mr);
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
	struct qelr_create_cq_resp resp;
	struct qelr_create_cq_req cmd;
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
	free(cq);

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
		   "destroy cq: successfully destroyed %p\n", cq);

	return 0;
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
		DP_ERR(cxt->dbg_fp, "create qp: failed to map SQ, got %d", rc);

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
	qp->rq.max_wr = max_recv_wr;
	qp->rq.max_sges = RDMA_MAX_SGE_PER_RQ_WQE;

	chain_size = max_recv_buf;
	rc = qelr_chain_alloc(&qp->rq.chain, chain_size, cxt->kernel_page_size,
			      QELR_RQE_ELEMENT_SIZE);
	if (rc)
		DP_ERR(cxt->dbg_fp, "create qp: failed to map RQ, got %d", rc);

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

	/* shadow SQ */
	qp->wqe_wr_id = calloc(qp->sq.max_wr, sizeof(*qp->wqe_wr_id));
	if (!qp->wqe_wr_id) {
		DP_ERR(cxt->dbg_fp,
		       "create qp: failed shdow SQ memory allocation\n");
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
	qp->rq.prod = 0;

	/* shadow RQ */
	qp->rqe_wr_id = calloc(qp->rq.max_wr, sizeof(*qp->rqe_wr_id));
	if (!qp->rqe_wr_id) {
		DP_ERR(cxt->dbg_fp,
		       "create qp: failed shdow RQ memory allocation\n");
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
				struct qelr_create_qp_req *req)
{
	req->sq_addr = (uintptr_t)qp->sq.chain.first_addr;
	req->sq_len = qp->sq.chain.size;
}

static inline void
qelr_create_qp_configure_rq_req(struct qelr_qp *qp,
				struct qelr_create_qp_req *req)
{
	req->rq_addr = (uintptr_t)qp->rq.chain.first_addr;
	req->rq_len = qp->rq.chain.size;
}

static inline void
qelr_create_qp_configure_req(struct qelr_qp *qp,
			     struct qelr_create_qp_req *req)
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
	struct qelr_create_qp_resp resp;
	struct qelr_create_qp_req req;
	struct qelr_qp *qp;
	int rc;

	qelr_print_qp_init_attr(cxt, attrs);

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	rc = qelr_create_qp_buffers(cxt, qp, attrs);
	if (rc)
		goto err0;

	qelr_create_qp_configure_req(qp, &req);

	rc = ibv_cmd_create_qp(pd, &qp->ibv_qp, attrs, &req.ibv_qp, sizeof(req),
			       &resp.ibv_resp, sizeof(resp));
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
		   attr->grh.dgid.global.interface_id,
		   attr->grh.dgid.global.subnet_prefix,
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
			wmb();
			writel(qp->rq.db_data.raw, qp->rq.db);
			wc_wmb();
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
	int rc;

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_QP, "QP Modify %p, attr_mask=0x%x\n",
		   qp, attr_mask);

	qelr_print_qp_attr(cxt, attr);

	rc = ibv_cmd_modify_qp(ibqp, attr, attr_mask, &cmd, sizeof(cmd));

	if (!rc && (attr_mask & IBV_QP_STATE)) {
		DP_VERBOSE(cxt->dbg_fp, QELR_MSG_QP, "QP Modify state %d->%d\n",
			   qp->state, attr->qp_state);
		qelr_update_qp_state(qp, attr->qp_state);
	}

	return rc;
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
	free(qp);

	DP_VERBOSE(cxt->dbg_fp, QELR_MSG_QP,
		   "destroy cq: succesfully destroyed %p\n", qp);

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
	int i;

	for (i = 0; i < ROCE_WQE_ELEM_SIZE / sizeof(uint64_t); i++, p++)
		*p = htobe64(htole64(*p));
}

static void qelr_init_edpm_info(struct qelr_qp *qp, struct qelr_devctx *cxt)
{
	memset(&qp->edpm, 0, sizeof(qp->edpm));

	qp->edpm.rdma_ext = (struct qelr_rdma_ext *)&qp->edpm.dpm_payload;
	if (qelr_chain_is_full(&qp->sq.chain))
		qp->edpm.is_edpm = 1;
}

#define QELR_IB_OPCODE_SEND_ONLY                         0x04
#define QELR_IB_OPCODE_SEND_ONLY_WITH_IMMEDIATE          0x05
#define QELR_IB_OPCODE_RDMA_WRITE_ONLY                   0x0a
#define QELR_IB_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE    0x0b
#define QELR_IS_IMM(opcode) \
	((opcode == QELR_IB_OPCODE_SEND_ONLY_WITH_IMMEDIATE) || \
	 (opcode == QELR_IB_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE))

static inline void qelr_edpm_set_msg_data(struct qelr_qp *qp,
					  uint8_t opcode,
					  uint16_t length,
					  uint8_t se,
					  uint8_t comp)
{
	uint32_t wqe_size = length +
		(QELR_IS_IMM(opcode) ? sizeof(uint32_t) : 0);
	uint32_t dpm_size = wqe_size + sizeof(struct db_roce_dpm_data);

	if (!qp->edpm.is_edpm)
		return;

	SET_FIELD(qp->edpm.msg.data.params.params,
		  DB_ROCE_DPM_PARAMS_SIZE,
		  (dpm_size + sizeof(uint64_t) - 1) / sizeof(uint64_t));

	SET_FIELD(qp->edpm.msg.data.params.params,
		  DB_ROCE_DPM_PARAMS_DPM_TYPE, DPM_ROCE);

	SET_FIELD(qp->edpm.msg.data.params.params,
		  DB_ROCE_DPM_PARAMS_OPCODE,
		  opcode);

	SET_FIELD(qp->edpm.msg.data.params.params,
		  DB_ROCE_DPM_PARAMS_WQE_SIZE,
		  wqe_size);

	SET_FIELD(qp->edpm.msg.data.params.params,
		  DB_ROCE_DPM_PARAMS_COMPLETION_FLG, comp ? 1 : 0);

	SET_FIELD(qp->edpm.msg.data.params.params,
		  DB_ROCE_DPM_PARAMS_S_FLG,
		  se ? 1 : 0);
}

static inline void qelr_edpm_set_inv_imm(struct qelr_qp *qp,
					 uint32_t inv_key_or_imm_data)
{
	if (!qp->edpm.is_edpm)
		return;

	memcpy(&qp->edpm.dpm_payload[qp->edpm.dpm_payload_offset],
	       &inv_key_or_imm_data, sizeof(inv_key_or_imm_data));

	qp->edpm.dpm_payload_offset += sizeof(inv_key_or_imm_data);
	qp->edpm.dpm_payload_size += sizeof(inv_key_or_imm_data);
}

static inline void qelr_edpm_set_rdma_ext(struct qelr_qp *qp,
					  uint64_t remote_addr,
					  uint32_t rkey)
{
	if (!qp->edpm.is_edpm)
		return;

	qp->edpm.rdma_ext->remote_va = htonll(remote_addr);
	qp->edpm.rdma_ext->remote_key = htonl(rkey);
	qp->edpm.dpm_payload_offset += sizeof(*qp->edpm.rdma_ext);
	qp->edpm.dpm_payload_size += sizeof(*qp->edpm.rdma_ext);
}

static inline void qelr_edpm_set_payload(struct qelr_qp *qp, char *buf,
					 uint32_t length)
{
	if (!qp->edpm.is_edpm)
		return;

	memcpy(&qp->edpm.dpm_payload[qp->edpm.dpm_payload_offset],
	       buf,
	       length);

	qp->edpm.dpm_payload_offset += length;
}

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

static uint32_t qelr_prepare_sq_inline_data(struct qelr_qp *qp,
					    uint8_t *wqe_size,
					    struct ibv_send_wr *wr,
					    struct ibv_send_wr **bad_wr,
					    uint8_t *bits, uint8_t bit)
{
	int i, seg_siz;
	char *seg_prt, *wqe;
	uint32_t data_size = sge_data_len(wr->sg_list, wr->num_sge);

	if (data_size > ROCE_REQ_MAX_INLINE_DATA_SIZE) {
		DP_ERR(stderr, "Too much inline data in WR: %d\n", data_size);
		*bad_wr = wr;
		return 0;
	}

	if (!data_size)
		return data_size;

	/* set the bit */
	*bits |= bit;

	seg_prt = NULL;
	wqe = NULL;
	seg_siz = 0;

	/* copy data inline */
	for (i = 0; i < wr->num_sge; i++) {
		uint32_t len = wr->sg_list[i].length;
		void *src = (void *)(uintptr_t)wr->sg_list[i].addr;

		qelr_edpm_set_payload(qp, src, wr->sg_list[i].length);

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
			cur = MIN(len, seg_siz);

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

	if (qp->edpm.is_edpm) {
		qp->edpm.dpm_payload_size += data_size;

		if (wr->opcode == IBV_WR_RDMA_WRITE ||
		    wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
			qp->edpm.rdma_ext->dma_length = htonl(data_size);
	}

	return data_size;
}

static uint32_t qelr_prepare_sq_sges(struct qelr_qp *qp,
				     uint8_t *wqe_size,
				     struct ibv_send_wr *wr)
{
	uint32_t data_size = 0;
	int i;

	for (i = 0; i < wr->num_sge; i++) {
		struct rdma_sq_sge *sge = qelr_chain_produce(&qp->sq.chain);

		TYPEPTR_ADDR_SET(sge, addr, wr->sg_list[i].addr);
		sge->l_key = htole32(wr->sg_list[i].lkey);
		sge->length = htole32(wr->sg_list[i].length);
		data_size += wr->sg_list[i].length;
	}

	if (wqe_size)
		*wqe_size += wr->num_sge;

	return data_size;
}

static uint32_t qelr_prepare_sq_rdma_data(struct qelr_qp *qp,
					  struct rdma_sq_rdma_wqe_1st *rwqe,
					  struct rdma_sq_rdma_wqe_2nd *rwqe2,
					  struct ibv_send_wr *wr,
					  struct ibv_send_wr **bad_wr)
{
	memset(rwqe2, 0, sizeof(*rwqe2));
	rwqe2->r_key = htole32(wr->wr.rdma.rkey);
	TYPEPTR_ADDR_SET(rwqe2, remote_va, wr->wr.rdma.remote_addr);

	if (wr->send_flags & IBV_SEND_INLINE &&
	    (wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM ||
	     wr->opcode == IBV_WR_RDMA_WRITE)) {
		uint8_t flags = 0;

		SET_FIELD2(flags, RDMA_SQ_RDMA_WQE_1ST_INLINE_FLG, 1);
		return qelr_prepare_sq_inline_data(qp, &rwqe->wqe_size, wr,
						   bad_wr, &rwqe->flags, flags);
	}
	/* else */
	qp->edpm.is_edpm = 0;

	return qelr_prepare_sq_sges(qp, &rwqe->wqe_size, wr);
}

static uint32_t qelr_prepare_sq_send_data(struct qelr_qp *qp,
					  struct rdma_sq_send_wqe_1st *swqe,
					  struct rdma_sq_send_wqe_2st *swqe2,
					  struct ibv_send_wr *wr,
					  struct ibv_send_wr **bad_wr)
{
	memset(swqe2, 0, sizeof(*swqe2));
	if (wr->send_flags & IBV_SEND_INLINE) {
		uint8_t flags = 0;

		SET_FIELD2(flags, RDMA_SQ_SEND_WQE_INLINE_FLG, 1);
		return qelr_prepare_sq_inline_data(qp, &swqe->wqe_size, wr,
						   bad_wr, &swqe->flags, flags);
	}

	qp->edpm.is_edpm = 0;

	/* else */

	return qelr_prepare_sq_sges(qp, &swqe->wqe_size, wr);
}

static enum ibv_wc_opcode qelr_ibv_to_wc_opcode(enum ibv_wr_opcode opcode)
{
	switch (opcode) {
	case IBV_WR_RDMA_WRITE:
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		return IBV_WC_RDMA_WRITE;
	case IBV_WR_SEND_WITH_IMM:
	case IBV_WR_SEND:
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

static void doorbell_edpm_qp(struct qelr_qp *qp)
{
	uint32_t offset = 0;
	uint64_t data;
	uint64_t *dpm_payload = (uint64_t *)qp->edpm.dpm_payload;
	uint32_t num_dwords;
	int bytes = 0;

	if (!qp->edpm.is_edpm)
		return;

	wmb();

	qp->edpm.msg.data.icid = qp->sq.db_data.data.icid;
	qp->edpm.msg.data.prod_val = qp->sq.db_data.data.value;

	writeq(qp->edpm.msg.raw, qp->sq.edpm_db);

	bytes += sizeof(uint64_t);

	num_dwords = (qp->edpm.dpm_payload_size + sizeof(uint64_t) - 1) /
		sizeof(uint64_t);

	while (offset < num_dwords) {
		data = dpm_payload[offset];

		writeq(data,
		       qp->sq.edpm_db + sizeof(qp->edpm.msg.data) + offset *
		       sizeof(uint64_t));

		bytes += sizeof(uint64_t);
		/* Need to place a barrier after every 64 bytes */
		if (bytes == 64) {
			wc_wmb();
			bytes = 0;
		}
		offset++;
	}

	wc_wmb();
}

int qelr_post_send(struct ibv_qp *ib_qp, struct ibv_send_wr *wr,
		   struct ibv_send_wr **bad_wr)
{
	int status = 0;
	struct qelr_qp *qp = get_qelr_qp(ib_qp);
	struct qelr_devctx *cxt = get_qelr_ctx(ib_qp->context);
	uint8_t se, comp, fence;
	uint16_t db_val;
	*bad_wr = NULL;

	pthread_spin_lock(&qp->q_lock);

	if (qp->state != QELR_QPS_RTS && qp->state != QELR_QPS_SQD) {
		pthread_spin_unlock(&qp->q_lock);
		*bad_wr = wr;
		return -EINVAL;
	}

	while (wr) {
		struct rdma_sq_common_wqe *wqe;
		struct rdma_sq_send_wqe_1st *swqe;
		struct rdma_sq_send_wqe_2st *swqe2;
		struct rdma_sq_rdma_wqe_1st *rwqe;
		struct rdma_sq_rdma_wqe_2nd *rwqe2;
		struct rdma_sq_atomic_wqe_1st *awqe1;
		struct rdma_sq_atomic_wqe_2nd *awqe2;
		struct rdma_sq_atomic_wqe_3rd *awqe3;

		if ((qelr_chain_get_elem_left_u32(&qp->sq.chain) <
					QELR_MAX_SQ_WQE_SIZE) ||
		     (wr->num_sge > qp->sq.max_sges)) {
			status = -ENOMEM;
			*bad_wr = wr;
			break;
		}

		qelr_init_edpm_info(qp, cxt);

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

		qp->wqe_wr_id[qp->sq.prod].opcode =
		qelr_ibv_to_wc_opcode(wr->opcode);

		switch (wr->opcode) {
		case IBV_WR_SEND_WITH_IMM:
			wqe->req_type = RDMA_SQ_REQ_TYPE_SEND_WITH_IMM;
			swqe = (struct rdma_sq_send_wqe_1st *)wqe;

			swqe->wqe_size = 2;
			swqe2 = (struct rdma_sq_send_wqe_2st *)
					qelr_chain_produce(&qp->sq.chain);
			swqe->inv_key_or_imm_data =
					htonl(htole32(wr->imm_data));
			qelr_edpm_set_inv_imm(qp, swqe->inv_key_or_imm_data);
			swqe->length = htole32(
					qelr_prepare_sq_send_data(qp, swqe,
								  swqe2, wr,
								  bad_wr));
			qelr_edpm_set_msg_data(qp,
					       QELR_IB_OPCODE_SEND_ONLY_WITH_IMMEDIATE,
					       swqe->length,
					       se, comp);
			qp->wqe_wr_id[qp->sq.prod].wqe_size = swqe->wqe_size;
			qp->prev_wqe_size = swqe->wqe_size;
			qp->wqe_wr_id[qp->sq.prod].bytes_len = swqe->length;
			FP_DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
				      "SEND w/ IMM length = %d imm data=%x\n",
				      swqe->length, wr->imm_data);
			break;

		case IBV_WR_SEND:
			wqe->req_type = RDMA_SQ_REQ_TYPE_SEND;
			swqe = (struct rdma_sq_send_wqe_1st *)wqe;

			swqe->wqe_size = 2;
			swqe2 = (struct rdma_sq_send_wqe_2st *)
					qelr_chain_produce(&qp->sq.chain);
			swqe->length = htole32(
					qelr_prepare_sq_send_data(qp, swqe,
								  swqe2, wr,
								  bad_wr));
			qelr_edpm_set_msg_data(qp, QELR_IB_OPCODE_SEND_ONLY,
					       swqe->length,
					       se, comp);
			qp->wqe_wr_id[qp->sq.prod].wqe_size = swqe->wqe_size;
			qp->prev_wqe_size = swqe->wqe_size;
			qp->wqe_wr_id[qp->sq.prod].bytes_len = swqe->length;
			FP_DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
				      "SEND w/o IMM length = %d\n",
				      swqe->length);
			break;

		case IBV_WR_RDMA_WRITE_WITH_IMM:
			wqe->req_type = RDMA_SQ_REQ_TYPE_RDMA_WR_WITH_IMM;
			rwqe = (struct rdma_sq_rdma_wqe_1st *)wqe;

			rwqe->wqe_size = 2;
			rwqe->imm_data = htonl(htole32(wr->imm_data));
			qelr_edpm_set_rdma_ext(qp, wr->wr.rdma.remote_addr,
					       wr->wr.rdma.rkey);
			qelr_edpm_set_inv_imm(qp, rwqe->imm_data);
			rwqe2 = (struct rdma_sq_rdma_wqe_2nd *)
					qelr_chain_produce(&qp->sq.chain);
			rwqe->length = htole32(
					qelr_prepare_sq_rdma_data(qp, rwqe,
								  rwqe2, wr,
								  bad_wr));
			qelr_edpm_set_msg_data(qp,
					       QELR_IB_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE,
					       rwqe->length + sizeof(*qp->edpm.rdma_ext),
					       se, comp);
			qp->wqe_wr_id[qp->sq.prod].wqe_size = rwqe->wqe_size;
			qp->prev_wqe_size = rwqe->wqe_size;
			qp->wqe_wr_id[qp->sq.prod].bytes_len = rwqe->length;
			FP_DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
				      "RDMA WRITE w/ IMM length = %d imm data=%x\n",
				      rwqe->length, rwqe->imm_data);
			break;

		case IBV_WR_RDMA_WRITE:
			wqe->req_type = RDMA_SQ_REQ_TYPE_RDMA_WR;
			rwqe = (struct rdma_sq_rdma_wqe_1st *)wqe;

			rwqe->wqe_size = 2;
			qelr_edpm_set_rdma_ext(qp, wr->wr.rdma.remote_addr,
					       wr->wr.rdma.rkey);
			rwqe2 = (struct rdma_sq_rdma_wqe_2nd *)
					qelr_chain_produce(&qp->sq.chain);
			rwqe->length = htole32(
				qelr_prepare_sq_rdma_data(qp, rwqe, rwqe2, wr,
							  bad_wr));
			qelr_edpm_set_msg_data(qp,
					       QELR_IB_OPCODE_RDMA_WRITE_ONLY,
					       rwqe->length + sizeof(*qp->edpm.rdma_ext),
					       se, comp);
			qp->wqe_wr_id[qp->sq.prod].wqe_size = rwqe->wqe_size;
			qp->prev_wqe_size = rwqe->wqe_size;
			qp->wqe_wr_id[qp->sq.prod].bytes_len = rwqe->length;
			FP_DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
				      "RDMA WRITE w/o IMM length = %d\n",
				      rwqe->length);
			break;

		case IBV_WR_RDMA_READ:
			wqe->req_type = RDMA_SQ_REQ_TYPE_RDMA_RD;
			rwqe = (struct rdma_sq_rdma_wqe_1st *)wqe;

			rwqe->wqe_size = 2;
			rwqe2 = (struct rdma_sq_rdma_wqe_2nd *)
					qelr_chain_produce(&qp->sq.chain);
			rwqe->length = htole32(
					qelr_prepare_sq_rdma_data(qp, rwqe,
								  rwqe2, wr,
								  bad_wr));

			qp->wqe_wr_id[qp->sq.prod].wqe_size = rwqe->wqe_size;
			qp->prev_wqe_size = rwqe->wqe_size;
			qp->wqe_wr_id[qp->sq.prod].bytes_len = rwqe->length;
			FP_DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
				      "RDMA READ length = %d\n", rwqe->length);
			break;

		case IBV_WR_ATOMIC_CMP_AND_SWP:
		case IBV_WR_ATOMIC_FETCH_AND_ADD:
			FP_DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ, "ATOMIC\n");
			if (!qp->atomic_supported) {
				DP_ERR(cxt->dbg_fp,
				       "Atomic not supported on this machine\n");
				status = -EINVAL;
				*bad_wr = wr;
				break;
			}
			awqe1 = (struct rdma_sq_atomic_wqe_1st *)wqe;
			awqe1->wqe_size = 4;

			awqe2 = (struct rdma_sq_atomic_wqe_2nd *)
					qelr_chain_produce(&qp->sq.chain);
			TYPEPTR_ADDR_SET(awqe2, remote_va,
					 wr->wr.atomic.remote_addr);
			awqe2->r_key = htole32(wr->wr.atomic.rkey);

			awqe3 = (struct rdma_sq_atomic_wqe_3rd *)
				qelr_chain_produce(&qp->sq.chain);

			if (wr->opcode == IBV_WR_ATOMIC_FETCH_AND_ADD) {
				wqe->req_type = RDMA_SQ_REQ_TYPE_ATOMIC_ADD;
				TYPEPTR_ADDR_SET(awqe3, swap_data,
						 wr->wr.atomic.compare_add);
			} else {
				wqe->req_type =
					RDMA_SQ_REQ_TYPE_ATOMIC_CMP_AND_SWAP;
				TYPEPTR_ADDR_SET(awqe3, swap_data,
						 wr->wr.atomic.swap);
				TYPEPTR_ADDR_SET(awqe3, cmp_data,
						 wr->wr.atomic.compare_add);
			}

			qelr_prepare_sq_sges(qp, NULL, wr);

			qp->wqe_wr_id[qp->sq.prod].wqe_size = awqe1->wqe_size;
			qp->prev_wqe_size = awqe1->wqe_size;

			break;

		default:
			*bad_wr = wr;
			break;
		}

		if (*bad_wr) {
			/* restore prod to its position before this WR was
			 * processed
			 */
			qelr_chain_set_prod(&qp->sq.chain,
					    le16toh(qp->sq.db_data.data.value),
					    wqe);
			/* restore prev_wqe_size */
			qp->prev_wqe_size = wqe->prev_wqe_size;
			status = -EINVAL;
			DP_ERR(cxt->dbg_fp, "POST SEND FAILED\n");
			break; /* out of the loop */
		}

		qp->wqe_wr_id[qp->sq.prod].wr_id = wr->wr_id;

		qelr_inc_sw_prod_u16(&qp->sq);

		db_val = le16toh(qp->sq.db_data.data.value) + 1;
		qp->sq.db_data.data.value = htole16(db_val);

		wr = wr->next;

		/* Doorbell */
		doorbell_edpm_qp(qp);
	}

	if (!qp->edpm.is_edpm) {
		wmb();

		writel(qp->sq.db_data.raw, qp->sq.db);

		wc_wmb();
	}

	pthread_spin_unlock(&qp->q_lock);

	return status;
}

int qelr_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		   struct ibv_recv_wr **bad_wr)
{
	int status = 0;
	struct qelr_qp *qp =  get_qelr_qp(ibqp);
	struct qelr_devctx *cxt = get_qelr_ctx(ibqp->context);
	uint16_t db_val;

	pthread_spin_lock(&qp->q_lock);

	if (qp->state == QELR_QPS_RST || qp->state == QELR_QPS_ERR) {
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
		FP_DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
			      "RQ WR: SGEs: %d with wr_id[%d] = %lx\n",
			      wr->num_sge, qp->rq.prod, wr->wr_id);
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
			FP_DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
				      "[%d]: len %d key %x addr %x:%x\n", i,
				      rqe->length, rqe->flags,
				      rqe->first_addr.hi, rqe->first_addr.lo);
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

		wmb();

		db_val = le16toh(qp->rq.db_data.data.value) + 1;
		qp->rq.db_data.data.value = htole16(db_val);

		writel(qp->rq.db_data.raw, qp->rq.db);

		wc_wmb();

		wr = wr->next;
	}

	FP_DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ, "POST: Elements in RespQ: %d\n",
		      qelr_chain_get_elem_left_u32(&qp->rq.chain));
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

	return (struct qelr_qp *)HILO_U64(qph->hi, qph->lo);
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
	int cnt = 0;

	switch (req->status) {
	case RDMA_CQE_REQ_STS_OK:
		cnt = process_req(qp, cq, num_entries, wc, req->sq_cons,
				  IBV_WC_SUCCESS, 0);
		break;
	case RDMA_CQE_REQ_STS_WORK_REQUEST_FLUSHED_ERR:
		DP_ERR(cxt->dbg_fp,
		       "Error: POLL CQ with ROCE_CQE_REQ_STS_WORK_REQUEST_FLUSHED_ERR. QP icid=0x%x\n",
		       qp->sq.icid);
		cnt = process_req(qp, cq, num_entries, wc, req->sq_cons,
				  IBV_WC_WR_FLUSH_ERR, 0);
		break;
	default: /* other errors case */
		/* process all WQE before the consumer */
		qp->state = QELR_QPS_ERR;
		cnt = process_req(qp, cq, num_entries, wc, req->sq_cons - 1,
				  IBV_WC_SUCCESS, 0);
		wc += cnt;
		/* if we have extra WC fill it with actual error info */
		if (cnt < num_entries) {
			enum ibv_wc_status wc_status;

			switch (req->status) {
			case	RDMA_CQE_REQ_STS_BAD_RESPONSE_ERR:
				DP_ERR(cxt->dbg_fp,
				       "Error: POLL CQ with RDMA_CQE_REQ_STS_BAD_RESPONSE_ERR. QP icid=0x%x\n",
				       qp->sq.icid);
				wc_status = IBV_WC_BAD_RESP_ERR;
				break;
			case	RDMA_CQE_REQ_STS_LOCAL_LENGTH_ERR:
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

			cnt += process_req(qp, cq, 1, wc, req->sq_cons,
					   wc_status, 1 /* force use of WC */);
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
	wc->wc_flags = 0;

	FP_DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ, "\n");

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
			/* fall to set imm data */
		case QELR_RESP_IMM:
			wc->imm_data =
				ntohl(le32toh(resp->imm_data_or_inv_r_Key));
			wc->wc_flags |= IBV_WC_WITH_IMM;
			FP_DP_VERBOSE(cxt->dbg_fp, QELR_MSG_CQ,
				      "POLL CQ RQ2: RESP_RDMA_IMM imm_data = %x resp_len=%d\n",
				      wc->imm_data, wc->byte_len);
			break;
		case QELR_RESP_RDMA:
			DP_ERR(cxt->dbg_fp, "Invalid flags detected\n");
			break;
		default:
			/* valid configuration, but nothing to do here */
			break;
		}

		wc->wr_id = wr_id;
		break;
	default:
		wc->status = IBV_WC_GENERAL_ERR;
		DP_ERR(cxt->dbg_fp, "Invalid CQE status detected\n");
	}

	/* fill WC */
	wc->status = wc_status;
	wc->qp_num = qp->qp_id;
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
	if (le16toh(req->sq_cons) == qp->sq.wqe_cons) {
		consume_cqe(cq);
		*update |= 1;
	}
}

/* used with flush only, when resp->rq_cons is valid */
static void try_consume_resp_cqe(struct qelr_cq *cq, struct qelr_qp *qp,
				 struct rdma_cqe_responder *resp, int *update)
{
	if (le16toh(resp->rq_cons) == qp->rq.wqe_cons) {
		consume_cqe(cq);
		*update |= 1;
	}
}

static int qelr_poll_cq_resp(struct qelr_qp *qp, struct qelr_cq *cq,
			     int num_entries, struct ibv_wc *wc,
			     struct rdma_cqe_responder *resp, int *update)
{
	int cnt;

	if (resp->status == RDMA_CQE_RESP_STS_WORK_REQUEST_FLUSHED_ERR) {
		cnt = process_resp_flush(qp, cq, num_entries, wc,
					 resp->rq_cons);
		try_consume_resp_cqe(cq, qp, resp, update);
	} else {
		cnt = process_resp_one(qp, cq, wc, resp);
		consume_cqe(cq);
		*update |= 1;
	}

	return cnt;
}

static void doorbell_cq(struct qelr_cq *cq, uint32_t cons, uint8_t flags)
{
	wmb();
	cq->db.data.agg_flags = flags;
	cq->db.data.value = htole32(cons);

	writeq(cq->db.raw, cq->db_addr);
	wc_wmb();
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
		rmb();

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
		FP_DP_VERBOSE(stderr, QELR_MSG_CQ, "doorbell_cq cons=%x\n",
			      db_cons);
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
	FP_DP_VERBOSE(get_qelr_ctx(ibcq->context)->dbg_fp, QELR_MSG_CQ,
		      "Arm CQ cons=%x solicited=%d\n", db_cons, solicited);

	cq->arm_flags = solicited ? DQ_UCM_ROCE_CQ_ARM_SE_CF_CMD :
				    DQ_UCM_ROCE_CQ_ARM_CF_CMD;

	doorbell_cq(cq, db_cons, cq->arm_flags);

	return 0;
}

void qelr_async_event(struct ibv_async_event *event)
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
	case IBV_EVENT_PORT_ACTIVE:
	case IBV_EVENT_PORT_ERR:
		break;
	default:
		break;
	}

	fprintf(stderr, "qelr_async_event not implemented yet cq=%p qp=%p\n",
		cq, qp);
}
