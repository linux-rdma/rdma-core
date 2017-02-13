/*
 * Broadcom NetXtreme-E User Space RoCE driver
 *
 * Copyright (c) 2015-2017, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Description: User IB-Verbs implementation
 */

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

#include "main.h"
#include "verbs.h"

int bnxt_re_query_device(struct ibv_context *ibvctx,
			 struct ibv_device_attr *dev_attr)
{
	struct ibv_query_device cmd;
	uint64_t fw_ver;
	int status;

	memset(dev_attr, 0, sizeof(struct ibv_device_attr));
	status = ibv_cmd_query_device(ibvctx, dev_attr, &fw_ver,
				      &cmd, sizeof(cmd));
	return status;
}

int bnxt_re_query_port(struct ibv_context *ibvctx, uint8_t port,
		       struct ibv_port_attr *port_attr)
{
	struct ibv_query_port cmd;

	memset(port_attr, 0, sizeof(struct ibv_port_attr));
	return ibv_cmd_query_port(ibvctx, port, port_attr, &cmd, sizeof(cmd));
}

struct ibv_pd *bnxt_re_alloc_pd(struct ibv_context *ibvctx)
{
	struct ibv_alloc_pd cmd;
	struct bnxt_re_pd_resp resp;
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ibvctx->device);
	struct bnxt_re_pd *pd;
	uint64_t dbr;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	memset(&resp, 0, sizeof(resp));
	if (ibv_cmd_alloc_pd(ibvctx, &pd->ibvpd, &cmd, sizeof(cmd),
			     &resp.resp, sizeof(resp)))
		goto out;

	pd->pdid = resp.pdid;
	dbr = *(uint64_t *)((uint32_t *)&resp + 3);

	/* Map DB page now. */
	cntx->udpi.dpindx = resp.dpi;
	cntx->udpi.dbpage = mmap(NULL, dev->pg_size, PROT_WRITE, MAP_SHARED,
				 ibvctx->cmd_fd, dbr);
	if (cntx->udpi.dbpage == MAP_FAILED) {
		(void)ibv_cmd_dealloc_pd(&pd->ibvpd);
		goto out;
	}
	pthread_spin_init(&cntx->udpi.db_lock, PTHREAD_PROCESS_PRIVATE);

	return &pd->ibvpd;
out:
	free(pd);
	return NULL;
}

int bnxt_re_free_pd(struct ibv_pd *ibvpd)
{
	struct bnxt_re_pd *pd = to_bnxt_re_pd(ibvpd);
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvpd->context);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(cntx->ibvctx.device);
	int status;

	status = ibv_cmd_dealloc_pd(ibvpd);
	if (status)
		return status;

	pthread_spin_destroy(&cntx->udpi.db_lock);
	if (cntx->udpi.dbpage && (cntx->udpi.dbpage != MAP_FAILED))
		munmap(cntx->udpi.dbpage, dev->pg_size);

	free(pd);

	return 0;
}

struct ibv_mr *bnxt_re_reg_mr(struct ibv_pd *ibvpd, void *sva, size_t len,
			      int access)
{
	struct bnxt_re_mr *mr;
	struct ibv_reg_mr cmd;
	struct bnxt_re_mr_resp resp;

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return NULL;

	if (ibv_cmd_reg_mr(ibvpd, sva, len, (uintptr_t)sva, access, &mr->ibvmr,
			   &cmd, sizeof(cmd), &resp.resp, sizeof(resp))) {
		free(mr);
		return NULL;
	}

	return &mr->ibvmr;
}

int bnxt_re_dereg_mr(struct ibv_mr *ibvmr)
{
	struct bnxt_re_mr *mr = (struct bnxt_re_mr *)ibvmr;
	int status;

	status = ibv_cmd_dereg_mr(ibvmr);
	if (status)
		return status;
	free(mr);

	return 0;
}

struct ibv_cq *bnxt_re_create_cq(struct ibv_context *ibvctx, int ncqe,
				 struct ibv_comp_channel *channel, int vec)
{
	struct bnxt_re_cq *cq;
	struct bnxt_re_cq_req cmd;
	struct bnxt_re_cq_resp resp;

	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ibvctx->device);

	if (ncqe > dev->max_cq_depth)
		return NULL;

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	cq->cqq.depth = roundup_pow_of_two(ncqe + 1);
	if (cq->cqq.depth > dev->max_cq_depth + 1)
		cq->cqq.depth = dev->max_cq_depth + 1;
	cq->cqq.stride = dev->cqe_size;
	if (bnxt_re_alloc_aligned(&cq->cqq, dev->pg_size))
		goto fail;

	pthread_spin_init(&cq->cqq.qlock, PTHREAD_PROCESS_PRIVATE);

	cmd.cq_va = (uintptr_t)cq->cqq.va;
	cmd.cq_handle = (uintptr_t)cq;

	memset(&resp, 0, sizeof(resp));
	if (ibv_cmd_create_cq(ibvctx, ncqe, channel, vec,
			      &cq->ibvcq, &cmd.cmd, sizeof(cmd),
			      &resp.resp, sizeof(resp)))
		goto cmdfail;

	cq->cqid = resp.cqid;
	cq->phase = resp.phase;
	cq->cqq.tail = resp.tail;
	cq->udpi = &cntx->udpi;

	return &cq->ibvcq;
cmdfail:
	bnxt_re_free_aligned(&cq->cqq);
fail:
	free(cq);
	return NULL;
}

int bnxt_re_resize_cq(struct ibv_cq *ibvcq, int ncqe)
{
	return -ENOSYS;
}

int bnxt_re_destroy_cq(struct ibv_cq *ibvcq)
{
	int status;
	struct bnxt_re_cq *cq = to_bnxt_re_cq(ibvcq);

	status = ibv_cmd_destroy_cq(ibvcq);
	if (status)
		return status;

	bnxt_re_free_aligned(&cq->cqq);
	free(cq);

	return 0;
}

int bnxt_re_poll_cq(struct ibv_cq *ibvcq, int nwc, struct ibv_wc *wc)
{
	return -ENOSYS;
}

void bnxt_re_cq_event(struct ibv_cq *ibvcq)
{

}

int bnxt_re_arm_cq(struct ibv_cq *ibvcq, int flags)
{
	return -ENOSYS;
}

static int bnxt_re_check_qp_limits(struct ibv_qp_init_attr *attr)
{
	return 0;
}

static void bnxt_re_free_queue_ptr(struct bnxt_re_qp *qp)
{
	if (qp->rqq)
		free(qp->rqq);
	if (qp->sqq)
		free(qp->sqq);
}

static int bnxt_re_alloc_queue_ptr(struct bnxt_re_qp *qp,
				   struct ibv_qp_init_attr *attr)
{
	qp->sqq = calloc(1, sizeof(struct bnxt_re_queue));
	if (!qp->sqq)
		return -ENOMEM;
	if (attr->srq)
		qp->srq = NULL;/*TODO: to_bnxt_re_srq(attr->srq);*/
	else {
		qp->rqq = calloc(1, sizeof(struct bnxt_re_queue));
		if (!qp->rqq) {
			free(qp->sqq);
			return -ENOMEM;
		}
	}

	return 0;
}

static void bnxt_re_free_queues(struct bnxt_re_qp *qp)
{
	if (qp->rwrid)
		free(qp->rwrid);
	pthread_spin_destroy(&qp->rqq->qlock);
	bnxt_re_free_aligned(qp->rqq);

	if (qp->swrid)
		free(qp->swrid);
	pthread_spin_destroy(&qp->sqq->qlock);
	bnxt_re_free_aligned(qp->sqq);
}

static int bnxt_re_alloc_queues(struct bnxt_re_qp *qp,
				struct ibv_qp_init_attr *attr,
				uint32_t pg_size) {
	struct bnxt_re_queue *que;
	uint32_t psn_depth;
	int ret;

	if (attr->cap.max_send_wr) {
		que = qp->sqq;
		que->stride = bnxt_re_get_sqe_sz();
		que->depth = roundup_pow_of_two(attr->cap.max_send_wr);
		/* psn_depth extra entries of size que->stride */
		psn_depth = (que->depth * sizeof(struct bnxt_re_psns)) /
			     que->stride;
		que->depth += psn_depth;
		ret = bnxt_re_alloc_aligned(qp->sqq, pg_size);
		if (ret)
			return ret;
		/* exclude psns depth*/
		que->depth -= psn_depth;
		/* start of spsn space sizeof(struct bnxt_re_psns) each. */
		qp->psns = (que->va + que->stride * que->depth);
		pthread_spin_init(&que->qlock, PTHREAD_PROCESS_PRIVATE);
		qp->swrid = calloc(que->depth, sizeof(uint64_t));
		if (!qp->swrid) {
			ret = -ENOMEM;
			goto fail;
		}
	}

	if (attr->cap.max_recv_wr && qp->rqq) {
		que = qp->rqq;
		que->stride = bnxt_re_get_rqe_sz();
		que->depth = roundup_pow_of_two(attr->cap.max_recv_wr);
		ret = bnxt_re_alloc_aligned(qp->rqq, pg_size);
		if (ret)
			goto fail;
		pthread_spin_init(&que->qlock, PTHREAD_PROCESS_PRIVATE);
		qp->rwrid = calloc(que->depth, sizeof(uint64_t));
		if (!qp->rwrid) {
			ret = -ENOMEM;
			goto fail;
		}
	}

	return 0;

fail:
	bnxt_re_free_queues(qp);
	return ret;
}

struct ibv_qp *bnxt_re_create_qp(struct ibv_pd *ibvpd,
				 struct ibv_qp_init_attr *attr)
{
	struct bnxt_re_qp *qp;
	struct bnxt_re_qp_req req;
	struct bnxt_re_qp_resp resp;

	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvpd->context);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(cntx->ibvctx.device);

	if (bnxt_re_check_qp_limits(attr))
		return NULL;

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;
	/* alloc queue pointers */
	if (bnxt_re_alloc_queue_ptr(qp, attr))
		goto fail;
	/* alloc queues */
	if (bnxt_re_alloc_queues(qp, attr, dev->pg_size))
		goto failq;
	/* Fill ibv_cmd */
	req.qpsva = (uintptr_t)qp->sqq->va;
	req.qprva = qp->rqq ? (uintptr_t)qp->rqq->va : 0;
	req.qp_handle = (uintptr_t)qp;

	if (ibv_cmd_create_qp(ibvpd, &qp->ibvqp, attr, &req.cmd, sizeof(req),
			      &resp.resp, sizeof(resp))) {
		goto failcmd;
	}

	qp->qpid = resp.qpid;
	qp->qptyp = attr->qp_type;
	qp->qpst = IBV_QPS_RESET;
	qp->scq = to_bnxt_re_cq(attr->send_cq);
	qp->rcq = to_bnxt_re_cq(attr->recv_cq);
	qp->udpi = &cntx->udpi;

	return &qp->ibvqp;
failcmd:
	bnxt_re_free_queues(qp);
failq:
	bnxt_re_free_queue_ptr(qp);
fail:
	free(qp);

	return NULL;
}

int bnxt_re_modify_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr,
		      int attr_mask)
{
	struct ibv_modify_qp cmd = {};
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	int rc;

	rc = ibv_cmd_modify_qp(ibvqp, attr, attr_mask, &cmd, sizeof(cmd));
	if (!rc)
		qp->qpst = ibvqp->state;

	return rc;
}

int bnxt_re_query_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr,
		     int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	int rc;

	rc = ibv_cmd_query_qp(ibvqp, attr, attr_mask, init_attr,
			      &cmd, sizeof(cmd));
	if (!rc)
		qp->qpst = ibvqp->state;

	return rc;
}

int bnxt_re_destroy_qp(struct ibv_qp *ibvqp)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	int status;

	status = ibv_cmd_destroy_qp(ibvqp);
	if (status)
		return status;

	bnxt_re_free_queues(qp);
	bnxt_re_free_queue_ptr(qp);
	free(qp);

	return 0;
}

int bnxt_re_post_send(struct ibv_qp *ibvqp, struct ibv_send_wr *wr,
		      struct ibv_send_wr **bad)
{
	return -ENOSYS;
}

int bnxt_re_post_recv(struct ibv_qp *ibvqp, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad)
{
	return -ENOSYS;
}

struct ibv_srq *bnxt_re_create_srq(struct ibv_pd *ibvpd,
				   struct ibv_srq_init_attr *attr)
{
	return NULL;
}

int bnxt_re_modify_srq(struct ibv_srq *ibvsrq, struct ibv_srq_attr *attr,
		       int init_attr)
{
	return -ENOSYS;
}

int bnxt_re_destroy_srq(struct ibv_srq *ibvsrq)
{
	return -ENOSYS;
}

int bnxt_re_query_srq(struct ibv_srq *ibvsrq, struct ibv_srq_attr *attr)
{
	return -ENOSYS;
}

int bnxt_re_post_srq_recv(struct ibv_srq *ibvsrq, struct ibv_recv_wr *wr,
			  struct ibv_recv_wr **bad)
{
	return -ENOSYS;
}

struct ibv_ah *bnxt_re_create_ah(struct ibv_pd *ibvpd, struct ibv_ah_attr *attr)
{
	return NULL;
}

int bnxt_re_destroy_ah(struct ibv_ah *ibvah)
{
	return -ENOSYS;
}
