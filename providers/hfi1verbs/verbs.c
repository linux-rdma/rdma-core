/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2015 Intel Corporation.

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  Contact Information:
  Intel Corporation
  www.intel.com

  BSD LICENSE

  Copyright(c) 2015 Intel Corporation.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  Copyright (C) 2006-2009 QLogic Corporation, All rights reserved.
  Copyright (c) 2005. PathScale, Inc. All rights reserved.

*/

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <errno.h>

#include "hfiverbs.h"
#include "hfi-abi.h"

int hfi1_query_device(struct ibv_context *context,
		       struct ibv_device_attr *attr)
{
	struct ibv_query_device cmd;
	uint64_t raw_fw_ver;
	unsigned major, minor, sub_minor;
	int ret;

	ret = ibv_cmd_query_device(context, attr, &raw_fw_ver,
				   &cmd, sizeof cmd);
	if (ret)
		return ret;

	major     = (raw_fw_ver >> 32) & 0xffff;
	minor     = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(attr->fw_ver, sizeof attr->fw_ver,
		 "%d.%d.%d", major, minor, sub_minor);

	return 0;
}

int hfi1_query_port(struct ibv_context *context, uint8_t port,
		     struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof cmd);
}

struct ibv_pd *hfi1_alloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd	  cmd;
	struct ib_uverbs_alloc_pd_resp  resp;
	struct ibv_pd		 *pd;

	pd = malloc(sizeof *pd);
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, pd, &cmd, sizeof cmd,
			     &resp, sizeof resp)) {
		free(pd);
		return NULL;
	}

	return pd;
}

int hfi1_free_pd(struct ibv_pd *pd)
{
	int ret;

	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	free(pd);
	return 0;
}

struct ibv_mr *hfi1_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			   uint64_t hca_va, int access)
{
	struct verbs_mr *vmr;
	struct ibv_reg_mr cmd;
	struct ib_uverbs_reg_mr_resp resp;
	int ret;

	vmr = malloc(sizeof(*vmr));
	if (!vmr)
		return NULL;

	ret = ibv_cmd_reg_mr(pd, addr, length, hca_va, access, vmr, &cmd,
			     sizeof(cmd), &resp, sizeof(resp));

	if (ret) {
		free(vmr);
		return NULL;
	}

	return &vmr->ibv_mr;
}

int hfi1_dereg_mr(struct verbs_mr *vmr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

	free(vmr);
	return 0;
}

struct ibv_cq *hfi1_create_cq(struct ibv_context *context, int cqe,
			       struct ibv_comp_channel *channel,
			       int comp_vector)
{
	struct hfi1_cq		   *cq;
	struct hfi1_create_cq_resp resp;
	int			    ret;
	size_t			    size;

	memset(&resp, 0, sizeof(resp));
	cq = malloc(sizeof *cq);
	if (!cq)
		return NULL;

	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				&cq->ibv_cq, NULL, 0,
				&resp.ibv_resp, sizeof resp);
	if (ret) {
		free(cq);
		return NULL;
	}

	size = sizeof(struct hfi1_cq_wc) + sizeof(struct hfi1_wc) * cqe;
	cq->queue = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
			 context->cmd_fd, resp.offset);
	if ((void *) cq->queue == MAP_FAILED) {
		ibv_cmd_destroy_cq(&cq->ibv_cq);
		free(cq);
		return NULL;
	}

	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);
	return &cq->ibv_cq;
}

struct ibv_cq *hfi1_create_cq_v1(struct ibv_context *context, int cqe,
				  struct ibv_comp_channel *channel,
				  int comp_vector)
{
	struct ibv_cq		   *cq;
	int			    ret;

	cq = malloc(sizeof *cq);
	if (!cq)
		return NULL;

	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				cq, NULL, 0, NULL, 0);
	if (ret) {
		free(cq);
		return NULL;
	}

	return cq;
}

int hfi1_resize_cq(struct ibv_cq *ibcq, int cqe)
{
	struct hfi1_cq		       *cq = to_icq(ibcq);
	struct ibv_resize_cq		cmd;
	struct hfi1_resize_cq_resp	resp;
	size_t				size;
	int				ret;

	memset(&resp, 0, sizeof(resp));
	pthread_spin_lock(&cq->lock);
	/* Save the old size so we can unmmap the queue. */
	size = sizeof(struct hfi1_cq_wc) +
		(sizeof(struct hfi1_wc) * cq->ibv_cq.cqe);
	ret = ibv_cmd_resize_cq(ibcq, cqe, &cmd, sizeof cmd,
				&resp.ibv_resp, sizeof resp);
	if (ret) {
		pthread_spin_unlock(&cq->lock);
		return ret;
	}
	(void) munmap(cq->queue, size);
	size = sizeof(struct hfi1_cq_wc) +
		(sizeof(struct hfi1_wc) * cq->ibv_cq.cqe);
	cq->queue = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
			 ibcq->context->cmd_fd, resp.offset);
	ret = errno;
	pthread_spin_unlock(&cq->lock);
	if ((void *) cq->queue == MAP_FAILED)
		return ret;
	return 0;
}

int hfi1_resize_cq_v1(struct ibv_cq *ibcq, int cqe)
{
	struct ibv_resize_cq		cmd;
	struct ib_uverbs_resize_cq_resp	resp;

	return ibv_cmd_resize_cq(ibcq, cqe, &cmd, sizeof cmd,
				 &resp, sizeof resp);
}

int hfi1_destroy_cq(struct ibv_cq *ibcq)
{
	struct hfi1_cq *cq = to_icq(ibcq);
	int ret;

	ret = ibv_cmd_destroy_cq(ibcq);
	if (ret)
		return ret;

	(void) munmap(cq->queue, sizeof(struct hfi1_cq_wc) +
				 (sizeof(struct hfi1_wc) * cq->ibv_cq.cqe));
	free(cq);
	return 0;
}

int hfi1_destroy_cq_v1(struct ibv_cq *ibcq)
{
	int ret;

	ret = ibv_cmd_destroy_cq(ibcq);
	if (!ret)
		free(ibcq);
	return ret;
}

int hfi1_poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	struct hfi1_cq *cq = to_icq(ibcq);
	struct hfi1_cq_wc *q;
	int npolled;
	uint32_t tail;

	pthread_spin_lock(&cq->lock);
	q = cq->queue;
	tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
	for (npolled = 0; npolled < ne; ++npolled, ++wc) {
		if (tail == atomic_load(&q->head))
			break;
		/* Make sure entry is read after head index is read. */
		atomic_thread_fence(memory_order_acquire);
		memcpy(wc, &q->queue[tail], sizeof(*wc));
		if (tail == cq->ibv_cq.cqe)
			tail = 0;
		else
			tail++;
	}
	atomic_store(&q->tail, tail);
	pthread_spin_unlock(&cq->lock);

	return npolled;
}

struct ibv_qp *hfi1_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct ibv_create_qp	     cmd;
	struct hfi1_create_qp_resp  resp;
	struct hfi1_qp		    *qp;
	int			     ret;
	size_t			     size;

	memset(&resp, 0, sizeof(resp));
	qp = malloc(sizeof *qp);
	if (!qp)
		return NULL;

	ret = ibv_cmd_create_qp(pd, &qp->ibv_qp, attr, &cmd, sizeof cmd,
				&resp.ibv_resp, sizeof resp);
	if (ret) {
		free(qp);
		return NULL;
	}

	if (attr->srq) {
		qp->rq.size = 0;
		qp->rq.max_sge = 0;
		qp->rq.rwq = NULL;
	} else {
		qp->rq.size = attr->cap.max_recv_wr + 1;
		qp->rq.max_sge = attr->cap.max_recv_sge;
		size = sizeof(struct hfi1_rwq) +
			(sizeof(struct hfi1_rwqe) +
			 (sizeof(struct ibv_sge) * qp->rq.max_sge)) *
			qp->rq.size;
		qp->rq.rwq = mmap(NULL, size,
				  PROT_READ | PROT_WRITE, MAP_SHARED,
				  pd->context->cmd_fd, resp.offset);
		if ((void *) qp->rq.rwq == MAP_FAILED) {
			ibv_cmd_destroy_qp(&qp->ibv_qp);
			free(qp);
			return NULL;
		}
	}

	pthread_spin_init(&qp->rq.lock, PTHREAD_PROCESS_PRIVATE);
	return &qp->ibv_qp;
}

struct ibv_qp *hfi1_create_qp_v1(struct ibv_pd *pd,
				  struct ibv_qp_init_attr *attr)
{
	struct ibv_create_qp	     cmd;
	struct ib_uverbs_create_qp_resp    resp;
	struct ibv_qp		    *qp;
	int			     ret;

	qp = malloc(sizeof *qp);
	if (!qp)
		return NULL;

	ret = ibv_cmd_create_qp(pd, qp, attr, &cmd, sizeof cmd,
				&resp, sizeof resp);
	if (ret) {
		free(qp);
		return NULL;
	}

	return qp;
}

int hfi1_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		   int attr_mask,
		   struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr,
				&cmd, sizeof cmd);
}

int hfi1_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		    int attr_mask)
{
	struct ibv_modify_qp cmd = {};

	return ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof cmd);
}

int hfi1_destroy_qp(struct ibv_qp *ibqp)
{
	struct hfi1_qp	*qp = to_iqp(ibqp);
	int ret;

	ret = ibv_cmd_destroy_qp(ibqp);
	if (ret)
		return ret;

	if (qp->rq.rwq) {
		size_t size;

		size = sizeof(struct hfi1_rwq) +
			(sizeof(struct hfi1_rwqe) +
			 (sizeof(struct ibv_sge) * qp->rq.max_sge)) *
			qp->rq.size;
		(void) munmap(qp->rq.rwq, size);
	}
	free(qp);
	return 0;
}

int hfi1_destroy_qp_v1(struct ibv_qp *ibqp)
{
	int ret;

	ret = ibv_cmd_destroy_qp(ibqp);
	if (!ret)
		free(ibqp);
	return ret;
}

int hfi1_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr,
		    struct ibv_send_wr **bad_wr)
{
	unsigned wr_count;
	struct ibv_send_wr *i;

	/* Sanity check the number of WRs being posted */
	for (i = wr, wr_count = 0; i; i = i->next)
		if (++wr_count > 10)
			goto iter;

	return ibv_cmd_post_send(qp, wr, bad_wr);

iter:
	do {
		struct ibv_send_wr *next;
		int ret;

		next = i->next;
		i->next = NULL;
		ret = ibv_cmd_post_send(qp, wr, bad_wr);
		i->next = next;
		if (ret)
			return ret;
		if (next == NULL)
			break;
		wr = next;
		for (i = wr, wr_count = 0; i->next; i = i->next)
			if (++wr_count > 2)
				break;
	} while (1);
	return 0;
}

static int post_recv(struct hfi1_rq *rq, struct ibv_recv_wr *wr,
		     struct ibv_recv_wr **bad_wr)
{
	struct ibv_recv_wr *i;
	struct hfi1_rwq *rwq;
	struct hfi1_rwqe *wqe;
	uint32_t head;
	int n, ret;

	pthread_spin_lock(&rq->lock);
	rwq = rq->rwq;
	head = atomic_load_explicit(&rwq->head, memory_order_relaxed);
	for (i = wr; i; i = i->next) {
		if ((unsigned) i->num_sge > rq->max_sge) {
			ret = EINVAL;
			goto bad;
		}
		wqe = get_rwqe_ptr(rq, head);
		if (++head >= rq->size)
			head = 0;
		if (head == atomic_load(&rwq->tail)) {
			ret = ENOMEM;
			goto bad;
		}
		wqe->wr_id = i->wr_id;
		wqe->num_sge = i->num_sge;
		for (n = 0; n < wqe->num_sge; n++)
			wqe->sg_list[n] = i->sg_list[n];

		/* Make sure queue entry is written before the head index. */
		atomic_thread_fence(memory_order_release);
		atomic_store(&rwq->head, head);
	}
	ret = 0;
	goto done;

bad:
	if (bad_wr)
		*bad_wr = i;
done:
	pthread_spin_unlock(&rq->lock);
	return ret;
}

int hfi1_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		    struct ibv_recv_wr **bad_wr)
{
	struct hfi1_qp *qp = to_iqp(ibqp);

	return post_recv(&qp->rq, wr, bad_wr);
}

struct ibv_srq *hfi1_create_srq(struct ibv_pd *pd,
				 struct ibv_srq_init_attr *attr)
{
	struct hfi1_srq *srq;
	struct ibv_create_srq cmd;
	struct hfi1_create_srq_resp resp;
	int ret;
	size_t size;

	memset(&resp, 0, sizeof(resp));
	srq = malloc(sizeof *srq);
	if (srq == NULL)
		return NULL;

	ret = ibv_cmd_create_srq(pd, &srq->ibv_srq, attr, &cmd, sizeof cmd,
				 &resp.ibv_resp, sizeof resp);
	if (ret) {
		free(srq);
		return NULL;
	}

	srq->rq.size = attr->attr.max_wr + 1;
	srq->rq.max_sge = attr->attr.max_sge;
	size = sizeof(struct hfi1_rwq) +
		(sizeof(struct hfi1_rwqe) +
		 (sizeof(struct ibv_sge) * srq->rq.max_sge)) * srq->rq.size;
	srq->rq.rwq = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
			   pd->context->cmd_fd, resp.offset);
	if ((void *) srq->rq.rwq == MAP_FAILED) {
		ibv_cmd_destroy_srq(&srq->ibv_srq);
		free(srq);
		return NULL;
	}

	pthread_spin_init(&srq->rq.lock, PTHREAD_PROCESS_PRIVATE);
	return &srq->ibv_srq;
}

struct ibv_srq *hfi1_create_srq_v1(struct ibv_pd *pd,
				    struct ibv_srq_init_attr *attr)
{
	struct ibv_srq *srq;
	struct ibv_create_srq cmd;
	struct ib_uverbs_create_srq_resp resp;
	int ret;

	srq = malloc(sizeof *srq);
	if (srq == NULL)
		return NULL;

	ret = ibv_cmd_create_srq(pd, srq, attr, &cmd, sizeof cmd,
				 &resp, sizeof resp);
	if (ret) {
		free(srq);
		return NULL;
	}

	return srq;
}

int hfi1_modify_srq(struct ibv_srq *ibsrq,
		     struct ibv_srq_attr *attr, 
		     int attr_mask)
{
	struct hfi1_srq            *srq = to_isrq(ibsrq);
	struct hfi1_modify_srq_cmd  cmd;
	__u64                        offset;
	size_t                       size = 0; /* Shut up gcc */
	int                          ret;

	if (attr_mask & IBV_SRQ_MAX_WR) {
		pthread_spin_lock(&srq->rq.lock);
		/* Save the old size so we can unmmap the queue. */
		size = sizeof(struct hfi1_rwq) +
			(sizeof(struct hfi1_rwqe) +
			 (sizeof(struct ibv_sge) * srq->rq.max_sge)) *
			srq->rq.size;
	}
	cmd.offset_addr = (uintptr_t) &offset;
	ret = ibv_cmd_modify_srq(ibsrq, attr, attr_mask,
				 &cmd.ibv_cmd, sizeof cmd);
	if (ret) {
		if (attr_mask & IBV_SRQ_MAX_WR)
			pthread_spin_unlock(&srq->rq.lock);
		return ret;
	}
	if (attr_mask & IBV_SRQ_MAX_WR) {
		(void) munmap(srq->rq.rwq, size);
		srq->rq.size = attr->max_wr + 1;
		size = sizeof(struct hfi1_rwq) +
			(sizeof(struct hfi1_rwqe) +
			 (sizeof(struct ibv_sge) * srq->rq.max_sge)) *
			srq->rq.size;
		srq->rq.rwq = mmap(NULL, size,
				   PROT_READ | PROT_WRITE, MAP_SHARED,
				   ibsrq->context->cmd_fd, offset);
		pthread_spin_unlock(&srq->rq.lock);
		/* XXX Now we have no receive queue. */
		if ((void *) srq->rq.rwq == MAP_FAILED)
			return errno;
	}
	return 0;
}

int hfi1_modify_srq_v1(struct ibv_srq *ibsrq,
			struct ibv_srq_attr *attr, 
			int attr_mask)
{
	struct ibv_modify_srq cmd;

	return ibv_cmd_modify_srq(ibsrq, attr, attr_mask,
				  &cmd, sizeof cmd);
}

int hfi1_query_srq(struct ibv_srq *srq, struct ibv_srq_attr *attr)
{
	struct ibv_query_srq cmd;

	return ibv_cmd_query_srq(srq, attr, &cmd, sizeof cmd);
}

int hfi1_destroy_srq(struct ibv_srq *ibsrq)
{
	struct hfi1_srq *srq = to_isrq(ibsrq);
	size_t size;
	int ret;

	ret = ibv_cmd_destroy_srq(ibsrq);
	if (ret)
		return ret;

	size = sizeof(struct hfi1_rwq) +
		(sizeof(struct hfi1_rwqe) +
		 (sizeof(struct ibv_sge) * srq->rq.max_sge)) * srq->rq.size;
	(void) munmap(srq->rq.rwq, size);
	free(srq);
	return 0;
}

int hfi1_destroy_srq_v1(struct ibv_srq *ibsrq)
{
	int ret;

	ret = ibv_cmd_destroy_srq(ibsrq);
	if (!ret)
		free(ibsrq);
	return ret;
}

int hfi1_post_srq_recv(struct ibv_srq *ibsrq, struct ibv_recv_wr *wr,
			struct ibv_recv_wr **bad_wr)
{
	struct hfi1_srq *srq = to_isrq(ibsrq);

	return post_recv(&srq->rq, wr, bad_wr); 
}

struct ibv_ah *hfi1_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	struct ibv_ah *ah;
	struct ib_uverbs_create_ah_resp resp;

	ah = malloc(sizeof *ah);
	if (ah == NULL)
		return NULL;

	memset(&resp, 0, sizeof(resp));
	if (ibv_cmd_create_ah(pd, ah, attr, &resp, sizeof(resp))) {
		free(ah);
		return NULL;
	}

	return ah;
}

int hfi1_destroy_ah(struct ibv_ah *ah)
{
	int ret;

	ret = ibv_cmd_destroy_ah(ah);
	if (ret)
		return ret;

	free(ah);
	return 0;
}
