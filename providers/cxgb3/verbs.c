/*
 * Copyright (c) 2006-2007 Chelsio, Inc. All rights reserved.
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
 *        disclaimer in the documentation and/or other materials
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <inttypes.h>

#include "iwch.h"
#include "iwch-abi.h"

int iwch_query_device(struct ibv_context *context, struct ibv_device_attr *attr)
{
	struct ibv_query_device cmd;
	uint64_t raw_fw_ver;
	unsigned major, minor, sub_minor;
	int ret;

	ret = ibv_cmd_query_device(context, attr, &raw_fw_ver, &cmd, 
	  			   sizeof cmd);
	if (ret)
		return ret;

	major = (raw_fw_ver >> 32) & 0xffff;
	minor = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(attr->fw_ver, sizeof attr->fw_ver,
		 "%d.%d.%d", major, minor, sub_minor);

	return 0;
}

int iwch_query_port(struct ibv_context *context, uint8_t port,
		    struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof cmd);
}

struct ibv_pd *iwch_alloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct uiwch_alloc_pd_resp resp;
	struct iwch_pd *pd;

	pd = malloc(sizeof *pd);
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, &pd->ibv_pd, &cmd, sizeof cmd,
			     &resp.ibv_resp, sizeof resp)) {
		free(pd);
		return NULL;
	}

	return &pd->ibv_pd;
}

int iwch_free_pd(struct ibv_pd *pd)
{
	int ret;

	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	free(pd);
	return 0;
}

static struct ibv_mr *__iwch_reg_mr(struct ibv_pd *pd, void *addr,
				    size_t length, uint64_t hca_va,
				    int access)
{
	struct iwch_mr *mhp;
	struct ibv_reg_mr cmd;
	struct uiwch_reg_mr_resp resp;
	struct iwch_device *dev = to_iwch_dev(pd->context->device);

	mhp = malloc(sizeof *mhp);
	if (!mhp)
		return NULL;

	if (ibv_cmd_reg_mr(pd, addr, length, hca_va,
			   access, &mhp->vmr, &cmd, sizeof(cmd),
			   &resp.ibv_resp, sizeof resp)) {
		free(mhp);
		return NULL;
	}

	mhp->va_fbo = hca_va;
	mhp->page_size = iwch_page_shift - 12;
	mhp->pbl_addr = resp.pbl_addr;
	mhp->len = length;

	PDBG("%s stag 0x%x va_fbo 0x%" PRIx64
             " page_size %d pbl_addr 0x%x len %d\n",
	     __func__, mhp->vmr.ibv_mr.rkey, mhp->va_fbo,
	     mhp->page_size, mhp->pbl_addr, mhp->len);

	pthread_spin_lock(&dev->lock);
	dev->mmid2ptr[t3_mmid(mhp->vmr.ibv_mr.lkey)] = mhp;
	pthread_spin_unlock(&dev->lock);
	
	return &mhp->vmr.ibv_mr;
}

struct ibv_mr *iwch_reg_mr(struct ibv_pd *pd, void *addr,
			   size_t length, int access)
{
	PDBG("%s addr %p length %ld\n", __FUNCTION__, addr, length);
	return __iwch_reg_mr(pd, addr, length, (uintptr_t) addr, access);
}

int iwch_dereg_mr(struct verbs_mr *vmr)
{
	int ret;
	struct iwch_device *dev = to_iwch_dev(vmr->ibv_mr.pd->context->device);

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

	pthread_spin_lock(&dev->lock);
	dev->mmid2ptr[t3_mmid(vmr->ibv_mr.lkey)] = NULL;
	pthread_spin_unlock(&dev->lock);

	free(to_iwch_mr(vmr));
	
	return 0;
}

struct ibv_cq *iwch_create_cq(struct ibv_context *context, int cqe,
			      struct ibv_comp_channel *channel, int comp_vector)
{
	struct uiwch_create_cq cmd;
	struct uiwch_create_cq_resp resp;
	struct iwch_cq *chp;
	struct iwch_device *dev = to_iwch_dev(context->device);
	int ret;

	chp = calloc(1, sizeof *chp);
	if (!chp) {
		return NULL;
	}

	cmd.user_rptr_addr = (uint64_t)(unsigned long)&chp->cq.rptr;
	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				&chp->ibv_cq, &cmd.ibv_cmd, sizeof cmd,
				&resp.ibv_resp, sizeof resp);
	if (ret)
		goto err1;

	pthread_spin_init(&chp->lock, PTHREAD_PROCESS_PRIVATE);
	chp->rhp = dev;
	chp->cq.cqid = resp.cqid;
	chp->cq.size_log2 = resp.size_log2;
	if (dev->abi_version == 0)
		chp->cq.memsize = PAGE_ALIGN((1UL << chp->cq.size_log2) *
					     sizeof(struct t3_cqe));
	else
		chp->cq.memsize = resp.memsize;
	chp->cq.queue = mmap(NULL, t3_cq_memsize(&chp->cq),
			     PROT_READ|PROT_WRITE, MAP_SHARED, context->cmd_fd,
			     resp.key);
	if (chp->cq.queue == MAP_FAILED)
		goto err2;

	chp->cq.sw_queue = calloc(t3_cq_depth(&chp->cq), sizeof(struct t3_cqe));
	if (!chp->cq.sw_queue)
		goto err3;

	PDBG("%s cqid 0x%x physaddr %" PRIx64 " va %p memsize %d\n", 
	       __FUNCTION__, chp->cq.cqid, resp.physaddr, chp->cq.queue, 
	       t3_cq_memsize(&chp->cq));
	
	pthread_spin_lock(&dev->lock);
	dev->cqid2ptr[chp->cq.cqid] = chp;
	pthread_spin_unlock(&dev->lock);

	return &chp->ibv_cq;
err3:
	munmap(chp->cq.queue, t3_cq_memsize(&chp->cq));
err2:
	(void)ibv_cmd_destroy_cq(&chp->ibv_cq);
err1:
	free(chp);
	return NULL;
}

int iwch_resize_cq(struct ibv_cq *ibcq, int cqe)
{
#ifdef notyet
	int ret;
	struct ibv_resize_cq cmd;
	struct iwch_cq *chp = to_iwch_cq(ibcq);

	pthread_spin_lock(&chp->lock);
	ret = ibv_cmd_resize_cq(ibcq, cqe, &cmd, sizeof cmd);
	/* remap and realloc swcq here */
	pthread_spin_unlock(&chp->lock);
	return ret;
#else
	return -ENOSYS;
#endif
}

int iwch_destroy_cq(struct ibv_cq *ibcq)
{
	int ret;
	struct iwch_cq *chp = to_iwch_cq(ibcq);
	void *cqva = chp->cq.queue;
	unsigned size = t3_cq_memsize(&chp->cq);
	struct iwch_device *dev = to_iwch_dev(ibcq->context->device);

	munmap(cqva, size);
	ret = ibv_cmd_destroy_cq(ibcq);
	if (ret) {
		return ret;
	}

	pthread_spin_lock(&dev->lock);
	dev->cqid2ptr[chp->cq.cqid] = NULL;
	pthread_spin_unlock(&dev->lock);

	free(chp->cq.sw_queue);
	free(chp);
	return 0;
}

struct ibv_srq *iwch_create_srq(struct ibv_pd *pd,
				struct ibv_srq_init_attr *attr)
{
	return NULL;
}

int iwch_modify_srq(struct ibv_srq *srq, struct ibv_srq_attr *attr, 
		    int attr_mask)
{
	return -ENOSYS;
}

int iwch_destroy_srq(struct ibv_srq *srq)
{
	return -ENOSYS;
}

int iwch_post_srq_recv(struct ibv_srq *ibsrq, struct ibv_recv_wr *wr, 
		       struct ibv_recv_wr **bad_wr)
{
	return -ENOSYS;
}

struct ibv_qp *iwch_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct uiwch_create_qp cmd;
	struct uiwch_create_qp_resp resp;
	struct iwch_qp *qhp;
	struct iwch_device *dev = to_iwch_dev(pd->context->device);
	int ret;
	void *dbva;

	PDBG("%s enter qp\n", __FUNCTION__);
	qhp = calloc(1, sizeof *qhp);
	if (!qhp)
		goto err1;

	ret = ibv_cmd_create_qp(pd, &qhp->ibv_qp, attr, &cmd.ibv_cmd, 
				sizeof cmd, &resp.ibv_resp, sizeof resp);
	if (ret)
		goto err2;

	PDBG("%s qpid 0x%x physaddr %" PRIx64 " doorbell %" PRIx64 
	       " size %d sq_size %d rq_size %d\n",
		__FUNCTION__, resp.qpid, resp.physaddr, resp.doorbell,
		1 << resp.size_log2, 1 << resp.sq_size_log2, 
		1 << resp.rq_size_log2);

	qhp->rhp = dev;
	qhp->wq.qpid = resp.qpid;
	qhp->wq.size_log2 = resp.size_log2;
	qhp->wq.sq_size_log2 = resp.sq_size_log2;
	qhp->wq.rq_size_log2 = resp.rq_size_log2;
	pthread_spin_init(&qhp->lock, PTHREAD_PROCESS_PRIVATE);
	dbva = mmap(NULL, iwch_page_size, PROT_WRITE, MAP_SHARED, 
		    pd->context->cmd_fd, resp.db_key & ~(iwch_page_mask));
	if (dbva == MAP_FAILED)
		goto err3;

	qhp->wq.doorbell = dbva + (resp.db_key & (iwch_page_mask));
	qhp->wq.queue = mmap(NULL, t3_wq_memsize(&qhp->wq),
			    PROT_READ|PROT_WRITE, MAP_SHARED, 
			    pd->context->cmd_fd, resp.key);
	if (qhp->wq.queue == MAP_FAILED)
		goto err4;

	qhp->wq.rq = calloc(t3_rq_depth(&qhp->wq), sizeof (uint64_t));
	if (!qhp->wq.rq) 
		goto err5;

	qhp->wq.sq = calloc(t3_sq_depth(&qhp->wq), sizeof (struct t3_swsq));
	if (!qhp->wq.sq) 
		goto err6;

	PDBG("%s dbva %p wqva %p wq memsize %d\n", __FUNCTION__, 
	     qhp->wq.doorbell, qhp->wq.queue, t3_wq_memsize(&qhp->wq));

	qhp->sq_sig_all = attr->sq_sig_all;

	pthread_spin_lock(&dev->lock);
	dev->qpid2ptr[qhp->wq.qpid] = qhp;
	pthread_spin_unlock(&dev->lock);

	return &qhp->ibv_qp;
err6:
	free(qhp->wq.rq);
err5:
	munmap((void *)qhp->wq.queue, t3_wq_memsize(&qhp->wq));
err4:
	munmap((void *)dbva, iwch_page_size);
err3:
	(void)ibv_cmd_destroy_qp(&qhp->ibv_qp);
err2:
	free(qhp);
err1:
	return NULL;
}

static void reset_qp(struct iwch_qp *qhp)
{
	PDBG("%s enter qp %p\n", __FUNCTION__, qhp);
	qhp->wq.wptr = 0;
	qhp->wq.rq_wptr = qhp->wq.rq_rptr = 0;
	qhp->wq.sq_wptr = qhp->wq.sq_rptr = 0;
	qhp->wq.error = 0;
	qhp->wq.oldest_read = NULL;
	memset(qhp->wq.queue, 0, t3_wq_memsize(&qhp->wq));
}

int iwch_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
		   int attr_mask)
{
	struct ibv_modify_qp cmd = {};
	struct iwch_qp *qhp = to_iwch_qp(ibqp);
	int ret;

	PDBG("%s enter qp %p new state %d\n", __FUNCTION__, ibqp, attr_mask & IBV_QP_STATE ? attr->qp_state : -1);
	pthread_spin_lock(&qhp->lock);
	if (t3b_device(qhp->rhp) && t3_wq_in_error(&qhp->wq))
		iwch_flush_qp(qhp);
	ret = ibv_cmd_modify_qp(ibqp, attr, attr_mask, &cmd, sizeof cmd);
	if (!ret && (attr_mask & IBV_QP_STATE) && attr->qp_state == IBV_QPS_RESET)
		reset_qp(qhp);
	pthread_spin_unlock(&qhp->lock);
	return ret;
}

int iwch_destroy_qp(struct ibv_qp *ibqp)
{
	int ret;
	struct iwch_qp *qhp = to_iwch_qp(ibqp);
	struct iwch_device *dev = to_iwch_dev(ibqp->context->device);
	void *dbva, *wqva;
	unsigned wqsize;

	PDBG("%s enter qp %p\n", __FUNCTION__, ibqp);
	if (t3b_device(dev)) {
		pthread_spin_lock(&qhp->lock);
		iwch_flush_qp(qhp);
		pthread_spin_unlock(&qhp->lock);
	}

	dbva = (void *)((unsigned long)qhp->wq.doorbell & ~(iwch_page_mask));
	wqva = qhp->wq.queue;
	wqsize = t3_wq_memsize(&qhp->wq);

	munmap(dbva, iwch_page_size);
	munmap(wqva, wqsize);
	ret = ibv_cmd_destroy_qp(ibqp);
	if (ret) {
		return ret;
	}

	pthread_spin_lock(&dev->lock);
	dev->qpid2ptr[qhp->wq.qpid] = NULL;
	pthread_spin_unlock(&dev->lock);

	free(qhp->wq.rq);
	free(qhp->wq.sq);
	free(qhp);
	return 0;
}

int iwch_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		  int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	return -ENOSYS;
}

struct ibv_ah *iwch_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	return NULL;
}

int iwch_destroy_ah(struct ibv_ah *ah)
{
	return -ENOSYS;
}

int iwch_attach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	return -ENOSYS;
}

int iwch_detach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	return -ENOSYS;
}

void t3b_async_event(struct ibv_async_event *event)
{
	PDBG("%s type %d obj %p\n", __FUNCTION__, event->event_type, 
	     event->element.cq);

	switch (event->event_type) {
	case IBV_EVENT_CQ_ERR:
		break;
	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_REQ_ERR:
	case IBV_EVENT_QP_ACCESS_ERR:
	case IBV_EVENT_PATH_MIG_ERR: {
		struct iwch_qp *qhp = to_iwch_qp(event->element.qp);
		pthread_spin_lock(&qhp->lock);
		iwch_flush_qp(qhp);
		pthread_spin_unlock(&qhp->lock);
		break;
	}
	case IBV_EVENT_SQ_DRAINED:
	case IBV_EVENT_PATH_MIG:
	case IBV_EVENT_COMM_EST:
	case IBV_EVENT_QP_LAST_WQE_REACHED:
	default:
		break;
	}
}
