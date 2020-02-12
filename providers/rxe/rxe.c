/*
 * Copyright (c) 2009 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2009 System Fabric Works, Inc. All rights reserved.
 * Copyright (C) 2006-2007 QLogic Corporation, All rights reserved.
 * Copyright (c) 2005. PathScale, Inc. All rights reserved.
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
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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

#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <errno.h>

#include <endian.h>
#include <pthread.h>
#include <stddef.h>

#include <infiniband/driver.h>
#include <infiniband/verbs.h>

#include "rxe_queue.h"
#include "rxe-abi.h"
#include "rxe.h"

static void rxe_free_context(struct ibv_context *ibctx);

static const struct verbs_match_ent hca_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_RXE),
	VERBS_NAME_MATCH("rxe", NULL),
	{},
};

static int rxe_query_device(struct ibv_context *context,
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

	major = (raw_fw_ver >> 32) & 0xffff;
	minor = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(attr->fw_ver, sizeof attr->fw_ver,
		 "%d.%d.%d", major, minor, sub_minor);

	return 0;
}

static int rxe_query_port(struct ibv_context *context, uint8_t port,
			  struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof cmd);
}

static struct ibv_pd *rxe_alloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct ib_uverbs_alloc_pd_resp resp;
	struct ibv_pd *pd;

	pd = malloc(sizeof *pd);
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, pd, &cmd, sizeof cmd, &resp, sizeof resp)) {
		free(pd);
		return NULL;
	}

	return pd;
}

static int rxe_dealloc_pd(struct ibv_pd *pd)
{
	int ret;

	ret = ibv_cmd_dealloc_pd(pd);
	if (!ret)
		free(pd);

	return ret;
}

static struct ibv_mr *rxe_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
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

static int rxe_dereg_mr(struct verbs_mr *vmr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

	free(vmr);
	return 0;
}

static struct ibv_cq *rxe_create_cq(struct ibv_context *context, int cqe,
				    struct ibv_comp_channel *channel,
				    int comp_vector)
{
	struct rxe_cq *cq;
	struct urxe_create_cq_resp resp;
	int ret;

	cq = malloc(sizeof *cq);
	if (!cq) {
		return NULL;
	}

	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				&cq->ibv_cq, NULL, 0,
				&resp.ibv_resp, sizeof resp);
	if (ret) {
		free(cq);
		return NULL;
	}

	cq->queue = mmap(NULL, resp.mi.size, PROT_READ | PROT_WRITE, MAP_SHARED,
			 context->cmd_fd, resp.mi.offset);
	if ((void *)cq->queue == MAP_FAILED) {
		ibv_cmd_destroy_cq(&cq->ibv_cq);
		free(cq);
		return NULL;
	}

	cq->mmap_info = resp.mi;
	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);

	return &cq->ibv_cq;
}

static int rxe_resize_cq(struct ibv_cq *ibcq, int cqe)
{
	struct rxe_cq *cq = to_rcq(ibcq);
	struct ibv_resize_cq cmd;
	struct urxe_resize_cq_resp resp;
	int ret;

	pthread_spin_lock(&cq->lock);

	ret = ibv_cmd_resize_cq(ibcq, cqe, &cmd, sizeof cmd,
				&resp.ibv_resp, sizeof resp);
	if (ret) {
		pthread_spin_unlock(&cq->lock);
		return ret;
	}

	munmap(cq->queue, cq->mmap_info.size);

	cq->queue = mmap(NULL, resp.mi.size,
			 PROT_READ | PROT_WRITE, MAP_SHARED,
			 ibcq->context->cmd_fd, resp.mi.offset);

	ret = errno;
	pthread_spin_unlock(&cq->lock);

	if ((void *)cq->queue == MAP_FAILED) {
		cq->queue = NULL;
		cq->mmap_info.size = 0;
		return ret;
	}

	cq->mmap_info = resp.mi;

	return 0;
}

static int rxe_destroy_cq(struct ibv_cq *ibcq)
{
	struct rxe_cq *cq = to_rcq(ibcq);
	int ret;

	ret = ibv_cmd_destroy_cq(ibcq);
	if (ret)
		return ret;

	if (cq->mmap_info.size)
		munmap(cq->queue, cq->mmap_info.size);
	free(cq);

	return 0;
}

static int rxe_poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	struct rxe_cq *cq = to_rcq(ibcq);
	struct rxe_queue *q;
	int npolled;
	uint8_t *src;

	pthread_spin_lock(&cq->lock);
	q = cq->queue;

	for (npolled = 0; npolled < ne; ++npolled, ++wc) {
		if (queue_empty(q))
			break;

		atomic_thread_fence(memory_order_acquire);
		src = consumer_addr(q);
		memcpy(wc, src, sizeof(*wc));
		advance_consumer(q);
	}

	pthread_spin_unlock(&cq->lock);
	return npolled;
}

static struct ibv_srq *rxe_create_srq(struct ibv_pd *pd,
				      struct ibv_srq_init_attr *attr)
{
	struct rxe_srq *srq;
	struct ibv_create_srq cmd;
	struct urxe_create_srq_resp resp;
	int ret;

	srq = malloc(sizeof *srq);
	if (srq == NULL) {
		return NULL;
	}

	ret = ibv_cmd_create_srq(pd, &srq->ibv_srq, attr, &cmd, sizeof cmd,
				 &resp.ibv_resp, sizeof resp);
	if (ret) {
		free(srq);
		return NULL;
	}

	srq->rq.queue = mmap(NULL, resp.mi.size,
			     PROT_READ | PROT_WRITE, MAP_SHARED,
			     pd->context->cmd_fd, resp.mi.offset);
	if ((void *)srq->rq.queue == MAP_FAILED) {
		ibv_cmd_destroy_srq(&srq->ibv_srq);
		free(srq);
		return NULL;
	}

	srq->mmap_info = resp.mi;
	srq->rq.max_sge = attr->attr.max_sge;
	pthread_spin_init(&srq->rq.lock, PTHREAD_PROCESS_PRIVATE);

	return &srq->ibv_srq;
}

static int rxe_modify_srq(struct ibv_srq *ibsrq,
		   struct ibv_srq_attr *attr, int attr_mask)
{
	struct rxe_srq *srq = to_rsrq(ibsrq);
	struct urxe_modify_srq cmd;
	int rc = 0;
	struct mminfo mi;

	mi.offset = 0;
	mi.size = 0;

	if (attr_mask & IBV_SRQ_MAX_WR)
		pthread_spin_lock(&srq->rq.lock);

	cmd.mmap_info_addr = (__u64)(uintptr_t) & mi;
	rc = ibv_cmd_modify_srq(ibsrq, attr, attr_mask,
				&cmd.ibv_cmd, sizeof cmd);
	if (rc)
		goto out;

	if (attr_mask & IBV_SRQ_MAX_WR) {
		(void)munmap(srq->rq.queue, srq->mmap_info.size);
		srq->rq.queue = mmap(NULL, mi.size,
				     PROT_READ | PROT_WRITE, MAP_SHARED,
				     ibsrq->context->cmd_fd, mi.offset);

		if ((void *)srq->rq.queue == MAP_FAILED) {
			rc = errno;
			srq->rq.queue = NULL;
			srq->mmap_info.size = 0;
			goto out;
		}

		srq->mmap_info = mi;
	}

out:
	if (attr_mask & IBV_SRQ_MAX_WR)
		pthread_spin_unlock(&srq->rq.lock);
	return rc;
}

static int rxe_query_srq(struct ibv_srq *srq, struct ibv_srq_attr *attr)
{
	struct ibv_query_srq cmd;

	return ibv_cmd_query_srq(srq, attr, &cmd, sizeof cmd);
}

static int rxe_destroy_srq(struct ibv_srq *ibvsrq)
{
	int ret;
	struct rxe_srq *srq = to_rsrq(ibvsrq);
	struct rxe_queue *q = srq->rq.queue;

	ret = ibv_cmd_destroy_srq(ibvsrq);
	if (!ret) {
		if (srq->mmap_info.size)
			munmap(q, srq->mmap_info.size);
		free(srq);
	}

	return ret;
}

static int rxe_post_one_recv(struct rxe_wq *rq, struct ibv_recv_wr *recv_wr)
{
	int i;
	struct rxe_recv_wqe *wqe;
	struct rxe_queue *q = rq->queue;
	int length = 0;
	int rc = 0;

	if (queue_full(q)) {
		rc  = -ENOMEM;
		goto out;
	}

	if (recv_wr->num_sge > rq->max_sge) {
		rc = -EINVAL;
		goto out;
	}

	wqe = (struct rxe_recv_wqe *)producer_addr(q);

	wqe->wr_id = recv_wr->wr_id;
	wqe->num_sge = recv_wr->num_sge;

	memcpy(wqe->dma.sge, recv_wr->sg_list,
	       wqe->num_sge*sizeof(*wqe->dma.sge));

	for (i = 0; i < wqe->num_sge; i++) {
		length += wqe->dma.sge[i].length;
	}

	wqe->dma.length = length;
	wqe->dma.resid = length;
	wqe->dma.cur_sge = 0;
	wqe->dma.num_sge = wqe->num_sge;
	wqe->dma.sge_offset = 0;

	advance_producer(q);

out:
	return rc;
}

static int rxe_post_srq_recv(struct ibv_srq *ibvsrq,
			     struct ibv_recv_wr *recv_wr,
			     struct ibv_recv_wr **bad_recv_wr)
{
	struct rxe_srq *srq = to_rsrq(ibvsrq);
	int rc = 0;

	pthread_spin_lock(&srq->rq.lock);

	while (recv_wr) {
		rc = rxe_post_one_recv(&srq->rq, recv_wr);
		if (rc) {
			*bad_recv_wr = recv_wr;
			break;
		}

		recv_wr = recv_wr->next;
	}

	pthread_spin_unlock(&srq->rq.lock);

	return rc;
}

static struct ibv_qp *rxe_create_qp(struct ibv_pd *pd,
				    struct ibv_qp_init_attr *attr)
{
	struct ibv_create_qp cmd;
	struct urxe_create_qp_resp resp;
	struct rxe_qp *qp;
	int ret;

	qp = malloc(sizeof *qp);
	if (!qp) {
		return NULL;
	}

	ret = ibv_cmd_create_qp(pd, &qp->ibv_qp, attr, &cmd, sizeof cmd,
				&resp.ibv_resp, sizeof resp);
	if (ret) {
		free(qp);
		return NULL;
	}

	if (attr->srq) {
		qp->rq.max_sge = 0;
		qp->rq.queue = NULL;
		qp->rq_mmap_info.size = 0;
	} else {
		qp->rq.max_sge = attr->cap.max_recv_sge;
		qp->rq.queue = mmap(NULL, resp.rq_mi.size, PROT_READ | PROT_WRITE,
				    MAP_SHARED,
				    pd->context->cmd_fd, resp.rq_mi.offset);
		if ((void *)qp->rq.queue == MAP_FAILED) {
			ibv_cmd_destroy_qp(&qp->ibv_qp);
			free(qp);
			return NULL;
		}

		qp->rq_mmap_info = resp.rq_mi;
		pthread_spin_init(&qp->rq.lock, PTHREAD_PROCESS_PRIVATE);
	}

	qp->sq.max_sge = attr->cap.max_send_sge;
	qp->sq.max_inline = attr->cap.max_inline_data;
	qp->sq.queue = mmap(NULL, resp.sq_mi.size, PROT_READ | PROT_WRITE,
			    MAP_SHARED,
			    pd->context->cmd_fd, resp.sq_mi.offset);
	if ((void *)qp->sq.queue == MAP_FAILED) {
		if (qp->rq_mmap_info.size)
			munmap(qp->rq.queue, qp->rq_mmap_info.size);
		ibv_cmd_destroy_qp(&qp->ibv_qp);
		free(qp);
		return NULL;
	}

	qp->sq_mmap_info = resp.sq_mi;
	pthread_spin_init(&qp->sq.lock, PTHREAD_PROCESS_PRIVATE);

	return &qp->ibv_qp;
}

static int rxe_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
			int attr_mask,
			struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr,
				&cmd, sizeof cmd);
}

static int rxe_modify_qp(struct ibv_qp *ibvqp,
			 struct ibv_qp_attr *attr,
			 int attr_mask)
{
	struct ibv_modify_qp cmd = {};

	return ibv_cmd_modify_qp(ibvqp, attr, attr_mask, &cmd, sizeof cmd);
}

static int rxe_destroy_qp(struct ibv_qp *ibv_qp)
{
	int ret;
	struct rxe_qp *qp = to_rqp(ibv_qp);

	ret = ibv_cmd_destroy_qp(ibv_qp);
	if (!ret) {
		if (qp->rq_mmap_info.size)
			munmap(qp->rq.queue, qp->rq_mmap_info.size);
		if (qp->sq_mmap_info.size)
			munmap(qp->sq.queue, qp->sq_mmap_info.size);

		free(qp);
	}

	return ret;
}

/* basic sanity checks for send work request */
static int validate_send_wr(struct rxe_wq *sq, struct ibv_send_wr *ibwr,
			    unsigned int length)
{
	enum ibv_wr_opcode opcode = ibwr->opcode;

	if (ibwr->num_sge > sq->max_sge)
		return -EINVAL;

	if ((opcode == IBV_WR_ATOMIC_CMP_AND_SWP)
	    || (opcode == IBV_WR_ATOMIC_FETCH_AND_ADD))
		if (length < 8 || ibwr->wr.atomic.remote_addr & 0x7)
			return -EINVAL;

	if ((ibwr->send_flags & IBV_SEND_INLINE) && (length > sq->max_inline))
		return -EINVAL;

	return 0;
}

static void convert_send_wr(struct rxe_send_wr *kwr, struct ibv_send_wr *uwr)
{
	memset(kwr, 0, sizeof(*kwr));

	kwr->wr_id		= uwr->wr_id;
	kwr->num_sge		= uwr->num_sge;
	kwr->opcode		= uwr->opcode;
	kwr->send_flags		= uwr->send_flags;
	kwr->ex.imm_data	= uwr->imm_data;

	switch(uwr->opcode) {
	case IBV_WR_RDMA_WRITE:
	case IBV_WR_RDMA_WRITE_WITH_IMM:
	case IBV_WR_RDMA_READ:
		kwr->wr.rdma.remote_addr	= uwr->wr.rdma.remote_addr;
		kwr->wr.rdma.rkey		= uwr->wr.rdma.rkey;
		break;

	case IBV_WR_SEND:
	case IBV_WR_SEND_WITH_IMM:
		kwr->wr.ud.remote_qpn		= uwr->wr.ud.remote_qpn;
		kwr->wr.ud.remote_qkey		= uwr->wr.ud.remote_qkey;
		break;

	case IBV_WR_ATOMIC_CMP_AND_SWP:
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		kwr->wr.atomic.remote_addr	= uwr->wr.atomic.remote_addr;
		kwr->wr.atomic.compare_add	= uwr->wr.atomic.compare_add;
		kwr->wr.atomic.swap		= uwr->wr.atomic.swap;
		kwr->wr.atomic.rkey		= uwr->wr.atomic.rkey;
		break;

	case IBV_WR_LOCAL_INV:
	case IBV_WR_BIND_MW:
	case IBV_WR_SEND_WITH_INV:
	case IBV_WR_TSO:
	case IBV_WR_DRIVER1:
		break;
	}
}

static int init_send_wqe(struct rxe_qp *qp, struct rxe_wq *sq,
		  struct ibv_send_wr *ibwr, unsigned int length,
		  struct rxe_send_wqe *wqe)
{
	int num_sge = ibwr->num_sge;
	int i;
	unsigned int opcode = ibwr->opcode;

	convert_send_wr(&wqe->wr, ibwr);

	if (qp_type(qp) == IBV_QPT_UD)
		memcpy(&wqe->av, &to_rah(ibwr->wr.ud.ah)->av,
		       sizeof(struct rxe_av));

	if (ibwr->send_flags & IBV_SEND_INLINE) {
		uint8_t *inline_data = wqe->dma.inline_data;

		for (i = 0; i < num_sge; i++) {
			memcpy(inline_data,
			       (uint8_t *)(long)ibwr->sg_list[i].addr,
			       ibwr->sg_list[i].length);
			inline_data += ibwr->sg_list[i].length;
		}
	} else
		memcpy(wqe->dma.sge, ibwr->sg_list,
		       num_sge*sizeof(struct ibv_sge));

	if ((opcode == IBV_WR_ATOMIC_CMP_AND_SWP)
	    || (opcode == IBV_WR_ATOMIC_FETCH_AND_ADD))
		wqe->iova	= ibwr->wr.atomic.remote_addr;
	else
		wqe->iova	= ibwr->wr.rdma.remote_addr;
	wqe->dma.length		= length;
	wqe->dma.resid		= length;
	wqe->dma.num_sge	= num_sge;
	wqe->dma.cur_sge	= 0;
	wqe->dma.sge_offset	= 0;
	wqe->state		= 0;
	wqe->ssn		= qp->ssn++;

	return 0;
}

static int post_one_send(struct rxe_qp *qp, struct rxe_wq *sq,
			 struct ibv_send_wr *ibwr)
{
	int err;
	struct rxe_send_wqe *wqe;
	unsigned int length = 0;
	int i;

	for (i = 0; i < ibwr->num_sge; i++)
		length += ibwr->sg_list[i].length;

	err = validate_send_wr(sq, ibwr, length);
	if (err) {
		printf("validate send failed\n");
		return err;
	}

	wqe = (struct rxe_send_wqe *)producer_addr(sq->queue);

	err = init_send_wqe(qp, sq, ibwr, length, wqe);
	if (err)
		return err;

	if (queue_full(sq->queue))
		return -ENOMEM;

	advance_producer(sq->queue);

	return 0;
}

/* send a null post send as a doorbell */
static int post_send_db(struct ibv_qp *ibqp)
{
	struct ibv_post_send cmd;
	struct ib_uverbs_post_send_resp resp;

	cmd.hdr.command	= IB_USER_VERBS_CMD_POST_SEND;
	cmd.hdr.in_words = sizeof(cmd) / 4;
	cmd.hdr.out_words = sizeof(resp) / 4;
	cmd.response	= (uintptr_t)&resp;
	cmd.qp_handle	= ibqp->handle;
	cmd.wr_count	= 0;
	cmd.sge_count	= 0;
	cmd.wqe_size	= sizeof(struct ibv_send_wr);

	if (write(ibqp->context->cmd_fd, &cmd, sizeof(cmd)) != sizeof(cmd))
		return errno;

	return 0;
}

/* this API does not make a distinction between
   restartable and non-restartable errors */
static int rxe_post_send(struct ibv_qp *ibqp,
			 struct ibv_send_wr *wr_list,
			 struct ibv_send_wr **bad_wr)
{
	int rc = 0;
	int err;
	struct rxe_qp *qp = to_rqp(ibqp);
	struct rxe_wq *sq = &qp->sq;

	if (!bad_wr)
		return EINVAL;

	*bad_wr = NULL;

	if (!sq || !wr_list || !sq->queue)
	 	return EINVAL;

	pthread_spin_lock(&sq->lock);

	while (wr_list) {
		rc = post_one_send(qp, sq, wr_list);
		if (rc) {
			*bad_wr = wr_list;
			break;
		}

		wr_list = wr_list->next;
	}

	pthread_spin_unlock(&sq->lock);

	err =  post_send_db(ibqp);
	return err ? err : rc;
}

static int rxe_post_recv(struct ibv_qp *ibqp,
			 struct ibv_recv_wr *recv_wr,
			 struct ibv_recv_wr **bad_wr)
{
	int rc = 0;
	struct rxe_qp *qp = to_rqp(ibqp);
	struct rxe_wq *rq = &qp->rq;

	if (!bad_wr)
		return EINVAL;

	*bad_wr = NULL;

	if (!rq || !recv_wr || !rq->queue)
		return EINVAL;

	pthread_spin_lock(&rq->lock);

	while (recv_wr) {
		rc = rxe_post_one_recv(rq, recv_wr);
		if (rc) {
			*bad_wr = recv_wr;
			break;
		}

		recv_wr = recv_wr->next;
	}

	pthread_spin_unlock(&rq->lock);

	return rc;
}

static inline int ipv6_addr_v4mapped(const struct in6_addr *a)
{
	return IN6_IS_ADDR_V4MAPPED(a);
}

typedef typeof(((struct rxe_av *)0)->sgid_addr) sockaddr_union_t;

static inline int rdma_gid2ip(sockaddr_union_t *out, union ibv_gid *gid)
{
	if (ipv6_addr_v4mapped((struct in6_addr *)gid)) {
		memset(&out->_sockaddr_in, 0, sizeof(out->_sockaddr_in));
		memcpy(&out->_sockaddr_in.sin_addr.s_addr, gid->raw + 12, 4);
	} else {
		memset(&out->_sockaddr_in6, 0, sizeof(out->_sockaddr_in6));
		out->_sockaddr_in6.sin6_family = AF_INET6;
		memcpy(&out->_sockaddr_in6.sin6_addr.s6_addr, gid->raw, 16);
	}
	return 0;
}

static struct ibv_ah *rxe_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	int err;
	struct rxe_ah *ah;
	struct rxe_av *av;
	union ibv_gid sgid;
	struct ib_uverbs_create_ah_resp resp;

	err = ibv_query_gid(pd->context, attr->port_num, attr->grh.sgid_index,
			    &sgid);
	if (err) {
		fprintf(stderr, "rxe: Failed to query sgid.\n");
		return NULL;
	}

	ah = malloc(sizeof *ah);
	if (ah == NULL)
		return NULL;

	av = &ah->av;
	av->port_num = attr->port_num;
	memcpy(&av->grh, &attr->grh, sizeof(attr->grh));
	av->network_type =
		ipv6_addr_v4mapped((struct in6_addr *)attr->grh.dgid.raw) ?
		RDMA_NETWORK_IPV4 : RDMA_NETWORK_IPV6;

	rdma_gid2ip(&av->sgid_addr, &sgid);
	rdma_gid2ip(&av->dgid_addr, &attr->grh.dgid);
	if (ibv_resolve_eth_l2_from_gid(pd->context, attr, av->dmac, NULL)) {
		free(ah);
		return NULL;
	}

	memset(&resp, 0, sizeof(resp));
	if (ibv_cmd_create_ah(pd, &ah->ibv_ah, attr, &resp, sizeof(resp))) {
		free(ah);
		return NULL;
	}

	return &ah->ibv_ah;
}

static int rxe_destroy_ah(struct ibv_ah *ibah)
{
	int ret;
	struct rxe_ah *ah = to_rah(ibah);

	ret = ibv_cmd_destroy_ah(&ah->ibv_ah);
	if (ret)
		return ret;

	free(ah);
	return 0;
}

static const struct verbs_context_ops rxe_ctx_ops = {
	.query_device = rxe_query_device,
	.query_port = rxe_query_port,
	.alloc_pd = rxe_alloc_pd,
	.dealloc_pd = rxe_dealloc_pd,
	.reg_mr = rxe_reg_mr,
	.dereg_mr = rxe_dereg_mr,
	.create_cq = rxe_create_cq,
	.poll_cq = rxe_poll_cq,
	.req_notify_cq = ibv_cmd_req_notify_cq,
	.resize_cq = rxe_resize_cq,
	.destroy_cq = rxe_destroy_cq,
	.create_srq = rxe_create_srq,
	.modify_srq = rxe_modify_srq,
	.query_srq = rxe_query_srq,
	.destroy_srq = rxe_destroy_srq,
	.post_srq_recv = rxe_post_srq_recv,
	.create_qp = rxe_create_qp,
	.query_qp = rxe_query_qp,
	.modify_qp = rxe_modify_qp,
	.destroy_qp = rxe_destroy_qp,
	.post_send = rxe_post_send,
	.post_recv = rxe_post_recv,
	.create_ah = rxe_create_ah,
	.destroy_ah = rxe_destroy_ah,
	.attach_mcast = ibv_cmd_attach_mcast,
	.detach_mcast = ibv_cmd_detach_mcast,
	.free_context = rxe_free_context,
};

static struct verbs_context *rxe_alloc_context(struct ibv_device *ibdev,
					       int cmd_fd,
					       void *private_data)
{
	struct rxe_context *context;
	struct ibv_get_context cmd;
	struct ib_uverbs_get_context_resp resp;

	context = verbs_init_and_alloc_context(ibdev, cmd_fd, context, ibv_ctx,
					       RDMA_DRIVER_RXE);
	if (!context)
		return NULL;

	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd,
				sizeof cmd, &resp, sizeof resp))
		goto out;

	verbs_set_ops(&context->ibv_ctx, &rxe_ctx_ops);

	return &context->ibv_ctx;

out:
	verbs_uninit_context(&context->ibv_ctx);
	free(context);
	return NULL;
}

static void rxe_free_context(struct ibv_context *ibctx)
{
	struct rxe_context *context = to_rctx(ibctx);

	verbs_uninit_context(&context->ibv_ctx);
	free(context);
}

static void rxe_uninit_device(struct verbs_device *verbs_device)
{
	struct rxe_device *dev = to_rdev(&verbs_device->device);

	free(dev);
}

static struct verbs_device *rxe_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct rxe_device *dev;
	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->abi_version = sysfs_dev->abi_ver;

	return &dev->ibv_dev;
}

static const struct verbs_device_ops rxe_dev_ops = {
	.name = "rxe",
	/*
	 * For 64 bit machines ABI version 1 and 2 are the same. Otherwise 32
	 * bit machines require ABI version 2 which guarentees the user and
	 * kernel use the same ABI.
	 */
	.match_min_abi_version = sizeof(void *) == 8?1:2,
	.match_max_abi_version = 2,
	.match_table = hca_table,
	.alloc_device = rxe_device_alloc,
	.uninit_device = rxe_uninit_device,
	.alloc_context = rxe_alloc_context,
};
PROVIDER_DRIVER(rxe, rxe_dev_ops);
