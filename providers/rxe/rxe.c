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
			    const struct ibv_query_device_ex_input *input,
			    struct ibv_device_attr_ex *attr, size_t attr_size)
{
	struct ib_uverbs_ex_query_device_resp resp;
	size_t resp_size = sizeof(resp);
	uint64_t raw_fw_ver;
	unsigned int major, minor, sub_minor;
	int ret;

	ret = ibv_cmd_query_device_any(context, input, attr, attr_size, &resp,
				       &resp_size);
	if (ret)
		return ret;

	raw_fw_ver = resp.base.fw_ver;
	major = (raw_fw_ver >> 32) & 0xffff;
	minor = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(attr->orig_attr.fw_ver, sizeof(attr->orig_attr.fw_ver),
		 "%d.%d.%d", major, minor, sub_minor);

	return 0;
}

static int rxe_query_port(struct ibv_context *context, uint8_t port,
			  struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof(cmd));
}

static struct ibv_pd *rxe_alloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct ib_uverbs_alloc_pd_resp resp;
	struct ibv_pd *pd;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, pd, &cmd, sizeof(cmd),
					&resp, sizeof(resp))) {
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

static struct ibv_mw *rxe_alloc_mw(struct ibv_pd *ibpd, enum ibv_mw_type type)
{
	int ret;
	struct ibv_mw *ibmw;
	struct ibv_alloc_mw cmd = {};
	struct ib_uverbs_alloc_mw_resp resp = {};

	ibmw = calloc(1, sizeof(*ibmw));
	if (!ibmw)
		return NULL;

	ret = ibv_cmd_alloc_mw(ibpd, type, ibmw, &cmd, sizeof(cmd), &resp,
			       sizeof(resp));
	if (ret) {
		free(ibmw);
		return NULL;
	}

	return ibmw;
}

static int rxe_dealloc_mw(struct ibv_mw *ibmw)
{
	int ret;

	ret = ibv_cmd_dealloc_mw(ibmw);
	if (ret)
		return ret;

	free(ibmw);
	return 0;
}

static int next_rkey(int rkey)
{
	return (rkey & 0xffffff00) | ((rkey + 1) & 0x000000ff);
}

static int rxe_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr_list,
			 struct ibv_send_wr **bad_wr);

static int rxe_bind_mw(struct ibv_qp *ibqp, struct ibv_mw *ibmw,
		       struct ibv_mw_bind *mw_bind)
{
	int ret;
	struct ibv_mw_bind_info *bind_info = &mw_bind->bind_info;
	struct ibv_send_wr ibwr;
	struct ibv_send_wr *bad_wr;

	if (!bind_info->mr && (bind_info->addr || bind_info->length)) {
		ret = EINVAL;
		goto err;
	}

	if (bind_info->mw_access_flags & IBV_ACCESS_ZERO_BASED) {
		ret = EINVAL;
		goto err;
	}

	if (bind_info->mr) {
		if (ibmw->pd != bind_info->mr->pd) {
			ret = EPERM;
			goto err;
		}
	}

	memset(&ibwr, 0, sizeof(ibwr));

	ibwr.opcode = IBV_WR_BIND_MW;
	ibwr.next = NULL;
	ibwr.wr_id = mw_bind->wr_id;
	ibwr.send_flags = mw_bind->send_flags;
	ibwr.bind_mw.bind_info = mw_bind->bind_info;
	ibwr.bind_mw.mw = ibmw;
	ibwr.bind_mw.rkey = next_rkey(ibmw->rkey);

	ret = rxe_post_send(ibqp, &ibwr, &bad_wr);
	if (ret)
		goto err;

	/* user has to undo this if he gets an error wc */
	ibmw->rkey = ibwr.bind_mw.rkey;

	return 0;
err:
	errno = ret;
	return errno;
}

static struct ibv_mr *rxe_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
				 uint64_t hca_va, int access)
{
	struct verbs_mr *vmr;
	struct ibv_reg_mr cmd;
	struct ib_uverbs_reg_mr_resp resp;
	int ret;

	vmr = calloc(1, sizeof(*vmr));
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

static int cq_start_poll(struct ibv_cq_ex *current,
			 struct ibv_poll_cq_attr *attr)
{
	struct rxe_cq *cq = container_of(current, struct rxe_cq, vcq.cq_ex);

	pthread_spin_lock(&cq->lock);

	cq->cur_index = load_consumer_index(cq->queue);

	if (check_cq_queue_empty(cq)) {
		pthread_spin_unlock(&cq->lock);
		errno = ENOENT;
		return errno;
	}

	cq->wc = addr_from_index(cq->queue, cq->cur_index);
	cq->vcq.cq_ex.status = cq->wc->status;
	cq->vcq.cq_ex.wr_id = cq->wc->wr_id;

	return 0;
}

static int cq_next_poll(struct ibv_cq_ex *current)
{
	struct rxe_cq *cq = container_of(current, struct rxe_cq, vcq.cq_ex);

	advance_cq_cur_index(cq);

	if (check_cq_queue_empty(cq)) {
		store_consumer_index(cq->queue, cq->cur_index);
		pthread_spin_unlock(&cq->lock);
		errno = ENOENT;
		return errno;
	}

	cq->wc = addr_from_index(cq->queue, cq->cur_index);
	cq->vcq.cq_ex.status = cq->wc->status;
	cq->vcq.cq_ex.wr_id = cq->wc->wr_id;

	return 0;
}

static void cq_end_poll(struct ibv_cq_ex *current)
{
	struct rxe_cq *cq = container_of(current, struct rxe_cq, vcq.cq_ex);

	advance_cq_cur_index(cq);
	store_consumer_index(cq->queue, cq->cur_index);
	pthread_spin_unlock(&cq->lock);
}

static enum ibv_wc_opcode cq_read_opcode(struct ibv_cq_ex *current)
{
	struct rxe_cq *cq = container_of(current, struct rxe_cq, vcq.cq_ex);

	return cq->wc->opcode;
}

static uint32_t cq_read_vendor_err(struct ibv_cq_ex *current)
{
	struct rxe_cq *cq = container_of(current, struct rxe_cq, vcq.cq_ex);

	return cq->wc->vendor_err;
}

static uint32_t cq_read_byte_len(struct ibv_cq_ex *current)
{
	struct rxe_cq *cq = container_of(current, struct rxe_cq, vcq.cq_ex);

	return cq->wc->byte_len;
}

static __be32 cq_read_imm_data(struct ibv_cq_ex *current)
{
	struct rxe_cq *cq = container_of(current, struct rxe_cq, vcq.cq_ex);

	return cq->wc->ex.imm_data;
}

static uint32_t cq_read_qp_num(struct ibv_cq_ex *current)
{
	struct rxe_cq *cq = container_of(current, struct rxe_cq, vcq.cq_ex);

	return cq->wc->qp_num;
}

static uint32_t cq_read_src_qp(struct ibv_cq_ex *current)
{
	struct rxe_cq *cq = container_of(current, struct rxe_cq, vcq.cq_ex);

	return cq->wc->src_qp;
}

static unsigned int cq_read_wc_flags(struct ibv_cq_ex *current)
{
	struct rxe_cq *cq = container_of(current, struct rxe_cq, vcq.cq_ex);

	return cq->wc->wc_flags;
}

static uint32_t cq_read_slid(struct ibv_cq_ex *current)
{
	struct rxe_cq *cq = container_of(current, struct rxe_cq, vcq.cq_ex);

	return cq->wc->slid;
}

static uint8_t cq_read_sl(struct ibv_cq_ex *current)
{
	struct rxe_cq *cq = container_of(current, struct rxe_cq, vcq.cq_ex);

	return cq->wc->sl;
}

static uint8_t cq_read_dlid_path_bits(struct ibv_cq_ex *current)
{
	struct rxe_cq *cq = container_of(current, struct rxe_cq, vcq.cq_ex);

	return cq->wc->dlid_path_bits;
}

static int rxe_destroy_cq(struct ibv_cq *ibcq);

static struct ibv_cq *rxe_create_cq(struct ibv_context *context, int cqe,
				    struct ibv_comp_channel *channel,
				    int comp_vector)
{
	struct rxe_cq *cq;
	struct urxe_create_cq_resp resp = {};
	int ret;

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				&cq->vcq.cq, NULL, 0,
				&resp.ibv_resp, sizeof(resp));
	if (ret) {
		free(cq);
		return NULL;
	}

	cq->queue = mmap(NULL, resp.mi.size, PROT_READ | PROT_WRITE, MAP_SHARED,
			 context->cmd_fd, resp.mi.offset);
	if ((void *)cq->queue == MAP_FAILED) {
		ibv_cmd_destroy_cq(&cq->vcq.cq);
		free(cq);
		return NULL;
	}

	cq->wc_size = 1ULL << cq->queue->log2_elem_size;

	if (cq->wc_size < sizeof(struct ib_uverbs_wc)) {
		rxe_destroy_cq(&cq->vcq.cq);
		return NULL;
	}

	cq->mmap_info = resp.mi;
	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);

	return &cq->vcq.cq;
}

enum rxe_sup_wc_flags {
	RXE_SUP_WC_FLAGS	= IBV_WC_EX_WITH_BYTE_LEN
				| IBV_WC_EX_WITH_IMM
				| IBV_WC_EX_WITH_QP_NUM
				| IBV_WC_EX_WITH_SRC_QP
				| IBV_WC_EX_WITH_SLID
				| IBV_WC_EX_WITH_SL
				| IBV_WC_EX_WITH_DLID_PATH_BITS,
	RXE_SUP_WC_EX_FLAGS	= RXE_SUP_WC_FLAGS,
				// add extended flags here
};

static struct ibv_cq_ex *rxe_create_cq_ex(struct ibv_context *context,
					  struct ibv_cq_init_attr_ex *attr)
{
	int ret;
	struct rxe_cq *cq;
	struct urxe_create_cq_ex_resp resp = {};

	/* user is asking for flags we don't support */
	if (attr->wc_flags & ~RXE_SUP_WC_EX_FLAGS) {
		errno = EOPNOTSUPP;
		goto err;
	}

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		goto err;

	ret = ibv_cmd_create_cq_ex(context, attr, &cq->vcq,
				   NULL, 0,
				   &resp.ibv_resp, sizeof(resp), 0);
	if (ret)
		goto err_free;

	cq->queue = mmap(NULL, resp.mi.size, PROT_READ | PROT_WRITE, MAP_SHARED,
			 context->cmd_fd, resp.mi.offset);
	if ((void *)cq->queue == MAP_FAILED)
		goto err_destroy;

	cq->wc_size = 1ULL << cq->queue->log2_elem_size;

	if (cq->wc_size < sizeof(struct ib_uverbs_wc))
		goto err_unmap;

	cq->mmap_info = resp.mi;
	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);

	cq->vcq.cq_ex.start_poll	= cq_start_poll;
	cq->vcq.cq_ex.next_poll		= cq_next_poll;
	cq->vcq.cq_ex.end_poll		= cq_end_poll;
	cq->vcq.cq_ex.read_opcode	= cq_read_opcode;
	cq->vcq.cq_ex.read_vendor_err	= cq_read_vendor_err;
	cq->vcq.cq_ex.read_wc_flags	= cq_read_wc_flags;

	if (attr->wc_flags & IBV_WC_EX_WITH_BYTE_LEN)
		cq->vcq.cq_ex.read_byte_len
			= cq_read_byte_len;

	if (attr->wc_flags & IBV_WC_EX_WITH_IMM)
		cq->vcq.cq_ex.read_imm_data
			= cq_read_imm_data;

	if (attr->wc_flags & IBV_WC_EX_WITH_QP_NUM)
		cq->vcq.cq_ex.read_qp_num
			= cq_read_qp_num;

	if (attr->wc_flags & IBV_WC_EX_WITH_SRC_QP)
		cq->vcq.cq_ex.read_src_qp
			= cq_read_src_qp;

	if (attr->wc_flags & IBV_WC_EX_WITH_SLID)
		cq->vcq.cq_ex.read_slid
			= cq_read_slid;

	if (attr->wc_flags & IBV_WC_EX_WITH_SL)
		cq->vcq.cq_ex.read_sl
			= cq_read_sl;

	if (attr->wc_flags & IBV_WC_EX_WITH_DLID_PATH_BITS)
		cq->vcq.cq_ex.read_dlid_path_bits
			= cq_read_dlid_path_bits;

	return &cq->vcq.cq_ex;

err_unmap:
	if (cq->mmap_info.size)
		munmap(cq->queue, cq->mmap_info.size);
err_destroy:
	ibv_cmd_destroy_cq(&cq->vcq.cq);
err_free:
	free(cq);
err:
	return NULL;
}

static int rxe_resize_cq(struct ibv_cq *ibcq, int cqe)
{
	struct rxe_cq *cq = to_rcq(ibcq);
	struct ibv_resize_cq cmd;
	struct urxe_resize_cq_resp resp;
	int ret;

	pthread_spin_lock(&cq->lock);

	ret = ibv_cmd_resize_cq(ibcq, cqe, &cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp));
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
	struct rxe_queue_buf *q;
	int npolled;
	uint8_t *src;

	pthread_spin_lock(&cq->lock);
	q = cq->queue;

	for (npolled = 0; npolled < ne; ++npolled, ++wc) {
		if (queue_empty(q))
			break;

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

	srq = calloc(1, sizeof(*srq));
	if (srq == NULL)
		return NULL;

	ret = ibv_cmd_create_srq(pd, &srq->ibv_srq, attr, &cmd, sizeof(cmd),
				 &resp.ibv_resp, sizeof(resp));
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

	cmd.mmap_info_addr = (__u64)(uintptr_t) &mi;
	rc = ibv_cmd_modify_srq(ibsrq, attr, attr_mask,
				&cmd.ibv_cmd, sizeof(cmd));
	if (rc)
		goto out;

	if (attr_mask & IBV_SRQ_MAX_WR) {
		munmap(srq->rq.queue, srq->mmap_info.size);
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

	return ibv_cmd_query_srq(srq, attr, &cmd, sizeof(cmd));
}

static int rxe_destroy_srq(struct ibv_srq *ibvsrq)
{
	int ret;
	struct rxe_srq *srq = to_rsrq(ibvsrq);
	struct rxe_queue_buf *q = srq->rq.queue;

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
	struct rxe_queue_buf *q = rq->queue;
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

	for (i = 0; i < wqe->num_sge; i++)
		length += wqe->dma.sge[i].length;

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

/*
 * builders always consume one send queue slot
 * setters (below) reach back and adjust previous build
 */
static void wr_atomic_cmp_swp(struct ibv_qp_ex *ibqp, uint32_t rkey,
			      uint64_t remote_addr, uint64_t compare,
			      uint64_t swap)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue, qp->cur_index);

	if (check_qp_queue_full(qp))
		return;

	memset(wqe, 0, sizeof(*wqe));

	wqe->wr.wr_id = ibqp->wr_id;
	wqe->wr.send_flags = ibqp->wr_flags;
	wqe->wr.opcode = IBV_WR_ATOMIC_CMP_AND_SWP;

	wqe->wr.wr.atomic.remote_addr = remote_addr;
	wqe->wr.wr.atomic.compare_add = compare;
	wqe->wr.wr.atomic.swap = swap;
	wqe->wr.wr.atomic.rkey = rkey;
	wqe->iova = remote_addr;
	wqe->ssn = qp->ssn++;

	advance_qp_cur_index(qp);
}

static void wr_atomic_fetch_add(struct ibv_qp_ex *ibqp, uint32_t rkey,
				uint64_t remote_addr, uint64_t add)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue, qp->cur_index);

	if (check_qp_queue_full(qp))
		return;

	memset(wqe, 0, sizeof(*wqe));

	wqe->wr.wr_id = qp->vqp.qp_ex.wr_id;
	wqe->wr.opcode = IBV_WR_ATOMIC_FETCH_AND_ADD;
	wqe->wr.send_flags = qp->vqp.qp_ex.wr_flags;
	wqe->wr.wr.atomic.remote_addr = remote_addr;
	wqe->wr.wr.atomic.compare_add = add;
	wqe->wr.wr.atomic.rkey = rkey;
	wqe->iova = remote_addr;
	wqe->ssn = qp->ssn++;

	advance_qp_cur_index(qp);
}

static void wr_bind_mw(struct ibv_qp_ex *ibqp, struct ibv_mw *ibmw,
		       uint32_t rkey, const struct ibv_mw_bind_info *info)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue, qp->cur_index);

	if (check_qp_queue_full(qp))
		return;

	memset(wqe, 0, sizeof(*wqe));

	wqe->wr.wr_id = ibqp->wr_id;
	wqe->wr.opcode = IBV_WR_BIND_MW;
	wqe->wr.send_flags = qp->vqp.qp_ex.wr_flags;
	wqe->wr.wr.mw.addr = info->addr;
	wqe->wr.wr.mw.length = info->length;
	wqe->wr.wr.mw.mr_lkey = info->mr->lkey;
	wqe->wr.wr.mw.mw_rkey = ibmw->rkey;
	wqe->wr.wr.mw.rkey = rkey;
	wqe->wr.wr.mw.access = info->mw_access_flags;
	wqe->ssn = qp->ssn++;

	advance_qp_cur_index(qp);
}

static void wr_local_inv(struct ibv_qp_ex *ibqp, uint32_t invalidate_rkey)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue, qp->cur_index);

	if (check_qp_queue_full(qp))
		return;

	memset(wqe, 0, sizeof(*wqe));

	wqe->wr.wr_id = qp->vqp.qp_ex.wr_id;
	wqe->wr.opcode = IBV_WR_LOCAL_INV;
	wqe->wr.send_flags = qp->vqp.qp_ex.wr_flags;
	wqe->wr.ex.invalidate_rkey = invalidate_rkey;
	wqe->ssn = qp->ssn++;

	advance_qp_cur_index(qp);
}

static void wr_rdma_read(struct ibv_qp_ex *ibqp, uint32_t rkey,
			 uint64_t remote_addr)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue, qp->cur_index);

	if (check_qp_queue_full(qp))
		return;

	memset(wqe, 0, sizeof(*wqe));

	wqe->wr.wr_id = qp->vqp.qp_ex.wr_id;
	wqe->wr.opcode = IBV_WR_RDMA_READ;
	wqe->wr.send_flags = qp->vqp.qp_ex.wr_flags;
	wqe->wr.wr.rdma.remote_addr = remote_addr;
	wqe->wr.wr.rdma.rkey = rkey;
	wqe->iova = remote_addr;
	wqe->ssn = qp->ssn++;

	advance_qp_cur_index(qp);
}

static void wr_rdma_write(struct ibv_qp_ex *ibqp, uint32_t rkey,
			  uint64_t remote_addr)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue, qp->cur_index);

	if (check_qp_queue_full(qp))
		return;

	memset(wqe, 0, sizeof(*wqe));

	wqe->wr.wr_id = qp->vqp.qp_ex.wr_id;
	wqe->wr.opcode = IBV_WR_RDMA_WRITE;
	wqe->wr.send_flags = qp->vqp.qp_ex.wr_flags;
	wqe->wr.wr.rdma.remote_addr = remote_addr;
	wqe->wr.wr.rdma.rkey = rkey;
	wqe->iova = remote_addr;
	wqe->ssn = qp->ssn++;

	advance_qp_cur_index(qp);
}

static void wr_rdma_write_imm(struct ibv_qp_ex *ibqp, uint32_t rkey,
			      uint64_t remote_addr, __be32 imm_data)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue, qp->cur_index);

	if (check_qp_queue_full(qp))
		return;

	memset(wqe, 0, sizeof(*wqe));

	wqe->wr.wr_id = qp->vqp.qp_ex.wr_id;
	wqe->wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
	wqe->wr.send_flags = qp->vqp.qp_ex.wr_flags;
	wqe->wr.wr.rdma.remote_addr = remote_addr;
	wqe->wr.wr.rdma.rkey = rkey;
	wqe->wr.ex.imm_data = imm_data;
	wqe->iova = remote_addr;
	wqe->ssn = qp->ssn++;

	advance_qp_cur_index(qp);
}

static void wr_send(struct ibv_qp_ex *ibqp)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue, qp->cur_index);

	if (check_qp_queue_full(qp))
		return;

	memset(wqe, 0, sizeof(*wqe));

	wqe->wr.wr_id = qp->vqp.qp_ex.wr_id;
	wqe->wr.opcode = IBV_WR_SEND;
	wqe->wr.send_flags = qp->vqp.qp_ex.wr_flags;
	wqe->ssn = qp->ssn++;

	advance_qp_cur_index(qp);
}

static void wr_send_imm(struct ibv_qp_ex *ibqp, __be32 imm_data)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue, qp->cur_index);

	if (check_qp_queue_full(qp))
		return;

	memset(wqe, 0, sizeof(*wqe));

	wqe->wr.wr_id = qp->vqp.qp_ex.wr_id;
	wqe->wr.opcode = IBV_WR_SEND_WITH_IMM;
	wqe->wr.send_flags = qp->vqp.qp_ex.wr_flags;
	wqe->wr.ex.imm_data = imm_data;
	wqe->ssn = qp->ssn++;

	advance_qp_cur_index(qp);
}

static void wr_send_inv(struct ibv_qp_ex *ibqp, uint32_t invalidate_rkey)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue, qp->cur_index);

	if (check_qp_queue_full(qp))
		return;

	memset(wqe, 0, sizeof(*wqe));

	wqe->wr.wr_id = qp->vqp.qp_ex.wr_id;
	wqe->wr.opcode = IBV_WR_SEND_WITH_INV;
	wqe->wr.send_flags = qp->vqp.qp_ex.wr_flags;
	wqe->wr.ex.invalidate_rkey = invalidate_rkey;
	wqe->ssn = qp->ssn++;

	advance_qp_cur_index(qp);
}

static void wr_set_ud_addr(struct ibv_qp_ex *ibqp, struct ibv_ah *ibah,
			   uint32_t remote_qpn, uint32_t remote_qkey)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_ah *ah = container_of(ibah, struct rxe_ah, ibv_ah);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue,
						   qp->cur_index - 1);

	if (qp->err)
		return;

	memcpy(&wqe->wr.wr.ud.av, &ah->av, sizeof(ah->av));
	wqe->wr.wr.ud.remote_qpn = remote_qpn;
	wqe->wr.wr.ud.remote_qkey = remote_qkey;
}

static void wr_set_inline_data(struct ibv_qp_ex *ibqp, void *addr,
			       size_t length)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue,
						   qp->cur_index - 1);

	if (qp->err)
		return;

	if (length > qp->sq.max_inline) {
		qp->err = ENOSPC;
		return;
	}

	memcpy(wqe->dma.inline_data, addr, length);
	wqe->dma.length = length;
	wqe->dma.resid = length;
}

static void wr_set_inline_data_list(struct ibv_qp_ex *ibqp, size_t num_buf,
				    const struct ibv_data_buf *buf_list)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue,
						   qp->cur_index - 1);
	uint8_t *data = wqe->dma.inline_data;
	size_t length;
	size_t tot_length = 0;

	if (qp->err)
		return;

	while (num_buf--) {
		length = buf_list->length;

		if (tot_length + length > qp->sq.max_inline) {
			qp->err = ENOSPC;
			return;
		}

		memcpy(data, buf_list->addr, length);

		buf_list++;
		data += length;
	}

	wqe->dma.length = tot_length;
	wqe->dma.resid = tot_length;
}

static void wr_set_sge(struct ibv_qp_ex *ibqp, uint32_t lkey, uint64_t addr,
		       uint32_t length)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue,
						   qp->cur_index - 1);

	if (qp->err)
		return;

	if (length) {
		wqe->dma.length = length;
		wqe->dma.resid = length;
		wqe->dma.num_sge = 1;

		wqe->dma.sge[0].addr = addr;
		wqe->dma.sge[0].length = length;
		wqe->dma.sge[0].lkey = lkey;
	}
}

static void wr_set_sge_list(struct ibv_qp_ex *ibqp, size_t num_sge,
			    const struct ibv_sge *sg_list)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);
	struct rxe_send_wqe *wqe = addr_from_index(qp->sq.queue,
						   qp->cur_index - 1);
	size_t tot_length = 0;

	if (qp->err)
		return;

	if (num_sge > qp->sq.max_sge) {
		qp->err = ENOSPC;
		return;
	}

	wqe->dma.num_sge = num_sge;
	memcpy(wqe->dma.sge, sg_list, num_sge*sizeof(*sg_list));

	while (num_sge--)
		tot_length += sg_list->length;

	wqe->dma.length = tot_length;
	wqe->dma.resid = tot_length;
}


static void wr_start(struct ibv_qp_ex *ibqp)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);

	pthread_spin_lock(&qp->sq.lock);

	qp->err = 0;
	qp->cur_index = load_producer_index(qp->sq.queue);
}

static int post_send_db(struct ibv_qp *ibqp);

static int wr_complete(struct ibv_qp_ex *ibqp)
{
	int ret;
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);

	if (qp->err) {
		pthread_spin_unlock(&qp->sq.lock);
		return qp->err;
	}

	store_producer_index(qp->sq.queue, qp->cur_index);
	ret = post_send_db(&qp->vqp.qp);

	pthread_spin_unlock(&qp->sq.lock);
	return ret;
}

static void wr_abort(struct ibv_qp_ex *ibqp)
{
	struct rxe_qp *qp = container_of(ibqp, struct rxe_qp, vqp.qp_ex);

	pthread_spin_unlock(&qp->sq.lock);
}

static int map_queue_pair(int cmd_fd, struct rxe_qp *qp,
			  struct ibv_qp_init_attr *attr,
			  struct rxe_create_qp_resp *resp)
{
	if (attr->srq) {
		qp->rq.max_sge = 0;
		qp->rq.queue = NULL;
		qp->rq_mmap_info.size = 0;
	} else {
		qp->rq.max_sge = attr->cap.max_recv_sge;
		qp->rq.queue = mmap(NULL, resp->rq_mi.size, PROT_READ | PROT_WRITE,
				    MAP_SHARED,
				    cmd_fd, resp->rq_mi.offset);
		if ((void *)qp->rq.queue == MAP_FAILED)
			return errno;

		qp->rq_mmap_info = resp->rq_mi;
		pthread_spin_init(&qp->rq.lock, PTHREAD_PROCESS_PRIVATE);
	}

	qp->sq.max_sge = attr->cap.max_send_sge;
	qp->sq.max_inline = attr->cap.max_inline_data;
	qp->sq.queue = mmap(NULL, resp->sq_mi.size, PROT_READ | PROT_WRITE,
			    MAP_SHARED,
			    cmd_fd, resp->sq_mi.offset);
	if ((void *)qp->sq.queue == MAP_FAILED) {
		if (qp->rq_mmap_info.size)
			munmap(qp->rq.queue, qp->rq_mmap_info.size);
		return errno;
	}

	qp->sq_mmap_info = resp->sq_mi;
	pthread_spin_init(&qp->sq.lock, PTHREAD_PROCESS_PRIVATE);

	return 0;
}

static struct ibv_qp *rxe_create_qp(struct ibv_pd *ibpd,
				    struct ibv_qp_init_attr *attr)
{
	struct ibv_create_qp cmd = {};
	struct urxe_create_qp_resp resp = {};
	struct rxe_qp *qp;
	int ret;

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		goto err;

	ret = ibv_cmd_create_qp(ibpd, &qp->vqp.qp, attr, &cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp));
	if (ret)
		goto err_free;

	ret = map_queue_pair(ibpd->context->cmd_fd, qp, attr,
			     &resp.drv_payload);
	if (ret)
		goto err_destroy;

	qp->sq_mmap_info = resp.sq_mi;
	pthread_spin_init(&qp->sq.lock, PTHREAD_PROCESS_PRIVATE);

	return &qp->vqp.qp;

err_destroy:
	ibv_cmd_destroy_qp(&qp->vqp.qp);
err_free:
	free(qp);
err:
	return NULL;
}

enum {
	RXE_QP_CREATE_FLAGS_SUP = 0,

	RXE_QP_COMP_MASK_SUP = IBV_QP_INIT_ATTR_PD |
		IBV_QP_INIT_ATTR_CREATE_FLAGS | IBV_QP_INIT_ATTR_SEND_OPS_FLAGS,

	RXE_SUP_RC_QP_SEND_OPS_FLAGS =
		IBV_QP_EX_WITH_RDMA_WRITE | IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM |
		IBV_QP_EX_WITH_SEND | IBV_QP_EX_WITH_SEND_WITH_IMM |
		IBV_QP_EX_WITH_RDMA_READ | IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP |
		IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD | IBV_QP_EX_WITH_LOCAL_INV |
		IBV_QP_EX_WITH_BIND_MW | IBV_QP_EX_WITH_SEND_WITH_INV,

	RXE_SUP_UC_QP_SEND_OPS_FLAGS =
		IBV_QP_EX_WITH_RDMA_WRITE | IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM |
		IBV_QP_EX_WITH_SEND | IBV_QP_EX_WITH_SEND_WITH_IMM |
		IBV_QP_EX_WITH_BIND_MW | IBV_QP_EX_WITH_SEND_WITH_INV,

	RXE_SUP_UD_QP_SEND_OPS_FLAGS =
		IBV_QP_EX_WITH_SEND | IBV_QP_EX_WITH_SEND_WITH_IMM,
};

static int check_qp_init_attr(struct ibv_qp_init_attr_ex *attr)
{
	if (attr->comp_mask & ~RXE_QP_COMP_MASK_SUP)
		goto err;

	if ((attr->comp_mask & IBV_QP_INIT_ATTR_CREATE_FLAGS) &&
	    (attr->create_flags & ~RXE_QP_CREATE_FLAGS_SUP))
		goto err;

	if (attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS) {
		switch (attr->qp_type) {
		case IBV_QPT_RC:
			if (attr->send_ops_flags & ~RXE_SUP_RC_QP_SEND_OPS_FLAGS)
				goto err;
			break;
		case IBV_QPT_UC:
			if (attr->send_ops_flags & ~RXE_SUP_UC_QP_SEND_OPS_FLAGS)
				goto err;
			break;
		case IBV_QPT_UD:
			if (attr->send_ops_flags & ~RXE_SUP_UD_QP_SEND_OPS_FLAGS)
				goto err;
			break;
		default:
			goto err;
		}
	}

	return 0;
err:
	errno = EOPNOTSUPP;
	return errno;
}

static void set_qp_send_ops(struct rxe_qp *qp, uint64_t flags)
{
	if (flags & IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP)
		qp->vqp.qp_ex.wr_atomic_cmp_swp = wr_atomic_cmp_swp;

	if (flags & IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD)
		qp->vqp.qp_ex.wr_atomic_fetch_add = wr_atomic_fetch_add;

	if (flags & IBV_QP_EX_WITH_BIND_MW)
		qp->vqp.qp_ex.wr_bind_mw = wr_bind_mw;

	if (flags & IBV_QP_EX_WITH_LOCAL_INV)
		qp->vqp.qp_ex.wr_local_inv = wr_local_inv;

	if (flags & IBV_QP_EX_WITH_RDMA_READ)
		qp->vqp.qp_ex.wr_rdma_read = wr_rdma_read;

	if (flags & IBV_QP_EX_WITH_RDMA_WRITE)
		qp->vqp.qp_ex.wr_rdma_write = wr_rdma_write;

	if (flags & IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM)
		qp->vqp.qp_ex.wr_rdma_write_imm = wr_rdma_write_imm;

	if (flags & IBV_QP_EX_WITH_SEND)
		qp->vqp.qp_ex.wr_send = wr_send;

	if (flags & IBV_QP_EX_WITH_SEND_WITH_IMM)
		qp->vqp.qp_ex.wr_send_imm = wr_send_imm;

	if (flags & IBV_QP_EX_WITH_SEND_WITH_INV)
		qp->vqp.qp_ex.wr_send_inv = wr_send_inv;

	qp->vqp.qp_ex.wr_set_ud_addr = wr_set_ud_addr;
	qp->vqp.qp_ex.wr_set_inline_data = wr_set_inline_data;
	qp->vqp.qp_ex.wr_set_inline_data_list = wr_set_inline_data_list;
	qp->vqp.qp_ex.wr_set_sge = wr_set_sge;
	qp->vqp.qp_ex.wr_set_sge_list = wr_set_sge_list;

	qp->vqp.qp_ex.wr_start = wr_start;
	qp->vqp.qp_ex.wr_complete = wr_complete;
	qp->vqp.qp_ex.wr_abort = wr_abort;
}

static struct ibv_qp *rxe_create_qp_ex(struct ibv_context *context,
				struct ibv_qp_init_attr_ex *attr)
{
	int ret;
	struct rxe_qp *qp;
	struct ibv_create_qp_ex cmd = {};
	struct urxe_create_qp_ex_resp resp = {};
	size_t cmd_size = sizeof(cmd);
	size_t resp_size = sizeof(resp);

	ret = check_qp_init_attr(attr);
	if (ret)
		goto err;

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		goto err;

	if (attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS)
		set_qp_send_ops(qp, attr->send_ops_flags);

	ret = ibv_cmd_create_qp_ex2(context, &qp->vqp, attr,
				    &cmd, cmd_size,
				    &resp.ibv_resp, resp_size);
	if (ret)
		goto err_free;

	qp->vqp.comp_mask |= VERBS_QP_EX;

	ret = map_queue_pair(context->cmd_fd, qp,
			     (struct ibv_qp_init_attr *)attr,
			     &resp.drv_payload);
	if (ret)
		goto err_destroy;

	return &qp->vqp.qp;

err_destroy:
	ibv_cmd_destroy_qp(&qp->vqp.qp);
err_free:
	free(qp);
err:
	return NULL;
}

static int rxe_query_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
			int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd = {};

	return ibv_cmd_query_qp(ibqp, attr, attr_mask, init_attr,
				&cmd, sizeof(cmd));
}

static int rxe_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
		  int attr_mask)
{
	struct ibv_modify_qp cmd = {};

	return ibv_cmd_modify_qp(ibqp, attr, attr_mask, &cmd, sizeof(cmd));
}

static int rxe_destroy_qp(struct ibv_qp *ibqp)
{
	int ret;
	struct rxe_qp *qp = to_rqp(ibqp);

	ret = ibv_cmd_destroy_qp(ibqp);
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
static int validate_send_wr(struct rxe_qp *qp, struct ibv_send_wr *ibwr,
			    unsigned int length)
{
	struct rxe_wq *sq = &qp->sq;
	enum ibv_wr_opcode opcode = ibwr->opcode;

	if (ibwr->num_sge > sq->max_sge)
		return -EINVAL;

	if ((opcode == IBV_WR_ATOMIC_CMP_AND_SWP)
	    || (opcode == IBV_WR_ATOMIC_FETCH_AND_ADD))
		if (length < 8 || ibwr->wr.atomic.remote_addr & 0x7)
			return -EINVAL;

	if ((ibwr->send_flags & IBV_SEND_INLINE) && (length > sq->max_inline))
		return -EINVAL;

	if (ibwr->opcode == IBV_WR_BIND_MW) {
		if (length)
			return -EINVAL;
		if (ibwr->num_sge)
			return -EINVAL;
		if (ibwr->imm_data)
			return -EINVAL;
		if ((qp_type(qp) != IBV_QPT_RC) && (qp_type(qp) != IBV_QPT_UC))
			return -EINVAL;
	}

	return 0;
}

static void convert_send_wr(struct rxe_send_wr *kwr, struct ibv_send_wr *uwr)
{
	struct ibv_mw *ibmw;
	struct ibv_mr *ibmr;

	memset(kwr, 0, sizeof(*kwr));

	kwr->wr_id		= uwr->wr_id;
	kwr->num_sge		= uwr->num_sge;
	kwr->opcode		= uwr->opcode;
	kwr->send_flags		= uwr->send_flags;
	kwr->ex.imm_data	= uwr->imm_data;

	switch (uwr->opcode) {
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

	case IBV_WR_BIND_MW:
		ibmr = uwr->bind_mw.bind_info.mr;
		ibmw = uwr->bind_mw.mw;

		kwr->wr.mw.addr = uwr->bind_mw.bind_info.addr;
		kwr->wr.mw.length = uwr->bind_mw.bind_info.length;
		kwr->wr.mw.mr_lkey = ibmr->lkey;
		kwr->wr.mw.mw_rkey = ibmw->rkey;
		kwr->wr.mw.rkey = uwr->bind_mw.rkey;
		kwr->wr.mw.access = uwr->bind_mw.bind_info.mw_access_flags;
		break;

	default:
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
		memcpy(&wqe->wr.wr.ud.av, &to_rah(ibwr->wr.ud.ah)->av,
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

	err = validate_send_wr(qp, ibwr, length);
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
 * restartable and non-restartable errors
 */
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

	ah = calloc(1, sizeof(*ah));
	if (ah == NULL)
		return NULL;

	av = &ah->av;
	av->port_num = attr->port_num;
	memcpy(&av->grh, &attr->grh, sizeof(attr->grh));
	av->network_type =
		ipv6_addr_v4mapped((struct in6_addr *)attr->grh.dgid.raw) ?
		RXE_NETWORK_TYPE_IPV4 : RXE_NETWORK_TYPE_IPV6;

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
	.query_device_ex = rxe_query_device,
	.query_port = rxe_query_port,
	.alloc_pd = rxe_alloc_pd,
	.dealloc_pd = rxe_dealloc_pd,
	.reg_mr = rxe_reg_mr,
	.dereg_mr = rxe_dereg_mr,
	.alloc_mw = rxe_alloc_mw,
	.dealloc_mw = rxe_dealloc_mw,
	.bind_mw = rxe_bind_mw,
	.create_cq = rxe_create_cq,
	.create_cq_ex = rxe_create_cq_ex,
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
	.create_qp_ex = rxe_create_qp_ex,
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

	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof(cmd),
				&resp, sizeof(resp)))
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
