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
#include <sys/mman.h>
#include <netinet/in.h>
#include <unistd.h>
#include <ccan/ilog.h>

#include <util/compiler.h>
#include <util/util.h>

#include "main.h"
#include "verbs.h"

static int bnxt_re_poll_one(struct bnxt_re_cq *cq, int nwc, struct ibv_wc *wc,
			    uint32_t *resize);
int bnxt_re_query_device(struct ibv_context *context,
			 const struct ibv_query_device_ex_input *input,
			 struct ibv_device_attr_ex *attr, size_t attr_size)
{
	struct ib_uverbs_ex_query_device_resp resp;
	size_t resp_size = sizeof(resp);
	uint8_t fw_ver[8];
	int err;

	err = ibv_cmd_query_device_any(context, input, attr, attr_size, &resp,
				       &resp_size);
	if (err)
		return err;

	memcpy(fw_ver, &resp.base.fw_ver, sizeof(resp.base.fw_ver));
	snprintf(attr->orig_attr.fw_ver, 64, "%d.%d.%d.%d", fw_ver[0],
		 fw_ver[1], fw_ver[2], fw_ver[3]);
	return 0;
}

int bnxt_re_query_port(struct ibv_context *ibvctx, uint8_t port,
		       struct ibv_port_attr *port_attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(ibvctx, port, port_attr, &cmd, sizeof(cmd));
}

static inline bool bnxt_re_is_wcdpi_enabled(struct bnxt_re_context *cntx)
{
	return cntx->comp_mask & BNXT_RE_COMP_MASK_UCNTX_WC_DPI_ENABLED;
}

static int bnxt_re_map_db_page(struct ibv_context *ibvctx,
			       uint64_t dbr, uint32_t dpi)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ibvctx->device);

	cntx->udpi.dpindx = dpi;
	cntx->udpi.dbpage = mmap(NULL, dev->pg_size, PROT_WRITE,
				 MAP_SHARED, ibvctx->cmd_fd, dbr);
	if (cntx->udpi.dbpage == MAP_FAILED)
		return -ENOMEM;
	return 0;
}

int bnxt_re_get_toggle_mem(struct ibv_context *ibvctx,
			   struct bnxt_re_mmap_info *minfo,
			   uint32_t *page_handle)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       BNXT_RE_OBJECT_GET_TOGGLE_MEM,
			       BNXT_RE_METHOD_GET_TOGGLE_MEM,
			       4);
	struct ib_uverbs_attr *handle;
	int ret;

	handle = fill_attr_out_obj(cmd, BNXT_RE_TOGGLE_MEM_HANDLE);
	fill_attr_const_in(cmd, BNXT_RE_TOGGLE_MEM_TYPE, minfo->type);
	fill_attr_in(cmd, BNXT_RE_TOGGLE_MEM_RES_ID, &minfo->res_id, sizeof(minfo->res_id));
	fill_attr_out_ptr(cmd, BNXT_RE_TOGGLE_MEM_MMAP_PAGE,  &minfo->alloc_offset);
	fill_attr_out_ptr(cmd, BNXT_RE_TOGGLE_MEM_MMAP_LENGTH, &minfo->alloc_size);
	fill_attr_out_ptr(cmd, BNXT_RE_TOGGLE_MEM_MMAP_OFFSET, &minfo->pg_offset);


	ret = execute_ioctl(ibvctx, cmd);

	if (ret)
		return ret;
	if (page_handle)
		*page_handle = read_attr_obj(BNXT_RE_TOGGLE_MEM_HANDLE, handle);
	return 0;
}


int bnxt_re_notify_drv(struct ibv_context *ibvctx)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       BNXT_RE_OBJECT_NOTIFY_DRV,
			       BNXT_RE_METHOD_NOTIFY_DRV,
			       0);

	return execute_ioctl(ibvctx, cmd);
}

int bnxt_re_alloc_page(struct ibv_context *ibvctx,
		       struct bnxt_re_mmap_info *minfo,
		       uint32_t *page_handle)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       BNXT_RE_OBJECT_ALLOC_PAGE,
			       BNXT_RE_METHOD_ALLOC_PAGE,
			       4);
	struct ib_uverbs_attr *handle;
	int ret;

	handle = fill_attr_out_obj(cmd, BNXT_RE_ALLOC_PAGE_HANDLE);
	fill_attr_const_in(cmd, BNXT_RE_ALLOC_PAGE_TYPE, minfo->type);
	fill_attr_out_ptr(cmd, BNXT_RE_ALLOC_PAGE_MMAP_OFFSET,
			  &minfo->alloc_offset);
	fill_attr_out_ptr(cmd, BNXT_RE_ALLOC_PAGE_MMAP_LENGTH, &minfo->alloc_size);
	fill_attr_out_ptr(cmd, BNXT_RE_ALLOC_PAGE_DPI, &minfo->dpi);

	ret = execute_ioctl(ibvctx, cmd);

	if (ret)
		return ret;
	if (page_handle)
		*page_handle = read_attr_obj(BNXT_RE_ALLOC_PAGE_HANDLE, handle);
	return 0;
}

static int bnxt_re_alloc_map_push_page(struct ibv_context *ibvctx)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_mmap_info minfo = {};
	int ret;

	minfo.type = BNXT_RE_ALLOC_WC_PAGE;
	ret = bnxt_re_alloc_page(ibvctx, &minfo, &cntx->wc_handle);
	if (ret)
		return ret;

	cntx->udpi.wcdbpg = mmap(NULL, minfo.alloc_size, PROT_WRITE,
				 MAP_SHARED, ibvctx->cmd_fd, minfo.alloc_offset);
	if (cntx->udpi.wcdbpg == MAP_FAILED)
		return -ENOMEM;

	cntx->udpi.wcdpi = minfo.dpi;
	return 0;
}



struct ibv_pd *bnxt_re_alloc_pd(struct ibv_context *ibvctx)
{
	struct ibv_alloc_pd cmd;
	struct ubnxt_re_pd_resp resp;
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_pd *pd;
	uint64_t dbr = 0;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	memset(&resp, 0, sizeof(resp));
	if (ibv_cmd_alloc_pd(ibvctx, &pd->ibvpd, &cmd, sizeof(cmd),
			     &resp.ibv_resp, sizeof(resp)))
		goto out;

	pd->pdid = resp.pdid;
	dbr = resp.dbr;
	static_assert(offsetof(struct ubnxt_re_pd_resp, dbr) == 4 * 3,
		      "Bad dbr placement");

	/* Map DB page now. */
	if (!cntx->udpi.dbpage) {
		if (bnxt_re_map_db_page(ibvctx, dbr, resp.dpi))
			goto fail;
		if (bnxt_re_is_wcdpi_enabled(cntx)) {
			bnxt_re_alloc_map_push_page(ibvctx);
			if (cntx->cctx.gen_p5_p7 && cntx->udpi.wcdpi)
				bnxt_re_init_pbuf_list(cntx);
		}
        }

	return &pd->ibvpd;
fail:
	(void)ibv_cmd_dealloc_pd(&pd->ibvpd);
out:
	free(pd);
	return NULL;
}

int bnxt_re_free_pd(struct ibv_pd *ibvpd)
{
	struct bnxt_re_pd *pd = to_bnxt_re_pd(ibvpd);
	int status;

	status = ibv_cmd_dealloc_pd(ibvpd);
	if (status)
		return status;
	/* DPI un-mapping will be during uninit_ucontext */
	free(pd);

	return 0;
}

struct ibv_mr *bnxt_re_reg_mr(struct ibv_pd *ibvpd, void *sva, size_t len,
			      uint64_t hca_va, int access)
{
	struct bnxt_re_mr *mr;
	struct ibv_reg_mr cmd;
	struct ubnxt_re_mr_resp resp;

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return NULL;

	if (ibv_cmd_reg_mr(ibvpd, sva, len, hca_va, access, &mr->vmr, &cmd,
			   sizeof(cmd), &resp.ibv_resp, sizeof(resp))) {
		free(mr);
		return NULL;
	}

	return &mr->vmr.ibv_mr;
}

struct ibv_mr *bnxt_re_reg_dmabuf_mr(struct ibv_pd *ibvpd, uint64_t start, size_t len,
				     uint64_t iova, int fd, int access)
{
	struct bnxt_re_mr *mr;

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return NULL;

	if (ibv_cmd_reg_dmabuf_mr(ibvpd, start, len, iova, fd,
				  access, &mr->vmr, NULL)) {
		free(mr);
		return NULL;
	}

	return &mr->vmr.ibv_mr;
}

int bnxt_re_dereg_mr(struct verbs_mr *vmr)
{
	struct bnxt_re_mr *mr = (struct bnxt_re_mr *)vmr;
	int status;

	status = ibv_cmd_dereg_mr(vmr);
	if (status)
		return status;
	free(mr);

	return 0;
}

static void *bnxt_re_alloc_cqslab(struct bnxt_re_context *cntx,
				  uint32_t ncqe, uint32_t cur)
{
	struct bnxt_re_mem *mem;
	uint32_t depth, sz;

	depth = bnxt_re_init_depth(ncqe + 1, cntx->comp_mask);
	if (depth > cntx->rdev->max_cq_depth + 1)
		depth = cntx->rdev->max_cq_depth + 1;
	if (depth == cur)
		return NULL;
	sz = align((depth * cntx->rdev->cqe_size), cntx->rdev->pg_size);
	mem = bnxt_re_alloc_mem(sz, cntx->rdev->pg_size);
	if (mem)
		mem->pad = depth;
	return mem;
}

struct ibv_cq *bnxt_re_create_cq(struct ibv_context *ibvctx, int ncqe,
				 struct ibv_comp_channel *channel, int vec)
{
	struct bnxt_re_cq *cq;
	struct ubnxt_re_cq cmd;
	struct ubnxt_re_cq_resp resp;
	struct bnxt_re_mmap_info minfo = {};
	int ret;

	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ibvctx->device);

	if (ncqe > dev->max_cq_depth) {
		errno = EINVAL;
		return NULL;
	}

	cq = calloc(1, (sizeof(*cq) + sizeof(struct bnxt_re_queue)));
	if (!cq)
		return NULL;

	/* Enable deferred DB mode for CQ if the CQ is small */
	if (ncqe * 2 < dev->max_cq_depth) {
		cq->deffered_db_sup = true;
		ncqe = 2 * ncqe;
	}

	cq->cqq = (void *)((char *)cq + sizeof(*cq));
	if (!cq->cqq)
		goto fail;

	cq->mem = bnxt_re_alloc_cqslab(cntx, ncqe, 0);
	if (!cq->mem)
		goto fail;
	cq->cqq->depth = cq->mem->pad;
	cq->cqq->stride = dev->cqe_size;
	/* As an exception no need to call get_ring api we know
	 * this is the only consumer
	 */
	cq->cqq->va = cq->mem->va_head;
	if (!cq->cqq->va)
		goto cmdfail;

	pthread_spin_init(&cq->cqq->qlock, PTHREAD_PROCESS_PRIVATE);

	cmd.cq_va = (uintptr_t)cq->cqq->va;
	cmd.cq_handle = (uintptr_t)cq;

	memset(&resp, 0, sizeof(resp));
	if (ibv_cmd_create_cq(ibvctx, ncqe, channel, vec,
			      &cq->ibvcq, &cmd.ibv_cmd, sizeof(cmd),
			      &resp.ibv_resp, sizeof(resp)))
		goto cmdfail;

	cq->cqid = resp.cqid;
	cq->phase = resp.phase;
	cq->cqq->tail = resp.tail;
	cq->udpi = &cntx->udpi;
	cq->cntx = cntx;
	cq->rand.seed = cq->cqid;

	if (resp.comp_mask & BNXT_RE_CQ_TOGGLE_PAGE_SUPPORT) {

		minfo.type = BNXT_RE_CQ_TOGGLE_MEM;
		minfo.res_id = resp.cqid;
		ret = bnxt_re_get_toggle_mem(ibvctx, &minfo, &cq->mem_handle);
		if (ret)
			goto cmdfail;
		cq->toggle_map = mmap(NULL, minfo.alloc_size, PROT_READ,
				MAP_SHARED, ibvctx->cmd_fd, minfo.alloc_offset);
		if (cq->toggle_map == MAP_FAILED)
			goto cmdfail;
		cq->toggle_size = minfo.alloc_size;
	}
	list_head_init(&cq->sfhead);
	list_head_init(&cq->rfhead);
	list_head_init(&cq->prev_cq_head);

	return &cq->ibvcq;
cmdfail:
	bnxt_re_free_mem(cq->mem);
fail:
	free(cq);
	return NULL;
}

#define BNXT_RE_QUEUE_START_PHASE	0x01
/*
 * Function to complete the last steps in CQ resize. Invoke poll function
 * in the kernel driver; this serves as a signal to the driver to complete CQ
 * resize steps required. Free memory mapped for the original CQ and switch
 * over to the memory mapped for CQ with the new size. Finally Ack the Cutoff
 * CQE. This function must be called under cq->cqq.lock.
 */
static void bnxt_re_resize_cq_complete(struct bnxt_re_cq *cq)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(cq->ibvcq.context);
	struct ibv_wc tmp_wc;

	ibv_cmd_poll_cq(&cq->ibvcq, 1, &tmp_wc);
	bnxt_re_free_mem(cq->mem);

	cq->mem = cq->resize_mem;
	cq->resize_mem = NULL;
	cq->cqq->va = cq->mem->va_head;

	/* mark the CQ resize flag and save the old head index */
	cq->cqq->cq_resized = true;
	cq->cqq->old_head = cq->cqq->head;

	cq->cqq->depth = cq->mem->pad;
	cq->cqq->stride = cntx->rdev->cqe_size;
	cq->cqq->head = 0;
	cq->cqq->tail = 0;
	cq->phase = BNXT_RE_QUEUE_START_PHASE;
	/* Reset epoch portion of the flags */
	cq->cqq->flags &= ~(BNXT_RE_FLAG_EPOCH_TAIL_MASK);
	bnxt_re_ring_cq_arm_db(cq, BNXT_RE_QUE_TYPE_CQ_CUT_ACK);
}

int bnxt_re_resize_cq(struct ibv_cq *ibvcq, int ncqe)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvcq->context);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ibvcq->context->device);
	struct bnxt_re_cq *cq = to_bnxt_re_cq(ibvcq);
	struct ib_uverbs_resize_cq_resp resp = {};
	struct ubnxt_re_resize_cq cmd = {};
	uint16_t msec_wait = 100;
	uint16_t exit_cnt = 20;
	int rc = 0;

	if (ncqe > dev->max_cq_depth)
		return -EINVAL;

	/* Check if we can be in defered DB mode with the
	 * newer size of CQE.
	 */
	if (2 * ncqe > dev->max_cq_depth) {
		cq->deffered_db_sup = false;
	} else {
		ncqe = 2 * ncqe;
		cq->deffered_db_sup = true;
	}

	pthread_spin_lock(&cq->cqq->qlock);

	cq->resize_mem = bnxt_re_alloc_cqslab(cntx, ncqe, cq->cqq->depth);
	if (unlikely(!cq->resize_mem)) {
		rc = -ENOMEM;
		goto done;
	}
	/* As an exception no need to call get_ring api we know
	 * this is the only consumer
	 */
	cmd.cq_va = (uintptr_t)cq->resize_mem->va_head;
	rc = ibv_cmd_resize_cq(ibvcq, ncqe, &cmd.ibv_cmd,
			       sizeof(cmd), &resp, sizeof(resp));
	if (rc) {
		bnxt_re_free_mem(cq->mem);
		goto done;
	}

	while (true) {
		struct bnxt_re_work_compl *compl = NULL;
		struct ibv_wc tmp_wc = {};
		uint32_t resize = 0;
		int dqed = 0;

		dqed = bnxt_re_poll_one(cq, 1, &tmp_wc, &resize);
		if (resize)
			break;
		if (dqed) {
			compl = calloc(1, sizeof(*compl));
			if (!compl)
				break;
			memcpy(&compl->wc, &tmp_wc, sizeof(tmp_wc));
			list_add_tail(&cq->prev_cq_head, &compl->list);
			compl = NULL;
			memset(&tmp_wc, 0, sizeof(tmp_wc));
		} else {
			exit_cnt--;
			if (unlikely(!exit_cnt)) {
				rc = -EIO;
				break;
			}
			bnxt_re_sub_sec_busy_wait(msec_wait * 1000000);
		}
	}
done:
	pthread_spin_unlock(&cq->cqq->qlock);
	return rc;
}

static void bnxt_re_destroy_resize_cq_list(struct bnxt_re_cq *cq)
{
	struct bnxt_re_work_compl *compl, *tmp;

	if (list_empty(&cq->prev_cq_head))
		return;

	list_for_each_safe(&cq->prev_cq_head, compl, tmp, list) {
		list_del(&compl->list);
		free(compl);
	}
}

int bnxt_re_destroy_cq(struct ibv_cq *ibvcq)
{
	int status;
	struct bnxt_re_cq *cq = to_bnxt_re_cq(ibvcq);

	if (cq->toggle_map)
		munmap(cq->toggle_map, cq->toggle_size);
	status = ibv_cmd_destroy_cq(ibvcq);
	if (status)
		return status;
	bnxt_re_destroy_resize_cq_list(cq);
	bnxt_re_free_mem(cq->mem);
	free(cq);
	return 0;
}

static uint8_t bnxt_re_poll_err_scqe(struct bnxt_re_qp *qp,
				     struct ibv_wc *ibvwc,
				     struct bnxt_re_bcqe *hdr,
				     struct bnxt_re_req_cqe *scqe, int *cnt)
{
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	struct bnxt_re_wrid *swrid;
	struct bnxt_re_cq *scq;
	uint8_t status;
	uint32_t head;

	scq = to_bnxt_re_cq(qp->ibvqp->send_cq);

	head = qp->jsqq->last_idx;
	swrid = &qp->jsqq->swque[head];

	*cnt = 1;
	status = (le32toh(hdr->flg_st_typ_ph) >> BNXT_RE_BCQE_STATUS_SHIFT) &
		  BNXT_RE_BCQE_STATUS_MASK;
	ibvwc->status = bnxt_re_to_ibv_wc_status(status, true);
	ibvwc->vendor_err = status;
	ibvwc->wc_flags = 0;
	ibvwc->wr_id = swrid->wrid;
	ibvwc->qp_num = qp->qpid;
	ibvwc->opcode = swrid->wc_opcd;
	ibvwc->byte_len = 0;

	bnxt_re_incr_head(sq, swrid->slots);
	bnxt_re_jqq_mod_last(qp->jsqq, head);

	if (qp->qpst != IBV_QPS_ERR)
		qp->qpst = IBV_QPS_ERR;
	bnxt_re_fque_add_node(&scq->sfhead, &qp->snode);

	return false;
}

static uint8_t bnxt_re_poll_success_scqe(struct bnxt_re_qp *qp,
					 struct ibv_wc *ibvwc,
					 struct bnxt_re_bcqe *hdr,
					 struct bnxt_re_req_cqe *scqe,
					 int *cnt)
{
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	struct bnxt_re_wrid *swrid;
	uint32_t cindx;
	uint32_t head;

	head = qp->jsqq->last_idx;
	swrid = &qp->jsqq->swque[head];
	cindx = le32toh(scqe->con_indx) % qp->cap.max_swr;

	if (!(swrid->sig & IBV_SEND_SIGNALED)) {
		*cnt = 0;
	} else {
		ibvwc->status = IBV_WC_SUCCESS;
		ibvwc->wc_flags = 0;
		ibvwc->qp_num = qp->qpid;
		ibvwc->wr_id = swrid->wrid;
		ibvwc->opcode = swrid->wc_opcd;
		if (ibvwc->opcode == IBV_WC_RDMA_READ ||
		    ibvwc->opcode == IBV_WC_COMP_SWAP ||
		    ibvwc->opcode == IBV_WC_FETCH_ADD)
			ibvwc->byte_len = swrid->bytes;

		*cnt = 1;
	}

	bnxt_re_incr_head(sq, swrid->slots);
	bnxt_re_jqq_mod_last(qp->jsqq, head);

	if (qp->jsqq->last_idx != cindx)
		return true;

	return false;
}

static uint8_t bnxt_re_poll_scqe(struct bnxt_re_qp *qp, struct ibv_wc *ibvwc,
				 void *cqe, int *cnt)
{
	struct bnxt_re_req_cqe *scqe;
	struct bnxt_re_bcqe *hdr;
	uint8_t status;

	scqe = cqe;
	hdr = cqe + sizeof(struct bnxt_re_req_cqe);

	status = (le32toh(hdr->flg_st_typ_ph) >> BNXT_RE_BCQE_STATUS_SHIFT) &
		  BNXT_RE_BCQE_STATUS_MASK;
	if (likely(status == BNXT_RE_REQ_ST_OK))
		return bnxt_re_poll_success_scqe(qp, ibvwc, hdr, scqe, cnt);
	else
		return bnxt_re_poll_err_scqe(qp, ibvwc, hdr, scqe, cnt);
}

static void bnxt_re_release_srqe(struct bnxt_re_srq *srq, int tag)
{
	pthread_spin_lock(&srq->srqq->qlock);
	srq->srwrid[srq->last_idx].next_idx = tag;
	srq->last_idx = tag;
	srq->srwrid[srq->last_idx].next_idx = -1;
	pthread_spin_unlock(&srq->srqq->qlock);
}

static int bnxt_re_poll_err_rcqe(struct bnxt_re_qp *qp, struct ibv_wc *ibvwc,
				 struct bnxt_re_bcqe *hdr, void *cqe)
{
	struct bnxt_re_wrid *swque;
	struct bnxt_re_queue *rq;
	uint8_t status, cnt = 0;
	struct bnxt_re_cq *rcq;
	uint32_t head = 0;

	rcq = to_bnxt_re_cq(qp->ibvqp->recv_cq);

	if (!qp->srq) {
		rq = qp->jrqq->hwque;
		head = qp->jrqq->last_idx;
		swque = &qp->jrqq->swque[head];
		ibvwc->wr_id = swque->wrid;
		cnt = swque->slots;
	} else {
		struct bnxt_re_srq *srq;
		int tag;

		srq = qp->srq;
		rq = srq->srqq;
		cnt = 1;
		tag = le32toh(hdr->qphi_rwrid) & BNXT_RE_BCQE_RWRID_MASK;
		ibvwc->wr_id = srq->srwrid[tag].wrid;
		bnxt_re_release_srqe(srq, tag);
	}

	status = (le32toh(hdr->flg_st_typ_ph) >> BNXT_RE_BCQE_STATUS_SHIFT) &
		  BNXT_RE_BCQE_STATUS_MASK;
	/* skip h/w flush errors */
	if (status == BNXT_RE_RSP_ST_HW_FLUSH)
		return 0;

	ibvwc->status = bnxt_re_to_ibv_wc_status(status, false);
	ibvwc->vendor_err = status;
	ibvwc->qp_num = qp->qpid;
	ibvwc->opcode = IBV_WC_RECV;
	ibvwc->byte_len = 0;
	ibvwc->wc_flags = 0;
	if (qp->qptyp == IBV_QPT_UD)
		ibvwc->src_qp = 0;

	if (!qp->srq)
		bnxt_re_jqq_mod_last(qp->jrqq, head);
	bnxt_re_incr_head(rq, cnt);

	if (!qp->srq)
		bnxt_re_fque_add_node(&rcq->rfhead, &qp->rnode);

	return 1;
}

static void bnxt_re_fill_ud_cqe(struct ibv_wc *ibvwc,
				struct bnxt_re_bcqe *hdr, void *cqe, uint8_t flags)
{
	struct bnxt_re_ud_cqe *ucqe = cqe;
	uint32_t qpid;

	qpid = ((le32toh(hdr->qphi_rwrid) >> BNXT_RE_BCQE_SRCQP_SHIFT) &
		 BNXT_RE_BCQE_SRCQP_SHIFT) << 0x10; /* higher 8 bits of 24 */
	qpid |= (le64toh(ucqe->qplo_mac) >> BNXT_RE_UD_CQE_SRCQPLO_SHIFT) &
		 BNXT_RE_UD_CQE_SRCQPLO_MASK; /*lower 16 of 24 */
	ibvwc->src_qp = qpid;
	ibvwc->wc_flags |= IBV_WC_GRH;
	ibvwc->sl = (flags & BNXT_RE_UD_FLAGS_IP_VER_MASK) >>
                     BNXT_RE_UD_FLAGS_IP_VER_SFT;
	/*IB-stack ABI in user do not ask for MAC to be reported. */
}

static void bnxt_re_poll_success_rcqe(struct bnxt_re_qp *qp,
				      struct ibv_wc *ibvwc,
				      struct bnxt_re_bcqe *hdr, void *cqe)
{
	uint8_t flags, is_imm, is_rdma;
	struct bnxt_re_rc_cqe *rcqe;
	struct bnxt_re_wrid *swque;
	struct bnxt_re_queue *rq;
	uint32_t rcqe_len;
	uint32_t head = 0;
	uint8_t cnt = 0;

	rcqe = cqe;
	if (!qp->srq) {
		rq = qp->jrqq->hwque;
		head = qp->jrqq->last_idx;
		swque = &qp->jrqq->swque[head];
		ibvwc->wr_id = swque->wrid;
		cnt = swque->slots;
	} else {
		struct bnxt_re_srq *srq;
		int tag;

		srq = qp->srq;
		rq = srq->srqq;
		tag = le32toh(hdr->qphi_rwrid) & BNXT_RE_BCQE_RWRID_MASK;
		ibvwc->wr_id = srq->srwrid[tag].wrid;
		cnt = 1;
		bnxt_re_release_srqe(srq, tag);
	}

	ibvwc->status = IBV_WC_SUCCESS;
	ibvwc->qp_num = qp->qpid;
	rcqe_len = le32toh(rcqe->length);
	ibvwc->byte_len = (qp->qptyp == IBV_QPT_UD) ?
		rcqe_len & BNXT_RE_UD_CQE_LEN_MASK: rcqe_len ;
	ibvwc->opcode = IBV_WC_RECV;

	flags = (le32toh(hdr->flg_st_typ_ph) >> BNXT_RE_BCQE_FLAGS_SHIFT) &
		 BNXT_RE_BCQE_FLAGS_MASK;
	is_imm = (flags & BNXT_RE_RC_FLAGS_IMM_MASK) >>
		     BNXT_RE_RC_FLAGS_IMM_SHIFT;
	is_rdma = (flags & BNXT_RE_RC_FLAGS_RDMA_MASK) >>
		   BNXT_RE_RC_FLAGS_RDMA_SHIFT;
	ibvwc->wc_flags = 0;
	if (is_imm) {
		ibvwc->wc_flags |= IBV_WC_WITH_IMM;
		/* Completion reports the raw-data in LE format, While
		 * user expects it in BE format. Thus, swapping on outgoing
		 * data is needed. On a BE platform le32toh will do the swap
		 * while on LE platform htobe32 will do the job.
		 */
		ibvwc->imm_data = htobe32(le32toh(rcqe->imm_key));
		if (is_rdma)
			ibvwc->opcode = IBV_WC_RECV_RDMA_WITH_IMM;
	}

	if (qp->qptyp == IBV_QPT_UD)
		bnxt_re_fill_ud_cqe(ibvwc, hdr, cqe, flags);

	if (!qp->srq)
		bnxt_re_jqq_mod_last(qp->jrqq, head);
	bnxt_re_incr_head(rq, cnt);
}

static uint8_t bnxt_re_poll_rcqe(struct bnxt_re_qp *qp, struct ibv_wc *ibvwc,
				 void *cqe, int *cnt)
{
	struct bnxt_re_bcqe *hdr;
	uint8_t status, pcqe = false;

	hdr = cqe + sizeof(struct bnxt_re_rc_cqe);

	status = (le32toh(hdr->flg_st_typ_ph) >> BNXT_RE_BCQE_STATUS_SHIFT) &
		  BNXT_RE_BCQE_STATUS_MASK;
	*cnt = 1;
	if (likely(status == BNXT_RE_RSP_ST_OK))
		bnxt_re_poll_success_rcqe(qp, ibvwc, hdr, cqe);
	else
		*cnt = bnxt_re_poll_err_rcqe(qp, ibvwc, hdr, cqe);

	return pcqe;
}

static void bnxt_re_qp_move_flush_err(struct bnxt_re_qp *qp)
{
	struct bnxt_re_cq *scq, *rcq;

	scq = to_bnxt_re_cq(qp->ibvqp->send_cq);
	rcq = to_bnxt_re_cq(qp->ibvqp->recv_cq);

	if (qp->qpst != IBV_QPS_ERR)
		qp->qpst = IBV_QPS_ERR;
	bnxt_re_fque_add_node(&rcq->rfhead, &qp->rnode);
	bnxt_re_fque_add_node(&scq->sfhead, &qp->snode);
}

static uint8_t bnxt_re_poll_term_cqe(struct bnxt_re_qp *qp, int *cnt)
{
	/* For now just add the QP to flush list without
	 * considering the index reported in the CQE.
	 * Continue reporting flush completions until the
	 * SQ and RQ are empty.
	 */
	*cnt = 0;
	if (qp->qpst != IBV_QPS_RESET)
		bnxt_re_qp_move_flush_err(qp);

	return 0;
}

static inline void bnxt_re_check_and_ring_cq_db(struct bnxt_re_cq *cq,
						int *hw_polled)
{
	/* Ring doorbell only if the CQ is at
	 * least half when deferred db mode is active
	 */
	if (cq->deffered_db_sup) {
		if (cq->hw_cqes < cq->cqq->depth / 2)
			return;
		*hw_polled = 0;
		cq->hw_cqes = 0;
	}
	bnxt_re_ring_cq_db(cq);
}

static int bnxt_re_poll_one(struct bnxt_re_cq *cq, int nwc, struct ibv_wc *wc,
			    uint32_t *resize)
{
	int type, cnt = 0, dqed = 0, hw_polled = 0;
	struct bnxt_re_queue *cqq = cq->cqq;
	struct bnxt_re_req_cqe *scqe;
	struct bnxt_re_ud_cqe *rcqe;
	uint64_t *qp_handle = NULL;
	struct bnxt_re_bcqe *hdr;
	struct bnxt_re_qp *qp;
	uint8_t pcqe = false;
	uint32_t flg_val;
	void *cqe;

	while (nwc) {
		cqe = cqq->va + cqq->head * bnxt_re_get_cqe_sz();
		hdr = cqe + sizeof(struct bnxt_re_req_cqe);
		if (!bnxt_re_is_cqe_valid(cq, hdr))
			break;
		flg_val = le32toh(hdr->flg_st_typ_ph);
		type = (flg_val >> BNXT_RE_BCQE_TYPE_SHIFT) & BNXT_RE_BCQE_TYPE_MASK;
		switch (type) {
		case BNXT_RE_WC_TYPE_SEND:
			scqe = cqe;
			qp_handle = (uint64_t *)&scqe->qp_handle;
			qp = (struct bnxt_re_qp *)
			     (uintptr_t)le64toh(scqe->qp_handle);
			if (!qp)
				break; /*stale cqe. should be rung.*/
			pcqe = bnxt_re_poll_scqe(qp, wc, cqe, &cnt);
			break;
		case BNXT_RE_WC_TYPE_RECV_RC:
		case BNXT_RE_WC_TYPE_RECV_UD:
			rcqe = cqe;
			qp_handle = (uint64_t *)&rcqe->qp_handle;
			qp = (struct bnxt_re_qp *)
			     (uintptr_t)le64toh(rcqe->qp_handle);
			if (!qp)
				break; /*stale cqe. should be rung.*/
			pcqe = bnxt_re_poll_rcqe(qp, wc, cqe, &cnt);
			break;
		case BNXT_RE_WC_TYPE_RECV_RAW:
			break;
		case BNXT_RE_WC_TYPE_TERM:
			scqe = cqe;
			qp_handle = (uint64_t *)&scqe->qp_handle;
			qp = (struct bnxt_re_qp *)
			     (uintptr_t)le64toh(scqe->qp_handle);
			if (!qp)
				break;
			pcqe = bnxt_re_poll_term_cqe(qp, &cnt);
			break;
		case BNXT_RE_WC_TYPE_COFF:
			/* Stop further processing and return */
			cq->resize_tog = (flg_val >> BNXT_RE_BCQE_RESIZE_TOG_SHIFT)
						& BNXT_RE_BCQE_RESIZE_TOG_MASK;
			bnxt_re_resize_cq_complete(cq);
			if (resize)
				*resize = 1;
			return dqed;
		default:
			break;
		};

		if (pcqe)
			goto skipp_real;

		hw_polled++;
		cq->hw_cqes++;
		if (qp_handle) {
			*qp_handle = 0x0ULL; /* mark cqe as read */
			qp_handle = NULL;
		}
		bnxt_re_incr_head(cq->cqq, 1);
		bnxt_re_change_cq_phase(cq);
skipp_real:
		if (cnt) {
			cnt = 0;
			dqed++;
			nwc--;
			wc++;
		}
		/* Extra check required to avoid CQ full */
		if (cq->deffered_db_sup)
			bnxt_re_check_and_ring_cq_db(cq, &hw_polled);
	}

	if (likely(hw_polled))
		bnxt_re_check_and_ring_cq_db(cq, &hw_polled);

	return dqed;
}

static int bnxt_re_poll_flush_wcs(struct bnxt_re_joint_queue *jqq,
				  struct ibv_wc *ibvwc, uint32_t qpid,
				  int nwc)
{
	uint8_t opcode = IBV_WC_RECV;
	struct bnxt_re_queue *que;
	struct bnxt_re_wrid *wrid;
	struct bnxt_re_psns *psns;
	uint32_t cnt = 0;

	que = jqq->hwque;
	while (nwc) {
		if (bnxt_re_is_que_empty(que))
			break;
		wrid = &jqq->swque[jqq->last_idx];
		if (wrid->psns) {
			psns = wrid->psns;
			opcode = (le32toh(psns->opc_spsn) >>
				  BNXT_RE_PSNS_OPCD_SHIFT) &
				  BNXT_RE_PSNS_OPCD_MASK;
		}

		ibvwc->status = IBV_WC_WR_FLUSH_ERR;
		ibvwc->opcode = opcode;
		ibvwc->wr_id = wrid->wrid;
		ibvwc->qp_num = qpid;
		ibvwc->byte_len = 0;
		ibvwc->wc_flags = 0;

		bnxt_re_jqq_mod_last(jqq, jqq->last_idx);
		bnxt_re_incr_head(que, wrid->slots);
		nwc--;
		cnt++;
		ibvwc++;
	}

	return cnt;
}

static int bnxt_re_poll_flush_wqes(struct bnxt_re_cq *cq,
				   struct list_head *lhead,
				   struct ibv_wc *ibvwc,
				   int32_t nwc)
{
	struct bnxt_re_fque_node *cur, *tmp;
	struct bnxt_re_joint_queue *jqq;
	struct bnxt_re_qp *qp;
	bool sq_list = false;
	uint32_t polled = 0;

	sq_list = (lhead == &cq->sfhead) ? true : false;
	if (!list_empty(lhead)) {
		list_for_each_safe(lhead, cur, tmp, list) {
			if (sq_list) {
				qp = container_of(cur, struct bnxt_re_qp,
						  snode);
				jqq = qp->jsqq;
			} else {
				qp = container_of(cur, struct bnxt_re_qp,
						  rnode);
				jqq = qp->jrqq;
			}
			if (bnxt_re_is_que_empty(jqq->hwque))
				continue;
			polled += bnxt_re_poll_flush_wcs(jqq, ibvwc + polled,
							 qp->qpid,
							 nwc - polled);
			if (!(nwc - polled))
				break;
		}
	}

	return polled;
}

static int bnxt_re_poll_flush_lists(struct bnxt_re_cq *cq, uint32_t nwc,
				    struct ibv_wc *ibvwc)
{
	int left, polled = 0;

	/* Check if flush Qs are empty */
	if (list_empty(&cq->sfhead) && list_empty(&cq->rfhead))
		return 0;

	polled  = bnxt_re_poll_flush_wqes(cq, &cq->sfhead, ibvwc, nwc);
	left = nwc - polled;

	if (!left)
		return polled;

	polled  += bnxt_re_poll_flush_wqes(cq, &cq->rfhead,
			ibvwc + polled, left);
	return polled;
}

static int bnxt_re_poll_resize_cq_list(struct bnxt_re_cq *cq, uint32_t nwc,
				       struct ibv_wc *ibvwc)
{
	struct bnxt_re_work_compl *compl, *tmp;
	int left;

	left = nwc;
	list_for_each_safe(&cq->prev_cq_head, compl, tmp, list) {
		if (!left)
			break;
		memcpy(ibvwc, &compl->wc, sizeof(*ibvwc));
		ibvwc++;
		left--;
		list_del(&compl->list);
		free(compl);
	}

	return nwc - left;
}

int bnxt_re_poll_cq(struct ibv_cq *ibvcq, int nwc, struct ibv_wc *wc)
{
	struct bnxt_re_cq *cq = to_bnxt_re_cq(ibvcq);
	int dqed = 0, left = 0;
	uint32_t resize = 0;

	pthread_spin_lock(&cq->cqq->qlock);
	left = nwc;
	/* Check  whether we have anything to be completed
	 * from prev cq context.
	 */
	if (unlikely(!list_empty(&cq->prev_cq_head))) {
		dqed = bnxt_re_poll_resize_cq_list(cq, nwc, wc);
		left = nwc - dqed;
		if (!left) {
			pthread_spin_unlock(&cq->cqq->qlock);
			return dqed;
		}
	}
	dqed += bnxt_re_poll_one(cq, left, wc + dqed, &resize);
	left = nwc - dqed;
	if (unlikely(left && (!list_empty(&cq->sfhead) ||
			      !list_empty(&cq->rfhead))))
		/* Check if anything is there to flush. */
		dqed += bnxt_re_poll_flush_lists(cq, left, (wc + dqed));
	pthread_spin_unlock(&cq->cqq->qlock);

	return dqed;
}

static void bnxt_re_cleanup_cq(struct bnxt_re_qp *qp, struct bnxt_re_cq *cq)
{
	struct bnxt_re_queue *que = cq->cqq;
	struct bnxt_re_bcqe *hdr;
	struct bnxt_re_req_cqe *scqe;
	struct bnxt_re_rc_cqe *rcqe;
	void *cqe;
	int indx, type;

	pthread_spin_lock(&que->qlock);
	for (indx = 0; indx < que->depth; indx++) {
		cqe = que->va + indx * bnxt_re_get_cqe_sz();
		hdr = cqe + sizeof(struct bnxt_re_req_cqe);
		type = (le32toh(hdr->flg_st_typ_ph) >>
			BNXT_RE_BCQE_TYPE_SHIFT) & BNXT_RE_BCQE_TYPE_MASK;

		if (type == BNXT_RE_WC_TYPE_COFF)
			continue;
		if (type == BNXT_RE_WC_TYPE_SEND ||
		    type == BNXT_RE_WC_TYPE_TERM) {
			scqe = cqe;
			if (le64toh(scqe->qp_handle) == (uintptr_t)qp)
				scqe->qp_handle = 0ULL;
		} else {
			rcqe = cqe;
			if (le64toh(rcqe->qp_handle) == (uintptr_t)qp)
				rcqe->qp_handle = 0ULL;
		}

	}

	bnxt_re_fque_del_node(&qp->snode);
	bnxt_re_fque_del_node(&qp->rnode);
	pthread_spin_unlock(&que->qlock);
}

int bnxt_re_arm_cq(struct ibv_cq *ibvcq, int flags)
{
	struct bnxt_re_cq *cq = to_bnxt_re_cq(ibvcq);

	pthread_spin_lock(&cq->cqq->qlock);
	flags = !flags ? BNXT_RE_QUE_TYPE_CQ_ARMALL :
			 BNXT_RE_QUE_TYPE_CQ_ARMSE;
	bnxt_re_ring_cq_arm_db(cq, flags);
	pthread_spin_unlock(&cq->cqq->qlock);

	return 0;
}

static int bnxt_re_check_qp_limits(struct bnxt_re_context *cntx,
				   struct ibv_qp_init_attr_ex *attr)
{
	struct ibv_device_attr *devattr;
	struct bnxt_re_dev *rdev;

	rdev = cntx->rdev;
	devattr = &rdev->devattr;

	if (attr->cap.max_send_sge > devattr->max_sge)
		return EINVAL;
	if (attr->cap.max_recv_sge > devattr->max_sge)
		return EINVAL;
	if (attr->cap.max_inline_data > BNXT_RE_MAX_INLINE_SIZE)
		return EINVAL;
	if (attr->cap.max_send_wr > devattr->max_qp_wr)
		return EINVAL;
	if (attr->cap.max_recv_wr > devattr->max_qp_wr)
		return EINVAL;

	return 0;
}

static int bnxt_re_calc_wqe_sz(int nsge)
{
	/* This is used for both sq and rq. In case hdr size differs
	 * in future move to individual functions.
	 */
	return sizeof(struct bnxt_re_sge) * nsge + bnxt_re_get_sqe_hdr_sz();
}

static int bnxt_re_get_rq_slots(struct bnxt_re_dev *rdev, uint8_t qpmode,
				uint32_t nrwr, uint32_t nsge, uint32_t *esz)
{
	uint32_t max_wqesz;
	uint32_t wqe_size;
	uint32_t stride;
	uint32_t slots;

	stride = sizeof(struct bnxt_re_sge);
	max_wqesz = bnxt_re_calc_wqe_sz(rdev->devattr.max_sge);

	if (qpmode == BNXT_RE_WQE_MODE_STATIC)
		nsge = BNXT_RE_STATIC_WQE_MAX_SGE;

	wqe_size = bnxt_re_calc_wqe_sz(nsge);
	if (wqe_size > max_wqesz)
		return -EINVAL;

	if (esz)
		*esz = wqe_size;

	slots = (nrwr * wqe_size) / stride;
	return slots;
}

#define BNXT_VAR_MAX_SLOT_ALIGN 256

static int bnxt_re_get_sq_slots(struct bnxt_re_dev *rdev,
				uint8_t qpmode, uint32_t nswr,
				uint32_t nsge, uint32_t ils, uint32_t *esize)
{
	uint32_t align_bytes;
	uint32_t max_wqesz;
	uint32_t wqe_size;
	uint32_t cal_ils;
	uint32_t stride;
	uint32_t ilsize;
	uint32_t hdr_sz;
	uint32_t slots;

	hdr_sz = bnxt_re_get_sqe_hdr_sz();
	stride = sizeof(struct bnxt_re_sge);
	align_bytes = hdr_sz;
	if (qpmode == BNXT_RE_WQE_MODE_VARIABLE)
		align_bytes = stride;
	max_wqesz = bnxt_re_calc_wqe_sz(rdev->devattr.max_sge);
	ilsize = align(ils, align_bytes);

	wqe_size = bnxt_re_calc_wqe_sz(nsge);
	if (ilsize) {
		cal_ils = hdr_sz + ilsize;
		wqe_size = MAX(cal_ils, wqe_size);
		wqe_size = align(wqe_size, hdr_sz);
	}
	if (wqe_size > max_wqesz)
		return -EINVAL;

	if (qpmode == BNXT_RE_WQE_MODE_STATIC)
		wqe_size = bnxt_re_calc_wqe_sz(6);

	if (esize)
		*esize = wqe_size;
	slots = (nswr * wqe_size) / stride;
	if (qpmode == BNXT_RE_WQE_MODE_VARIABLE)
		slots = align(slots, BNXT_VAR_MAX_SLOT_ALIGN);
	return slots;
}

static int bnxt_re_get_sqmem_size(struct bnxt_re_context *cntx,
				  struct ibv_qp_init_attr_ex *attr,
				  struct bnxt_re_qattr *qattr)
{
	uint32_t nsge, nswr, diff = 0;
	size_t bytes = 0;
	uint32_t npsn;
	uint32_t ils;
	uint8_t mode;
	uint32_t esz;
	int nslots;

	mode = cntx->wqe_mode & BNXT_RE_WQE_MODE_VARIABLE;
	nsge = attr->cap.max_send_sge;
	diff = BNXT_RE_FULL_FLAG_DELTA;
	nswr = attr->cap.max_send_wr + 1 + diff;
	nswr = bnxt_re_init_depth(nswr, cntx->comp_mask);
	ils = attr->cap.max_inline_data;
	nslots = bnxt_re_get_sq_slots(cntx->rdev, mode, nswr,
				      nsge, ils, &esz);
	if (nslots < 0)
		return nslots;
	npsn = bnxt_re_get_npsn(mode, nswr, nslots);
	if (BNXT_RE_MSN_TBL_EN(cntx))
		npsn = roundup_pow_of_two(npsn);

	qattr->nwr = nswr;
	qattr->slots = nslots;
	qattr->esize = esz;
	if (mode)
		qattr->sw_nwr = nslots;
	else
		qattr->sw_nwr = nswr;

	bytes = nslots * sizeof(struct bnxt_re_sge); /* ring */
	bytes += npsn * bnxt_re_get_psne_size(cntx); /* psn */
	qattr->sz_ring = align(bytes, cntx->rdev->pg_size);
	qattr->sz_shad = qattr->sw_nwr * sizeof(struct bnxt_re_wrid); /* shadow */
	return 0;
}

static int bnxt_re_get_rqmem_size(struct bnxt_re_context *cntx,
				  struct ibv_qp_init_attr_ex *attr,
				  struct bnxt_re_qattr *qattr)
{
	uint32_t nrwr, nsge;
	size_t bytes = 0;
	uint32_t esz;
	int nslots;

	nsge = attr->cap.max_recv_sge;
	nrwr = attr->cap.max_recv_wr + 1;
	nrwr = bnxt_re_init_depth(nrwr, cntx->comp_mask);
	nslots = bnxt_re_get_rq_slots(cntx->rdev, cntx->wqe_mode,
				      nrwr, nsge, &esz);
	if (nslots < 0)
		return nslots;
	qattr->nwr = nrwr;
	qattr->slots = nslots;
	qattr->esize = esz;
	qattr->sw_nwr = nrwr;

	bytes = nslots * sizeof(struct bnxt_re_sge);
	qattr->sz_ring = align(bytes, cntx->rdev->pg_size);
	qattr->sz_shad = nrwr * sizeof(struct bnxt_re_wrid);
	return 0;
}

static int bnxt_re_get_qpmem_size(struct bnxt_re_context *cntx,
				  struct ibv_qp_init_attr_ex *attr,
				  struct bnxt_re_qattr *qattr)
{
	int size = 0;
	int tmp;
	int rc;

	size = sizeof(struct bnxt_re_qp);
	tmp = sizeof(struct bnxt_re_joint_queue);
	tmp += sizeof(struct bnxt_re_queue);
	size += tmp;

	rc = bnxt_re_get_sqmem_size(cntx, attr, &qattr[BNXT_RE_QATTR_SQ_INDX]);
	if (rc < 0)
		return -EINVAL;
	size += qattr[BNXT_RE_QATTR_SQ_INDX].sz_ring;
	size += qattr[BNXT_RE_QATTR_SQ_INDX].sz_shad;

	if (!attr->srq) {
		tmp = sizeof(struct bnxt_re_joint_queue);
		tmp += sizeof(struct bnxt_re_queue);
		size += tmp;
		rc = bnxt_re_get_rqmem_size(cntx, attr,
					    &qattr[BNXT_RE_QATTR_RQ_INDX]);
		if (rc < 0)
			return -EINVAL;
		size += qattr[BNXT_RE_QATTR_RQ_INDX].sz_ring;
		size += qattr[BNXT_RE_QATTR_RQ_INDX].sz_shad;
	}
	return size;
}

static void *bnxt_re_alloc_qpslab(struct bnxt_re_context *cntx,
				  struct ibv_qp_init_attr_ex *attr,
				  struct bnxt_re_qattr *qattr)
{
	int bytes;

	bytes = bnxt_re_get_qpmem_size(cntx, attr, qattr);
	if (bytes < 0)
		return NULL;
	return bnxt_re_alloc_mem(bytes, cntx->rdev->pg_size);
}

static int bnxt_re_alloc_queue_ptr(struct bnxt_re_qp *qp,
				   struct ibv_qp_init_attr_ex *attr)
{
	int rc = -ENOMEM;
	int jqsz, qsz;

	jqsz = sizeof(struct bnxt_re_joint_queue);
	qsz = sizeof(struct bnxt_re_queue);
	qp->jsqq = bnxt_re_get_obj(qp->mem, jqsz);
	if (!qp->jsqq)
		return rc;
	qp->jsqq->hwque = bnxt_re_get_obj(qp->mem, qsz);
	if (!qp->jsqq->hwque)
		goto fail;

	if (!attr->srq) {
		qp->jrqq = bnxt_re_get_obj(qp->mem, jqsz);
		if (!qp->jrqq)
			goto fail;
		qp->jrqq->hwque = bnxt_re_get_obj(qp->mem, qsz);
		if (!qp->jrqq->hwque)
			goto fail;
	}

	return 0;
fail:
	return rc;
}

static int bnxt_re_alloc_init_swque(struct bnxt_re_joint_queue *jqq,
				    struct bnxt_re_mem *mem,
				    struct bnxt_re_qattr *qattr)
{
	int indx;

	jqq->swque = bnxt_re_get_obj(mem, qattr->sz_shad);
	if (!jqq->swque)
		return -ENOMEM;
	jqq->start_idx = 0;
	jqq->last_idx = qattr->sw_nwr - 1;
	for (indx = 0; indx < qattr->sw_nwr; indx++)
		jqq->swque[indx].next_idx = indx + 1;
	jqq->swque[jqq->last_idx].next_idx = 0;
	jqq->last_idx = 0;

	return 0;
}

static int bnxt_re_alloc_queues(struct bnxt_re_qp *qp,
				struct ibv_qp_init_attr_ex *attr,
				struct bnxt_re_qattr *qattr)
{
	struct bnxt_re_queue *que;
	uint32_t psn_size;
	uint8_t indx;
	int ret;

	indx = BNXT_RE_QATTR_SQ_INDX;
	que = qp->jsqq->hwque;
	que->stride = sizeof(struct bnxt_re_sge);
	que->depth = qattr[indx].slots;
	que->diff = (BNXT_RE_FULL_FLAG_DELTA * qattr[indx].esize) /
		     que->stride;
	que->va = bnxt_re_get_ring(qp->mem, qattr[indx].sz_ring);
	if (!que->va)
		return -ENOMEM;
	/* PSN-search memory is allocated without checking for
	 * QP-Type. Kernel driver do not map this memory if it
	 * is UD-qp. UD-qp use this memory to maintain WC-opcode.
	 * See definition of bnxt_re_fill_psns() for the use case.
	 */
	que->pad = (que->va + que->depth * que->stride);
	psn_size = bnxt_re_get_psne_size(qp->cntx);
	que->pad_stride_log2 = ilog32(psn_size - 1);

	ret = bnxt_re_alloc_init_swque(qp->jsqq, qp->mem, &qattr[indx]);
	if (ret)
		goto fail;

	qp->cap.max_swr = qattr[indx].sw_nwr;
	qp->jsqq->cntx = qp->cntx;
	que->dbtail = (qp->qpmode == BNXT_RE_WQE_MODE_VARIABLE) ?
		       &que->tail : &qp->jsqq->start_idx;

	/* Init and adjust MSN table size according to qp mode */
	if (!BNXT_RE_MSN_TBL_EN(qp->cntx))
		goto skip_msn;
	que->msn = 0;
	que->msn_tbl_sz = 0;
	if (qp->qpmode & BNXT_RE_WQE_MODE_VARIABLE)
		que->msn_tbl_sz = roundup_pow_of_two(qattr->slots) / 2;
	else
		que->msn_tbl_sz = roundup_pow_of_two(qattr->nwr);
skip_msn:
	pthread_spin_init(&que->qlock, PTHREAD_PROCESS_PRIVATE);

	if (qp->jrqq) {
		indx = BNXT_RE_QATTR_RQ_INDX;
		que = qp->jrqq->hwque;
		que->stride = sizeof(struct bnxt_re_sge);
		que->depth = qattr[indx].slots;
		que->max_slots = qattr[indx].esize / que->stride;
		que->dbtail = &qp->jrqq->start_idx;
		que->va = bnxt_re_get_ring(qp->mem, qattr[indx].sz_ring);
		if (!que->va)
			return -ENOMEM;
		/* For RQ only bnxt_re_wri.wrid is used. */
		ret = bnxt_re_alloc_init_swque(qp->jrqq, qp->mem, &qattr[indx]);
		if (ret)
			goto fail;

		pthread_spin_init(&que->qlock, PTHREAD_PROCESS_PRIVATE);
		qp->cap.max_rwr = qattr[indx].nwr;
		qp->jrqq->cntx = qp->cntx;
	}

	return 0;
fail:
	return ret;
}

void bnxt_re_async_event(struct ibv_context *context,
		      struct ibv_async_event *event)
{
	struct ibv_qp *ibvqp;
	struct bnxt_re_qp *qp;

	switch (event->event_type) {
	case IBV_EVENT_CQ_ERR:
		break;
	case IBV_EVENT_SRQ_ERR:
	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_REQ_ERR:
	case IBV_EVENT_QP_ACCESS_ERR:
	case IBV_EVENT_PATH_MIG_ERR: {
		ibvqp = event->element.qp;
		qp = to_bnxt_re_qp(ibvqp);
		bnxt_re_qp_move_flush_err(qp);
		break;
	}
	case IBV_EVENT_SQ_DRAINED:
	case IBV_EVENT_PATH_MIG:
	case IBV_EVENT_COMM_EST:
	case IBV_EVENT_QP_LAST_WQE_REACHED:
	case IBV_EVENT_SRQ_LIMIT_REACHED:
	case IBV_EVENT_PORT_ACTIVE:
	case IBV_EVENT_PORT_ERR:
	default:
		break;
	}
}

static void *bnxt_re_pull_psn_buff(struct bnxt_re_queue *que, bool hw_retx)
{
	if (hw_retx)
		return (void *)(que->pad + ((que->msn) << que->pad_stride_log2));
	return (void *)(que->pad + ((*que->dbtail) << que->pad_stride_log2));
}

static void bnxt_re_fill_psns_for_msntbl(struct bnxt_re_qp *qp, uint32_t len,
					 uint32_t st_idx, uint8_t opcode)
{
	uint32_t npsn = 0, start_psn = 0, next_psn = 0;
	struct bnxt_re_msns *msns;
	uint32_t pkt_cnt = 0;

	msns = bnxt_re_pull_psn_buff(qp->jsqq->hwque, true);
	msns->start_idx_next_psn_start_psn = 0;

	if (qp->qptyp == IBV_QPT_RC) {
		start_psn = qp->sq_psn;
		pkt_cnt = (len / qp->mtu);
		if (len % qp->mtu)
			pkt_cnt++;
		/* Increment the psn even for 0 len packets
		 * e.g. for opcode rdma-write-with-imm-data
		 * with length field = 0
		 */
		if (len == 0)
			pkt_cnt = 1;
		/* make it 24 bit */
		next_psn = qp->sq_psn + pkt_cnt;
		npsn = next_psn;
		qp->sq_psn = next_psn;
		msns->start_idx_next_psn_start_psn |=
			bnxt_re_update_msn_tbl(st_idx, npsn, start_psn);
		qp->jsqq->hwque->msn++;
		qp->jsqq->hwque->msn %= qp->jsqq->hwque->msn_tbl_sz;
	}
}

static void bnxt_re_fill_psns(struct bnxt_re_qp *qp, uint32_t len,
			      uint32_t st_idx, uint8_t opcode)
{
	uint32_t opc_spsn = 0, flg_npsn = 0;
	struct bnxt_re_psns_ext *psns_ext;
	uint32_t pkt_cnt = 0, nxt_psn = 0;
	struct bnxt_re_psns *psns;

	psns = bnxt_re_pull_psn_buff(qp->jsqq->hwque, false);
	psns_ext = (struct bnxt_re_psns_ext *)psns;

	if (qp->qptyp == IBV_QPT_RC) {
		opc_spsn = qp->sq_psn & BNXT_RE_PSNS_SPSN_MASK;
		pkt_cnt = (len / qp->mtu);
		if (len % qp->mtu)
			pkt_cnt++;
		if (len == 0)
			pkt_cnt = 1;
		nxt_psn = ((qp->sq_psn + pkt_cnt) & BNXT_RE_PSNS_NPSN_MASK);
		flg_npsn = nxt_psn;
		qp->sq_psn = nxt_psn;
	}
	opc_spsn |= (((uint32_t)opcode & BNXT_RE_PSNS_OPCD_MASK) <<
		      BNXT_RE_PSNS_OPCD_SHIFT);
	memset(psns, 0, sizeof(*psns));
	psns->opc_spsn = htole32(opc_spsn);
	psns->flg_npsn = htole32(flg_npsn);
	if (qp->cctx->gen_p5_p7)
		psns_ext->st_slot_idx = st_idx;
}

static inline void bnxt_re_set_wr_hdr_flags(struct bnxt_re_qp *qp,
					    unsigned int send_flags)
{
	uint32_t hdrval = 0;
	uint8_t opcd;

	if (send_flags & IBV_SEND_SIGNALED || qp->cap.sqsig)
		hdrval |= ((BNXT_RE_WR_FLAGS_SIGNALED & BNXT_RE_HDR_FLAGS_MASK)
				<< BNXT_RE_HDR_FLAGS_SHIFT);
	if (send_flags & IBV_SEND_FENCE)
		/*TODO: See when RD fence can be used. */
		hdrval |= ((BNXT_RE_WR_FLAGS_UC_FENCE & BNXT_RE_HDR_FLAGS_MASK)
				<< BNXT_RE_HDR_FLAGS_SHIFT);
	if (send_flags & IBV_SEND_SOLICITED)
		hdrval |= ((BNXT_RE_WR_FLAGS_SE & BNXT_RE_HDR_FLAGS_MASK)
				<< BNXT_RE_HDR_FLAGS_SHIFT);
	if (send_flags & IBV_SEND_INLINE)
		hdrval |= ((BNXT_RE_WR_FLAGS_INLINE & BNXT_RE_HDR_FLAGS_MASK)
				<< BNXT_RE_HDR_FLAGS_SHIFT);
	hdrval |= ((qp->wr_sq.cur_slot_cnt) & BNXT_RE_HDR_WS_MASK) << BNXT_RE_HDR_WS_SHIFT;
	opcd = bnxt_re_ibv_to_bnxt_wr_opcd(qp->wr_sq.cur_opcode);
	hdrval |= (opcd & BNXT_RE_HDR_WT_MASK);
	qp->wr_sq.cur_hdr->rsv_ws_fl_wt = htole32(hdrval);
}

static inline void *bnxt_re_get_wr_swqe(struct bnxt_re_joint_queue *jqq,
					uint32_t cnt)
{
	return &jqq->swque[jqq->start_idx + cnt];
}

static uint16_t bnxt_re_put_wr_inline(struct bnxt_re_queue *que, uint32_t *idx,
				      struct bnxt_re_push_buffer *pbuf, size_t num_buf,
				      const struct ibv_data_buf *buf_list, size_t *msg_len)
{
	int len, t_len, offt = 0;
	int t_cplen = 0, cplen;
	bool pull_dst = true;
	int alsize, indx;
	void *il_dst;
	void *il_src;

	t_len = 0;
	alsize = sizeof(struct bnxt_re_sge);
	for (indx = 0; indx < num_buf; indx++) {
		len = buf_list[indx].length;
		il_src = (void *)buf_list[indx].addr;
		t_len += len;
		while (len) {
			if (pull_dst) {
				pull_dst = false;
				il_dst = bnxt_re_get_hwqe(que, (*idx)++);
				if (pbuf)
					pbuf->wqe[*idx - 1] = (uintptr_t)il_dst;
				t_cplen = 0;
				offt = 0;
			}
			cplen = MIN(len, alsize);
			cplen = MIN(cplen, (alsize - offt));
			memcpy(il_dst, il_src, cplen);
			t_cplen += cplen;
			il_src += cplen;
			il_dst += cplen;
			offt += cplen;
			len -= cplen;
			if (t_cplen == alsize)
				pull_dst = true;
		}
	}
	return t_len;
}

static inline void bnxt_re_update_wr_common_hdr(struct bnxt_re_qp *qp, uint8_t opcode)
{
	struct bnxt_re_queue *sq = qp->jsqq->hwque;

	qp->wr_sq.cur_hdr = bnxt_re_get_hwqe(sq, qp->wr_sq.cur_slot_cnt++);
	qp->wr_sq.cur_sqe = bnxt_re_get_hwqe(sq, qp->wr_sq.cur_slot_cnt++);
	qp->wr_sq.cur_opcode = opcode;
}

static inline void bnxt_re_update_sge(struct bnxt_re_sge *sge, uint32_t lkey,
				      uint64_t addr, uint32_t length)
{
	sge->pa = htole64(addr);
	sge->lkey = htole32(lkey);
	sge->length = htole32(length);
}

static inline void bnxt_re_update_swqe(struct ibv_qp_ex *ibvqp, struct bnxt_re_qp *qp,
				       uint32_t length)
{
	struct bnxt_re_wrid *wrid;

	wrid = bnxt_re_get_wr_swqe(qp->jsqq, qp->wr_sq.cur_wqe_cnt);
	wrid->wrid = ibvqp->wr_id;
	wrid->bytes = length;
	wrid->slots = (qp->qpmode == BNXT_RE_WQE_MODE_STATIC) ?
		STATIC_WQE_NUM_SLOTS : qp->wr_sq.cur_slot_cnt;
	wrid->sig = (ibvqp->wr_flags & IBV_SEND_SIGNALED || qp->cap.sqsig) ?
		IBV_SEND_SIGNALED : 0;
	wrid->wc_opcd = bnxt_re_ibv_wr_to_wc_opcd(qp->wr_sq.cur_opcode);
}

static void bnxt_re_send_wr_start(struct ibv_qp_ex *ibvqp)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;

	pthread_spin_lock(&sq->qlock);
	qp->wr_sq.cur_hdr = NULL;
	qp->wr_sq.cur_sqe = NULL;
	qp->wr_sq.cur_slot_cnt = 0;
	qp->wr_sq.cur_wqe_cnt = 0;
	qp->wr_sq.cur_opcode = 0xff;
	qp->wr_sq.cur_push_wqe = false;
	qp->wr_sq.cur_push_size = 0;
	qp->wr_sq.cur_swq_idx = qp->jsqq->start_idx;
}

static int bnxt_re_send_wr_complete(struct ibv_qp_ex *ibvqp)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	int err = qp->wr_sq.error;
	uint8_t slots;

	if (unlikely(err))
		goto exit;
	bnxt_re_set_wr_hdr_flags(qp, ibvqp->wr_flags);
	qp->wqe_cnt += qp->wr_sq.cur_wqe_cnt;
	slots = (qp->qpmode == BNXT_RE_WQE_MODE_STATIC) ?
		STATIC_WQE_NUM_SLOTS : qp->wr_sq.cur_slot_cnt;
	bnxt_re_incr_tail(sq, slots);
	bnxt_re_jqq_mod_start(qp->jsqq, qp->wr_sq.cur_swq_idx + qp->wr_sq.cur_wqe_cnt - 1);
	if (!qp->wr_sq.cur_push_wqe) {
		bnxt_re_ring_sq_db(qp);
	} else {
		struct bnxt_re_push_buffer *pushb;

		pushb = (struct bnxt_re_push_buffer *)qp->pbuf;
		pushb->wqe[0] = (uintptr_t)qp->wr_sq.cur_hdr;
		pushb->wqe[1] = (uintptr_t)qp->wr_sq.cur_sqe;
		pushb->tail = *sq->dbtail;
		bnxt_re_fill_push_wcb(qp, pushb, qp->wr_sq.cur_slot_cnt);
	}
exit:
	pthread_spin_unlock(&sq->qlock);
	return err;
}

static void bnxt_re_send_wr_abort(struct ibv_qp_ex *ibvqp)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;

	pthread_spin_unlock(&sq->qlock);
}

static void bnxt_re_send_wr_set_sge(struct ibv_qp_ex *ibvqp, uint32_t lkey,
				    uint64_t addr, uint32_t length)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	struct bnxt_re_sge *sge;

	sge = bnxt_re_get_hwqe(sq, qp->wr_sq.cur_slot_cnt++);
	bnxt_re_update_sge(sge, lkey, addr, length);
	if (qp->qptyp == IBV_QPT_UD) {
		qp->wr_sq.cur_hdr->lhdr.qkey_len |= htole64(length);
	} else {
		if ((qp->wr_sq.cur_opcode != IBV_WR_ATOMIC_FETCH_AND_ADD) &&
		    (qp->wr_sq.cur_opcode != IBV_WR_ATOMIC_CMP_AND_SWP))
			qp->wr_sq.cur_hdr->lhdr.qkey_len = htole64(length);
	}
	if (BNXT_RE_MSN_TBL_EN(qp->cntx))
		bnxt_re_fill_psns_for_msntbl(qp, length, *sq->dbtail, qp->wr_sq.cur_opcode);
	else
		bnxt_re_fill_psns(qp, length, *sq->dbtail, qp->wr_sq.cur_opcode);

	bnxt_re_update_swqe(ibvqp, qp, length);
	qp->wr_sq.cur_wqe_cnt++;
}

static void bnxt_re_send_wr_set_sge_list(struct ibv_qp_ex *ibvqp, size_t nsge,
					 const struct ibv_sge *sgl)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	struct bnxt_re_sge *sge;
	uint32_t i, len = 0;

	if ((qp->wr_sq.cur_opcode == IBV_WR_ATOMIC_FETCH_AND_ADD) ||
	    (qp->wr_sq.cur_opcode == IBV_WR_ATOMIC_CMP_AND_SWP)) {
		qp->wr_sq.error = -EINVAL;
		return;
	}

	/* check the queue full including header slots */
	if (bnxt_re_is_que_full(sq, nsge)) {
		qp->wr_sq.error = ENOMEM;
		return;
	}
	for (i = 0; i < nsge; i++) {
		sge = bnxt_re_get_hwqe(sq, qp->wr_sq.cur_slot_cnt++);
		bnxt_re_update_sge(sge, sgl[i].lkey, sgl[i].addr, sgl[i].length);
		len += sgl[i].length;
		sge++;
	}
	if (qp->qptyp == IBV_QPT_UD) {
		qp->wr_sq.cur_hdr->lhdr.qkey_len |= htole64(len);
	} else {
		if ((qp->wr_sq.cur_opcode != IBV_WR_ATOMIC_FETCH_AND_ADD) &&
		    (qp->wr_sq.cur_opcode != IBV_WR_ATOMIC_CMP_AND_SWP))
			qp->wr_sq.cur_hdr->lhdr.qkey_len = htole64(len);
	}
	if (BNXT_RE_MSN_TBL_EN(qp->cntx))
		bnxt_re_fill_psns_for_msntbl(qp, len, *sq->dbtail, qp->wr_sq.cur_opcode);
	else
		bnxt_re_fill_psns(qp, len, *sq->dbtail, qp->wr_sq.cur_opcode);

	bnxt_re_update_swqe(ibvqp, qp, len);
	qp->wr_sq.cur_wqe_cnt++;
}

static void bnxt_re_send_wr_set_inline_data(struct ibv_qp_ex *ibvqp,
					    void *addr, size_t length)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	struct bnxt_re_push_buffer *pushb = NULL;
	struct ibv_data_buf ibv_buf;
	uint32_t len = 0;

	if (unlikely(qp->wr_sq.error))
		return;
	if (qp->push_st_en && length < qp->max_push_sz) {
		pushb = (struct bnxt_re_push_buffer *)qp->pbuf;
		pushb->qpid = qp->qpid;
		pushb->st_idx = *sq->dbtail;
		qp->wr_sq.cur_push_wqe = true;
	}
	ibv_buf.addr = addr;
	ibv_buf.length = length;
	len = bnxt_re_put_wr_inline(sq, &qp->wr_sq.cur_slot_cnt, pushb, 1, &ibv_buf, &length);
	if (qp->qptyp == IBV_QPT_UD) {
		qp->wr_sq.cur_hdr->lhdr.qkey_len |= htole64(len);
	} else {
		if ((qp->wr_sq.cur_opcode != IBV_WR_ATOMIC_FETCH_AND_ADD) &&
		    (qp->wr_sq.cur_opcode != IBV_WR_ATOMIC_CMP_AND_SWP))
			qp->wr_sq.cur_hdr->lhdr.qkey_len = htole64(len);
	}
	if (BNXT_RE_MSN_TBL_EN(qp->cntx))
		bnxt_re_fill_psns_for_msntbl(qp, len, *sq->dbtail, qp->wr_sq.cur_wqe_cnt);
	else
		bnxt_re_fill_psns(qp, len, *sq->dbtail, qp->wr_sq.cur_opcode);
	bnxt_re_update_swqe(ibvqp, qp, len);
	qp->wr_sq.cur_wqe_cnt++;
	qp->wr_sq.cur_push_size += length;
}

static void bnxt_re_send_wr_set_inline_data_list(struct ibv_qp_ex *ibvqp, size_t num_buf,
						 const struct ibv_data_buf *buf_list)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	struct bnxt_re_push_buffer *pushb = NULL;
	uint32_t i, num, len = 0;
	size_t msg_len = 0;

	/* Get the total message length */
	for (i = 0; i < num_buf; i++)
		msg_len += buf_list[i].length;
	if (qp->push_st_en && msg_len < qp->max_push_sz) {
		pushb = (struct bnxt_re_push_buffer *)qp->pbuf;
		pushb->qpid = qp->qpid;
		pushb->st_idx = *sq->dbtail;
		qp->wr_sq.cur_push_wqe = true;
	}
	num = (msg_len + MSG_LEN_ADJ_TO_BYTES) >> SLOTS_RSH_TO_NUM_WQE;
	/* check the queue full including header slots */
	if (bnxt_re_is_que_full(sq, num + 2)) {
		qp->wr_sq.error = ENOMEM;
		return;
	}
	len = bnxt_re_put_wr_inline(sq, &qp->wr_sq.cur_slot_cnt, pushb,
				    num_buf, buf_list, &msg_len);

	if (qp->qptyp == IBV_QPT_UD) {
		qp->wr_sq.cur_hdr->lhdr.qkey_len |= htole64(len);
	} else {
		if ((qp->wr_sq.cur_opcode != IBV_WR_ATOMIC_FETCH_AND_ADD) &&
		    (qp->wr_sq.cur_opcode != IBV_WR_ATOMIC_CMP_AND_SWP))
			qp->wr_sq.cur_hdr->lhdr.qkey_len = htole64(len);
	}
	if (BNXT_RE_MSN_TBL_EN(qp->cntx))
		bnxt_re_fill_psns_for_msntbl(qp, len, *sq->dbtail, qp->wr_sq.cur_opcode);
	else
		bnxt_re_fill_psns(qp, len, *sq->dbtail, qp->wr_sq.cur_opcode);
	bnxt_re_update_swqe(ibvqp, qp, len);
	qp->wr_sq.cur_wqe_cnt++;
	qp->wr_sq.cur_push_size += msg_len;
}

static void bnxt_re_send_wr_set_ud_addr(struct ibv_qp_ex *ibvqp, struct ibv_ah *ibah,
					uint32_t remote_qpn, uint32_t remote_qkey)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_ah *ah;
	uint64_t qkey;

	if (unlikely(!ibah)) {
		qp->wr_sq.error = -EINVAL;
		return;
	}
	ah = to_bnxt_re_ah(ibah);
	qkey = remote_qkey;
	qp->wr_sq.cur_hdr->lhdr.qkey_len |= htole64(qkey << 32);
	qp->wr_sq.cur_sqe->dst_qp = htole32(remote_qpn);
	qp->wr_sq.cur_sqe->avid = htole32(ah->avid & 0xFFFFF);
}

static void bnxt_re_send_wr_send(struct ibv_qp_ex *ibvqp)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;

	if (bnxt_re_is_que_full(sq, SEND_SGE_MIN_SLOTS)) {
		qp->wr_sq.error = ENOMEM;
		return;
	}
	bnxt_re_update_wr_common_hdr(qp, IBV_WR_SEND);
}

static void bnxt_re_send_wr_send_imm(struct ibv_qp_ex *ibvqp, __be32 imm_data)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;

	if (bnxt_re_is_que_full(sq, SEND_SGE_MIN_SLOTS)) {
		qp->wr_sq.error = ENOMEM;
		return;
	}
	bnxt_re_update_wr_common_hdr(qp, IBV_WR_SEND_WITH_IMM);
	qp->wr_sq.cur_hdr->key_immd = htole32(be32toh(imm_data));
}

static void bnxt_re_send_wr_rdma_read(struct ibv_qp_ex *ibvqp, uint32_t rkey, uint64_t raddr)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	struct bnxt_re_rdma *rsqe;

	if (bnxt_re_is_que_full(sq, SEND_SGE_MIN_SLOTS)) {
		qp->wr_sq.error = ENOMEM;
		return;
	}
	bnxt_re_update_wr_common_hdr(qp, IBV_WR_RDMA_READ);
	rsqe = (struct bnxt_re_rdma *)qp->wr_sq.cur_sqe;
	rsqe->rva = htole64(raddr);
	rsqe->rkey = htole32(rkey);
}

static void bnxt_re_send_wr_rdma_write(struct ibv_qp_ex *ibvqp, uint32_t rkey, uint64_t raddr)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	struct bnxt_re_rdma *rsqe;

	if (bnxt_re_is_que_full(sq, SEND_SGE_MIN_SLOTS)) {
		qp->wr_sq.error = ENOMEM;
		return;
	}
	bnxt_re_update_wr_common_hdr(qp, IBV_WR_RDMA_WRITE);
	rsqe = (struct bnxt_re_rdma *)qp->wr_sq.cur_sqe;
	rsqe->rva = htole64(raddr);
	rsqe->rkey = htole32(rkey);
}

static void bnxt_re_send_wr_rdma_write_imm(struct ibv_qp_ex *ibvqp, uint32_t rkey, uint64_t raddr,
					   __be32 imm_data)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	struct bnxt_re_rdma *rsqe;

	if (bnxt_re_is_que_full(sq, SEND_SGE_MIN_SLOTS)) {
		qp->wr_sq.error = ENOMEM;
		return;
	}
	bnxt_re_update_wr_common_hdr(qp, IBV_WR_RDMA_WRITE_WITH_IMM);
	qp->wr_sq.cur_hdr->key_immd = htole32(be32toh(imm_data));
	rsqe = (struct bnxt_re_rdma *)qp->wr_sq.cur_sqe;
	rsqe->rva = htole64(raddr);
	rsqe->rkey = htole32(rkey);
}

static void bnxt_re_send_wr_atomic_cmp_swp(struct ibv_qp_ex *ibvqp, uint32_t rkey,
					   uint64_t raddr, uint64_t compare, uint64_t swap)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	struct bnxt_re_atomic *sqe;

	if (bnxt_re_is_que_full(sq, SEND_SGE_MIN_SLOTS)) {
		qp->wr_sq.error = ENOMEM;
		return;
	}
	bnxt_re_update_wr_common_hdr(qp, IBV_WR_ATOMIC_CMP_AND_SWP);
	qp->wr_sq.cur_hdr->key_immd = htole32(rkey);
	qp->wr_sq.cur_hdr->lhdr.rva = htole64(raddr);
	sqe = (struct bnxt_re_atomic *)qp->wr_sq.cur_sqe;
	sqe->cmp_dt = htole64(compare);
	sqe->swp_dt = htole64(swap);
}

static void bnxt_re_send_wr_atomic_fetch_add(struct ibv_qp_ex *ibvqp, uint32_t rkey,
					     uint64_t raddr, uint64_t add)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp((struct ibv_qp *)ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	struct bnxt_re_atomic *sqe;

	if (unlikely(!qp->cap.is_atomic_cap)) {
		qp->wr_sq.error = -EINVAL;
		return;
	}
	if (bnxt_re_is_que_full(sq, SEND_SGE_MIN_SLOTS)) {
		qp->wr_sq.error = ENOMEM;
		return;
	}

	bnxt_re_update_wr_common_hdr(qp, IBV_WR_ATOMIC_FETCH_AND_ADD);
	qp->wr_sq.cur_hdr->key_immd = htole32(rkey);
	qp->wr_sq.cur_hdr->lhdr.rva = htole64(raddr);
	sqe = (struct bnxt_re_atomic *)qp->wr_sq.cur_sqe;
	sqe->swp_dt = htole64(add);
}

static void bnxt_re_set_qp_ex_ops(struct  bnxt_re_qp *qp, uint64_t ops_flags)
{
	struct ibv_qp_ex *ibqp = &qp->vqp.qp_ex;

	if (ops_flags & IBV_QP_EX_WITH_RDMA_WRITE)
		ibqp->wr_rdma_write = bnxt_re_send_wr_rdma_write;
	if (ops_flags & IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM)
		ibqp->wr_rdma_write_imm = bnxt_re_send_wr_rdma_write_imm;
	if (ops_flags & IBV_QP_EX_WITH_SEND)
		ibqp->wr_send = bnxt_re_send_wr_send;
	if (ops_flags & IBV_QP_EX_WITH_SEND_WITH_IMM)
		ibqp->wr_send_imm = bnxt_re_send_wr_send_imm;
	if (ops_flags & IBV_QP_EX_WITH_RDMA_READ)
		ibqp->wr_rdma_read = bnxt_re_send_wr_rdma_read;
	if (ops_flags & IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP)
		ibqp->wr_atomic_cmp_swp = bnxt_re_send_wr_atomic_cmp_swp;
	if (ops_flags & IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD)
		ibqp->wr_atomic_fetch_add = bnxt_re_send_wr_atomic_fetch_add;

	ibqp->wr_set_sge = bnxt_re_send_wr_set_sge;
	ibqp->wr_set_sge_list = bnxt_re_send_wr_set_sge_list;
	ibqp->wr_set_inline_data = bnxt_re_send_wr_set_inline_data;
	ibqp->wr_set_inline_data_list = bnxt_re_send_wr_set_inline_data_list;
	ibqp->wr_set_ud_addr = bnxt_re_send_wr_set_ud_addr;
	ibqp->wr_start = bnxt_re_send_wr_start;
	ibqp->wr_complete = bnxt_re_send_wr_complete;
	ibqp->wr_abort = bnxt_re_send_wr_abort;
}

static struct ibv_qp *__bnxt_re_create_qp(struct ibv_context *ibvctx,
					  struct ibv_qp_init_attr_ex *attr)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(cntx->ibvctx.context.device);
	struct ubnxt_re_qp_resp resp = {};
	struct bnxt_re_qattr qattr[2];
	struct bnxt_re_qpcap *cap;
	struct ubnxt_re_qp req;
	struct bnxt_re_qp *qp;
	void *mem;

	if (bnxt_re_check_qp_limits(cntx, attr))
		return NULL;

	memset(qattr, 0, (2 * sizeof(*qattr)));
	mem = bnxt_re_alloc_qpslab(cntx, attr, qattr);
	if (!mem)
		return NULL;
	qp = bnxt_re_get_obj(mem, sizeof(*qp));
	if (!qp)
		goto fail;
	qp->ibvqp = &qp->vqp.qp;
	qp->mem = mem;

	qp->cctx = &cntx->cctx;

	qp->cntx = cntx;
	qp->qpmode = cntx->wqe_mode & BNXT_RE_WQE_MODE_VARIABLE;
	/* alloc queue pointers */
	if (bnxt_re_alloc_queue_ptr(qp, attr))
		goto fail;
	/* alloc queues */
	if (bnxt_re_alloc_queues(qp, attr, qattr))
		goto fail;
	/* Fill ibv_cmd */
	cap = &qp->cap;
	req.qpsva = (uintptr_t)qp->jsqq->hwque->va;
	req.qprva = qp->jrqq ? (uintptr_t)qp->jrqq->hwque->va : 0;
	req.qp_handle = (uintptr_t)qp;
	if (qp->qpmode == BNXT_RE_WQE_MODE_VARIABLE)
		req.sq_slots = qattr[BNXT_RE_QATTR_SQ_INDX].slots;

	if (ibv_cmd_create_qp_ex(ibvctx, &qp->vqp, attr,
				&req.ibv_cmd, sizeof(req), &resp.ibv_resp, sizeof(resp)))
		goto fail;


	if (attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS) {
		bnxt_re_set_qp_ex_ops(qp, attr->send_ops_flags);
		qp->vqp.comp_mask |= VERBS_QP_EX;
	}

	qp->qpid = resp.qpid;
	qp->qptyp = attr->qp_type;
	qp->qpst = IBV_QPS_RESET;
	qp->scq = to_bnxt_re_cq(attr->send_cq);
	qp->rcq = to_bnxt_re_cq(attr->recv_cq);
	if (attr->srq)
		qp->srq = to_bnxt_re_srq(attr->srq);
	qp->udpi = &cntx->udpi;
	qp->rand.seed = qp->qpid;
	/* Save/return the altered Caps. */
	cap->max_ssge = attr->cap.max_send_sge;
	cap->max_rsge = attr->cap.max_recv_sge;
	cap->max_inline = attr->cap.max_inline_data;
	cap->sqsig = attr->sq_sig_all;
	cap->is_atomic_cap = dev->devattr.atomic_cap;
	fque_init_node(&qp->snode);
	fque_init_node(&qp->rnode);

	if (qp->cctx->gen_p5_p7 && cntx->udpi.wcdpi) {
		qp->push_st_en = 1;
		qp->max_push_sz = BNXT_RE_MAX_INLINE_SIZE;
		qp->pbuf = bnxt_re_get_pbuf(&qp->push_st_en, cntx);
	}

	return qp->ibvqp;
fail:
	bnxt_re_free_mem(mem);
	return NULL;
}

struct ibv_qp *bnxt_re_create_qp_ex(struct ibv_context *ibvctx,
				    struct ibv_qp_init_attr_ex *attr)
{
	return __bnxt_re_create_qp(ibvctx, attr);
}

struct ibv_qp *bnxt_re_create_qp(struct ibv_pd *ibvpd,
				 struct ibv_qp_init_attr *attr)
{
	struct ibv_qp_init_attr_ex attr_ex;
	struct ibv_qp *qp;

	memset(&attr_ex, 0, sizeof(attr_ex));
	memcpy(&attr_ex, attr, sizeof(attr_ex));
	attr_ex.comp_mask = IBV_QP_INIT_ATTR_PD;
	attr_ex.pd = ibvpd;
	qp = __bnxt_re_create_qp(ibvpd->context, &attr_ex);
	if (qp)
		memcpy(attr, &attr_ex, sizeof(*attr));
	return qp;
}

int bnxt_re_modify_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr,
		      int attr_mask)
{
	struct ibv_modify_qp cmd = {};
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	int rc;

	rc = ibv_cmd_modify_qp(ibvqp, attr, attr_mask, &cmd, sizeof(cmd));
	if (!rc) {
		if (attr_mask & IBV_QP_STATE) {
			qp->qpst = attr->qp_state;
			/* transition to reset */
			if (qp->qpst == IBV_QPS_RESET) {
				qp->jsqq->hwque->head = 0;
				qp->jsqq->hwque->tail = 0;
				bnxt_re_cleanup_cq(qp, qp->scq);
				qp->jsqq->start_idx = 0;
				qp->jsqq->last_idx = 0;
				if (qp->jrqq) {
					qp->jrqq->hwque->head = 0;
					qp->jrqq->hwque->tail = 0;
					bnxt_re_cleanup_cq(qp, qp->rcq);
					qp->jrqq->start_idx = 0;
					qp->jrqq->last_idx = 0;
				}
			}
		}

		if (attr_mask & IBV_QP_SQ_PSN)
			qp->sq_psn = attr->sq_psn;
		if (attr_mask & IBV_QP_PATH_MTU)
			qp->mtu = (0x80 << attr->path_mtu);
	}

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
	struct bnxt_re_mem *mem;
	int status;

	qp->qpst = IBV_QPS_RESET;
	status = ibv_cmd_destroy_qp(ibvqp);
	if (status)
		return status;

	if (qp->pbuf) {
		bnxt_re_put_pbuf(qp->cntx, qp->pbuf);
		qp->pbuf = NULL;
	}
	bnxt_re_cleanup_cq(qp, qp->rcq);
	bnxt_re_cleanup_cq(qp, qp->scq);
	mem = qp->mem;
	bnxt_re_free_mem(mem);
	return 0;
}

static void bnxt_re_put_rx_sge(struct bnxt_re_queue *que, uint32_t *idx,
			       struct ibv_sge *sgl, int nsg)
{
	struct bnxt_re_sge *sge;
	int indx;

	for (indx = 0; indx < nsg; indx++) {
		sge = bnxt_re_get_hwqe(que, (*idx)++);
		sge->pa = htole64(sgl[indx].addr);
		sge->lkey = htole32(sgl[indx].lkey);
		sge->length = htole32(sgl[indx].length);
	}
}

static int bnxt_re_put_tx_sge(struct bnxt_re_queue *que, uint32_t *idx,
			      struct ibv_sge *sgl, int nsg)
{
	struct bnxt_re_sge *sge;
	int indx;
	int len;

	len = 0;
	for (indx = 0; indx < nsg; indx++) {
		sge = bnxt_re_get_hwqe(que, (*idx)++);
		sge->pa = htole64(sgl[indx].addr);
		sge->lkey = htole32(sgl[indx].lkey);
		sge->length = htole32(sgl[indx].length);
		len += sgl[indx].length;
	}
	return len;
}

static inline int bnxt_re_calc_inline_len(struct ibv_send_wr *swr)
{
	int illen, indx;

	illen = 0;
	for (indx = 0; indx < swr->num_sge; indx++)
		illen += swr->sg_list[indx].length;
	return illen;
}

static int bnxt_re_put_inline(struct bnxt_re_queue *que, uint32_t *idx,
			      struct bnxt_re_push_buffer *pbuf,
			      struct ibv_sge *sgl, uint32_t nsg,
			      uint16_t max_ils)
{
	int len, t_len, offt = 0;
	int t_cplen = 0, cplen;
	bool pull_dst = true;
	void *il_dst = NULL;
	void *il_src = NULL;
	int alsize;
	int indx;

	alsize = sizeof(struct bnxt_re_sge);

	t_len = 0;
	for (indx = 0; indx < nsg; indx++) {
		len = sgl[indx].length;
		il_src = (void *)(uintptr_t)(sgl[indx].addr);
		t_len += len;
		if (t_len > max_ils)
			goto bad;

		while (len) {
			if (pull_dst) {
				pull_dst = false;
				il_dst = bnxt_re_get_hwqe(que, (*idx)++);
				if (pbuf)
					pbuf->wqe[*idx - 1] =
					(uintptr_t)il_dst;
				t_cplen = 0;
				offt = 0;
			}
			cplen = MIN(len, alsize);
			cplen = MIN(cplen, (alsize - offt));
			memcpy(il_dst, il_src, cplen);
			t_cplen += cplen;
			il_src += cplen;
			il_dst += cplen;
			offt += cplen;
			len -= cplen;
			if (t_cplen == alsize)
				pull_dst = true;
		}
	}

	return t_len;
bad:
	return -ENOMEM;
}

static int bnxt_re_required_slots(struct bnxt_re_qp *qp, struct ibv_send_wr *wr,
				  uint32_t *wqe_sz, void **pbuf)
{
	uint32_t wqe_byte;
	int ilsize;

	if (wr->send_flags & IBV_SEND_INLINE) {
		ilsize = bnxt_re_calc_inline_len(wr);
		if (ilsize > qp->cap.max_inline)
			return -EINVAL;
		ilsize = align(ilsize, sizeof(struct bnxt_re_sge));
		if (qp->push_st_en && ilsize <= qp->max_push_sz)
			*pbuf = qp->pbuf;
		wqe_byte = (ilsize + bnxt_re_get_sqe_hdr_sz());
	} else {
		wqe_byte = bnxt_re_calc_wqe_sz(wr->num_sge);
	}

	/* que->stride is always 2^4 = 16, thus using hard-coding */
	*wqe_sz = wqe_byte >> 4;
	if (qp->qpmode == BNXT_RE_WQE_MODE_STATIC)
		return 8;
	return *wqe_sz;
}

static inline void bnxt_re_set_hdr_flags(struct bnxt_re_bsqe *hdr,
					 struct ibv_send_wr *wr,
					 uint32_t slots, uint8_t sqsig)
{
	uint32_t send_flags;
	uint32_t hdrval = 0;
	uint8_t opcd;

	send_flags = wr->send_flags;
	if (send_flags & IBV_SEND_SIGNALED || sqsig)
		hdrval |= ((BNXT_RE_WR_FLAGS_SIGNALED & BNXT_RE_HDR_FLAGS_MASK)
			    << BNXT_RE_HDR_FLAGS_SHIFT);
	if (send_flags & IBV_SEND_FENCE)
		/*TODO: See when RD fence can be used. */
		hdrval |= ((BNXT_RE_WR_FLAGS_UC_FENCE & BNXT_RE_HDR_FLAGS_MASK)
			    << BNXT_RE_HDR_FLAGS_SHIFT);
	if (send_flags & IBV_SEND_SOLICITED)
		hdrval |= ((BNXT_RE_WR_FLAGS_SE & BNXT_RE_HDR_FLAGS_MASK)
			    << BNXT_RE_HDR_FLAGS_SHIFT);
	if (send_flags & IBV_SEND_INLINE)
		hdrval |= ((BNXT_RE_WR_FLAGS_INLINE & BNXT_RE_HDR_FLAGS_MASK)
			    << BNXT_RE_HDR_FLAGS_SHIFT);
	hdrval |= (slots & BNXT_RE_HDR_WS_MASK) << BNXT_RE_HDR_WS_SHIFT;

	/* Fill opcode */
	opcd = bnxt_re_ibv_to_bnxt_wr_opcd(wr->opcode);
	hdrval |= (opcd & BNXT_RE_HDR_WT_MASK);
	hdr->rsv_ws_fl_wt = htole32(hdrval);
}

static int bnxt_re_build_tx_sge(struct bnxt_re_queue *que, uint32_t *idx,
				struct bnxt_re_push_buffer *pbuf,
				struct ibv_send_wr *wr,
				uint16_t max_il)
{
	if (wr->send_flags & IBV_SEND_INLINE)
		return bnxt_re_put_inline(que, idx, pbuf, wr->sg_list, wr->num_sge, max_il);

	return bnxt_re_put_tx_sge(que, idx, wr->sg_list, wr->num_sge);
}

static void bnxt_re_fill_wrid(struct bnxt_re_wrid *wrid, uint64_t wr_id,
			      uint32_t len, uint8_t sqsig, uint32_t st_idx,
			      uint8_t slots)
{
	wrid->wrid = wr_id;
	wrid->bytes = len;
	wrid->sig = 0;
	if (sqsig)
		wrid->sig = IBV_SEND_SIGNALED;
	wrid->st_slot_idx = st_idx;
	wrid->slots = slots;
}

static int bnxt_re_build_ud_sqe(struct ibv_send_wr *wr,
				struct bnxt_re_bsqe *hdr,
				struct bnxt_re_send *sqe)
{
	struct bnxt_re_ah *ah;
	uint64_t qkey;

	ah = to_bnxt_re_ah(wr->wr.ud.ah);
	if (!wr->wr.ud.ah)
		return -EINVAL;
	qkey = wr->wr.ud.remote_qkey;
	hdr->lhdr.qkey_len |= htole64(qkey << 32);
	sqe->dst_qp = htole32(wr->wr.ud.remote_qpn);
	sqe->avid = htole32(ah->avid & 0xFFFFF);

	return 0;
}

static bool __atomic_not_supported(struct bnxt_re_qp *qp, struct ibv_send_wr *wr)
{
	/* Atomic capability disabled or the request has more than 1 SGE */
	return (!qp->cap.is_atomic_cap || wr->num_sge > 1);
}

static void bnxt_re_build_cns_sqe(struct ibv_send_wr *wr,
				  struct bnxt_re_bsqe *hdr,
				  void *hdr2)
{
	struct bnxt_re_atomic *sqe = hdr2;

	hdr->key_immd = htole32(wr->wr.atomic.rkey);
	hdr->lhdr.rva = htole64(wr->wr.atomic.remote_addr);
	sqe->cmp_dt = htole64(wr->wr.atomic.compare_add);
	sqe->swp_dt = htole64(wr->wr.atomic.swap);
}

static void bnxt_re_build_fna_sqe(struct ibv_send_wr *wr,
				  struct bnxt_re_bsqe *hdr,
				  void *hdr2)
{
	struct bnxt_re_atomic *sqe = hdr2;

	hdr->key_immd = htole32(wr->wr.atomic.rkey);
	hdr->lhdr.rva = htole64(wr->wr.atomic.remote_addr);
	sqe->swp_dt = htole64(wr->wr.atomic.compare_add);
}

static int bnxt_re_build_atomic_sqe(struct bnxt_re_qp *qp,
				    struct ibv_send_wr *wr,
				    struct bnxt_re_bsqe *hdr,
				    void *hdr2)
{
	if (__atomic_not_supported(qp, wr))
		return -EINVAL;
	switch (wr->opcode) {
	case IBV_WR_ATOMIC_CMP_AND_SWP:
		bnxt_re_build_cns_sqe(wr, hdr, hdr2);
		return 0;
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		bnxt_re_build_fna_sqe(wr, hdr, hdr2);
		return 0;
	default:
		return -EINVAL;
	}
}

static void bnxt_re_force_rts2rts(struct bnxt_re_qp *qp)
{
	struct ibv_qp_attr attr;
	int attr_mask;

	attr_mask = IBV_QP_STATE;
	attr.qp_state = IBV_QPS_RTS;
	bnxt_re_modify_qp(qp->ibvqp, &attr, attr_mask);
	qp->wqe_cnt = 0;
}

int bnxt_re_post_send(struct ibv_qp *ibvqp, struct ibv_send_wr *wr,
		      struct ibv_send_wr **bad)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	struct bnxt_re_push_buffer *pbuf = NULL;
	struct bnxt_re_wrid *wrid;
	struct bnxt_re_rdma *rsqe;
	struct bnxt_re_send *sqe;
	struct bnxt_re_bsqe *hdr;
	uint32_t swq_idx, slots;
	int ret = 0, bytes = 0;
	uint32_t wqe_size = 0;
	bool ring_db = false;
	uint8_t sig = 0;
	uint32_t idx;

	pthread_spin_lock(&sq->qlock);
	while (wr) {

		pbuf = NULL;
		slots = bnxt_re_required_slots(qp, wr, &wqe_size, (void **)&pbuf);
		if (bnxt_re_is_que_full(sq, slots) ||
		    wr->num_sge > qp->cap.max_ssge) {
			*bad = wr;
			ret = ENOMEM;
			goto bad_wr;
		}

		idx = 2;
		bytes = 0;
		hdr = bnxt_re_get_hwqe(sq, 0);
		sqe = bnxt_re_get_hwqe(sq, 1);

		/* populate push buffer */
		if (pbuf) {
			pbuf->qpid = qp->qpid;
			pbuf->wqe[0] = (uintptr_t)hdr;
			pbuf->wqe[1] = (uintptr_t)sqe;
			pbuf->st_idx = *sq->dbtail;
		}

		if (wr->num_sge) {
			bytes = bnxt_re_build_tx_sge(sq, &idx, pbuf, wr, qp->cap.max_inline);
			if (unlikely(bytes < 0)) {
				ret = ENOMEM;
				*bad = wr;
				goto bad_wr;
			}
		}
		hdr->lhdr.qkey_len = htole64((uint64_t)bytes);
		bnxt_re_set_hdr_flags(hdr, wr, wqe_size, qp->cap.sqsig);

		switch (wr->opcode) {
		case IBV_WR_SEND_WITH_IMM:
		case IBV_WR_SEND_WITH_INV:
			/* Since our h/w is LE and for send_with_imm user supplies
			 * raw-data in  BE format. Swapping on incoming data is needed.
			 * On a BE platform htole32 will do the swap while on
			 * LE platform be32toh will do the job.
			 * For send_with_inv, send the data as BE.
			 */
			if (wr->opcode == IBV_WR_SEND_WITH_INV)
				hdr->imm_data = wr->imm_data;
			else
				hdr->key_immd = htole32(be32toh(wr->imm_data));
			SWITCH_FALLTHROUGH;
		case IBV_WR_SEND:
			if (qp->qptyp == IBV_QPT_UD)
				bytes = bnxt_re_build_ud_sqe(wr, hdr, sqe);
			break;
		case IBV_WR_RDMA_WRITE_WITH_IMM:
			hdr->key_immd = htole32(be32toh(wr->imm_data));
			SWITCH_FALLTHROUGH;
		case IBV_WR_RDMA_WRITE:
		case IBV_WR_RDMA_READ:
			rsqe = (struct bnxt_re_rdma *)sqe;
			rsqe->rva = htole64(wr->wr.rdma.remote_addr);
			rsqe->rkey = htole32(wr->wr.rdma.rkey);
			break;
		case IBV_WR_ATOMIC_CMP_AND_SWP:
		case IBV_WR_ATOMIC_FETCH_AND_ADD:
			if (bnxt_re_build_atomic_sqe(qp, wr, hdr, sqe)) {
				ret = EINVAL;
				*bad = wr;
				goto bad_wr;
			}
			break;
		default:
			ret = -EINVAL;
			*bad = wr;
			goto bad_wr;
		}

		wrid = bnxt_re_get_swqe(qp->jsqq, &swq_idx);
		sig = ((wr->send_flags & IBV_SEND_SIGNALED) || qp->cap.sqsig);
		bnxt_re_fill_wrid(wrid, wr->wr_id, bytes,
				  sig, sq->tail, slots);
		wrid->wc_opcd = bnxt_re_ibv_wr_to_wc_opcd(wr->opcode);
		if (BNXT_RE_MSN_TBL_EN(qp->cntx))
			bnxt_re_fill_psns_for_msntbl(qp, bytes, *sq->dbtail, wr->opcode);
		else
			bnxt_re_fill_psns(qp, bytes, *sq->dbtail, wr->opcode);
		bnxt_re_jqq_mod_start(qp->jsqq, swq_idx);
		bnxt_re_incr_tail(sq, slots);
		ring_db = true;

		if (pbuf) {
			ring_db = false;
			pbuf->tail = *sq->dbtail;
			bnxt_re_fill_push_wcb(qp, pbuf, idx);
			pbuf = NULL;
		}

		qp->wqe_cnt++;
		wr = wr->next;

		if (unlikely(!qp->cntx->cctx.gen_p5_p7 && qp->wqe_cnt == BNXT_RE_UD_QP_HW_STALL &&
			     qp->qptyp == IBV_QPT_UD))
			bnxt_re_force_rts2rts(qp);
	}

bad_wr:
	if (ring_db)
		bnxt_re_ring_sq_db(qp);


	pthread_spin_unlock(&sq->qlock);
	return ret;
}

int bnxt_re_post_recv(struct ibv_qp *ibvqp, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	struct bnxt_re_queue *rq = qp->jrqq->hwque;
	struct bnxt_re_wrid *swque;
	struct bnxt_re_brqe *hdr;
	struct bnxt_re_sge *sge;
	bool ring_db = false;
	uint32_t hdrval = 0;
	uint32_t idx = 0;
	uint32_t swq_idx;
	int rc = 0;

	pthread_spin_lock(&rq->qlock);
	while (wr) {
		if (unlikely(bnxt_re_is_que_full(rq, rq->max_slots) ||
			     wr->num_sge > qp->cap.max_rsge)) {
			*bad = wr;
			rc = ENOMEM;
			break;
		}
		swque = bnxt_re_get_swqe(qp->jrqq, &swq_idx);

		/*
		 * Initialize idx to 2 since the length of header wqe is 32 bytes
		 * i.e. sizeof(struct bnxt_re_brqe) + sizeof(struct bnxt_re_send)
		 */
		idx = 2;
		hdr = bnxt_re_get_hwqe_hdr(rq);

		if (unlikely(!wr->num_sge)) {
			/*
			 * HW needs at least one SGE for RQ Entries.
			 * Create an entry if num_sge = 0,
			 * update the idx and set length of sge to 0.
			 */
			sge = bnxt_re_get_hwqe(rq, idx++);
			sge->length = 0;
		} else {
			/* Fill SGEs */
			bnxt_re_put_rx_sge(rq, &idx, wr->sg_list, wr->num_sge);
		}
		hdrval = BNXT_RE_WR_OPCD_RECV;
		hdrval |= ((idx & BNXT_RE_HDR_WS_MASK) << BNXT_RE_HDR_WS_SHIFT);
		hdr->rsv_ws_fl_wt = htole32(hdrval);
		hdr->wrid = htole32(swq_idx);

		swque->wrid = wr->wr_id;
		swque->slots = rq->max_slots;
		swque->wc_opcd = BNXT_RE_WC_OPCD_RECV;

		bnxt_re_jqq_mod_start(qp->jrqq, swq_idx);
		bnxt_re_incr_tail(rq, rq->max_slots);
		ring_db = true;
		wr = wr->next;
	}
	if (ring_db)
		bnxt_re_ring_rq_db(qp);
	pthread_spin_unlock(&rq->qlock);

	return rc;
}

static size_t bnxt_re_get_srqmem_size(struct bnxt_re_context *cntx,
				      struct ibv_srq_init_attr *attr,
				      struct bnxt_re_qattr *qattr)
{
	uint32_t stride, nswr;
	size_t size = 0;

	size = sizeof(struct bnxt_re_srq);
	size += sizeof(struct bnxt_re_queue);
	/* allocate 1 extra to determin full condition */
	nswr = attr->attr.max_wr + 1;
	nswr = bnxt_re_init_depth(nswr, cntx->comp_mask);

	stride = bnxt_re_get_srqe_sz();

	qattr->nwr = nswr;
	qattr->slots = nswr;
	qattr->esize = stride;

	qattr->sz_ring = align((nswr * stride), cntx->rdev->pg_size);
	qattr->sz_shad = nswr * sizeof(struct bnxt_re_wrid); /* shadow */

	size += qattr->sz_ring;
	size += qattr->sz_shad;
	return size;
}

static void *bnxt_re_alloc_srqslab(struct bnxt_re_context *cntx,
				   struct ibv_srq_init_attr *attr,
				   struct bnxt_re_qattr *qattr)
{
	size_t bytes;

	bytes = bnxt_re_get_srqmem_size(cntx, attr, qattr);
	return bnxt_re_alloc_mem(bytes, cntx->rdev->pg_size);
}

static struct bnxt_re_srq *bnxt_re_srq_alloc_queue_ptr(struct bnxt_re_mem *mem)
{
	struct bnxt_re_srq *srq;

	srq = bnxt_re_get_obj(mem, sizeof(*srq));
	if (!srq)
		return NULL;
	srq->srqq = bnxt_re_get_obj(mem, sizeof(struct bnxt_re_queue));
	if (!srq->srqq)
		return NULL;
	return srq;
}

static int bnxt_re_srq_alloc_queue(struct bnxt_re_srq *srq,
				   struct ibv_srq_init_attr *attr,
				   struct bnxt_re_qattr *qattr)
{
	struct bnxt_re_queue *que;
	int ret = -ENOMEM;
	int idx;

	que = srq->srqq;
	que->depth = qattr->slots;
	que->stride = qattr->esize;
	que->va = bnxt_re_get_ring(srq->mem, qattr->sz_ring);
	if (!que->va)
		goto bail;
	pthread_spin_init(&que->qlock, PTHREAD_PROCESS_PRIVATE);
	/* For SRQ only bnxt_re_wrid.wrid is used. */
	srq->srwrid = bnxt_re_get_obj(srq->mem, qattr->sz_shad);
	if (!srq->srwrid)
		goto bail;

	srq->start_idx = 0;
	srq->last_idx = que->depth - 1;
	for (idx = 0; idx < que->depth; idx++)
		srq->srwrid[idx].next_idx = idx + 1;
	srq->srwrid[srq->last_idx].next_idx = -1;
	/*TODO: update actual max depth. */
	return 0;
bail:
	pthread_spin_destroy(&srq->srqq->qlock);
	return ret;
}

struct ibv_srq *bnxt_re_create_srq(struct ibv_pd *ibvpd,
				   struct ibv_srq_init_attr *attr)
{
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvpd->context);
	struct bnxt_re_mmap_info minfo = {};
	struct ubnxt_re_srq_resp resp = {};
	struct bnxt_re_qattr qattr = {};
	struct ubnxt_re_srq req;
	struct bnxt_re_srq *srq;
	void *mem;
	int ret;

	mem = bnxt_re_alloc_srqslab(cntx, attr, &qattr);
	if (!mem)
		return NULL;

	srq = bnxt_re_srq_alloc_queue_ptr(mem);
	if (!srq)
		goto fail;
	srq->cntx = cntx;
	srq->mem = mem;
	if (bnxt_re_srq_alloc_queue(srq, attr, &qattr))
		goto fail;

	req.srqva = (uintptr_t)srq->srqq->va;
	req.srq_handle = (uintptr_t)srq;
	ret = ibv_cmd_create_srq(ibvpd, &srq->ibvsrq, attr,
				 &req.ibv_cmd, sizeof(req),
				 &resp.ibv_resp, sizeof(resp));
	if (ret)
		goto fail;

	srq->srqid = resp.srqid;
	srq->cntx = cntx;
	srq->udpi = &cntx->udpi;
	srq->rand.seed = srq->srqid;

	srq->cap.max_wr = srq->srqq->depth;
	srq->cap.max_sge = attr->attr.max_sge;
	srq->cap.srq_limit = attr->attr.srq_limit;
	srq->arm_req = false;
	if (resp.comp_mask & BNXT_RE_SRQ_TOGGLE_PAGE_SUPPORT) {
		minfo.type = BNXT_RE_SRQ_TOGGLE_MEM;
		minfo.res_id = resp.srqid;
		ret = bnxt_re_get_toggle_mem(ibvpd->context, &minfo, &srq->mem_handle);
		if (ret)
			goto fail;
		srq->toggle_map = mmap(NULL, minfo.alloc_size, PROT_READ,
				       MAP_SHARED, ibvpd->context->cmd_fd,
				       minfo.alloc_offset);
		if (srq->toggle_map == MAP_FAILED)
			goto fail;
		srq->toggle_size = minfo.alloc_size;
	}
	return &srq->ibvsrq;
fail:
	bnxt_re_free_mem(mem);
	return NULL;
}

int bnxt_re_modify_srq(struct ibv_srq *ibvsrq, struct ibv_srq_attr *attr,
		       int attr_mask)
{
	struct bnxt_re_srq *srq = to_bnxt_re_srq(ibvsrq);
	struct ibv_modify_srq cmd;
	int status = 0;

	status =  ibv_cmd_modify_srq(ibvsrq, attr, attr_mask,
				     &cmd, sizeof(cmd));
	if (!status && ((attr_mask & IBV_SRQ_LIMIT) &&
			(srq->cap.srq_limit != attr->srq_limit))) {
		srq->cap.srq_limit = attr->srq_limit;
	}
	srq->arm_req = true;
	return status;
}

int bnxt_re_destroy_srq(struct ibv_srq *ibvsrq)
{
	struct bnxt_re_srq *srq = to_bnxt_re_srq(ibvsrq);
	struct bnxt_re_mem *mem;
	int ret;

	ret = ibv_cmd_destroy_srq(ibvsrq);
	if (ret)
		return ret;

	if (srq->toggle_map)
		munmap(srq->toggle_map, srq->toggle_size);
	mem = srq->mem;
	bnxt_re_free_mem(mem);
	return 0;
}

int bnxt_re_query_srq(struct ibv_srq *ibvsrq, struct ibv_srq_attr *attr)
{
	struct ibv_query_srq cmd;

	return ibv_cmd_query_srq(ibvsrq, attr, &cmd, sizeof(cmd));
}

static void bnxt_re_build_srqe(struct bnxt_re_srq *srq,
			       struct ibv_recv_wr *wr, void *srqe)
{
	struct bnxt_re_brqe *hdr = srqe;
	struct bnxt_re_wrid *wrid;
	struct bnxt_re_sge *sge;
	int wqe_sz, len, next;
	uint32_t hdrval = 0;
	int indx;

	sge = (srqe + bnxt_re_get_srqe_hdr_sz());
	next = srq->start_idx;
	wrid = &srq->srwrid[next];

	len = 0;
	for (indx = 0; indx < wr->num_sge; indx++, sge++) {
		sge->pa = htole64(wr->sg_list[indx].addr);
		sge->lkey = htole32(wr->sg_list[indx].lkey);
		sge->length = htole32(wr->sg_list[indx].length);
		len += wr->sg_list[indx].length;
	}

	hdrval = BNXT_RE_WR_OPCD_RECV;
	wqe_sz = wr->num_sge + (bnxt_re_get_srqe_hdr_sz() >> 4); /* 16B align */
	hdrval |= ((wqe_sz & BNXT_RE_HDR_WS_MASK) << BNXT_RE_HDR_WS_SHIFT);
	hdr->rsv_ws_fl_wt = htole32(hdrval);
	hdr->wrid = htole32((uint32_t)next);

	/* Fill wrid */
	wrid->wrid = wr->wr_id;
	wrid->bytes = len; /* N.A. for RQE */
	wrid->sig = 0; /* N.A. for RQE */
}

int bnxt_re_post_srq_recv(struct ibv_srq *ibvsrq, struct ibv_recv_wr *wr,
			  struct ibv_recv_wr **bad)
{
	struct bnxt_re_srq *srq = to_bnxt_re_srq(ibvsrq);
	struct bnxt_re_queue *rq = srq->srqq;
	int count = 0, rc = 0;
	bool ring_db = false;
	void *srqe;

	pthread_spin_lock(&rq->qlock);
	count = rq->tail > rq->head ? rq->tail - rq->head :
			   rq->depth - rq->head + rq->tail;
	while (wr) {
		if (srq->start_idx == srq->last_idx ||
		    wr->num_sge > srq->cap.max_sge) {
			*bad = wr;
			rc = ENOMEM;
			goto exit;
		}

		srqe = (void *) (rq->va + (rq->tail * rq->stride));
		memset(srqe, 0, bnxt_re_get_srqe_sz());
		bnxt_re_build_srqe(srq, wr, srqe);

		srq->start_idx = srq->srwrid[srq->start_idx].next_idx;
		bnxt_re_incr_tail(rq, 1);
		ring_db = true;
		wr = wr->next;
		count++;
		if (srq->arm_req == true && count > srq->cap.srq_limit) {
			srq->arm_req = false;
			ring_db = false;
			bnxt_re_ring_srq_db(srq);
			bnxt_re_ring_srq_arm(srq);
		}
	}
exit:
	if (ring_db)
		bnxt_re_ring_srq_db(srq);
	pthread_spin_unlock(&rq->qlock);

	return rc;
}

struct ibv_ah *bnxt_re_create_ah(struct ibv_pd *ibvpd, struct ibv_ah_attr *attr)
{
	struct bnxt_re_context *uctx;
	struct bnxt_re_ah *ah;
	struct ib_uverbs_create_ah_resp resp;
	int status;

	uctx = to_bnxt_re_context(ibvpd->context);

	ah = calloc(1, sizeof(*ah));
	if (!ah)
		goto failed;

	pthread_mutex_lock(&uctx->shlock);
	memset(&resp, 0, sizeof(resp));
	status = ibv_cmd_create_ah(ibvpd, &ah->ibvah, attr,
				   &resp, sizeof(resp));
	if (status) {
		pthread_mutex_unlock(&uctx->shlock);
		free(ah);
		goto failed;
	}
	/* read AV ID now. */
	ah->avid = *(uint32_t *)(uctx->shpg + BNXT_RE_AVID_OFFT);
	pthread_mutex_unlock(&uctx->shlock);

	return &ah->ibvah;
failed:
	return NULL;
}

int bnxt_re_destroy_ah(struct ibv_ah *ibvah)
{
	struct bnxt_re_ah *ah;
	int status;

	ah = to_bnxt_re_ah(ibvah);
	status = ibv_cmd_destroy_ah(ibvah);
	if (status)
		return status;
	free(ah);

	return 0;
}
