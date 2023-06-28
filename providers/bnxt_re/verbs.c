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

#include <util/compiler.h>

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

struct ibv_pd *bnxt_re_alloc_pd(struct ibv_context *ibvctx)
{
	struct ibv_alloc_pd cmd;
	struct ubnxt_re_pd_resp resp;
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ibvctx->device);
	struct bnxt_re_pd *pd;
	uint64_t dbr;

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
		cntx->udpi.dpindx = resp.dpi;
		cntx->udpi.dbpage = mmap(NULL, dev->pg_size, PROT_WRITE,
					 MAP_SHARED, ibvctx->cmd_fd, dbr);
		if (cntx->udpi.dbpage == MAP_FAILED) {
			(void)ibv_cmd_dealloc_pd(&pd->ibvpd);
			goto out;
		}
        }

	return &pd->ibvpd;
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

struct ibv_cq *bnxt_re_create_cq(struct ibv_context *ibvctx, int ncqe,
				 struct ibv_comp_channel *channel, int vec)
{
	struct bnxt_re_cq *cq;
	struct ubnxt_re_cq cmd;
	struct ubnxt_re_cq_resp resp;

	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ibvctx->device);

	if (!ncqe || ncqe > dev->max_cq_depth) {
		errno = EINVAL;
		return NULL;
	}

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
			      &cq->ibvcq, &cmd.ibv_cmd, sizeof(cmd),
			      &resp.ibv_resp, sizeof(resp)))
		goto cmdfail;

	cq->cqid = resp.cqid;
	cq->phase = resp.phase;
	cq->cqq.tail = resp.tail;
	cq->udpi = &cntx->udpi;

	list_head_init(&cq->sfhead);
	list_head_init(&cq->rfhead);
	list_head_init(&cq->prev_cq_head);

	return &cq->ibvcq;
cmdfail:
	bnxt_re_free_aligned(&cq->cqq);
fail:
	free(cq);
	return NULL;
}

/*
 * Function to complete the last steps in CQ resize. Invoke poll function
 * in the kernel driver; this serves as a signal to the driver to complete CQ
 * resize steps required. Free memory mapped for the original CQ and switch
 * over to the memory mapped for CQ with the new size. Finally Ack the Cutoff
 * CQE. This function must be called under cq->cqq.lock.
 */
static void bnxt_re_resize_cq_complete(struct bnxt_re_cq *cq)
{
	struct ibv_wc tmp_wc;

	ibv_cmd_poll_cq(&cq->ibvcq, 1, &tmp_wc);
	bnxt_re_free_aligned(&cq->cqq);
	memcpy(&cq->cqq, &cq->resize_cqq, sizeof(cq->cqq));
	bnxt_re_ring_cq_arm_db(cq, BNXT_RE_QUE_TYPE_CQ_CUT_ACK);
}

int bnxt_re_resize_cq(struct ibv_cq *ibvcq, int ncqe)
{
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ibvcq->context->device);
	struct bnxt_re_cq *cq = to_bnxt_re_cq(ibvcq);
	struct ib_uverbs_resize_cq_resp resp = {};
	struct ubnxt_re_resize_cq cmd = {};
	int rc = 0;

	if (ncqe > dev->max_cq_depth)
		return -EINVAL;

	pthread_spin_lock(&cq->cqq.qlock);
	cq->resize_cqq.depth = roundup_pow_of_two(ncqe + 1);
	if (cq->resize_cqq.depth > dev->max_cq_depth + 1)
		cq->resize_cqq.depth = dev->max_cq_depth + 1;
	cq->resize_cqq.stride = dev->cqe_size;
	if (bnxt_re_alloc_aligned(&cq->resize_cqq, dev->pg_size))
		goto done;
	/* As an exception no need to call get_ring api we know
	 * this is the only consumer
	 */
	cmd.cq_va = (uintptr_t)cq->resize_cqq.va;
	rc = ibv_cmd_resize_cq(ibvcq, ncqe, &cmd.ibv_cmd,
			       sizeof(cmd), &resp, sizeof(resp));
	if (rc) {
		bnxt_re_free_aligned(&cq->resize_cqq);
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
		}
	}
done:
	pthread_spin_unlock(&cq->cqq.qlock);
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

	status = ibv_cmd_destroy_cq(ibvcq);
	if (status)
		return status;
	bnxt_re_destroy_resize_cq_list(cq);
	bnxt_re_free_aligned(&cq->cqq);
	free(cq);

	return 0;
}

static uint8_t bnxt_re_poll_err_scqe(struct bnxt_re_qp *qp,
				     struct ibv_wc *ibvwc,
				     struct bnxt_re_bcqe *hdr,
				     struct bnxt_re_req_cqe *scqe, int *cnt)
{
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	struct bnxt_re_context *cntx;
	struct bnxt_re_wrid *swrid;
	struct bnxt_re_psns *spsn;
	struct bnxt_re_cq *scq;
	uint8_t status;
	uint32_t head;

	scq = to_bnxt_re_cq(qp->ibvqp.send_cq);

	head = qp->jsqq->last_idx;
	cntx = to_bnxt_re_context(scq->ibvcq.context);
	swrid = &qp->jsqq->swque[head];
	spsn = swrid->psns;

	*cnt = 1;
	status = (le32toh(hdr->flg_st_typ_ph) >> BNXT_RE_BCQE_STATUS_SHIFT) &
		  BNXT_RE_BCQE_STATUS_MASK;
	ibvwc->status = bnxt_re_to_ibv_wc_status(status, true);
	ibvwc->wc_flags = 0;
	ibvwc->wr_id = swrid->wrid;
	ibvwc->qp_num = qp->qpid;
	ibvwc->opcode = (le32toh(spsn->opc_spsn) >>
			BNXT_RE_PSNS_OPCD_SHIFT) &
			BNXT_RE_PSNS_OPCD_MASK;
	ibvwc->byte_len = 0;

	bnxt_re_incr_head(sq, swrid->slots);
	bnxt_re_jqq_mod_last(qp->jsqq, head);

	if (qp->qpst != IBV_QPS_ERR)
		qp->qpst = IBV_QPS_ERR;
	pthread_spin_lock(&cntx->fqlock);
	bnxt_re_fque_add_node(&scq->sfhead, &qp->snode);
	pthread_spin_unlock(&cntx->fqlock);

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
	struct bnxt_re_psns *spsn;
	uint8_t pcqe = false;
	uint32_t cindx;
	uint32_t head;

	head = qp->jsqq->last_idx;
	swrid = &qp->jsqq->swque[head];
	spsn = swrid->psns;
	cindx = le32toh(scqe->con_indx) & (qp->cap.max_swr - 1);

	if (!(swrid->sig & IBV_SEND_SIGNALED)) {
		*cnt = 0;
	} else {
		ibvwc->status = IBV_WC_SUCCESS;
		ibvwc->wc_flags = 0;
		ibvwc->qp_num = qp->qpid;
		ibvwc->wr_id = swrid->wrid;
		ibvwc->opcode = (le32toh(spsn->opc_spsn) >>
				BNXT_RE_PSNS_OPCD_SHIFT) &
				BNXT_RE_PSNS_OPCD_MASK;
		if (ibvwc->opcode == IBV_WC_RDMA_READ ||
		    ibvwc->opcode == IBV_WC_COMP_SWAP ||
		    ibvwc->opcode == IBV_WC_FETCH_ADD)
			ibvwc->byte_len = swrid->bytes;

		*cnt = 1;
	}

	bnxt_re_incr_head(sq, swrid->slots);
	bnxt_re_jqq_mod_last(qp->jsqq, head);

	if (qp->jsqq->last_idx != cindx)
		pcqe = true;

	return pcqe;
}

static uint8_t bnxt_re_poll_scqe(struct bnxt_re_qp *qp, struct ibv_wc *ibvwc,
				 void *cqe, int *cnt)
{
	struct bnxt_re_bcqe *hdr;
	struct bnxt_re_req_cqe *scqe;
	uint8_t status, pcqe = false;

	scqe = cqe;
	hdr = cqe + sizeof(struct bnxt_re_req_cqe);

	status = (le32toh(hdr->flg_st_typ_ph) >> BNXT_RE_BCQE_STATUS_SHIFT) &
		  BNXT_RE_BCQE_STATUS_MASK;
	if (status == BNXT_RE_REQ_ST_OK)
		pcqe = bnxt_re_poll_success_scqe(qp, ibvwc, hdr, scqe, cnt);
	else
		pcqe = bnxt_re_poll_err_scqe(qp, ibvwc, hdr, scqe, cnt);

	return pcqe;
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
	struct bnxt_re_context *cntx;
	struct bnxt_re_wrid *swque;
	struct bnxt_re_queue *rq;
	uint8_t status, cnt = 0;
	struct bnxt_re_cq *rcq;
	uint32_t head = 0;

	rcq = to_bnxt_re_cq(qp->ibvqp.recv_cq);
	cntx = to_bnxt_re_context(rcq->ibvcq.context);

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
	ibvwc->qp_num = qp->qpid;
	ibvwc->opcode = IBV_WC_RECV;
	ibvwc->byte_len = 0;
	ibvwc->wc_flags = 0;
	if (qp->qptyp == IBV_QPT_UD)
		ibvwc->src_qp = 0;

	if (!qp->srq)
		bnxt_re_jqq_mod_last(qp->jrqq, head);
	bnxt_re_incr_head(rq, cnt);

	if (!qp->srq) {
		pthread_spin_lock(&cntx->fqlock);
		bnxt_re_fque_add_node(&rcq->rfhead, &qp->rnode);
		pthread_spin_unlock(&cntx->fqlock);
	}

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
	if (status == BNXT_RE_RSP_ST_OK)
		bnxt_re_poll_success_rcqe(qp, ibvwc, hdr, cqe);
	else
		*cnt = bnxt_re_poll_err_rcqe(qp, ibvwc, hdr, cqe);

	return pcqe;
}

static uint8_t bnxt_re_poll_term_cqe(struct bnxt_re_qp *qp,
				     struct ibv_wc *ibvwc, void *cqe, int *cnt)
{
	struct bnxt_re_context *cntx;
	struct bnxt_re_cq *scq, *rcq;
	uint8_t pcqe = false;

	scq = to_bnxt_re_cq(qp->ibvqp.send_cq);
	rcq = to_bnxt_re_cq(qp->ibvqp.recv_cq);
	cntx = to_bnxt_re_context(scq->ibvcq.context);
	/* For now just add the QP to flush list without
	 * considering the index reported in the CQE.
	 * Continue reporting flush completions until the
	 * SQ and RQ are empty.
	 */
	*cnt = 0;
	/* If the QP is destroyed, avoid handling this QP as flushlist */
	if (qp->qpst == IBV_QPS_RESET)
		goto exit;
	if (qp->qpst != IBV_QPS_ERR)
		qp->qpst = IBV_QPS_ERR;
	pthread_spin_lock(&cntx->fqlock);
	bnxt_re_fque_add_node(&rcq->rfhead, &qp->rnode);
	bnxt_re_fque_add_node(&scq->sfhead, &qp->snode);
	pthread_spin_unlock(&cntx->fqlock);
exit:
	return pcqe;
}

static int bnxt_re_poll_one(struct bnxt_re_cq *cq, int nwc, struct ibv_wc *wc,
			    uint32_t *resize)
{
	struct bnxt_re_queue *cqq = &cq->cqq;
	struct bnxt_re_qp *qp;
	struct bnxt_re_bcqe *hdr;
	struct bnxt_re_req_cqe *scqe;
	struct bnxt_re_ud_cqe *rcqe;
	void *cqe;
	uint64_t *qp_handle = NULL;
	int type, cnt = 0, dqed = 0, hw_polled = 0;
	uint8_t pcqe = false;

	while (nwc) {
		cqe = cqq->va + cqq->head * bnxt_re_get_cqe_sz();
		hdr = cqe + sizeof(struct bnxt_re_req_cqe);
		if (!bnxt_re_is_cqe_valid(cq, hdr))
			break;
		type = (le32toh(hdr->flg_st_typ_ph) >>
			BNXT_RE_BCQE_TYPE_SHIFT) & BNXT_RE_BCQE_TYPE_MASK;
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
			pcqe = bnxt_re_poll_term_cqe(qp, wc, cqe, &cnt);
			break;
		case BNXT_RE_WC_TYPE_COFF:
			/* Stop further processing and return */
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
		if (qp_handle) {
			*qp_handle = 0x0ULL; /* mark cqe as read */
			qp_handle = NULL;
		}
		bnxt_re_incr_head(&cq->cqq, 1);
		bnxt_re_change_cq_phase(cq);
skipp_real:
		if (cnt) {
			cnt = 0;
			dqed++;
			nwc--;
			wc++;
		}
	}

	if (hw_polled)
		bnxt_re_ring_cq_db(cq);

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
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvcq->context);
	int dqed = 0, left = 0;
	uint32_t resize = 0;

	pthread_spin_lock(&cq->cqq.qlock);
	left = nwc;
	/* Check  whether we have anything to be completed
	 * from prev cq context.
	 */
	if (!list_empty(&cq->prev_cq_head)) {
		dqed = bnxt_re_poll_resize_cq_list(cq, nwc, wc);
		left = nwc - dqed;
		if (!left) {
			pthread_spin_unlock(&cq->cqq.qlock);
			return dqed;
		}
	}
	dqed += bnxt_re_poll_one(cq, left, wc + dqed, &resize);
	pthread_spin_unlock(&cq->cqq.qlock);
	left = nwc - dqed;
	if (left) {
		/* Check if anything is there to flush. */
		pthread_spin_lock(&cntx->fqlock);
		dqed += bnxt_re_poll_flush_lists(cq, left, (wc + dqed));
		pthread_spin_unlock(&cntx->fqlock);
	}

	return dqed;
}

static void bnxt_re_cleanup_cq(struct bnxt_re_qp *qp, struct bnxt_re_cq *cq)
{
	struct bnxt_re_context *cntx;
	struct bnxt_re_queue *que = &cq->cqq;
	struct bnxt_re_bcqe *hdr;
	struct bnxt_re_req_cqe *scqe;
	struct bnxt_re_rc_cqe *rcqe;
	void *cqe;
	int indx, type;

	cntx = to_bnxt_re_context(cq->ibvcq.context);

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
	pthread_spin_unlock(&que->qlock);

	pthread_spin_lock(&cntx->fqlock);
	bnxt_re_fque_del_node(&qp->snode);
	bnxt_re_fque_del_node(&qp->rnode);
	pthread_spin_unlock(&cntx->fqlock);
}

int bnxt_re_arm_cq(struct ibv_cq *ibvcq, int flags)
{
	struct bnxt_re_cq *cq = to_bnxt_re_cq(ibvcq);

	pthread_spin_lock(&cq->cqq.qlock);
	flags = !flags ? BNXT_RE_QUE_TYPE_CQ_ARMALL :
			 BNXT_RE_QUE_TYPE_CQ_ARMSE;
	bnxt_re_ring_cq_arm_db(cq, flags);
	pthread_spin_unlock(&cq->cqq.qlock);

	return 0;
}

static int bnxt_re_check_qp_limits(struct bnxt_re_context *cntx,
				   struct ibv_qp_init_attr *attr)
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
		attr->cap.max_send_wr = devattr->max_qp_wr;
	if (attr->cap.max_recv_wr > devattr->max_qp_wr)
		attr->cap.max_recv_wr = devattr->max_qp_wr;

	return 0;
}

static void bnxt_re_free_queue_ptr(struct bnxt_re_qp *qp)
{
	if (qp->jrqq) {
		free(qp->jrqq->hwque);
		free(qp->jrqq);
	}
	if (qp->jsqq) {
		free(qp->jsqq->hwque);
		free(qp->jsqq);
	}
}

static int bnxt_re_alloc_queue_ptr(struct bnxt_re_qp *qp,
				   struct ibv_qp_init_attr *attr)
{
	int rc = -ENOMEM;

	qp->jsqq = calloc(1, sizeof(struct bnxt_re_joint_queue));
	if (!qp->jsqq)
		return rc;
	qp->jsqq->hwque = calloc(1, sizeof(struct bnxt_re_queue));
	if (!qp->jsqq->hwque)
		goto fail;

	if (!attr->srq) {
		qp->jrqq = calloc(1, sizeof(struct bnxt_re_joint_queue));
		if (!qp->jrqq) {
			free(qp->jsqq);
			goto fail;
		}
		qp->jrqq->hwque = calloc(1, sizeof(struct bnxt_re_queue));
		if (!qp->jrqq->hwque)
			goto fail;
	}

	return 0;
fail:
	bnxt_re_free_queue_ptr(qp);
	return rc;
}

static void bnxt_re_free_queues(struct bnxt_re_qp *qp)
{
	if (qp->jrqq) {
		free(qp->jrqq->swque);
		pthread_spin_destroy(&qp->jrqq->hwque->qlock);
		bnxt_re_free_aligned(qp->jrqq->hwque);
	}

	free(qp->jsqq->swque);
	pthread_spin_destroy(&qp->jsqq->hwque->qlock);
	bnxt_re_free_aligned(qp->jsqq->hwque);
}

static int bnxt_re_alloc_init_swque(struct bnxt_re_joint_queue *jqq, int nwr)
{
	int indx;

	jqq->swque = calloc(nwr, sizeof(struct bnxt_re_wrid));
	if (!jqq->swque)
		return -ENOMEM;
	jqq->start_idx = 0;
	jqq->last_idx = nwr - 1;
	for (indx = 0; indx < nwr; indx++)
		jqq->swque[indx].next_idx = indx + 1;
	jqq->swque[jqq->last_idx].next_idx = 0;
	jqq->last_idx = 0;

	return 0;
}

static int bnxt_re_calc_wqe_sz(int nsge)
{
	/* This is used for both sq and rq. In case hdr size differs
	 * in future move to individual functions.
	 */
	return sizeof(struct bnxt_re_sge) * nsge + bnxt_re_get_sqe_hdr_sz();
}

static int bnxt_re_get_rq_slots(struct bnxt_re_dev *rdev,
				struct bnxt_re_qp *qp, uint32_t nrwr,
				uint32_t nsge)
{
	uint32_t max_wqesz;
	uint32_t wqe_size;
	uint32_t stride;
	uint32_t slots;

	stride = sizeof(struct bnxt_re_sge);
	max_wqesz = bnxt_re_calc_wqe_sz(rdev->devattr.max_sge);

	wqe_size = bnxt_re_calc_wqe_sz(nsge);
	if (wqe_size > max_wqesz)
		return -EINVAL;

	if (qp->qpmode == BNXT_RE_WQE_MODE_STATIC)
		wqe_size = bnxt_re_calc_wqe_sz(6);

	qp->jrqq->hwque->esize = wqe_size;
	qp->jrqq->hwque->max_slots = wqe_size / stride;

	slots = (nrwr * wqe_size) / stride;
	return slots;
}

static int bnxt_re_get_sq_slots(struct bnxt_re_dev *rdev,
				struct bnxt_re_qp *qp, uint32_t nswr,
				uint32_t nsge, uint32_t *ils)
{
	uint32_t max_wqesz;
	uint32_t wqe_size;
	uint32_t cal_ils;
	uint32_t stride;
	uint32_t ilsize;
	uint32_t hdr_sz;
	uint32_t slots;

	hdr_sz = bnxt_re_get_sqe_hdr_sz();
	stride = sizeof(struct bnxt_re_sge);
	max_wqesz = bnxt_re_calc_wqe_sz(rdev->devattr.max_sge);
	ilsize = get_aligned(*ils, hdr_sz);

	wqe_size = bnxt_re_calc_wqe_sz(nsge);
	if (ilsize) {
		cal_ils = hdr_sz + ilsize;
		wqe_size = MAX(cal_ils, wqe_size);
		wqe_size = get_aligned(wqe_size, hdr_sz);
	}
	if (wqe_size > max_wqesz)
		return -EINVAL;

	if (qp->qpmode == BNXT_RE_WQE_MODE_STATIC)
		wqe_size = bnxt_re_calc_wqe_sz(6);

	if (*ils)
		*ils = wqe_size - hdr_sz;
	qp->jsqq->hwque->esize = wqe_size;
	qp->jsqq->hwque->max_slots = (qp->qpmode == BNXT_RE_WQE_MODE_STATIC) ?
		wqe_size / stride : 1;
	slots = (nswr * wqe_size) / stride;
	return slots;
}

static int bnxt_re_alloc_queues(struct bnxt_re_dev *dev,
				struct bnxt_re_qp *qp,
				struct ibv_qp_init_attr *attr,
				uint32_t pg_size) {
	struct bnxt_re_psns_ext *psns_ext;
	struct bnxt_re_wrid *swque;
	struct bnxt_re_queue *que;
	struct bnxt_re_psns *psns;
	uint32_t nswr, diff;
	uint32_t psn_depth;
	uint32_t psn_size;
	uint32_t nsge;
	int ret, indx;
	int nslots;

	que = qp->jsqq->hwque;
	diff = (qp->qpmode == BNXT_RE_WQE_MODE_VARIABLE) ?
		0 : BNXT_RE_FULL_FLAG_DELTA;
	nswr = roundup_pow_of_two(attr->cap.max_send_wr + 1 + diff);
	nsge = attr->cap.max_send_sge;
	if (nsge % 2)
		nsge++;
	nslots = bnxt_re_get_sq_slots(dev, qp, nswr, nsge,
				      &attr->cap.max_inline_data);
	if (nslots < 0)
		 return nslots;
	que->stride = sizeof(struct bnxt_re_sge);
	que->depth = nslots;
	que->diff = (diff * que->esize) / que->stride;

	/* psn_depth extra entries of size que->stride */
	psn_size = qp->cctx->gen_p5 ? sizeof(struct bnxt_re_psns_ext) :
				      sizeof(struct bnxt_re_psns);
	psn_depth = (nswr * psn_size) / que->stride;
	if ((nswr * psn_size) % que->stride)
		psn_depth++;
	que->depth += psn_depth;
	/* PSN-search memory is allocated without checking for
	 * QP-Type. Kenrel driver do not map this memory if it
	 * is UD-qp. UD-qp use this memory to maintain WC-opcode.
	 * See definition of bnxt_re_fill_psns() for the use case.
	 */
	ret = bnxt_re_alloc_aligned(que, pg_size);
	if (ret)
		return ret;
	/* exclude psns depth*/
	que->depth -= psn_depth;
	/* start of spsn space sizeof(struct bnxt_re_psns) each. */
	psns = (que->va + que->stride * que->depth);
	psns_ext = (struct bnxt_re_psns_ext *)psns;

	ret = bnxt_re_alloc_init_swque(qp->jsqq, nswr);
	if (ret) {
		ret = -ENOMEM;
		goto fail;
	}

	swque = qp->jsqq->swque;
	for (indx = 0 ; indx < nswr; indx++, psns++)
		swque[indx].psns = psns;
	if (qp->cctx->gen_p5) {
		for (indx = 0 ; indx < nswr; indx++, psns_ext++) {
			swque[indx].psns_ext = psns_ext;
			swque[indx].psns = (struct bnxt_re_psns *)psns_ext;
		}
	}
	qp->cap.max_swr = nswr;
	pthread_spin_init(&que->qlock, PTHREAD_PROCESS_PRIVATE);

	if (qp->jrqq) {
		que = qp->jrqq->hwque;
		nswr = roundup_pow_of_two(attr->cap.max_recv_wr + 1);
		nsge = attr->cap.max_recv_sge;
		if (nsge % 2)
			nsge++;
		nslots = bnxt_re_get_rq_slots(dev, qp, nswr, nsge);
		if (nslots < 0) {
			ret = nslots;
			goto fail;
		}
		que->stride = sizeof(struct bnxt_re_sge);
		que->depth = nslots;
		que->diff = 0;

		ret = bnxt_re_alloc_aligned(que, pg_size);
		if (ret)
			goto fail;
		/* For RQ only bnxt_re_wri.wrid is used. */
		ret = bnxt_re_alloc_init_swque(qp->jrqq, nswr);
		if (ret)
			goto fail;
		pthread_spin_init(&que->qlock, PTHREAD_PROCESS_PRIVATE);
		qp->cap.max_rwr = nswr;
	}

	return 0;
fail:
	bnxt_re_free_queues(qp);
	return ret;
}

struct ibv_qp *bnxt_re_create_qp(struct ibv_pd *ibvpd,
				 struct ibv_qp_init_attr *attr)
{
	struct ubnxt_re_qp_resp resp;
	struct bnxt_re_qpcap *cap;
	struct ubnxt_re_qp req;
	struct bnxt_re_qp *qp;

	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvpd->context);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(cntx->ibvctx.context.device);

	if (bnxt_re_check_qp_limits(cntx, attr))
		return NULL;

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;
	/* alloc queue pointers */
	if (bnxt_re_alloc_queue_ptr(qp, attr))
		goto fail;
	/* alloc queues */
	qp->cctx = &cntx->cctx;
	qp->qpmode = cntx->wqe_mode & BNXT_RE_WQE_MODE_VARIABLE;
	if (bnxt_re_alloc_queues(dev, qp, attr, dev->pg_size))
		goto failq;
	/* Fill ibv_cmd */
	cap = &qp->cap;
	req.qpsva = (uintptr_t)qp->jsqq->hwque->va;
	req.qprva = qp->jrqq ? (uintptr_t)qp->jrqq->hwque->va : 0;
	req.qp_handle = (uintptr_t)qp;

	if (ibv_cmd_create_qp(ibvpd, &qp->ibvqp, attr, &req.ibv_cmd, sizeof(req),
			      &resp.ibv_resp, sizeof(resp))) {
		goto failcmd;
	}

	qp->qpid = resp.qpid;
	qp->qptyp = attr->qp_type;
	qp->qpst = IBV_QPS_RESET;
	qp->scq = to_bnxt_re_cq(attr->send_cq);
	qp->rcq = to_bnxt_re_cq(attr->recv_cq);
	if (attr->srq)
		qp->srq = to_bnxt_re_srq(attr->srq);
	qp->udpi = &cntx->udpi;
	/* Save/return the altered Caps. */
	cap->max_ssge = attr->cap.max_send_sge;
	cap->max_rsge = attr->cap.max_recv_sge;
	cap->max_inline = attr->cap.max_inline_data;
	cap->sqsig = attr->sq_sig_all;
	fque_init_node(&qp->snode);
	fque_init_node(&qp->rnode);

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
	int status;

	qp->qpst = IBV_QPS_RESET;
	status = ibv_cmd_destroy_qp(ibvqp);
	if (status)
		return status;

	bnxt_re_cleanup_cq(qp, qp->rcq);
	bnxt_re_cleanup_cq(qp, qp->scq);
	bnxt_re_free_queues(qp);
	bnxt_re_free_queue_ptr(qp);
	free(qp);

	return 0;
}

static int bnxt_re_calc_inline_len(struct ibv_send_wr *swr, uint32_t max_ils)
{
	int illen, indx;

	illen = 0;
	for (indx = 0; indx < swr->num_sge; indx++)
		illen += swr->sg_list[indx].length;
	if (illen > max_ils)
		illen = max_ils;
	return illen;
}

static int bnxt_re_calc_posted_wqe_slots(struct bnxt_re_queue *que, void *wr,
					 uint32_t max_ils, bool is_rq)
{
	struct ibv_send_wr *swr;
	struct ibv_recv_wr *rwr;
	uint32_t wqe_byte;
	uint32_t nsge;
	int ilsize;

	swr = wr;
	rwr = wr;

	nsge = is_rq ? rwr->num_sge : swr->num_sge;
	wqe_byte = bnxt_re_calc_wqe_sz(nsge);
	if (!is_rq && (swr->send_flags & IBV_SEND_INLINE)) {
		ilsize = bnxt_re_calc_inline_len(swr, max_ils);
		wqe_byte = get_aligned(ilsize, sizeof(struct bnxt_re_sge));
		wqe_byte += bnxt_re_get_sqe_hdr_sz();
	}

	return (wqe_byte / que->stride);
}

static inline uint8_t bnxt_re_set_hdr_flags(struct bnxt_re_bsqe *hdr,
					    uint32_t send_flags, uint8_t sqsig,
					    uint32_t slots)
{
	uint8_t is_inline = false;
	uint32_t hdrval = 0;

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

	if (send_flags & IBV_SEND_INLINE) {
		hdrval |= ((BNXT_RE_WR_FLAGS_INLINE & BNXT_RE_HDR_FLAGS_MASK)
			    << BNXT_RE_HDR_FLAGS_SHIFT);
		is_inline = true;
	}
	hdrval |= (slots & BNXT_RE_HDR_WS_MASK) << BNXT_RE_HDR_WS_SHIFT;
	hdr->rsv_ws_fl_wt = htole32(hdrval);

	return is_inline;
}

static int bnxt_re_build_sge(struct bnxt_re_queue *que, struct ibv_sge *sg_list,
			     uint32_t num_sge, uint8_t is_inline,
			     uint32_t *idx)
{
	struct bnxt_re_sge *sge;
	int indx, length = 0;
	void *dst;

	if (!num_sge)
		return 0;

	if (is_inline) {
		for (indx = 0; indx < num_sge; indx++) {
			dst = bnxt_re_get_hwqe(que, *idx);
			(*idx)++;
			length += sg_list[indx].length;
			memcpy(dst, (void *)(uintptr_t)sg_list[indx].addr,
			       sg_list[indx].length);
		}
	} else {
		for (indx = 0; indx < num_sge; indx++) {
			sge = bnxt_re_get_hwqe(que, *idx);
			(*idx)++;
			sge->pa = htole64(sg_list[indx].addr);
			sge->lkey = htole32(sg_list[indx].lkey);
			sge->length = htole32(sg_list[indx].length);
			length += sg_list[indx].length;
		}
	}

	return length;
}

static void bnxt_re_fill_psns(struct bnxt_re_qp *qp, struct bnxt_re_wrid *wrid,
			      uint8_t opcode, uint32_t len)
{
	uint32_t opc_spsn = 0, flg_npsn = 0;
	struct bnxt_re_psns_ext *psns_ext;
	uint32_t pkt_cnt = 0, nxt_psn = 0;
	struct bnxt_re_psns *psns;

	psns = wrid->psns;
	psns_ext = wrid->psns_ext;
	len = wrid->bytes;

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
	opcode = bnxt_re_ibv_wr_to_wc_opcd(opcode);
	opc_spsn |= (((uint32_t)opcode & BNXT_RE_PSNS_OPCD_MASK) <<
		      BNXT_RE_PSNS_OPCD_SHIFT);
	memset(psns, 0, sizeof(*psns));
	psns->opc_spsn = htole32(opc_spsn);
	psns->flg_npsn = htole32(flg_npsn);
	if (qp->cctx->gen_p5)
		psns_ext->st_slot_idx = wrid->st_slot_idx;
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

static int bnxt_re_build_send_sqe(struct bnxt_re_qp *qp,
				  struct ibv_send_wr *wr,
				  struct bnxt_re_bsqe *hdr,
				  uint8_t is_inline, uint32_t *idx)
{
	struct bnxt_re_queue *que;
	uint32_t hdrval = 0;
	uint8_t opcode;
	int len;

	que = qp->jsqq->hwque;
	len = bnxt_re_build_sge(que, wr->sg_list, wr->num_sge,
				is_inline, idx);
	if (len < 0)
		return len;
	hdr->lhdr.qkey_len = htole64((uint64_t)len);

	/* Fill Header */
	opcode = bnxt_re_ibv_to_bnxt_wr_opcd(wr->opcode);
	if (opcode == BNXT_RE_WR_OPCD_INVAL)
		return -EINVAL;
	hdrval = (opcode & BNXT_RE_HDR_WT_MASK);
	hdr->rsv_ws_fl_wt |= htole32(hdrval);
	return len;
}

static int bnxt_re_build_ud_sqe(struct bnxt_re_qp *qp, struct ibv_send_wr *wr,
				struct bnxt_re_bsqe *hdr, uint8_t is_inline,
				uint32_t *idx)
{
	struct bnxt_re_send *sqe;
	struct bnxt_re_ah *ah;
	uint64_t qkey;
	int len;

	sqe = bnxt_re_get_hwqe(qp->jsqq->hwque, *idx);
	(*idx)++;
	len = bnxt_re_build_send_sqe(qp, wr, hdr, is_inline, idx);
	if (!wr->wr.ud.ah) {
		len = -EINVAL;
		goto bail;
	}
	ah = to_bnxt_re_ah(wr->wr.ud.ah);
	qkey = wr->wr.ud.remote_qkey;
	hdr->lhdr.qkey_len |= htole64(qkey << 32);
	sqe->dst_qp = htole32(wr->wr.ud.remote_qpn);
	sqe->avid = htole32(ah->avid & 0xFFFFF);
bail:
	return len;
}

static int bnxt_re_build_rdma_sqe(struct bnxt_re_qp *qp,
				  struct bnxt_re_bsqe *hdr,
				  struct ibv_send_wr *wr,
				  uint8_t is_inline, uint32_t *idx)
{
	struct bnxt_re_rdma *sqe;
	int len;

	sqe = bnxt_re_get_hwqe(qp->jsqq->hwque, *idx);
	(*idx)++;
	len = bnxt_re_build_send_sqe(qp, wr, hdr, is_inline, idx);
	sqe->rva = htole64(wr->wr.rdma.remote_addr);
	sqe->rkey = htole32(wr->wr.rdma.rkey);

	return len;
}

static int bnxt_re_build_cns_sqe(struct bnxt_re_qp *qp,
				 struct bnxt_re_bsqe *hdr,
				 struct ibv_send_wr *wr, uint32_t *idx)
{
	struct bnxt_re_atomic *sqe;
	int len;

	sqe = bnxt_re_get_hwqe(qp->jsqq->hwque, *idx);
	(*idx)++;
	len = bnxt_re_build_send_sqe(qp, wr, hdr, false, idx);
	hdr->key_immd = htole32(wr->wr.atomic.rkey);
	hdr->lhdr.rva = htole64(wr->wr.atomic.remote_addr);
	sqe->cmp_dt = htole64(wr->wr.atomic.compare_add);
	sqe->swp_dt = htole64(wr->wr.atomic.swap);

	return len;
}

static int bnxt_re_build_fna_sqe(struct bnxt_re_qp *qp,
				 struct bnxt_re_bsqe *hdr,
				 struct ibv_send_wr *wr, uint32_t *idx)
{
	struct bnxt_re_atomic *sqe;
	int len;

	sqe = bnxt_re_get_hwqe(qp->jsqq->hwque, *idx);
	(*idx)++;
	len = bnxt_re_build_send_sqe(qp, wr, hdr, false, idx);
	hdr->key_immd = htole32(wr->wr.atomic.rkey);
	hdr->lhdr.rva = htole64(wr->wr.atomic.remote_addr);
	sqe->swp_dt = htole64(wr->wr.atomic.compare_add);

	return len;
}

int bnxt_re_post_send(struct ibv_qp *ibvqp, struct ibv_send_wr *wr,
		      struct ibv_send_wr **bad)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	struct bnxt_re_queue *sq = qp->jsqq->hwque;
	struct bnxt_re_wrid *wrid;
	struct bnxt_re_send *sqe;
	uint8_t is_inline = false;
	struct bnxt_re_bsqe *hdr;
	uint32_t swq_idx, slots;
	int ret = 0, bytes = 0;
	bool ring_db = false;
	uint32_t wqe_size;
	uint32_t max_ils;
	uint8_t sig = 0;
	uint32_t idx;

	pthread_spin_lock(&sq->qlock);
	while (wr) {
		max_ils = qp->cap.max_inline;
		wqe_size = bnxt_re_calc_posted_wqe_slots(sq, wr, max_ils, false);
		slots = (qp->qpmode == BNXT_RE_WQE_MODE_STATIC) ? 8 : wqe_size;
		if (bnxt_re_is_que_full(sq, slots) ||
		    wr->num_sge > qp->cap.max_ssge) {
			*bad = wr;
			ret = ENOMEM;
			goto bad_wr;
		}

		idx = 0;
		hdr = bnxt_re_get_hwqe(sq, idx++);
		is_inline = bnxt_re_set_hdr_flags(hdr, wr->send_flags,
						  qp->cap.sqsig, wqe_size);
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
			if (qp->qptyp == IBV_QPT_UD) {
				bytes = bnxt_re_build_ud_sqe(qp, wr, hdr,
							     is_inline, &idx);
			} else {
				sqe = bnxt_re_get_hwqe(sq, idx++);
				memset(sqe, 0, sizeof(struct bnxt_re_send));
				bytes = bnxt_re_build_send_sqe(qp, wr, hdr,
							       is_inline,
							       &idx);
			}
			break;
		case IBV_WR_RDMA_WRITE_WITH_IMM:
			hdr->key_immd = htole32(be32toh(wr->imm_data));
			SWITCH_FALLTHROUGH;
		case IBV_WR_RDMA_WRITE:
			bytes = bnxt_re_build_rdma_sqe(qp, hdr, wr, is_inline, &idx);
			break;
		case IBV_WR_RDMA_READ:
			bytes = bnxt_re_build_rdma_sqe(qp, hdr, wr, false, &idx);
			break;
		case IBV_WR_ATOMIC_CMP_AND_SWP:
			bytes = bnxt_re_build_cns_sqe(qp, hdr, wr, &idx);
			break;
		case IBV_WR_ATOMIC_FETCH_AND_ADD:
			bytes = bnxt_re_build_fna_sqe(qp, hdr, wr, &idx);
			break;
		default:
			bytes = -EINVAL;
			break;
		}

		if (bytes < 0) {
			ret = (bytes == -EINVAL) ? EINVAL : ENOMEM;
			*bad = wr;
			break;
		}

		wrid = bnxt_re_get_swqe(qp->jsqq, &swq_idx);
		sig = ((wr->send_flags & IBV_SEND_SIGNALED) || qp->cap.sqsig);
		bnxt_re_fill_wrid(wrid, wr->wr_id, bytes,
				  sig, sq->tail, slots);
		bnxt_re_fill_psns(qp, wrid, wr->opcode, bytes);
		bnxt_re_jqq_mod_start(qp->jsqq, swq_idx);
		bnxt_re_incr_tail(sq, slots);
		qp->wqe_cnt++;
		wr = wr->next;
		ring_db = true;

		if (qp->wqe_cnt == BNXT_RE_UD_QP_HW_STALL &&
		    qp->qptyp == IBV_QPT_UD) {
			/* Move RTS to RTS since it is time. */
			struct ibv_qp_attr attr;
			int attr_mask;

			attr_mask = IBV_QP_STATE;
			attr.qp_state = IBV_QPS_RTS;
			bnxt_re_modify_qp(&qp->ibvqp, &attr, attr_mask);
			qp->wqe_cnt = 0;
		}
	}

bad_wr:
	if (ring_db)
		bnxt_re_ring_sq_db(qp);

	pthread_spin_unlock(&sq->qlock);
	return ret;
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

int bnxt_re_post_recv(struct ibv_qp *ibvqp, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	struct bnxt_re_queue *rq = qp->jrqq->hwque;
	struct bnxt_re_wrid *swque;
	struct bnxt_re_brqe *hdr;
	struct bnxt_re_sge *sge;
	bool ring_db = false;
	uint32_t idx = 0;
	uint32_t swq_idx;
	uint32_t hdrval;
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

		if (!wr->num_sge) {
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

static void bnxt_re_srq_free_queue_ptr(struct bnxt_re_srq *srq)
{
	free(srq->srqq);
	free(srq);
}

static struct bnxt_re_srq *bnxt_re_srq_alloc_queue_ptr(void)
{
	struct bnxt_re_srq *srq;

	srq = calloc(1, sizeof(struct bnxt_re_srq));
	if (!srq)
		return NULL;

	srq->srqq = calloc(1, sizeof(struct bnxt_re_queue));
	if (!srq->srqq) {
		free(srq);
		return NULL;
	}

	return srq;
}

static void bnxt_re_srq_free_queue(struct bnxt_re_srq *srq)
{
	free(srq->srwrid);
	pthread_spin_destroy(&srq->srqq->qlock);
	bnxt_re_free_aligned(srq->srqq);
}

static int bnxt_re_srq_alloc_queue(struct bnxt_re_srq *srq,
				   struct ibv_srq_init_attr *attr,
				   uint32_t pg_size)
{
	struct bnxt_re_queue *que;
	int ret, idx;

	que = srq->srqq;
	que->depth = roundup_pow_of_two(attr->attr.max_wr + 1);
	que->diff = que->depth - attr->attr.max_wr;
	que->stride = bnxt_re_get_srqe_sz();
	ret = bnxt_re_alloc_aligned(que, pg_size);
	if (ret)
		goto bail;
	pthread_spin_init(&que->qlock, PTHREAD_PROCESS_PRIVATE);
	/* For SRQ only bnxt_re_wrid.wrid is used. */
	srq->srwrid = calloc(que->depth, sizeof(struct bnxt_re_wrid));
	if (!srq->srwrid) {
		ret = -ENOMEM;
		goto bail;
	}

	srq->start_idx = 0;
	srq->last_idx = que->depth - 1;
	for (idx = 0; idx < que->depth; idx++)
		srq->srwrid[idx].next_idx = idx + 1;
	srq->srwrid[srq->last_idx].next_idx = -1;

	/*TODO: update actual max depth. */
	return 0;
bail:
	bnxt_re_srq_free_queue(srq);
	return ret;
}

struct ibv_srq *bnxt_re_create_srq(struct ibv_pd *ibvpd,
				   struct ibv_srq_init_attr *attr)
{
	struct bnxt_re_srq *srq;
	struct ubnxt_re_srq req;
	struct ubnxt_re_srq_resp resp;
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvpd->context);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(cntx->ibvctx.context.device);
	int ret;

	/*TODO: Check max limit on queue depth and sge.*/
	srq = bnxt_re_srq_alloc_queue_ptr();
	if (!srq)
		goto fail;

	if (bnxt_re_srq_alloc_queue(srq, attr, dev->pg_size))
		goto fail;

	req.srqva = (uintptr_t)srq->srqq->va;
	req.srq_handle = (uintptr_t)srq;
	ret = ibv_cmd_create_srq(ibvpd, &srq->ibvsrq, attr,
				 &req.ibv_cmd, sizeof(req),
				 &resp.ibv_resp, sizeof(resp));
	if (ret)
		goto fail;

	srq->srqid = resp.srqid;
	srq->udpi = &cntx->udpi;
	srq->cap.max_wr = srq->srqq->depth;
	srq->cap.max_sge = attr->attr.max_sge;
	srq->cap.srq_limit = attr->attr.srq_limit;
	srq->arm_req = false;

	return &srq->ibvsrq;
fail:
	bnxt_re_srq_free_queue_ptr(srq);
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
	int ret;

	ret = ibv_cmd_destroy_srq(ibvsrq);
	if (ret)
		return ret;
	bnxt_re_srq_free_queue(srq);
	bnxt_re_srq_free_queue_ptr(srq);

	return 0;
}

int bnxt_re_query_srq(struct ibv_srq *ibvsrq, struct ibv_srq_attr *attr)
{
	struct ibv_query_srq cmd;

	return ibv_cmd_query_srq(ibvsrq, attr, &cmd, sizeof(cmd));
}

static int bnxt_re_build_srqe(struct bnxt_re_srq *srq,
			      struct ibv_recv_wr *wr, void *srqe)
{
	struct bnxt_re_brqe *hdr = srqe;
	struct bnxt_re_sge *sge;
	struct bnxt_re_wrid *wrid;
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

	return len;
}

int bnxt_re_post_srq_recv(struct ibv_srq *ibvsrq, struct ibv_recv_wr *wr,
			  struct ibv_recv_wr **bad)
{
	struct bnxt_re_srq *srq = to_bnxt_re_srq(ibvsrq);
	struct bnxt_re_queue *rq = srq->srqq;
	void *srqe;
	int ret, count = 0;

	pthread_spin_lock(&rq->qlock);
	count = rq->tail > rq->head ? rq->tail - rq->head :
			   rq->depth - rq->head + rq->tail;
	while (wr) {
		if (srq->start_idx == srq->last_idx ||
		    wr->num_sge > srq->cap.max_sge) {
			*bad = wr;
			pthread_spin_unlock(&rq->qlock);
			return ENOMEM;
		}

		srqe = (void *) (rq->va + (rq->tail * rq->stride));
		memset(srqe, 0, bnxt_re_get_srqe_sz());
		ret = bnxt_re_build_srqe(srq, wr, srqe);
		if (ret < 0) {
			pthread_spin_unlock(&rq->qlock);
			*bad = wr;
			return ENOMEM;
		}

		srq->start_idx = srq->srwrid[srq->start_idx].next_idx;
		bnxt_re_incr_tail(rq, 1);
		wr = wr->next;
		bnxt_re_ring_srq_db(srq);
		count++;
		if (srq->arm_req == true && count > srq->cap.srq_limit) {
			srq->arm_req = false;
			bnxt_re_ring_srq_arm(srq);
		}
	}
	pthread_spin_unlock(&rq->qlock);

	return 0;
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
