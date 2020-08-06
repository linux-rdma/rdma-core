/*
 * Copyright (c) 2006-2016 Chelsio, Inc. All rights reserved.
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
#include <assert.h>

#include "libcxgb4.h"
#include "cxgb4-abi.h"

bool is_64b_cqe;

#define MASKED(x) (void *)((unsigned long)(x) & c4iw_page_mask)

int c4iw_query_device(struct ibv_context *context, struct ibv_device_attr *attr)
{
	struct ibv_query_device cmd;
	uint64_t raw_fw_ver;
	u8 major, minor, sub_minor, build;
	int ret;

	ret = ibv_cmd_query_device(context, attr, &raw_fw_ver, &cmd,
				   sizeof cmd);
	if (ret)
		return ret;

	major = (raw_fw_ver >> 24) & 0xff;
	minor = (raw_fw_ver >> 16) & 0xff;
	sub_minor = (raw_fw_ver >> 8) & 0xff;
	build = raw_fw_ver & 0xff;

	snprintf(attr->fw_ver, sizeof attr->fw_ver,
		 "%d.%d.%d.%d", major, minor, sub_minor, build);

	return 0;
}

int c4iw_query_port(struct ibv_context *context, uint8_t port,
		    struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof cmd);
}

struct ibv_pd *c4iw_alloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct uc4iw_alloc_pd_resp resp;
	struct c4iw_pd *pd;

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

int c4iw_free_pd(struct ibv_pd *pd)
{
	int ret;

	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	free(pd);
	return 0;
}

struct ibv_mr *c4iw_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			   uint64_t hca_va, int access)
{
	struct c4iw_mr *mhp;
	struct ibv_reg_mr cmd;
	struct ib_uverbs_reg_mr_resp resp;
	struct c4iw_dev *dev = to_c4iw_dev(pd->context->device);

	PDBG("%s addr %p length %ld hca_va %p\n", __func__, addr, length,
	     hca_va);

	mhp = malloc(sizeof *mhp);
	if (!mhp)
		return NULL;

	if (ibv_cmd_reg_mr(pd, addr, length, hca_va,
			   access, &mhp->vmr, &cmd, sizeof(cmd),
			   &resp, sizeof resp)) {
		free(mhp);
		return NULL;
	}

	mhp->va_fbo = hca_va;
	mhp->len = length;

	PDBG("%s stag 0x%x va_fbo 0x%" PRIx64 " len %d\n",
	     __func__, mhp->vmr.ibv_mr.rkey, mhp->va_fbo, mhp->len);

	pthread_spin_lock(&dev->lock);
	dev->mmid2ptr[c4iw_mmid(mhp->vmr.ibv_mr.lkey)] = mhp;
	pthread_spin_unlock(&dev->lock);
	INC_STAT(mr);
	return &mhp->vmr.ibv_mr;
}

int c4iw_dereg_mr(struct verbs_mr *vmr)
{
	int ret;
	struct c4iw_dev *dev = to_c4iw_dev(vmr->ibv_mr.pd->context->device);

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

	pthread_spin_lock(&dev->lock);
	dev->mmid2ptr[c4iw_mmid(vmr->ibv_mr.lkey)] = NULL;
	pthread_spin_unlock(&dev->lock);

	free(to_c4iw_mr(vmr));

	return 0;
}

struct ibv_cq *c4iw_create_cq(struct ibv_context *context, int cqe,
			      struct ibv_comp_channel *channel, int comp_vector)
{
	struct uc4iw_create_cq cmd = {};
	struct uc4iw_create_cq_resp resp;
	struct c4iw_cq *chp;
	struct c4iw_dev *dev = to_c4iw_dev(context->device);
	int ret;

	chp = calloc(1, sizeof *chp);
	if (!chp) {
		return NULL;
	}

	resp.flags = 0;
	cmd.flags = C4IW_64B_CQE;

	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				&chp->ibv_cq, &cmd.ibv_cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof resp);
	if (ret)
		goto err1;

	if (resp.flags & C4IW_64B_CQE)
		is_64b_cqe = true;

	pthread_spin_init(&chp->lock, PTHREAD_PROCESS_PRIVATE);
#ifdef STALL_DETECTION
	gettimeofday(&chp->time, NULL);
#endif
	chp->rhp = dev;
	chp->cq.qid_mask = resp.qid_mask;
	chp->cq.cqid = resp.cqid;
	chp->cq.size = resp.size;
	chp->cq.memsize = resp.memsize;
	chp->cq.gen = 1;
	chp->cq.queue = mmap(NULL, chp->cq.memsize, PROT_READ|PROT_WRITE,
			     MAP_SHARED, context->cmd_fd, resp.key);
	if (chp->cq.queue == MAP_FAILED)
		goto err2;

	chp->cq.qp_errp =
	&((struct t4_status_page *)
			Q_ENTRY(chp->cq.queue, chp->cq.size))->qp_err;

	chp->cq.ugts = mmap(NULL, c4iw_page_size, PROT_WRITE, MAP_SHARED,
			   context->cmd_fd, resp.gts_key);
	if (chp->cq.ugts == MAP_FAILED)
		goto err3;

	if (dev_is_t4(chp->rhp))
		chp->cq.ugts += 1;
	else
		chp->cq.ugts += 5;
	chp->cq.sw_queue = calloc(chp->cq.size, CQE_SIZE(chp->cq.queue));
	if (!chp->cq.sw_queue)
		goto err4;

	PDBG("%s cqid 0x%x key %" PRIx64 " va %p memsize %lu gts_key %"
	       PRIx64 " va %p qid_mask 0x%x\n",
	       __func__, chp->cq.cqid, resp.key, chp->cq.queue,
	       chp->cq.memsize, resp.gts_key, chp->cq.ugts, chp->cq.qid_mask);

	pthread_spin_lock(&dev->lock);
	dev->cqid2ptr[chp->cq.cqid] = chp;
	pthread_spin_unlock(&dev->lock);
	INC_STAT(cq);
	return &chp->ibv_cq;
err4:
	munmap(MASKED(chp->cq.ugts), c4iw_page_size);
err3:
	munmap(chp->cq.queue, chp->cq.memsize);
err2:
	(void)ibv_cmd_destroy_cq(&chp->ibv_cq);
err1:
	free(chp);
	return NULL;
}

int c4iw_destroy_cq(struct ibv_cq *ibcq)
{
	int ret;
	struct c4iw_cq *chp = to_c4iw_cq(ibcq);
	struct c4iw_dev *dev = to_c4iw_dev(ibcq->context->device);

	chp->cq.error = 1;
	ret = ibv_cmd_destroy_cq(ibcq);
	if (ret) {
		return ret;
	}
	munmap(MASKED(chp->cq.ugts), c4iw_page_size);
	munmap(chp->cq.queue, chp->cq.memsize);

	pthread_spin_lock(&dev->lock);
	dev->cqid2ptr[chp->cq.cqid] = NULL;
	pthread_spin_unlock(&dev->lock);

	free(chp->cq.sw_queue);
	free(chp);
	return 0;
}

struct ibv_srq *c4iw_create_srq(struct ibv_pd *pd,
				struct ibv_srq_init_attr *attr)
{
	struct c4iw_dev *dev = to_c4iw_dev(pd->context->device);
	struct uc4iw_create_srq_resp resp;
	unsigned long segment_offset;
	struct ibv_create_srq cmd;
	struct c4iw_srq *srq;
	void *dbva;
	int ret;

	PDBG("%s enter\n", __func__);
	srq = calloc(1, sizeof(*srq));
	if (!srq)
		goto err;

	ret = ibv_cmd_create_srq(pd, &srq->ibv_srq, attr, &cmd,
			sizeof(cmd), &resp.ibv_resp, sizeof(resp));
	if (ret)
		goto err_free_srq_mem;

	PDBG("%s srq id 0x%x srq key %" PRIx64 " srq db/gts key %" PRIx64
			" qid_mask 0x%x\n", __func__,
			resp.srqid, resp.srq_key, resp.srq_db_gts_key,
			resp.qid_mask);

	srq->rhp = dev;
	srq->wq.qid = resp.srqid;
	srq->wq.size = resp.srq_size;
	srq->wq.memsize = resp.srq_memsize;
	srq->wq.rqt_abs_idx = resp.rqt_abs_idx;
	srq->flags = resp.flags;
	pthread_spin_init(&srq->lock, PTHREAD_PROCESS_PRIVATE);

	dbva = mmap(NULL, c4iw_page_size, PROT_WRITE, MAP_SHARED,
			pd->context->cmd_fd, resp.srq_db_gts_key);
	if (dbva == MAP_FAILED)
		goto err_destroy_srq;
	srq->wq.udb = dbva;

	segment_offset = 128 * (srq->wq.qid & resp.qid_mask);
	if (segment_offset < c4iw_page_size) {
		srq->wq.udb += segment_offset / 4;
		srq->wq.wc_reg_available = 1;
	} else
		srq->wq.bar2_qid = srq->wq.qid & resp.qid_mask;
	srq->wq.udb += 2;

	srq->wq.queue = mmap(NULL, srq->wq.memsize,
			PROT_WRITE, MAP_SHARED,
			pd->context->cmd_fd, resp.srq_key);
	if (srq->wq.queue == MAP_FAILED)
		goto err_unmap_udb;

	srq->wq.sw_rq = calloc(srq->wq.size, sizeof(struct t4_swrqe));
	if (!srq->wq.sw_rq)
		goto err_unmap_queue;
	srq->wq.pending_wrs =
		calloc(srq->wq.size, sizeof(*srq->wq.pending_wrs));
	if (!srq->wq.pending_wrs)
		goto err_free_sw_rq;

	pthread_spin_lock(&dev->lock);
	list_add_tail(&dev->srq_list, &srq->list);
	pthread_spin_unlock(&dev->lock);

	PDBG("%s srq dbva %p srq qva %p srq depth %u srq memsize %lu\n",
			__func__, srq->wq.udb, srq->wq.queue,
			srq->wq.size, srq->wq.memsize);

	INC_STAT(srq);
	return &srq->ibv_srq;
err_free_sw_rq:
	free(srq->wq.sw_rq);
err_unmap_queue:
	munmap((void *)srq->wq.queue, srq->wq.memsize);
err_unmap_udb:
	munmap(MASKED(srq->wq.udb), c4iw_page_size);
err_destroy_srq:
	(void)ibv_cmd_destroy_srq(&srq->ibv_srq);
err_free_srq_mem:
	free(srq);
err:

	return NULL;
}

int c4iw_modify_srq(struct ibv_srq *ibsrq, struct ibv_srq_attr *attr,
		    int attr_mask)
{
	struct c4iw_srq *srq = to_c4iw_srq(ibsrq);
	struct ibv_modify_srq cmd;
	int ret;

	/* XXX no support for this yet */
	if (attr_mask & IBV_SRQ_MAX_WR)
		return EINVAL;

	ret = ibv_cmd_modify_srq(ibsrq, attr, attr_mask, &cmd, sizeof(cmd));
	if (!ret) {
		if (attr_mask & IBV_SRQ_LIMIT) {
			srq->armed = 1;
			srq->srq_limit = attr->srq_limit;
		}
	}
	return ret;
}

int c4iw_destroy_srq(struct ibv_srq *ibsrq)
{
	int ret;
	struct c4iw_srq *srq = to_c4iw_srq(ibsrq);

	PDBG("%s enter qp %p\n", __func__, ibsrq);

	ret = ibv_cmd_destroy_srq(ibsrq);
	if (ret)
		return ret;

	pthread_spin_lock(&srq->rhp->lock);
	list_del(&srq->list);
	pthread_spin_unlock(&srq->rhp->lock);

	munmap(MASKED(srq->wq.udb), c4iw_page_size);
	munmap(srq->wq.queue, srq->wq.memsize);

	free(srq->wq.pending_wrs);
	free(srq->wq.sw_rq);
	free(srq);
	return 0;

}

int c4iw_query_srq(struct ibv_srq *ibsrq, struct ibv_srq_attr *attr)
{
	struct ibv_query_srq cmd;

	return ibv_cmd_query_srq(ibsrq, attr, &cmd, sizeof(cmd));
}

static struct ibv_qp *create_qp_v0(struct ibv_pd *pd,
				   struct ibv_qp_init_attr *attr)
{
	struct ibv_create_qp cmd;
	struct uc4iw_create_qp_v0_resp resp;
	struct c4iw_qp *qhp;
	struct c4iw_dev *dev = to_c4iw_dev(pd->context->device);
	int ret;
	void *dbva;

	PDBG("%s enter qp\n", __func__);
	qhp = calloc(1, sizeof *qhp);
	if (!qhp)
		goto err1;

	ret = ibv_cmd_create_qp(pd, &qhp->ibv_qp, attr, &cmd,
				sizeof cmd, &resp.ibv_resp, sizeof resp);
	if (ret)
		goto err2;

	PDBG("%s sqid 0x%x sq key %" PRIx64 " sq db/gts key %" PRIx64
	       " rqid 0x%x rq key %" PRIx64 " rq db/gts key %" PRIx64
	       " qid_mask 0x%x\n",
		__func__,
		resp.sqid, resp.sq_key, resp.sq_db_gts_key,
		resp.rqid, resp.rq_key, resp.rq_db_gts_key, resp.qid_mask);

	qhp->wq.qid_mask = resp.qid_mask;
	qhp->rhp = dev;
	qhp->wq.sq.qid = resp.sqid;
	qhp->wq.sq.size = resp.sq_size;
	qhp->wq.sq.memsize = resp.sq_memsize;
	qhp->wq.sq.flags = 0;
	qhp->wq.rq.msn = 1;
	qhp->wq.rq.qid = resp.rqid;
	qhp->wq.rq.size = resp.rq_size;
	qhp->wq.rq.memsize = resp.rq_memsize;
	pthread_spin_init(&qhp->lock, PTHREAD_PROCESS_PRIVATE);

	dbva = mmap(NULL, c4iw_page_size, PROT_WRITE, MAP_SHARED,
		    pd->context->cmd_fd, resp.sq_db_gts_key);
	if (dbva == MAP_FAILED)
		goto err3;

	qhp->wq.sq.udb = dbva;
	qhp->wq.sq.queue = mmap(NULL, qhp->wq.sq.memsize,
			    PROT_WRITE, MAP_SHARED,
			    pd->context->cmd_fd, resp.sq_key);
	if (qhp->wq.sq.queue == MAP_FAILED)
		goto err4;

	dbva = mmap(NULL, c4iw_page_size, PROT_WRITE, MAP_SHARED,
		    pd->context->cmd_fd, resp.rq_db_gts_key);
	if (dbva == MAP_FAILED)
		goto err5;
	qhp->wq.rq.udb = dbva;
	qhp->wq.rq.queue = mmap(NULL, qhp->wq.rq.memsize,
			    PROT_WRITE, MAP_SHARED,
			    pd->context->cmd_fd, resp.rq_key);
	if (qhp->wq.rq.queue == MAP_FAILED)
		goto err6;

	qhp->wq.sq.sw_sq = calloc(qhp->wq.sq.size, sizeof (struct t4_swsqe));
	if (!qhp->wq.sq.sw_sq)
		goto err7;

	qhp->wq.rq.sw_rq = calloc(qhp->wq.rq.size, sizeof(struct t4_swrqe));
	if (!qhp->wq.rq.sw_rq)
		goto err8;

	PDBG("%s sq dbva %p sq qva %p sq depth %u sq memsize %lu "
	       " rq dbva %p rq qva %p rq depth %u rq memsize %lu\n",
	     __func__,
	     qhp->wq.sq.udb, qhp->wq.sq.queue,
	     qhp->wq.sq.size, qhp->wq.sq.memsize,
	     qhp->wq.rq.udb, qhp->wq.rq.queue,
	     qhp->wq.rq.size, qhp->wq.rq.memsize);

	qhp->sq_sig_all = attr->sq_sig_all;

	pthread_spin_lock(&dev->lock);
	dev->qpid2ptr[qhp->wq.sq.qid] = qhp;
	pthread_spin_unlock(&dev->lock);
	INC_STAT(qp);
	return &qhp->ibv_qp;
err8:
	free(qhp->wq.sq.sw_sq);
err7:
	munmap((void *)qhp->wq.rq.queue, qhp->wq.rq.memsize);
err6:
	munmap(MASKED(qhp->wq.rq.udb), c4iw_page_size);
err5:
	munmap((void *)qhp->wq.sq.queue, qhp->wq.sq.memsize);
err4:
	munmap(MASKED(qhp->wq.sq.udb), c4iw_page_size);
err3:
	(void)ibv_cmd_destroy_qp(&qhp->ibv_qp);
err2:
	free(qhp);
err1:
	return NULL;
}

static struct ibv_qp *create_qp(struct ibv_pd *pd,
				struct ibv_qp_init_attr *attr)
{
	struct ibv_create_qp cmd;
	struct uc4iw_create_qp_resp resp;
	struct c4iw_qp *qhp;
	struct c4iw_dev *dev = to_c4iw_dev(pd->context->device);
	struct c4iw_context *ctx = to_c4iw_context(pd->context);
	int ret;
	void *dbva;

	PDBG("%s enter qp\n", __func__);
	qhp = calloc(1, sizeof *qhp);
	if (!qhp)
		goto err1;

	ret = ibv_cmd_create_qp(pd, &qhp->ibv_qp, attr, &cmd,
				sizeof cmd, &resp.ibv_resp, sizeof resp);
	if (ret)
		goto err2;

	PDBG("%s sqid 0x%x sq key %" PRIx64 " sq db/gts key %" PRIx64
	       " rqid 0x%x rq key %" PRIx64 " rq db/gts key %" PRIx64
	       " qid_mask 0x%x\n",
		__func__,
		resp.sqid, resp.sq_key, resp.sq_db_gts_key,
		resp.rqid, resp.rq_key, resp.rq_db_gts_key, resp.qid_mask);

	qhp->wq.qid_mask = resp.qid_mask;
	qhp->rhp = dev;
	qhp->wq.sq.qid = resp.sqid;
	qhp->wq.sq.size = resp.sq_size;
	qhp->wq.sq.memsize = resp.sq_memsize;
	qhp->wq.sq.flags = resp.flags & C4IW_QPF_ONCHIP ? T4_SQ_ONCHIP : 0;
	if (resp.flags & C4IW_QPF_WRITE_W_IMM)
		qhp->wq.sq.flags |= T4_SQ_WRITE_W_IMM;
	qhp->wq.sq.flush_cidx = -1;
	qhp->wq.rq.msn = 1;
	qhp->srq = to_c4iw_srq(attr->srq);
	if (!attr->srq) {
		qhp->wq.rq.qid = resp.rqid;
		qhp->wq.rq.size = resp.rq_size;
		qhp->wq.rq.memsize = resp.rq_memsize;
	}
	if (ma_wr && resp.sq_memsize < (resp.sq_size + 1) *
	    sizeof *qhp->wq.sq.queue + 16*sizeof(__be64) ) {
		ma_wr = 0;
		fprintf(stderr, "libcxgb4 warning - downlevel iw_cxgb4 driver. "
			"MA workaround disabled.\n");
	}
	pthread_spin_init(&qhp->lock, PTHREAD_PROCESS_PRIVATE);

	dbva = mmap(NULL, c4iw_page_size, PROT_WRITE, MAP_SHARED,
		    pd->context->cmd_fd, resp.sq_db_gts_key);
	if (dbva == MAP_FAILED)
		goto err3;
	qhp->wq.sq.udb = dbva;
	if (!dev_is_t4(qhp->rhp)) {
		unsigned long segment_offset = 128 * (qhp->wq.sq.qid &
						      qhp->wq.qid_mask);

		if (segment_offset < c4iw_page_size) {
			qhp->wq.sq.udb += segment_offset / 4;
			qhp->wq.sq.wc_reg_available = 1;
		} else
			qhp->wq.sq.bar2_qid = qhp->wq.sq.qid & qhp->wq.qid_mask;
		qhp->wq.sq.udb += 2;
	}

	qhp->wq.sq.queue = mmap(NULL, qhp->wq.sq.memsize,
			    PROT_WRITE, MAP_SHARED,
			    pd->context->cmd_fd, resp.sq_key);
	if (qhp->wq.sq.queue == MAP_FAILED)
		goto err4;

	if (!attr->srq) {
		dbva = mmap(NULL, c4iw_page_size, PROT_WRITE, MAP_SHARED,
				pd->context->cmd_fd, resp.rq_db_gts_key);
		if (dbva == MAP_FAILED)
			goto err5;
		qhp->wq.rq.udb = dbva;
		if (!dev_is_t4(qhp->rhp)) {
			unsigned long segment_offset = 128 * (qhp->wq.rq.qid &
					qhp->wq.qid_mask);

			if (segment_offset < c4iw_page_size) {
				qhp->wq.rq.udb += segment_offset / 4;
				qhp->wq.rq.wc_reg_available = 1;
			} else
				qhp->wq.rq.bar2_qid =
					qhp->wq.rq.qid & qhp->wq.qid_mask;
			qhp->wq.rq.udb += 2;
		}
		qhp->wq.rq.queue = mmap(NULL, qhp->wq.rq.memsize,
				PROT_WRITE, MAP_SHARED,
				pd->context->cmd_fd, resp.rq_key);
		if (qhp->wq.rq.queue == MAP_FAILED)
			goto err6;
	}

	qhp->wq.sq.sw_sq = calloc(qhp->wq.sq.size, sizeof (struct t4_swsqe));
	if (!qhp->wq.sq.sw_sq)
		goto err7;

	if (!attr->srq) {
		qhp->wq.rq.sw_rq =
			calloc(qhp->wq.rq.size, sizeof(struct t4_swrqe));
		if (!qhp->wq.rq.sw_rq)
			goto err8;
	}

	if (t4_sq_onchip(&qhp->wq)) {
		qhp->wq.sq.ma_sync = mmap(NULL, c4iw_page_size, PROT_WRITE,
					  MAP_SHARED, pd->context->cmd_fd,
					  resp.ma_sync_key);
		if (qhp->wq.sq.ma_sync == MAP_FAILED)
			goto err9;
		qhp->wq.sq.ma_sync += (A_PCIE_MA_SYNC & (c4iw_page_size - 1));
	}

	if (ctx->status_page_size) {
		qhp->wq.db_offp = &ctx->status_page->db_off;
	} else if (!attr->srq) {
		qhp->wq.db_offp = 
			&qhp->wq.rq.queue[qhp->wq.rq.size].status.db_off;
	}

	if (!attr->srq)
		qhp->wq.qp_errp =
			&qhp->wq.rq.queue[qhp->wq.rq.size].status.qp_err;
	else {
		qhp->wq.qp_errp =
			&qhp->wq.sq.queue[qhp->wq.sq.size].status.qp_err;
		qhp->wq.srqidxp =
			&qhp->wq.sq.queue[qhp->wq.sq.size].status.srqidx;
	}

	PDBG("%s sq dbva %p sq qva %p sq depth %u sq memsize %lu "
	       " rq dbva %p rq qva %p rq depth %u rq memsize %lu\n",
	     __func__,
	     qhp->wq.sq.udb, qhp->wq.sq.queue,
	     qhp->wq.sq.size, qhp->wq.sq.memsize,
	     qhp->wq.rq.udb, qhp->wq.rq.queue,
	     qhp->wq.rq.size, qhp->wq.rq.memsize);

	qhp->sq_sig_all = attr->sq_sig_all;

	pthread_spin_lock(&dev->lock);
	dev->qpid2ptr[qhp->wq.sq.qid] = qhp;
	pthread_spin_unlock(&dev->lock);
	INC_STAT(qp);
	return &qhp->ibv_qp;
err9:
	if (!attr->srq)
		free(qhp->wq.rq.sw_rq);
err8:
	free(qhp->wq.sq.sw_sq);
err7:
	if (!attr->srq)
		munmap((void *)qhp->wq.rq.queue, qhp->wq.rq.memsize);
err6:
	if (!attr->srq)
		munmap(MASKED(qhp->wq.rq.udb), c4iw_page_size);
err5:
	munmap((void *)qhp->wq.sq.queue, qhp->wq.sq.memsize);
err4:
	munmap(MASKED(qhp->wq.sq.udb), c4iw_page_size);
err3:
	(void)ibv_cmd_destroy_qp(&qhp->ibv_qp);
err2:
	free(qhp);
err1:
	return NULL;
}

struct ibv_qp *c4iw_create_qp(struct ibv_pd *pd,
				     struct ibv_qp_init_attr *attr)
{
	struct c4iw_dev *dev = to_c4iw_dev(pd->context->device);

	if (dev->abi_version == 0)
		return create_qp_v0(pd, attr);
	return create_qp(pd, attr);
}

static void reset_qp(struct c4iw_qp *qhp)
{
	PDBG("%s enter qp %p\n", __func__, qhp);
	qhp->wq.sq.cidx = 0;
	qhp->wq.sq.wq_pidx = qhp->wq.sq.pidx = qhp->wq.sq.in_use = 0;
	qhp->wq.rq.cidx = qhp->wq.rq.pidx = qhp->wq.rq.in_use = 0;
	qhp->wq.sq.oldest_read = NULL;
	memset(qhp->wq.sq.queue, 0, qhp->wq.sq.memsize);
	if (t4_sq_onchip(&qhp->wq))
		mmio_flush_writes();
	memset(qhp->wq.rq.queue, 0, qhp->wq.rq.memsize);
}

int c4iw_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
		   int attr_mask)
{
	struct ibv_modify_qp cmd = {};
	struct c4iw_qp *qhp = to_c4iw_qp(ibqp);
	int ret;

	PDBG("%s enter qp %p new state %d\n", __func__, ibqp, attr_mask & IBV_QP_STATE ? attr->qp_state : -1);
	if (t4_wq_in_error(&qhp->wq))
		c4iw_flush_qp(qhp);
	pthread_spin_lock(&qhp->lock);
	ret = ibv_cmd_modify_qp(ibqp, attr, attr_mask, &cmd, sizeof cmd);
	if (!ret && (attr_mask & IBV_QP_STATE) && attr->qp_state == IBV_QPS_RESET)
		reset_qp(qhp);
	pthread_spin_unlock(&qhp->lock);
	return ret;
}

int c4iw_destroy_qp(struct ibv_qp *ibqp)
{
	int ret;
	struct c4iw_qp *qhp = to_c4iw_qp(ibqp);
	struct c4iw_dev *dev = to_c4iw_dev(ibqp->context->device);

	PDBG("%s enter qp %p\n", __func__, ibqp);
	c4iw_flush_qp(qhp);

	ret = ibv_cmd_destroy_qp(ibqp);
	if (ret) {
		return ret;
	}
	if (t4_sq_onchip(&qhp->wq)) {
		qhp->wq.sq.ma_sync -= (A_PCIE_MA_SYNC & (c4iw_page_size - 1));
		munmap((void *)qhp->wq.sq.ma_sync, c4iw_page_size);
	}
	munmap(MASKED(qhp->wq.sq.udb), c4iw_page_size);
	munmap(qhp->wq.sq.queue, qhp->wq.sq.memsize);
	if (!qhp->srq) {
		munmap(MASKED(qhp->wq.rq.udb), c4iw_page_size);
		munmap(qhp->wq.rq.queue, qhp->wq.rq.memsize);
	}

	pthread_spin_lock(&dev->lock);
	dev->qpid2ptr[qhp->wq.sq.qid] = NULL;
	pthread_spin_unlock(&dev->lock);

	if (!qhp->srq)
		free(qhp->wq.rq.sw_rq);
	free(qhp->wq.sq.sw_sq);
	free(qhp);
	return 0;
}

int c4iw_query_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
		  int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;
	struct c4iw_qp *qhp = to_c4iw_qp(ibqp);
	int ret;

	if (t4_wq_in_error(&qhp->wq))
		c4iw_flush_qp(qhp);
	pthread_spin_lock(&qhp->lock);
	ret = ibv_cmd_query_qp(ibqp, attr, attr_mask, init_attr, &cmd, sizeof cmd);
	pthread_spin_unlock(&qhp->lock);
	return ret;
}

int c4iw_attach_mcast(struct ibv_qp *ibqp, const union ibv_gid *gid,
		      uint16_t lid)
{
	struct c4iw_qp *qhp = to_c4iw_qp(ibqp);
	int ret;

	if (t4_wq_in_error(&qhp->wq))
		c4iw_flush_qp(qhp);
	pthread_spin_lock(&qhp->lock);
	ret = ibv_cmd_attach_mcast(ibqp, gid, lid);
	pthread_spin_unlock(&qhp->lock);
	return ret;
}

int c4iw_detach_mcast(struct ibv_qp *ibqp, const union ibv_gid *gid,
		      uint16_t lid)
{
	struct c4iw_qp *qhp = to_c4iw_qp(ibqp);
	int ret;

	if (t4_wq_in_error(&qhp->wq))
		c4iw_flush_qp(qhp);
	pthread_spin_lock(&qhp->lock);
	ret = ibv_cmd_detach_mcast(ibqp, gid, lid);
	pthread_spin_unlock(&qhp->lock);
	return ret;
}

void c4iw_async_event(struct ibv_context *context,
		      struct ibv_async_event *event)
{
	PDBG("%s type %d obj %p\n", __func__, event->event_type,
	event->element.cq);

	switch (event->event_type) {
	case IBV_EVENT_CQ_ERR:
		break;
	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_REQ_ERR:
	case IBV_EVENT_QP_ACCESS_ERR:
	case IBV_EVENT_PATH_MIG_ERR: {
		struct c4iw_qp *qhp = to_c4iw_qp(event->element.qp);
		c4iw_flush_qp(qhp);
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
