/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
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
 *
 * $Id$
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <strings.h>
#include <pthread.h>
#include <netinet/in.h>

#include "mthca.h"
#include "mthca-abi.h"

int mthca_query_port(struct ibv_context *context, uint8_t port,
		     struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof cmd);
}

struct ibv_pd *mthca_alloc_pd(struct ibv_context *context)
{
	struct mthca_alloc_pd      cmd;
	struct mthca_alloc_pd_resp resp;
	struct mthca_pd           *pd;

	pd = malloc(sizeof *pd);
	if (!pd)
		return NULL;

	if (!mthca_is_memfree(context)) {
		pd->ah_list = NULL;
		if (pthread_mutex_init(&pd->ah_mutex, NULL)) {
			free(pd);
			return NULL;
		}
	}

	cmd.pdnbuf = (uintptr_t) &resp;
	if (ibv_cmd_alloc_pd(context, &pd->ibv_pd, &cmd.ibv_cmd, sizeof cmd)) {
		free(pd);
		return NULL;
	}

	pd->pdn = resp.pdn;

	return &pd->ibv_pd;
}

int mthca_free_pd(struct ibv_pd *pd)
{
	int ret;

	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	free(pd);
	return 0;
}

static struct ibv_mr *__mthca_reg_mr(struct ibv_pd *pd, void *addr,
				     size_t length, uint64_t hca_va,
				     enum ibv_access_flags access)
{
	struct ibv_mr *mr;
	struct ibv_reg_mr cmd;

	mr = malloc(sizeof *mr);
	if (!mr)
		return NULL;

	if (ibv_cmd_reg_mr(pd, addr, length, hca_va,
			   access, mr, &cmd, sizeof cmd)) {
		free(mr);
		return NULL;
	}

	return mr;
}

struct ibv_mr *mthca_reg_mr(struct ibv_pd *pd, void *addr,
			    size_t length, enum ibv_access_flags access)
{
	return __mthca_reg_mr(pd, addr, length, (uintptr_t) addr, access);
}

int mthca_dereg_mr(struct ibv_mr *mr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(mr);
	if (ret)
		return ret;

	free(mr);
	return 0;
}

struct ibv_cq *mthca_create_cq(struct ibv_context *context, int cqe)
{
	struct mthca_create_cq      cmd;
	struct mthca_create_cq_resp resp;
	struct mthca_cq      	   *cq;
	int                  	    nent;
	int                  	    ret;

	cq = malloc(sizeof *cq);
	if (!cq)
		return NULL;

	if (pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE))
		goto err;

	for (nent = 1; nent <= cqe; nent <<= 1)
		; /* nothing */

	if (posix_memalign(&cq->buf, to_mdev(context->device)->page_size,
			   align(nent * MTHCA_CQ_ENTRY_SIZE, to_mdev(context->device)->page_size)))
		goto err;

	mthca_init_cq_buf(cq, nent);

	cq->mr = __mthca_reg_mr(to_mctx(context)->pd, cq->buf,
				nent * MTHCA_CQ_ENTRY_SIZE,
				0, IBV_ACCESS_LOCAL_WRITE);
	if (!cq->mr)
		goto err_buf;

	cq->mr->context = context;

	if (mthca_is_memfree(context)) {
		cq->arm_sn          = 1;
		cq->set_ci_db_index = mthca_alloc_db(to_mctx(context)->db_tab,
						     MTHCA_DB_TYPE_CQ_SET_CI,
						     &cq->set_ci_db);
		if (cq->set_ci_db_index < 0)
			goto err_unreg;

		cq->arm_db_index    = mthca_alloc_db(to_mctx(context)->db_tab,
						     MTHCA_DB_TYPE_CQ_ARM,
						     &cq->arm_db);
		if (cq->arm_db_index < 0)
			goto err_set_db;

		cmd.arm_db_page  = db_align(cq->arm_db);
		cmd.set_db_page  = db_align(cq->set_ci_db);
		cmd.arm_db_index = cq->arm_db_index;
		cmd.set_db_index = cq->set_ci_db_index;
	}

	cmd.cqnbuf = (uintptr_t) &resp;
	cmd.lkey   = cq->mr->lkey;
	cmd.pdn    = to_mpd(to_mctx(context)->pd)->pdn;
	ret = ibv_cmd_create_cq(context, nent - 1, &cq->ibv_cq, &cmd.ibv_cmd, sizeof cmd);
	if (ret)
		goto err_arm_db;

	cq->cqn = resp.cqn;

	if (mthca_is_memfree(context)) {
		mthca_set_db_qn(cq->set_ci_db, MTHCA_DB_TYPE_CQ_SET_CI, cq->cqn);
		mthca_set_db_qn(cq->arm_db,    MTHCA_DB_TYPE_CQ_ARM,    cq->cqn);
	}

	return &cq->ibv_cq;

err_arm_db:
	if (mthca_is_memfree(context))
		mthca_free_db(to_mctx(context)->db_tab, MTHCA_DB_TYPE_CQ_SET_CI,
			      cq->set_ci_db_index);

err_set_db:
	if (mthca_is_memfree(context))
		mthca_free_db(to_mctx(context)->db_tab, MTHCA_DB_TYPE_CQ_ARM,
			      cq->arm_db_index);

err_unreg:
	mthca_dereg_mr(cq->mr);

err_buf:
	free(cq->buf);

err:
	free(cq);

	return NULL;
}

int mthca_destroy_cq(struct ibv_cq *cq)
{
	int ret;

	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		return ret;

	if (mthca_is_memfree(cq->context)) {
		mthca_free_db(to_mctx(cq->context)->db_tab, MTHCA_DB_TYPE_CQ_SET_CI,
			      to_mcq(cq)->set_ci_db_index);
		mthca_free_db(to_mctx(cq->context)->db_tab, MTHCA_DB_TYPE_CQ_ARM,
			      to_mcq(cq)->arm_db_index);
	}

	mthca_dereg_mr(to_mcq(cq)->mr);

	free(to_mcq(cq)->buf);
	free(to_mcq(cq));

	return 0;
}

static int align_qp_size(struct ibv_context *context, int size)
{
	int ret;

	if (mthca_is_memfree(context)) {
		for (ret = 1; ret < size; ret <<= 1)
			; /* nothing */

		return ret;
	} else
		return size;
}

struct ibv_qp *mthca_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct mthca_create_qp cmd;
	struct mthca_qp       *qp;
	int                    ret;

	qp = malloc(sizeof *qp);
	if (!qp)
		return NULL;

	qp->qpt = attr->qp_type;

	qp->sq.max    	 = align_qp_size(pd->context, attr->cap.max_send_wr);
	qp->sq.max_gs 	 = attr->cap.max_send_sge;
	qp->sq.next_ind  = 0;
	qp->sq.last_comp = qp->sq.max - 1;
	qp->sq.head    	 = 0;
	qp->sq.tail    	 = 0;
	qp->sq.last      = NULL;

	qp->rq.max    	 = align_qp_size(pd->context, attr->cap.max_recv_wr);
	qp->rq.max_gs 	 = attr->cap.max_recv_sge;
	qp->rq.next_ind	 = 0;
	qp->rq.last_comp = qp->rq.max - 1;
	qp->rq.head    	 = 0;
	qp->rq.tail    	 = 0;
	qp->rq.last      = NULL;

	if (mthca_alloc_qp_buf(pd, qp))
		goto err;

	if (pthread_spin_init(&qp->sq.lock, PTHREAD_PROCESS_PRIVATE) ||
	    pthread_spin_init(&qp->rq.lock, PTHREAD_PROCESS_PRIVATE))
		goto err_free;

	qp->mr = __mthca_reg_mr(pd, qp->buf, qp->buf_size, 0, 0);
	if (!qp->mr)
		goto err_free;

	qp->mr->context = pd->context;

	if (mthca_is_memfree(pd->context)) {
		qp->sq.db_index = mthca_alloc_db(to_mctx(pd->context)->db_tab,
						 MTHCA_DB_TYPE_SQ,
						 &qp->sq.db);
		if (qp->sq.db_index < 0)
			goto err_unreg;

		qp->rq.db_index = mthca_alloc_db(to_mctx(pd->context)->db_tab,
						 MTHCA_DB_TYPE_RQ,
						 &qp->rq.db);
		if (qp->rq.db_index < 0)
			goto err_sq_db;

		cmd.sq_db_page  = db_align(qp->sq.db);
		cmd.rq_db_page  = db_align(qp->rq.db);
		cmd.sq_db_index = qp->sq.db_index;
		cmd.rq_db_index = qp->rq.db_index;
	}

	cmd.lkey = qp->mr->lkey;

	ret = ibv_cmd_create_qp(pd, &qp->ibv_qp, attr, &cmd.ibv_cmd, sizeof cmd);
	if (ret)
		goto err_rq_db;

	if (mthca_is_memfree(pd->context)) {
		mthca_set_db_qn(qp->sq.db, MTHCA_DB_TYPE_SQ, qp->ibv_qp.qp_num);
		mthca_set_db_qn(qp->rq.db, MTHCA_DB_TYPE_RQ, qp->ibv_qp.qp_num);
	}

	ret = mthca_store_qp(to_mctx(pd->context), qp->ibv_qp.qp_num, qp);
	if (ret)
		goto err_destroy;

	return &qp->ibv_qp;

err_destroy:
	ibv_cmd_destroy_qp(&qp->ibv_qp);

err_rq_db:
	if (mthca_is_memfree(pd->context))
		mthca_free_db(to_mctx(pd->context)->db_tab, MTHCA_DB_TYPE_RQ,
			      qp->rq.db_index);

err_sq_db:
	if (mthca_is_memfree(pd->context))
		mthca_free_db(to_mctx(pd->context)->db_tab, MTHCA_DB_TYPE_SQ,
			      qp->sq.db_index);

err_unreg:
	mthca_dereg_mr(qp->mr);

err_free:
	free(qp->wrid);
	free(qp->buf);

err:
	free(qp);

	return NULL;
}

int mthca_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		    enum ibv_qp_attr_mask attr_mask)
{
	struct ibv_modify_qp cmd;

	return ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof cmd);
}

int mthca_destroy_qp(struct ibv_qp *qp)
{
	int ret;

	pthread_spin_lock(&to_mcq(qp->send_cq)->lock);
	if (qp->send_cq != qp->recv_cq)
		pthread_spin_lock(&to_mcq(qp->recv_cq)->lock);
	mthca_clear_qp(to_mctx(qp->context), qp->qp_num);
	if (qp->send_cq != qp->recv_cq)
		pthread_spin_unlock(&to_mcq(qp->recv_cq)->lock);
	pthread_spin_unlock(&to_mcq(qp->send_cq)->lock);

	ret = ibv_cmd_destroy_qp(qp);
	if (ret)
		return ret;

	if (mthca_is_memfree(qp->context)) {
		mthca_free_db(to_mctx(qp->context)->db_tab, MTHCA_DB_TYPE_RQ,
			      to_mqp(qp)->rq.db_index);
		mthca_free_db(to_mctx(qp->context)->db_tab, MTHCA_DB_TYPE_SQ,
			      to_mqp(qp)->sq.db_index);
	}

	mthca_dereg_mr(to_mqp(qp)->mr);

	free(to_mqp(qp)->buf);
	free(to_mqp(qp)->wrid);

	return 0;
}

struct ibv_ah *mthca_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	struct mthca_ah *ah;

	ah = malloc(sizeof *ah);
	if (!ah)
		return NULL;

	if (mthca_alloc_av(to_mpd(pd), attr, ah)) {
		free(ah);
		return NULL;
	}

	return &ah->ibv_ah;
}

int mthca_destroy_ah(struct ibv_ah *ah)
{
	mthca_free_av(to_mah(ah));

	free(ah);
	return 0;
}
