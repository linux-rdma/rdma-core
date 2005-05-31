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

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "ibverbs.h"

int ibv_query_port(struct ibv_context *context, uint8_t port_num,
		   struct ibv_port_attr *port_attr)
{
	return context->ops.query_port(context, port_num, port_attr);
}

int ibv_query_gid(struct ibv_context *context, uint8_t port_num,
		  int index, union ibv_gid *gid)
{
	return context->ops.query_gid(context, port_num, index, gid);
}

int ibv_query_pkey(struct ibv_context *context, uint8_t port_num,
		   int index, uint16_t *pkey)
{
	return context->ops.query_pkey(context, port_num, index, pkey);
}

struct ibv_pd *ibv_alloc_pd(struct ibv_context *context)
{
	struct ibv_pd *pd;

	pd = context->ops.alloc_pd(context);
	if (pd)
		pd->context = context;

	return pd;
}

int ibv_dealloc_pd(struct ibv_pd *pd)
{
	return pd->context->ops.dealloc_pd(pd);
}

struct ibv_mr *ibv_reg_mr(struct ibv_pd *pd, void *addr,
			  size_t length, enum ibv_access_flags access)
{
	struct ibv_mr *mr;

	mr = pd->context->ops.reg_mr(pd, addr, length, access);
	if (mr) {
		mr->context = pd->context;
		mr->pd      = pd;
	}

	return mr;
}

int ibv_dereg_mr(struct ibv_mr *mr)
{
	return mr->context->ops.dereg_mr(mr);
}

struct ibv_cq *ibv_create_cq(struct ibv_context *context, int cqe,
			     void *cq_context)
{
	struct ibv_cq *cq = context->ops.create_cq(context, cqe);

	if (cq) {
		cq->context    = context;
		cq->cq_context = cq_context;
	}

	return cq;
}

int ibv_destroy_cq(struct ibv_cq *cq)
{
	return cq->context->ops.destroy_cq(cq);
}


int ibv_get_cq_event(struct ibv_context *context, int comp_num,
		     struct ibv_cq **cq, void **cq_context)
{
	struct ibv_comp_event ev;

	if (comp_num < 0 || comp_num >= context->num_comp)
		return -1;

	if (read(context->cq_fd[comp_num], &ev, sizeof ev) != sizeof ev)
		return -1;

	*cq         = (struct ibv_cq *) (uintptr_t) ev.cq_handle;
	*cq_context = (*cq)->cq_context;

	if ((*cq)->context->ops.cq_event)
		(*cq)->context->ops.cq_event(*cq);

	return 0;
}

struct ibv_qp *ibv_create_qp(struct ibv_pd *pd,
			     struct ibv_qp_init_attr *qp_init_attr)
{
	struct ibv_qp *qp = pd->context->ops.create_qp(pd, qp_init_attr);

	if (qp) {
		qp->context    = pd->context;
		qp->qp_context = qp_init_attr->qp_context;
		qp->pd         = pd;
		qp->send_cq    = qp_init_attr->send_cq;
		qp->recv_cq    = qp_init_attr->recv_cq;
	}

	return qp;
}
int ibv_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		  enum ibv_qp_attr_mask attr_mask)
{
	int ret;

	ret = qp->context->ops.modify_qp(qp, attr, attr_mask);
	if (ret)
		return ret;

	if (attr_mask & IBV_QP_STATE)
		qp->state = attr->qp_state;

	return 0;
}

int ibv_destroy_qp(struct ibv_qp *qp)
{
	return qp->context->ops.destroy_qp(qp);
}

struct ibv_ah *ibv_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	struct ibv_ah *ah = pd->context->ops.create_ah(pd, attr);

	if (ah) {
		ah->context = pd->context;
		ah->pd      = pd;
	}

	return ah;
}

int ibv_destroy_ah(struct ibv_ah *ah)
{
	return ah->context->ops.destroy_ah(ah);
}

int ibv_attach_mcast(struct ibv_qp *qp, union ibv_gid *gid, uint16_t lid)
{
	return qp->context->ops.attach_mcast(qp, gid, lid);
}

int ibv_detach_mcast(struct ibv_qp *qp, union ibv_gid *gid, uint16_t lid)
{
	return qp->context->ops.detach_mcast(qp, gid, lid);
}
