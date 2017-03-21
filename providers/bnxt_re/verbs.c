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
	cntx->udpi.dbpage = mmap(NULL, 4096, PROT_WRITE, MAP_SHARED,
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
	int status;

	status = ibv_cmd_dealloc_pd(ibvpd);
	if (status)
		return status;

	pthread_spin_destroy(&cntx->udpi.db_lock);
	if (cntx->udpi.dbpage && (cntx->udpi.dbpage != MAP_FAILED))
		munmap(cntx->udpi.dbpage, 4096);
	free(pd);

	return 0;
}

struct ibv_mr *bnxt_re_reg_mr(struct ibv_pd *ibvpd, void *sva, size_t len,
			      int access)
{
	return NULL;
}

int bnxt_re_dereg_mr(struct ibv_mr *ibvmr)
{
	return -ENOSYS;
}

struct ibv_cq *bnxt_re_create_cq(struct ibv_context *ibvctx, int ncqe,
				 struct ibv_comp_channel *channel, int vec)
{
	return NULL;
}

int bnxt_re_resize_cq(struct ibv_cq *ibvcq, int ncqe)
{
	return -ENOSYS;
}

int bnxt_re_destroy_cq(struct ibv_cq *ibvcq)
{
	return -ENOSYS;
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

struct ibv_qp *bnxt_re_create_qp(struct ibv_pd *ibvpd,
				 struct ibv_qp_init_attr *attr)
{
	return NULL;
}

int bnxt_re_modify_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr,
		      int attr_mask)
{
	return -ENOSYS;
}

int bnxt_re_query_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr,
		     int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	return -ENOSYS;
}

int bnxt_re_destroy_qp(struct ibv_qp *ibvqp)
{
	return -ENOSYS;
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
