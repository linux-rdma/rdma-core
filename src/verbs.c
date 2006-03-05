/*
 * Copyright (c) 2006 Chelsio, Inc. All rights reserved.
 * Copyright (c) 2006 Open Grid Computing, Inc. All rights reserved.
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
#if HAVE_CONFIG_H
#  include <config.h>
#endif				/* HAVE_CONFIG_H */

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <netinet/in.h>

#include "iwch.h"
#include "iwch-abi.h"


int iwch_query_device(struct ibv_context *context, struct ibv_device_attr *attr)
{
	struct ibv_query_device cmd;
	uint64_t raw_fw_ver;
	unsigned major, minor, sub_minor;
	int ret;

	ret =
	    ibv_cmd_query_device(context, attr, &raw_fw_ver, &cmd, sizeof cmd);
	fprintf(stderr, "ibv_cmd_query_device ret = 0x%x\n", ret);
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
	struct iwch_alloc_pd_resp resp;
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
				    enum ibv_access_flags access)
{
	struct ibv_mr *mr;
	struct ibv_reg_mr cmd;

	mr = malloc(sizeof *mr);
	if (!mr)
		return NULL;

	if (ibv_cmd_reg_mr(pd, addr, length, hca_va,
			   access, mr, &cmd, sizeof cmd)) {
		fprintf(stderr, "ibv_cmd_reg_mr failed\n");
		free(mr);
		return NULL;
	}

	return mr;
}

struct ibv_mr *iwch_reg_mr(struct ibv_pd *pd, void *addr,
			   size_t length, enum ibv_access_flags access)
{
	return __iwch_reg_mr(pd, addr, length, (uintptr_t) addr, access);
}

int iwch_dereg_mr(struct ibv_mr *mr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(mr);
	if (ret)
		return ret;

	free(mr);
	return 0;
}

struct ibv_cq *iwch_create_cq(struct ibv_context *context, int cqe,
			      struct ibv_comp_channel *channel, int comp_vector)
{
	struct iwch_create_cq cmd;
	struct iwch_create_cq_resp resp;
	struct iwch_cq *cq;
	int ret;

	fprintf(stderr, "iwch_create_cq called\n");

	cq = malloc(sizeof *cq);
	if (!cq) {
		goto err;
	}

	fprintf(stderr, "Calling ibv_cmd_create_cq\n");
	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				&cq->ibv_cq, &cmd.ibv_cmd, sizeof cmd,
				&resp.ibv_resp, sizeof resp);
	if (ret)
		goto err;

#if 0 /* A reminder for bypass functionality */
	cq->physaddr = resp.physaddr;
	cq->queue =
	    (unsigned long) mmap(NULL, cqe * sizeof(struct t3_cqe), PROT_WRITE,
				 MAP_SHARED, context->cmd_fd, cq->physaddr);
#endif

	return &cq->ibv_cq;


err:
	free(cq);

	return NULL;
}

int iwch_resize_cq(struct ibv_cq *cq, int cqe)
{
	int ret;
	struct ibv_resize_cq cmd;

	ret = ibv_cmd_resize_cq(cq, cqe, &cmd, sizeof cmd);
	if (ret)
		return ret;
	/* We will need to unmap and remap when we implement user mode */

	return 0;
}

int iwch_destroy_cq(struct ibv_cq *cq)
{
	int ret;

	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		return ret;

	return 0;
}

struct ibv_srq *iwch_create_srq(struct ibv_pd *pd,
				struct ibv_srq_init_attr *attr)
{
	return (void *) -ENOSYS;
}

int iwch_modify_srq(struct ibv_srq *srq,
		    struct ibv_srq_attr *attr, enum ibv_srq_attr_mask attr_mask)
{
	return -ENOSYS;
}

int iwch_destroy_srq(struct ibv_srq *srq)
{
	return -ENOSYS;
}

int iwch_post_srq_recv(struct ibv_srq *ibsrq,
                       struct ibv_recv_wr *wr, struct ibv_recv_wr **bad_wr)
{
	return -ENOSYS;
}

struct ibv_qp *iwch_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct iwch_create_qp cmd;
	struct iwch_create_qp_resp resp;
	struct iwch_qp *qp;
	int ret;

	/* Sanity check QP size before proceeding */
	if (attr->cap.max_send_wr > 65536 ||
	    attr->cap.max_recv_wr > 65536 ||
	    attr->cap.max_send_sge > 4 ||
	    attr->cap.max_recv_sge > 4 || attr->cap.max_inline_data > 1024)
		return NULL;

	qp = malloc(sizeof *qp);
	if (!qp)
		return NULL;

	ret = ibv_cmd_create_qp(pd, &qp->ibv_qp, attr, &cmd.ibv_cmd, sizeof cmd,
				&resp.ibv_resp, sizeof resp);
	if (ret)
		return NULL;

#if 0 /* A reminder for bypass functionality */
	qp->physaddr = resp.physaddr;
#endif

	return &qp->ibv_qp;


	return NULL;
}

int iwch_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		   enum ibv_qp_attr_mask attr_mask)
{
	struct ibv_modify_qp cmd;

	return ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof cmd);
}

int iwch_destroy_qp(struct ibv_qp *qp)
{
	int ret;

	ret = ibv_cmd_destroy_qp(qp);
	if (ret)
		return ret;

	free(qp);

	return 0;
}

struct ibv_ah *iwch_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	return (void *) -ENOSYS;
}

int iwch_destroy_ah(struct ibv_ah *ah)
{
	return -ENOSYS;
}

int iwch_attach_mcast(struct ibv_qp *qp, union ibv_gid *gid, uint16_t lid)
{
	return -ENOSYS;
}

int iwch_detach_mcast(struct ibv_qp *qp, union ibv_gid *gid, uint16_t lid)
{
	return -ENOSYS;
}

