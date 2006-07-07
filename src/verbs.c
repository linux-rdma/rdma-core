/*
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
 * Patent licenses, if any, provided herein do not apply to
 * combinations of this program with other software, or any other
 * product whatsoever.
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>

#include "ipathverbs.h"

int ipath_query_device(struct ibv_context *context,
		       struct ibv_device_attr *attr)
{
	struct ibv_query_device cmd;
	uint64_t raw_fw_ver;
	unsigned major, minor, sub_minor;
	int ret;

	ret = ibv_cmd_query_device(context, attr, &raw_fw_ver, &cmd, sizeof cmd);
	if (ret)
		return ret;

	major     = (raw_fw_ver >> 32) & 0xffff;
	minor     = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(attr->fw_ver, sizeof attr->fw_ver,
		 "%d.%d.%d", major, minor, sub_minor);

	return 0;
}

int ipath_query_port(struct ibv_context *context, uint8_t port,
		     struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof cmd);
}

struct ibv_pd *ipath_alloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd	  cmd;
	struct ibv_alloc_pd_resp  resp;
	struct ibv_pd		 *pd;

	pd = malloc(sizeof *pd);
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, pd, &cmd, sizeof cmd,
			     &resp, sizeof resp)) {
		free(pd);
		return NULL;
	}

	return pd;
}

int ipath_free_pd(struct ibv_pd *pd)
{
	int ret;

	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	free(pd);
	return 0;
}

struct ibv_mr *ipath_reg_mr(struct ibv_pd *pd, void *addr,
			    size_t length, enum ibv_access_flags access)
{
	struct ibv_mr *mr;
	struct ibv_reg_mr cmd;

	mr = malloc(sizeof *mr);
	if (!mr)
		return NULL;

	if (ibv_cmd_reg_mr(pd, addr, length, (uintptr_t)addr,
			   access, mr, &cmd, sizeof cmd)) {
		free(mr);
		return NULL;
	}

	return mr;
}

int ipath_dereg_mr(struct ibv_mr *mr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(mr);
	if (ret)
		return ret;

	free(mr);
	return 0;
}

struct ibv_cq *ipath_create_cq(struct ibv_context *context, int cqe,
			       struct ibv_comp_channel *channel,
			       int comp_vector)
{
	struct ibv_cq		 *cq;
	struct ibv_create_cq	  cmd;
	struct ibv_create_cq_resp resp;
	int			  ret;

	cq = malloc(sizeof *cq);
	if (!cq)
		return NULL;

	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector, cq,
				&cmd, sizeof cmd, &resp, sizeof resp);
	if (ret) {
		free(cq);
		return NULL;
	}

	return cq;
}

int ipath_destroy_cq(struct ibv_cq *cq)
{
	int ret;

	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		return ret;

	free(cq);
	return 0;
}

struct ibv_qp *ipath_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct ibv_create_qp	  cmd;
	struct ibv_create_qp_resp resp;
	struct ibv_qp		 *qp;
	int			  ret;

	qp = malloc(sizeof *qp);
	if (!qp)
		return NULL;

	ret = ibv_cmd_create_qp(pd, qp, attr, &cmd, sizeof cmd, &resp, sizeof resp);
	if (ret) {
		free(qp);
		return NULL;
	}

	return qp;
}

int ipath_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		   enum ibv_qp_attr_mask attr_mask,
		   struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr,
				&cmd, sizeof cmd);
}

int ipath_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		    enum ibv_qp_attr_mask attr_mask)
{
	struct ibv_modify_qp cmd;

	return ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof cmd);
}

int ipath_destroy_qp(struct ibv_qp *qp)
{
	int ret;

	ret = ibv_cmd_destroy_qp(qp);
	if (ret)
		return ret;

	free(qp);
	return 0;
}

struct ibv_srq *ipath_create_srq(struct ibv_pd *pd,
				 struct ibv_srq_init_attr *attr)
{
	struct ibv_srq *srq;
	struct ibv_create_srq cmd;
	struct ibv_create_srq_resp resp;
	int ret;

	srq = malloc(sizeof *srq);
	if (srq == NULL)
		return NULL;

	ret = ibv_cmd_create_srq(pd, srq, attr, &cmd, sizeof cmd,
		&resp, sizeof resp);
	if (ret) {
		free(srq);
		return NULL;
	}

	return srq;
}

int ipath_modify_srq(struct ibv_srq *srq,
		     struct ibv_srq_attr *attr, 
		     enum ibv_srq_attr_mask attr_mask)
{
	struct ibv_modify_srq cmd;

	return ibv_cmd_modify_srq(srq, attr, attr_mask, &cmd, sizeof cmd);
}

int ipath_query_srq(struct ibv_srq *srq, struct ibv_srq_attr *attr)
{
	struct ibv_query_srq cmd;

	return ibv_cmd_query_srq(srq, attr, &cmd, sizeof cmd);
}

int ipath_destroy_srq(struct ibv_srq *srq)
{
	int ret;

	ret = ibv_cmd_destroy_srq(srq);
	if (ret)
		return ret;

	free(srq);
	return 0;
}

struct ibv_ah *ipath_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	struct ibv_ah *ah;

	ah = malloc(sizeof *ah);
	if (ah == NULL)
		return NULL;

	if (ibv_cmd_create_ah(pd, ah, attr)) {
		free(ah);
		return NULL;
	}

	return ah;
}

int ipath_destroy_ah(struct ibv_ah *ah)
{
	int ret;

	ret = ibv_cmd_destroy_ah(ah);
	if (ret)
		return ret;

	free(ah);
	return 0;
}
