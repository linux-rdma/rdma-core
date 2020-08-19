/*
 * Copyright (c) 2020 Mellanox Technologies, Ltd.  All rights reserved.
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

#include <infiniband/cmd_write.h>
#include "ibverbs.h"

static void set_vsrq(struct verbs_srq *vsrq,
		     struct ibv_srq_init_attr_ex *attr_ex,
		     uint32_t srq_num)
{
	vsrq->srq_type = (attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_TYPE) ?
		attr_ex->srq_type : IBV_SRQT_BASIC;
	if (vsrq->srq_type == IBV_SRQT_XRC) {
		vsrq->srq_num = srq_num;
		vsrq->xrcd = container_of(attr_ex->xrcd, struct verbs_xrcd, xrcd);
	}
	if (attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_CQ)
		vsrq->cq = attr_ex->cq;
}

static int ibv_icmd_create_srq(struct ibv_pd *pd, struct verbs_srq *vsrq,
			       struct ibv_srq *srq_in,
			       struct ibv_srq_init_attr_ex *attr_ex,
			       struct ibv_command_buffer *link)
{
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_SRQ, UVERBS_METHOD_SRQ_CREATE, 13, link);
	struct verbs_ex_private *priv = get_priv(pd->context);
	struct ib_uverbs_attr *handle;
	uint32_t max_wr;
	uint32_t max_sge;
	uint32_t srq_num;
	int ret;
	struct ibv_srq *srq = vsrq ? &vsrq->srq : srq_in;
	struct verbs_xrcd *vxrcd = NULL;
	enum ibv_srq_type srq_type;

	srq->context = pd->context;
	pthread_mutex_init(&srq->mutex, NULL);
	pthread_cond_init(&srq->cond, NULL);

	srq_type = (attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_TYPE) ?
			attr_ex->srq_type : IBV_SRQT_BASIC;
	switch (srq_type) {
	case IBV_SRQT_XRC:
		if (!(attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_XRCD) ||
		    !(attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_CQ)) {
			errno = EINVAL;
			return errno;
		}

		vxrcd = container_of(attr_ex->xrcd, struct verbs_xrcd, xrcd);
		fill_attr_in_obj(cmdb, UVERBS_ATTR_CREATE_SRQ_XRCD_HANDLE, vxrcd->handle);
		fill_attr_in_obj(cmdb, UVERBS_ATTR_CREATE_SRQ_CQ_HANDLE, attr_ex->cq->handle);
		fill_attr_out_ptr(cmdb, UVERBS_ATTR_CREATE_SRQ_RESP_SRQ_NUM, &srq_num);
		break;
	case IBV_SRQT_TM:
		if (!(attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_CQ) ||
		    !(attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_TM) ||
		    !(attr_ex->tm_cap.max_num_tags)) {
			errno = EINVAL;
			return errno;
		}

		fill_attr_in_obj(cmdb, UVERBS_ATTR_CREATE_SRQ_CQ_HANDLE, attr_ex->cq->handle);
		fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_SRQ_MAX_NUM_TAGS, attr_ex->tm_cap.max_num_tags);
		break;
	default:
		break;
	}

	handle = fill_attr_out_obj(cmdb, UVERBS_ATTR_CREATE_SRQ_HANDLE);
	fill_attr_const_in(cmdb, UVERBS_ATTR_CREATE_SRQ_TYPE, srq_type);
	fill_attr_in_uint64(cmdb, UVERBS_ATTR_CREATE_SRQ_USER_HANDLE, (uintptr_t)srq);
	fill_attr_in_obj(cmdb, UVERBS_ATTR_CREATE_SRQ_PD_HANDLE, pd->handle);
	fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_SRQ_MAX_WR, attr_ex->attr.max_wr);
	fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_SRQ_MAX_SGE, attr_ex->attr.max_sge);
	fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_SRQ_LIMIT, attr_ex->attr.srq_limit);
	fill_attr_in_fd(cmdb, UVERBS_ATTR_CREATE_SRQ_EVENT_FD, pd->context->async_fd);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_CREATE_SRQ_RESP_MAX_WR, &max_wr);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_CREATE_SRQ_RESP_MAX_SGE, &max_sge);

	if (priv->imported)
		fallback_require_ioctl(cmdb);

	switch (execute_ioctl_fallback(srq->context, create_srq, cmdb, &ret)) {
	case TRY_WRITE: {
		if (attr_ex->srq_type == IBV_SRQT_BASIC && abi_ver > 5) {
			DECLARE_LEGACY_UHW_BUFS(link, IB_USER_VERBS_CMD_CREATE_SRQ);

			*req = (struct ib_uverbs_create_srq){
				.pd_handle = pd->handle,
				.user_handle = (uintptr_t)srq,
				.max_wr = attr_ex->attr.max_wr,
				.max_sge = attr_ex->attr.max_sge,
				.srq_limit = attr_ex->attr.srq_limit,
			};

			ret = execute_write_bufs(
				srq->context, IB_USER_VERBS_CMD_CREATE_SRQ, req, resp);
			if (ret)
				return ret;

			srq->handle = resp->srq_handle;
			attr_ex->attr.max_wr = resp->max_wr;
			attr_ex->attr.max_sge = resp->max_sge;
		} else if (attr_ex->srq_type == IBV_SRQT_BASIC && abi_ver <= 5) {
			DECLARE_LEGACY_UHW_BUFS(link, IB_USER_VERBS_CMD_CREATE_SRQ_V5);

			*req = (struct ib_uverbs_create_srq){
				.pd_handle = pd->handle,
				.user_handle = (uintptr_t)srq,
				.max_wr = attr_ex->attr.max_wr,
				.max_sge = attr_ex->attr.max_sge,
				.srq_limit = attr_ex->attr.srq_limit,
			};

			ret = execute_write_bufs(
				srq->context, IB_USER_VERBS_CMD_CREATE_SRQ_V5, req, resp);
			if (ret)
				return ret;

			srq->handle = resp->srq_handle;
		} else {
			DECLARE_LEGACY_UHW_BUFS(link, IB_USER_VERBS_CMD_CREATE_XSRQ);

			*req = (struct ib_uverbs_create_xsrq){
				.pd_handle = pd->handle,
				.user_handle = (uintptr_t)srq,
				.max_wr = attr_ex->attr.max_wr,
				.max_sge =  attr_ex->attr.max_sge,
				.srq_limit = attr_ex->attr.srq_limit,
				.srq_type = attr_ex->srq_type,
				.cq_handle = attr_ex->cq->handle,
			};

			if (attr_ex->srq_type == IBV_SRQT_TM)
				req->max_num_tags = attr_ex->tm_cap.max_num_tags;
			else
				req->xrcd_handle = vxrcd->handle;

			ret = execute_write_bufs(
				srq->context, IB_USER_VERBS_CMD_CREATE_XSRQ, req, resp);
			if (ret)
				return ret;

			srq->handle = resp->srq_handle;
			attr_ex->attr.max_wr = resp->max_wr;
			attr_ex->attr.max_sge = resp->max_sge;
			set_vsrq(vsrq, attr_ex, resp->srqn);
		}

		return 0;
	}

	case SUCCESS:
		break;

	default:
		return ret;
	}

	srq->handle = read_attr_obj(UVERBS_ATTR_CREATE_SRQ_HANDLE, handle);
	attr_ex->attr.max_wr = max_wr;
	attr_ex->attr.max_sge = max_sge;
	if (vsrq)
		set_vsrq(vsrq, attr_ex, srq_num);

	return 0;
}

int ibv_cmd_create_srq(struct ibv_pd *pd, struct ibv_srq *srq,
		       struct ibv_srq_init_attr *attr,
		       struct ibv_create_srq *cmd, size_t cmd_size,
		       struct ib_uverbs_create_srq_resp *resp, size_t resp_size)
{
	DECLARE_CMD_BUFFER_COMPAT(cmdb, UVERBS_OBJECT_SRQ,
				  UVERBS_METHOD_SRQ_CREATE, cmd, cmd_size, resp,
				  resp_size);

	struct ibv_srq_init_attr_ex attr_ex = {};
	int ret;

	memcpy(&attr_ex, attr, sizeof(*attr));
	ret = ibv_icmd_create_srq(pd, NULL, srq, &attr_ex, cmdb);
	if (!ret) {
		attr->attr.max_wr = attr_ex.attr.max_wr;
		attr->attr.max_sge = attr_ex.attr.max_sge;
	}

	return ret;
}

int ibv_cmd_create_srq_ex(struct ibv_context *context,
			  struct verbs_srq *srq,
			  struct ibv_srq_init_attr_ex *attr_ex,
			  struct ibv_create_xsrq *cmd, size_t cmd_size,
			  struct ib_uverbs_create_srq_resp *resp, size_t resp_size)
{
	DECLARE_CMD_BUFFER_COMPAT(cmdb, UVERBS_OBJECT_SRQ,
				  UVERBS_METHOD_SRQ_CREATE, cmd, cmd_size, resp,
				  resp_size);

	if (attr_ex->comp_mask >= IBV_SRQ_INIT_ATTR_RESERVED) {
		errno = EOPNOTSUPP;
		return errno;
	}

	if (!(attr_ex->comp_mask & IBV_SRQ_INIT_ATTR_PD)) {
		errno = EINVAL;
		return errno;
	}

	return ibv_icmd_create_srq(attr_ex->pd, srq, NULL, attr_ex, cmdb);
}

int ibv_cmd_destroy_srq(struct ibv_srq *srq)
{
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_SRQ, UVERBS_METHOD_SRQ_DESTROY, 2,
			     NULL);
	struct ib_uverbs_destroy_srq_resp resp;
	int ret;

	fill_attr_out_ptr(cmdb, UVERBS_ATTR_DESTROY_SRQ_RESP, &resp);
	fill_attr_in_obj(cmdb, UVERBS_ATTR_DESTROY_SRQ_HANDLE, srq->handle);

	switch (execute_ioctl_fallback(srq->context, destroy_srq, cmdb, &ret)) {
	case TRY_WRITE: {
		struct ibv_destroy_srq req;

		req.core_payload = (struct ib_uverbs_destroy_srq){
			.srq_handle = srq->handle,
		};

		ret = execute_cmd_write(srq->context,
					IB_USER_VERBS_CMD_DESTROY_SRQ, &req,
					sizeof(req), &resp, sizeof(resp));
		break;
	}

	default:
		break;
	}

	if (verbs_is_destroy_err(&ret))
		return ret;

	pthread_mutex_lock(&srq->mutex);
	while (srq->events_completed != resp.events_reported)
		pthread_cond_wait(&srq->cond, &srq->mutex);
	pthread_mutex_unlock(&srq->mutex);

	return 0;
}

