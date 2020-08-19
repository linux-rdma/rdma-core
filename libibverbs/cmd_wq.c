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

static int ibv_icmd_create_wq(struct ibv_context *context,
			      struct ibv_wq_init_attr *wq_init_attr,
			      struct ibv_wq *wq,
			      struct ibv_command_buffer *link)
{
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_WQ, UVERBS_METHOD_WQ_CREATE, 13, link);
	struct verbs_ex_private *priv = get_priv(context);
	struct ib_uverbs_attr *handle;
	uint32_t create_flags = 0;
	uint32_t max_wr;
	uint32_t max_sge;
	uint32_t wq_num;
	int ret;

	wq->context = context;
	wq->cq = wq_init_attr->cq;
	wq->pd = wq_init_attr->pd;
	wq->wq_type = wq_init_attr->wq_type;

	handle = fill_attr_out_obj(cmdb, UVERBS_ATTR_CREATE_WQ_HANDLE);
	fill_attr_in_uint64(cmdb, UVERBS_ATTR_CREATE_WQ_USER_HANDLE, (uintptr_t)wq);
	fill_attr_in_obj(cmdb, UVERBS_ATTR_CREATE_WQ_PD_HANDLE, wq_init_attr->pd->handle);
	fill_attr_in_obj(cmdb, UVERBS_ATTR_CREATE_WQ_CQ_HANDLE, wq_init_attr->cq->handle);
	fill_attr_const_in(cmdb, UVERBS_ATTR_CREATE_WQ_TYPE, wq_init_attr->wq_type);
	fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_WQ_MAX_WR, wq_init_attr->max_wr);
	fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_WQ_MAX_SGE, wq_init_attr->max_sge);
	fill_attr_in_fd(cmdb, UVERBS_ATTR_CREATE_WQ_EVENT_FD, wq->context->async_fd);
	if (wq_init_attr->comp_mask & IBV_WQ_INIT_ATTR_FLAGS) {
		if (wq_init_attr->create_flags & ~(IBV_WQ_FLAGS_RESERVED - 1)) {
			errno = EOPNOTSUPP;
			return errno;
		}
		create_flags = wq_init_attr->create_flags;
	}
	fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_WQ_FLAGS, create_flags);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_CREATE_WQ_RESP_MAX_WR, &max_wr);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_CREATE_WQ_RESP_MAX_SGE, &max_sge);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_CREATE_WQ_RESP_WQ_NUM, &wq_num);

	if (priv->imported)
		fallback_require_ioctl(cmdb);
	fallback_require_ex(cmdb);

	switch (execute_ioctl_fallback(context, create_wq, cmdb, &ret)) {
	case TRY_WRITE_EX: {
		DECLARE_LEGACY_UHW_BUFS_EX(link,
					   IB_USER_VERBS_EX_CMD_CREATE_WQ);

		*req = (struct ib_uverbs_ex_create_wq){
			.user_handle = (uintptr_t)wq,
			.pd_handle = wq_init_attr->pd->handle,
			.cq_handle = wq_init_attr->cq->handle,
			.max_wr = wq_init_attr->max_wr,
			.max_sge = wq_init_attr->max_sge,
			.wq_type = wq_init_attr->wq_type,
			.create_flags = wq_init_attr->create_flags,
		};

		ret = execute_write_bufs_ex(
			context, IB_USER_VERBS_EX_CMD_CREATE_WQ, req, resp);
		if (ret)
			return ret;

		wq->handle  = resp->wq_handle;
		wq_init_attr->max_wr = resp->max_wr;
		wq_init_attr->max_sge = resp->max_sge;
		wq->wq_num = resp->wqn;
		return 0;
	}

	case SUCCESS:
		break;

	default:
		return ret;
	}

	wq->handle = read_attr_obj(UVERBS_ATTR_CREATE_WQ_HANDLE, handle);
	wq->wq_num = wq_num;
	wq_init_attr->max_wr = max_wr;
	wq_init_attr->max_sge = max_sge;

	return 0;
}

int ibv_cmd_create_wq(struct ibv_context *context,
		      struct ibv_wq_init_attr *wq_init_attr,
		      struct ibv_wq *wq,
		      struct ibv_create_wq *cmd,
		      size_t cmd_size,
		      struct ib_uverbs_ex_create_wq_resp *resp,
		      size_t resp_size)
{
	DECLARE_CMD_BUFFER_COMPAT(cmdb, UVERBS_OBJECT_WQ,
				  UVERBS_METHOD_WQ_CREATE, cmd, cmd_size, resp,
				  resp_size);

	if (wq_init_attr->comp_mask >= IBV_WQ_INIT_ATTR_RESERVED) {
		errno = EINVAL;
		return errno;
	}

	return ibv_icmd_create_wq(context, wq_init_attr, wq, cmdb);
}

int ibv_cmd_destroy_wq(struct ibv_wq *wq)
{
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_WQ, UVERBS_METHOD_WQ_DESTROY, 2,
			     NULL);
	struct ib_uverbs_ex_destroy_wq_resp resp;
	int ret;

	fill_attr_out_ptr(cmdb, UVERBS_ATTR_DESTROY_WQ_RESP, &resp.events_reported);
	fill_attr_in_obj(cmdb, UVERBS_ATTR_DESTROY_WQ_HANDLE, wq->handle);

	switch (execute_ioctl_fallback(wq->context, destroy_wq, cmdb, &ret)) {
	case TRY_WRITE: {
		struct ibv_destroy_wq req;

		req.core_payload = (struct ib_uverbs_ex_destroy_wq){
			.wq_handle = wq->handle,
		};


		ret = execute_cmd_write_ex(wq->context, IB_USER_VERBS_EX_CMD_DESTROY_WQ,
				   &req, sizeof(req), &resp, sizeof(resp));
		break;
	}

	default:
		break;
	}

	if (verbs_is_destroy_err(&ret))
		return ret;

	pthread_mutex_lock(&wq->mutex);
	while (wq->events_completed != resp.events_reported)
		pthread_cond_wait(&wq->cond, &wq->mutex);
	pthread_mutex_unlock(&wq->mutex);

	return 0;
}
