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

enum {
	CREATE_QP_EX_SUP_CREATE_FLAGS = IBV_QP_CREATE_BLOCK_SELF_MCAST_LB |
					IBV_QP_CREATE_SCATTER_FCS |
					IBV_QP_CREATE_CVLAN_STRIPPING |
					IBV_QP_CREATE_SOURCE_QPN |
					IBV_QP_CREATE_PCI_WRITE_END_PADDING
};


static void set_qp(struct verbs_qp *vqp,
		   struct ibv_qp *qp_in,
		   struct ibv_qp_init_attr_ex *attr_ex,
		   struct verbs_xrcd *vxrcd)
{
	struct ibv_qp *qp = vqp ? &vqp->qp : qp_in;

	qp->qp_context = attr_ex->qp_context;
	qp->pd = attr_ex->pd;
	qp->send_cq = attr_ex->send_cq;
	qp->recv_cq = attr_ex->recv_cq;
	qp->srq = attr_ex->srq;
	qp->qp_type		= attr_ex->qp_type;
	qp->state		= IBV_QPS_RESET;
	qp->events_completed = 0;
	pthread_mutex_init(&qp->mutex, NULL);
	pthread_cond_init(&qp->cond, NULL);

	if (vqp) {
		vqp->comp_mask = 0;
		if (attr_ex->comp_mask & IBV_QP_INIT_ATTR_XRCD) {
			vqp->comp_mask |= VERBS_QP_XRCD;
			vqp->xrcd = vxrcd;
		}
	}
}

static int ibv_icmd_create_qp(struct ibv_context *context,
			      struct verbs_qp *vqp,
			      struct ibv_qp *qp_in,
			      struct ibv_qp_init_attr_ex *attr_ex,
			      struct ibv_command_buffer *link)
{
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_QP, UVERBS_METHOD_QP_CREATE, 15, link);
	struct verbs_ex_private *priv = get_priv(context);
	struct ib_uverbs_attr *handle;
	uint32_t qp_num;
	uint32_t pd_handle;
	uint32_t send_cq_handle = 0;
	uint32_t recv_cq_handle = 0;
	int ret;
	struct ibv_qp *qp = vqp ? &vqp->qp : qp_in;
	struct verbs_xrcd *vxrcd = NULL;
	uint32_t create_flags = 0;

	qp->context = context;

	switch (attr_ex->qp_type) {
	case IBV_QPT_XRC_RECV:
		if (!(attr_ex->comp_mask & IBV_QP_INIT_ATTR_XRCD)) {
			errno = EINVAL;
			return errno;
		}

		vxrcd = container_of(attr_ex->xrcd, struct verbs_xrcd, xrcd);
		fill_attr_in_obj(cmdb, UVERBS_ATTR_CREATE_QP_XRCD_HANDLE, vxrcd->handle);
		pd_handle = vxrcd->handle;
		break;
	case IBV_QPT_RC:
	case IBV_QPT_UD:
	case IBV_QPT_UC:
	case IBV_QPT_RAW_PACKET:
	case IBV_QPT_XRC_SEND:
	case IBV_QPT_DRIVER:
		if (!(attr_ex->comp_mask & IBV_QP_INIT_ATTR_PD)) {
			errno = EINVAL;
			return errno;
		}

		fill_attr_in_obj(cmdb, UVERBS_ATTR_CREATE_QP_PD_HANDLE, attr_ex->pd->handle);
		pd_handle = attr_ex->pd->handle;

		if (attr_ex->comp_mask & IBV_QP_INIT_ATTR_IND_TABLE) {
			if (attr_ex->cap.max_recv_wr || attr_ex->cap.max_recv_sge ||
				attr_ex->recv_cq || attr_ex->srq) {
				errno = EINVAL;
				return errno;
			}

			fallback_require_ex(cmdb);
			fill_attr_in_obj(cmdb, UVERBS_ATTR_CREATE_QP_IND_TABLE_HANDLE,
				 attr_ex->rwq_ind_tbl->ind_tbl_handle);

			/* send_cq is optional */
			if (attr_ex->cap.max_send_wr) {
				fill_attr_in_obj(cmdb, UVERBS_ATTR_CREATE_QP_SEND_CQ_HANDLE,
						 attr_ex->send_cq->handle);
				send_cq_handle = attr_ex->send_cq->handle;
			}
		} else {
			fill_attr_in_obj(cmdb, UVERBS_ATTR_CREATE_QP_SEND_CQ_HANDLE,
				 attr_ex->send_cq->handle);
			send_cq_handle = attr_ex->send_cq->handle;

			if (attr_ex->qp_type != IBV_QPT_XRC_SEND) {
				fill_attr_in_obj(cmdb, UVERBS_ATTR_CREATE_QP_RECV_CQ_HANDLE,
						 attr_ex->recv_cq->handle);
				recv_cq_handle = attr_ex->recv_cq->handle;
			}
		}

		/* compatible with kernel code from the 'write' mode */
		if (attr_ex->qp_type == IBV_QPT_XRC_SEND) {
			attr_ex->cap.max_recv_wr = 0;
			attr_ex->cap.max_recv_sge = 0;
		}

		break;
	default:
		errno = EINVAL;
		return errno;
	}

	handle = fill_attr_out_obj(cmdb, UVERBS_ATTR_CREATE_QP_HANDLE);
	fill_attr_const_in(cmdb, UVERBS_ATTR_CREATE_QP_TYPE, attr_ex->qp_type);
	fill_attr_in_uint64(cmdb, UVERBS_ATTR_CREATE_QP_USER_HANDLE, (uintptr_t)qp);

	static_assert(offsetof(struct ibv_qp_cap, max_send_wr) ==
		offsetof(struct ib_uverbs_qp_cap, max_send_wr), "Bad layout");
	static_assert(offsetof(struct ibv_qp_cap, max_recv_wr) ==
		offsetof(struct ib_uverbs_qp_cap, max_recv_wr), "Bad layout");
	static_assert(offsetof(struct ibv_qp_cap, max_send_sge) ==
		offsetof(struct ib_uverbs_qp_cap, max_send_sge), "Bad layout");
	static_assert(offsetof(struct ibv_qp_cap, max_recv_sge) ==
		offsetof(struct ib_uverbs_qp_cap, max_recv_sge), "Bad layout");
	static_assert(offsetof(struct ibv_qp_cap, max_inline_data) ==
		offsetof(struct ib_uverbs_qp_cap, max_inline_data), "Bad layout");

	fill_attr_in_ptr(cmdb, UVERBS_ATTR_CREATE_QP_CAP, &attr_ex->cap);
	fill_attr_in_fd(cmdb, UVERBS_ATTR_CREATE_QP_EVENT_FD, context->async_fd);

	if (priv->imported)
		fallback_require_ioctl(cmdb);

	if (attr_ex->sq_sig_all)
		create_flags |= IB_UVERBS_QP_CREATE_SQ_SIG_ALL;

	if (attr_ex->comp_mask & IBV_QP_INIT_ATTR_CREATE_FLAGS) {
		if (attr_ex->create_flags & ~CREATE_QP_EX_SUP_CREATE_FLAGS) {
			errno = EINVAL;
			return errno;
		}

		fallback_require_ex(cmdb);
		create_flags |= attr_ex->create_flags;

		if (attr_ex->create_flags & IBV_QP_CREATE_SOURCE_QPN) {
			fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_QP_SOURCE_QPN,
					    attr_ex->source_qpn);
			/* source QPN is a self attribute once moving to ioctl,
			 * no extra bit is supported.
			 */
			create_flags &= ~IBV_QP_CREATE_SOURCE_QPN;
		}
	}

	if (create_flags)
		fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_QP_FLAGS,
				    create_flags);

	if (attr_ex->srq)
		fill_attr_in_obj(cmdb, UVERBS_ATTR_CREATE_QP_SRQ_HANDLE, attr_ex->srq->handle);

	fill_attr_out_ptr(cmdb, UVERBS_ATTR_CREATE_QP_RESP_CAP, &attr_ex->cap);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_CREATE_QP_RESP_QP_NUM, &qp_num);

	switch (execute_ioctl_fallback(context, create_qp, cmdb, &ret)) {
	case TRY_WRITE: {
		if (abi_ver > 4) {
			DECLARE_LEGACY_UHW_BUFS(link, IB_USER_VERBS_CMD_CREATE_QP);

			*req = (struct ib_uverbs_create_qp){
				.pd_handle = pd_handle,
				.user_handle = (uintptr_t)qp,
				.max_send_wr = attr_ex->cap.max_send_wr,
				.max_recv_wr = attr_ex->cap.max_recv_wr,
				.max_send_sge = attr_ex->cap.max_send_sge,
				.max_recv_sge = attr_ex->cap.max_recv_sge,
				.max_inline_data = attr_ex->cap.max_inline_data,
				.sq_sig_all = attr_ex->sq_sig_all,
				.qp_type = attr_ex->qp_type,
				.srq_handle = attr_ex->srq ? attr_ex->srq->handle : 0,
				.is_srq = !!attr_ex->srq,
				.recv_cq_handle = recv_cq_handle,
				.send_cq_handle = send_cq_handle,
			};

			ret = execute_write_bufs(
				context, IB_USER_VERBS_CMD_CREATE_QP, req, resp);
			if (ret)
				return ret;

			qp->handle = resp->qp_handle;
			qp->qp_num = resp->qpn;

			attr_ex->cap.max_recv_sge    = resp->max_recv_sge;
			attr_ex->cap.max_send_sge    = resp->max_send_sge;
			attr_ex->cap.max_recv_wr     = resp->max_recv_wr;
			attr_ex->cap.max_send_wr     = resp->max_send_wr;
			attr_ex->cap.max_inline_data = resp->max_inline_data;

		} else if (abi_ver == 4) {
			DECLARE_LEGACY_UHW_BUFS(link, IB_USER_VERBS_CMD_CREATE_QP_V4);

			*req = (struct ib_uverbs_create_qp){
				.pd_handle = pd_handle,
				.user_handle = (uintptr_t)qp,
				.max_send_wr = attr_ex->cap.max_send_wr,
				.max_recv_wr = attr_ex->cap.max_recv_wr,
				.max_send_sge = attr_ex->cap.max_send_sge,
				.max_recv_sge = attr_ex->cap.max_recv_sge,
				.max_inline_data = attr_ex->cap.max_inline_data,
				.sq_sig_all = attr_ex->sq_sig_all,
				.qp_type = attr_ex->qp_type,
				.srq_handle = attr_ex->srq ? attr_ex->srq->handle : 0,
				.is_srq = !!attr_ex->srq,
				.recv_cq_handle = recv_cq_handle,
				.send_cq_handle = send_cq_handle,
			};

			ret = execute_write_bufs(
				context, IB_USER_VERBS_CMD_CREATE_QP_V4, req, resp);
			if (ret)
				return ret;

			qp->handle = resp->qp_handle;
			qp->qp_num = resp->qpn;

			attr_ex->cap.max_recv_sge    = resp->max_recv_sge;
			attr_ex->cap.max_send_sge    = resp->max_send_sge;
			attr_ex->cap.max_recv_wr     = resp->max_recv_wr;
			attr_ex->cap.max_send_wr     = resp->max_send_wr;
			attr_ex->cap.max_inline_data = resp->max_inline_data;
		} else {
			DECLARE_LEGACY_UHW_BUFS(link, IB_USER_VERBS_CMD_CREATE_QP_V3);

			*req = (struct ib_uverbs_create_qp){
				.pd_handle = pd_handle,
				.user_handle = (uintptr_t)qp,
				.max_send_wr = attr_ex->cap.max_send_wr,
				.max_recv_wr = attr_ex->cap.max_recv_wr,
				.max_send_sge = attr_ex->cap.max_send_sge,
				.max_recv_sge = attr_ex->cap.max_recv_sge,
				.max_inline_data = attr_ex->cap.max_inline_data,
				.sq_sig_all = attr_ex->sq_sig_all,
				.qp_type = attr_ex->qp_type,
				.srq_handle = attr_ex->srq ? attr_ex->srq->handle : 0,
				.is_srq = !!attr_ex->srq,
				.recv_cq_handle = recv_cq_handle,
				.send_cq_handle = send_cq_handle,
			};

			ret = execute_write_bufs(
				context, IB_USER_VERBS_CMD_CREATE_QP_V3, req, resp);
			if (ret)
				return ret;

			qp->handle = resp->qp_handle;
			qp->qp_num = resp->qpn;
		}

		set_qp(vqp, qp, attr_ex, vxrcd);
		return 0;
	}

	case TRY_WRITE_EX: {
		DECLARE_LEGACY_UHW_BUFS_EX(link,
					   IB_USER_VERBS_EX_CMD_CREATE_QP);

		*req = (struct ib_uverbs_ex_create_qp){
			.pd_handle = pd_handle,
			.user_handle = (uintptr_t)qp,
			.max_send_wr = attr_ex->cap.max_send_wr,
			.max_recv_wr = attr_ex->cap.max_recv_wr,
			.max_send_sge = attr_ex->cap.max_send_sge,
			.max_recv_sge = attr_ex->cap.max_recv_sge,
			.max_inline_data = attr_ex->cap.max_inline_data,
			.sq_sig_all = attr_ex->sq_sig_all,
			.qp_type = attr_ex->qp_type,
			.srq_handle = attr_ex->srq ? attr_ex->srq->handle : 0,
			.is_srq = !!attr_ex->srq,
			.recv_cq_handle = recv_cq_handle,
			.send_cq_handle = send_cq_handle,
		};

		if (attr_ex->comp_mask & IBV_QP_INIT_ATTR_CREATE_FLAGS) {
			req->create_flags = attr_ex->create_flags;

			if (attr_ex->create_flags & IBV_QP_CREATE_SOURCE_QPN)
				req->source_qpn = attr_ex->source_qpn;
		}

		if (attr_ex->comp_mask & IBV_QP_INIT_ATTR_IND_TABLE) {
			req->rwq_ind_tbl_handle = attr_ex->rwq_ind_tbl->ind_tbl_handle;
			req->comp_mask = IB_UVERBS_CREATE_QP_MASK_IND_TABLE;
		}

		ret = execute_write_bufs_ex(
			context, IB_USER_VERBS_EX_CMD_CREATE_QP, req, resp);
		if (ret)
			return ret;

		qp->handle = resp->base.qp_handle;
		qp->qp_num = resp->base.qpn;

		attr_ex->cap.max_recv_sge    = resp->base.max_recv_sge;
		attr_ex->cap.max_send_sge    = resp->base.max_send_sge;
		attr_ex->cap.max_recv_wr     = resp->base.max_recv_wr;
		attr_ex->cap.max_send_wr     = resp->base.max_send_wr;
		attr_ex->cap.max_inline_data = resp->base.max_inline_data;
		set_qp(vqp, qp, attr_ex, vxrcd);
		return 0;
	}

	case SUCCESS:
		break;

	default:
		return ret;
	}

	qp->handle = read_attr_obj(UVERBS_ATTR_CREATE_QP_HANDLE, handle);
	qp->qp_num = qp_num;
	set_qp(vqp, qp, attr_ex, vxrcd);

	return 0;
}

int ibv_cmd_create_qp(struct ibv_pd *pd,
		      struct ibv_qp *qp, struct ibv_qp_init_attr *attr,
		      struct ibv_create_qp *cmd, size_t cmd_size,
		      struct ib_uverbs_create_qp_resp *resp, size_t resp_size)
{
	DECLARE_CMD_BUFFER_COMPAT(cmdb, UVERBS_OBJECT_QP,
				  UVERBS_METHOD_QP_CREATE, cmd, cmd_size, resp,
				  resp_size);

	struct ibv_qp_init_attr_ex attr_ex = {};
	int ret;

	attr_ex.qp_context = attr->qp_context;
	attr_ex.send_cq = attr->send_cq;
	attr_ex.recv_cq = attr->recv_cq;
	attr_ex.srq = attr->srq;
	attr_ex.cap = attr->cap;
	attr_ex.qp_type = attr->qp_type;
	attr_ex.sq_sig_all = attr->sq_sig_all;
	attr_ex.comp_mask = IBV_QP_INIT_ATTR_PD;
	attr_ex.pd = pd;
	ret = ibv_icmd_create_qp(pd->context, NULL, qp, &attr_ex, cmdb);
	if (!ret)
		memcpy(&attr->cap, &attr_ex.cap, sizeof(attr_ex.cap));

	return ret;
}

int ibv_cmd_create_qp_ex(struct ibv_context *context,
			 struct verbs_qp *qp,
			 struct ibv_qp_init_attr_ex *attr_ex,
			 struct ibv_create_qp *cmd, size_t cmd_size,
			 struct ib_uverbs_create_qp_resp *resp, size_t resp_size)
{
	DECLARE_CMD_BUFFER_COMPAT(cmdb, UVERBS_OBJECT_QP,
				  UVERBS_METHOD_QP_CREATE, cmd, cmd_size, resp,
				  resp_size);

	if (!check_comp_mask(attr_ex->comp_mask,
			     IBV_QP_INIT_ATTR_PD |
			     IBV_QP_INIT_ATTR_XRCD |
			     IBV_QP_INIT_ATTR_SEND_OPS_FLAGS)) {
		errno = EINVAL;
		return errno;
	}

	return ibv_icmd_create_qp(context, qp, NULL, attr_ex, cmdb);
}

int ibv_cmd_create_qp_ex2(struct ibv_context *context,
			  struct verbs_qp *qp,
			  struct ibv_qp_init_attr_ex *attr_ex,
			  struct ibv_create_qp_ex *cmd,
			  size_t cmd_size,
			  struct ib_uverbs_ex_create_qp_resp *resp,
			  size_t resp_size)
{
	DECLARE_CMD_BUFFER_COMPAT(cmdb, UVERBS_OBJECT_QP,
				  UVERBS_METHOD_QP_CREATE, cmd, cmd_size, resp,
				  resp_size);

	if (!check_comp_mask(attr_ex->comp_mask,
			     IBV_QP_INIT_ATTR_PD |
			     IBV_QP_INIT_ATTR_XRCD |
			     IBV_QP_INIT_ATTR_CREATE_FLAGS |
			     IBV_QP_INIT_ATTR_MAX_TSO_HEADER |
			     IBV_QP_INIT_ATTR_IND_TABLE |
			     IBV_QP_INIT_ATTR_RX_HASH |
			     IBV_QP_INIT_ATTR_SEND_OPS_FLAGS)) {
		errno = EINVAL;
		return errno;
	}

	return ibv_icmd_create_qp(context, qp, NULL, attr_ex, cmdb);
}

int ibv_cmd_destroy_qp(struct ibv_qp *qp)
{
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_QP, UVERBS_METHOD_QP_DESTROY, 2,
			     NULL);
	struct ib_uverbs_destroy_qp_resp resp;
	int ret;

	fill_attr_out_ptr(cmdb, UVERBS_ATTR_DESTROY_QP_RESP, &resp);
	fill_attr_in_obj(cmdb, UVERBS_ATTR_DESTROY_QP_HANDLE, qp->handle);

	switch (execute_ioctl_fallback(qp->context, destroy_qp, cmdb, &ret)) {
	case TRY_WRITE: {
		struct ibv_destroy_qp req;

		req.core_payload = (struct ib_uverbs_destroy_qp){
			.qp_handle = qp->handle,
		};

		ret = execute_cmd_write(qp->context,
					IB_USER_VERBS_CMD_DESTROY_QP, &req,
					sizeof(req), &resp, sizeof(resp));
		break;
	}

	default:
		break;
	}

	if (verbs_is_destroy_err(&ret))
		return ret;

	pthread_mutex_lock(&qp->mutex);
	while (qp->events_completed != resp.events_reported)
		pthread_cond_wait(&qp->cond, &qp->mutex);
	pthread_mutex_unlock(&qp->mutex);

	return 0;
}
