// SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
/*
 * Copyright (c) 2024 ZTE Corporation.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <rdma/zxdh_user_ioctl_cmds.h>
#include <rdma/zxdh_user_ioctl_verbs.h>
#include "private_verbs_cmd.h"
#include "zxdh_dv.h"

static void copy_query_qpc(struct zxdh_query_qpc_resp *resp,
			   struct zxdh_rdma_qpc *qpc)
{
	qpc->ack_err_flag = resp->ack_err_flag;
	qpc->retry_flag = resp->retry_flag;
	qpc->rnr_retry_flag = resp->rnr_retry_flag;
	qpc->cur_retry_count = resp->cur_retry_count;
	qpc->retry_cqe_sq_opcode = resp->retry_cqe_sq_opcode;
	qpc->err_flag = resp->err_flag;
	qpc->package_err_flag = resp->package_err_flag;
	qpc->recv_err_flag = resp->recv_err_flag;
	qpc->tx_last_ack_psn = resp->tx_last_ack_psn;
	qpc->retry_count = resp->retry_count;
	qpc->read_retry_flag = resp->read_retry_flag;
}

static int _zxdh_query_qpc(struct ibv_qp *qp, struct zxdh_rdma_qpc *qpc)
{
	DECLARE_COMMAND_BUFFER(cmd, ZXDH_IB_OBJECT_QP_OBJ,
			       ZXDH_IB_METHOD_QP_QUERY_QPC, 2);
	int ret;
	struct zxdh_query_qpc_resp resp_ex = { 0 };

	fill_attr_in_obj(cmd, ZXDH_IB_ATTR_QP_QUERY_HANDLE, qp->handle);
	fill_attr_out_ptr(cmd, ZXDH_IB_ATTR_QP_QUERY_RESP, &resp_ex);

	ret = execute_ioctl(qp->context, cmd);
	if (ret)
		return ret;

	copy_query_qpc(&resp_ex, qpc);
	return 0;
}

static struct zxdh_uvcontext_ops zxdh_ctx_ops = {
	.query_qpc = _zxdh_query_qpc,
};

static inline struct zxdh_uvcontext *to_zxdhtx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct zxdh_uvcontext, ibv_ctx.context);
}

int zxdh_reset_qp(struct ibv_qp *qp, uint64_t opcode)
{
	struct zxdh_uvcontext_ops *dvops = to_zxdhtx(qp->context)->cxt_ops;

	if (!dvops || !dvops->reset_qp)
		return -EOPNOTSUPP;
	return dvops->reset_qp(qp, opcode);
}

int zxdh_modify_qpc(struct ibv_qp *qp, struct zxdh_rdma_qpc *qpc,
		    uint64_t qpc_mask)
{
	struct zxdh_uvcontext_ops *dvops = to_zxdhtx(qp->context)->cxt_ops;

	if (!dvops || !dvops->modify_qpc)
		return -EOPNOTSUPP;
	return dvops->modify_qpc(qp, qpc, qpc_mask);
}

int zxdh_query_qpc(struct ibv_qp *qp, struct zxdh_rdma_qpc *qpc)
{
	struct zxdh_uvcontext_ops *dvops = to_zxdhtx(qp->context)->cxt_ops;

	if (!dvops || !dvops->query_qpc)
		return -EOPNOTSUPP;

	return dvops->query_qpc(qp, qpc);
}

void add_private_ops(struct zxdh_uvcontext *iwvctx)
{
	iwvctx->cxt_ops = &zxdh_ctx_ops;
}
