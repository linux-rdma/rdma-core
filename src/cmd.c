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
#include <alloca.h>

#include "ibverbs.h"

int ibv_cmd_get_context(int num_comp, struct ibv_context *context,
			struct ibv_get_context *cmd, size_t cmd_size,
			struct ibv_get_context_resp *resp, size_t resp_size)
{
	uint32_t *cq_fd_tab;
	int i;

	cq_fd_tab = alloca(num_comp * sizeof (uint32_t));
	IBV_INIT_CMD_RESP(cmd, cmd_size, GET_CONTEXT, resp, resp_size);

	cmd->cq_fd_tab = (uintptr_t) cq_fd_tab;

	if (write(context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	context->async_fd = resp->async_fd;
	for (i = 0; i < num_comp; ++i)
		context->cq_fd[i] = cq_fd_tab[i];

	return 0;
}

int ibv_cmd_query_device(struct ibv_context *context,
			 struct ibv_device_attr *device_attr,
			 struct ibv_query_device *cmd, size_t cmd_size)
{
	struct ibv_query_device_resp resp;

	IBV_INIT_CMD_RESP(cmd, cmd_size, QUERY_DEVICE, &resp, sizeof resp);

	if (write(context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	device_attr->fw_ver 		       = resp.fw_ver;
	device_attr->node_guid 		       = resp.node_guid;
	device_attr->sys_image_guid 	       = resp.sys_image_guid;
	device_attr->max_mr_size 	       = resp.max_mr_size;
	device_attr->page_size_cap 	       = resp.page_size_cap;
	device_attr->vendor_id 		       = resp.vendor_id;
	device_attr->vendor_part_id 	       = resp.vendor_part_id;
	device_attr->hw_ver 		       = resp.hw_ver;
	device_attr->max_qp 		       = resp.max_qp;
	device_attr->max_qp_wr 		       = resp.max_qp_wr;
	device_attr->device_cap_flags 	       = resp.device_cap_flags;
	device_attr->max_sge 		       = resp.max_sge;
	device_attr->max_sge_rd 	       = resp.max_sge_rd;
	device_attr->max_cq 		       = resp.max_cq;
	device_attr->max_cqe 		       = resp.max_cqe;
	device_attr->max_mr 		       = resp.max_mr;
	device_attr->max_pd 		       = resp.max_pd;
	device_attr->max_qp_rd_atom 	       = resp.max_qp_rd_atom;
	device_attr->max_ee_rd_atom 	       = resp.max_ee_rd_atom;
	device_attr->max_res_rd_atom 	       = resp.max_res_rd_atom;
	device_attr->max_qp_init_rd_atom       = resp.max_qp_init_rd_atom;
	device_attr->max_ee_init_rd_atom       = resp.max_ee_init_rd_atom;
	device_attr->atomic_cap 	       = resp.atomic_cap;
	device_attr->max_ee 		       = resp.max_ee;
	device_attr->max_rdd 		       = resp.max_rdd;
	device_attr->max_mw 		       = resp.max_mw;
	device_attr->max_raw_ipv6_qp 	       = resp.max_raw_ipv6_qp;
	device_attr->max_raw_ethy_qp 	       = resp.max_raw_ethy_qp;
	device_attr->max_mcast_grp 	       = resp.max_mcast_grp;
	device_attr->max_mcast_qp_attach       = resp.max_mcast_qp_attach;
	device_attr->max_total_mcast_qp_attach = resp.max_total_mcast_qp_attach;
	device_attr->max_ah 		       = resp.max_ah;
	device_attr->max_fmr 		       = resp.max_fmr;
	device_attr->max_map_per_fmr 	       = resp.max_map_per_fmr;
	device_attr->max_srq 		       = resp.max_srq;
	device_attr->max_srq_wr 	       = resp.max_srq_wr;
	device_attr->max_srq_sge 	       = resp.max_srq_sge;
	device_attr->max_pkeys 		       = resp.max_pkeys;
	device_attr->local_ca_ack_delay        = resp.local_ca_ack_delay;
	device_attr->phys_port_cnt	       = resp.phys_port_cnt;

	return 0;
}

int ibv_cmd_query_port(struct ibv_context *context, uint8_t port_num,
		       struct ibv_port_attr *port_attr,
		       struct ibv_query_port *cmd, size_t cmd_size)
{
	struct ibv_query_port_resp resp;

	IBV_INIT_CMD_RESP(cmd, cmd_size, QUERY_PORT, &resp, sizeof resp);
	cmd->port_num = port_num;

	if (write(context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	port_attr->state      	   = resp.state;
	port_attr->max_mtu         = resp.max_mtu;
	port_attr->active_mtu      = resp.active_mtu;
	port_attr->gid_tbl_len     = resp.gid_tbl_len;
	port_attr->port_cap_flags  = resp.port_cap_flags;
	port_attr->max_msg_sz      = resp.max_msg_sz;
	port_attr->bad_pkey_cntr   = resp.bad_pkey_cntr;
	port_attr->qkey_viol_cntr  = resp.qkey_viol_cntr;
	port_attr->pkey_tbl_len    = resp.pkey_tbl_len;
	port_attr->lid 	      	   = resp.lid;
	port_attr->sm_lid 	   = resp.sm_lid;
	port_attr->lmc 	      	   = resp.lmc;
	port_attr->max_vl_num      = resp.max_vl_num;
	port_attr->sm_sl      	   = resp.sm_sl;
	port_attr->subnet_timeout  = resp.subnet_timeout;
	port_attr->init_type_reply = resp.init_type_reply;
	port_attr->active_width    = resp.active_width;
	port_attr->active_speed    = resp.active_speed;
	port_attr->phys_state      = resp.phys_state;

	return 0;
}

int ibv_cmd_query_gid(struct ibv_context *context, uint8_t port_num,
		      int index, union ibv_gid *gid)
{
	struct ibv_query_gid      cmd;
	struct ibv_query_gid_resp resp;

	IBV_INIT_CMD_RESP(&cmd, sizeof cmd, QUERY_GID, &resp, sizeof resp);
	cmd.port_num = port_num;
	cmd.index    = index;

	if (write(context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	memcpy(gid->raw, resp.gid, 16);

	return 0;
}

int ibv_cmd_query_pkey(struct ibv_context *context, uint8_t port_num,
		       int index, uint16_t *pkey)
{
	struct ibv_query_pkey      cmd;
	struct ibv_query_pkey_resp resp;

	IBV_INIT_CMD_RESP(&cmd, sizeof cmd, QUERY_PKEY, &resp, sizeof resp);
	cmd.port_num = port_num;
	cmd.index    = index;

	if (write(context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	*pkey = resp.pkey;

	return 0;
}

int ibv_cmd_alloc_pd(struct ibv_context *context, struct ibv_pd *pd,
		     struct ibv_alloc_pd *cmd, size_t cmd_size,
		     struct ibv_alloc_pd_resp *resp, size_t resp_size)
{
	IBV_INIT_CMD_RESP(cmd, cmd_size, ALLOC_PD, resp, resp_size);

	if (write(context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	pd->handle = resp->pd_handle;

	return 0;
}

int ibv_cmd_dealloc_pd(struct ibv_pd *pd)
{
	struct ibv_dealloc_pd cmd;

	IBV_INIT_CMD(&cmd, sizeof cmd, DEALLOC_PD);
	cmd.pd_handle = pd->handle;

	if (write(pd->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	return 0;
}

int ibv_cmd_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
		   uint64_t hca_va, enum ibv_access_flags access,
		   struct ibv_mr *mr, struct ibv_reg_mr *cmd,
		   size_t cmd_size)
{
	struct ibv_reg_mr_resp resp;

	IBV_INIT_CMD_RESP(cmd, cmd_size, REG_MR, &resp, sizeof resp);

	cmd->start 	  = (uintptr_t) addr;
	cmd->length 	  = length;
	cmd->hca_va 	  = hca_va;
	cmd->pd_handle 	  = pd->handle;
	cmd->access_flags = access;

	if (write(pd->context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	mr->handle  = resp.mr_handle;
	mr->lkey    = resp.lkey;
	mr->rkey    = resp.rkey;

	return 0;
}

int ibv_cmd_dereg_mr(struct ibv_mr *mr)
{
	struct ibv_dereg_mr cmd;

	IBV_INIT_CMD(&cmd, sizeof cmd, DEREG_MR);
	cmd.mr_handle = mr->handle;

	if (write(mr->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	return 0;
}

int ibv_cmd_create_cq(struct ibv_context *context, int cqe,
		      struct ibv_cq *cq,
		      struct ibv_create_cq *cmd, size_t cmd_size,
		      struct ibv_create_cq_resp *resp, size_t resp_size)
{
	IBV_INIT_CMD_RESP(cmd, cmd_size, CREATE_CQ, resp, resp_size);
	cmd->user_handle = (uintptr_t) cq;
	cmd->cqe         = cqe;

	if (write(context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	cq->handle = resp->cq_handle;
	cq->cqe    = resp->cqe;

	return 0;
}

int ibv_cmd_destroy_cq(struct ibv_cq *cq)
{
	struct ibv_destroy_cq cmd;

	IBV_INIT_CMD(&cmd, sizeof cmd, DESTROY_CQ);
	cmd.cq_handle = cq->handle;

	if (write(cq->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	return 0;
}

int ibv_cmd_create_qp(struct ibv_pd *pd,
		      struct ibv_qp *qp, struct ibv_qp_init_attr *attr,
		      struct ibv_create_qp *cmd, size_t cmd_size)
{
	struct ibv_create_qp_resp resp;

	IBV_INIT_CMD_RESP(cmd, cmd_size, CREATE_QP, &resp, sizeof resp);
	cmd->user_handle     = (uintptr_t) qp;
	cmd->pd_handle 	     = pd->handle;
	cmd->send_cq_handle  = attr->send_cq->handle;
	cmd->recv_cq_handle  = attr->recv_cq->handle;
	cmd->max_send_wr     = attr->cap.max_send_wr;
	cmd->max_recv_wr     = attr->cap.max_recv_wr;
	cmd->max_send_sge    = attr->cap.max_send_sge;
	cmd->max_recv_sge    = attr->cap.max_recv_sge;
	cmd->max_inline_data = attr->cap.max_inline_data;
	cmd->sq_sig_all	     = attr->sq_sig_all;
	cmd->qp_type 	     = attr->qp_type;
	cmd->is_srq 	     = 0;

	if (write(pd->context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	qp->handle  = resp.qp_handle;
	qp->qp_num  = resp.qpn;

	return 0;
}

int ibv_cmd_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		      enum ibv_qp_attr_mask attr_mask,
		      struct ibv_modify_qp *cmd, size_t cmd_size)
{
	IBV_INIT_CMD(cmd, cmd_size, MODIFY_QP);

	cmd->qp_handle 		 = qp->handle;
	cmd->attr_mask 		 = attr_mask;
	cmd->qkey 		 = attr->qkey;
	cmd->rq_psn 		 = attr->rq_psn;
	cmd->sq_psn 		 = attr->sq_psn;
	cmd->dest_qp_num 	 = attr->dest_qp_num;
	cmd->qp_access_flags 	 = attr->qp_access_flags;
	cmd->pkey_index		 = attr->pkey_index;
	cmd->alt_pkey_index 	 = attr->alt_pkey_index;
	cmd->qp_state 		 = attr->qp_state;
	cmd->cur_qp_state 	 = attr->cur_qp_state;
	cmd->path_mtu 		 = attr->path_mtu;
	cmd->path_mig_state 	 = attr->path_mig_state;
	cmd->en_sqd_async_notify = attr->en_sqd_async_notify;
	cmd->max_rd_atomic 	 = attr->max_rd_atomic;
	cmd->max_dest_rd_atomic  = attr->max_dest_rd_atomic;
	cmd->min_rnr_timer 	 = attr->min_rnr_timer;
	cmd->port_num 		 = attr->port_num;
	cmd->timeout 		 = attr->timeout;
	cmd->retry_cnt 		 = attr->retry_cnt;
	cmd->rnr_retry 		 = attr->rnr_retry;
	cmd->alt_port_num 	 = attr->alt_port_num;
	cmd->alt_timeout 	 = attr->alt_timeout;

	memcpy(cmd->dest.dgid, attr->ah_attr.grh.dgid.raw, 16);
	cmd->dest.flow_label 	    = attr->ah_attr.grh.flow_label;
	cmd->dest.dlid 		    = attr->ah_attr.dlid;
	cmd->dest.sgid_index 	    = attr->ah_attr.grh.sgid_index;
	cmd->dest.hop_limit 	    = attr->ah_attr.grh.hop_limit;
	cmd->dest.traffic_class     = attr->ah_attr.grh.traffic_class;
	cmd->dest.sl 		    = attr->ah_attr.sl;
	cmd->dest.src_path_bits     = attr->ah_attr.src_path_bits;
	cmd->dest.static_rate 	    = attr->ah_attr.static_rate;
	cmd->dest.is_global 	    = attr->ah_attr.is_global;
	cmd->dest.port_num 	    = attr->ah_attr.port_num;

	memcpy(cmd->alt_dest.dgid, attr->alt_ah_attr.grh.dgid.raw, 16);
	cmd->alt_dest.flow_label    = attr->alt_ah_attr.grh.flow_label;
	cmd->alt_dest.dlid 	    = attr->alt_ah_attr.dlid;
	cmd->alt_dest.sgid_index    = attr->alt_ah_attr.grh.sgid_index;
	cmd->alt_dest.hop_limit     = attr->alt_ah_attr.grh.hop_limit;
	cmd->alt_dest.traffic_class = attr->alt_ah_attr.grh.traffic_class;
	cmd->alt_dest.sl 	    = attr->alt_ah_attr.sl;
	cmd->alt_dest.src_path_bits = attr->alt_ah_attr.src_path_bits;
	cmd->alt_dest.static_rate   = attr->alt_ah_attr.static_rate;
	cmd->alt_dest.is_global     = attr->alt_ah_attr.is_global;
	cmd->alt_dest.port_num 	    = attr->alt_ah_attr.port_num;

	if (write(qp->context->cmd_fd, cmd, cmd_size) != cmd_size)
		return errno;

	return 0;
}

int ibv_cmd_destroy_qp(struct ibv_qp *qp)
{
	struct ibv_destroy_qp cmd;

	IBV_INIT_CMD(&cmd, sizeof cmd, DESTROY_QP);
	cmd.qp_handle = qp->handle;

	if (write(qp->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	return 0;
}

int ibv_cmd_attach_mcast(struct ibv_qp *qp, union ibv_gid *gid, uint16_t lid)
{
	struct ibv_attach_mcast cmd;

	IBV_INIT_CMD(&cmd, sizeof cmd, ATTACH_MCAST);
	memcpy(cmd.gid, gid->raw, sizeof cmd.gid);
	cmd.qp_handle = qp->handle;
	cmd.mlid      = lid;

	if (write(qp->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	return 0;
}

int ibv_cmd_detach_mcast(struct ibv_qp *qp, union ibv_gid *gid, uint16_t lid)
{
	struct ibv_detach_mcast cmd;

	IBV_INIT_CMD(&cmd, sizeof cmd, DETACH_MCAST);
	memcpy(cmd.gid, gid->raw, sizeof cmd.gid);
	cmd.qp_handle = qp->handle;
	cmd.mlid      = lid;

	if (write(qp->context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd)
		return errno;

	return 0;
}
