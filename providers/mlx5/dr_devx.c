/*
 * Copyright (c) 2019 Mellanox Technologies, Inc.  All rights reserved.
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

#include <stdlib.h>
#include <stdio.h>
#include <infiniband/verbs.h>
#include <infiniband/cmd_ioctl.h>
#include <rdma/mlx5_user_ioctl_cmds.h>
#include "mlx5dv_dr.h"

int dr_devx_query_esw_vport_context(struct ibv_context *ctx,
				    bool other_vport, uint16_t vport_number,
				    uint64_t *icm_address_rx,
				    uint64_t *icm_address_tx)
{
	uint32_t out[DEVX_ST_SZ_DW(query_esw_vport_context_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(query_esw_vport_context_in)] = {};
	int err;

	DEVX_SET(query_esw_vport_context_in, in, opcode,
		 MLX5_CMD_OP_QUERY_ESW_VPORT_CONTEXT);
	DEVX_SET(query_esw_vport_context_in, in, other_vport, other_vport);
	DEVX_SET(query_esw_vport_context_in, in, vport_number, vport_number);

	err = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (err) {
		dr_dbg_ctx(ctx, "Query eswitch vport context failed %d\n", err);
		return err;
	}

	*icm_address_rx =
		DEVX_GET64(query_esw_vport_context_out, out,
			   esw_vport_context.sw_steering_vport_icm_address_rx);
	*icm_address_tx =
		DEVX_GET64(query_esw_vport_context_out, out,
			   esw_vport_context.sw_steering_vport_icm_address_tx);
	return 0;
}

int dr_devx_query_gvmi(struct ibv_context *ctx, bool other_vport,
		       uint16_t vport_number, uint16_t *gvmi)
{
	uint32_t out[DEVX_ST_SZ_DW(query_hca_cap_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(query_hca_cap_in)] = {};
	int err;

	DEVX_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, other_function, other_vport);
	DEVX_SET(query_hca_cap_in, in, function_id, vport_number);
	DEVX_SET(query_hca_cap_in, in, op_mod,
		 MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE |
		 HCA_CAP_OPMOD_GET_CUR);

	err = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (err) {
		dr_dbg_ctx(ctx, "Query general failed %d\n", err);
		return err;
	}

	*gvmi = DEVX_GET(query_hca_cap_out, out, capability.cmd_hca_cap.vhca_id);

	return 0;
}

int dr_devx_query_esw_caps(struct ibv_context *ctx, struct dr_esw_caps *caps)
{
	uint32_t out[DEVX_ST_SZ_DW(query_hca_cap_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(query_hca_cap_in)] = {};
	void *esw_caps;
	int err;

	DEVX_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, op_mod,
		 MLX5_SET_HCA_CAP_OP_MOD_ESW_FLOW_TABLE |
		 HCA_CAP_OPMOD_GET_CUR);

	err = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (err) {
		dr_dbg_ctx(ctx, "Query general failed %d\n", err);
		return err;
	}

	esw_caps = DEVX_ADDR_OF(query_hca_cap_out, out,
				capability.flow_table_eswitch_cap);
	caps->drop_icm_address_rx =
		DEVX_GET64(flow_table_eswitch_cap, esw_caps,
			   sw_steering_fdb_action_drop_icm_address_rx);
	caps->drop_icm_address_tx =
		DEVX_GET64(flow_table_eswitch_cap, esw_caps,
			   sw_steering_fdb_action_drop_icm_address_tx);
	caps->uplink_icm_address_rx =
		DEVX_GET64(flow_table_eswitch_cap, esw_caps,
			   sw_steering_uplink_icm_address_rx);
	caps->uplink_icm_address_tx =
		DEVX_GET64(flow_table_eswitch_cap, esw_caps,
			   sw_steering_uplink_icm_address_tx);
	caps->sw_owner =
		DEVX_GET(flow_table_eswitch_cap, esw_caps,
			 flow_table_properties_nic_esw_fdb.sw_owner);
	return 0;
}

int dr_devx_query_device(struct ibv_context *ctx, struct dr_devx_caps *caps)
{
	uint32_t out[DEVX_ST_SZ_DW(query_hca_cap_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(query_hca_cap_in)] = {};
	int err;

	DEVX_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, op_mod,
		 MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE |
		 HCA_CAP_OPMOD_GET_CUR);

	err = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (err) {
		dr_dbg_ctx(ctx, "Query general failed %d\n", err);
		return err;
	}

	caps->eswitch_manager = DEVX_GET(query_hca_cap_out, out,
					 capability.cmd_hca_cap.eswitch_manager);
	caps->gvmi = DEVX_GET(query_hca_cap_out, out, capability.cmd_hca_cap.vhca_id);
	caps->flex_protocols = DEVX_GET(query_hca_cap_out, out,
					capability.cmd_hca_cap.flex_parser_protocols);

	if (dr_matcher_supp_flex_parser_icmp_v4(caps)) {
		caps->flex_parser_id_icmp_dw0 =
			DEVX_GET(query_hca_cap_out,
				 out,
				 capability.cmd_hca_cap.flex_parser_id_icmp_dw0);
		caps->flex_parser_id_icmp_dw1 =
			DEVX_GET(query_hca_cap_out,
				 out,
				 capability.cmd_hca_cap.flex_parser_id_icmp_dw1);
	}

	if (dr_matcher_supp_flex_parser_icmp_v6(caps)) {
		caps->flex_parser_id_icmpv6_dw0 =
			DEVX_GET(query_hca_cap_out,
				 out,
				 capability.cmd_hca_cap.flex_parser_id_icmpv6_dw0);
		caps->flex_parser_id_icmpv6_dw1 =
			DEVX_GET(query_hca_cap_out,
				 out,
				 capability.cmd_hca_cap.flex_parser_id_icmpv6_dw1);
	}

	DEVX_SET(query_hca_cap_in, in, op_mod,
		 MLX5_SET_HCA_CAP_OP_MOD_NIC_FLOW_TABLE |
		 HCA_CAP_OPMOD_GET_CUR);

	err = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (err) {
		dr_dbg_ctx(ctx, "Query flow tables failed %d\n", err);
		return err;
	}

	caps->nic_rx_drop_address = DEVX_GET64(query_hca_cap_out, out,
					       capability.flow_table_nic_cap.
					       sw_steering_nic_rx_action_drop_icm_address);
	caps->nic_tx_drop_address = DEVX_GET64(query_hca_cap_out, out,
					       capability.flow_table_nic_cap.
					       sw_steering_nic_tx_action_drop_icm_address);
	caps->nic_tx_allow_address = DEVX_GET64(query_hca_cap_out, out,
						capability.flow_table_nic_cap.
						sw_steering_nic_tx_action_allow_icm_address);
	caps->rx_sw_owner = DEVX_GET(query_hca_cap_out, out,
				     capability.flow_table_nic_cap.
				     flow_table_properties_nic_receive.sw_owner);
	caps->tx_sw_owner = DEVX_GET(query_hca_cap_out, out,
				     capability.flow_table_nic_cap.
				     flow_table_properties_nic_transmit.sw_owner);
	caps->max_ft_level = DEVX_GET(query_hca_cap_out, out,
				      capability.flow_table_nic_cap.
				      flow_table_properties_nic_receive.max_ft_level);
	DEVX_SET(query_hca_cap_in, in, op_mod,
		 MLX5_SET_HCA_CAP_OP_MOD_DEVICE_MEMORY |
		 HCA_CAP_OPMOD_GET_CUR);

	err = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (err) {
		dr_dbg_ctx(ctx, "Query flow device memory caps failed %d\n", err);
		return err;
	}

	caps->log_icm_size = DEVX_GET(query_hca_cap_out, out,
				      capability.device_mem_cap.log_steering_sw_icm_size);
	caps->hdr_modify_icm_addr = DEVX_GET64(query_hca_cap_out, out,
					       capability.device_mem_cap.
					       header_modify_sw_icm_start_address);

	return 0;
}

int dr_devx_sync_steering(struct ibv_context *ctx)
{
	uint32_t out[DEVX_ST_SZ_DW(sync_steering_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(sync_steering_in)] = {};
	int err;

	DEVX_SET(sync_steering_in, in, opcode, MLX5_CMD_OP_SYNC_STEERING);

	err = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (err)
		dr_dbg_ctx(ctx, "Sync steering failed %d\n", err);

	return err;
}

struct mlx5dv_devx_obj *dr_devx_create_flow_table(struct ibv_context *ctx,
						  uint32_t table_type,
						  uint64_t icm_addr_rx,
						  uint64_t icm_addr_tx,
						  u8 level)
{
	uint32_t out[DEVX_ST_SZ_DW(create_flow_table_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(create_flow_table_in)] = {};
	void *ft_ctx;

	DEVX_SET(create_flow_table_in, in, opcode, MLX5_CMD_OP_CREATE_FLOW_TABLE);
	DEVX_SET(create_flow_table_in, in, table_type, table_type);

	ft_ctx = DEVX_ADDR_OF(create_flow_table_in, in, flow_table_context);
	DEVX_SET(flow_table_context, ft_ctx, sw_owner, 1);

	DEVX_SET(flow_table_context, ft_ctx, level, level);
	/*
	 * icm_addr_0 used for FDB RX / NIC TX / NIC_RX
	 * icm_addr_1 used for FDB TX
	 */
	if (table_type == FS_FT_NIC_RX) {
		DEVX_SET64(flow_table_context, ft_ctx, sw_owner_icm_root_0, icm_addr_rx);
	} else if (table_type == FS_FT_NIC_TX) {
		DEVX_SET64(flow_table_context, ft_ctx, sw_owner_icm_root_0, icm_addr_tx);
	} else if (table_type == FS_FT_FDB) {
		DEVX_SET64(flow_table_context, ft_ctx, sw_owner_icm_root_0, icm_addr_rx);
		DEVX_SET64(flow_table_context, ft_ctx, sw_owner_icm_root_1, icm_addr_tx);
	} else {
		assert(false);
	}

	return mlx5dv_devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
}

struct mlx5dv_devx_obj *dr_devx_create_reformat_ctx(struct ibv_context *ctx,
						    enum reformat_type rt,
						    size_t reformat_size,
						    void *reformat_data)
{
	uint32_t out[DEVX_ST_SZ_DW(alloc_packet_reformat_context_out)] = {};
	size_t insz, cmd_data_sz, cmd_total_sz;
	struct mlx5dv_devx_obj *obj;
	void *prctx;
	void *pdata;
	void *in;

	cmd_total_sz = DEVX_ST_SZ_BYTES(alloc_packet_reformat_context_in);
	cmd_data_sz = DEVX_FLD_SZ_BYTES(alloc_packet_reformat_context_in,
					packet_reformat_context.reformat_data);
	insz = align(cmd_total_sz + reformat_size - cmd_data_sz, 4);
	in = calloc(1, insz);
	if (!in) {
		errno = ENOMEM;
		return NULL;
	}

	DEVX_SET(alloc_packet_reformat_context_in, in, opcode,
		 MLX5_CMD_OP_ALLOC_PACKET_REFORMAT_CONTEXT);

	prctx = DEVX_ADDR_OF(alloc_packet_reformat_context_in, in, packet_reformat_context);
	pdata = DEVX_ADDR_OF(packet_reformat_context_in, prctx, reformat_data);

	DEVX_SET(packet_reformat_context_in, prctx, reformat_type, rt);
	DEVX_SET(packet_reformat_context_in, prctx, reformat_data_size, reformat_size);
	memcpy(pdata, reformat_data, reformat_size);

	obj = mlx5dv_devx_obj_create(ctx, in, insz, out, sizeof(out));
	free(in);

	return obj;
}

struct mlx5dv_devx_obj *dr_devx_create_meter(struct ibv_context *ctx,
					     struct mlx5dv_dr_flow_meter_attr
					     *meter_attr)
{
	uint32_t out[DEVX_ST_SZ_DW(general_obj_out_cmd_hdr)] = {};
	uint32_t in[DEVX_ST_SZ_DW(create_flow_meter_in)] = {};
	void *attr;

	if (meter_attr->flow_meter_parameter_sz >
	    DEVX_FLD_SZ_BYTES(flow_meter, flow_meter_params)) {
		errno = EINVAL;
		return NULL;
	}

	attr = DEVX_ADDR_OF(create_flow_meter_in, in, hdr);
	DEVX_SET(general_obj_in_cmd_hdr,
		 attr, opcode, MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	DEVX_SET(general_obj_in_cmd_hdr,
		 attr, obj_type, MLX5_OBJ_TYPE_FLOW_METER);

	attr = DEVX_ADDR_OF(create_flow_meter_in, in, meter);
	DEVX_SET(flow_meter, attr, active, meter_attr->active);
	DEVX_SET(flow_meter, attr, return_reg_id, meter_attr->reg_c_index);
	DEVX_SET(flow_meter, attr, table_type,
		 meter_attr->next_table->table_type);
	DEVX_SET(flow_meter, attr, destination_table_id,
		 meter_attr->next_table->devx_obj->object_id);

	attr = DEVX_ADDR_OF(flow_meter, attr, flow_meter_params);
	memcpy(attr, meter_attr->flow_meter_parameter,
	       meter_attr->flow_meter_parameter_sz);

	return mlx5dv_devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
}

int dr_devx_query_meter(struct mlx5dv_devx_obj *obj, uint64_t *rx_icm_addr,
			uint64_t *tx_icm_addr)
{
	uint32_t in[DEVX_ST_SZ_DW(general_obj_in_cmd_hdr)] = {};
	uint32_t out[DEVX_ST_SZ_DW(query_flow_meter_out)] = {};
	void *attr;
	int ret;

	DEVX_SET(general_obj_in_cmd_hdr, in, opcode,
		 MLX5_CMD_OP_QUERY_GENERAL_OBJECT);
	DEVX_SET(general_obj_in_cmd_hdr, in, obj_type,
		 MLX5_OBJ_TYPE_FLOW_METER);
	DEVX_SET(general_obj_in_cmd_hdr, in, obj_id, obj->object_id);

	ret = mlx5dv_devx_obj_query(obj, in, sizeof(in), out, sizeof(out));
	if (ret) {
		dr_dbg_ctx(obj->context, "Failed to query flow meter id %u\n",
			   obj->object_id);
		return ret;
	}

	attr = DEVX_ADDR_OF(query_flow_meter_out, out, obj);
	*rx_icm_addr = DEVX_GET64(flow_meter, attr, sw_steering_icm_address_rx);
	*tx_icm_addr = DEVX_GET64(flow_meter, attr, sw_steering_icm_address_tx);

	return 0;
}

int dr_devx_modify_meter(struct mlx5dv_devx_obj *obj,
			 struct mlx5dv_dr_flow_meter_attr *meter_attr,
			 __be64 modify_bits)
{
	uint32_t out[DEVX_ST_SZ_DW(general_obj_out_cmd_hdr)] = {};
	uint32_t in[DEVX_ST_SZ_DW(create_flow_meter_in)] = {};
	void *attr;

	if (meter_attr->flow_meter_parameter_sz >
	    DEVX_FLD_SZ_BYTES(flow_meter, flow_meter_params)) {
		errno = EINVAL;
		return errno;
	}

	attr = DEVX_ADDR_OF(create_flow_meter_in, in, hdr);
	DEVX_SET(general_obj_in_cmd_hdr,
		 attr, opcode, MLX5_CMD_OP_MODIFY_GENERAL_OBJECT);
	DEVX_SET(general_obj_in_cmd_hdr,
		 attr, obj_type, MLX5_OBJ_TYPE_FLOW_METER);
	DEVX_SET(general_obj_in_cmd_hdr, in, obj_id, obj->object_id);

	attr = DEVX_ADDR_OF(create_flow_meter_in, in, meter);
	memcpy(DEVX_ADDR_OF(flow_meter, attr, modify_field_select),
	       &modify_bits, sizeof(modify_bits));

	DEVX_SET(flow_meter, attr, active, meter_attr->active);

	attr = DEVX_ADDR_OF(flow_meter, attr, flow_meter_params);
	memcpy(attr, meter_attr->flow_meter_parameter,
	       meter_attr->flow_meter_parameter_sz);

	return mlx5dv_devx_obj_modify(obj, in, sizeof(in), out, sizeof(out));
}

struct mlx5dv_devx_obj *dr_devx_create_qp(struct ibv_context *ctx,
					  struct dr_devx_qp_create_attr *attr)
{
	uint32_t in[DEVX_ST_SZ_DW(create_qp_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(create_qp_out)] = {};
	void *qpc = DEVX_ADDR_OF(create_qp_in, in, qpc);

	DEVX_SET(create_qp_in, in, opcode, MLX5_CMD_OP_CREATE_QP);

	DEVX_SET(qpc, qpc, st, attr->service_type);
	DEVX_SET(qpc, qpc, pm_state, attr->pm_state);
	DEVX_SET(qpc, qpc, pd, attr->pdn);
	DEVX_SET(qpc, qpc, uar_page, attr->page_id);
	DEVX_SET(qpc, qpc, cqn_snd, attr->cqn);
	DEVX_SET(qpc, qpc, cqn_rcv, attr->cqn);
	DEVX_SET(qpc, qpc, log_sq_size, ilog32(attr->sq_wqe_cnt - 1));
	DEVX_SET(qpc, qpc, log_rq_stride, attr->rq_wqe_shift - 4);
	DEVX_SET(qpc, qpc, log_rq_size, ilog32(attr->rq_wqe_cnt - 1));
	DEVX_SET(qpc, qpc, dbr_umem_id, attr->db_umem_id);

	DEVX_SET(create_qp_in, in, wq_umem_id, attr->buff_umem_id);

	return mlx5dv_devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
}

int dr_devx_modify_qp_rst2init(struct ibv_context *ctx,
			       struct mlx5dv_devx_obj *qp_obj,
			       uint16_t port)
{
	uint32_t in[DEVX_ST_SZ_DW(rst2init_qp_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(rst2init_qp_out)] = {};
	void *qpc = DEVX_ADDR_OF(rst2init_qp_in, in, qpc);

	DEVX_SET(rst2init_qp_in, in, opcode, MLX5_CMD_OP_RST2INIT_QP);
	DEVX_SET(rst2init_qp_in, in, qpn, qp_obj->object_id);

	DEVX_SET(qpc, qpc, primary_address_path.vhca_port_num, port);
	DEVX_SET(qpc, qpc, pm_state, MLX5_QPC_PM_STATE_MIGRATED);
	DEVX_SET(qpc, qpc, rre, 1);
	DEVX_SET(qpc, qpc, rwe, 1);

	return mlx5dv_devx_obj_modify(qp_obj, in,
				      sizeof(in), out, sizeof(out));
}

#define DR_DEVX_ICM_UDP_PORT 49999

int dr_devx_modify_qp_init2rtr(struct ibv_context *ctx,
			       struct mlx5dv_devx_obj *qp_obj,
			       struct dr_devx_qp_rtr_attr *attr)
{
	uint32_t in[DEVX_ST_SZ_DW(init2rtr_qp_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(init2rtr_qp_out)] = {};
	void *qpc = DEVX_ADDR_OF(init2rtr_qp_in, in, qpc);

	DEVX_SET(init2rtr_qp_in, in, opcode, MLX5_CMD_OP_INIT2RTR_QP);
	DEVX_SET(init2rtr_qp_in, in, qpn, qp_obj->object_id);

	DEVX_SET(qpc, qpc, mtu, attr->mtu);
	DEVX_SET(qpc, qpc, log_msg_max, DR_CHUNK_SIZE_MAX - 1);
	DEVX_SET(qpc, qpc, remote_qpn, attr->qp_num);
	memcpy(DEVX_ADDR_OF(qpc, qpc, primary_address_path.rmac_47_32),
	       attr->dgid_attr.mac, sizeof(attr->dgid_attr.mac));
	memcpy(DEVX_ADDR_OF(qpc, qpc, primary_address_path.rgid_rip),
	       attr->dgid_attr.gid.raw, sizeof(attr->dgid_attr.gid.raw));
	DEVX_SET(qpc, qpc, primary_address_path.src_addr_index,
		 attr->sgid_index);

	if (attr->dgid_attr.roce_ver == MLX5_ROCE_VERSION_2)
		DEVX_SET(qpc, qpc, primary_address_path.udp_sport,
			 DR_DEVX_ICM_UDP_PORT);

	DEVX_SET(qpc, qpc, primary_address_path.vhca_port_num, attr->port_num);
	DEVX_SET(qpc, qpc, min_rnr_nak, 1);

	return mlx5dv_devx_obj_modify(qp_obj, in,
				      sizeof(in), out, sizeof(out));
}

int dr_devx_modify_qp_rtr2rts(struct ibv_context *ctx,
			      struct mlx5dv_devx_obj *qp_obj,
			      struct dr_devx_qp_rts_attr *attr)
{
	uint32_t in[DEVX_ST_SZ_DW(rtr2rts_qp_in)] = {};
	uint32_t out[DEVX_ST_SZ_DW(rtr2rts_qp_out)] = {};
	void *qpc = DEVX_ADDR_OF(rtr2rts_qp_in, in, qpc);

	DEVX_SET(rtr2rts_qp_in, in, opcode, MLX5_CMD_OP_RTR2RTS_QP);
	DEVX_SET(rtr2rts_qp_in, in, qpn, qp_obj->object_id);

	DEVX_SET(qpc, qpc, log_ack_req_freq, 0);
	DEVX_SET(qpc, qpc, retry_count, attr->retry_cnt);
	DEVX_SET(qpc, qpc, rnr_retry, attr->rnr_retry);

	return mlx5dv_devx_obj_modify(qp_obj, in,
				      sizeof(in), out, sizeof(out));
}

int dr_devx_query_gid(struct ibv_context *ctx, uint8_t vhca_port_num,
		      uint16_t index, struct dr_gid_attr *attr)
{
	uint32_t out[DEVX_ST_SZ_DW(query_roce_address_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(query_roce_address_in)] = {};
	int ret;

	DEVX_SET(query_roce_address_in, in, opcode,
		 MLX5_CMD_OP_QUERY_ROCE_ADDRESS);

	DEVX_SET(query_roce_address_in, in, roce_address_index, index);
	DEVX_SET(query_roce_address_in, in, vhca_port_num, vhca_port_num);

	ret = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (ret)
		return ret;

	memcpy(&attr->gid,
	       DEVX_ADDR_OF(query_roce_address_out,
			    out, roce_address.source_l3_address),
	       sizeof(attr->gid));
	memcpy(attr->mac,
	       DEVX_ADDR_OF(query_roce_address_out, out,
			    roce_address.source_mac_47_32),
	       sizeof(attr->mac));

	if (DEVX_GET(query_roce_address_out, out,
		     roce_address.roce_version) == MLX5_ROCE_VERSION_2)
		attr->roce_ver = MLX5_ROCE_VERSION_2;
	else
		attr->roce_ver = MLX5_ROCE_VERSION_1;

	return 0;
}
