/*
 * Copyright (c) 2019, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *	Redistribution and use in source and binary forms, with or
 *	without modification, are permitted provided that the following
 *	conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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

#include <unistd.h>
#include <stdlib.h>
#include "mlx5dv_dr.h"

enum {
	MLX5DV_DR_DOMAIN_SYNC_SUP_FLAGS =
		(MLX5DV_DR_DOMAIN_SYNC_FLAGS_SW |
		 MLX5DV_DR_DOMAIN_SYNC_FLAGS_HW |
		 MLX5DV_DR_DOMAIN_SYNC_FLAGS_MEM),
};

static int dr_domain_init_resources(struct mlx5dv_dr_domain *dmn)
{
	int ret = -1;

	dmn->ste_ctx = dr_ste_get_ctx(dmn->info.caps.sw_format_ver);
	if (!dmn->ste_ctx) {
		dr_dbg(dmn, "Couldn't initialize STE context\n");
		return errno;
	}

	dmn->pd = ibv_alloc_pd(dmn->ctx);
	if (!dmn->pd) {
		dr_dbg(dmn, "Couldn't allocate PD\n");
		return ret;
	}

	dmn->uar = mlx5dv_devx_alloc_uar(dmn->ctx,
					 MLX5_IB_UAPI_UAR_ALLOC_TYPE_NC);

	if (!dmn->uar)
		dmn->uar = mlx5dv_devx_alloc_uar(dmn->ctx,
						 MLX5_IB_UAPI_UAR_ALLOC_TYPE_BF);

	if (!dmn->uar) {
		dr_dbg(dmn, "Can't allocate UAR\n");
		goto clean_pd;
	}

	dmn->ste_icm_pool = dr_icm_pool_create(dmn, DR_ICM_TYPE_STE);
	if (!dmn->ste_icm_pool) {
		dr_dbg(dmn, "Couldn't get icm memory for %s\n",
		       ibv_get_device_name(dmn->ctx->device));
		goto clean_uar;
	}

	dmn->action_icm_pool = dr_icm_pool_create(dmn, DR_ICM_TYPE_MODIFY_ACTION);
	if (!dmn->action_icm_pool) {
		dr_dbg(dmn, "Couldn't get action icm memory for %s\n",
		       ibv_get_device_name(dmn->ctx->device));
		goto free_ste_icm_pool;
	}

	ret = dr_send_ring_alloc(dmn);
	if (ret) {
		dr_dbg(dmn, "Couldn't create send-ring for %s\n",
		       ibv_get_device_name(dmn->ctx->device));
		goto free_action_icm_pool;
	}

	return 0;

free_action_icm_pool:
	dr_icm_pool_destroy(dmn->action_icm_pool);
free_ste_icm_pool:
	dr_icm_pool_destroy(dmn->ste_icm_pool);
clean_uar:
	mlx5dv_devx_free_uar(dmn->uar);
clean_pd:
	ibv_dealloc_pd(dmn->pd);

	return ret;
}

static void dr_free_resources(struct mlx5dv_dr_domain *dmn)
{
	dr_send_ring_free(dmn);
	dr_icm_pool_destroy(dmn->action_icm_pool);
	dr_icm_pool_destroy(dmn->ste_icm_pool);
	mlx5dv_devx_free_uar(dmn->uar);
	ibv_dealloc_pd(dmn->pd);
}

static int dr_domain_vports_init(struct mlx5dv_dr_domain *dmn)
{
	struct dr_devx_vports *vports = &dmn->info.caps.vports;
	int ret;

	ret = pthread_spin_init(&vports->lock,
				PTHREAD_PROCESS_PRIVATE);
	if (ret) {
		errno = ret;
		return ret;
	}

	vports->vports = dr_vports_table_create(dmn);
	if (!vports->vports)
		goto free_spin_lock;

	dr_vports_table_add_wire(vports);
	return 0;

free_spin_lock:
	pthread_spin_destroy(&vports->lock);
	return errno;
}

static void dr_domain_vports_uninit(struct mlx5dv_dr_domain *dmn)
{
	struct dr_devx_vports *vports = &dmn->info.caps.vports;

	if (vports->vports) {
		/* Wire port must be deleted before destroying vports table,
		 * since it is not allocated dynamically but inserted to table
		 * as such.
		 */
		dr_vports_table_del_wire(vports);
		dr_vports_table_destroy(vports->vports);
		vports->vports = NULL;
	}
	pthread_spin_destroy(&vports->lock);
}

static int dr_domain_query_esw_mgr(struct mlx5dv_dr_domain *dmn,
				   struct dr_devx_vport_cap *esw_mngr)
{
	int ret;

	/* Query E-Switch manager PF/ECPF */
	ret = dr_devx_query_esw_vport_context(dmn->ctx, false, 0,
					      &esw_mngr->icm_address_rx,
					      &esw_mngr->icm_address_tx);
	if (ret)
		return ret;

	/* E-Switch manager gvmi and vhca id are the same */
	esw_mngr->vhca_gvmi = dmn->info.caps.gvmi;
	esw_mngr->vport_gvmi = dmn->info.caps.gvmi;

	return 0;
}

static int dr_domain_query_and_set_ib_ports(struct mlx5dv_dr_domain *dmn)
{
	struct dr_devx_vports *vports = &dmn->info.caps.vports;
	int i;

	vports->ib_ports = calloc(vports->num_ports, sizeof(struct dr_devx_vport_cap *));
	if (!vports->ib_ports) {
		errno = ENOMEM;
		return errno;
	}

	/* Best effort to query available ib ports */
	for (i = 1; i <= vports->num_ports; i++)
		dr_vports_table_get_ib_port_cap(&dmn->info.caps, i);

	return 0;
}

static int dr_domain_query_fdb_caps(struct ibv_context *ctx,
				    struct mlx5dv_dr_domain *dmn)
{
	struct dr_devx_vports *vports = &dmn->info.caps.vports;
	struct dr_esw_caps esw_caps = {};
	int ret;

	if (!dmn->info.caps.eswitch_manager)
		return 0;

	ret = dr_domain_query_esw_mgr(dmn, &vports->esw_mngr);
	if (ret)
		return ret;

	ret = dr_devx_query_esw_caps(ctx, &esw_caps);
	if (ret)
		return ret;

	vports->num_ports = dmn->info.attr.phys_port_cnt_ex;

	/* Set uplink */
	vports->wire.icm_address_rx = esw_caps.uplink_icm_address_rx;
	vports->wire.icm_address_tx = esw_caps.uplink_icm_address_tx;
	vports->wire.vhca_gvmi = vports->esw_mngr.vhca_gvmi;
	vports->wire.num = WIRE_PORT;

	/* Set FDB general caps */
	dmn->info.caps.fdb_sw_owner = esw_caps.sw_owner;
	dmn->info.caps.fdb_sw_owner_v2 = esw_caps.sw_owner_v2;
	dmn->info.caps.esw_rx_drop_address = esw_caps.drop_icm_address_rx;
	dmn->info.caps.esw_tx_drop_address = esw_caps.drop_icm_address_tx;

	/* Query all ib ports if supported */
	ret = dr_domain_query_and_set_ib_ports(dmn);
	if (ret) {
		dr_dbg(dmn, "Failed to query ib vports\n");
		return ret;
	}
	return 0;
}

static int dr_domain_caps_init(struct ibv_context *ctx,
			       struct mlx5dv_dr_domain *dmn)
{
	struct ibv_port_attr port_attr = {};
	int ret;

	dmn->info.caps.dmn = dmn;

	ret = ibv_query_port(ctx, 1, &port_attr);
	if (ret) {
		dr_dbg(dmn, "Failed to query port\n");
		return ret;
	}

	if (port_attr.link_layer != IBV_LINK_LAYER_ETHERNET) {
		dr_dbg(dmn, "Failed to allocate domain, bad link type\n");
		errno = EOPNOTSUPP;
		return errno;
	}

	ret = ibv_query_device_ex(ctx, NULL, &dmn->info.attr);
	if (ret)
		return ret;

	ret = dr_devx_query_device(ctx, &dmn->info.caps);
	if (ret)
		/* Ignore devx query failure to allow steering on root level
		 * tables in case devx is not supported over mlx5dv_dr API
		 */
		return 0;

	/* Non FDB type is supported over root table or when we can enable
	 * force-loopback.
	 */
	if ((dmn->type != MLX5DV_DR_DOMAIN_TYPE_FDB) &&
	    !dr_send_allow_fl(&dmn->info.caps))
		return 0;

	ret = dr_domain_vports_init(dmn);
	if (ret)
		return ret;

	ret = dr_domain_query_fdb_caps(ctx, dmn);
	if (ret)
		goto uninit_vports;

	switch (dmn->type) {
	case MLX5DV_DR_DOMAIN_TYPE_NIC_RX:
		if (!dmn->info.caps.rx_sw_owner &&
		    !(dmn->info.caps.rx_sw_owner_v2 &&
		      dmn->info.caps.sw_format_ver <= MLX5_HW_CONNECTX_6DX))
			return 0;

		dmn->info.supp_sw_steering = true;
		dmn->info.rx.type = DR_DOMAIN_NIC_TYPE_RX;
		dmn->info.rx.default_icm_addr = dmn->info.caps.nic_rx_drop_address;
		dmn->info.rx.drop_icm_addr = dmn->info.caps.nic_rx_drop_address;
		break;
	case MLX5DV_DR_DOMAIN_TYPE_NIC_TX:
		if (!dmn->info.caps.tx_sw_owner &&
		    !(dmn->info.caps.tx_sw_owner_v2 &&
		      dmn->info.caps.sw_format_ver <= MLX5_HW_CONNECTX_6DX))
			return 0;

		dmn->info.supp_sw_steering = true;
		dmn->info.tx.type = DR_DOMAIN_NIC_TYPE_TX;
		dmn->info.tx.default_icm_addr = dmn->info.caps.nic_tx_allow_address;
		dmn->info.tx.drop_icm_addr = dmn->info.caps.nic_tx_drop_address;
		break;
	case MLX5DV_DR_DOMAIN_TYPE_FDB:
		if (!dmn->info.caps.eswitch_manager)
			return 0;

		if (!dmn->info.caps.fdb_sw_owner &&
		    !(dmn->info.caps.fdb_sw_owner_v2 &&
		      dmn->info.caps.sw_format_ver <= MLX5_HW_CONNECTX_6DX))
			return 0;

		dmn->info.rx.type = DR_DOMAIN_NIC_TYPE_RX;
		dmn->info.tx.type = DR_DOMAIN_NIC_TYPE_TX;

		dmn->info.supp_sw_steering = true;
		dmn->info.tx.default_icm_addr = dmn->info.caps.vports.esw_mngr.icm_address_tx;
		dmn->info.rx.default_icm_addr = dmn->info.caps.vports.esw_mngr.icm_address_rx;
		dmn->info.rx.drop_icm_addr = dmn->info.caps.esw_rx_drop_address;
		dmn->info.tx.drop_icm_addr = dmn->info.caps.esw_tx_drop_address;
		break;
	default:
		dr_dbg(dmn, "Invalid domain\n");
		ret = EINVAL;
		break;
	}

	return ret;

uninit_vports:
	dr_domain_vports_uninit(dmn);
	return ret;
}

static void dr_domain_caps_uninit(struct mlx5dv_dr_domain *dmn)
{
	dr_domain_vports_uninit(dmn);
}

bool dr_domain_is_support_ste_icm_size(struct mlx5dv_dr_domain *dmn,
				       uint32_t req_log_icm_sz)
{
	if (dmn->info.caps.log_icm_size < req_log_icm_sz + DR_STE_LOG_SIZE)
		return false;

	return true;
}

bool dr_domain_set_max_ste_icm_size(struct mlx5dv_dr_domain *dmn,
				    uint32_t req_log_icm_sz)
{
	if (!dr_domain_is_support_ste_icm_size(dmn, req_log_icm_sz))
		return false;

	if (dmn->info.max_log_sw_icm_sz < req_log_icm_sz) {
		dmn->info.max_log_sw_icm_sz = req_log_icm_sz;
		dr_icm_pool_set_pool_max_log_chunk_sz(dmn->ste_icm_pool,
						      dmn->info.max_log_sw_icm_sz);
	}
	return true;
}

static int dr_domain_check_icm_memory_caps(struct mlx5dv_dr_domain *dmn)
{
	uint32_t max_req_bytes_log, max_req_chunks_log;

	/* Check for minimum ICM log byte size requirements */
	if (dmn->info.caps.log_modify_hdr_icm_size < DR_CHUNK_SIZE_4K +
	    DR_MODIFY_ACTION_LOG_SIZE) {
		errno = ENOMEM;
		return errno;
	}

	if (dmn->info.caps.log_icm_size < DR_CHUNK_SIZE_1024K +
	    DR_STE_LOG_SIZE) {
		errno = ENOMEM;
		return errno;
	}

	/* Current code tries to use large allocations to improve our internal
	 * memory allocation (less DMs and less FW calls).
	 * When creating multiple domains on the same PF, we want to make sure
	 * we don't deplete all of the ICM resources on a single domain.
	 * To provide some functionality with a limited resource we will use
	 * up to 1/8 of the total available size allowing opening a domain
	 * of each type.
	 */
	max_req_bytes_log = dmn->info.caps.log_modify_hdr_icm_size - 3;
	max_req_chunks_log = max_req_bytes_log - DR_MODIFY_ACTION_LOG_SIZE;
	dmn->info.max_log_action_icm_sz =
		min_t(uint32_t, DR_CHUNK_SIZE_1024K, max_req_chunks_log);

	max_req_bytes_log = dmn->info.caps.log_icm_size - 3;
	max_req_chunks_log = max_req_bytes_log - DR_STE_LOG_SIZE;
	dmn->info.max_log_sw_icm_sz =
		min_t(uint32_t, DR_CHUNK_SIZE_1024K, max_req_chunks_log);

	return 0;
}

struct mlx5dv_dr_domain *
mlx5dv_dr_domain_create(struct ibv_context *ctx,
			enum mlx5dv_dr_domain_type type)
{
	struct mlx5dv_dr_domain *dmn;
	int ret;

	if (type > MLX5DV_DR_DOMAIN_TYPE_FDB) {
		errno = EINVAL;
		return NULL;
	}

	dmn = calloc(1, sizeof(*dmn));
	if (!dmn) {
		errno = ENOMEM;
		return NULL;
	}

	dmn->ctx = ctx;
	dmn->type = type;
	atomic_init(&dmn->refcount, 1);
	list_head_init(&dmn->tbl_list);

	ret = pthread_spin_init(&dmn->debug_lock, PTHREAD_PROCESS_PRIVATE);
	if (ret) {
		errno = ret;
		goto free_domain;
	}

	ret = dr_domain_nic_lock_init(&dmn->info.rx);
	if (ret)
		goto free_debug_lock;

	ret = dr_domain_nic_lock_init(&dmn->info.tx);
	if (ret)
		goto uninit_rx_locks;

	if (dr_domain_caps_init(ctx, dmn)) {
		dr_dbg(dmn, "Failed init domain, no caps\n");
		goto uninit_tx_locks;
	}

	/* Allocate resources */
	if (dmn->info.supp_sw_steering) {

		if (dr_domain_check_icm_memory_caps(dmn))
			goto uninit_caps;

		ret = dr_domain_init_resources(dmn);
		if (ret) {
			dr_dbg(dmn, "Failed init domain resources for %s\n",
			       ibv_get_device_name(ctx->device));
			goto uninit_caps;
		}
		/* Init CRC table for htbl CRC calculation */
		dr_crc32_init_table();
	}

	return dmn;

uninit_caps:
	dr_domain_caps_uninit(dmn);
uninit_tx_locks:
	dr_domain_nic_lock_uninit(&dmn->info.tx);
uninit_rx_locks:
	dr_domain_nic_lock_uninit(&dmn->info.rx);
free_debug_lock:
	pthread_spin_destroy(&dmn->debug_lock);
free_domain:
	free(dmn);
	return NULL;
}

/*
 * Assure synchronization of the device steering tables with updates made by SW
 * insertion.
 */
int mlx5dv_dr_domain_sync(struct mlx5dv_dr_domain *dmn, uint32_t flags)
{
	int ret = 0;

	if (!dmn->info.supp_sw_steering ||
	    !check_comp_mask(flags, MLX5DV_DR_DOMAIN_SYNC_SUP_FLAGS)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	if (flags & MLX5DV_DR_DOMAIN_SYNC_FLAGS_SW) {
		ret = dr_send_ring_force_drain(dmn);
		if (ret)
			return ret;
	}

	if (flags & MLX5DV_DR_DOMAIN_SYNC_FLAGS_HW) {
		ret = dr_devx_sync_steering(dmn->ctx);
		if (ret)
			return ret;
	}

	if (flags & MLX5DV_DR_DOMAIN_SYNC_FLAGS_MEM) {
		if (dmn->ste_icm_pool) {
			ret = dr_icm_pool_sync_pool(dmn->ste_icm_pool);
			if (ret)
				return ret;
		}

		if (dmn->action_icm_pool)
			ret = dr_icm_pool_sync_pool(dmn->action_icm_pool);
	}

	return ret;
}

void mlx5dv_dr_domain_set_reclaim_device_memory(struct mlx5dv_dr_domain *dmn,
						bool enable)
{
	dr_domain_lock(dmn);
	if (enable)
		dmn->flags |= DR_DOMAIN_FLAG_MEMORY_RECLAIM;
	else
		dmn->flags &= ~DR_DOMAIN_FLAG_MEMORY_RECLAIM;
	dr_domain_unlock(dmn);
}

void mlx5dv_dr_domain_allow_duplicate_rules(struct mlx5dv_dr_domain *dmn,
					    bool allow)
{
	dr_domain_lock(dmn);
	if (allow)
		dmn->flags &= ~DR_DOMAIN_FLAG_DISABLE_DUPLICATE_RULES;
	else
		dmn->flags |= DR_DOMAIN_FLAG_DISABLE_DUPLICATE_RULES;
	dr_domain_unlock(dmn);
}

int mlx5dv_dr_domain_destroy(struct mlx5dv_dr_domain *dmn)
{
	if (atomic_load(&dmn->refcount) > 1)
		return EBUSY;

	if (dmn->info.supp_sw_steering) {
		/* make sure resources are not used by the hardware */
		dr_devx_sync_steering(dmn->ctx);
		dr_free_resources(dmn);
	}

	dr_domain_caps_uninit(dmn);

	dr_domain_nic_lock_uninit(&dmn->info.tx);
	dr_domain_nic_lock_uninit(&dmn->info.rx);
	pthread_spin_destroy(&dmn->debug_lock);

	free(dmn);
	return 0;
}
