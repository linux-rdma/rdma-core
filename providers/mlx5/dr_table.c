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

#include <stdlib.h>
#include "mlx5dv_dr.h"

static void dr_table_uninit_nic(struct dr_table_rx_tx *nic_tbl)
{
	dr_htbl_put(nic_tbl->s_anchor);
}

static void dr_table_uninit_fdb(struct mlx5dv_dr_table *tbl)
{
	dr_table_uninit_nic(&tbl->rx);
	dr_table_uninit_nic(&tbl->tx);
}

static void dr_table_uninit(struct mlx5dv_dr_table *tbl)
{
	pthread_mutex_lock(&tbl->dmn->mutex);

	switch (tbl->dmn->type) {
	case MLX5DV_DR_DOMAIN_TYPE_NIC_RX:
		dr_table_uninit_nic(&tbl->rx);
		break;
	case MLX5DV_DR_DOMAIN_TYPE_NIC_TX:
		dr_table_uninit_nic(&tbl->tx);
		break;
	case MLX5DV_DR_DOMAIN_TYPE_FDB:
		dr_table_uninit_fdb(tbl);
		break;
	default:
		break;
	}

	pthread_mutex_unlock(&tbl->dmn->mutex);
}

static int dr_table_init_nic(struct mlx5dv_dr_domain *dmn,
			     struct dr_table_rx_tx *nic_tbl)
{
	struct dr_domain_rx_tx *nic_dmn = nic_tbl->nic_dmn;
	struct dr_htbl_connect_info info;
	int ret;

	nic_tbl->s_anchor = dr_ste_htbl_alloc(dmn->ste_icm_pool,
					      DR_CHUNK_SIZE_1,
					      DR_STE_LU_TYPE_DONT_CARE,
					      0);
	if (!nic_tbl->s_anchor)
		return errno;

	info.type = CONNECT_MISS;
	info.miss_icm_addr = nic_dmn->default_icm_addr;
	ret = dr_ste_htbl_init_and_postsend(dmn, nic_dmn, nic_tbl->s_anchor,
					    &info, true);
	if (ret)
		goto free_s_anchor;

	dr_htbl_get(nic_tbl->s_anchor);

	return 0;

free_s_anchor:
	dr_ste_htbl_free(nic_tbl->s_anchor);
	return ret;
}

static int dr_table_init_fdb(struct mlx5dv_dr_table *tbl)
{
	int ret;

	ret = dr_table_init_nic(tbl->dmn, &tbl->rx);
	if (ret)
		return ret;

	ret = dr_table_init_nic(tbl->dmn, &tbl->tx);
	if (ret)
		goto destroy_rx;

	return 0;

destroy_rx:
	dr_table_uninit_nic(&tbl->rx);
	return ret;
}

static int dr_table_init(struct mlx5dv_dr_table *tbl)
{
	int ret = 0;

	list_head_init(&tbl->matcher_list);

	pthread_mutex_lock(&tbl->dmn->mutex);

	switch (tbl->dmn->type) {
	case MLX5DV_DR_DOMAIN_TYPE_NIC_RX:
		tbl->table_type = FS_FT_NIC_RX;
		tbl->rx.nic_dmn = &tbl->dmn->info.rx;
		ret = dr_table_init_nic(tbl->dmn, &tbl->rx);
		break;
	case MLX5DV_DR_DOMAIN_TYPE_NIC_TX:
		tbl->table_type = FS_FT_NIC_TX;
		tbl->tx.nic_dmn = &tbl->dmn->info.tx;
		ret = dr_table_init_nic(tbl->dmn, &tbl->tx);
		break;
	case MLX5DV_DR_DOMAIN_TYPE_FDB:
		tbl->table_type = FS_FT_FDB;
		tbl->rx.nic_dmn = &tbl->dmn->info.rx;
		tbl->tx.nic_dmn = &tbl->dmn->info.tx;
		ret = dr_table_init_fdb(tbl);
		break;
	default:
		assert(false);
		break;
	}

	pthread_mutex_unlock(&tbl->dmn->mutex);

	return ret;
}

static int dr_table_create_devx_tbl(struct mlx5dv_dr_table *tbl)
{
	uint64_t icm_addr_rx = 0;
	uint64_t icm_addr_tx = 0;

	if (tbl->rx.s_anchor)
		icm_addr_rx = tbl->rx.s_anchor->chunk->icm_addr;

	if (tbl->tx.s_anchor)
		icm_addr_tx = tbl->tx.s_anchor->chunk->icm_addr;

	tbl->devx_obj = dr_devx_create_flow_table(tbl->dmn->ctx,
						  tbl->table_type,
						  icm_addr_rx,
						  icm_addr_tx,
						  tbl->dmn->info.caps.max_ft_level - 1);
	if (!tbl->devx_obj)
		return errno;

	return 0;
}

struct mlx5dv_dr_table *mlx5dv_dr_table_create(struct mlx5dv_dr_domain *dmn,
					     uint32_t level)
{
	struct mlx5dv_dr_table *tbl;
	int ret;

	atomic_fetch_add(&dmn->refcount, 1);

	if (level && !dmn->info.supp_sw_steering) {
		errno = EOPNOTSUPP;
		goto dec_ref;
	}

	tbl = calloc(1, sizeof(*tbl));
	if (!tbl) {
		errno = ENOMEM;
		goto dec_ref;
	}

	tbl->dmn = dmn;
	tbl->level = level;
	atomic_init(&tbl->refcount, 1);

	if (!dr_is_root_table(tbl)) {
		ret = dr_table_init(tbl);
		if (ret)
			goto free_tbl;

		ret = dr_table_create_devx_tbl(tbl);
		if (ret)
			goto uninit_tbl;
	}

	list_node_init(&tbl->tbl_list);
	list_add_tail(&dmn->tbl_list, &tbl->tbl_list);

	return tbl;

uninit_tbl:
	dr_table_uninit(tbl);
free_tbl:
	free(tbl);
dec_ref:
	atomic_fetch_sub(&dmn->refcount, 1);
	return NULL;
}

int mlx5dv_dr_table_destroy(struct mlx5dv_dr_table *tbl)
{
	int ret = 0;

	if (atomic_load(&tbl->refcount) > 1)
		return EBUSY;

	if (!dr_is_root_table(tbl)) {
		ret = mlx5dv_devx_obj_destroy(tbl->devx_obj);
		if (ret)
			return ret;

		dr_table_uninit(tbl);
	}

	list_del(&tbl->tbl_list);
	atomic_fetch_sub(&tbl->dmn->refcount, 1);
	free(tbl);

	return ret;
}
