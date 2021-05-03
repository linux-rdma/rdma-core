/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <stdlib.h>
#include "mlx5dv_dr.h"

static uint32_t dr_vports_gen_vport_key(uint16_t vhca_gvmi, uint16_t vport_num)
{
	return (((uint32_t)vhca_gvmi) << 16) | vport_num;
}

static int dr_vports_calc_bucket_idx(uint32_t vport_key)
{
	return vport_key % DR_VPORTS_BUCKETS;
}

static struct dr_devx_vport_cap *
dr_vports_table_find_vport_num(struct dr_vports_table *h, uint16_t vhca_gvmi,
			       uint16_t vport_num)
{
	struct dr_devx_vport_cap *vport_cap;
	uint32_t vport_key;
	uint32_t idx;

	vport_key = dr_vports_gen_vport_key(vhca_gvmi, vport_num);
	idx = dr_vports_calc_bucket_idx(vport_key);

	vport_cap = h->buckets[idx];
	while (vport_cap) {
		if (vport_cap->vhca_gvmi == vhca_gvmi &&
		    vport_cap->num == vport_num)
			return vport_cap;
		vport_cap = vport_cap->next;
	}

	return NULL;
}

static void dr_vports_table_add_vport(struct dr_vports_table *h,
				      struct dr_devx_vport_cap *vport)
{
	uint32_t vport_key;
	uint32_t idx;

	vport_key = dr_vports_gen_vport_key(vport->vhca_gvmi, vport->num);
	idx = dr_vports_calc_bucket_idx(vport_key);

	vport->next = h->buckets[idx];
	h->buckets[idx] = vport;
}

static struct dr_devx_vport_cap *
dr_vports_table_query_and_add_vport(struct ibv_context *ctx,
				    struct dr_devx_vports *vports,
				    bool other_vport,
				    uint16_t vport_number)
{
	struct dr_devx_vport_cap *new_vport;
	int ret = 0;

	pthread_spin_lock(&vports->lock);
	new_vport = dr_vports_table_find_vport_num(vports->vports,
						   vports->esw_mngr.vhca_gvmi,
						   vport_number);
	if (new_vport)
		goto unlock_ret;

	new_vport = calloc(1, sizeof(*new_vport));
	if (!new_vport) {
		errno = ENOMEM;
		goto unlock_ret;
	}

	ret = dr_devx_query_esw_vport_context(ctx, other_vport,
					      vport_number,
					      &new_vport->icm_address_rx,
					      &new_vport->icm_address_tx);
	if (ret)
		goto unlock_free;

	ret = dr_devx_query_gvmi(ctx, other_vport, vport_number, &new_vport->vport_gvmi);
	if (ret)
		goto unlock_free;

	new_vport->num = vport_number;
	new_vport->vhca_gvmi = vports->esw_mngr.vhca_gvmi;
	dr_vports_table_add_vport(vports->vports, new_vport);

	pthread_spin_unlock(&vports->lock);
	return new_vport;

unlock_free:
	free(new_vport);
	new_vport = NULL;
unlock_ret:
	pthread_spin_unlock(&vports->lock);
	return new_vport;
}

struct dr_devx_vport_cap *
dr_vports_table_get_vport_cap(struct dr_devx_caps *caps, uint16_t vport)
{
	struct dr_devx_vports *vports = &caps->vports;
	struct dr_devx_vport_cap *vport_cap;
	bool other_vport = !!vport;

	/* no lock on vport_find since table is updated atomically */
	vport_cap = dr_vports_table_find_vport_num(vports->vports,
						   vports->esw_mngr.vhca_gvmi,
						   vport);
	if (vport_cap)
		return vport_cap;

	return dr_vports_table_query_and_add_vport(caps->dmn->ctx, vports,
						   other_vport, vport);
}

void dr_vports_table_add_wire(struct dr_devx_vports *vports)
{
	pthread_spin_lock(&vports->lock);
	vports->wire.num = WIRE_PORT;
	dr_vports_table_add_vport(vports->vports, &vports->wire);
	pthread_spin_unlock(&vports->lock);
}

void dr_vports_table_del_wire(struct dr_devx_vports *vports)
{
	struct dr_devx_vport_cap *wire = &vports->wire;
	struct dr_vports_table *h = vports->vports;
	struct dr_devx_vport_cap *vport, *prev;
	uint32_t vport_key;
	uint32_t idx;

	vport_key = dr_vports_gen_vport_key(wire->vhca_gvmi, wire->num);
	idx = dr_vports_calc_bucket_idx(vport_key);

	pthread_spin_lock(&vports->lock);
	if (h->buckets[idx] == wire) {
		h->buckets[idx] = wire->next;
		goto out_unlock;
	}

	vport = h->buckets[idx];
	while (vport) {
		if (vport == wire) {
			prev->next = vport->next;
			break;
		}
		prev = vport;
		vport = vport->next;
	}

out_unlock:
	pthread_spin_unlock(&vports->lock);
}

struct dr_vports_table *dr_vports_table_create(struct mlx5dv_dr_domain *dmn)
{
	struct dr_vports_table *h;

	h = calloc(1, sizeof(*h));
	if (!h) {
		errno = ENOMEM;
		return NULL;
	}

	return h;
}

void dr_vports_table_destroy(struct dr_vports_table *h)
{
	struct dr_devx_vport_cap *vport_cap, *next;
	uint32_t idx;

	for (idx = 0; idx < DR_VPORTS_BUCKETS; ++idx) {
		vport_cap = h->buckets[idx];
		while (vport_cap) {
			next = vport_cap->next;
			free(vport_cap);
			vport_cap = next;
		}
	}

	free(h);
}
