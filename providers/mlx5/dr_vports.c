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
