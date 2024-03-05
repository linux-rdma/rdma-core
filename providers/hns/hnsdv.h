/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2024 Hisilicon Limited.
 */

#ifndef __HNSDV_H__
#define __HNSDV_H__

#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <infiniband/verbs.h>

#ifdef __cplusplus
extern "C" {
#endif

struct hnsdv_qp_init_attr {
	uint64_t comp_mask;
};

struct hnsdv_context {
	uint64_t comp_mask;
};

bool hnsdv_is_supported(struct ibv_device *device);
int hnsdv_query_device(struct ibv_context *ctx_in,
		       struct hnsdv_context *attrs_out);
struct ibv_qp *hnsdv_create_qp(struct ibv_context *context,
			       struct ibv_qp_init_attr_ex *qp_attr,
			       struct hnsdv_qp_init_attr *hns_qp_attr);

#ifdef __cplusplus
}
#endif

#endif /* __HNSDV_H__ */
