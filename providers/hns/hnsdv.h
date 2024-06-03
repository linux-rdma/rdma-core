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

enum hnsdv_qp_congest_ctrl_type {
	HNSDV_QP_CREATE_ENABLE_DCQCN = 1 << 0,
	HNSDV_QP_CREATE_ENABLE_LDCP = 1 << 1,
	HNSDV_QP_CREATE_ENABLE_HC3 = 1 << 2,
	HNSDV_QP_CREATE_ENABLE_DIP = 1 << 3,
};

enum hnsdv_qp_init_attr_mask {
	HNSDV_QP_INIT_ATTR_MASK_QP_CONGEST_TYPE	= 1 << 1,
};

struct hnsdv_qp_init_attr {
	uint64_t comp_mask; /* Use enum hnsdv_qp_init_attr_mask */
	uint32_t create_flags;
	uint8_t congest_type; /* Use enum hnsdv_qp_congest_ctrl_type */
	uint8_t reserved[3];
};

enum hnsdv_query_context_comp_mask {
	HNSDV_CONTEXT_MASK_CONGEST_TYPE = 1 << 0,
};

struct hnsdv_context {
	uint64_t comp_mask; /* Use enum hnsdv_query_context_comp_mask */
	uint64_t flags;
	uint8_t congest_type; /* Use enum hnsdv_qp_congest_ctrl_type */
	uint8_t reserved[7];
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
