/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2021 HiSilicon Limited.
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

enum hnsdv_context_attr_flags {
	HNSDV_CONTEXT_FLAGS_DCA = 1 << 0,
};

enum hnsdv_context_comp_mask {
	HNSDV_CONTEXT_MASK_DCA_PRIME_QPS = 1 << 0,
	HNSDV_CONTEXT_MASK_DCA_UNIT_SIZE = 1 << 1,
	HNSDV_CONTEXT_MASK_DCA_MAX_SIZE = 1 << 2,
	HNSDV_CONTEXT_MASK_DCA_MIN_SIZE = 1 << 3,
};

struct hnsdv_context_attr {
	uint64_t flags; /* Use enum hnsdv_context_attr_flags */
	uint64_t comp_mask; /* Use enum hnsdv_context_comp_mask */
	uint32_t dca_prime_qps;
	uint32_t dca_unit_size;
	uint64_t dca_max_size;
	uint64_t dca_min_size;
};

bool hnsdv_is_supported(struct ibv_device *device);
struct ibv_context *hnsdv_open_device(struct ibv_device *device,
				      struct hnsdv_context_attr *attr);

enum hnsdv_qp_create_flags {
	HNSDV_QP_CREATE_ENABLE_DCA_MODE = 1 << 0,
};

enum hnsdv_qp_init_attr_mask {
	HNSDV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS	= 1 << 0,
};

struct hnsdv_qp_init_attr {
	uint64_t comp_mask;	/* Use enum hnsdv_qp_init_attr_mask */
	uint32_t create_flags;	/* Use enum hnsdv_qp_create_flags */
};

struct ibv_qp *hnsdv_create_qp(struct ibv_context *context,
			       struct ibv_qp_init_attr_ex *qp_attr,
			       struct hnsdv_qp_init_attr *hns_qp_attr);

#ifdef __cplusplus
}
#endif

#endif /* __HNSDV_H__ */
