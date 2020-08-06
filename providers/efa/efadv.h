/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef __EFADV_H__
#define __EFADV_H__

#include <stdio.h>
#include <sys/types.h>

#include <infiniband/verbs.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	/* Values must match the values in efa-abi.h */
	EFADV_QP_DRIVER_TYPE_SRD = 0,
};

struct ibv_qp *efadv_create_driver_qp(struct ibv_pd *ibvpd,
				      struct ibv_qp_init_attr *attr,
				      uint32_t driver_qp_type);

struct efadv_qp_init_attr {
	uint64_t comp_mask;
	uint32_t driver_qp_type;
	uint8_t reserved[4];
};

struct ibv_qp *efadv_create_qp_ex(struct ibv_context *ibvctx,
				  struct ibv_qp_init_attr_ex *attr_ex,
				  struct efadv_qp_init_attr *efa_attr,
				  uint32_t inlen);

enum {
	EFADV_DEVICE_ATTR_CAPS_RDMA_READ = 1 << 0,
};

struct efadv_device_attr {
	uint64_t comp_mask;
	uint32_t max_sq_wr;
	uint32_t max_rq_wr;
	uint16_t max_sq_sge;
	uint16_t max_rq_sge;
	uint16_t inline_buf_size;
	uint8_t reserved[2];
	uint32_t device_caps;
	uint32_t max_rdma_size;
};

int efadv_query_device(struct ibv_context *ibvctx,
		       struct efadv_device_attr *attr,
		       uint32_t inlen);

struct efadv_ah_attr {
	uint64_t comp_mask;
	uint16_t ahn;
	uint8_t reserved[6];
};

int efadv_query_ah(struct ibv_ah *ibvah, struct efadv_ah_attr *attr,
		   uint32_t inlen);

#ifdef __cplusplus
}
#endif

#endif /* __EFADV_H__ */
