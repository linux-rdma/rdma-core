/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2019-2023 Amazon.com, Inc. or its affiliates. All rights reserved.
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
	EFADV_DEVICE_ATTR_CAPS_RNR_RETRY = 1 << 1,
	EFADV_DEVICE_ATTR_CAPS_CQ_WITH_SGID = 1 << 2,
	EFADV_DEVICE_ATTR_CAPS_RDMA_WRITE = 1 << 3,
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

struct efadv_cq {
	uint64_t comp_mask;
	int (*wc_read_sgid)(struct efadv_cq *efadv_cq, union ibv_gid *sgid);
};

enum {
	EFADV_WC_EX_WITH_SGID = 1 << 0,
};

struct efadv_cq_init_attr {
	uint64_t comp_mask;
	uint64_t wc_flags;
};

struct ibv_cq_ex *efadv_create_cq(struct ibv_context *ibvctx,
				  struct ibv_cq_init_attr_ex *attr_ex,
				  struct efadv_cq_init_attr *efa_attr,
				  uint32_t inlen);

struct efadv_cq *efadv_cq_from_ibv_cq_ex(struct ibv_cq_ex *ibvcqx);

static inline int efadv_wc_read_sgid(struct efadv_cq *efadv_cq,
				     union ibv_gid *sgid)
{
	return efadv_cq->wc_read_sgid(efadv_cq, sgid);
}

#ifdef __cplusplus
}
#endif

#endif /* __EFADV_H__ */
