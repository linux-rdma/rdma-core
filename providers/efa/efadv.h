/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2019-2025 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef __EFADV_H__
#define __EFADV_H__

#include <stdio.h>
#include <sys/types.h>
#include <stdbool.h>

#include <infiniband/verbs.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	EFADV_DEVICE_ATTR_CAPS_RDMA_READ = 1 << 0,
	EFADV_DEVICE_ATTR_CAPS_RNR_RETRY = 1 << 1,
	EFADV_DEVICE_ATTR_CAPS_CQ_WITH_SGID = 1 << 2,
	EFADV_DEVICE_ATTR_CAPS_RDMA_WRITE = 1 << 3,
	EFADV_DEVICE_ATTR_CAPS_UNSOLICITED_WRITE_RECV = 1 << 4,
	EFADV_DEVICE_ATTR_CAPS_CQ_WITH_EXT_MEM_DMABUF = 1 << 5,
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

enum {
	/* Values must match the values in efa-abi.h */
	EFADV_QP_DRIVER_TYPE_SRD = 0,
};

struct ibv_qp *efadv_create_driver_qp(struct ibv_pd *ibvpd,
				      struct ibv_qp_init_attr *attr,
				      uint32_t driver_qp_type);

enum {
	EFADV_QP_FLAGS_UNSOLICITED_WRITE_RECV = 1 << 0,
};

struct efadv_qp_init_attr {
	uint64_t comp_mask;
	uint32_t driver_qp_type;
	uint16_t flags;
	uint8_t sl;
	uint8_t reserved;
};

struct ibv_qp *efadv_create_qp_ex(struct ibv_context *ibvctx,
				  struct ibv_qp_init_attr_ex *attr_ex,
				  struct efadv_qp_init_attr *efa_attr,
				  uint32_t inlen);

struct efadv_wq_attr {
	uint64_t comp_mask;
	uint8_t *buffer;
	uint32_t entry_size;
	uint32_t num_entries;
	uint32_t *doorbell;
	uint32_t max_batch;
	uint8_t reserved[4];
};

int efadv_query_qp_wqs(struct ibv_qp *ibvqp, struct efadv_wq_attr *sq_attr,
		       struct efadv_wq_attr *rq_attr, uint32_t inlen);

struct efadv_cq {
	uint64_t comp_mask;
	int (*wc_read_sgid)(struct efadv_cq *efadv_cq, union ibv_gid *sgid);
	bool (*wc_is_unsolicited)(struct efadv_cq *efadv_cq);
};

enum {
	EFADV_WC_EX_WITH_SGID = 1 << 0,
	EFADV_WC_EX_WITH_IS_UNSOLICITED = 1 << 1,
};

enum {
	EFADV_CQ_INIT_FLAGS_EXT_MEM_DMABUF = 1 << 0,
};

struct efadv_cq_init_attr {
	uint64_t comp_mask;
	uint64_t wc_flags;
	uint64_t flags;
	struct {
		uint8_t *buffer;
		uint64_t length;
		uint64_t offset;
		int32_t fd;
		uint8_t reserved[4];
	} ext_mem_dmabuf;
};

struct ibv_cq_ex *efadv_create_cq(struct ibv_context *ibvctx,
				  struct ibv_cq_init_attr_ex *attr_ex,
				  struct efadv_cq_init_attr *efa_attr,
				  uint32_t inlen);

struct efadv_cq_attr {
	uint64_t comp_mask;
	uint8_t *buffer;
	uint32_t entry_size;
	uint32_t num_entries;
	uint32_t *doorbell;
};

int efadv_query_cq(struct ibv_cq *ibvcq, struct efadv_cq_attr *attr, uint32_t inlen);

struct efadv_cq *efadv_cq_from_ibv_cq_ex(struct ibv_cq_ex *ibvcqx);

static inline int efadv_wc_read_sgid(struct efadv_cq *efadv_cq,
				     union ibv_gid *sgid)
{
	return efadv_cq->wc_read_sgid(efadv_cq, sgid);
}

static inline bool efadv_wc_is_unsolicited(struct efadv_cq *efadv_cq)
{
	return efadv_cq->wc_is_unsolicited(efadv_cq);
}

enum {
	EFADV_MR_ATTR_VALIDITY_RECV_IC_ID = 1 << 0,
	EFADV_MR_ATTR_VALIDITY_RDMA_READ_IC_ID = 1 << 1,
	EFADV_MR_ATTR_VALIDITY_RDMA_RECV_IC_ID = 1 << 2,
};

struct efadv_mr_attr {
	uint64_t comp_mask;
	uint16_t ic_id_validity;
	uint16_t recv_ic_id;
	uint16_t rdma_read_ic_id;
	uint16_t rdma_recv_ic_id;
};

int efadv_query_mr(struct ibv_mr *ibvmr, struct efadv_mr_attr *attr, uint32_t inlen);

#ifdef __cplusplus
}
#endif

#endif /* __EFADV_H__ */
