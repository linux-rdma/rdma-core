/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2025 Advanced Micro Devices, Inc.  All rights reserved.
 */

#ifndef IONIC_DV_H
#define IONIC_DV_H

#include <stdbool.h>
#include <infiniband/verbs.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ionic_dv_ctx_get_udma_count - Get number of udma pipelines.
 */
uint8_t ionic_dv_ctx_get_udma_count(struct ibv_context *ibctx);

/**
 * ionic_dv_ctx_get_udma_mask - Get mask of udma pipeline ids.
 */
uint8_t ionic_dv_ctx_get_udma_mask(struct ibv_context *ibctx);

/**
 * ionic_dv_pd_get_udma_mask - Get mask of udma pipeline ids of pd or parent domain.
 */
uint8_t ionic_dv_pd_get_udma_mask(struct ibv_pd *ibpd);

/**
 * ionic_dv_pd_set_udma_mask - Restrict pipeline ids of pd or parent domain.
 *
 * Queues associated with this pd will be restricted to one of the pipelines enabled by
 * the mask at the time of queue creation.
 *
 * Recommended usage is to create a pd, then parent domains of that pd for each different
 * udma mask.  Set the desired udma mask on each parent domain.  Then, create queues
 * associated with the parent domain with the desired udma mask.
 *
 * Alternative usage is to create a pd, and set the desired udma mask prior to creating
 * each queue.  Changing the udma mask of the pd has no effect on previously created
 * queues.
 */
int ionic_dv_pd_set_udma_mask(struct ibv_pd *ibpd, uint8_t udma_mask);

/**
 * ionic_dv_pd_set_sqcmb - Specify send queue preference for controller memory bar.
 *
 * Send queues associated with this pd will use the controller memory bar according to
 * this preference at the time of queue creation.
 *
 * @enable - Allow the use of the controller memory bar.
 * @expdb - Allow the use of express doorbell optimizations.
 * @require - Require preferences to be met, no fallback.
 */
int ionic_dv_pd_set_sqcmb(struct ibv_pd *ibpd, bool enable, bool expdb, bool require);

/**
 * ionic_dv_pd_set_rqcmb - Specify receive queue preference for controller memory bar.
 *
 * Receive queues associated with this pd will use the controller memory bar according to
 * this preference at the time of queue creation.
 *
 * @enable - Allow the use of the controller memory bar.
 * @expdb - Allow the use of express doorbell optimizations.
 * @require - Require preferences to be met, no fallback.
 */
int ionic_dv_pd_set_rqcmb(struct ibv_pd *ibpd, bool enable, bool expdb, bool require);

enum ionic_dv_qp_init_attr_mask {
	IONIC_DV_QP_INIT_ATTR_MASK_FLAGS		= (1 << 0),
};

enum ionic_dv_qp_init_attr_flags {
	IONIC_DV_CREATE_QP_TYPE_RCCL		= 1 << 16,
	IONIC_DV_CREATE_QP_RCCL_DATA		= 1 << 17,
	IONIC_DV_CREATE_QP_RCCL_RDFENCE		= 1 << 18,
	IONIC_DV_CREATE_QP_RCCL_RX_OFFLOAD	= 1 << 19,
	IONIC_DV_CREATE_QP_RCCL_RCQ			= 1 << 24,
};

struct ionic_dv_qp_init_attr_ex {
	uint64_t comp_mask;
	uint32_t ionic_flags;
};

/**
 * ionic_dv_create_qp_ex - Create a queue pair with ionic-specific attributes.
 *
 * @ibctx - Device context.
 * @ex - Standard QP init attributes.
 * @ionic_ex - Ionic-specific QP init attributes (transport mode, rcq paths).
 */
struct ibv_qp *ionic_dv_create_qp_ex(struct ibv_context *ibctx,
				     struct ibv_qp_init_attr_ex *ex,
				     struct ionic_dv_qp_init_attr_ex *ionic_ex);

#ifdef __cplusplus
}
#endif

#endif /* IONIC_DV_H */
