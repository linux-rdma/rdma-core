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
 * ionic_dv_cq_get_udma_mask - Get mask of udma pipeline ids of completion queue.
 */
uint8_t ionic_dv_cq_get_udma_mask(struct ibv_cq *ibcq);

/**
 * ionic_dv_qp_get_udma_idx - Get udma pipeline id of queue pair.
 */
uint8_t ionic_dv_qp_get_udma_idx(struct ibv_qp *ibqp);

/**
 * ionic_dv_pd_set_expdb_mask - Specify expdb mask.
 *
 * Queues associated with this pd will attempt to have expdb on for WQE sizes
 * other than default (and supported by the NIC).
 *
 * @mask - IONIC_EXPDB_* bitmap
 */
int ionic_dv_pd_set_expdb_mask(struct ibv_pd *ibpd, uint8_t mask);

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

enum ionic_qp_init_attr_mask {
	IONIC_QP_INIT_ATTR_MASK_FLAGS		= 1 << 0,
};

enum ionic_qp_init_attr_flags {
	IONIC_QP_INIT_ATTR_RCCL			= 1 << 16,
	IONIC_QP_INIT_ATTR_RCCL_DATA		= 1 << 17,
	IONIC_QP_INIT_ATTR_RCCL_RDFENCE		= 1 << 18,
	IONIC_QP_INIT_ATTR_RCCL_RX_OFFLOAD	= 1 << 19,
	IONIC_QP_INIT_ATTR_RCCL_RCQ		= 1 << 24,
	IONIC_QP_INIT_ATTR_RCCL_P2P		= 1 << 25,
};

struct ionic_dv_qp_init_attr_ex {
	uint64_t comp_mask;
	uint32_t flags;
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

/**
 * ionic_dv_qp_set_gda - Enable or disable GPU-Direct Async (GDA) mode.
 *
 * In GDA mode, when the application calls ibv_post_send() or ibv_post_recv(), the
 * provider writes WQEs in the descriptor ring without ringing the doorbell.
 *
 * To ring the doorbell, after posting the work the application should query to get the
 * doorbell data, and later write that data to the memory mapped doorbell register.
 *
 * See also: ionic_dv_get_ctx()
 * See also: ionic_dv_qp_get_send_dbell_data()
 * See also: ionic_dv_qp_get_recv_dbell_data()
 *
 * @ibqp - Set GDA mode for this queue pair.
 * @enable_send - Enable GDA mode for the send queue.
 * @enable_recv - Enable GDA mode for the recv queue.
 */
int ionic_dv_qp_set_gda(struct ibv_qp *ibqp, bool enable_send, bool enable_recv);

#ifdef __cplusplus
}
#endif

#endif /* IONIC_DV_H */
