/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2025 Advanced Micro Devices, Inc.  All rights reserved.
 */

#ifndef IONIC_DV_H
#define IONIC_DV_H

#include <stdbool.h>
#include <infiniband/verbs.h>

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

#endif /* IONIC_DV_H */
