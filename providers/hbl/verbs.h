/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright 2022-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include <infiniband/verbs.h>

#ifndef __HBL_VERBS_H__
#define __HBL_VERBS_H__

struct ibv_pd *hbl_alloc_pd(struct ibv_context *uctx);
int hbl_dealloc_pd(struct ibv_pd *ibvpd);

struct ibv_qp *hbl_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr);
struct ibv_qp *hbl_create_qp_ex(struct ibv_context *context, struct ibv_qp_init_attr_ex *attr_ex);
struct ibv_cq *hbl_create_cq(struct ibv_context *context, int cqe,
			     struct ibv_comp_channel *channel, int comp_vector);
int hbl_destroy_qp(struct ibv_qp *iqp);
int hbl_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr, int attr_mask);
int hbl_destroy_cq(struct ibv_cq *ibvcq);
int hbl_query_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr, int attr_mask,
		 struct ibv_qp_init_attr *init_attr);
void hbl_async_event(struct ibv_context *ctx, struct ibv_async_event *event);

#endif /* __HBL_VERBS_H__ */
