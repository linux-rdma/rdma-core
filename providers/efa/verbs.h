/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef __EFA_VERBS_H__
#define __EFA_VERBS_H__

#include <infiniband/driver.h>
#include <infiniband/verbs.h>

int efa_query_device(struct ibv_context *uctx, struct ibv_device_attr *attr);
int efa_query_port(struct ibv_context *uctx, uint8_t port,
		   struct ibv_port_attr *attr);
int efa_query_device_ex(struct ibv_context *context,
			const struct ibv_query_device_ex_input *input,
			struct ibv_device_attr_ex *attr, size_t attr_size);
struct ibv_pd *efa_alloc_pd(struct ibv_context *uctx);
int efa_dealloc_pd(struct ibv_pd *ibvpd);
struct ibv_mr *efa_reg_mr(struct ibv_pd *ibvpd, void *buf, size_t len,
			  uint64_t hca_va, int ibv_access_flags);
int efa_dereg_mr(struct verbs_mr *vmr);

struct ibv_cq *efa_create_cq(struct ibv_context *uctx, int ncqe,
			     struct ibv_comp_channel *ch, int vec);
int efa_destroy_cq(struct ibv_cq *ibvcq);
int efa_poll_cq(struct ibv_cq *ibvcq, int nwc, struct ibv_wc *wc);

struct ibv_qp *efa_create_qp(struct ibv_pd *ibvpd,
			     struct ibv_qp_init_attr *attr);
struct ibv_qp *efa_create_qp_ex(struct ibv_context *ibvctx,
				struct ibv_qp_init_attr_ex *attr_ex);
int efa_modify_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr,
		  int ibv_qp_attr_mask);
int efa_query_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr, int attr_mask,
		 struct ibv_qp_init_attr *init_attr);
int efa_destroy_qp(struct ibv_qp *ibvqp);
int efa_post_send(struct ibv_qp *ibvqp, struct ibv_send_wr *wr,
		  struct ibv_send_wr **bad);
int efa_post_recv(struct ibv_qp *ibvqp, struct ibv_recv_wr *wr,
		  struct ibv_recv_wr **bad);

struct ibv_ah *efa_create_ah(struct ibv_pd *ibvpd, struct ibv_ah_attr *attr);
int efa_destroy_ah(struct ibv_ah *ibvah);

#endif /* __EFA_VERBS_H__ */
