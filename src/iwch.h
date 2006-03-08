/*
 * Copyright (c) 2006 Chelsio, Inc. All rights reserved.
 * Copyright (c) 2006 Open Grid Computing, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef IWCH_H
#define IWCH_H

#include <infiniband/driver.h>
#include <infiniband/arch.h>

#define HIDDEN		__attribute__((visibility ("hidden")))

#define PFX		"cxgb3: "

enum iwch_hca_type {
	CHELSIO_CXGB3
};

struct iwch_device {
	struct ibv_device ibv_dev;
	enum iwch_hca_type hca_type;
	int page_size;
};

struct iwch_context {
	struct ibv_context ibv_ctx;
};

struct iwch_pd {
	struct ibv_pd ibv_pd;
};

struct iwch_cq {
	struct ibv_cq ibv_cq;
	__u32 cqid;
	__u32 entries;
	__u64 physaddr;
	__u64 queue;
};

struct iwch_qp {
	struct ibv_qp ibv_qp;
	__u32 qpid;
	__u32 entries;
	__u64 physaddr;
	__u64 physsize;
	__u64 queue;
};

#define to_iwch_xxx(xxx, type)						\
	((struct iwch_##type *)					\
	 ((void *) ib##xxx - offsetof(struct iwch_##type, ibv_##xxx)))

static inline struct iwch_device *to_iwch_dev(struct ibv_device *ibdev)
{
	return to_iwch_xxx(dev, device);
}

static inline struct iwch_context *to_iwch_ctx(struct ibv_context *ibctx)
{
	return to_iwch_xxx(ctx, context);
}

static inline struct iwch_pd *to_iwch_pd(struct ibv_pd *ibpd)
{
	return to_iwch_xxx(pd, pd);
}

static inline struct iwch_cq *to_iwch_cq(struct ibv_cq *ibcq)
{
	return to_iwch_xxx(cq, cq);
}

static inline struct iwch_qp *to_iwch_qp(struct ibv_qp *ibqp)
{
	return to_iwch_xxx(qp, qp);
}


extern int iwch_query_device(struct ibv_context *context,
			     struct ibv_device_attr *attr);
extern int iwch_query_port(struct ibv_context *context, uint8_t port,
			   struct ibv_port_attr *attr);

extern struct ibv_pd *iwch_alloc_pd(struct ibv_context *context);
extern int iwch_free_pd(struct ibv_pd *pd);

extern struct ibv_mr *iwch_reg_mr(struct ibv_pd *pd, void *addr,
				  size_t length, enum ibv_access_flags access);
extern int iwch_dereg_mr(struct ibv_mr *mr);

struct ibv_cq *iwch_create_cq(struct ibv_context *context, int cqe,
			      struct ibv_comp_channel *channel,
			      int comp_vector);
extern int iwch_resize_cq(struct ibv_cq *cq, int cqe);
extern int iwch_destroy_cq(struct ibv_cq *cq);
extern int iwch_poll_cq(struct ibv_cq *cq, int ne, struct ibv_wc *wc);
extern int iwch_arm_cq(struct ibv_cq *cq, int solicited);
extern void iwch_cq_event(struct ibv_cq *cq);
extern void iwch_init_cq_buf(struct iwch_cq *cq, int nent);

extern struct ibv_srq *iwch_create_srq(struct ibv_pd *pd,
				       struct ibv_srq_init_attr *attr);
extern int iwch_modify_srq(struct ibv_srq *srq,
			   struct ibv_srq_attr *attr,
			   enum ibv_srq_attr_mask mask);
extern int iwch_destroy_srq(struct ibv_srq *srq);
extern int iwch_post_srq_recv(struct ibv_srq *ibsrq,
			      struct ibv_recv_wr *wr,
			      struct ibv_recv_wr **bad_wr);

extern struct ibv_qp *iwch_create_qp(struct ibv_pd *pd,
				     struct ibv_qp_init_attr *attr);
extern int iwch_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
			  enum ibv_qp_attr_mask attr_mask);
extern int iwch_destroy_qp(struct ibv_qp *qp);
extern int iwch_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
			  struct ibv_send_wr **bad_wr);
extern int iwch_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
			  struct ibv_recv_wr **bad_wr);
extern struct ibv_ah *iwch_create_ah(struct ibv_pd *pd,
			     struct ibv_ah_attr *ah_attr);
extern int iwch_destroy_ah(struct ibv_ah *ah);
extern int iwch_attach_mcast(struct ibv_qp *qp, union ibv_gid *gid,
			     uint16_t lid);
extern int iwch_detach_mcast(struct ibv_qp *qp, union ibv_gid *gid,
			     uint16_t lid);

#endif				/* IWCH_H */
