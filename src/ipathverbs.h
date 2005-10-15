/*
 * Copyright (c) 2005. PathScale, Inc. All rights reserved.
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
 *
 * Patent licenses, if any, provided herein do not apply to
 * combinations of this program with other software, or any other
 * product whatsoever.
 */

#ifndef IPATH_H
#define IPATH_H

#include <endian.h>
#include <byteswap.h>

#include <infiniband/driver.h>
#include <infiniband/arch.h>
#include <infiniband/verbs.h>

#define HIDDEN		__attribute__((visibility ("hidden")))

#define PFX		"ipath: "

enum ipath_hca_type {
	IPATH_SPINNERET,
	IPATH_WALDO,
	IPATH_MONTY,
};

struct ipath_device {
	struct ibv_device	ibv_dev;
	enum ipath_hca_type	hca_type;
	int			page_size;
};

struct ipath_context {
	struct ibv_context	ibv_ctx;
};

#define to_ixxx(xxx, type)						\
	((struct ipath_##type *)					\
	 ((void *) ib##xxx - offsetof(struct ipath_##type, ibv_##xxx)))

static inline struct ipath_context *to_ictx(struct ibv_context *ibctx)
{
	return to_ixxx(ctx, context);
}

extern int ipath_query_device(struct ibv_context *context,
			      struct ibv_device_attr *attr);

extern int ipath_query_port(struct ibv_context *context, uint8_t port,
			    struct ibv_port_attr *attr);

struct ibv_pd *ipath_alloc_pd(struct ibv_context *pd);

int ipath_free_pd(struct ibv_pd *pd);

struct ibv_mr *ipath_reg_mr(struct ibv_pd *pd, void *addr,
			    size_t length, enum ibv_access_flags access);

int ipath_dereg_mr(struct ibv_mr *mr);

struct ibv_cq *ipath_create_cq(struct ibv_context *context, int cqe,
			       struct ibv_comp_channel *channel,
			       int comp_vector);

int ipath_destroy_cq(struct ibv_cq *cq);

struct ibv_qp *ipath_create_qp(struct ibv_pd *pd,
			       struct ibv_qp_init_attr *attr);

int ipath_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		    enum ibv_qp_attr_mask attr_mask);

int ipath_destroy_qp(struct ibv_qp *qp);

int ipath_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		    struct ibv_send_wr **bad_wr);

int ipath_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		    struct ibv_recv_wr **bad_wr);

struct ibv_srq *ipath_create_srq(struct ibv_pd *pd,
				 struct ibv_srq_init_attr *attr);

int ipath_modify_srq(struct ibv_srq *srq,
		     struct ibv_srq_attr *attr, 
		     enum ibv_srq_attr_mask attr_mask);

int ipath_destroy_srq(struct ibv_srq *srq);


struct ibv_ah *ipath_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr);

int ipath_destroy_ah(struct ibv_ah *ah);

#endif /* IPATH_H */
