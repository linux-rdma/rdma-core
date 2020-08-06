/*
 * Copyright (c) 2006-2009 QLogic Corp. All rights reserved.
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
#include <pthread.h>
#include <stddef.h>
#include <stdatomic.h>

#include <infiniband/driver.h>
#include <infiniband/verbs.h>

#define PFX		"ipath: "

struct ipath_device {
	struct verbs_device	ibv_dev;
	int			abi_version;
};

struct ipath_context {
	struct verbs_context	ibv_ctx;
};

/*
 * This structure needs to have the same size and offsets as
 * the kernel's ib_wc structure since it is memory mapped.
 */
struct ipath_wc {
	uint64_t		wr_id;
	enum ibv_wc_status	status;
	enum ibv_wc_opcode	opcode;
	uint32_t		vendor_err;
	uint32_t		byte_len;
	uint32_t		imm_data;	/* in network byte order */
	uint32_t		qp_num;
	uint32_t		src_qp;
	enum ibv_wc_flags	wc_flags;
	uint16_t		pkey_index;
	uint16_t		slid;
	uint8_t			sl;
	uint8_t			dlid_path_bits;
	uint8_t			port_num;
};

struct ipath_cq_wc {
	_Atomic(uint32_t)	head;
	_Atomic(uint32_t)	tail;
	struct ipath_wc		queue[1];
};

struct ipath_cq {
	struct ibv_cq		ibv_cq;
	struct ipath_cq_wc	*queue;
	pthread_spinlock_t	lock;
};

/*
 * Receive work request queue entry.
 * The size of the sg_list is determined when the QP is created and stored
 * in qp->r_max_sge.
 */
struct ipath_rwqe {
	uint64_t		wr_id;
	uint8_t			num_sge;
	uint8_t			padding[7];
	struct ibv_sge		sg_list[0];
};

/*
 * This struture is used to contain the head pointer, tail pointer,
 * and receive work queue entries as a single memory allocation so
 * it can be mmap'ed into user space.
 * Note that the wq array elements are variable size so you can't
 * just index into the array to get the N'th element;
 * use get_rwqe_ptr() instead.
 */
struct ipath_rwq {
	_Atomic(uint32_t)	head;	/* new requests posted to the head. */
	_Atomic(uint32_t)	tail;	/* receives pull requests from here. */
	struct ipath_rwqe	wq[0];
};

struct ipath_rq {
	struct ipath_rwq       *rwq;
	pthread_spinlock_t	lock;
	uint32_t		size;
	uint32_t		max_sge;
};

struct ipath_qp {
	struct ibv_qp		ibv_qp;
	struct ipath_rq		rq;
};

struct ipath_srq {
	struct ibv_srq		ibv_srq;
	struct ipath_rq		rq;
};

#define to_ixxx(xxx, type) container_of(ib##xxx, struct ipath_##type, ibv_##xxx)

static inline struct ipath_context *to_ictx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct ipath_context, ibv_ctx.context);
}

static inline struct ipath_device *to_idev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct ipath_device, ibv_dev.device);
}

static inline struct ipath_cq *to_icq(struct ibv_cq *ibcq)
{
	return to_ixxx(cq, cq);
}

static inline struct ipath_qp *to_iqp(struct ibv_qp *ibqp)
{
	return to_ixxx(qp, qp);
}

static inline struct ipath_srq *to_isrq(struct ibv_srq *ibsrq)
{
	return to_ixxx(srq, srq);
}

/*
 * Since struct ipath_rwqe is not a fixed size, we can't simply index into
 * struct ipath_rq.wq.  This function does the array index computation.
 */
static inline struct ipath_rwqe *get_rwqe_ptr(struct ipath_rq *rq,
					      unsigned n)
{
	return (struct ipath_rwqe *)
		((char *) rq->rwq->wq +
		 (sizeof(struct ipath_rwqe) +
		  rq->max_sge * sizeof(struct ibv_sge)) * n);
}

extern int ipath_query_device(struct ibv_context *context,
			      struct ibv_device_attr *attr);

extern int ipath_query_port(struct ibv_context *context, uint8_t port,
			    struct ibv_port_attr *attr);

struct ibv_pd *ipath_alloc_pd(struct ibv_context *pd);

int ipath_free_pd(struct ibv_pd *pd);

struct ibv_mr *ipath_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			    uint64_t hca_va, int access);

int ipath_dereg_mr(struct verbs_mr *vmr);

struct ibv_cq *ipath_create_cq(struct ibv_context *context, int cqe,
			       struct ibv_comp_channel *channel,
			       int comp_vector);

struct ibv_cq *ipath_create_cq_v1(struct ibv_context *context, int cqe,
				  struct ibv_comp_channel *channel,
				  int comp_vector);

int ipath_resize_cq(struct ibv_cq *cq, int cqe);

int ipath_resize_cq_v1(struct ibv_cq *cq, int cqe);

int ipath_destroy_cq(struct ibv_cq *cq);

int ipath_destroy_cq_v1(struct ibv_cq *cq);

int ipath_poll_cq(struct ibv_cq *cq, int ne, struct ibv_wc *wc);

struct ibv_qp *ipath_create_qp(struct ibv_pd *pd,
			       struct ibv_qp_init_attr *attr);

struct ibv_qp *ipath_create_qp_v1(struct ibv_pd *pd,
				  struct ibv_qp_init_attr *attr);

int ipath_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		   int attr_mask,
		   struct ibv_qp_init_attr *init_attr);

int ipath_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		    int attr_mask);

int ipath_destroy_qp(struct ibv_qp *qp);

int ipath_destroy_qp_v1(struct ibv_qp *qp);

int ipath_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		    struct ibv_send_wr **bad_wr);

int ipath_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		    struct ibv_recv_wr **bad_wr);

struct ibv_srq *ipath_create_srq(struct ibv_pd *pd,
				 struct ibv_srq_init_attr *attr);

struct ibv_srq *ipath_create_srq_v1(struct ibv_pd *pd,
				    struct ibv_srq_init_attr *attr);

int ipath_modify_srq(struct ibv_srq *srq,
		     struct ibv_srq_attr *attr, 
		     int attr_mask);

int ipath_modify_srq_v1(struct ibv_srq *srq,
			struct ibv_srq_attr *attr, 
			int attr_mask);

int ipath_query_srq(struct ibv_srq *srq, struct ibv_srq_attr *attr);

int ipath_destroy_srq(struct ibv_srq *srq);

int ipath_destroy_srq_v1(struct ibv_srq *srq);

int ipath_post_srq_recv(struct ibv_srq *srq, struct ibv_recv_wr *wr,
			struct ibv_recv_wr **bad_wr);

struct ibv_ah *ipath_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr);

int ipath_destroy_ah(struct ibv_ah *ah);

#endif /* IPATH_H */
