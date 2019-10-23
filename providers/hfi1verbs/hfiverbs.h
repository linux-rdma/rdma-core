/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2015 Intel Corporation.

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  Contact Information:
  Intel Corporation
  www.intel.com

  BSD LICENSE

  Copyright(c) 2015 Intel Corporation.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  Copyright (C) 2006-2009 QLogic Corporation, All rights reserved.
  Copyright (c) 2005. PathScale, Inc. All rights reserved.

*/

#ifndef HFI1_H
#define HFI1_H

#include <endian.h>
#include <pthread.h>
#include <stddef.h>
#include <stdatomic.h>

#include <infiniband/driver.h>
#include <infiniband/verbs.h>

#define PFX		"hfi1: "

struct hfi1_device {
	struct verbs_device	ibv_dev;
	int			abi_version;
};

struct hfi1_context {
	struct verbs_context	ibv_ctx;
};

/*
 * This structure needs to have the same size and offsets as
 * the kernel's ib_wc structure since it is memory mapped.
 */
struct hfi1_wc {
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

struct hfi1_cq_wc {
	_Atomic(uint32_t)	head;
	_Atomic(uint32_t)	tail;
	struct hfi1_wc		queue[1];
};

struct hfi1_cq {
	struct ibv_cq		ibv_cq;
	struct hfi1_cq_wc	*queue;
	pthread_spinlock_t	lock;
};

/*
 * Receive work request queue entry.
 * The size of the sg_list is determined when the QP is created and stored
 * in qp->r_max_sge.
 */
struct hfi1_rwqe {
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
struct hfi1_rwq {
	_Atomic(uint32_t)	head;	/* new requests posted to the head. */
	_Atomic(uint32_t)	tail;	/* receives pull requests from here. */
	struct hfi1_rwqe	wq[0];
};

struct hfi1_rq {
	struct hfi1_rwq       *rwq;
	pthread_spinlock_t	lock;
	uint32_t		size;
	uint32_t		max_sge;
};

struct hfi1_qp {
	struct ibv_qp		ibv_qp;
	struct hfi1_rq		rq;
};

struct hfi1_srq {
	struct ibv_srq		ibv_srq;
	struct hfi1_rq		rq;
};

#define to_ixxx(xxx, type)						\
	container_of(ib##xxx, struct hfi1_##type, ibv_##xxx)

static inline struct hfi1_context *to_ictx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct hfi1_context, ibv_ctx.context);
}

static inline struct hfi1_device *to_idev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct hfi1_device, ibv_dev.device);
}

static inline struct hfi1_cq *to_icq(struct ibv_cq *ibcq)
{
	return to_ixxx(cq, cq);
}

static inline struct hfi1_qp *to_iqp(struct ibv_qp *ibqp)
{
	return to_ixxx(qp, qp);
}

static inline struct hfi1_srq *to_isrq(struct ibv_srq *ibsrq)
{
	return to_ixxx(srq, srq);
}

/*
 * Since struct hfi1_rwqe is not a fixed size, we can't simply index into
 * struct hfi1_rq.wq.  This function does the array index computation.
 */
static inline struct hfi1_rwqe *get_rwqe_ptr(struct hfi1_rq *rq,
					      unsigned n)
{
	return (struct hfi1_rwqe *)
		((char *) rq->rwq->wq +
		 (sizeof(struct hfi1_rwqe) +
		  rq->max_sge * sizeof(struct ibv_sge)) * n);
}

extern int hfi1_query_device(struct ibv_context *context,
			      struct ibv_device_attr *attr);

extern int hfi1_query_port(struct ibv_context *context, uint8_t port,
			    struct ibv_port_attr *attr);

struct ibv_pd *hfi1_alloc_pd(struct ibv_context *pd);

int hfi1_free_pd(struct ibv_pd *pd);

struct ibv_mr *hfi1_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			   uint64_t hca_va, int access);

int hfi1_dereg_mr(struct verbs_mr *vmr);

struct ibv_cq *hfi1_create_cq(struct ibv_context *context, int cqe,
			       struct ibv_comp_channel *channel,
			       int comp_vector);

struct ibv_cq *hfi1_create_cq_v1(struct ibv_context *context, int cqe,
				  struct ibv_comp_channel *channel,
				  int comp_vector);

int hfi1_resize_cq(struct ibv_cq *cq, int cqe);

int hfi1_resize_cq_v1(struct ibv_cq *cq, int cqe);

int hfi1_destroy_cq(struct ibv_cq *cq);

int hfi1_destroy_cq_v1(struct ibv_cq *cq);

int hfi1_poll_cq(struct ibv_cq *cq, int ne, struct ibv_wc *wc);

struct ibv_qp *hfi1_create_qp(struct ibv_pd *pd,
			       struct ibv_qp_init_attr *attr);

struct ibv_qp *hfi1_create_qp_v1(struct ibv_pd *pd,
				  struct ibv_qp_init_attr *attr);

int hfi1_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		   int attr_mask,
		   struct ibv_qp_init_attr *init_attr);

int hfi1_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		    int attr_mask);

int hfi1_destroy_qp(struct ibv_qp *qp);

int hfi1_destroy_qp_v1(struct ibv_qp *qp);

int hfi1_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		    struct ibv_send_wr **bad_wr);

int hfi1_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		    struct ibv_recv_wr **bad_wr);

struct ibv_srq *hfi1_create_srq(struct ibv_pd *pd,
				 struct ibv_srq_init_attr *attr);

struct ibv_srq *hfi1_create_srq_v1(struct ibv_pd *pd,
				    struct ibv_srq_init_attr *attr);

int hfi1_modify_srq(struct ibv_srq *srq,
		     struct ibv_srq_attr *attr, 
		     int attr_mask);

int hfi1_modify_srq_v1(struct ibv_srq *srq,
			struct ibv_srq_attr *attr, 
			int attr_mask);

int hfi1_query_srq(struct ibv_srq *srq, struct ibv_srq_attr *attr);

int hfi1_destroy_srq(struct ibv_srq *srq);

int hfi1_destroy_srq_v1(struct ibv_srq *srq);

int hfi1_post_srq_recv(struct ibv_srq *srq, struct ibv_recv_wr *wr,
			struct ibv_recv_wr **bad_wr);

struct ibv_ah *hfi1_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr);

int hfi1_destroy_ah(struct ibv_ah *ah);

#endif /* HFI1_H */
