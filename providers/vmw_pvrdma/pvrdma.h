/*
 * Copyright (c) 2012-2016 VMware, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of EITHER the GNU General Public License
 * version 2 as published by the Free Software Foundation or the BSD
 * 2-Clause License. This program is distributed in the hope that it
 * will be useful, but WITHOUT ANY WARRANTY; WITHOUT EVEN THE IMPLIED
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License version 2 for more details at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program available in the file COPYING in the main
 * directory of this source tree.
 *
 * The BSD 2-Clause License
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __PVRDMA_H__
#define __PVRDMA_H__

#include <config.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <infiniband/driver.h>
#include <ccan/minmax.h>
#include <util/compiler.h>

#include "pvrdma-abi.h"
#include "pvrdma_ring.h"

#define PFX "pvrdma: "

enum {
	PVRDMA_OPCODE_NOP			= 0x00,
	PVRDMA_OPCODE_SEND_INVAL		= 0x01,
	PVRDMA_OPCODE_RDMA_WRITE		= 0x08,
	PVRDMA_OPCODE_RDMA_WRITE_IMM		= 0x09,
	PVRDMA_OPCODE_SEND			= 0x0a,
	PVRDMA_OPCODE_SEND_IMM			= 0x0b,
	PVRDMA_OPCODE_LSO			= 0x0e,
	PVRDMA_OPCODE_RDMA_READ			= 0x10,
	PVRDMA_OPCODE_ATOMIC_CS			= 0x11,
	PVRDMA_OPCODE_ATOMIC_FA			= 0x12,
	PVRDMA_OPCODE_ATOMIC_MASK_CS		= 0x14,
	PVRDMA_OPCODE_ATOMIC_MASK_FA		= 0x15,
	PVRDMA_OPCODE_BIND_MW			= 0x18,
	PVRDMA_OPCODE_FMR			= 0x19,
	PVRDMA_OPCODE_LOCAL_INVAL		= 0x1b,
	PVRDMA_OPCODE_CONFIG_CMD		= 0x1f,

	PVRDMA_RECV_OPCODE_RDMA_WRITE_IMM	= 0x00,
	PVRDMA_RECV_OPCODE_SEND			= 0x01,
	PVRDMA_RECV_OPCODE_SEND_IMM		= 0x02,
	PVRDMA_RECV_OPCODE_SEND_INVAL		= 0x03,

	PVRDMA_CQE_OPCODE_ERROR			= 0x1e,
	PVRDMA_CQE_OPCODE_RESIZE		= 0x16,
};

enum {
	PVRDMA_WQE_CTRL_FENCE			= 1 << 6,
	PVRDMA_WQE_CTRL_CQ_UPDATE		= 3 << 2,
	PVRDMA_WQE_CTRL_SOLICIT			= 1 << 1,
};

struct pvrdma_device {
	struct verbs_device		ibv_dev;
	int				page_size;
	int				abi_version;
};

struct pvrdma_context {
	struct verbs_context		ibv_ctx;
	void				*uar;
	pthread_spinlock_t		uar_lock;
	int				max_qp_wr;
	int				max_sge;
	int				max_cqe;
	struct pvrdma_qp		**qp_tbl;
};

struct pvrdma_buf {
	void				*buf;
	size_t				length;
};

struct pvrdma_pd {
	struct ibv_pd			ibv_pd;
	uint32_t			pdn;
};

struct pvrdma_cq {
	struct ibv_cq			ibv_cq;
	struct pvrdma_buf		buf;
	struct pvrdma_buf		resize_buf;
	pthread_spinlock_t		lock;
	struct pvrdma_ring_state	*ring_state;
	uint32_t			cqe_cnt;
	uint32_t			offset;
	uint32_t			cqn;
};

struct pvrdma_srq {
	struct ibv_srq			ibv_srq;
	struct pvrdma_buf		buf;
	pthread_spinlock_t		lock;
	uint64_t			*wrid;
	uint32_t			srqn;
	int				wqe_cnt;
	int				wqe_size;
	int				max_gs;
	int				wqe_shift;
	struct pvrdma_ring_state	*ring_state;
	uint16_t			counter;
	int				offset;
};

struct pvrdma_wq {
	uint64_t			*wrid;
	pthread_spinlock_t		lock;
	int				wqe_cnt;
	int				wqe_size;
	struct pvrdma_ring		*ring_state;
	int				max_gs;
	int				wqe_shift;
	int				offset;
};

struct pvrdma_qp {
	struct ibv_qp			ibv_qp;
	struct pvrdma_buf		rbuf;
	struct pvrdma_buf		sbuf;
	int				max_inline_data;
	int				buf_size;
	__be32				sq_signal_bits;
	int				sq_spare_wqes;
	struct pvrdma_wq		sq;
	struct pvrdma_wq		rq;
	int				is_srq;
	uint32_t			qp_handle;
};

struct pvrdma_ah {
	struct ibv_ah			ibv_ah;
	struct pvrdma_av		av;
};

static inline unsigned long align(unsigned long val, unsigned long align)
{
	return (val + align - 1) & ~(align - 1);
}

static inline int align_next_power2(int size)
{
	int  val = 1;

	while (val < size)
		val <<= 1;

	return val;
}

static inline struct pvrdma_device *to_vdev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct pvrdma_device, ibv_dev.device);
}

static inline struct pvrdma_context *to_vctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct pvrdma_context, ibv_ctx.context);
}

static inline struct pvrdma_pd *to_vpd(struct ibv_pd *ibpd)
{
	return container_of(ibpd, struct pvrdma_pd, ibv_pd);
}

static inline struct pvrdma_cq *to_vcq(struct ibv_cq *ibcq)
{
	return container_of(ibcq, struct pvrdma_cq, ibv_cq);
}

static inline struct pvrdma_srq *to_vsrq(struct ibv_srq *ibsrq)
{
	return container_of(ibsrq, struct pvrdma_srq, ibv_srq);
}

static inline struct pvrdma_qp *to_vqp(struct ibv_qp *ibqp)
{
	return container_of(ibqp, struct pvrdma_qp, ibv_qp);
}

static inline struct pvrdma_ah *to_vah(struct ibv_ah *ibah)
{
	return container_of(ibah, struct pvrdma_ah, ibv_ah);
}

static inline void pvrdma_write_uar_qp(void *uar, unsigned value)
{
	*(__le32 *)(uar + PVRDMA_UAR_QP_OFFSET) = htole32(value);
}

static inline void pvrdma_write_uar_cq(void *uar, unsigned value)
{
	*(__le32 *)(uar + PVRDMA_UAR_CQ_OFFSET) = htole32(value);
}

static inline void pvrdma_write_uar_srq(void *uar, unsigned int value)
{
	*(__le32 *)(uar + PVRDMA_UAR_SRQ_OFFSET) = htole32(value);
}

static inline int ibv_send_flags_to_pvrdma(int flags)
{
	return flags;
}

static inline enum pvrdma_wr_opcode ibv_wr_opcode_to_pvrdma(
						enum ibv_wr_opcode op)
{
	return (enum pvrdma_wr_opcode)op;
}

static inline enum ibv_wc_status pvrdma_wc_status_to_ibv(
					enum pvrdma_wc_status status)
{
	return (enum ibv_wc_status)status;
}

static inline enum ibv_wc_opcode pvrdma_wc_opcode_to_ibv(
					enum pvrdma_wc_opcode op)
{
	return (enum ibv_wc_opcode)op;
}

static inline int pvrdma_wc_flags_to_ibv(int flags)
{
	return flags;
}

int pvrdma_alloc_buf(struct pvrdma_buf *buf, size_t size, int page_size);
void pvrdma_free_buf(struct pvrdma_buf *buf);

int pvrdma_query_device(struct ibv_context *context,
			struct ibv_device_attr *attr);
int pvrdma_query_port(struct ibv_context *context, uint8_t port,
		      struct ibv_port_attr *attr);

struct ibv_pd *pvrdma_alloc_pd(struct ibv_context *context);
int pvrdma_free_pd(struct ibv_pd *pd);

struct ibv_mr *pvrdma_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			     uint64_t hca_va, int access);
int pvrdma_dereg_mr(struct verbs_mr *mr);

struct ibv_cq *pvrdma_create_cq(struct ibv_context *context, int cqe,
				struct ibv_comp_channel *channel,
				int comp_vector);
int pvrdma_alloc_cq_buf(struct pvrdma_device *dev, struct pvrdma_cq *cq,
			struct pvrdma_buf *buf, int nent);
int pvrdma_destroy_cq(struct ibv_cq *cq);
int pvrdma_req_notify_cq(struct ibv_cq *cq, int solicited);
int pvrdma_poll_cq(struct ibv_cq *cq, int ne, struct ibv_wc *wc);
void pvrdma_cq_event(struct ibv_cq *cq);
void pvrdma_cq_clean_int(struct pvrdma_cq *cq, uint32_t qp_handle);
void pvrdma_cq_clean(struct pvrdma_cq *cq, uint32_t qp_handle);
int pvrdma_get_outstanding_cqes(struct pvrdma_cq *cq);
void pvrdma_cq_resize_copy_cqes(struct pvrdma_cq *cq, void *buf,
				int new_cqe);

struct ibv_qp *pvrdma_create_qp(struct ibv_pd *pd,
				struct ibv_qp_init_attr *attr);
int pvrdma_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		    int attr_mask, struct ibv_qp_init_attr *init_attr);
int pvrdma_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		     int attr_mask);
int pvrdma_destroy_qp(struct ibv_qp *qp);
void pvrdma_init_qp_indices(struct pvrdma_qp *qp);
void pvrdma_qp_init_sq_ownership(struct pvrdma_qp *qp);
int pvrdma_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		     struct ibv_send_wr **bad_wr);
int pvrdma_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		     struct ibv_recv_wr **bad_wr);
void pvrdma_calc_sq_wqe_size(struct ibv_qp_cap *cap, enum ibv_qp_type type,
			     struct pvrdma_qp *qp);
int pvrdma_alloc_qp_buf(struct pvrdma_device *dev, struct ibv_qp_cap *cap,
			enum ibv_qp_type type, struct pvrdma_qp *qp);
void pvrdma_set_sq_sizes(struct pvrdma_qp *qp, struct ibv_qp_cap *cap,
			 enum ibv_qp_type type);
struct pvrdma_qp *pvrdma_find_qp(struct pvrdma_context *ctx,
				 uint32_t qpn);
int pvrdma_store_qp(struct pvrdma_context *ctx, uint32_t qpn,
		    struct pvrdma_qp *qp);
void pvrdma_clear_qp(struct pvrdma_context *ctx, uint32_t qpn);

struct ibv_srq *pvrdma_create_srq(struct ibv_pd *pd,
				  struct ibv_srq_init_attr *attr);
int pvrdma_modify_srq(struct ibv_srq *srq, struct ibv_srq_attr *attr,
		      int attr_mask);
int pvrdma_query_srq(struct ibv_srq *srq,
		     struct ibv_srq_attr *attr);
int pvrdma_destroy_srq(struct ibv_srq *srq);
int pvrdma_alloc_srq_buf(struct pvrdma_device *dev,
			 struct ibv_srq_attr *attr,
			 struct pvrdma_srq *srq);
int pvrdma_post_srq_recv(struct ibv_srq *ibsrq,
			 struct ibv_recv_wr *wr,
			 struct ibv_recv_wr **bad_wr);
void pvrdma_init_srq_queue(struct pvrdma_srq *srq);

struct ibv_ah *pvrdma_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr);
int pvrdma_destroy_ah(struct ibv_ah *ah);

int pvrdma_alloc_av(struct pvrdma_pd *pd, struct ibv_ah_attr *attr,
		    struct pvrdma_ah *ah);
void pvrdma_free_av(struct pvrdma_ah *ah);

#endif /* __PVRDMA_H__ */
