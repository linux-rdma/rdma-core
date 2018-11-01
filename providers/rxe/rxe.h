/*
 * Copyright (c) 2009 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2009 System Fabric Works, Inc. All rights reserved.
 * Copyright (c) 2006-2007 QLogic Corp. All rights reserved.
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
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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

#ifndef RXE_H
#define RXE_H

#include <infiniband/driver.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <rdma/rdma_user_rxe.h> /* struct rxe_av */
#include "rxe-abi.h"

enum rdma_network_type {
	RDMA_NETWORK_IB,
	RDMA_NETWORK_IPV4,
	RDMA_NETWORK_IPV6
};

struct rxe_device {
	struct verbs_device	ibv_dev;
	int	abi_version;
};

struct rxe_context {
	struct verbs_context	ibv_ctx;
};

struct rxe_cq {
	struct ibv_cq		ibv_cq;
	struct mminfo		mmap_info;
	struct rxe_queue		*queue;
	pthread_spinlock_t	lock;
};

struct rxe_ah {
	struct ibv_ah		ibv_ah;
	struct rxe_av		av;
};

struct rxe_wq {
	struct rxe_queue	*queue;
	pthread_spinlock_t	lock;
	unsigned int		max_sge;
	unsigned int		max_inline;
};

struct rxe_qp {
	struct ibv_qp		ibv_qp;
	struct mminfo		rq_mmap_info;
	struct rxe_wq		rq;
	struct mminfo		sq_mmap_info;
	struct rxe_wq		sq;
	unsigned int		ssn;
};

#define qp_type(qp)		((qp)->ibv_qp.qp_type)

struct rxe_srq {
	struct ibv_srq		ibv_srq;
	struct mminfo		mmap_info;
	struct rxe_wq		rq;
	uint32_t		srq_num;
};

#define to_rxxx(xxx, type) container_of(ib##xxx, struct rxe_##type, ibv_##xxx)

static inline struct rxe_context *to_rctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct rxe_context, ibv_ctx.context);
}

static inline struct rxe_device *to_rdev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct rxe_device, ibv_dev.device);
}

static inline struct rxe_cq *to_rcq(struct ibv_cq *ibcq)
{
	return to_rxxx(cq, cq);
}

static inline struct rxe_qp *to_rqp(struct ibv_qp *ibqp)
{
	return to_rxxx(qp, qp);
}

static inline struct rxe_srq *to_rsrq(struct ibv_srq *ibsrq)
{
	return to_rxxx(srq, srq);
}

static inline struct rxe_ah *to_rah(struct ibv_ah *ibah)
{
	return to_rxxx(ah, ah);
}

#endif /* RXE_H */
