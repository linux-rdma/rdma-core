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
 *
 * Patent licenses, if any, provided herein do not apply to
 * combinations of this program with other software, or any other
 * product whatsoever.
 */

#ifndef RXE_H
#define RXE_H

struct rxe_device {
	struct ibv_device	ibv_dev;
	int	abi_version;
};

struct rxe_context {
	struct ibv_context	ibv_ctx;
};

/* MUST MATCH kernel struct ib_uwc */
struct rxe_wc {
	uint64_t		wr_id;
	enum ibv_wc_status	status;
	enum ibv_wc_opcode	opcode;
	uint32_t		vendor_err;
	uint32_t		byte_len;
	uint32_t		imm_data;
	uint32_t		qp_num;
	uint32_t		src_qp;
	enum ibv_wc_flags	wc_flags;
	uint16_t		pkey_index;
	uint16_t		slid;
	uint8_t			sl;
	uint8_t			dlid_path_bits;
	uint8_t			port_num;
};

struct rxe_cq {
	struct ibv_cq		ibv_cq;
	struct mmap_info	mmap_info;
	struct rxe_queue		*queue;
	pthread_spinlock_t	lock;
};

/* MUST MATCH rxe_dma_info struct in kernel rxe_verbs.h */
struct rxe_dma_info {
	uint32_t		length;			/* message length		*/
	uint32_t		resid;			/* Data left to send or write	*/
	uint32_t		cur_sge;		/* current sg element		*/
	uint32_t		num_sge;		/* number sg elements		*/
	uint32_t		sge_offset;		/* offset in current element	*/
	union {
		uint8_t			msg[0];
		struct ibv_sge		sge[0];
	};
};

/* MUST MATCH rxe_user_rwqe struct in kernel rxe_verbs.h */
struct rxe_recv_wqe {
	uint64_t		wr_id;
	uint32_t		num_sge;
	uint32_t		padding;
	struct rxe_dma_info	dma;
};

#ifdef RXE_USER_SEND_QUEUE

/* kernel send wr */
struct ib_send_wr {
	struct ib_send_wr      *next;
	uint64_t		wr_id;
	struct ib_sge	       *sg_list;
	int			num_sge;
	unsigned int		opcode;
	int			send_flags;
	uint32_t		imm_data;

	union {
		struct {
			uint64_t	remote_addr;
			uint32_t	rkey;
		} rdma;
		struct {
			uint64_t	remote_addr;
			uint64_t	compare_add;
			uint64_t	swap;
			uint64_t	compare_add_mask;
			uint64_t	swap_mask;
			uint32_t	rkey;
		} atomic;
		struct {
			struct ib_ah	*ah;
			void		*header;
			int		hlen;
			int		mss;
			uint32_t	remote_qpn;
			uint32_t	remote_qkey;
			uint16_t	pkey_index; /* valid for GSI only */
			uint8_t		port_num;   /* valid for DR SMPs on switch only */
		} ud;
	} wr;
};

#define RXE_LL_ADDR_LEN		(16)

struct rxe_av {
	struct ibv_ah_attr	attr;
	uint8_t			ll_addr[RXE_LL_ADDR_LEN];
};

struct rxe_ah {
	struct ibv_ah		ibv_ah;
	struct rxe_av		av;
};

struct rxe_send_wqe {
	struct ib_send_wr	ibwr;
	struct rxe_av		av;
	uint32_t		status;
	uint32_t		state;
	uint64_t		iova;
	uint32_t		mask;
	uint32_t		first_psn;
	uint32_t		last_psn;
	uint32_t		ack_length;
	uint32_t		ssn;
	uint32_t		has_rd_atomic;
	struct rxe_dma_info	dma;
};
#endif

struct rxe_wq {
	struct rxe_queue	*queue;
	pthread_spinlock_t	lock;
	unsigned int		max_sge;
	unsigned int		max_inline;
};

struct rxe_qp {
	struct ibv_qp		ibv_qp;
	struct mmap_info	rq_mmap_info;
	struct rxe_wq		rq;
#ifdef RXE_USER_SEND_QUEUE
	struct mmap_info	sq_mmap_info;
	struct rxe_wq		sq;
	unsigned int		ssn;
#endif
};

#define qp_type(qp)		((qp)->ibv_qp.qp_type)

struct rxe_srq {
	struct ibv_srq		ibv_srq;
	struct mmap_info	mmap_info;
	struct rxe_wq		rq;
	uint32_t		srq_num;
};

#define to_rxxx(xxx, type)						\
	((struct rxe_##type *)					      \
	 ((void *) ib##xxx - offsetof(struct rxe_##type, ibv_##xxx)))

static inline struct rxe_context *to_rctx(struct ibv_context *ibctx)
{
	return to_rxxx(ctx, context);
}

static inline struct rxe_device *to_rdev(struct ibv_device *ibdev)
{
	return to_rxxx(dev, device);
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
