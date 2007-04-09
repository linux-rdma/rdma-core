/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies Ltd.  All rights reserved.
 * Copyright (c) 2006, 2007 Cisco Systems.  All rights reserved.
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <netinet/in.h>
#include <string.h>

#include <infiniband/opcode.h>

#include "mlx4.h"
#include "doorbell.h"

enum {
	MLX4_CQ_DOORBELL			= 0x20
};

enum {
	CQ_OK					=  0,
	CQ_EMPTY				= -1,
	CQ_POLL_ERR				= -2
};

#define MLX4_CQ_DB_REQ_NOT_SOL			(1 << 24)
#define MLX4_CQ_DB_REQ_NOT			(2 << 24)

enum {
	MLX4_CQE_OWNER_MASK			= 0x80,
	MLX4_CQE_IS_SEND_MASK			= 0x40,
	MLX4_CQE_OPCODE_MASK			= 0x1f
};

enum {
	SYNDROME_LOCAL_LENGTH_ERR		= 0x01,
	SYNDROME_LOCAL_QP_OP_ERR		= 0x02,
	SYNDROME_LOCAL_EEC_OP_ERR		= 0x03,
	SYNDROME_LOCAL_PROT_ERR			= 0x04,
	SYNDROME_WR_FLUSH_ERR			= 0x05,
	SYNDROME_MW_BIND_ERR			= 0x06,
	SYNDROME_BAD_RESP_ERR			= 0x10,
	SYNDROME_LOCAL_ACCESS_ERR		= 0x11,
	SYNDROME_REMOTE_INVAL_REQ_ERR		= 0x12,
	SYNDROME_REMOTE_ACCESS_ERR		= 0x13,
	SYNDROME_REMOTE_OP_ERR			= 0x14,
	SYNDROME_RETRY_EXC_ERR			= 0x15,
	SYNDROME_RNR_RETRY_EXC_ERR		= 0x16,
	SYNDROME_LOCAL_RDD_VIOL_ERR		= 0x20,
	SYNDROME_REMOTE_INVAL_RD_REQ_ERR	= 0x21,
	SYNDROME_REMOTE_ABORTED_ERR		= 0x22,
	SYNDROME_INVAL_EECN_ERR			= 0x23,
	SYNDROME_INVAL_EEC_STATE_ERR		= 0x24
};

struct mlx4_cqe {
	uint32_t	my_qpn;
	uint32_t	immed_rss_invalid;
	uint32_t	g_mlpath_rqpn;
	uint8_t		sl;
	uint8_t		reserved1;
	uint16_t	rlid;
	uint32_t	reserved2;
	uint32_t	byte_cnt;
	uint16_t	wqe_index;
	uint16_t	checksum;
	uint8_t		reserved3[3];
	uint8_t		owner_sr_opcode;
};

struct mlx4_err_cqe {
	uint32_t	my_qpn;
	uint32_t	reserved1[5];
	uint16_t	wqe_index;
	uint8_t		vendor_err;
	uint8_t		syndrome;
	uint8_t		reserved2[3];
	uint8_t		owner_sr_opcode;
};

static inline struct mlx4_cqe *get_cqe(struct mlx4_cq *cq, int entry)
{
	return cq->buf.buf + entry * MLX4_CQ_ENTRY_SIZE;
}

static inline struct mlx4_cqe *next_cqe_sw(struct mlx4_cq *cq)
{
	struct mlx4_cqe *cqe = get_cqe(cq, cq->cons_index & cq->ibv_cq.cqe);

	return (!!(cqe->owner_sr_opcode & MLX4_CQE_OWNER_MASK) ^
		!!(cq->cons_index & (cq->ibv_cq.cqe + 1))) ? NULL : cqe;
}

static void update_cons_index(struct mlx4_cq *cq)
{
	*cq->set_ci_db = htonl(cq->cons_index & 0xffffff);
}

static int handle_error_cqe(struct mlx4_cq *cq, struct mlx4_qp *qp,
			    int wqe_index, int is_send,
			    struct mlx4_err_cqe *cqe,
			    struct ibv_wc *wc)
{
	/* XXX handle error CQE */
	return 0;
}

static int mlx4_poll_one(struct mlx4_cq *cq,
			 struct mlx4_qp **cur_qp,
			 struct ibv_wc *wc)
{
	struct mlx4_wq *wq;
	struct mlx4_cqe *cqe;
	struct mlx4_srq *srq;
	uint32_t qpn;
	uint16_t wqe_index;
	int is_error;
	int is_send;
	int err = 0;

	cqe = next_cqe_sw(cq);
	if (!cqe)
		return CQ_EMPTY;

	++cq->cons_index;

	VALGRIND_MAKE_MEM_DEFINED(cqe, sizeof *cqe);

	/*
	 * Make sure we read CQ entry contents after we've checked the
	 * ownership bit.
	 */
	rmb();

	qpn = ntohl(cqe->my_qpn);

	is_send  = cqe->owner_sr_opcode & MLX4_CQE_IS_SEND_MASK;
	is_error = (cqe->owner_sr_opcode & MLX4_CQE_OPCODE_MASK) ==
		MLX4_CQE_OPCODE_ERROR;

	if (!*cur_qp ||
	    (ntohl(cqe->my_qpn) & 0xffffff) != (*cur_qp)->ibv_qp.qp_num) {
		/*
		 * We do not have to take the QP table lock here,
		 * because CQs will be locked while QPs are removed
		 * from the table.
		 */
		*cur_qp = mlx4_find_qp(to_mctx(cq->ibv_cq.context),
				       ntohl(cqe->my_qpn) & 0xffffff);
		if (!*cur_qp)
			return CQ_POLL_ERR;
	}

	wc->qp_num = (*cur_qp)->ibv_qp.qp_num;

	if (is_send) {
		wq = &(*cur_qp)->sq;
		wqe_index = ntohs(cqe->wqe_index);
		wq->tail += wqe_index - (uint16_t) wq->tail;
		wc->wr_id = wq->wrid[wq->tail & (wq->max - 1)];
		++wq->tail;
	} else if ((*cur_qp)->ibv_qp.srq) {
		srq = to_msrq((*cur_qp)->ibv_qp.srq);
		wqe_index = htons(cqe->wqe_index);
		wc->wr_id = srq->wrid[wqe_index];
		mlx4_free_srq_wqe(srq, wqe_index);
	} else {
		wq = &(*cur_qp)->rq;
		wc->wr_id = wq->wrid[wq->tail & (wq->max - 1)];
		++wq->tail;
	}

	if (is_error) {
		err = handle_error_cqe(cq, *cur_qp, wqe_index, is_send,
				       (struct mlx4_err_cqe *) cqe, wc);
		return err;
	}

	wc->status = IBV_WC_SUCCESS;

	if (is_send) {
		wc->wc_flags = 0;
		switch (cqe->owner_sr_opcode & MLX4_CQE_OPCODE_MASK) {
		case MLX4_OPCODE_RDMA_WRITE_IMM:
			wc->wc_flags |= IBV_WC_WITH_IMM;
		case MLX4_OPCODE_RDMA_WRITE:
			wc->opcode    = IBV_WC_RDMA_WRITE;
			break;
		case MLX4_OPCODE_SEND_IMM:
			wc->wc_flags |= IBV_WC_WITH_IMM;
		case MLX4_OPCODE_SEND:
			wc->opcode    = IBV_WC_SEND;
			break;
		case MLX4_OPCODE_RDMA_READ:
			wc->opcode    = IBV_WC_RDMA_READ;
			wc->byte_len  = ntohl(cqe->byte_cnt);
			break;
		case MLX4_OPCODE_ATOMIC_CS:
			wc->opcode    = IBV_WC_COMP_SWAP;
			/* XXX byte_len? */
			break;
		case MLX4_OPCODE_ATOMIC_FA:
			wc->opcode    = IBV_WC_FETCH_ADD;
			/* XXX byte_len? */
			break;
		case MLX4_OPCODE_BIND_MW:
			wc->opcode    = IBV_WC_BIND_MW;
			break;
		default:
			/* assume it's a send completion */
			wc->opcode    = IBV_WC_SEND;
			break;
		}
	} else {
		wc->byte_len = ntohl(cqe->byte_cnt);

		switch (cqe->owner_sr_opcode & MLX4_CQE_OPCODE_MASK) {
		case MLX4_RECV_OPCODE_RDMA_WRITE_IMM:
			wc->opcode   = IBV_WC_RECV_RDMA_WITH_IMM;
			wc->wc_flags = IBV_WC_WITH_IMM;
			wc->imm_data = cqe->immed_rss_invalid;
			break;
		case MLX4_RECV_OPCODE_SEND:
			wc->opcode   = IBV_WC_RECV;
			wc->wc_flags = 0;
			break;
		case MLX4_RECV_OPCODE_SEND_IMM:
			wc->opcode   = IBV_WC_RECV;
			wc->wc_flags = IBV_WC_WITH_IMM;
			wc->imm_data = cqe->immed_rss_invalid;
			break;
		}

		wc->slid 	   = ntohs(cqe->rlid);
		wc->sl   	   = cqe->sl >> 4;
		wc->src_qp 	   = ntohl(cqe->g_mlpath_rqpn) & 0xffffff;
		wc->dlid_path_bits = (ntohl(cqe->g_mlpath_rqpn) >> 24) & 0x7f;
		wc->pkey_index     = ntohl(cqe->immed_rss_invalid) >> 16;
		wc->wc_flags      |= ntohs(cqe->g_mlpath_rqpn) & 0x80000000 ?
			IBV_WC_GRH : 0;
	}

	return 0;
}

int mlx4_poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	struct mlx4_cq *cq = to_mcq(ibcq);
	struct mlx4_qp *qp = NULL;
	int npolled;
	int err = CQ_OK;

	pthread_spin_lock(&cq->lock);

	for (npolled = 0; npolled < ne; ++npolled) {
		err = mlx4_poll_one(cq, &qp, wc + npolled);
		if (err != CQ_OK)
			break;
	}

	if (npolled)
		update_cons_index(cq);

	pthread_spin_unlock(&cq->lock);

	return err == CQ_POLL_ERR ? err : npolled;
}

int mlx4_arm_cq(struct ibv_cq *ibvcq, int solicited)
{
	struct mlx4_cq *cq = to_mcq(ibvcq);
	uint32_t doorbell[2];
	uint32_t sn;
	uint32_t ci;
	uint32_t cmd;

	sn  = cq->arm_sn & 3;
	ci  = cq->cons_index & 0xffffff;
	cmd = solicited ? MLX4_CQ_DB_REQ_NOT_SOL : MLX4_CQ_DB_REQ_NOT;

	*cq->arm_db = htonl(sn << 28 | cmd | ci);

	/*
	 * Make sure that the doorbell record in host memory is
	 * written before ringing the doorbell via PCI MMIO.
	 */
	wmb();

	doorbell[0] = htonl(sn << 28 | cmd | cq->cqn);
	doorbell[1] = htonl(ci);

	mlx4_write64(doorbell, to_mctx(ibvcq->context), MLX4_CQ_DOORBELL);

	return 0;
}

void mlx4_cq_event(struct ibv_cq *cq)
{
	to_mcq(cq)->arm_sn++;
}

void mlx4_cq_clean(struct mlx4_cq *cq, uint32_t qpn, struct mlx4_srq *srq)
{
}

void mlx4_cq_resize_copy_cqes(struct mlx4_cq *cq, void *buf, int old_cqe)
{
}
