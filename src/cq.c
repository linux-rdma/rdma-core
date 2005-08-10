/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies Ltd.  All rights reserved.
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
 * $Id$
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <netinet/in.h>
#include <pthread.h>

#include <infiniband/opcode.h>

#include "mthca.h"
#include "doorbell.h"

enum {
	MTHCA_CQ_DOORBELL	= 0x20
};

enum {
	CQ_OK		=  0,
	CQ_EMPTY	= -1,
	CQ_POLL_ERR	= -2
};

#define MTHCA_TAVOR_CQ_DB_INC_CI       (1 << 24)
#define MTHCA_TAVOR_CQ_DB_REQ_NOT      (2 << 24)
#define MTHCA_TAVOR_CQ_DB_REQ_NOT_SOL  (3 << 24)
#define MTHCA_TAVOR_CQ_DB_SET_CI       (4 << 24)
#define MTHCA_TAVOR_CQ_DB_REQ_NOT_MULT (5 << 24)

#define MTHCA_ARBEL_CQ_DB_REQ_NOT_SOL  (1 << 24)
#define MTHCA_ARBEL_CQ_DB_REQ_NOT      (2 << 24)
#define MTHCA_ARBEL_CQ_DB_REQ_NOT_MULT (3 << 24)

enum {
	MTHCA_CQ_ENTRY_OWNER_SW     = 0x00,
	MTHCA_CQ_ENTRY_OWNER_HW     = 0x80,
	MTHCA_ERROR_CQE_OPCODE_MASK = 0xfe
};

enum {
	SYNDROME_LOCAL_LENGTH_ERR 	 = 0x01,
	SYNDROME_LOCAL_QP_OP_ERR  	 = 0x02,
	SYNDROME_LOCAL_EEC_OP_ERR 	 = 0x03,
	SYNDROME_LOCAL_PROT_ERR   	 = 0x04,
	SYNDROME_WR_FLUSH_ERR     	 = 0x05,
	SYNDROME_MW_BIND_ERR      	 = 0x06,
	SYNDROME_BAD_RESP_ERR     	 = 0x10,
	SYNDROME_LOCAL_ACCESS_ERR 	 = 0x11,
	SYNDROME_REMOTE_INVAL_REQ_ERR 	 = 0x12,
	SYNDROME_REMOTE_ACCESS_ERR 	 = 0x13,
	SYNDROME_REMOTE_OP_ERR     	 = 0x14,
	SYNDROME_RETRY_EXC_ERR 		 = 0x15,
	SYNDROME_RNR_RETRY_EXC_ERR 	 = 0x16,
	SYNDROME_LOCAL_RDD_VIOL_ERR 	 = 0x20,
	SYNDROME_REMOTE_INVAL_RD_REQ_ERR = 0x21,
	SYNDROME_REMOTE_ABORTED_ERR 	 = 0x22,
	SYNDROME_INVAL_EECN_ERR 	 = 0x23,
	SYNDROME_INVAL_EEC_STATE_ERR 	 = 0x24
};

struct mthca_cqe {
	uint32_t	my_qpn;
	uint32_t	my_ee;
	uint32_t	rqpn;
	uint16_t	sl_g_mlpath;
	uint16_t	rlid;
	uint32_t	imm_etype_pkey_eec;
	uint32_t	byte_cnt;
	uint32_t	wqe;
	uint8_t		opcode;
	uint8_t		is_send;
	uint8_t		reserved;
	uint8_t		owner;
};

struct mthca_err_cqe {
	uint32_t	my_qpn;
	uint32_t	reserved1[3];
	uint8_t		syndrome;
	uint8_t		reserved2;
	uint16_t	db_cnt;
	uint32_t	reserved3;
	uint32_t	wqe;
	uint8_t		opcode;
	uint8_t		reserved4[2];
	uint8_t		owner;
};

static inline struct mthca_cqe *get_cqe(struct mthca_cq *cq, int entry)
{
	return cq->buf + entry * MTHCA_CQ_ENTRY_SIZE;
}

static inline struct mthca_cqe *cqe_sw(struct mthca_cq *cq, int i)
{
	struct mthca_cqe *cqe = get_cqe(cq, i);
	return MTHCA_CQ_ENTRY_OWNER_HW & cqe->owner ? NULL : cqe;
}

static inline struct mthca_cqe *next_cqe_sw(struct mthca_cq *cq)
{
	return cqe_sw(cq, cq->cons_index & cq->ibv_cq.cqe);
}

static inline void set_cqe_hw(struct mthca_cqe *cqe)
{
	cqe->owner = MTHCA_CQ_ENTRY_OWNER_HW;
}

/*
 * incr is ignored in native Arbel (mem-free) mode, so cq->cons_index
 * should be correct before calling update_cons_index().
 */
static inline void update_cons_index(struct mthca_cq *cq, int incr)
{
	uint32_t doorbell[2];

	if (mthca_is_memfree(cq->ibv_cq.context)) {
		*cq->set_ci_db = htonl(cq->cons_index);
		mb();
	} else {
		doorbell[0] = htonl(MTHCA_TAVOR_CQ_DB_INC_CI | cq->cqn);
		doorbell[1] = htonl(incr - 1);

		mthca_write64(doorbell, to_mctx(cq->ibv_cq.context), MTHCA_CQ_DOORBELL);
	}
}

static int handle_error_cqe(struct mthca_cq *cq,
			    struct mthca_qp *qp, int wqe_index, int is_send,
			    struct mthca_err_cqe *cqe,
			    struct ibv_wc *wc, int *free_cqe)
{
	int err;
	int dbd;
	uint32_t new_wqe;

	/*
	 * For completions in error, only work request ID, status (and
	 * freed resource count for RD) have to be set.
	 */
	switch (cqe->syndrome) {
	case SYNDROME_LOCAL_LENGTH_ERR:
		wc->status = IBV_WC_LOC_LEN_ERR;
		break;
	case SYNDROME_LOCAL_QP_OP_ERR:
		wc->status = IBV_WC_LOC_QP_OP_ERR;
		break;
	case SYNDROME_LOCAL_EEC_OP_ERR:
		wc->status = IBV_WC_LOC_EEC_OP_ERR;
		break;
	case SYNDROME_LOCAL_PROT_ERR:
		wc->status = IBV_WC_LOC_PROT_ERR;
		break;
	case SYNDROME_WR_FLUSH_ERR:
		wc->status = IBV_WC_WR_FLUSH_ERR;
		break;
	case SYNDROME_MW_BIND_ERR:
		wc->status = IBV_WC_MW_BIND_ERR;
		break;
	case SYNDROME_BAD_RESP_ERR:
		wc->status = IBV_WC_BAD_RESP_ERR;
		break;
	case SYNDROME_LOCAL_ACCESS_ERR:
		wc->status = IBV_WC_LOC_ACCESS_ERR;
		break;
	case SYNDROME_REMOTE_INVAL_REQ_ERR:
		wc->status = IBV_WC_REM_INV_REQ_ERR;
		break;
	case SYNDROME_REMOTE_ACCESS_ERR:
		wc->status = IBV_WC_REM_ACCESS_ERR;
		break;
	case SYNDROME_REMOTE_OP_ERR:
		wc->status = IBV_WC_REM_OP_ERR;
		break;
	case SYNDROME_RETRY_EXC_ERR:
		wc->status = IBV_WC_RETRY_EXC_ERR;
		break;
	case SYNDROME_RNR_RETRY_EXC_ERR:
		wc->status = IBV_WC_RNR_RETRY_EXC_ERR;
		break;
	case SYNDROME_LOCAL_RDD_VIOL_ERR:
		wc->status = IBV_WC_LOC_RDD_VIOL_ERR;
		break;
	case SYNDROME_REMOTE_INVAL_RD_REQ_ERR:
		wc->status = IBV_WC_REM_INV_RD_REQ_ERR;
		break;
	case SYNDROME_REMOTE_ABORTED_ERR:
		wc->status = IBV_WC_REM_ABORT_ERR;
		break;
	case SYNDROME_INVAL_EECN_ERR:
		wc->status = IBV_WC_INV_EECN_ERR;
		break;
	case SYNDROME_INVAL_EEC_STATE_ERR:
		wc->status = IBV_WC_INV_EEC_STATE_ERR;
		break;
	default:
		wc->status = IBV_WC_GENERAL_ERR;
		break;
	}

	/*
	 * Mem-free HCAs always generate one CQE per WQE, even in the
	 * error case, so we don't have to check the doorbell count, etc.
	 */
	if (mthca_is_memfree(cq->ibv_cq.context))
		return 0;

	err = mthca_free_err_wqe(qp, is_send, wqe_index, &dbd, &new_wqe);
	if (err)
		return err;

	/*
	 * If we're at the end of the WQE chain, or we've used up our
	 * doorbell count, free the CQE.  Otherwise just update it for
	 * the next poll operation.
	 */
	if (!(new_wqe & htonl(0x3f)) || (!cqe->db_cnt && dbd))
		return 0;

	cqe->db_cnt   = htons(ntohs(cqe->db_cnt) - dbd);
	cqe->wqe      = new_wqe;
	cqe->syndrome = SYNDROME_WR_FLUSH_ERR;

	*free_cqe = 0;

	return 0;
}

static void dump_cqe(struct mthca_cqe *cqe)
{
	int j;

	for (j = 0; j < 8; ++j)
		printf("  [%2x] %08x\n", j * 4, ntohl(((uint32_t *) cqe)[j]));
}

static inline int mthca_poll_one(struct mthca_cq *cq,
				 struct mthca_qp **cur_qp,
				 int *freed,
				 struct ibv_wc *wc)
{
	struct mthca_wq *wq;
	struct mthca_cqe *cqe;
	struct mthca_srq *srq;
	uint32_t qpn;
	uint32_t wqe;
	int wqe_index;
	int is_error;
	int is_send;
	int free_cqe = 1;
	int err = 0;

	cqe = next_cqe_sw(cq);
	if (!cqe)
		return CQ_EMPTY;

	/*
	 * Make sure we read CQ entry contents after we've checked the
	 * ownership bit.
	 */
	mb();

	qpn = ntohl(cqe->my_qpn);

	is_error = (cqe->opcode & MTHCA_ERROR_CQE_OPCODE_MASK) ==
		MTHCA_ERROR_CQE_OPCODE_MASK;
	is_send  = is_error ? cqe->opcode & 0x01 : cqe->is_send & 0x80;

	if (is_error)
		dump_cqe(cqe);

	if (!*cur_qp || ntohl(cqe->my_qpn) != (*cur_qp)->ibv_qp.qp_num) {
		/*
		 * We do not have to take the QP table lock here,
		 * because CQs will be locked while QPs are removed
		 * from the table.
		 */
		*cur_qp = mthca_find_qp(to_mctx(cq->ibv_cq.context), ntohl(cqe->my_qpn));
		if (!*cur_qp) {
			err = CQ_POLL_ERR;
			goto out;
		}
	}

	wc->qp_num = (*cur_qp)->ibv_qp.qp_num;

	if (is_send) {
		wq = &(*cur_qp)->sq;
		wqe_index = ((ntohl(cqe->wqe) - (*cur_qp)->send_wqe_offset) >> wq->wqe_shift);
		wc->wr_id = (*cur_qp)->wrid[wqe_index + (*cur_qp)->rq.max];
	} else if ((*cur_qp)->ibv_qp.srq) {
		srq = to_msrq((*cur_qp)->ibv_qp.srq);
		wqe = htonl(cqe->wqe);
		wq = NULL;
		wqe_index = wqe >> srq->wqe_shift;
		wc->wr_id = srq->wrid[wqe_index];
		mthca_free_srq_wqe(srq, wqe);
	} else {
		wq = &(*cur_qp)->rq;
		wqe_index = ntohl(cqe->wqe) >> wq->wqe_shift;
		wc->wr_id = (*cur_qp)->wrid[wqe_index];
	}

	if (wq) {
		if (wq->last_comp < wqe_index)
			wq->tail += wqe_index - wq->last_comp;
		else
			wq->tail += wqe_index + wq->max - wq->last_comp;

		wq->last_comp = wqe_index;
	}

	if (is_error) {
		err = handle_error_cqe(cq, *cur_qp, wqe_index, is_send,
				       (struct mthca_err_cqe *) cqe,
				       wc, &free_cqe);
		goto out;
	}

	if (is_send) {
		wc->wc_flags = 0;
		switch (cqe->opcode) {
		case MTHCA_OPCODE_RDMA_WRITE:
			wc->opcode    = IBV_WC_RDMA_WRITE;
			break;
		case MTHCA_OPCODE_RDMA_WRITE_IMM:
			wc->opcode    = IBV_WC_RDMA_WRITE;
			wc->wc_flags |= IBV_WC_WITH_IMM;
			break;
		case MTHCA_OPCODE_SEND:
			wc->opcode    = IBV_WC_SEND;
			break;
		case MTHCA_OPCODE_SEND_IMM:
			wc->opcode    = IBV_WC_SEND;
			wc->wc_flags |= IBV_WC_WITH_IMM;
			break;
		case MTHCA_OPCODE_RDMA_READ:
			wc->opcode    = IBV_WC_RDMA_READ;
			wc->byte_len  = ntohl(cqe->byte_cnt);
			break;
		case MTHCA_OPCODE_ATOMIC_CS:
			wc->opcode    = IBV_WC_COMP_SWAP;
			wc->byte_len  = ntohl(cqe->byte_cnt);
			break;
		case MTHCA_OPCODE_ATOMIC_FA:
			wc->opcode    = IBV_WC_FETCH_ADD;
			wc->byte_len  = ntohl(cqe->byte_cnt);
			break;
		case MTHCA_OPCODE_BIND_MW:
			wc->opcode    = IBV_WC_BIND_MW;
			break;
		default:
			/* assume it's a send completion */
			wc->opcode    = IBV_WC_SEND;
			break;
		}
	} else {
		wc->byte_len = ntohl(cqe->byte_cnt);
		switch (cqe->opcode & 0x1f) {
		case IBV_OPCODE_SEND_LAST_WITH_IMMEDIATE:
		case IBV_OPCODE_SEND_ONLY_WITH_IMMEDIATE:
			wc->wc_flags = IBV_WC_WITH_IMM;
			wc->imm_data = cqe->imm_etype_pkey_eec;
			wc->opcode = IBV_WC_RECV;
			break;
		case IBV_OPCODE_RDMA_WRITE_LAST_WITH_IMMEDIATE:
		case IBV_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE:
			wc->wc_flags = IBV_WC_WITH_IMM;
			wc->imm_data = cqe->imm_etype_pkey_eec;
			wc->opcode = IBV_WC_RECV_RDMA_WITH_IMM;
			break;
		default:
			wc->wc_flags = 0;
			wc->opcode = IBV_WC_RECV;
			break;
		}
		wc->slid 	   = ntohs(cqe->rlid);
		wc->sl   	   = ntohs(cqe->sl_g_mlpath) >> 12;
		wc->src_qp 	   = ntohl(cqe->rqpn) & 0xffffff;
		wc->dlid_path_bits = ntohs(cqe->sl_g_mlpath) & 0x7f;
		wc->pkey_index     = ntohl(cqe->imm_etype_pkey_eec) >> 16;
		wc->wc_flags      |= ntohs(cqe->sl_g_mlpath) & 0x80 ?
			IBV_WC_GRH : 0;
	}

	wc->status = IBV_WC_SUCCESS;

out:
	if (free_cqe) {
		set_cqe_hw(cqe);
		++(*freed);
		++cq->cons_index;
	}

	return err;
}

int mthca_poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	struct mthca_cq *cq = to_mcq(ibcq);
	struct mthca_qp *qp = NULL;
	int npolled;
	int err = CQ_OK;
	int freed = 0;

	pthread_spin_lock(&cq->lock);

	for (npolled = 0; npolled < ne; ++npolled) {
		err = mthca_poll_one(cq, &qp, &freed, wc + npolled);
		if (err != CQ_OK)
			break;
	}

	if (freed) {
		mb();
		update_cons_index(cq, freed);
	}

	pthread_spin_unlock(&cq->lock);

	return err == CQ_POLL_ERR ? err : npolled;
}

int mthca_tavor_arm_cq(struct ibv_cq *cq, int solicited)
{
	uint32_t doorbell[2];

	doorbell[0] = htonl((solicited ?
			     MTHCA_TAVOR_CQ_DB_REQ_NOT_SOL :
			     MTHCA_TAVOR_CQ_DB_REQ_NOT)      |
			    to_mcq(cq)->cqn);
	doorbell[1] = 0xffffffff;

	mthca_write64(doorbell, to_mctx(cq->context), MTHCA_CQ_DOORBELL);

	return 0;
}

int mthca_arbel_arm_cq(struct ibv_cq *ibvcq, int solicited)
{
	struct mthca_cq *cq = to_mcq(ibvcq);
	uint32_t doorbell[2];
	uint32_t sn;
	uint32_t ci;

	sn = cq->arm_sn & 3;
	ci = htonl(cq->cons_index);

	doorbell[0] = ci;
	doorbell[1] = htonl((cq->cqn << 8) | (2 << 5) | (sn << 3) |
			    (solicited ? 1 : 2));

	mthca_write_db_rec(doorbell, cq->arm_db);

	/*
	 * Make sure that the doorbell record in host memory is
	 * written before ringing the doorbell via PCI MMIO.
	 */
	mb();

	doorbell[0] = htonl((sn << 28)                       |
			    (solicited ?
			     MTHCA_ARBEL_CQ_DB_REQ_NOT_SOL :
			     MTHCA_ARBEL_CQ_DB_REQ_NOT)      |
			    cq->cqn);
	doorbell[1] = ci;

	mthca_write64(doorbell, to_mctx(ibvcq->context), MTHCA_CQ_DOORBELL);

	return 0;
}

void mthca_arbel_cq_event(struct ibv_cq *cq)
{
	to_mcq(cq)->arm_sn++;
}

void mthca_init_cq_buf(struct mthca_cq *cq, int nent)
{
	int i;

	for (i = 0; i < nent; ++i)
		set_cqe_hw(get_cqe(cq, i));

	cq->cons_index = 0;
}
