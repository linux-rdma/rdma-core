/*
 * Copyright (c) 2006 - 2007 NetEffect, Inc. All rights reserved.
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
#include <config.h>
#endif				/* HAVE_CONFIG_H */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <malloc.h>
#include <sys/mman.h>
#include <netinet/in.h>

#include "nes_umain.h"
#include "nes-abi.h"

extern long int page_size;


/**
 * nes_uquery_device
 */
int nes_uquery_device(struct ibv_context *context, struct ibv_device_attr *attr)
{
	struct ibv_query_device cmd;
	uint64_t reserved;
	int ret;

	ret = ibv_cmd_query_device(context, attr, &reserved, &cmd, sizeof cmd);
	if (ret)
		return ret;

	return 0;
}


/**
 * nes_uquery_port
 */
int nes_uquery_port(struct ibv_context *context, uint8_t port,
		struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof cmd);
}


/**
 * nes_ualloc_pd
 */
struct ibv_pd *nes_ualloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct nes_ualloc_pd_resp resp;
	struct nes_upd *nesupd;

	nesupd = malloc(sizeof *nesupd);
	if (!nesupd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, &nesupd->ibv_pd, &cmd, sizeof cmd,
			&resp.ibv_resp, sizeof resp)) {
		free(nesupd);
		return NULL;
	}
	nesupd->pd_id = resp.pd_id;
	nesupd->db_index = resp.db_index;

	nesupd->udoorbell = mmap(NULL, page_size, PROT_WRITE | PROT_READ, MAP_SHARED,
			context->cmd_fd, nesupd->db_index * page_size);

	if (((void *)-1) == nesupd->udoorbell) {
		free(nesupd);
		return NULL;
	}

	return (&nesupd->ibv_pd);
}


/**
 * nes_ufree_pd
 */
int nes_ufree_pd(struct ibv_pd *pd)
{
	int ret;
	struct nes_upd *nesupd;

	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	nesupd = to_nes_upd(pd);

	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	munmap((void *)nesupd->udoorbell, page_size);
	free(nesupd);
	return 0;
}


/**
 * nes_ureg_mr
 */
struct ibv_mr *nes_ureg_mr(struct ibv_pd *pd, void *addr,
		size_t length, enum ibv_access_flags access)
{
	struct ibv_mr *mr;
	struct nes_ureg_mr cmd;
#ifdef IBV_CMD_REG_MR_HAS_RESP_PARAMS
	struct ibv_reg_mr_resp resp;
#endif
	/* fprintf(stderr, PFX "%s: address = %p, length = %u.\n",
			__FUNCTION__, addr, length); */

	mr = malloc(sizeof *mr);
	if (!mr)
		return NULL;

	cmd.reg_type = NES_UMEMREG_TYPE_MEM;
#ifdef IBV_CMD_REG_MR_HAS_RESP_PARAMS
	if (ibv_cmd_reg_mr(pd, addr, length, (uintptr_t) addr,
			access, mr, &cmd.ibv_cmd, sizeof cmd,
			&resp, sizeof resp)) {
#else
	if (ibv_cmd_reg_mr(pd, addr, length, (uintptr_t) addr,
			access, mr, &cmd.ibv_cmd, sizeof cmd)) {
#endif
		fprintf(stderr, "ibv_cmd_reg_mr failed\n");
		free(mr);
		return NULL;
	}

	return mr;
}


/**
 * nes_udereg_mr
 */
int nes_udereg_mr(struct ibv_mr *mr)
{
	int ret;

	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */

	ret = ibv_cmd_dereg_mr(mr);
	if (ret)
		return ret;

	free(mr);
	return 0;
}


/**
 * nes_ucreate_cq
 */
struct ibv_cq *nes_ucreate_cq(struct ibv_context *context, int cqe,
		struct ibv_comp_channel *channel, int comp_vector)
{
	struct nes_ucq *nesucq;
	struct nes_ureg_mr reg_mr_cmd;
#ifdef IBV_CMD_REG_MR_HAS_RESP_PARAMS
	struct ibv_reg_mr_resp reg_mr_resp;
#endif
	struct nes_ucreate_cq cmd;
	struct nes_ucreate_cq_resp resp;
	int ret;
	struct nes_uvcontext *nesvctx = to_nes_uctx(context);

	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */

	nesucq = malloc(sizeof *nesucq);
	/* fprintf(stderr, "nesucq=%p, size=%u\n", nesucq, sizeof(*nesucq)); */
	if (!nesucq) {
		return NULL;
	}
	memset(nesucq, 0, sizeof(*nesucq));

	if (pthread_spin_init(&nesucq->lock, PTHREAD_PROCESS_PRIVATE)) {
		free(nesucq);
		return NULL;
	}

	if (cqe < 4) /* just trying to keep to a reasonable minimum */
		cqe = 4;
	nesucq->size = cqe + 1;

	nesucq->cqes = memalign(page_size, nesucq->size*sizeof(struct nes_hw_cqe));
	if (!nesucq->cqes)
		goto err;

	/* Register the memory for the CQ */
	reg_mr_cmd.reg_type = NES_UMEMREG_TYPE_CQ;


	/* fprintf(stderr, PFX "%s: call ibv_cmd_reg_mr: nesucq->cqes=%p,
			"cq entries=%u, length=0x%lx\n",
			__FUNCTION__, nesucq->cqes, nesucq->size,
			nesucq->size * sizeof(struct nes_hw_cqe)); */

#ifdef IBV_CMD_REG_MR_HAS_RESP_PARAMS
	ret = ibv_cmd_reg_mr(&nesvctx->nesupd->ibv_pd, (void *)nesucq->cqes,
			(nesucq->size*sizeof(struct nes_hw_cqe)),
			(uintptr_t)nesucq->cqes, IBV_ACCESS_LOCAL_WRITE, &nesucq->mr,
			&reg_mr_cmd.ibv_cmd, sizeof reg_mr_cmd,
			&reg_mr_resp, sizeof reg_mr_resp);
#else
	ret = ibv_cmd_reg_mr(&nesvctx->nesupd->ibv_pd, (void *)nesucq->cqes,
			(nesucq->size*sizeof(struct nes_hw_cqe)),
			(uintptr_t)nesucq->cqes, IBV_ACCESS_LOCAL_WRITE, &nesucq->mr,
			&reg_mr_cmd.ibv_cmd, sizeof reg_mr_cmd);
#endif
	if (ret) {
		fprintf(stderr, "ibv_cmd_reg_mr failed (ret = %d).\n", ret);
		free((struct nes_hw_cqe *)nesucq->cqes);
		goto err;
	}

	/* Create the CQ */
	memset(&cmd, 0, sizeof(cmd));
	cmd.user_cq_buffer = (__u64)((uintptr_t)nesucq->cqes);

	ret = ibv_cmd_create_cq(context, nesucq->size-1, channel, comp_vector,
			&nesucq->ibv_cq, &cmd.ibv_cmd, sizeof cmd,
			&resp.ibv_resp, sizeof resp);
	if (ret)
		goto err;

	nesucq->cq_id = (uint16_t)resp.cq_id;
	if (nesucq->size != (uint16_t)resp.cq_size) {
		fprintf(stderr, PFX "%s: CQ allocation error: number of requested"
				" entries = %u, returned = %u.\n",
				__FUNCTION__, nesucq->size, (uint16_t)resp.cq_size);
	}

	/* Zero out the CQ */
	memset((struct nes_hw_cqe *)nesucq->cqes, 0, nesucq->size*sizeof(struct nes_hw_cqe));

	return (&nesucq->ibv_cq);

err:
 	fprintf(stderr, PFX "%s: Error Creating CQ.\n", __FUNCTION__);
	pthread_spin_destroy(&nesucq->lock);
	free(nesucq);

	return NULL;
}


/**
 * nes_uresize_cq
 */
int nes_uresize_cq(struct ibv_cq *cq, int cqe)
{
 	fprintf(stderr, PFX "%s\n", __FUNCTION__);

	return -ENOSYS;
}


/**
 * nes_udestroy_cq
 */
int nes_udestroy_cq(struct ibv_cq *cq)
{
	struct nes_ucq *nesucq = to_nes_ucq(cq);
	int ret;

	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */

	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		return ret;

	/* Free CQ the memory */
	free((struct nes_hw_cqe *)nesucq->cqes);
	pthread_spin_destroy(&nesucq->lock);
	free(nesucq);

	return 0;
}


/**
 * nes_upoll_cq
 */
int nes_upoll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *entry)
{
	uint64_t wrid;
	struct nes_ucq *nesucq;
	struct nes_uvcontext *nesvctx = NULL;
	struct nes_uqp *nesuqp;
	int cqe_count=0;
	uint32_t head;
	uint32_t wq_tail;
	uint32_t cq_size;
	uint32_t wqe_index;
	struct nes_hw_cqe cqe;
	uint32_t tmp;

	/* fprintf(stderr, PFX "%s:%s:%u\n", __FILE__, __FUNCTION__, __LINE__); */

	nesucq = to_nes_ucq(cq);
	nesvctx = to_nes_uctx(cq->context);

	pthread_spin_lock(&nesucq->lock);

	head = nesucq->head;
	cq_size = nesucq->size;

	while (cqe_count<num_entries) {
		if (nesucq->cqes[head].cqe_words[NES_CQE_OPCODE_IDX] & NES_CQE_VALID) {
			cqe = (volatile struct nes_hw_cqe)nesucq->cqes[head];

			memset(entry, 0, sizeof *entry);
			/* this is for both the cqe copy and the zeroing of entry */
			asm __volatile__("": : :"memory");

			nesucq->cqes[head].cqe_words[NES_CQE_OPCODE_IDX] = 0;

			/* parse CQE, get completion context from WQE (either rq or sq */
			wqe_index = cqe.cqe_words[NES_CQE_COMP_COMP_CTX_LOW_IDX] & 511;
			nesuqp = *((struct nes_uqp **)&cqe.cqe_words[NES_CQE_COMP_COMP_CTX_LOW_IDX]);
			nesuqp = (struct nes_uqp *)((uintptr_t)nesuqp & (~1023));
			/* fprintf(stderr, PFX "wqe index = %u. nesuqp = %p\n", wqe_index, nesuqp); */
			if (0 == cqe.cqe_words[NES_CQE_ERROR_CODE_IDX]) {
				entry->status = IBV_WC_SUCCESS;
			} else {
				/* TODO: other errors? */
				entry->status = IBV_WC_WR_FLUSH_ERR;
			}
			entry->qp_num = nesuqp->qp_id;
			entry->src_qp = nesuqp->qp_id;

			if (cqe.cqe_words[NES_CQE_OPCODE_IDX] & NES_CQE_SQ) {
				/* Working on a SQ Completion*/
				wq_tail = wqe_index;
				nesuqp->sq_tail = (wqe_index+1)&(nesuqp->sq_size - 1);
				wrid = *((uint64_t *)&nesuqp->sq_vbase[wq_tail].
						wqe_words[NES_IWARP_SQ_WQE_COMP_SCRATCH_LOW_IDX]);
				entry->byte_len = nesuqp->sq_vbase[wq_tail].
						wqe_words[NES_IWARP_SQ_WQE_TOTAL_PAYLOAD_IDX];

				switch (nesuqp->sq_vbase[wq_tail].
						wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] & 0x3f) {
					case NES_IWARP_SQ_OP_RDMAW:
						/* fprintf(stderr, PFX "%s: Operation = RDMA WRITE.\n",
								__FUNCTION__ ); */
						entry->opcode = IBV_WC_RDMA_WRITE;
						break;
					case NES_IWARP_SQ_OP_RDMAR:
						/* fprintf(stderr, PFX "%s: Operation = RDMA READ.\n",
								__FUNCTION__ ); */
						entry->opcode = IBV_WC_RDMA_READ;
						entry->byte_len = nesuqp->sq_vbase[wq_tail].
								wqe_words[NES_IWARP_SQ_WQE_RDMA_LENGTH_IDX];
						break;
					case NES_IWARP_SQ_OP_SENDINV:
					case NES_IWARP_SQ_OP_SENDSEINV:
					case NES_IWARP_SQ_OP_SEND:
					case NES_IWARP_SQ_OP_SENDSE:
						/* fprintf(stderr, PFX "%s: Operation = Send.\n",
								__FUNCTION__ ); */
						entry->opcode = IBV_WC_SEND;
						break;
				}
			} else {
				/* Working on a RQ Completion*/
				wq_tail = wqe_index;
				nesuqp->rq_tail = (wqe_index+1)&(nesuqp->rq_size - 1);
				entry->byte_len = cqe.cqe_words[NES_CQE_PAYLOAD_LENGTH_IDX];

				wrid = *((uint64_t *)&nesuqp->rq_vbase[wq_tail].
						wqe_words[NES_IWARP_RQ_WQE_COMP_SCRATCH_LOW_IDX]);
				entry->opcode = IBV_WC_RECV;
			}
			entry->wr_id = wrid;

			if (++head >= cq_size)
				head = 0;
			cqe_count++;
			nesucq->polled_completions++;

			/* TODO: find a better number...if there is one */
			if ((nesucq->polled_completions > (cq_size/2)) ||
					(nesucq->polled_completions == 255)) {
				if (NULL == nesvctx)
					nesvctx = to_nes_uctx(cq->context);
				nesvctx->nesupd->udoorbell->cqe_alloc = nesucq->cq_id |
						(nesucq->polled_completions << 16);
				tmp = nesvctx->nesupd->udoorbell->cqe_alloc;
				nesucq->polled_completions = 0;
			}
			entry++;
		} else
			break;
	}

	if (nesucq->polled_completions) {
		if (NULL == nesvctx)
			nesvctx = to_nes_uctx(cq->context);
		nesvctx->nesupd->udoorbell->cqe_alloc = nesucq->cq_id |
				(nesucq->polled_completions << 16);
		tmp = nesvctx->nesupd->udoorbell->cqe_alloc;
		nesucq->polled_completions = 0;
	}
	nesucq->head = head;

	pthread_spin_unlock(&nesucq->lock);
	return cqe_count;
}


/**
 * nes_uarm_cq
 */
int nes_uarm_cq(struct ibv_cq *cq, int solicited)
{
	struct nes_ucq *nesucq;
	struct nes_uvcontext *nesvctx;
	uint32_t cq_arm;
	uint32_t tmp;

	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */

	nesucq = to_nes_ucq(cq);
	nesvctx = to_nes_uctx(cq->context);

	/* fprintf(stderr, PFX "%s: Requesting notification for CQ%u.\n",
			__FUNCTION__, nesucq->cq_id); */
	cq_arm = nesucq->cq_id;

	if (solicited)
		cq_arm |= NES_CQE_ALLOC_NOTIFY_SE;
	else
		cq_arm |= NES_CQE_ALLOC_NOTIFY_NEXT;

	/* fprintf(stderr, PFX "%s: Arming CQ%u, command = 0x%08X.\n",
			__FUNCTION__, nesucq->cq_id, cq_arm); */
	nesvctx->nesupd->udoorbell->cqe_alloc = cq_arm;
	tmp = nesvctx->nesupd->udoorbell->cqe_alloc;

	return 0;
}


/**
 * nes_ucreate_srq
 */
struct ibv_srq *nes_ucreate_srq(struct ibv_pd *pd, struct ibv_srq_init_attr *attr)
{
	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return (void *)-ENOSYS;
}


/**
 * nes_umodify_srq
 */
int nes_umodify_srq(struct ibv_srq *srq, struct ibv_srq_attr *attr,
		enum ibv_srq_attr_mask attr_mask)
{
	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return -ENOSYS;
}


/**
 * nes_udestroy_srq
 */
int nes_udestroy_srq(struct ibv_srq *srq)
{
	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return -ENOSYS;
}


/**
 * nes_upost_srq_recv
 */
int nes_upost_srq_recv(struct ibv_srq *ibsrq, struct ibv_recv_wr *wr,
		struct ibv_recv_wr **bad_wr)
{
	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return -ENOSYS;
}


/**
 * nes_ucreate_qp
 */
struct ibv_qp *nes_ucreate_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct nes_uqp *nesuqp;
	struct nes_uvcontext *nesvctx = to_nes_uctx(pd->context);
	struct nes_ucreate_qp cmd;
	struct nes_ucreate_qp_resp resp;
	unsigned long mmap_offset;
	int ret;

	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	/* Sanity check QP size before proceeding */
	if (attr->cap.max_send_wr > 510 ||
			attr->cap.max_recv_wr > 510 ||
			attr->cap.max_send_sge > 4 ||
			attr->cap.max_recv_sge > 4 )
		return NULL;

	nesuqp = memalign(1024, sizeof(*nesuqp));
	if (!nesuqp)
		return NULL;
	memset(nesuqp, 0, sizeof(*nesuqp));

	if (pthread_spin_init(&nesuqp->lock, PTHREAD_PROCESS_PRIVATE)) {
		free(nesuqp);
		return NULL;
	}

	ret = ibv_cmd_create_qp(pd, &nesuqp->ibv_qp, attr, &cmd.ibv_cmd, sizeof cmd,
			&resp.ibv_resp, sizeof resp);
	if (ret) {
		pthread_spin_destroy(&nesuqp->lock);
		free(nesuqp);
		return NULL;
	}

	nesuqp->qp_id = resp.qp_id;
	nesuqp->sq_db_index = resp.mmap_sq_db_index;
	nesuqp->rq_db_index = resp.mmap_rq_db_index;
	nesuqp->sq_size = resp.actual_sq_size;
	nesuqp->rq_size = resp.actual_rq_size;
	/* Account for LSMM, in theory, could get overrun if app preposts to SQ */
	nesuqp->sq_head = 1;
	nesuqp->sq_tail = 1;

	/* Map the SQ/RQ buffers */
	mmap_offset = ((nesvctx->max_pds*4096) + page_size-1) & (~(page_size-1));
	mmap_offset += (((sizeof(struct nes_hw_qp_wqe) * nesvctx->wq_size) + page_size-1) &
			(~(page_size-1)))*nesuqp->sq_db_index;

	nesuqp->sq_vbase = mmap(NULL, (nesuqp->sq_size+nesuqp->rq_size) *
			sizeof(struct nes_hw_qp_wqe), PROT_WRITE | PROT_READ,
			MAP_SHARED, pd->context->cmd_fd, mmap_offset);

	if (((void *)-1) == nesuqp->sq_vbase) {
		pthread_spin_destroy(&nesuqp->lock);
		free(nesuqp);
		return NULL;
	}
	nesuqp->rq_vbase = (struct nes_hw_qp_wqe *)(((char *)nesuqp->sq_vbase) +
			(nesuqp->sq_size*sizeof(struct nes_hw_qp_wqe)));
	*((unsigned int *)nesuqp->sq_vbase) = 0;

	return (&nesuqp->ibv_qp);
}


/**
 * nes_uquery_qp
 */
int nes_uquery_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		enum ibv_qp_attr_mask attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	/* fprintf(stderr, PFX "nes_uquery_qp: calling ibv_cmd_query_qp\n"); */

	return (ibv_cmd_query_qp(qp, attr, attr_mask, init_attr, &cmd, sizeof(cmd)));
}


/**
 * nes_umodify_qp
 */
int nes_umodify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		enum ibv_qp_attr_mask attr_mask)
{
	struct ibv_modify_qp cmd;

	/* fprintf(stderr, PFX "%s, QP State = %u, attr_mask = 0x%X.\n", __FUNCTION__,
			(unsigned int)attr->qp_state, (unsigned int)attr_mask ); */
	return (ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof cmd));
}


/**
 * nes_udestroy_qp
 */
int nes_udestroy_qp(struct ibv_qp *qp)
{
	struct nes_uqp *nesuqp = to_nes_uqp(qp);
	int ret;

	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */

	munmap((void *) nesuqp->sq_vbase, (nesuqp->sq_size+nesuqp->rq_size) *
			sizeof(struct nes_hw_qp_wqe));


	ret = ibv_cmd_destroy_qp(qp);
	if (ret)
		return ret;

	pthread_spin_destroy(&nesuqp->lock);
	free(nesuqp);

	return 0;
}


/**
 * nes_upost_send
 */
int nes_upost_send(struct ibv_qp *ib_qp, struct ibv_send_wr *ib_wr,
		struct ibv_send_wr **bad_wr)
{
	struct nes_uqp *nesuqp = to_nes_uqp(ib_qp);
	struct nes_upd *nesupd = to_nes_upd(ib_qp->pd);
	struct nes_hw_qp_wqe volatile *wqe;
	uint32_t head = nesuqp->sq_head;
	uint32_t qsize = nesuqp->sq_size;
	uint32_t counter;
	uint32_t err = 0;
	uint32_t wqe_count = 0;
	uint32_t outstanding_wqes;
	int sge_index;
	uint32_t total_payload_length = 0;

	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	pthread_spin_lock(&nesuqp->lock);

	while (ib_wr) {
		/* Check for SQ overflow */
		outstanding_wqes = head + (2 * qsize) - nesuqp->sq_tail;
		outstanding_wqes &= qsize - 1;
		if (unlikely(outstanding_wqes == (qsize - 1))) {
			err = -EINVAL;
			break;
		}
		if (unlikely(ib_wr->num_sge > 4)) {
			err = -EINVAL;
			break;
		}

		wqe = (struct nes_hw_qp_wqe *)&nesuqp->sq_vbase[head];
		/* fprintf(stderr, PFX "%s: QP%u: processing sq wqe at %p, head = %u.\n",
				__FUNCTION__, nesuqp->qp_id, wqe, head);  */
		*((volatile uint64_t *)&wqe->wqe_words[NES_IWARP_SQ_WQE_COMP_SCRATCH_LOW_IDX]) =
					ib_wr->wr_id;
		*((volatile uint64_t *)&wqe->wqe_words[NES_IWARP_SQ_WQE_COMP_CTX_LOW_IDX]) =
					(uint64_t)((uintptr_t)nesuqp);
		asm __volatile__("": : :"memory");
		wqe->wqe_words[NES_IWARP_SQ_WQE_COMP_CTX_LOW_IDX] |= head;

		switch (ib_wr->opcode) {
		case IBV_WR_SEND:
		case IBV_WR_SEND_WITH_IMM:
			/* fprintf(stderr, PFX "%s: QP%u: processing sq wqe%u. Opcode = %s\n",
					__FUNCTION__, nesuqp->qp_id, head, "Send"); */
			if (ib_wr->send_flags & IBV_SEND_SOLICITED) {
				wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] = NES_IWARP_SQ_OP_SENDSE;
			} else {
				wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] = NES_IWARP_SQ_OP_SEND;
			}

			if (ib_wr->send_flags & IBV_SEND_FENCE) {
				wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] |= NES_IWARP_SQ_WQE_LOCAL_FENCE;
			}

			/* if (ib_wr->send_flags & IBV_SEND_INLINE) {
				fprintf(stderr, PFX "%s: Send SEND_INLINE, length=%d\n",
						__FUNCTION__, ib_wr->sg_list[0].length);
			} */
			if ((ib_wr->send_flags & IBV_SEND_INLINE) && (ib_wr->sg_list[0].length <= 64) &&
				(ib_wr->num_sge == 1)) {
				memcpy((void *)&wqe->wqe_words[NES_IWARP_SQ_WQE_IMM_DATA_START_IDX],
						(void *)ib_wr->sg_list[0].addr, ib_wr->sg_list[0].length);
				wqe->wqe_words[NES_IWARP_SQ_WQE_TOTAL_PAYLOAD_IDX] = ib_wr->sg_list[0].length;
				wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] |= NES_IWARP_SQ_WQE_IMM_DATA;
			} else {
				total_payload_length = 0;
				for (sge_index=0; sge_index < ib_wr->num_sge; sge_index++) {
					wqe->wqe_words[NES_IWARP_SQ_WQE_FRAG0_LOW_IDX+(sge_index*4)] =
							(uint32_t)ib_wr->sg_list[sge_index].addr;
					wqe->wqe_words[NES_IWARP_SQ_WQE_FRAG0_HIGH_IDX+(sge_index*4)] =
							(uint32_t)(ib_wr->sg_list[sge_index].addr>>32);
					wqe->wqe_words[NES_IWARP_SQ_WQE_LENGTH0_IDX+(sge_index*4)] =
							ib_wr->sg_list[sge_index].length;
					wqe->wqe_words[NES_IWARP_SQ_WQE_STAG0_IDX+(sge_index*4)] =
							ib_wr->sg_list[sge_index].lkey;
					total_payload_length += ib_wr->sg_list[sge_index].length;
				}
				wqe->wqe_words[NES_IWARP_SQ_WQE_TOTAL_PAYLOAD_IDX] = total_payload_length;
			}

			break;
		case IBV_WR_RDMA_WRITE:
		case IBV_WR_RDMA_WRITE_WITH_IMM:
			/* fprintf(stderr, PFX "%s:QP%u: processing sq wqe%u. Opcode = %s\n",
					__FUNCTION__, nesuqp->qp_id, head, "Write"); */
			wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] = NES_IWARP_SQ_OP_RDMAW;

			if (ib_wr->send_flags & IBV_SEND_FENCE) {
				wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] |= NES_IWARP_SQ_WQE_LOCAL_FENCE;
			}
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_STAG_IDX] = ib_wr->wr.rdma.rkey;
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_TO_LOW_IDX] =
					(uint32_t)ib_wr->wr.rdma.remote_addr;
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_TO_HIGH_IDX] =
					(uint32_t)(ib_wr->wr.rdma.remote_addr>>32);

			/* if (ib_wr->send_flags & IBV_SEND_INLINE) {
				fprintf(stderr, PFX "%s: Write SEND_INLINE, length=%d\n",
						__FUNCTION__, ib_wr->sg_list[0].length);
			} */
			if ((ib_wr->send_flags & IBV_SEND_INLINE) && (ib_wr->sg_list[0].length <= 64) &&
				(ib_wr->num_sge == 1)) {
				memcpy((void *)&wqe->wqe_words[NES_IWARP_SQ_WQE_IMM_DATA_START_IDX],
						(void *)ib_wr->sg_list[0].addr, ib_wr->sg_list[0].length);
				wqe->wqe_words[NES_IWARP_SQ_WQE_TOTAL_PAYLOAD_IDX] = ib_wr->sg_list[0].length;
				wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] |= NES_IWARP_SQ_WQE_IMM_DATA;
			} else {
				total_payload_length = 0;
				for (sge_index=0; sge_index < ib_wr->num_sge; sge_index++) {
					wqe->wqe_words[NES_IWARP_SQ_WQE_FRAG0_LOW_IDX+(sge_index*4)] =
							(uint32_t)ib_wr->sg_list[sge_index].addr;
					wqe->wqe_words[NES_IWARP_SQ_WQE_FRAG0_HIGH_IDX+(sge_index*4)] =
							(uint32_t)(ib_wr->sg_list[sge_index].addr>>32);
					wqe->wqe_words[NES_IWARP_SQ_WQE_LENGTH0_IDX+(sge_index*4)] =
							ib_wr->sg_list[sge_index].length;
					wqe->wqe_words[NES_IWARP_SQ_WQE_STAG0_IDX+(sge_index*4)] =
							ib_wr->sg_list[sge_index].lkey;
					total_payload_length += ib_wr->sg_list[sge_index].length;
				}
				wqe->wqe_words[NES_IWARP_SQ_WQE_TOTAL_PAYLOAD_IDX] = total_payload_length;
			}
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_LENGTH_IDX] =
					wqe->wqe_words[NES_IWARP_SQ_WQE_TOTAL_PAYLOAD_IDX];
			break;
		case IBV_WR_RDMA_READ:
			/* fprintf(stderr, PFX "%s:QP%u:processing sq wqe%u. Opcode = %s\n",
					__FUNCTION__, nesuqp->qp_id, head, "Read"); */
			/* IWarp only supports 1 sge for RDMA reads */
			if (ib_wr->num_sge > 1) {
				err = -EINVAL;
				break;
			}
			wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] = NES_IWARP_SQ_OP_RDMAR;
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_TO_LOW_IDX] = (uint32_t)ib_wr->wr.rdma.remote_addr;
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_TO_HIGH_IDX] = (uint32_t)(ib_wr->wr.rdma.remote_addr>>32);
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_STAG_IDX] = ib_wr->wr.rdma.rkey;
			wqe->wqe_words[NES_IWARP_SQ_WQE_RDMA_LENGTH_IDX] = ib_wr->sg_list->length;
			wqe->wqe_words[NES_IWARP_SQ_WQE_FRAG0_LOW_IDX] = (uint32_t)ib_wr->sg_list->addr;
			wqe->wqe_words[NES_IWARP_SQ_WQE_FRAG0_HIGH_IDX] = (uint32_t)(ib_wr->sg_list->addr>>32);
			wqe->wqe_words[NES_IWARP_SQ_WQE_STAG0_IDX] = ib_wr->sg_list->lkey;
			break;
		default:
			/* error */
			err = -EINVAL;
			break;
		}

		if (ib_wr->send_flags & IBV_SEND_SIGNALED) {
			/* fprintf(stderr, PFX "%s:sq wqe%u is signalled\n", __FUNCTION__, head); */
			wqe->wqe_words[NES_IWARP_SQ_WQE_MISC_IDX] |= NES_IWARP_SQ_WQE_SIGNALED_COMPL;
		}
		ib_wr = ib_wr->next;
		head++;
		wqe_count++;
		if (head >= qsize)
			head = 0;
	}

	nesuqp->sq_head = head;
	asm __volatile__("": : :"memory");
	while (wqe_count) {
		counter = (wqe_count<(uint32_t)255) ? wqe_count : 255;
		wqe_count -= counter;
		nesupd->udoorbell->wqe_alloc =  (counter<<24) | 0x00800000 | nesuqp->qp_id;
	}

	if (err)
		*bad_wr = ib_wr;

	pthread_spin_unlock(&nesuqp->lock);

	return err;
}


/**
 * nes_upost_recv
 */
int nes_upost_recv(struct ibv_qp *ib_qp, struct ibv_recv_wr *ib_wr,
		struct ibv_recv_wr **bad_wr)
{
	struct nes_uqp *nesuqp = to_nes_uqp(ib_qp);
	struct nes_upd *nesupd = to_nes_upd(ib_qp->pd);
	struct nes_hw_qp_wqe *wqe;
	uint32_t head = nesuqp->rq_head;
	uint32_t qsize = nesuqp->rq_size;
	uint32_t counter;
	uint32_t err = 0;
	uint32_t wqe_count = 0;
	uint32_t outstanding_wqes;
	int sge_index;
	uint32_t total_payload_length;

	/* fprintf(stderr, PFX "%s: nesuqp = %p, nesupd = %p.\n", __FUNCTION__,
			nesuqp, nesupd); */
	/* fprintf(stderr, PFX "%s: rq_base = %p, sq_base = %p.\n", __FUNCTION__,
			nesuqp->rq_vbase, nesuqp->sq_vbase); */
	pthread_spin_lock(&nesuqp->lock);

	while (ib_wr) {
		/* Check for RQ overflow */
		outstanding_wqes = head + (2 * qsize) - nesuqp->rq_tail;
		outstanding_wqes &= qsize - 1;
		if (unlikely(outstanding_wqes == (qsize - 1))) {
			err = -EINVAL;
			break;
		}

		/* fprintf(stderr, PFX "%s: ibwr (%p) sge count = %u, sglist = %p.\n",
				__FUNCTION__, ib_wr, ib_wr->num_sge, ib_wr->sg_list); */
		wqe = (struct nes_hw_qp_wqe *)&nesuqp->rq_vbase[head];
		/* fprintf(stderr, PFX "%s:QP%u: processing rq wqe at %p, head = %u.\n",
				__FUNCTION__, nesuqp->qp_id, wqe, head); */
		*((uint64_t volatile *)&wqe->wqe_words[NES_IWARP_RQ_WQE_COMP_SCRATCH_LOW_IDX]) =
				ib_wr->wr_id;
		*((uint64_t volatile *)&wqe->wqe_words[NES_IWARP_RQ_WQE_COMP_CTX_LOW_IDX]) =
				(uint64_t)((uintptr_t)nesuqp);
		asm __volatile__("": : :"memory");
		wqe->wqe_words[NES_IWARP_RQ_WQE_COMP_CTX_LOW_IDX] |= head;

		total_payload_length = 0;
		for (sge_index=0; sge_index < ib_wr->num_sge; sge_index++) {
			wqe->wqe_words[NES_IWARP_RQ_WQE_FRAG0_LOW_IDX+(sge_index*4)] =
					(uint32_t)ib_wr->sg_list[sge_index].addr;
			wqe->wqe_words[NES_IWARP_RQ_WQE_FRAG0_HIGH_IDX+(sge_index*4)] =
					(uint32_t)(ib_wr->sg_list[sge_index].addr>>32);
			wqe->wqe_words[NES_IWARP_RQ_WQE_LENGTH0_IDX+(sge_index*4)] =
					ib_wr->sg_list[sge_index].length;
			wqe->wqe_words[NES_IWARP_RQ_WQE_STAG0_IDX+(sge_index*4)] =
					ib_wr->sg_list[sge_index].lkey;
			total_payload_length += ib_wr->sg_list->length;
		}
		wqe->wqe_words[NES_IWARP_RQ_WQE_TOTAL_PAYLOAD_IDX] = total_payload_length;

		ib_wr = ib_wr->next;
		head++;
		wqe_count++;
		if (head >= qsize)
			head = 0;
	}

	nesuqp->rq_head = head;
	asm __volatile__("": : :"memory");
	while (wqe_count) {
		counter = (wqe_count<(uint32_t)255) ? wqe_count : 255;
		wqe_count -= counter;
		nesupd->udoorbell->wqe_alloc = (counter << 24) | nesuqp->qp_id;
	}

	if (err)
		*bad_wr = ib_wr;

	pthread_spin_unlock(&nesuqp->lock);

	return err;
}


/**
 * nes_ucreate_ah
 */
struct ibv_ah *nes_ucreate_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return (void *)-ENOSYS;
}


/**
 * nes_udestroy_ah
 */
int nes_udestroy_ah(struct ibv_ah *ah)
{
	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return -ENOSYS;
}


/**
 * nes_uattach_mcast
 */
int nes_uattach_mcast(struct ibv_qp *qp, union ibv_gid *gid, uint16_t lid)
{
	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return -ENOSYS;
}


/**
 * nes_udetach_mcast
 */
int nes_udetach_mcast(struct ibv_qp *qp, union ibv_gid *gid, uint16_t lid)
{
	/* fprintf(stderr, PFX "%s\n", __FUNCTION__); */
	return -ENOSYS;
}

