// SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
/*
 * Copyright (c) 2024 ZTE Corporation.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "zxdh_status.h"
#include "zxdh_defs.h"
#include "zxdh_verbs.h"
#include "zxdh_zrdma.h"
#include <errno.h>
#include <ccan/container_of.h>
#include "private_verbs_cmd.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#define ERROR_CODE_VALUE 65

static inline void qp_tx_psn_add(__u32 *x, __u32 y, __u16 mtu)
{
	if (y == 0) {
		*x = (*x + 1) & 0xffffff;
		return;
	}
	__u32 chunks = (y + mtu - 1) / mtu;
	*x = (*x + chunks) & 0xffffff;
}

/**
 * zxdh_fragcnt_to_quanta_sq - calculate quanta based on fragment count for SQ
 * @frag_cnt: number of fragments
 * @quanta: quanta for frag_cnt
 */
static inline enum zxdh_status_code zxdh_fragcnt_to_quanta_sq(__u32 frag_cnt,
							      __u16 *quanta)
{
	if (unlikely(frag_cnt > ZXDH_MAX_SQ_FRAG))
		return ZXDH_ERR_INVALID_FRAG_COUNT;
	*quanta = (frag_cnt >> 1) + 1;
	return 0;
}

/**
 * zxdh_set_fragment - set fragment in wqe
 * @wqe: wqe for setting fragment
 * @offset: offset value
 * @sge: sge length and stag
 * @valid: The wqe valid
 */
static void zxdh_set_fragment(__le64 *wqe, __u32 offset, struct zxdh_sge *sge,
			      __u8 valid)
{
	if (sge) {
		set_64bit_val(wqe, offset + 8,
			      FIELD_PREP(ZXDHQPSQ_FRAG_TO, sge->tag_off));
		set_64bit_val(wqe, offset,
			      FIELD_PREP(ZXDHQPSQ_VALID, valid) |
				      FIELD_PREP(ZXDHQPSQ_FRAG_LEN, sge->len) |
				      FIELD_PREP(ZXDHQPSQ_FRAG_STAG,
						 sge->stag));
	} else {
		set_64bit_val(wqe, offset + 8, 0);
		set_64bit_val(wqe, offset, FIELD_PREP(ZXDHQPSQ_VALID, valid));
	}
}

/**
 * zxdh_nop_1 - insert a NOP wqe
 * @qp: hw qp ptr
 */
static enum zxdh_status_code zxdh_nop_1(struct zxdh_qp *qp)
{
	__u64 hdr;
	__le64 *wqe;
	__u32 wqe_idx;
	bool signaled = false;

	if (!qp->sq_ring.head)
		return ZXDH_ERR_PARAM;

	wqe_idx = ZXDH_RING_CURRENT_HEAD(qp->sq_ring);
	wqe = qp->sq_base[wqe_idx].elem;

	qp->sq_wrtrk_array[wqe_idx].quanta = ZXDH_QP_WQE_MIN_QUANTA;

	set_64bit_val(wqe, 8, 0);
	set_64bit_val(wqe, 16, 0);
	set_64bit_val(wqe, 24, 0);

	hdr = FIELD_PREP(ZXDHQPSQ_OPCODE, ZXDH_OP_TYPE_NOP) |
	      FIELD_PREP(ZXDHQPSQ_SIGCOMPL, signaled) |
	      FIELD_PREP(ZXDHQPSQ_VALID, qp->swqe_polarity);

	/* make sure WQE is written before valid bit is set */
	udma_to_device_barrier();

	set_64bit_val(wqe, 0, hdr);

	return 0;
}

/**
 * zxdh_qp_post_wr - ring doorbell
 * @qp: hw qp ptr
 */
void zxdh_qp_post_wr(struct zxdh_qp *qp)
{
	/* valid bit is written before ringing doorbell */
	udma_to_device_barrier();

	db_wr32(qp->qp_id, qp->wqe_alloc_db);
	qp->initial_ring.head = qp->sq_ring.head;
}

/**
 * zxdh_qp_set_shadow_area - fill SW_RQ_Head
 * @qp: hw qp ptr
 */
void zxdh_qp_set_shadow_area(struct zxdh_qp *qp)
{
	__u8 polarity = 0;

	polarity = ((ZXDH_RING_CURRENT_HEAD(qp->rq_ring) == 0) ?
			    !qp->rwqe_polarity :
			    qp->rwqe_polarity);
	set_64bit_val(qp->shadow_area, 0,
		      FIELD_PREP(ZXDHQPDBSA_RQ_POLARITY, polarity) |
			      FIELD_PREP(ZXDHQPDBSA_RQ_SW_HEAD,
					 ZXDH_RING_CURRENT_HEAD(qp->rq_ring)));
}

/**
 * zxdh_qp_ring_push_db -  ring qp doorbell
 * @qp: hw qp ptr
 * @wqe_idx: wqe index
 */
static void zxdh_qp_ring_push_db(struct zxdh_qp *qp, __u32 wqe_idx)
{
	set_32bit_val(qp->push_db, 0,
		      FIELD_PREP(ZXDH_WQEALLOC_WQE_DESC_INDEX, wqe_idx >> 3) |
			      qp->qp_id);
	qp->initial_ring.head = qp->sq_ring.head;
	qp->push_mode = true;
	qp->push_dropped = false;
}

void zxdh_qp_push_wqe(struct zxdh_qp *qp, __le64 *wqe, __u16 quanta,
		      __u32 wqe_idx, bool post_sq)
{
	__le64 *push;

	if (ZXDH_RING_CURRENT_HEAD(qp->initial_ring) !=
		    ZXDH_RING_CURRENT_TAIL(qp->sq_ring) &&
	    !qp->push_mode) {
		if (post_sq)
			zxdh_qp_post_wr(qp);
	} else {
		push = (__le64 *)((uintptr_t)qp->push_wqe +
				  (wqe_idx & 0x7) * 0x20);
		memcpy(push, wqe, quanta * ZXDH_QP_WQE_MIN_SIZE);
		zxdh_qp_ring_push_db(qp, wqe_idx);
	}
}

/**
 * zxdh_qp_get_next_send_wqe - pad with NOP if needed, return where next WR should go
 * @qp: hw qp ptr
 * @wqe_idx: return wqe index
 * @quanta: size of WR in quanta
 * @total_size: size of WR in bytes
 * @info: info on WR
 */
__le64 *zxdh_qp_get_next_send_wqe(struct zxdh_qp *qp, __u32 *wqe_idx,
				  __u16 quanta, __u32 total_size,
				  struct zxdh_post_sq_info *info)
{
	__le64 *wqe;
	__u16 avail_quanta;
	__u16 i;

	avail_quanta = ZXDH_MAX_SQ_WQES_PER_PAGE -
		       (ZXDH_RING_CURRENT_HEAD(qp->sq_ring) %
			ZXDH_MAX_SQ_WQES_PER_PAGE);
	if (likely(quanta <= avail_quanta)) {
		/* WR fits in current chunk */
		if (unlikely(quanta > ZXDH_RING_FREE_QUANTA(qp->sq_ring)))
			return NULL;
	} else {
		/* Need to pad with NOP */
		if (quanta + avail_quanta > ZXDH_RING_FREE_QUANTA(qp->sq_ring))
			return NULL;

		for (i = 0; i < avail_quanta; i++) {
			zxdh_nop_1(qp);
			ZXDH_RING_MOVE_HEAD_NOCHECK(qp->sq_ring);
		}
	}

	*wqe_idx = ZXDH_RING_CURRENT_HEAD(qp->sq_ring);
	if (!*wqe_idx)
		qp->swqe_polarity = !qp->swqe_polarity;

	ZXDH_RING_MOVE_HEAD_BY_COUNT_NOCHECK(qp->sq_ring, quanta);

	wqe = qp->sq_base[*wqe_idx].elem;
	qp->sq_wrtrk_array[*wqe_idx].wrid = info->wr_id;
	qp->sq_wrtrk_array[*wqe_idx].wr_len = total_size;
	qp->sq_wrtrk_array[*wqe_idx].quanta = quanta;

	return wqe;
}

/**
 * zxdh_qp_get_next_recv_wqe - get next qp's rcv wqe
 * @qp: hw qp ptr
 * @wqe_idx: return wqe index
 */
__le64 *zxdh_qp_get_next_recv_wqe(struct zxdh_qp *qp, __u32 *wqe_idx)
{
	__le64 *wqe;
	enum zxdh_status_code ret_code;

	if (ZXDH_RING_FULL_ERR(qp->rq_ring))
		return NULL;

	ZXDH_ATOMIC_RING_MOVE_HEAD(qp->rq_ring, *wqe_idx, ret_code);
	if (ret_code)
		return NULL;

	if (!*wqe_idx)
		qp->rwqe_polarity = !qp->rwqe_polarity;
	/* rq_wqe_size_multiplier is no of 16 byte quanta in one rq wqe */
	wqe = qp->rq_base[*wqe_idx * qp->rq_wqe_size_multiplier].elem;

	return wqe;
}

static enum zxdh_status_code
zxdh_post_rdma_write(struct zxdh_qp *qp, struct zxdh_post_sq_info *info,
		     bool post_sq, __u32 total_size)
{
	enum zxdh_status_code ret_code;
	struct zxdh_rdma_write *op_info;
	__u32 i, byte_off = 0;
	__u32 frag_cnt, addl_frag_cnt;
	__le64 *wqe;
	__u32 wqe_idx;
	__u16 quanta;
	__u64 hdr;
	bool imm_data_flag;

	op_info = &info->op.rdma_write;
	imm_data_flag = info->imm_data_valid ? 1 : 0;

	if (imm_data_flag)
		frag_cnt =
			op_info->num_lo_sges ? (op_info->num_lo_sges + 1) : 2;
	else
		frag_cnt = op_info->num_lo_sges;
	addl_frag_cnt =
		op_info->num_lo_sges > 1 ? (op_info->num_lo_sges - 1) : 0;

	ret_code = zxdh_fragcnt_to_quanta_sq(frag_cnt, &quanta);
	if (ret_code)
		return ret_code;

	wqe = zxdh_qp_get_next_send_wqe(qp, &wqe_idx, quanta, total_size, info);
	if (!wqe)
		return ZXDH_ERR_QP_TOOMANY_WRS_POSTED;

	if (op_info->num_lo_sges) {
		set_64bit_val(
			wqe, 16,
			FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_VALID,
				   op_info->lo_sg_list->len ==
						   ZXDH_MAX_SQ_PAYLOAD_SIZE ?
					   1 :
					   0) |
				FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_LEN,
					   op_info->lo_sg_list->len) |
				FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_STAG,
					   op_info->lo_sg_list->stag));
		set_64bit_val(wqe, 8,
			      FIELD_PREP(ZXDHQPSQ_FRAG_TO,
					 op_info->lo_sg_list->tag_off));
	} else {
		/*if zero sge,post a special sge with zero length*/
		set_64bit_val(wqe, 16,
			      FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_VALID, 0) |
				      FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_LEN, 0) |
				      FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_STAG,
						 0x100));
		set_64bit_val(wqe, 8, FIELD_PREP(ZXDHQPSQ_FRAG_TO, 0));
	}

	if (imm_data_flag) {
		byte_off = ZXDH_SQ_WQE_BYTESIZE + ZXDH_QP_FRAG_BYTESIZE;
		if (op_info->num_lo_sges > 1) {
			qp->wqe_ops.iw_set_fragment(wqe, byte_off,
						    &op_info->lo_sg_list[1],
						    qp->swqe_polarity);
			byte_off += ZXDH_QP_FRAG_BYTESIZE;
		}
		set_64bit_val(
			wqe, ZXDH_SQ_WQE_BYTESIZE,
			FIELD_PREP(ZXDHQPSQ_IMMDATA_VALID, qp->swqe_polarity) |
				FIELD_PREP(ZXDHQPSQ_IMMDATA, info->imm_data));
		i = 2;
		if (i < op_info->num_lo_sges) {
			for (byte_off = ZXDH_SQ_WQE_BYTESIZE +
					2 * ZXDH_QP_FRAG_BYTESIZE;
			     i < op_info->num_lo_sges; i += 2) {
				if (i == addl_frag_cnt) {
					qp->wqe_ops.iw_set_fragment(
						wqe, byte_off,
						&op_info->lo_sg_list[i],
						qp->swqe_polarity);
					byte_off += ZXDH_QP_FRAG_BYTESIZE;
					break;
				}
				byte_off += ZXDH_QP_FRAG_BYTESIZE;
				qp->wqe_ops.iw_set_fragment(
					wqe, byte_off,
					&op_info->lo_sg_list[i + 1],
					qp->swqe_polarity);
				byte_off -= ZXDH_QP_FRAG_BYTESIZE;
				qp->wqe_ops.iw_set_fragment(
					wqe, byte_off, &op_info->lo_sg_list[i],
					qp->swqe_polarity);
				byte_off += 2 * ZXDH_QP_FRAG_BYTESIZE;
			}
		}
	} else {
		i = 1;
		for (byte_off = ZXDH_SQ_WQE_BYTESIZE; i < op_info->num_lo_sges;
		     i += 2) {
			if (i == addl_frag_cnt) {
				qp->wqe_ops.iw_set_fragment(
					wqe, byte_off, &op_info->lo_sg_list[i],
					qp->swqe_polarity);
				byte_off += ZXDH_QP_FRAG_BYTESIZE;
				break;
			}
			byte_off += ZXDH_QP_FRAG_BYTESIZE;
			qp->wqe_ops.iw_set_fragment(wqe, byte_off,
						    &op_info->lo_sg_list[i + 1],
						    qp->swqe_polarity);
			byte_off -= ZXDH_QP_FRAG_BYTESIZE;
			qp->wqe_ops.iw_set_fragment(wqe, byte_off,
						    &op_info->lo_sg_list[i],
						    qp->swqe_polarity);
			byte_off += 2 * ZXDH_QP_FRAG_BYTESIZE;
		}
	}
	/* if not an odd number set valid bit in next fragment */
	if (!(frag_cnt & 0x01) && frag_cnt) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, NULL,
					    qp->swqe_polarity);
	}

	hdr = FIELD_PREP(ZXDHQPSQ_VALID, qp->swqe_polarity) |
	      FIELD_PREP(ZXDHQPSQ_OPCODE, info->op_type) |
	      FIELD_PREP(ZXDHQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(ZXDHQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(ZXDHQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(ZXDHQPSQ_SOLICITED, info->solicited) |
	      FIELD_PREP(ZXDHQPSQ_IMMDATAFLAG, imm_data_flag) |
	      FIELD_PREP(ZXDHQPSQ_ADDFRAGCNT, addl_frag_cnt) |
	      FIELD_PREP(ZXDHQPSQ_REMSTAG, op_info->rem_addr.stag);
	set_64bit_val(wqe, 24,
		      FIELD_PREP(ZXDHQPSQ_FRAG_TO, op_info->rem_addr.tag_off));

	udma_to_device_barrier(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 0, hdr);
	if (post_sq)
		zxdh_qp_post_wr(qp);
	qp_tx_psn_add(&qp->next_psn, total_size, qp->mtu);
	return 0;
}

static void split_write_imm_wqe(struct zxdh_qp *qp,
				struct zxdh_post_sq_info *info,
				struct zxdh_post_sq_info *split_part1_info,
				struct zxdh_post_sq_info *split_part2_info)
{
	__u32 total_size = 0;
	struct zxdh_rdma_write *op_info;

	op_info = &info->op.rdma_write;
	total_size = op_info->rem_addr.len;
	split_part1_info->op.rdma_write.lo_sg_list =
		info->op.rdma_write.lo_sg_list;
	split_part2_info->op.rdma_write.lo_sg_list = NULL;

	split_part1_info->op_type = ZXDH_OP_TYPE_WRITE;
	split_part1_info->signaled = false;
	split_part1_info->local_fence = info->local_fence;
	split_part1_info->read_fence = info->read_fence;
	split_part1_info->solicited = info->solicited;
	split_part1_info->imm_data_valid = false;
	split_part1_info->wr_id = info->wr_id;
	split_part1_info->op.rdma_write.num_lo_sges =
		info->op.rdma_write.num_lo_sges;
	split_part1_info->op.rdma_write.rem_addr.stag = op_info->rem_addr.stag;
	split_part1_info->op.rdma_write.rem_addr.tag_off =
		op_info->rem_addr.tag_off;

	split_part2_info->op_type = info->op_type;
	split_part2_info->signaled = info->signaled;
	split_part2_info->local_fence = info->local_fence;
	split_part2_info->read_fence = info->read_fence;
	split_part2_info->solicited = info->solicited;
	split_part2_info->imm_data_valid = info->imm_data_valid;
	split_part2_info->wr_id = info->wr_id;
	split_part2_info->imm_data = info->imm_data;
	split_part2_info->op.rdma_write.num_lo_sges = 0;
	split_part2_info->op.rdma_write.rem_addr.stag = op_info->rem_addr.stag;
	split_part2_info->op.rdma_write.rem_addr.tag_off =
		op_info->rem_addr.tag_off + total_size;
}

/**
 * zxdh_rdma_write - rdma write operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
enum zxdh_status_code zxdh_rdma_write(struct zxdh_qp *qp,
				      struct zxdh_post_sq_info *info,
				      bool post_sq)
{
	struct zxdh_post_sq_info split_part1_info = { 0 };
	struct zxdh_post_sq_info split_part2_info = { 0 };
	struct zxdh_rdma_write *op_info;
	struct zxdh_uqp *iwuqp;
	struct zxdh_uvcontext *iwvctx;
	__u32 i;
	__u32 total_size = 0;
	enum zxdh_status_code ret_code;
	bool imm_data_flag = info->imm_data_valid ? 1 : 0;

	iwuqp = container_of(qp, struct zxdh_uqp, qp);
	iwvctx = container_of(iwuqp->vqp.qp.context, struct zxdh_uvcontext,
			      ibv_ctx.context);
	op_info = &info->op.rdma_write;
	if (op_info->num_lo_sges > qp->max_sq_frag_cnt)
		return ZXDH_ERR_INVALID_FRAG_COUNT;

	for (i = 0; i < op_info->num_lo_sges; i++) {
		total_size += op_info->lo_sg_list[i].len;
		if (0 != i && 0 == op_info->lo_sg_list[i].len)
			return ZXDH_ERR_INVALID_FRAG_LEN;
	}

	if (total_size > ZXDH_MAX_SQ_PAYLOAD_SIZE)
		return ZXDH_ERR_QP_INVALID_MSG_SIZE;

	op_info->rem_addr.len = total_size;
	if (iwvctx->zxdh_write_imm_split_switch == 0) {
		ret_code = zxdh_post_rdma_write(qp, info, post_sq, total_size);
		if (ret_code)
			return ret_code;
	} else {
		if (imm_data_flag && total_size > qp->mtu) {
			split_write_imm_wqe(qp, info, &split_part1_info,
					    &split_part2_info);

			ret_code = zxdh_post_rdma_write(qp, &split_part1_info,
							post_sq, total_size);
			if (ret_code)
				return ret_code;
			ret_code = zxdh_post_rdma_write(qp, &split_part2_info,
							post_sq, 0);
			if (ret_code)
				return ret_code;
		} else {
			ret_code = zxdh_post_rdma_write(qp, info, post_sq,
							total_size);
			if (ret_code)
				return ret_code;
		}
	}

	return 0;
}

static void split_two_part_info(struct zxdh_qp *qp,
				struct zxdh_post_sq_info *info, __u32 ori_psn,
				__u32 pre_cal_psn,
				struct zxdh_post_sq_info *split_part1_info,
				struct zxdh_post_sq_info *split_part2_info)
{
	__u32 total_size = 0;
	__u32 remain_size = 0;
	__u32 split_size = 0;
	struct zxdh_rdma_read *op_info;

	op_info = &info->op.rdma_read;
	total_size = op_info->rem_addr.len;
	split_part1_info->op.rdma_read.lo_sg_list = qp->split_sg_list;
	split_part2_info->op.rdma_read.lo_sg_list =
		qp->split_sg_list + op_info->num_lo_sges;

	memset(split_part1_info->op.rdma_read.lo_sg_list, 0,
	       2 * op_info->num_lo_sges * sizeof(struct zxdh_sge));
	if (pre_cal_psn < ori_psn && pre_cal_psn != 0)
		remain_size = (0xffffff - ori_psn + 1) * qp->mtu;
	else
		remain_size = (0x800000 - ori_psn) * qp->mtu;

	split_size = total_size - remain_size;

	split_part1_info->signaled = false;
	split_part1_info->local_fence = info->local_fence;
	split_part1_info->read_fence = info->read_fence;
	split_part1_info->solicited = false;
	split_part1_info->wr_id = info->wr_id;
	split_part1_info->op.rdma_read.rem_addr.stag = op_info->rem_addr.stag;
	split_part1_info->op.rdma_read.rem_addr.tag_off =
		op_info->rem_addr.tag_off;

	split_part2_info->signaled = info->signaled;
	split_part2_info->local_fence = info->local_fence;
	split_part2_info->read_fence = info->read_fence;
	split_part2_info->solicited = info->solicited;
	split_part2_info->wr_id = info->wr_id;
	split_part2_info->op.rdma_read.rem_addr.stag = op_info->rem_addr.stag;
	split_part2_info->op.rdma_read.rem_addr.tag_off =
		op_info->rem_addr.tag_off + remain_size;

	for (int i = 0; i < op_info->num_lo_sges; i++) {
		if (op_info->lo_sg_list[i].len +
			    split_part1_info->op.rdma_read.rem_addr.len <
		    remain_size) {
			split_part1_info->op.rdma_read.rem_addr.len +=
				op_info->lo_sg_list[i].len;
			split_part1_info->op.rdma_read.num_lo_sges += 1;
			memcpy(split_part1_info->op.rdma_read.lo_sg_list + i,
			       op_info->lo_sg_list + i,
			       sizeof(struct zxdh_sge));
			continue;
		} else if (op_info->lo_sg_list[i].len +
				   split_part1_info->op.rdma_read.rem_addr.len ==
			   remain_size) {
			split_part1_info->op.rdma_read.rem_addr.len +=
				op_info->lo_sg_list[i].len;
			split_part1_info->op.rdma_read.num_lo_sges += 1;
			memcpy(split_part1_info->op.rdma_read.lo_sg_list + i,
			       op_info->lo_sg_list + i,
			       sizeof(struct zxdh_sge));
			split_part2_info->op.rdma_read.rem_addr.len =
				split_size;
			split_part2_info->op.rdma_read.num_lo_sges =
				op_info->num_lo_sges -
				split_part1_info->op.rdma_read.num_lo_sges;
			memcpy(split_part2_info->op.rdma_read.lo_sg_list,
			       op_info->lo_sg_list + i + 1,
			       split_part2_info->op.rdma_read.num_lo_sges *
				       sizeof(struct zxdh_sge));
			break;
		}

		split_part1_info->op.rdma_read.lo_sg_list[i].len =
			remain_size -
			split_part1_info->op.rdma_read.rem_addr.len;
		split_part1_info->op.rdma_read.lo_sg_list[i].tag_off =
			op_info->lo_sg_list[i].tag_off;
		split_part1_info->op.rdma_read.lo_sg_list[i].stag =
			op_info->lo_sg_list[i].stag;
		split_part1_info->op.rdma_read.rem_addr.len = remain_size;
		split_part1_info->op.rdma_read.num_lo_sges += 1;
		split_part2_info->op.rdma_read.lo_sg_list[0].len =
			op_info->lo_sg_list[i].len -
			split_part1_info->op.rdma_read.lo_sg_list[i].len;
		split_part2_info->op.rdma_read.lo_sg_list[0].tag_off =
			op_info->lo_sg_list[i].tag_off +
			split_part1_info->op.rdma_read.lo_sg_list[i].len;
		split_part2_info->op.rdma_read.lo_sg_list[0].stag =
			op_info->lo_sg_list[i].stag;
		split_part2_info->op.rdma_read.rem_addr.len = split_size;
		split_part2_info->op.rdma_read.num_lo_sges =
			op_info->num_lo_sges -
			split_part1_info->op.rdma_read.num_lo_sges + 1;
		if (split_part2_info->op.rdma_read.num_lo_sges - 1 > 0) {
			memcpy(split_part2_info->op.rdma_read.lo_sg_list + 1,
			       op_info->lo_sg_list + i + 1,
			       (split_part2_info->op.rdma_read.num_lo_sges -
				1) * sizeof(struct zxdh_sge));
		}
		break;
	}
}

static enum zxdh_status_code zxdh_post_rdma_read(struct zxdh_qp *qp,
						 struct zxdh_post_sq_info *info,
						 bool post_sq, __u32 total_size)
{
	enum zxdh_status_code ret_code;
	struct zxdh_rdma_read *op_info;
	__u32 i, byte_off = 0;
	__u32 addl_frag_cnt;
	__le64 *wqe;
	__u32 wqe_idx;
	__u16 quanta;
	__u64 hdr;

	op_info = &info->op.rdma_read;
	ret_code = zxdh_fragcnt_to_quanta_sq(op_info->num_lo_sges, &quanta);
	if (ret_code)
		return ret_code;

	wqe = zxdh_qp_get_next_send_wqe(qp, &wqe_idx, quanta, total_size, info);
	if (!wqe)
		return ZXDH_ERR_QP_TOOMANY_WRS_POSTED;

	addl_frag_cnt =
		op_info->num_lo_sges > 1 ? (op_info->num_lo_sges - 1) : 0;

	if (op_info->num_lo_sges) {
		set_64bit_val(
			wqe, 16,
			FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_VALID,
				   op_info->lo_sg_list->len ==
						   ZXDH_MAX_SQ_PAYLOAD_SIZE ?
					   1 :
					   0) |
				FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_LEN,
					   op_info->lo_sg_list->len) |
				FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_STAG,
					   op_info->lo_sg_list->stag));
		set_64bit_val(wqe, 8,
			      FIELD_PREP(ZXDHQPSQ_FRAG_TO,
					 op_info->lo_sg_list->tag_off));
	} else {
		/*if zero sge,post a special sge with zero length*/
		set_64bit_val(wqe, 16,
			      FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_VALID, 0) |
				      FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_LEN, 0) |
				      FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_STAG,
						 0x100));
		set_64bit_val(wqe, 8, FIELD_PREP(ZXDHQPSQ_FRAG_TO, 0));
	}

	i = 1;
	for (byte_off = ZXDH_SQ_WQE_BYTESIZE; i < op_info->num_lo_sges;
	     i += 2) {
		if (i == addl_frag_cnt) {
			qp->wqe_ops.iw_set_fragment(wqe, byte_off,
						    &op_info->lo_sg_list[i],
						    qp->swqe_polarity);
			byte_off += ZXDH_QP_FRAG_BYTESIZE;
			break;
		}
		byte_off += ZXDH_QP_FRAG_BYTESIZE;
		qp->wqe_ops.iw_set_fragment(wqe, byte_off,
					    &op_info->lo_sg_list[i + 1],
					    qp->swqe_polarity);
		byte_off -= ZXDH_QP_FRAG_BYTESIZE;
		qp->wqe_ops.iw_set_fragment(wqe, byte_off,
					    &op_info->lo_sg_list[i],
					    qp->swqe_polarity);
		byte_off += 2 * ZXDH_QP_FRAG_BYTESIZE;
	}

	/* if not an odd number set valid bit in next fragment */
	if (!(op_info->num_lo_sges & 0x01) && op_info->num_lo_sges) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, NULL,
					    qp->swqe_polarity);
	}

	hdr = FIELD_PREP(ZXDHQPSQ_VALID, qp->swqe_polarity) |
	      FIELD_PREP(ZXDHQPSQ_OPCODE, ZXDH_OP_TYPE_READ) |
	      FIELD_PREP(ZXDHQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(ZXDHQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(ZXDHQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(ZXDHQPSQ_SOLICITED, info->solicited) |
	      FIELD_PREP(ZXDHQPSQ_ADDFRAGCNT, addl_frag_cnt) |
	      FIELD_PREP(ZXDHQPSQ_REMSTAG, op_info->rem_addr.stag);
	set_64bit_val(wqe, 24,
		      FIELD_PREP(ZXDHQPSQ_FRAG_TO, op_info->rem_addr.tag_off));

	udma_to_device_barrier(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 0, hdr);
	if (post_sq)
		zxdh_qp_post_wr(qp);
	return 0;
}

/**
 * zxdh_rdma_read - rdma read command
 * @qp: hw qp ptr
 * @info: post sq information
 * @inv_stag: flag for inv_stag
 * @post_sq: flag to post sq
 */
enum zxdh_status_code zxdh_rdma_read(struct zxdh_qp *qp,
				     struct zxdh_post_sq_info *info,
				     bool inv_stag, bool post_sq)
{
	struct zxdh_post_sq_info split_part1_info = { 0 };
	struct zxdh_post_sq_info split_part2_info = { 0 };
	struct zxdh_rdma_read *op_info;
	enum zxdh_status_code ret_code;
	struct zxdh_uqp *iwuqp;
	struct zxdh_uvcontext *iwvctx;

	__u32 i, total_size = 0, pre_cal_psn = 0;

	iwuqp = container_of(qp, struct zxdh_uqp, qp);
	iwvctx = container_of(iwuqp->vqp.qp.context, struct zxdh_uvcontext,
			      ibv_ctx.context);
	op_info = &info->op.rdma_read;
	if (qp->max_sq_frag_cnt < op_info->num_lo_sges)
		return ZXDH_ERR_INVALID_FRAG_COUNT;

	for (i = 0; i < op_info->num_lo_sges; i++) {
		total_size += op_info->lo_sg_list[i].len;
		if (0 != i && 0 == op_info->lo_sg_list[i].len)
			return ZXDH_ERR_INVALID_FRAG_LEN;
	}

	if (total_size > ZXDH_MAX_SQ_PAYLOAD_SIZE)
		return ZXDH_ERR_QP_INVALID_MSG_SIZE;
	op_info->rem_addr.len = total_size;
	pre_cal_psn = qp->next_psn;
	qp_tx_psn_add(&pre_cal_psn, total_size, qp->mtu);
	if (read_wqe_need_split(pre_cal_psn, qp->next_psn,
				iwvctx->dev_attrs.chip_rev)) {
		split_two_part_info(qp, info, qp->next_psn, pre_cal_psn,
				    &split_part1_info, &split_part2_info);
		ret_code = zxdh_post_rdma_read(qp, &split_part1_info, post_sq,
					       total_size);
		if (ret_code)
			return ret_code;

		qp_tx_psn_add(&qp->next_psn,
			      split_part1_info.op.rdma_read.rem_addr.len,
			      qp->mtu);
		ret_code = zxdh_post_rdma_read(qp, &split_part2_info, post_sq,
					       total_size);
		if (ret_code)
			return ret_code;

		qp_tx_psn_add(&qp->next_psn,
			      split_part2_info.op.rdma_read.rem_addr.len,
			      qp->mtu);
	} else {
		ret_code = zxdh_post_rdma_read(qp, info, post_sq, total_size);
		if (ret_code)
			return ret_code;

		qp_tx_psn_add(&qp->next_psn, total_size, qp->mtu);
	}
	return 0;
}

/**
 * zxdh_rc_send - rdma send command
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
enum zxdh_status_code zxdh_rc_send(struct zxdh_qp *qp,
				   struct zxdh_post_sq_info *info, bool post_sq)
{
	__le64 *wqe;
	struct zxdh_post_send *op_info;
	__u64 hdr;
	__u32 i, wqe_idx, total_size = 0, byte_off;
	enum zxdh_status_code ret_code;
	__u32 frag_cnt, addl_frag_cnt;
	__u16 quanta;
	bool imm_data_flag = info->imm_data_valid ? 1 : 0;

	op_info = &info->op.send;
	if (qp->max_sq_frag_cnt < op_info->num_sges)
		return ZXDH_ERR_INVALID_FRAG_COUNT;

	for (i = 0; i < op_info->num_sges; i++) {
		total_size += op_info->sg_list[i].len;
		if (0 != i && 0 == op_info->sg_list[i].len)
			return ZXDH_ERR_INVALID_FRAG_LEN;
	}

	if (total_size > ZXDH_MAX_SQ_PAYLOAD_SIZE)
		return ZXDH_ERR_QP_INVALID_MSG_SIZE;

	if (imm_data_flag)
		frag_cnt = op_info->num_sges ? (op_info->num_sges + 1) : 2;
	else
		frag_cnt = op_info->num_sges;
	ret_code = zxdh_fragcnt_to_quanta_sq(frag_cnt, &quanta);
	if (ret_code)
		return ret_code;

	wqe = zxdh_qp_get_next_send_wqe(qp, &wqe_idx, quanta, total_size, info);
	if (!wqe)
		return ZXDH_ERR_QP_TOOMANY_WRS_POSTED;

	addl_frag_cnt = op_info->num_sges > 1 ? (op_info->num_sges - 1) : 0;
	if (op_info->num_sges) {
		set_64bit_val(
			wqe, 16,
			FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_VALID,
				   op_info->sg_list->len ==
						   ZXDH_MAX_SQ_PAYLOAD_SIZE ?
					   1 :
					   0) |
				FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_LEN,
					   op_info->sg_list->len) |
				FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_STAG,
					   op_info->sg_list->stag));
		set_64bit_val(wqe, 8,
			      FIELD_PREP(ZXDHQPSQ_FRAG_TO,
					 op_info->sg_list->tag_off));
	} else {
		/*if zero sge,post a special sge with zero length*/
		set_64bit_val(wqe, 16,
			      FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_VALID, 0) |
				      FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_LEN, 0) |
				      FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_STAG,
						 0x100));
		set_64bit_val(wqe, 8, FIELD_PREP(ZXDHQPSQ_FRAG_TO, 0));
	}

	if (imm_data_flag) {
		byte_off = ZXDH_SQ_WQE_BYTESIZE + ZXDH_QP_FRAG_BYTESIZE;
		if (op_info->num_sges > 1) {
			qp->wqe_ops.iw_set_fragment(wqe, byte_off,
						    &op_info->sg_list[1],
						    qp->swqe_polarity);
			byte_off += ZXDH_QP_FRAG_BYTESIZE;
		}
		set_64bit_val(
			wqe, ZXDH_SQ_WQE_BYTESIZE,
			FIELD_PREP(ZXDHQPSQ_IMMDATA_VALID, qp->swqe_polarity) |
				FIELD_PREP(ZXDHQPSQ_IMMDATA, info->imm_data));
		i = 2;
		if (i < op_info->num_sges) {
			for (byte_off = ZXDH_SQ_WQE_BYTESIZE +
					2 * ZXDH_QP_FRAG_BYTESIZE;
			     i < op_info->num_sges; i += 2) {
				if (i == addl_frag_cnt) {
					qp->wqe_ops.iw_set_fragment(
						wqe, byte_off,
						&op_info->sg_list[i],
						qp->swqe_polarity);
					byte_off += ZXDH_QP_FRAG_BYTESIZE;
					break;
				}
				byte_off += ZXDH_QP_FRAG_BYTESIZE;
				qp->wqe_ops.iw_set_fragment(
					wqe, byte_off, &op_info->sg_list[i + 1],
					qp->swqe_polarity);
				byte_off -= ZXDH_QP_FRAG_BYTESIZE;
				qp->wqe_ops.iw_set_fragment(
					wqe, byte_off, &op_info->sg_list[i],
					qp->swqe_polarity);
				byte_off += 2 * ZXDH_QP_FRAG_BYTESIZE;
			}
		}
	} else {
		i = 1;
		for (byte_off = ZXDH_SQ_WQE_BYTESIZE; i < op_info->num_sges;
		     i += 2) {
			if (i == addl_frag_cnt) {
				qp->wqe_ops.iw_set_fragment(
					wqe, byte_off, &op_info->sg_list[i],
					qp->swqe_polarity);
				byte_off += ZXDH_QP_FRAG_BYTESIZE;
				break;
			}
			byte_off += ZXDH_QP_FRAG_BYTESIZE;
			qp->wqe_ops.iw_set_fragment(wqe, byte_off,
						    &op_info->sg_list[i + 1],
						    qp->swqe_polarity);
			byte_off -= ZXDH_QP_FRAG_BYTESIZE;
			qp->wqe_ops.iw_set_fragment(wqe, byte_off,
						    &op_info->sg_list[i],
						    qp->swqe_polarity);
			byte_off += 2 * ZXDH_QP_FRAG_BYTESIZE;
		}
	}

	/* if not an odd number set valid bit in next fragment */
	if (!(frag_cnt & 0x01) && frag_cnt) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, NULL,
					    qp->swqe_polarity);
	}

	hdr = FIELD_PREP(ZXDHQPSQ_VALID, qp->swqe_polarity) |
	      FIELD_PREP(ZXDHQPSQ_OPCODE, info->op_type) |
	      FIELD_PREP(ZXDHQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(ZXDHQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(ZXDHQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(ZXDHQPSQ_SOLICITED, info->solicited) |
	      FIELD_PREP(ZXDHQPSQ_IMMDATAFLAG, imm_data_flag) |
	      FIELD_PREP(ZXDHQPSQ_ADDFRAGCNT, addl_frag_cnt) |
	      FIELD_PREP(ZXDHQPSQ_REMSTAG, info->stag_to_inv);
	set_64bit_val(wqe, 24,
		      FIELD_PREP(ZXDHQPSQ_INLINEDATAFLAG, 0) |
			      FIELD_PREP(ZXDHQPSQ_INLINEDATALEN, 0));

	udma_to_device_barrier(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 0, hdr);
	if (post_sq)
		zxdh_qp_post_wr(qp);
	qp_tx_psn_add(&qp->next_psn, total_size, qp->mtu);

	return 0;
}

/**
 * zxdh_ud_send - rdma send command
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
enum zxdh_status_code zxdh_ud_send(struct zxdh_qp *qp,
				   struct zxdh_post_sq_info *info, bool post_sq)
{
	__le64 *wqe_base;
	__le64 *wqe_ex = NULL;
	struct zxdh_post_send *op_info;
	__u64 hdr;
	__u32 i, wqe_idx, total_size = 0, byte_off;
	enum zxdh_status_code ret_code;
	__u32 frag_cnt, addl_frag_cnt;
	__u16 quanta;
	bool imm_data_flag = info->imm_data_valid ? 1 : 0;

	op_info = &info->op.send;
	if (qp->max_sq_frag_cnt < op_info->num_sges)
		return ZXDH_ERR_INVALID_FRAG_COUNT;

	for (i = 0; i < op_info->num_sges; i++) {
		total_size += op_info->sg_list[i].len;
		if (0 != i && 0 == op_info->sg_list[i].len)
			return ZXDH_ERR_INVALID_FRAG_LEN;
	}

	if (total_size > ZXDH_MAX_SQ_PAYLOAD_SIZE)
		return ZXDH_ERR_QP_INVALID_MSG_SIZE;

	if (imm_data_flag)
		frag_cnt = op_info->num_sges ? (op_info->num_sges + 1) : 2;
	else
		frag_cnt = op_info->num_sges;
	ret_code = zxdh_fragcnt_to_quanta_sq(frag_cnt, &quanta);
	if (ret_code)
		return ret_code;

	if (quanta > ZXDH_RING_FREE_QUANTA(qp->sq_ring))
		return ZXDH_ERR_QP_TOOMANY_WRS_POSTED;

	wqe_idx = ZXDH_RING_CURRENT_HEAD(qp->sq_ring);
	if (!wqe_idx)
		qp->swqe_polarity = !qp->swqe_polarity;

	ZXDH_RING_MOVE_HEAD_BY_COUNT_NOCHECK(qp->sq_ring, quanta);

	wqe_base = qp->sq_base[wqe_idx].elem;
	qp->sq_wrtrk_array[wqe_idx].wrid = info->wr_id;
	qp->sq_wrtrk_array[wqe_idx].wr_len = total_size;
	qp->sq_wrtrk_array[wqe_idx].quanta = quanta;

	addl_frag_cnt = op_info->num_sges > 1 ? (op_info->num_sges - 1) : 0;
	hdr = FIELD_PREP(ZXDHQPSQ_VALID, qp->swqe_polarity) |
	      FIELD_PREP(ZXDHQPSQ_OPCODE, info->op_type) |
	      FIELD_PREP(ZXDHQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(ZXDHQPSQ_SOLICITED, info->solicited) |
	      FIELD_PREP(ZXDHQPSQ_IMMDATAFLAG, imm_data_flag) |
	      FIELD_PREP(ZXDHQPSQ_UD_INLINEDATAFLAG, 0) |
	      FIELD_PREP(ZXDHQPSQ_UD_INLINEDATALEN, 0) |
	      FIELD_PREP(ZXDHQPSQ_UD_ADDFRAGCNT, addl_frag_cnt) |
	      FIELD_PREP(ZXDHQPSQ_AHID, op_info->ah_id);

	if (op_info->num_sges) {
		set_64bit_val(
			wqe_base, 16,
			FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_VALID,
				   op_info->sg_list->len ==
						   ZXDH_MAX_SQ_PAYLOAD_SIZE ?
					   1 :
					   0) |
				FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_LEN,
					   op_info->sg_list->len) |
				FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_STAG,
					   op_info->sg_list->stag));
		set_64bit_val(wqe_base, 8,
			      FIELD_PREP(ZXDHQPSQ_FRAG_TO,
					 op_info->sg_list->tag_off));
	} else {
		/*if zero sge,post a special sge with zero length*/
		set_64bit_val(wqe_base, 16,
			      FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_VALID, 0) |
				      FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_LEN, 0) |
				      FIELD_PREP(ZXDHQPSQ_FIRST_FRAG_STAG,
						 0x100));
		set_64bit_val(wqe_base, 8, FIELD_PREP(ZXDHQPSQ_FRAG_TO, 0));
	}

	if (imm_data_flag) {
		wqe_idx = (wqe_idx + 1) % qp->sq_ring.size;
		if (!wqe_idx)
			qp->swqe_polarity = !qp->swqe_polarity;
		wqe_ex = qp->sq_base[wqe_idx].elem;
		if (op_info->num_sges > 1) {
			qp->wqe_ops.iw_set_fragment(wqe_ex,
						    ZXDH_QP_FRAG_BYTESIZE,
						    &op_info->sg_list[1],
						    qp->swqe_polarity);
		}
		set_64bit_val(
			wqe_ex, 0,
			FIELD_PREP(ZXDHQPSQ_IMMDATA_VALID, qp->swqe_polarity) |
				FIELD_PREP(ZXDHQPSQ_IMMDATA, info->imm_data));
		i = 2;
		for (byte_off = ZXDH_QP_FRAG_BYTESIZE; i < op_info->num_sges;
		     i += 2) {
			if (!(i & 0x1)) {
				wqe_idx = (wqe_idx + 1) % qp->sq_ring.size;
				if (!wqe_idx)
					qp->swqe_polarity = !qp->swqe_polarity;
				wqe_ex = qp->sq_base[wqe_idx].elem;
			}
			if (i == addl_frag_cnt) {
				qp->wqe_ops.iw_set_fragment(
					wqe_ex, 0, &op_info->sg_list[i],
					qp->swqe_polarity);
				break;
			}
			qp->wqe_ops.iw_set_fragment(
				wqe_ex, byte_off % ZXDH_SQ_WQE_BYTESIZE,
				&op_info->sg_list[i + 1], qp->swqe_polarity);
			byte_off -= ZXDH_QP_FRAG_BYTESIZE;
			qp->wqe_ops.iw_set_fragment(
				wqe_ex, byte_off % ZXDH_SQ_WQE_BYTESIZE,
				&op_info->sg_list[i], qp->swqe_polarity);
			byte_off += ZXDH_QP_FRAG_BYTESIZE;
		}
	} else {
		i = 1;
		for (byte_off = 0; i < op_info->num_sges; i += 2) {
			if (i & 0x1) {
				wqe_idx = (wqe_idx + 1) % qp->sq_ring.size;
				if (!wqe_idx)
					qp->swqe_polarity = !qp->swqe_polarity;
				wqe_ex = qp->sq_base[wqe_idx].elem;
			}
			if (i == addl_frag_cnt) {
				qp->wqe_ops.iw_set_fragment(
					wqe_ex, 0, &op_info->sg_list[i],
					qp->swqe_polarity);
				break;
			}
			byte_off += ZXDH_QP_FRAG_BYTESIZE;
			qp->wqe_ops.iw_set_fragment(
				wqe_ex, byte_off % ZXDH_SQ_WQE_BYTESIZE,
				&op_info->sg_list[i + 1], qp->swqe_polarity);
			byte_off -= ZXDH_QP_FRAG_BYTESIZE;
			qp->wqe_ops.iw_set_fragment(
				wqe_ex, byte_off % ZXDH_SQ_WQE_BYTESIZE,
				&op_info->sg_list[i], qp->swqe_polarity);
		}
	}

	/* if not an odd number set valid bit in next fragment */
	if (!(frag_cnt & 0x01) && frag_cnt && wqe_ex) {
		qp->wqe_ops.iw_set_fragment(wqe_ex, ZXDH_QP_FRAG_BYTESIZE, NULL,
					    qp->swqe_polarity);
	}

	set_64bit_val(wqe_base, 24,
		      FIELD_PREP(ZXDHQPSQ_DESTQPN, op_info->dest_qp) |
			      FIELD_PREP(ZXDHQPSQ_DESTQKEY, op_info->qkey));

	udma_to_device_barrier(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe_base, 0, hdr);
	if (post_sq)
		zxdh_qp_post_wr(qp);

	return 0;
}

/**
 * zxdh_set_mw_bind_wqe - set mw bind in wqe
 * @wqe: wqe for setting mw bind
 * @op_info: info for setting wqe values
 */
static void zxdh_set_mw_bind_wqe(__le64 *wqe, struct zxdh_bind_window *op_info)
{
	__u32 value = 0;
	__u8 leaf_pbl_size = op_info->leaf_pbl_size;

	set_64bit_val(wqe, 8, (uintptr_t)op_info->va);

	if (leaf_pbl_size == 0) {
		value = (__u32)(op_info->mw_pa_pble_index >> 12);
		value = (value & 0x03FFFFFFFC0000) >> 18;
		set_64bit_val(
			wqe, 16,
			FIELD_PREP(ZXDHQPSQ_PARENTMRSTAG, op_info->mr_stag) |
				FIELD_PREP(ZXDHQPSQ_MW_PA_PBLE_TWO, value));
	} else if (leaf_pbl_size == 1) {
		value = (__u32)((op_info->mw_pa_pble_index & 0x0FFC0000) >> 18);
		set_64bit_val(
			wqe, 16,
			FIELD_PREP(ZXDHQPSQ_PARENTMRSTAG, op_info->mr_stag) |
				FIELD_PREP(ZXDHQPSQ_MW_PA_PBLE_TWO, value));
	} else {
		value = (__u32)((op_info->mw_pa_pble_index & 0x0FFC0000) >> 18);
		set_64bit_val(
			wqe, 16,
			FIELD_PREP(ZXDHQPSQ_PARENTMRSTAG, op_info->mr_stag) |
				FIELD_PREP(ZXDHQPSQ_MW_LEVLE2_FIRST_PBLE_INDEX,
					   value) |
				FIELD_PREP(ZXDHQPSQ_MW_LEVLE2_ROOT_PBLE_INDEX,
					   op_info->root_leaf_offset));
	}

	if (leaf_pbl_size == 0) {
		value = (__u32)(op_info->mw_pa_pble_index >> 12);
		value = value & 0x3FFFF;
	} else {
		value = (__u32)(op_info->mw_pa_pble_index & 0x3FFFF);
	}

	set_64bit_val(wqe, 24,
		      op_info->bind_len |
			      FIELD_PREP(ZXDHQPSQ_MW_PA_PBLE_ONE, value));
}

/**
 * zxdh_copy_inline_data - Copy inline data to wqe
 * @dest: pointer to wqe
 * @src: pointer to inline data
 * @len: length of inline data to copy
 * @polarity: polarity of wqe valid bit
 */
static void zxdh_copy_inline_data(__u8 *dest, __u8 *src, __u32 len,
				  __u8 polarity, bool imm_data_flag)
{
	__u8 inline_valid = polarity << ZXDH_INLINE_VALID_S;
	__u32 copy_size;
	__u8 *inline_valid_addr;

	dest += ZXDH_WQE_SIZE_32; /* point to additional 32 byte quanta */
	if (len) {
		inline_valid_addr = dest + WQE_OFFSET_7BYTES;
		if (imm_data_flag) {
			copy_size = len < INLINE_DATASIZE_24BYTES ?
					    len :
					    INLINE_DATASIZE_24BYTES;
			dest += WQE_OFFSET_8BYTES;
			memcpy(dest, src, copy_size);
			len -= copy_size;
			dest += WQE_OFFSET_24BYTES;
			src += copy_size;
		} else {
			if (len <= INLINE_DATASIZE_7BYTES) {
				copy_size = len;
				memcpy(dest, src, copy_size);
				*inline_valid_addr = inline_valid;
				return;
			}
			memcpy(dest, src, INLINE_DATASIZE_7BYTES);
			len -= INLINE_DATASIZE_7BYTES;
			dest += WQE_OFFSET_8BYTES;
			src += INLINE_DATA_OFFSET_7BYTES;
			copy_size = len < INLINE_DATASIZE_24BYTES ?
					    len :
					    INLINE_DATASIZE_24BYTES;
			memcpy(dest, src, copy_size);
			len -= copy_size;
			dest += WQE_OFFSET_24BYTES;
			src += copy_size;
		}
		*inline_valid_addr = inline_valid;
	}

	while (len) {
		inline_valid_addr = dest + WQE_OFFSET_7BYTES;
		if (len <= INLINE_DATASIZE_7BYTES) {
			copy_size = len;
			memcpy(dest, src, copy_size);
			*inline_valid_addr = inline_valid;
			return;
		}
		memcpy(dest, src, INLINE_DATASIZE_7BYTES);
		len -= INLINE_DATASIZE_7BYTES;
		dest += WQE_OFFSET_8BYTES;
		src += INLINE_DATA_OFFSET_7BYTES;
		copy_size = len < INLINE_DATASIZE_24BYTES ?
				    len :
				    INLINE_DATASIZE_24BYTES;
		memcpy(dest, src, copy_size);
		len -= copy_size;
		dest += WQE_OFFSET_24BYTES;
		src += copy_size;

		*inline_valid_addr = inline_valid;
	}
}

/**
 * zxdh_inline_data_size_to_quanta - based on inline data, quanta
 * @data_size: data size for inline
 * @imm_data_flag: flag for immediate data
 *
 * Gets the quanta based on inline and immediate data.
 */
static __u16 zxdh_inline_data_size_to_quanta(__u32 data_size,
					     bool imm_data_flag)
{
	if (imm_data_flag)
		data_size += INLINE_DATASIZE_7BYTES;

	return data_size % 31 ? data_size / 31 + 2 : data_size / 31 + 1;
}

/**
 * zxdh_inline_rdma_write - inline rdma write operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
enum zxdh_status_code zxdh_inline_rdma_write(struct zxdh_qp *qp,
					     struct zxdh_post_sq_info *info,
					     bool post_sq)
{
	__le64 *wqe;
	__u8 imm_valid;
	struct zxdh_inline_rdma_write *op_info;
	__u64 hdr = 0;
	__u32 wqe_idx;
	bool read_fence = false;
	__u16 quanta;
	bool imm_data_flag = info->imm_data_valid ? 1 : 0;

	op_info = &info->op.inline_rdma_write;

	if (op_info->len > qp->max_inline_data)
		return ZXDH_ERR_INVALID_INLINE_DATA_SIZE;
	if (imm_data_flag && op_info->len > ZXDH_MAX_SQ_INLINE_DATELEN_WITH_IMM)
		return ZXDH_ERR_INVALID_INLINE_DATA_SIZE;

	quanta = qp->wqe_ops.iw_inline_data_size_to_quanta(op_info->len,
							   imm_data_flag);
	wqe = zxdh_qp_get_next_send_wqe(qp, &wqe_idx, quanta, op_info->len,
					info);
	if (!wqe)
		return ZXDH_ERR_QP_TOOMANY_WRS_POSTED;

	read_fence |= info->read_fence;
	hdr = FIELD_PREP(ZXDHQPSQ_VALID, qp->swqe_polarity) |
	      FIELD_PREP(ZXDHQPSQ_OPCODE, info->op_type) |
	      FIELD_PREP(ZXDHQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(ZXDHQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(ZXDHQPSQ_READFENCE, read_fence) |
	      FIELD_PREP(ZXDHQPSQ_SOLICITED, info->solicited) |
	      FIELD_PREP(ZXDHQPSQ_IMMDATAFLAG, imm_data_flag) |
	      FIELD_PREP(ZXDHQPSQ_WRITE_INLINEDATAFLAG, 1) |
	      FIELD_PREP(ZXDHQPSQ_WRITE_INLINEDATALEN, op_info->len) |
	      FIELD_PREP(ZXDHQPSQ_ADDFRAGCNT, (__u16)(quanta - 1)) |
	      FIELD_PREP(ZXDHQPSQ_REMSTAG, op_info->rem_addr.stag);
	set_64bit_val(wqe, 24,
		      FIELD_PREP(ZXDHQPSQ_FRAG_TO, op_info->rem_addr.tag_off));

	if (imm_data_flag) {
		/* if inline exist, not update imm valid */
		imm_valid = (op_info->len == 0) ? qp->swqe_polarity :
						  (!qp->swqe_polarity);

		set_64bit_val(wqe, 32,
			      FIELD_PREP(ZXDHQPSQ_IMMDATA_VALID, imm_valid) |
				      FIELD_PREP(ZXDHQPSQ_IMMDATA,
						 info->imm_data));
	}
	qp->wqe_ops.iw_copy_inline_data((__u8 *)wqe, op_info->data,
					op_info->len, qp->swqe_polarity,
					imm_data_flag);

	udma_to_device_barrier(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_qp_post_wr(qp);
	qp_tx_psn_add(&qp->next_psn, op_info->len, qp->mtu);
	return 0;
}

/**
 * zxdh_rc_inline_send - inline send operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
enum zxdh_status_code zxdh_rc_inline_send(struct zxdh_qp *qp,
					  struct zxdh_post_sq_info *info,
					  bool post_sq)
{
	__le64 *wqe;
	__u8 imm_valid;
	struct zxdh_inline_rdma_send *op_info;
	__u64 hdr;
	__u32 wqe_idx;
	__u16 quanta;
	bool imm_data_flag = info->imm_data_valid ? 1 : 0;

	op_info = &info->op.inline_rdma_send;

	if (op_info->len > qp->max_inline_data)
		return ZXDH_ERR_INVALID_INLINE_DATA_SIZE;
	if (imm_data_flag && op_info->len > ZXDH_MAX_SQ_INLINE_DATELEN_WITH_IMM)
		return ZXDH_ERR_INVALID_INLINE_DATA_SIZE;

	quanta = qp->wqe_ops.iw_inline_data_size_to_quanta(op_info->len,
							   imm_data_flag);
	wqe = zxdh_qp_get_next_send_wqe(qp, &wqe_idx, quanta, op_info->len,
					info);
	if (!wqe)
		return ZXDH_ERR_QP_TOOMANY_WRS_POSTED;

	hdr = FIELD_PREP(ZXDHQPSQ_VALID, qp->swqe_polarity) |
	      FIELD_PREP(ZXDHQPSQ_OPCODE, info->op_type) |
	      FIELD_PREP(ZXDHQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(ZXDHQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(ZXDHQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(ZXDHQPSQ_SOLICITED, info->solicited) |
	      FIELD_PREP(ZXDHQPSQ_ADDFRAGCNT, (__u16)(quanta - 1)) |
	      FIELD_PREP(ZXDHQPSQ_IMMDATAFLAG, imm_data_flag) |
	      FIELD_PREP(ZXDHQPSQ_REMSTAG, info->stag_to_inv);
	set_64bit_val(wqe, 24,
		      FIELD_PREP(ZXDHQPSQ_INLINEDATAFLAG, 1) |
			      FIELD_PREP(ZXDHQPSQ_INLINEDATALEN, op_info->len));

	if (imm_data_flag) {
		/* if inline exist, not update imm valid */
		imm_valid = (op_info->len == 0) ? qp->swqe_polarity :
						  (!qp->swqe_polarity);
		set_64bit_val(wqe, 32,
			      FIELD_PREP(ZXDHQPSQ_IMMDATA_VALID, imm_valid) |
				      FIELD_PREP(ZXDHQPSQ_IMMDATA,
						 info->imm_data));
	}

	qp->wqe_ops.iw_copy_inline_data((__u8 *)wqe, op_info->data,
					op_info->len, qp->swqe_polarity,
					imm_data_flag);

	udma_to_device_barrier(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_qp_post_wr(qp);

	qp_tx_psn_add(&qp->next_psn, op_info->len, qp->mtu);
	return 0;
}

/**
 * zxdh_ud_inline_send - inline send operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
enum zxdh_status_code zxdh_ud_inline_send(struct zxdh_qp *qp,
					  struct zxdh_post_sq_info *info,
					  bool post_sq)
{
	__le64 *wqe_base;
	__le64 *wqe_ex;
	struct zxdh_inline_rdma_send *op_info;
	__u64 hdr;
	__u32 wqe_idx;
	__u16 quanta;
	bool imm_data_flag = info->imm_data_valid ? 1 : 0;
	__u8 *inline_dest;
	__u8 *inline_src;
	__u32 inline_len;
	__u32 copy_size;
	__u8 *inline_valid_addr;

	op_info = &info->op.inline_rdma_send;
	inline_len = op_info->len;

	if (op_info->len > qp->max_inline_data)
		return ZXDH_ERR_INVALID_INLINE_DATA_SIZE;
	if (imm_data_flag && op_info->len > ZXDH_MAX_SQ_INLINE_DATELEN_WITH_IMM)
		return ZXDH_ERR_INVALID_INLINE_DATA_SIZE;

	quanta = qp->wqe_ops.iw_inline_data_size_to_quanta(op_info->len,
							   imm_data_flag);
	if (quanta > ZXDH_RING_FREE_QUANTA(qp->sq_ring))
		return ZXDH_ERR_QP_TOOMANY_WRS_POSTED;

	wqe_idx = ZXDH_RING_CURRENT_HEAD(qp->sq_ring);
	if (!wqe_idx)
		qp->swqe_polarity = !qp->swqe_polarity;

	ZXDH_RING_MOVE_HEAD_BY_COUNT_NOCHECK(qp->sq_ring, quanta);

	wqe_base = qp->sq_base[wqe_idx].elem;
	qp->sq_wrtrk_array[wqe_idx].wrid = info->wr_id;
	qp->sq_wrtrk_array[wqe_idx].wr_len = op_info->len;
	qp->sq_wrtrk_array[wqe_idx].quanta = quanta;

	hdr = FIELD_PREP(ZXDHQPSQ_VALID, qp->swqe_polarity) |
	      FIELD_PREP(ZXDHQPSQ_OPCODE, info->op_type) |
	      FIELD_PREP(ZXDHQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(ZXDHQPSQ_SOLICITED, info->solicited) |
	      FIELD_PREP(ZXDHQPSQ_IMMDATAFLAG, imm_data_flag) |
	      FIELD_PREP(ZXDHQPSQ_UD_INLINEDATAFLAG, 1) |
	      FIELD_PREP(ZXDHQPSQ_UD_INLINEDATALEN, op_info->len) |
	      FIELD_PREP(ZXDHQPSQ_UD_ADDFRAGCNT, (__u16)(quanta - 1)) |
	      FIELD_PREP(ZXDHQPSQ_AHID, op_info->ah_id);
	set_64bit_val(wqe_base, 24,
		      FIELD_PREP(ZXDHQPSQ_DESTQPN, op_info->dest_qp) |
			      FIELD_PREP(ZXDHQPSQ_DESTQKEY, op_info->qkey));

	if (imm_data_flag) {
		wqe_idx = (wqe_idx + 1) % qp->sq_ring.size;
		if (!wqe_idx)
			qp->swqe_polarity = !qp->swqe_polarity;
		wqe_ex = qp->sq_base[wqe_idx].elem;

		if (inline_len) {
			/* imm and inline use the same valid, valid set after inline data updated*/
			copy_size = inline_len < INLINE_DATASIZE_24BYTES ?
					    inline_len :
					    INLINE_DATASIZE_24BYTES;
			inline_dest = (__u8 *)wqe_ex + WQE_OFFSET_8BYTES;
			inline_src = (__u8 *)op_info->data;
			memcpy(inline_dest, inline_src, copy_size);
			inline_len -= copy_size;
			inline_src += copy_size;
		}
		set_64bit_val(
			wqe_ex, 0,
			FIELD_PREP(ZXDHQPSQ_IMMDATA_VALID, qp->swqe_polarity) |
				FIELD_PREP(ZXDHQPSQ_IMMDATA, info->imm_data));

	} else if (inline_len) {
		wqe_idx = (wqe_idx + 1) % qp->sq_ring.size;
		if (!wqe_idx)
			qp->swqe_polarity = !qp->swqe_polarity;
		wqe_ex = qp->sq_base[wqe_idx].elem;
		inline_dest = (__u8 *)wqe_ex;
		inline_src = (__u8 *)op_info->data;

		if (inline_len <= INLINE_DATASIZE_7BYTES) {
			copy_size = inline_len;
			memcpy(inline_dest, inline_src, copy_size);
			inline_len = 0;
		} else {
			copy_size = INLINE_DATASIZE_7BYTES;
			memcpy(inline_dest, inline_src, copy_size);
			inline_len -= copy_size;
			inline_src += copy_size;
			inline_dest += WQE_OFFSET_8BYTES;
			copy_size = inline_len < INLINE_DATASIZE_24BYTES ?
					    inline_len :
					    INLINE_DATASIZE_24BYTES;
			memcpy(inline_dest, inline_src, copy_size);
			inline_len -= copy_size;
			inline_src += copy_size;
		}
		inline_valid_addr = (__u8 *)wqe_ex + WQE_OFFSET_7BYTES;
		*inline_valid_addr = qp->swqe_polarity << ZXDH_INLINE_VALID_S;
	}

	while (inline_len) {
		wqe_idx = (wqe_idx + 1) % qp->sq_ring.size;
		if (!wqe_idx)
			qp->swqe_polarity = !qp->swqe_polarity;
		wqe_ex = qp->sq_base[wqe_idx].elem;
		inline_dest = (__u8 *)wqe_ex;

		if (inline_len <= INLINE_DATASIZE_7BYTES) {
			copy_size = inline_len;
			memcpy(inline_dest, inline_src, copy_size);
			inline_len = 0;
		} else {
			copy_size = INLINE_DATASIZE_7BYTES;
			memcpy(inline_dest, inline_src, copy_size);
			inline_len -= copy_size;
			inline_src += copy_size;
			inline_dest += WQE_OFFSET_8BYTES;
			copy_size = inline_len < INLINE_DATASIZE_24BYTES ?
					    inline_len :
					    INLINE_DATASIZE_24BYTES;
			memcpy(inline_dest, inline_src, copy_size);
			inline_len -= copy_size;
			inline_src += copy_size;
		}
		inline_valid_addr = (__u8 *)wqe_ex + WQE_OFFSET_7BYTES;
		*inline_valid_addr = qp->swqe_polarity << ZXDH_INLINE_VALID_S;
	}

	udma_to_device_barrier(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe_base, 0, hdr);

	if (post_sq)
		zxdh_qp_post_wr(qp);

	return 0;
}

/**
 * zxdh_stag_local_invalidate - stag invalidate operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
enum zxdh_status_code zxdh_stag_local_invalidate(struct zxdh_qp *qp,
						 struct zxdh_post_sq_info *info,
						 bool post_sq)
{
	__le64 *wqe;
	struct zxdh_inv_local_stag *op_info;
	__u64 hdr;
	__u32 wqe_idx;
	bool local_fence = true;

	op_info = &info->op.inv_local_stag;

	wqe = zxdh_qp_get_next_send_wqe(qp, &wqe_idx, ZXDH_QP_WQE_MIN_QUANTA, 0,
					info);
	if (!wqe)
		return ZXDH_ERR_QP_TOOMANY_WRS_POSTED;

	set_64bit_val(wqe, 16, 0);

	hdr = FIELD_PREP(ZXDHQPSQ_VALID, qp->swqe_polarity) |
	      FIELD_PREP(ZXDHQPSQ_OPCODE, ZXDH_OP_TYPE_LOCAL_INV) |
	      FIELD_PREP(ZXDHQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(ZXDHQPSQ_LOCALFENCE, local_fence) |
	      FIELD_PREP(ZXDHQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(ZXDHQPSQ_REMSTAG, op_info->target_stag);

	udma_to_device_barrier(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_qp_post_wr(qp);

	return 0;
}

/**
 * zxdh_mw_bind - bind Memory Window
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
enum zxdh_status_code zxdh_mw_bind(struct zxdh_qp *qp,
				   struct zxdh_post_sq_info *info, bool post_sq)
{
	__le64 *wqe;
	struct zxdh_bind_window *op_info;
	__u64 hdr;
	__u32 wqe_idx;
	__u8 access = 1;
	__u16 value = 0;

	op_info = &info->op.bind_window;
	wqe = zxdh_qp_get_next_send_wqe(qp, &wqe_idx, ZXDH_QP_WQE_MIN_QUANTA, 0,
					info);
	if (!wqe)
		return ZXDH_ERR_QP_TOOMANY_WRS_POSTED;

	if (op_info->ena_writes) {
		access = (op_info->ena_reads << 2) |
			 (op_info->ena_writes << 3) | (1 << 1) | access;
	} else {
		access = (op_info->ena_reads << 2) |
			 (op_info->ena_writes << 3) | access;
	}

	qp->wqe_ops.iw_set_mw_bind_wqe(wqe, op_info);

	value = (__u16)((op_info->mw_pa_pble_index >> 12) & 0xC000000000000);

	hdr = FIELD_PREP(ZXDHQPSQ_OPCODE, ZXDH_OP_TYPE_BIND_MW) |
	      FIELD_PREP(ZXDHQPSQ_MWSTAG, op_info->mw_stag) |
	      FIELD_PREP(ZXDHQPSQ_STAGRIGHTS, access) |
	      FIELD_PREP(ZXDHQPSQ_VABASEDTO,
			 (op_info->addressing_type == ZXDH_ADDR_TYPE_VA_BASED ?
				  1 :
				  0)) |
	      FIELD_PREP(ZXDHQPSQ_MEMWINDOWTYPE,
			 (op_info->mem_window_type_1 ? 1 : 0)) |
	      FIELD_PREP(ZXDHQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(ZXDHQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(ZXDHQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(ZXDHQPSQ_MW_HOST_PAGE_SIZE, op_info->host_page_size) |
	      FIELD_PREP(ZXDHQPSQ_MW_LEAF_PBL_SIZE, op_info->leaf_pbl_size) |
	      FIELD_PREP(ZXDHQPSQ_MW_PA_PBLE_THREE, value) |
	      FIELD_PREP(ZXDHQPSQ_VALID, qp->swqe_polarity);

	udma_to_device_barrier(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	if (post_sq)
		zxdh_qp_post_wr(qp);

	return 0;
}

static void zxdh_sleep_ns(unsigned int nanoseconds)
{
	struct timespec req;

	req.tv_sec = 0;
	req.tv_nsec = nanoseconds;
	nanosleep(&req, NULL);
}

/**
 * zxdh_post_receive - post receive wqe
 * @qp: hw qp ptr
 * @info: post rq information
 */
enum zxdh_status_code zxdh_post_receive(struct zxdh_qp *qp,
					struct zxdh_post_rq_info *info)
{
	__u32 wqe_idx, i, byte_off;
	__le64 *wqe;
	struct zxdh_sge *sge;

	if (qp->max_rq_frag_cnt < info->num_sges)
		return ZXDH_ERR_INVALID_FRAG_COUNT;

	wqe = zxdh_qp_get_next_recv_wqe(qp, &wqe_idx);
	if (unlikely(!wqe))
		return ZXDH_ERR_QP_TOOMANY_WRS_POSTED;

	qp->rq_wrid_array[wqe_idx] = info->wr_id;

	for (i = 0, byte_off = ZXDH_QP_FRAG_BYTESIZE; i < info->num_sges; i++) {
		sge = &info->sg_list[i];
		set_64bit_val(wqe, byte_off, sge->tag_off);
		set_64bit_val(wqe, byte_off + 8,
			      FIELD_PREP(ZXDHQPRQ_FRAG_LEN, sge->len) |
				      FIELD_PREP(ZXDHQPRQ_STAG, sge->stag));
		byte_off += ZXDH_QP_FRAG_BYTESIZE;
	}

	/**
	 * while info->num_sges < qp->max_rq_frag_cnt, or 0 == info->num_sges，
	 * fill next fragment with FRAG_LEN=0, FRAG_STAG=0x00000100,
	 * witch indicates a invalid fragment
	 */
	if (info->num_sges < qp->max_rq_frag_cnt || 0 == info->num_sges) {
		set_64bit_val(wqe, byte_off, 0);
		set_64bit_val(wqe, byte_off + 8,
			      FIELD_PREP(ZXDHQPRQ_FRAG_LEN, 0) |
				      FIELD_PREP(ZXDHQPRQ_STAG, 0x00000100));
	}

	set_64bit_val(wqe, 0,
		      FIELD_PREP(ZXDHQPRQ_ADDFRAGCNT, info->num_sges) |
			      FIELD_PREP(ZXDHQPRQ_SIGNATURE,
					 qp->rwqe_signature));

	udma_to_device_barrier(); /* make sure WQE is populated before valid bit is set */
	if (info->num_sges > 3)
		zxdh_sleep_ns(1000);

	set_64bit_val(wqe, 8, FIELD_PREP(ZXDHQPRQ_VALID, qp->rwqe_polarity));

	return 0;
}

/**
 * zxdh_cq_resize - reset the cq buffer info
 * @cq: cq to resize
 * @cq_base: new cq buffer addr
 * @cq_size: number of cqes
 */
void zxdh_cq_resize(struct zxdh_cq *cq, void *cq_base, int cq_size)
{
	cq->cq_base = cq_base;
	cq->cq_size = cq_size;
	ZXDH_RING_INIT(cq->cq_ring, cq->cq_size);
	cq->polarity = 1;
}

/**
 * zxdh_cq_set_resized_cnt - record the count of the resized buffers
 * @cq: cq to resize
 * @cq_cnt: the count of the resized cq buffers
 */
void zxdh_cq_set_resized_cnt(struct zxdh_cq *cq, __u16 cq_cnt)
{
	__u64 temp_val;
	__u16 sw_cq_sel;
	__u8 arm_next;
	__u8 arm_seq_num;

	get_64bit_val(cq->shadow_area, 0, &temp_val);

	sw_cq_sel = (__u16)FIELD_GET(ZXDH_CQ_DBSA_SW_CQ_SELECT, temp_val);
	sw_cq_sel += cq_cnt;

	arm_seq_num = (__u8)FIELD_GET(ZXDH_CQ_DBSA_ARM_SEQ_NUM, temp_val);
	arm_next = (__u8)FIELD_GET(ZXDH_CQ_DBSA_ARM_NEXT, temp_val);
	cq->cqe_rd_cnt = 0;

	temp_val = FIELD_PREP(ZXDH_CQ_DBSA_ARM_SEQ_NUM, arm_seq_num) |
		   FIELD_PREP(ZXDH_CQ_DBSA_SW_CQ_SELECT, sw_cq_sel) |
		   FIELD_PREP(ZXDH_CQ_DBSA_ARM_NEXT, arm_next) |
		   FIELD_PREP(ZXDH_CQ_DBSA_CQEIDX, cq->cqe_rd_cnt);

	set_64bit_val(cq->shadow_area, 0, temp_val);
}

/**
 * zxdh_cq_request_notification - cq notification request (door bell)
 * @cq: hw cq
 * @cq_notify: notification type
 */
void zxdh_cq_request_notification(struct zxdh_cq *cq,
				  enum zxdh_cmpl_notify cq_notify)
{
	__u64 temp_val;
	__u16 sw_cq_sel;
	__u8 arm_next = 0;
	__u8 arm_seq_num;
	__u32 cqe_index;
	__u32 hdr;

	get_64bit_val(cq->shadow_area, 0, &temp_val);
	arm_seq_num = (__u8)FIELD_GET(ZXDH_CQ_DBSA_ARM_SEQ_NUM, temp_val);
	arm_seq_num++;
	sw_cq_sel = (__u16)FIELD_GET(ZXDH_CQ_DBSA_SW_CQ_SELECT, temp_val);
	cqe_index = (__u32)FIELD_GET(ZXDH_CQ_DBSA_CQEIDX, temp_val);

	if (cq_notify == ZXDH_CQ_COMPL_SOLICITED)
		arm_next = 1;
	temp_val = FIELD_PREP(ZXDH_CQ_DBSA_ARM_SEQ_NUM, arm_seq_num) |
		   FIELD_PREP(ZXDH_CQ_DBSA_SW_CQ_SELECT, sw_cq_sel) |
		   FIELD_PREP(ZXDH_CQ_DBSA_ARM_NEXT, arm_next) |
		   FIELD_PREP(ZXDH_CQ_DBSA_CQEIDX, cqe_index);

	set_64bit_val(cq->shadow_area, 0, temp_val);

	hdr = FIELD_PREP(ZXDH_CQ_ARM_DBSA_VLD, 0) |
	      FIELD_PREP(ZXDH_CQ_ARM_CQ_ID, cq->cq_id);

	udma_to_device_barrier(); /* make sure WQE is populated before valid bit is set */

	db_wr32(hdr, cq->cqe_alloc_db);
}

static inline void build_comp_status(__u32 cq_type,
				     struct zxdh_cq_poll_info *info)
{
	if (!info->error) {
		info->comp_status = ZXDH_COMPL_STATUS_SUCCESS;
		if (cq_type == ZXDH_CQE_QTYPE_RQ) {
			if (info->major_err != ERROR_CODE_VALUE &&
			    info->minor_err != ERROR_CODE_VALUE) {
				info->comp_status = ZXDH_COMPL_STATUS_UNKNOWN;
			}
		}
		return;
	}

	switch (info->major_err) {
	case ZXDH_RETRY_ACK_MAJOR_ERR:
		if (info->minor_err == ZXDH_RETRY_ACK_MINOR_ERR) {
			info->comp_status = ZXDH_COMPL_STATUS_RETRY_ACK_ERR;
			return;
		}
		if (info->minor_err == ZXDH_TX_WINDOW_QUERY_ITEM_MINOR_ERR) {
			info->comp_status =
				ZXDH_COMPL_STATUS_TX_WINDOW_QUERY_ITEM_ERR;
			return;
		}
		break;
	case ZXDH_FLUSH_MAJOR_ERR:
		info->comp_status = ZXDH_COMPL_STATUS_FLUSHED;
		return;
	default:
		info->comp_status = ZXDH_COMPL_STATUS_UNKNOWN;
		return;
	}
}

__le64 *get_current_cqe(struct zxdh_cq *cq)
{
	return ZXDH_GET_CURRENT_EXTENDED_CQ_ELEM(cq);
}

static inline void zxdh_get_cq_poll_info(struct zxdh_qp *qp,
					 struct zxdh_cq_poll_info *info,
					 __u64 qword2, __u64 qword3)
{
	__u8 qp_type;

	qp_type = qp->qp_type;

	info->imm_valid = (bool)FIELD_GET(ZXDH_CQ_IMMVALID, qword2);
	if (info->imm_valid) {
		info->imm_data = (__u32)FIELD_GET(ZXDH_CQ_IMMDATA, qword3);
		info->op_type = ZXDH_OP_TYPE_REC_IMM;
	} else {
		info->op_type = ZXDH_OP_TYPE_REC;
	}

	info->bytes_xfered = (__u32)FIELD_GET(ZXDHCQ_PAYLDLEN, qword3);

	if (likely(qp_type == ZXDH_QP_TYPE_ROCE_RC)) {
		if (qword2 & ZXDHCQ_STAG) {
			info->stag_invalid_set = true;
			info->inv_stag =
				(__u32)FIELD_GET(ZXDHCQ_INVSTAG, qword2);
		} else {
			info->stag_invalid_set = false;
		}
	} else if (qp_type == ZXDH_QP_TYPE_ROCE_UD) {
		info->ipv4 = (bool)FIELD_GET(ZXDHCQ_IPV4, qword2);
		info->ud_src_qpn = (__u32)FIELD_GET(ZXDHCQ_UDSRCQPN, qword2);
	}
}

static enum zxdh_status_code update_cq_poll_info(struct zxdh_qp *qp,
						 struct zxdh_cq_poll_info *info,
						 __u32 wqe_idx, __u64 qword0)
{
	info->wr_id = qp->sq_wrtrk_array[wqe_idx].wrid;
	if (!info->comp_status)
		info->bytes_xfered = qp->sq_wrtrk_array[wqe_idx].wr_len;
	info->op_type = (__u8)FIELD_GET(ZXDHCQ_OP, qword0);
	ZXDH_RING_SET_TAIL(qp->sq_ring,
			   wqe_idx + qp->sq_wrtrk_array[wqe_idx].quanta);
	return ZXDH_SUCCESS;
}

static enum zxdh_status_code
process_tx_window_query_item_err(struct zxdh_qp *qp,
				 struct zxdh_cq_poll_info *info)
{
	int ret;
	struct ibv_qp *ib_qp;
	struct zxdh_uqp *iwuqp;
	struct zxdh_rdma_qpc qpc = { 0 };

	iwuqp = container_of(qp, struct zxdh_uqp, qp);
	ib_qp = &iwuqp->vqp.qp;
	ret = zxdh_query_qpc(ib_qp, &qpc);
	if (ret) {
		zxdh_dbg(ZXDH_DBG_QP,
			 "process tx window query item query qpc failed:%d\n",
			 ret);
		return ZXDH_ERR_RETRY_ACK_ERR;
	}
	if (qpc.tx_last_ack_psn != qp->qp_last_ack_qsn)
		qp->qp_reset_cnt = 0;

	qp->qp_last_ack_qsn = qpc.tx_last_ack_psn;
	if (qp->qp_reset_cnt >= ZXDH_QP_RETRY_COUNT)
		return ZXDH_ERR_RETRY_ACK_ERR;

	ret = zxdh_reset_qp(ib_qp, ZXDH_RESET_RETRY_TX_ITEM_FLAG);
	if (ret) {
		zxdh_dbg(ZXDH_DBG_QP,
			 "process tx window query item reset qp failed:%d\n",
			 ret);
		return ZXDH_ERR_RETRY_ACK_ERR;
	}
	qp->qp_reset_cnt++;
	return ZXDH_ERR_RETRY_ACK_NOT_EXCEED_ERR;
}

static enum zxdh_status_code
process_retry_ack_err(struct zxdh_qp *qp, struct zxdh_cq_poll_info *info)
{
	int ret;
	struct ibv_qp *ib_qp;
	struct zxdh_uqp *iwuqp;
	struct zxdh_rdma_qpc qpc = { 0 };
	struct zxdh_rdma_qpc qpc_req_cmd = { 0 };

	iwuqp = container_of(qp, struct zxdh_uqp, qp);

	ib_qp = &iwuqp->vqp.qp;
	ret = zxdh_query_qpc(ib_qp, &qpc);
	if (ret) {
		zxdh_dbg(ZXDH_DBG_QP, "process retry ack query qpc failed:%d\n",
			 ret);
		return ZXDH_ERR_RETRY_ACK_ERR;
	}
	if (!(qpc.retry_cqe_sq_opcode >= ZXDH_RETRY_CQE_SQ_OPCODE_ERR &&
	      (qpc.recv_err_flag == ZXDH_RECV_ERR_FLAG_NAK_RNR_NAK ||
	       qpc.recv_err_flag == ZXDH_RECV_ERR_FLAG_READ_RESP))) {
		return ZXDH_ERR_RETRY_ACK_ERR;
	}
	if (qpc.tx_last_ack_psn != qp->cqe_last_ack_qsn)
		qp->cqe_retry_cnt = 0;

	qp->cqe_last_ack_qsn = qpc.tx_last_ack_psn;
	if (qp->cqe_retry_cnt >= ZXDH_QP_RETRY_COUNT)
		return ZXDH_ERR_RETRY_ACK_ERR;

	memcpy(&qpc_req_cmd, &qpc, sizeof(qpc));
	qpc_req_cmd.package_err_flag = 0;
	qpc_req_cmd.ack_err_flag = 0;
	qpc_req_cmd.err_flag = 0;
	qpc_req_cmd.retry_cqe_sq_opcode &= ZXDH_RESET_RETRY_CQE_SQ_OPCODE_ERR;
	qpc_req_cmd.cur_retry_count = qpc.retry_count;
	ret = zxdh_modify_qpc(ib_qp, &qpc_req_cmd,
			      ZXDH_PACKAGE_ERR_FLAG | ZXDH_ERR_FLAG_SET |
				      ZXDH_RETRY_CQE_SQ_OPCODE |
				      ZXDH_TX_READ_RETRY_FLAG_SET);
	if (ret) {
		zxdh_dbg(ZXDH_DBG_QP,
			 "process retry ack modify qpc failed:%d\n", ret);
		return ZXDH_ERR_RETRY_ACK_ERR;
	}
	qp->cqe_retry_cnt++;
	return ZXDH_ERR_RETRY_ACK_NOT_EXCEED_ERR;
}

static enum zxdh_status_code
zxdh_flush_sq_comp_info(struct zxdh_qp *qp, struct zxdh_cq_poll_info *info,
			bool *move_cq_head)
{
	if (!ZXDH_RING_MORE_WORK(qp->sq_ring)) {
		ZXDH_RING_INIT(qp->sq_ring, qp->sq_ring.size)
		return ZXDH_ERR_Q_EMPTY;
	}
	do {
		__le64 *sw_wqe;
		__u64 wqe_qword;
		__u64 wqe_idx;

		wqe_idx = qp->sq_ring.tail;
		sw_wqe = qp->sq_base[wqe_idx].elem;
		get_64bit_val(sw_wqe, 0, &wqe_qword);
		info->op_type = (__u8)FIELD_GET(ZXDHQPSQ_OPCODE, wqe_qword);
		ZXDH_RING_SET_TAIL(qp->sq_ring,
				   wqe_idx +
					   qp->sq_wrtrk_array[wqe_idx].quanta);

		if (info->op_type != ZXDH_OP_TYPE_NOP) {
			info->wr_id = qp->sq_wrtrk_array[wqe_idx].wrid;
			break;
		}
	} while (1);
	qp->sq_flush_seen = true;
	if (!ZXDH_RING_MORE_WORK(qp->sq_ring)) {
		qp->sq_flush_complete = true;
		ZXDH_RING_INIT(qp->sq_ring, qp->sq_ring.size)
	} else
		*move_cq_head = false;
	return ZXDH_SUCCESS;
}

static enum zxdh_status_code zxdh_sq_comp_info(struct zxdh_qp *qp,
					       struct zxdh_cq_poll_info *info,
					       __u32 wqe_idx, __u64 qword0,
					       bool *move_cq_head)
{
	enum zxdh_status_code status_code;

	switch (info->comp_status) {
	case ZXDH_COMPL_STATUS_SUCCESS:
	case ZXDH_COMPL_STATUS_UNKNOWN:
		break;
	case ZXDH_COMPL_STATUS_RETRY_ACK_ERR:
		if (qp->qp_type == ZXDH_QP_TYPE_ROCE_RC) {
			status_code = process_retry_ack_err(qp, info);
			return (status_code == ZXDH_ERR_RETRY_ACK_ERR) ?
				       update_cq_poll_info(qp, info, wqe_idx,
							   qword0) :
				       status_code;
		}
		break;
	case ZXDH_COMPL_STATUS_TX_WINDOW_QUERY_ITEM_ERR:
		if (qp->qp_type == ZXDH_QP_TYPE_ROCE_RC) {
			status_code =
				process_tx_window_query_item_err(qp, info);
			return (status_code == ZXDH_ERR_RETRY_ACK_ERR) ?
				       update_cq_poll_info(qp, info, wqe_idx,
							   qword0) :
				       status_code;
		}
		break;
	case ZXDH_COMPL_STATUS_FLUSHED:
		return zxdh_flush_sq_comp_info(qp, info, move_cq_head);
	default:
		break;
	}
	return update_cq_poll_info(qp, info, wqe_idx, qword0);
}

static enum zxdh_status_code zxdh_rq_comp_info(struct zxdh_qp *qp,
					       struct zxdh_cq_poll_info *info,
					       __u32 wqe_idx, __u64 qword2,
					       __u64 qword3, bool *move_cq_head)
{
	struct zxdh_uqp *iwuqp = NULL;
	struct zxdh_usrq *iwusrq = NULL;
	struct zxdh_srq *srq = NULL;

	if (qp->is_srq) {
		iwuqp = container_of(qp, struct zxdh_uqp, qp);
		iwusrq = iwuqp->srq;
		srq = &iwusrq->srq;
		zxdh_free_srq_wqe(srq, wqe_idx);
		info->wr_id = srq->srq_wrid_array[wqe_idx];
		zxdh_get_cq_poll_info(qp, info, qword2, qword3);
	} else {
		if (unlikely(info->comp_status == ZXDH_COMPL_STATUS_FLUSHED ||
			     info->comp_status == ZXDH_COMPL_STATUS_UNKNOWN)) {
			if (!ZXDH_RING_MORE_WORK(qp->rq_ring))
				return ZXDH_ERR_Q_EMPTY;

			wqe_idx = qp->rq_ring.tail;
		}
		info->wr_id = qp->rq_wrid_array[wqe_idx];
		zxdh_get_cq_poll_info(qp, info, qword2, qword3);
		ZXDH_RING_SET_TAIL(qp->rq_ring, wqe_idx + 1);
		if (info->comp_status == ZXDH_COMPL_STATUS_FLUSHED) {
			qp->rq_flush_seen = true;
			if (!ZXDH_RING_MORE_WORK(qp->rq_ring))
				qp->rq_flush_complete = true;
			else
				*move_cq_head = false;
		}
	}
	return ZXDH_SUCCESS;
}

/**
 * zxdh_cq_poll_cmpl - get cq completion info
 * @cq: hw cq
 * @info: cq poll information returned
 */
enum zxdh_status_code zxdh_cq_poll_cmpl(struct zxdh_cq *cq,
					struct zxdh_cq_poll_info *info)
{
	__u64 comp_ctx, qword0, qword2, qword3;
	__le64 *cqe;
	struct zxdh_qp *qp;
	struct zxdh_ring *pring = NULL;
	__u32 wqe_idx, q_type;
	int ret_code;
	bool move_cq_head = true;
	__u8 polarity;

	cqe = get_current_cqe(cq);

	get_64bit_val(cqe, 0, &qword0);
	polarity = (__u8)FIELD_GET(ZXDH_CQ_VALID, qword0);
	if (polarity != cq->polarity)
		return ZXDH_ERR_Q_EMPTY;

	/* Ensure CQE contents are read after valid bit is checked */
	udma_from_device_barrier();
	get_64bit_val(cqe, 8, &comp_ctx);
	get_64bit_val(cqe, 16, &qword2);
	get_64bit_val(cqe, 24, &qword3);

	qp = (struct zxdh_qp *)(unsigned long)comp_ctx;
	if (unlikely(!qp || qp->destroy_pending)) {
		ret_code = ZXDH_ERR_Q_DESTROYED;
		goto exit;
	}

	info->qp_handle = (zxdh_qp_handle)(unsigned long)qp;
	q_type = (__u8)FIELD_GET(ZXDH_CQ_SQ, qword0);
	info->solicited_event = (bool)FIELD_GET(ZXDHCQ_SOEVENT, qword0);
	wqe_idx = (__u32)FIELD_GET(ZXDH_CQ_WQEIDX, qword0);
	info->error = (bool)FIELD_GET(ZXDH_CQ_ERROR, qword0);
	info->major_err = FIELD_GET(ZXDH_CQ_MAJERR, qword0);
	info->minor_err = FIELD_GET(ZXDH_CQ_MINERR, qword0);

	/* Set the min error to standard flush error code for remaining cqes */
	if (unlikely(info->error && info->major_err == ZXDH_FLUSH_MAJOR_ERR &&
		     info->minor_err != FLUSH_GENERAL_ERR)) {
		qword0 &= ~ZXDH_CQ_MINERR;
		qword0 |= FIELD_PREP(ZXDH_CQ_MINERR, FLUSH_GENERAL_ERR);
		set_64bit_val(cqe, 0, qword0);
	}
	build_comp_status(q_type, info);

	info->qp_id = (__u32)FIELD_GET(ZXDHCQ_QPID, qword2);
	info->imm_valid = false;
	switch (q_type) {
	case ZXDH_CQE_QTYPE_SQ:
		ret_code = zxdh_sq_comp_info(qp, info, wqe_idx, qword0,
					     &move_cq_head);
		pring = &qp->sq_ring;
		break;
	case ZXDH_CQE_QTYPE_RQ:
		ret_code = zxdh_rq_comp_info(qp, info, wqe_idx, qword2, qword3,
					     &move_cq_head);
		pring = &qp->rq_ring;
		break;
	default:
		zxdh_dbg(ZXDH_DBG_CQ, "zxdh get cqe type unknown!\n");
		ret_code = ZXDH_ERR_Q_DESTROYED;
		break;
	}
exit:
	if (move_cq_head) {
		__u64 cq_shadow_temp;

		ZXDH_RING_MOVE_HEAD_NOCHECK(cq->cq_ring);
		if (!ZXDH_RING_CURRENT_HEAD(cq->cq_ring))
			cq->polarity ^= 1;

		ZXDH_RING_MOVE_TAIL(cq->cq_ring);
		cq->cqe_rd_cnt++;
		get_64bit_val(cq->shadow_area, 0, &cq_shadow_temp);
		cq_shadow_temp &= ~ZXDH_CQ_DBSA_CQEIDX;
		cq_shadow_temp |=
			FIELD_PREP(ZXDH_CQ_DBSA_CQEIDX, cq->cqe_rd_cnt);
		set_64bit_val(cq->shadow_area, 0, cq_shadow_temp);
	} else {
		qword0 &= ~ZXDH_CQ_WQEIDX;
		qword0 |= FIELD_PREP(ZXDH_CQ_WQEIDX, pring->tail);
		set_64bit_val(cqe, 0, qword0);
	}

	return ret_code;
}

/**
 * zxdh_qp_round_up - return round up qp wq depth
 * @wqdepth: wq depth in quanta to round up
 */
int zxdh_qp_round_up(__u32 wqdepth)
{
	int scount = 1;

	if (wqdepth == 0)
		return 0;

	for (wqdepth--; scount <= 16; scount *= 2)
		wqdepth |= wqdepth >> scount;

	return ++wqdepth;
}

/**
 * zxdh_cq_round_up - return round up cq wq depth
 * @wqdepth: wq depth in quanta to round up
 */
int zxdh_cq_round_up(__u32 wqdepth)
{
	int scount = 1;

	if (wqdepth == 0)
		return 0;

	for (wqdepth--; scount <= 16; scount *= 2)
		wqdepth |= wqdepth >> scount;

	return ++wqdepth;
}

/**
 * zxdh_get_rq_wqe_shift - get shift count for maximum rq wqe size
 * @sge: Maximum Scatter Gather Elements wqe
 * @shift: Returns the shift needed based on sge
 *
 * Shift can be used to left shift the rq wqe size based on number of SGEs.
 * For 1 SGE, shift = 1 (wqe size of 2*16 bytes).
 * For 2 or 3 SGEs, shift = 2 (wqe size of 4*16 bytes).
 * For 4-7 SGE's Shift of 3.
 *  For 8-15 SGE's Shift of 4 otherwise (wqe size of 512 bytes).
 */
void zxdh_get_rq_wqe_shift(__u32 sge, __u8 *shift)
{
	*shift = 0; //16bytes RQE, need to confirm configuration
	if (sge < 2)
		*shift = 1;
	else if (sge < 4)
		*shift = 2;
	else if (sge < 8)
		*shift = 3;
	else if (sge < 16)
		*shift = 4;
	else
		*shift = 5;
}

/**
 * zxdh_get_sq_wqe_shift - get shift count for maximum wqe size
 * @sge: Maximum Scatter Gather Elements wqe
 * @inline_data: Maximum inline data size
 * @shift: Returns the shift needed based on sge
 *
 * Shift can be used to left shift the wqe size based on number of SGEs and inlind data size.
 * To surport WR with imm_data,shift = 1 (wqe size of 2*32 bytes).
 * For 2-7 SGEs or 24 < inline data <= 86, shift = 2 (wqe size of 4*32 bytes).
 * Otherwise (wqe size of 256 bytes).
 */
void zxdh_get_sq_wqe_shift(__u32 sge, __u32 inline_data, __u8 *shift)
{
	*shift = 1;

	if (sge > 1 || inline_data > 24) {
		if (sge < 8 && inline_data <= 86)
			*shift = 2;
		else
			*shift = 3;
	}
}

/*
 * zxdh_get_sqdepth - get SQ depth (quanta)
 * @dev_attrs: qp HW attributes
 * @sq_size: SQ size
 * @shift: shift which determines size of WQE
 * @sqdepth: depth of SQ
 *
 */
enum zxdh_status_code zxdh_get_sqdepth(struct zxdh_dev_attrs *dev_attrs,
				       __u32 sq_size, __u8 shift,
				       __u32 *sqdepth)
{
	if (sq_size > ZXDH_MAX_SQ_DEPTH)
		return ZXDH_ERR_INVALID_SIZE;

	*sqdepth = zxdh_qp_round_up((sq_size << shift) + ZXDH_SQ_RSVD);

	if (*sqdepth < (ZXDH_QP_SW_MIN_WQSIZE << shift))
		*sqdepth = ZXDH_QP_SW_MIN_WQSIZE << shift;
	else if (*sqdepth > dev_attrs->max_hw_wq_quanta)
		return ZXDH_ERR_INVALID_SIZE;

	return 0;
}

/*
 * zxdh_get_rqdepth - get RQ depth (quanta)
 * @dev_attrs: qp HW attributes
 * @rq_size: RQ size
 * @shift: shift which determines size of WQE
 * @rqdepth: depth of RQ
 */
enum zxdh_status_code zxdh_get_rqdepth(struct zxdh_dev_attrs *dev_attrs,
				       __u32 rq_size, __u8 shift,
				       __u32 *rqdepth)
{
	*rqdepth = zxdh_qp_round_up((rq_size << shift) + ZXDH_RQ_RSVD);

	if (*rqdepth < (ZXDH_QP_SW_MIN_WQSIZE << shift))
		*rqdepth = ZXDH_QP_SW_MIN_WQSIZE << shift;
	else if (*rqdepth > dev_attrs->max_hw_rq_quanta)
		return ZXDH_ERR_INVALID_SIZE;

	return 0;
}

static const struct zxdh_wqe_ops iw_wqe_ops = {
	.iw_copy_inline_data = zxdh_copy_inline_data,
	.iw_inline_data_size_to_quanta = zxdh_inline_data_size_to_quanta,
	.iw_set_fragment = zxdh_set_fragment,
	.iw_set_mw_bind_wqe = zxdh_set_mw_bind_wqe,
};

/**
 * zxdh_qp_init - initialize shared qp
 * @qp: hw qp (user and kernel)
 * @info: qp initialization info
 *
 * initializes the vars used in both user and kernel mode.
 * size of the wqe depends on numbers of max. fragements
 * allowed. Then size of wqe * the number of wqes should be the
 * amount of memory allocated for sq and rq.
 */
enum zxdh_status_code zxdh_qp_init(struct zxdh_qp *qp,
				   struct zxdh_qp_init_info *info)
{
	enum zxdh_status_code ret_code = 0;
	__u32 sq_ring_size;
	__u8 sqshift, rqshift;

	qp->dev_attrs = info->dev_attrs;
	if (info->max_sq_frag_cnt > qp->dev_attrs->max_hw_wq_frags ||
	    info->max_rq_frag_cnt > qp->dev_attrs->max_hw_wq_frags)
		return ZXDH_ERR_INVALID_FRAG_COUNT;

	zxdh_get_rq_wqe_shift(info->max_rq_frag_cnt, &rqshift);
	zxdh_get_sq_wqe_shift(info->max_sq_frag_cnt, info->max_inline_data,
			      &sqshift);

	qp->qp_caps = info->qp_caps;
	qp->sq_base = info->sq;
	qp->rq_base = info->rq;
	qp->qp_type = info->type;
	qp->shadow_area = info->shadow_area;
	set_64bit_val(qp->shadow_area, 0, 0x8000);
	qp->sq_wrtrk_array = info->sq_wrtrk_array;

	qp->rq_wrid_array = info->rq_wrid_array;
	qp->wqe_alloc_db = info->wqe_alloc_db;
	qp->qp_id = info->qp_id;
	qp->sq_size = info->sq_size;
	qp->push_mode = false;
	qp->max_sq_frag_cnt = info->max_sq_frag_cnt;
	sq_ring_size = qp->sq_size << sqshift;
	ZXDH_RING_INIT(qp->sq_ring, sq_ring_size);
	ZXDH_RING_INIT(qp->initial_ring, sq_ring_size);
	qp->swqe_polarity = 0;
	qp->swqe_polarity_deferred = 1;
	qp->rwqe_polarity = 0;
	qp->rwqe_signature = 0;
	qp->rq_size = info->rq_size;
	qp->max_rq_frag_cnt = info->max_rq_frag_cnt;
	qp->max_inline_data = (info->max_inline_data == 0) ?
				      ZXDH_MAX_INLINE_DATA_SIZE :
				      info->max_inline_data;
	qp->rq_wqe_size = rqshift;
	ZXDH_RING_INIT(qp->rq_ring, qp->rq_size);
	qp->rq_wqe_size_multiplier = 1 << rqshift;
	qp->wqe_ops = iw_wqe_ops;
	return ret_code;
}

/**
 * zxdh_cq_init - initialize shared cq (user and kernel)
 * @cq: hw cq
 * @info: hw cq initialization info
 */
enum zxdh_status_code zxdh_cq_init(struct zxdh_cq *cq,
				   struct zxdh_cq_init_info *info)
{
	cq->cq_base = info->cq_base;
	cq->cq_id = info->cq_id;
	cq->cq_size = info->cq_size;
	cq->cqe_alloc_db = info->cqe_alloc_db;
	cq->cq_ack_db = info->cq_ack_db;
	cq->shadow_area = info->shadow_area;
	cq->cqe_size = info->cqe_size;
	ZXDH_RING_INIT(cq->cq_ring, cq->cq_size);
	cq->polarity = 1;
	cq->cqe_rd_cnt = 0;

	return 0;
}

/**
 * zxdh_clean_cq - clean cq entries
 * @q: completion context
 * @cq: cq to clean
 */
void zxdh_clean_cq(void *q, struct zxdh_cq *cq)
{
	__le64 *cqe;
	__u64 qword0, comp_ctx;
	__u32 cq_head;
	__u8 polarity, temp;

	cq_head = cq->cq_ring.head;
	temp = cq->polarity;
	do {
		if (cq->cqe_size)
			cqe = ((struct zxdh_extended_cqe
					*)(cq->cq_base))[cq_head]
				      .buf;
		else
			cqe = cq->cq_base[cq_head].buf;
		get_64bit_val(cqe, 0, &qword0);
		polarity = (__u8)FIELD_GET(ZXDH_CQ_VALID, qword0);

		if (polarity != temp)
			break;

		get_64bit_val(cqe, 8, &comp_ctx);
		if ((void *)(uintptr_t)comp_ctx == q)
			set_64bit_val(cqe, 8, 0);

		cq_head = (cq_head + 1) % cq->cq_ring.size;
		if (!cq_head)
			temp ^= 1;
	} while (true);
}

__le64 *zxdh_get_srq_wqe(struct zxdh_srq *srq, int wqe_index)
{
	__le64 *wqe;

	wqe = srq->srq_base[wqe_index * srq->srq_wqe_size_multiplier].elem;
	return wqe;
}


void zxdh_free_srq_wqe(struct zxdh_srq *srq, int wqe_index)
{
	struct zxdh_usrq *iwusrq;
	__le64 *wqe;
	__u64 hdr;

	iwusrq = container_of(srq, struct zxdh_usrq, srq);
	/* always called with interrupts disabled. */
	pthread_spin_lock(&iwusrq->lock);
	wqe = zxdh_get_srq_wqe(srq, srq->srq_ring.tail);
	srq->srq_ring.tail = wqe_index;
	hdr = FIELD_PREP(ZXDHQPSRQ_NEXT_WQE_INDEX, wqe_index);

	udma_to_device_barrier(); /* make sure WQE is populated before valid bit is set */
	set_64bit_val(wqe, 0, hdr);

	pthread_spin_unlock(&iwusrq->lock);
	zxdh_dbg(ZXDH_DBG_SRQ, "%s srq->srq_id:%d wqe_index:%d\n", __func__,
		 srq->srq_id, wqe_index);
}
