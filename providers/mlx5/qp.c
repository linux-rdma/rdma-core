/*
 * Copyright (c) 2012 Mellanox Technologies, Inc.  All rights reserved.
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

#include <config.h>

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <util/mmio.h>
#include <util/compiler.h>

#include "mlx5.h"
#include "wqe.h"

#define MLX5_ATOMIC_SIZE 8

static const uint32_t mlx5_ib_opcode[] = {
	[IBV_WR_SEND]			= MLX5_OPCODE_SEND,
	[IBV_WR_SEND_WITH_INV]		= MLX5_OPCODE_SEND_INVAL,
	[IBV_WR_SEND_WITH_IMM]		= MLX5_OPCODE_SEND_IMM,
	[IBV_WR_RDMA_WRITE]		= MLX5_OPCODE_RDMA_WRITE,
	[IBV_WR_RDMA_WRITE_WITH_IMM]	= MLX5_OPCODE_RDMA_WRITE_IMM,
	[IBV_WR_RDMA_READ]		= MLX5_OPCODE_RDMA_READ,
	[IBV_WR_ATOMIC_CMP_AND_SWP]	= MLX5_OPCODE_ATOMIC_CS,
	[IBV_WR_ATOMIC_FETCH_AND_ADD]	= MLX5_OPCODE_ATOMIC_FA,
	[IBV_WR_BIND_MW]		= MLX5_OPCODE_UMR,
	[IBV_WR_LOCAL_INV]		= MLX5_OPCODE_UMR,
	[IBV_WR_TSO]			= MLX5_OPCODE_TSO,
	[IBV_WR_DRIVER1]		= MLX5_OPCODE_UMR,
};

static void *get_recv_wqe(struct mlx5_qp *qp, int n)
{
	return qp->buf.buf + qp->rq.offset + (n << qp->rq.wqe_shift);
}

static void *get_wq_recv_wqe(struct mlx5_rwq *rwq, int n)
{
	return rwq->pbuff  + (n << rwq->rq.wqe_shift);
}

static int copy_to_scat(struct mlx5_wqe_data_seg *scat, void *buf, int *size,
			 int max, struct mlx5_context *ctx)
{
	int copy;
	int i;

	if (unlikely(!(*size)))
		return IBV_WC_SUCCESS;

	for (i = 0; i < max; ++i) {
		copy = min_t(long, *size, be32toh(scat->byte_count));

		/* When NULL MR is used can't copy to target,
		 * expected to be NULL.
		 */
		if (likely(scat->lkey != ctx->dump_fill_mkey_be))
			memcpy((void *)(unsigned long)be64toh(scat->addr),
			       buf, copy);

		*size -= copy;
		if (*size == 0)
			return IBV_WC_SUCCESS;

		buf += copy;
		++scat;
	}
	return IBV_WC_LOC_LEN_ERR;
}

int mlx5_copy_to_recv_wqe(struct mlx5_qp *qp, int idx, void *buf, int size)
{
	struct mlx5_context *ctx = to_mctx(qp->ibv_qp->pd->context);

	struct mlx5_wqe_data_seg *scat;
	int max = 1 << (qp->rq.wqe_shift - 4);

	scat = get_recv_wqe(qp, idx);
	if (unlikely(qp->wq_sig))
		++scat;

	return copy_to_scat(scat, buf, &size, max, ctx);
}

int mlx5_copy_to_send_wqe(struct mlx5_qp *qp, int idx, void *buf, int size)
{
	struct mlx5_context *ctx = to_mctx(qp->ibv_qp->pd->context);
	struct mlx5_wqe_ctrl_seg *ctrl;
	struct mlx5_wqe_data_seg *scat;
	void *p;
	int max;

	idx &= (qp->sq.wqe_cnt - 1);
	ctrl = mlx5_get_send_wqe(qp, idx);
	if (qp->ibv_qp->qp_type != IBV_QPT_RC) {
		fprintf(stderr, "scatter to CQE is supported only for RC QPs\n");
		return IBV_WC_GENERAL_ERR;
	}
	p = ctrl + 1;

	switch (be32toh(ctrl->opmod_idx_opcode) & 0xff) {
	case MLX5_OPCODE_RDMA_READ:
		p = p + sizeof(struct mlx5_wqe_raddr_seg);
		break;

	case MLX5_OPCODE_ATOMIC_CS:
	case MLX5_OPCODE_ATOMIC_FA:
		p = p + sizeof(struct mlx5_wqe_raddr_seg) +
			sizeof(struct mlx5_wqe_atomic_seg);
		break;

	default:
		fprintf(stderr, "scatter to CQE for opcode %d\n",
			be32toh(ctrl->opmod_idx_opcode) & 0xff);
		return IBV_WC_REM_INV_REQ_ERR;
	}

	scat = p;
	max = (be32toh(ctrl->qpn_ds) & 0x3F) - (((void *)scat - (void *)ctrl) >> 4);
	if (unlikely((void *)(scat + max) > qp->sq.qend)) {
		int tmp = ((void *)qp->sq.qend - (void *)scat) >> 4;
		int orig_size = size;

		if (copy_to_scat(scat, buf, &size, tmp, ctx) == IBV_WC_SUCCESS)
			return IBV_WC_SUCCESS;
		max = max - tmp;
		buf += orig_size - size;
		scat = mlx5_get_send_wqe(qp, 0);
	}

	return copy_to_scat(scat, buf, &size, max, ctx);
}

void *mlx5_get_send_wqe(struct mlx5_qp *qp, int n)
{
	return qp->sq_start + (n << MLX5_SEND_WQE_SHIFT);
}

void mlx5_init_rwq_indices(struct mlx5_rwq *rwq)
{
	rwq->rq.head	 = 0;
	rwq->rq.tail	 = 0;
}

void mlx5_init_qp_indices(struct mlx5_qp *qp)
{
	qp->sq.head	 = 0;
	qp->sq.tail	 = 0;
	qp->rq.head	 = 0;
	qp->rq.tail	 = 0;
	qp->sq.cur_post  = 0;
}

static int mlx5_wq_overflow(struct mlx5_wq *wq, int nreq, struct mlx5_cq *cq)
{
	unsigned cur;

	cur = wq->head - wq->tail;
	if (cur + nreq < wq->max_post)
		return 0;

	mlx5_spin_lock(&cq->lock);
	cur = wq->head - wq->tail;
	mlx5_spin_unlock(&cq->lock);

	return cur + nreq >= wq->max_post;
}

static inline void set_raddr_seg(struct mlx5_wqe_raddr_seg *rseg,
				 uint64_t remote_addr, uint32_t rkey)
{
	rseg->raddr    = htobe64(remote_addr);
	rseg->rkey     = htobe32(rkey);
	rseg->reserved = 0;
}

static void set_tm_seg(struct mlx5_wqe_tm_seg *tmseg, int op,
		       struct ibv_ops_wr *wr, int index)
{
	tmseg->flags = 0;
	if (wr->flags & IBV_OPS_SIGNALED)
		tmseg->flags |= MLX5_SRQ_FLAG_TM_CQE_REQ;
	if (wr->flags & IBV_OPS_TM_SYNC) {
		tmseg->flags |= MLX5_SRQ_FLAG_TM_SW_CNT;
		tmseg->sw_cnt = htobe16(wr->tm.unexpected_cnt);
	}
	tmseg->opcode = op << 4;
	if (op == MLX5_TM_OPCODE_NOP)
		return;
	tmseg->index = htobe16(index);
	if (op == MLX5_TM_OPCODE_REMOVE)
		return;
	tmseg->append_tag = htobe64(wr->tm.add.tag);
	tmseg->append_mask = htobe64(wr->tm.add.mask);
}

static inline void _set_atomic_seg(struct mlx5_wqe_atomic_seg *aseg,
				   enum ibv_wr_opcode opcode,
				   uint64_t swap,
				   uint64_t compare_add)
				   ALWAYS_INLINE;
static inline void _set_atomic_seg(struct mlx5_wqe_atomic_seg *aseg,
				   enum ibv_wr_opcode opcode,
				   uint64_t swap,
				   uint64_t compare_add)
{
	if (opcode == IBV_WR_ATOMIC_CMP_AND_SWP) {
		aseg->swap_add = htobe64(swap);
		aseg->compare = htobe64(compare_add);
	} else {
		aseg->swap_add = htobe64(compare_add);
	}
}

static void set_atomic_seg(struct mlx5_wqe_atomic_seg *aseg,
			   enum ibv_wr_opcode opcode,
			   uint64_t swap,
			   uint64_t compare_add)
{
	_set_atomic_seg(aseg, opcode, swap, compare_add);
}

static inline void _set_datagram_seg(struct mlx5_wqe_datagram_seg *dseg,
				     struct mlx5_wqe_av *av,
				     uint32_t remote_qpn,
				     uint32_t remote_qkey)
{
	memcpy(&dseg->av, av, sizeof(dseg->av));
	dseg->av.dqp_dct = htobe32(remote_qpn | MLX5_EXTENDED_UD_AV);
	dseg->av.key.qkey.qkey = htobe32(remote_qkey);
}

static void set_datagram_seg(struct mlx5_wqe_datagram_seg *dseg,
			     struct ibv_send_wr *wr)
{
	_set_datagram_seg(dseg, &to_mah(wr->wr.ud.ah)->av, wr->wr.ud.remote_qpn,
			  wr->wr.ud.remote_qkey);
}

static void set_data_ptr_seg(struct mlx5_wqe_data_seg *dseg, struct ibv_sge *sg,
			     int offset)
{
	dseg->byte_count = htobe32(sg->length - offset);
	dseg->lkey       = htobe32(sg->lkey);
	dseg->addr       = htobe64(sg->addr + offset);
}

static void set_data_ptr_seg_atomic(struct mlx5_wqe_data_seg *dseg,
				    struct ibv_sge *sg)
{
	dseg->byte_count = htobe32(MLX5_ATOMIC_SIZE);
	dseg->lkey       = htobe32(sg->lkey);
	dseg->addr       = htobe64(sg->addr);
}

static void set_data_ptr_seg_end(struct mlx5_wqe_data_seg *dseg)
{
	dseg->byte_count = 0;
	dseg->lkey       = htobe32(MLX5_INVALID_LKEY);
	dseg->addr       = 0;
}

/*
 * Avoid using memcpy() to copy to BlueFlame page, since memcpy()
 * implementations may use move-string-buffer assembler instructions,
 * which do not guarantee order of copying.
 */
static void mlx5_bf_copy(uint64_t *dst, const uint64_t *src, unsigned bytecnt,
			 struct mlx5_qp *qp)
{
	do {
		mmio_memcpy_x64(dst, src, 64);
		bytecnt -= 64;
		dst += 8;
		src += 8;
		if (unlikely(src == qp->sq.qend))
			src = qp->sq_start;
	} while (bytecnt > 0);
}

static __be32 send_ieth(struct ibv_send_wr *wr)
{
	switch (wr->opcode) {
	case IBV_WR_SEND_WITH_IMM:
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		return wr->imm_data;
	case IBV_WR_SEND_WITH_INV:
		return htobe32(wr->invalidate_rkey);
	default:
		return 0;
	}
}

static int set_data_inl_seg(struct mlx5_qp *qp, struct ibv_send_wr *wr,
			    void *wqe, int *sz,
			    struct mlx5_sg_copy_ptr *sg_copy_ptr)
{
	struct mlx5_wqe_inline_seg *seg;
	void *addr;
	int len;
	int i;
	int inl = 0;
	void *qend = qp->sq.qend;
	int copy;
	int offset = sg_copy_ptr->offset;

	seg = wqe;
	wqe += sizeof *seg;
	for (i = sg_copy_ptr->index; i < wr->num_sge; ++i) {
		addr = (void *) (unsigned long)(wr->sg_list[i].addr + offset);
		len  = wr->sg_list[i].length - offset;
		inl += len;
		offset = 0;

		if (unlikely(inl > qp->max_inline_data))
			return ENOMEM;

		if (unlikely(wqe + len > qend)) {
			copy = qend - wqe;
			memcpy(wqe, addr, copy);
			addr += copy;
			len -= copy;
			wqe = mlx5_get_send_wqe(qp, 0);
		}
		memcpy(wqe, addr, len);
		wqe += len;
	}

	if (likely(inl)) {
		seg->byte_count = htobe32(inl | MLX5_INLINE_SEG);
		*sz = align(inl + sizeof seg->byte_count, 16) / 16;
	} else
		*sz = 0;

	return 0;
}

static uint8_t wq_sig(struct mlx5_wqe_ctrl_seg *ctrl)
{
	return calc_sig(ctrl, be32toh(ctrl->qpn_ds));
}

#ifdef MLX5_DEBUG
static void dump_wqe(FILE *fp, int idx, int size_16, struct mlx5_qp *qp)
{
	uint32_t *uninitialized_var(p);
	int i, j;
	int tidx = idx;

	fprintf(fp, "dump wqe at %p\n", mlx5_get_send_wqe(qp, tidx));
	for (i = 0, j = 0; i < size_16 * 4; i += 4, j += 4) {
		if ((i & 0xf) == 0) {
			void *buf = mlx5_get_send_wqe(qp, tidx);
			tidx = (tidx + 1) & (qp->sq.wqe_cnt - 1);
			p = buf;
			j = 0;
		}
		fprintf(fp, "%08x %08x %08x %08x\n", be32toh(p[j]), be32toh(p[j + 1]),
			be32toh(p[j + 2]), be32toh(p[j + 3]));
	}
}
#endif /* MLX5_DEBUG */


void *mlx5_get_atomic_laddr(struct mlx5_qp *qp, uint16_t idx, int *byte_count)
{
	struct mlx5_wqe_data_seg *dpseg;
	void *addr;

	dpseg = mlx5_get_send_wqe(qp, idx) + sizeof(struct mlx5_wqe_ctrl_seg) +
		sizeof(struct mlx5_wqe_raddr_seg) +
		sizeof(struct mlx5_wqe_atomic_seg);
	addr = (void *)(unsigned long)be64toh(dpseg->addr);

	/*
	 * Currently byte count is always 8 bytes. Fix this when
	 * we support variable size of atomics
	 */
	*byte_count = 8;
	return addr;
}

static inline int copy_eth_inline_headers(struct ibv_qp *ibqp,
					  const void *list,
					  size_t nelem,
					  struct mlx5_wqe_eth_seg *eseg,
					  struct mlx5_sg_copy_ptr *sg_copy_ptr,
					  bool is_sge)
					  ALWAYS_INLINE;
static inline int copy_eth_inline_headers(struct ibv_qp *ibqp,
					  const void *list,
					  size_t nelem,
					  struct mlx5_wqe_eth_seg *eseg,
					  struct mlx5_sg_copy_ptr *sg_copy_ptr,
					  bool is_sge)
{
	uint32_t inl_hdr_size = to_mctx(ibqp->context)->eth_min_inline_size;
	size_t inl_hdr_copy_size = 0;
	int j = 0;
	FILE *fp = to_mctx(ibqp->context)->dbg_fp;
	size_t length;
	void *addr;

	if (unlikely(nelem < 1)) {
		mlx5_dbg(fp, MLX5_DBG_QP_SEND,
			 "illegal num_sge: %zu, minimum is 1\n", nelem);
		return EINVAL;
	}

	if (is_sge) {
		addr = (void *)(uintptr_t)((struct ibv_sge *)list)[0].addr;
		length = (size_t)((struct ibv_sge *)list)[0].length;
	} else {
		addr = ((struct ibv_data_buf *)list)[0].addr;
		length = ((struct ibv_data_buf *)list)[0].length;
	}

	if (likely(length >= MLX5_ETH_L2_INLINE_HEADER_SIZE)) {
		inl_hdr_copy_size = inl_hdr_size;
		memcpy(eseg->inline_hdr_start, addr, inl_hdr_copy_size);
	} else {
		uint32_t inl_hdr_size_left = inl_hdr_size;

		for (j = 0; j < nelem && inl_hdr_size_left > 0; ++j) {
			if (is_sge) {
				addr = (void *)(uintptr_t)((struct ibv_sge *)list)[j].addr;
				length = (size_t)((struct ibv_sge *)list)[j].length;
			} else {
				addr = ((struct ibv_data_buf *)list)[j].addr;
				length = ((struct ibv_data_buf *)list)[j].length;
			}

			inl_hdr_copy_size = min_t(size_t, length, inl_hdr_size_left);
			memcpy(eseg->inline_hdr_start +
			       (MLX5_ETH_L2_INLINE_HEADER_SIZE - inl_hdr_size_left),
			       addr, inl_hdr_copy_size);
			inl_hdr_size_left -= inl_hdr_copy_size;
		}
		if (unlikely(inl_hdr_size_left)) {
			mlx5_dbg(fp, MLX5_DBG_QP_SEND, "Ethernet headers < 16 bytes\n");
			return EINVAL;
		}
		if (j)
			--j;
	}

	eseg->inline_hdr_sz = htobe16(inl_hdr_size);

	/* If we copied all the sge into the inline-headers, then we need to
	 * start copying from the next sge into the data-segment.
	 */
	if (unlikely(length == inl_hdr_copy_size)) {
		++j;
		inl_hdr_copy_size = 0;
	}

	sg_copy_ptr->index = j;
	sg_copy_ptr->offset = inl_hdr_copy_size;

	return 0;
}

#define ALIGN(x, log_a) ((((x) + (1 << (log_a)) - 1)) & ~((1 << (log_a)) - 1))

static inline __be16 get_klm_octo(int nentries)
{
	return htobe16(ALIGN(nentries, 3) / 2);
}

static void set_umr_data_seg(struct mlx5_qp *qp, enum ibv_mw_type type,
			     int32_t rkey,
			     const struct ibv_mw_bind_info *bind_info,
			     uint32_t qpn, void **seg, int *size)
{
	union {
		struct mlx5_wqe_umr_klm_seg	klm;
		uint8_t				reserved[64];
	} *data = *seg;

	data->klm.byte_count = htobe32(bind_info->length);
	data->klm.mkey = htobe32(bind_info->mr->lkey);
	data->klm.address = htobe64(bind_info->addr);

	memset(&data->klm + 1, 0, sizeof(data->reserved) -
	       sizeof(data->klm));

	*seg += sizeof(*data);
	*size += (sizeof(*data) / 16);
}

static void set_umr_mkey_seg(struct mlx5_qp *qp, enum ibv_mw_type type,
			     int32_t rkey,
			     const struct ibv_mw_bind_info *bind_info,
			     uint32_t qpn, void **seg, int *size)
{
	struct mlx5_wqe_mkey_context_seg	*mkey = *seg;

	mkey->qpn_mkey = htobe32((rkey & 0xFF) |
				   ((type == IBV_MW_TYPE_1 || !bind_info->length) ?
				    0xFFFFFF00 : qpn << 8));
	if (bind_info->length) {
		/* Local read is set in kernel */
		mkey->access_flags = 0;
		mkey->free = 0;
		if (bind_info->mw_access_flags & IBV_ACCESS_LOCAL_WRITE)
			mkey->access_flags |=
				MLX5_WQE_MKEY_CONTEXT_ACCESS_FLAGS_LOCAL_WRITE;
		if (bind_info->mw_access_flags & IBV_ACCESS_REMOTE_WRITE)
			mkey->access_flags |=
				MLX5_WQE_MKEY_CONTEXT_ACCESS_FLAGS_REMOTE_WRITE;
		if (bind_info->mw_access_flags & IBV_ACCESS_REMOTE_READ)
			mkey->access_flags |=
				MLX5_WQE_MKEY_CONTEXT_ACCESS_FLAGS_REMOTE_READ;
		if (bind_info->mw_access_flags & IBV_ACCESS_REMOTE_ATOMIC)
			mkey->access_flags |=
				MLX5_WQE_MKEY_CONTEXT_ACCESS_FLAGS_ATOMIC;
		if (bind_info->mw_access_flags & IBV_ACCESS_ZERO_BASED)
			mkey->start_addr = 0;
		else
			mkey->start_addr = htobe64(bind_info->addr);
		mkey->len = htobe64(bind_info->length);
	} else {
		mkey->free = MLX5_WQE_MKEY_CONTEXT_FREE;
	}

	*seg += sizeof(struct mlx5_wqe_mkey_context_seg);
	*size += (sizeof(struct mlx5_wqe_mkey_context_seg) / 16);
}

static inline void set_umr_control_seg(struct mlx5_qp *qp, enum ibv_mw_type type,
				       int32_t rkey,
				       const struct ibv_mw_bind_info *bind_info,
				       uint32_t qpn, void **seg, int *size)
{
	struct mlx5_wqe_umr_ctrl_seg		*ctrl = *seg;

	ctrl->flags = MLX5_WQE_UMR_CTRL_FLAG_TRNSLATION_OFFSET |
		MLX5_WQE_UMR_CTRL_FLAG_INLINE;
	ctrl->mkey_mask = htobe64(MLX5_WQE_UMR_CTRL_MKEY_MASK_FREE |
				     MLX5_WQE_UMR_CTRL_MKEY_MASK_MKEY);
	ctrl->translation_offset = 0;
	memset(ctrl->rsvd0, 0, sizeof(ctrl->rsvd0));
	memset(ctrl->rsvd1, 0, sizeof(ctrl->rsvd1));

	if (type == IBV_MW_TYPE_2)
		ctrl->mkey_mask |= htobe64(MLX5_WQE_UMR_CTRL_MKEY_MASK_QPN);

	if (bind_info->length) {
		ctrl->klm_octowords = get_klm_octo(1);
		if (type == IBV_MW_TYPE_2)
			ctrl->flags |=  MLX5_WQE_UMR_CTRL_FLAG_CHECK_FREE;
		ctrl->mkey_mask |= htobe64(MLX5_WQE_UMR_CTRL_MKEY_MASK_LEN	|
					      MLX5_WQE_UMR_CTRL_MKEY_MASK_START_ADDR |
					      MLX5_WQE_UMR_CTRL_MKEY_MASK_ACCESS_LOCAL_WRITE |
					      MLX5_WQE_UMR_CTRL_MKEY_MASK_ACCESS_REMOTE_READ |
					      MLX5_WQE_UMR_CTRL_MKEY_MASK_ACCESS_REMOTE_WRITE |
					      MLX5_WQE_UMR_CTRL_MKEY_MASK_ACCESS_ATOMIC);
	} else {
		ctrl->klm_octowords = get_klm_octo(0);
		if (type == IBV_MW_TYPE_2)
			ctrl->flags |= MLX5_WQE_UMR_CTRL_FLAG_CHECK_QPN;
	}

	*seg += sizeof(struct mlx5_wqe_umr_ctrl_seg);
	*size += sizeof(struct mlx5_wqe_umr_ctrl_seg) / 16;
}

static inline int set_bind_wr(struct mlx5_qp *qp, enum ibv_mw_type type,
			      int32_t rkey,
			      const struct ibv_mw_bind_info *bind_info,
			      uint32_t qpn, void **seg, int *size)
{
	void *qend = qp->sq.qend;

#ifdef MW_DEBUG
	if (bind_info->mw_access_flags &
	    ~(IBV_ACCESS_REMOTE_ATOMIC | IBV_ACCESS_REMOTE_READ |
	     IBV_ACCESS_REMOTE_WRITE))
		return EINVAL;

	if (bind_info->mr &&
	    (bind_info->mr->addr > (void *)bind_info->addr ||
	     bind_info->mr->addr + bind_info->mr->length <
	     (void *)bind_info->addr + bind_info->length ||
	     !(to_mmr(bind_info->mr)->alloc_flags &  IBV_ACCESS_MW_BIND) ||
	     (bind_info->mw_access_flags &
	      (IBV_ACCESS_REMOTE_ATOMIC | IBV_ACCESS_REMOTE_WRITE) &&
	      !(to_mmr(bind_info->mr)->alloc_flags & IBV_ACCESS_LOCAL_WRITE))))
		return EINVAL;

#endif

	/* check that len > 2GB because KLM support only 2GB */
	if (bind_info->length > 1UL << 31)
		return EOPNOTSUPP;

	set_umr_control_seg(qp, type, rkey, bind_info, qpn, seg, size);
	if (unlikely((*seg == qend)))
		*seg = mlx5_get_send_wqe(qp, 0);

	set_umr_mkey_seg(qp, type, rkey, bind_info, qpn, seg, size);
	if (!bind_info->length)
		return 0;

	if (unlikely((seg == qend)))
		*seg = mlx5_get_send_wqe(qp, 0);

	set_umr_data_seg(qp, type, rkey, bind_info, qpn, seg, size);
	return 0;
}

/* Copy tso header to eth segment with considering padding and WQE
 * wrap around in WQ buffer.
 */
static inline int set_tso_eth_seg(void **seg, void *hdr, uint16_t hdr_sz,
				  uint16_t mss,
				  struct mlx5_qp *qp, int *size)
{
	struct mlx5_wqe_eth_seg *eseg = *seg;
	int size_of_inl_hdr_start = sizeof(eseg->inline_hdr_start);
	uint64_t left, left_len, copy_sz;
	FILE *fp = to_mctx(qp->ibv_qp->context)->dbg_fp;

	if (unlikely(hdr_sz < MLX5_ETH_L2_MIN_HEADER_SIZE ||
		     hdr_sz > qp->max_tso_header)) {
		mlx5_dbg(fp, MLX5_DBG_QP_SEND,
			 "TSO header size should be at least %d and at most %d\n",
			 MLX5_ETH_L2_MIN_HEADER_SIZE,
			 qp->max_tso_header);
		return EINVAL;
	}

	left = hdr_sz;
	eseg->mss = htobe16(mss);
	eseg->inline_hdr_sz = htobe16(hdr_sz);

	/* Check if there is space till the end of queue, if yes,
	 * copy all in one shot, otherwise copy till the end of queue,
	 * rollback and then copy the left
	 */
	left_len = qp->sq.qend - (void *)eseg->inline_hdr_start;
	copy_sz = min(left_len, left);

	memcpy(eseg->inline_hdr_start, hdr, copy_sz);

	/* The -1 is because there are already 16 bytes included in
	 * eseg->inline_hdr[16]
	 */
	*seg += align(copy_sz - size_of_inl_hdr_start, 16) - 16;
	*size += align(copy_sz - size_of_inl_hdr_start, 16) / 16 - 1;

	/* The last wqe in the queue */
	if (unlikely(copy_sz < left)) {
		*seg = mlx5_get_send_wqe(qp, 0);
		left -= copy_sz;
		hdr += copy_sz;
		memcpy(*seg, hdr, left);
		*seg += align(left, 16);
		*size += align(left, 16) / 16;
	}

	return 0;
}

static inline int mlx5_post_send_underlay(struct mlx5_qp *qp, struct ibv_send_wr *wr,
					  void **pseg, int *total_size,
					  struct mlx5_sg_copy_ptr *sg_copy_ptr)
{
	struct mlx5_wqe_eth_seg *eseg;
	int inl_hdr_copy_size;
	void *seg = *pseg;
	int size = 0;

	if (unlikely(wr->opcode == IBV_WR_SEND_WITH_IMM))
		return EINVAL;

	memset(seg, 0, sizeof(struct mlx5_wqe_eth_pad));
	size += sizeof(struct mlx5_wqe_eth_pad);
	seg += sizeof(struct mlx5_wqe_eth_pad);
	eseg = seg;
	*((uint64_t *)eseg) = 0;
	eseg->rsvd2 = 0;

	if (wr->send_flags & IBV_SEND_IP_CSUM) {
		if (!(qp->qp_cap_cache & MLX5_CSUM_SUPPORT_UNDERLAY_UD))
			return EINVAL;

		eseg->cs_flags |= MLX5_ETH_WQE_L3_CSUM | MLX5_ETH_WQE_L4_CSUM;
	}

	if (likely(wr->sg_list[0].length >= MLX5_SOURCE_QPN_INLINE_MAX_HEADER_SIZE))
		/* Copying the minimum required data unless inline mode is set */
		inl_hdr_copy_size = (wr->send_flags & IBV_SEND_INLINE) ?
				MLX5_SOURCE_QPN_INLINE_MAX_HEADER_SIZE :
				MLX5_IPOIB_INLINE_MIN_HEADER_SIZE;
	else {
		inl_hdr_copy_size = MLX5_IPOIB_INLINE_MIN_HEADER_SIZE;
		/* We expect at least 4 bytes as part of first entry to hold the IPoIB header */
		if (unlikely(wr->sg_list[0].length < inl_hdr_copy_size))
			return EINVAL;
	}

	memcpy(eseg->inline_hdr_start, (void *)(uintptr_t)wr->sg_list[0].addr,
	       inl_hdr_copy_size);
	eseg->inline_hdr_sz = htobe16(inl_hdr_copy_size);
	size += sizeof(struct mlx5_wqe_eth_seg);
	seg += sizeof(struct mlx5_wqe_eth_seg);

	/* If we copied all the sge into the inline-headers, then we need to
	 * start copying from the next sge into the data-segment.
	 */
	if (unlikely(wr->sg_list[0].length == inl_hdr_copy_size))
		sg_copy_ptr->index++;
	else
		sg_copy_ptr->offset = inl_hdr_copy_size;

	*pseg = seg;
	*total_size += (size / 16);
	return 0;
}

static inline void post_send_db(struct mlx5_qp *qp, struct mlx5_bf *bf,
				int nreq, int inl, int size, void *ctrl)
{
	struct mlx5_context *ctx;

	if (unlikely(!nreq))
		return;

	qp->sq.head += nreq;

	/*
	 * Make sure that descriptors are written before
	 * updating doorbell record and ringing the doorbell
	 */
	udma_to_device_barrier();
	qp->db[MLX5_SND_DBR] = htobe32(qp->sq.cur_post & 0xffff);

	/* Make sure that the doorbell write happens before the memcpy
	 * to WC memory below
	 */
	ctx = to_mctx(qp->ibv_qp->context);
	if (bf->need_lock)
		mmio_wc_spinlock(&bf->lock.lock);
	else
		mmio_wc_start();

	if (!ctx->shut_up_bf && nreq == 1 && bf->uuarn &&
	    (inl || ctx->prefer_bf) && size > 1 &&
	    size <= bf->buf_size / 16)
		mlx5_bf_copy(bf->reg + bf->offset, ctrl,
			     align(size * 16, 64), qp);
	else
		mmio_write64_be(bf->reg + bf->offset, *(__be64 *)ctrl);

	/*
	 * use mmio_flush_writes() to ensure write combining buffers are
	 * flushed out of the running CPU. This must be carried inside
	 * the spinlock. Otherwise, there is a potential race. In the
	 * race, CPU A writes doorbell 1, which is waiting in the WC
	 * buffer. CPU B writes doorbell 2, and it's write is flushed
	 * earlier. Since the mmio_flush_writes is CPU local, this will
	 * result in the HCA seeing doorbell 2, followed by doorbell 1.
	 * Flush before toggling bf_offset to be latency oriented.
	 */
	mmio_flush_writes();
	bf->offset ^= bf->buf_size;
	if (bf->need_lock)
		mlx5_spin_unlock(&bf->lock);
}

static inline int _mlx5_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
				  struct ibv_send_wr **bad_wr)
{
	struct mlx5_qp *qp = to_mqp(ibqp);
	void *seg;
	struct mlx5_wqe_eth_seg *eseg;
	struct mlx5_wqe_ctrl_seg *ctrl = NULL;
	struct mlx5_wqe_data_seg *dpseg;
	struct mlx5_sg_copy_ptr sg_copy_ptr = {.index = 0, .offset = 0};
	int nreq;
	int inl = 0;
	int err = 0;
	int size = 0;
	int i;
	unsigned idx;
	uint8_t opmod = 0;
	struct mlx5_bf *bf = qp->bf;
	void *qend = qp->sq.qend;
	uint32_t mlx5_opcode;
	struct mlx5_wqe_xrc_seg *xrc;
	uint8_t fence;
	uint8_t next_fence;
	uint32_t max_tso = 0;
	FILE *fp = to_mctx(ibqp->context)->dbg_fp; /* The compiler ignores in non-debug mode */

	mlx5_spin_lock(&qp->sq.lock);

	next_fence = qp->fm_cache;

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (unlikely(wr->opcode < 0 ||
		    wr->opcode >= sizeof mlx5_ib_opcode / sizeof mlx5_ib_opcode[0])) {
			mlx5_dbg(fp, MLX5_DBG_QP_SEND, "bad opcode %d\n", wr->opcode);
			err = EINVAL;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(mlx5_wq_overflow(&qp->sq, nreq,
					      to_mcq(qp->ibv_qp->send_cq)))) {
			mlx5_dbg(fp, MLX5_DBG_QP_SEND, "work queue overflow\n");
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->num_sge > qp->sq.max_gs)) {
			mlx5_dbg(fp, MLX5_DBG_QP_SEND, "max gs exceeded %d (max = %d)\n",
				 wr->num_sge, qp->sq.max_gs);
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (wr->send_flags & IBV_SEND_FENCE)
			fence = MLX5_WQE_CTRL_FENCE;
		else
			fence = next_fence;
		next_fence = 0;
		idx = qp->sq.cur_post & (qp->sq.wqe_cnt - 1);
		ctrl = seg = mlx5_get_send_wqe(qp, idx);
		*(uint32_t *)(seg + 8) = 0;
		ctrl->imm = send_ieth(wr);
		ctrl->fm_ce_se = qp->sq_signal_bits | fence |
			(wr->send_flags & IBV_SEND_SIGNALED ?
			 MLX5_WQE_CTRL_CQ_UPDATE : 0) |
			(wr->send_flags & IBV_SEND_SOLICITED ?
			 MLX5_WQE_CTRL_SOLICITED : 0);

		seg += sizeof *ctrl;
		size = sizeof *ctrl / 16;

		switch (ibqp->qp_type) {
		case IBV_QPT_XRC_SEND:
			if (unlikely(wr->opcode != IBV_WR_BIND_MW &&
				     wr->opcode != IBV_WR_LOCAL_INV)) {
				xrc = seg;
				xrc->xrc_srqn = htobe32(wr->qp_type.xrc.remote_srqn);
				seg += sizeof(*xrc);
				size += sizeof(*xrc) / 16;
			}
			/* fall through */
		case IBV_QPT_RC:
			switch (wr->opcode) {
			case IBV_WR_RDMA_READ:
			case IBV_WR_RDMA_WRITE:
			case IBV_WR_RDMA_WRITE_WITH_IMM:
				set_raddr_seg(seg, wr->wr.rdma.remote_addr,
					      wr->wr.rdma.rkey);
				seg  += sizeof(struct mlx5_wqe_raddr_seg);
				size += sizeof(struct mlx5_wqe_raddr_seg) / 16;
				break;

			case IBV_WR_ATOMIC_CMP_AND_SWP:
			case IBV_WR_ATOMIC_FETCH_AND_ADD:
				if (unlikely(!qp->atomics_enabled)) {
					mlx5_dbg(fp, MLX5_DBG_QP_SEND, "atomic operations are not supported\n");
					err = EOPNOTSUPP;
					*bad_wr = wr;
					goto out;
				}
				set_raddr_seg(seg, wr->wr.atomic.remote_addr,
					      wr->wr.atomic.rkey);
				seg  += sizeof(struct mlx5_wqe_raddr_seg);

				set_atomic_seg(seg, wr->opcode,
					       wr->wr.atomic.swap,
					       wr->wr.atomic.compare_add);
				seg  += sizeof(struct mlx5_wqe_atomic_seg);

				size += (sizeof(struct mlx5_wqe_raddr_seg) +
				sizeof(struct mlx5_wqe_atomic_seg)) / 16;
				break;

			case IBV_WR_BIND_MW:
				next_fence = MLX5_WQE_CTRL_INITIATOR_SMALL_FENCE;
				ctrl->imm = htobe32(wr->bind_mw.mw->rkey);
				err = set_bind_wr(qp, wr->bind_mw.mw->type,
						  wr->bind_mw.rkey,
						  &wr->bind_mw.bind_info,
						  ibqp->qp_num, &seg, &size);
				if (err) {
					*bad_wr = wr;
					goto out;
				}

				qp->sq.wr_data[idx] = IBV_WC_BIND_MW;
				break;
			case IBV_WR_LOCAL_INV: {
				struct ibv_mw_bind_info	bind_info = {};

				next_fence = MLX5_WQE_CTRL_INITIATOR_SMALL_FENCE;
				ctrl->imm = htobe32(wr->invalidate_rkey);
				err = set_bind_wr(qp, IBV_MW_TYPE_2, 0,
						  &bind_info, ibqp->qp_num,
						  &seg, &size);
				if (err) {
					*bad_wr = wr;
					goto out;
				}

				qp->sq.wr_data[idx] = IBV_WC_LOCAL_INV;
				break;
			}

			default:
				break;
			}
			break;

		case IBV_QPT_UC:
			switch (wr->opcode) {
			case IBV_WR_RDMA_WRITE:
			case IBV_WR_RDMA_WRITE_WITH_IMM:
				set_raddr_seg(seg, wr->wr.rdma.remote_addr,
					      wr->wr.rdma.rkey);
				seg  += sizeof(struct mlx5_wqe_raddr_seg);
				size += sizeof(struct mlx5_wqe_raddr_seg) / 16;
				break;
			case IBV_WR_BIND_MW:
				next_fence = MLX5_WQE_CTRL_INITIATOR_SMALL_FENCE;
				ctrl->imm = htobe32(wr->bind_mw.mw->rkey);
				err = set_bind_wr(qp, wr->bind_mw.mw->type,
						  wr->bind_mw.rkey,
						  &wr->bind_mw.bind_info,
						  ibqp->qp_num, &seg, &size);
				if (err) {
					*bad_wr = wr;
					goto out;
				}

				qp->sq.wr_data[idx] = IBV_WC_BIND_MW;
				break;
			case IBV_WR_LOCAL_INV: {
				struct ibv_mw_bind_info	bind_info = {};

				next_fence = MLX5_WQE_CTRL_INITIATOR_SMALL_FENCE;
				ctrl->imm = htobe32(wr->invalidate_rkey);
				err = set_bind_wr(qp, IBV_MW_TYPE_2, 0,
						  &bind_info, ibqp->qp_num,
						  &seg, &size);
				if (err) {
					*bad_wr = wr;
					goto out;
				}

				qp->sq.wr_data[idx] = IBV_WC_LOCAL_INV;
				break;
			}

			default:
				break;
			}
			break;

		case IBV_QPT_UD:
			set_datagram_seg(seg, wr);
			seg  += sizeof(struct mlx5_wqe_datagram_seg);
			size += sizeof(struct mlx5_wqe_datagram_seg) / 16;
			if (unlikely((seg == qend)))
				seg = mlx5_get_send_wqe(qp, 0);

			if (unlikely(qp->flags & MLX5_QP_FLAGS_USE_UNDERLAY)) {
				err = mlx5_post_send_underlay(qp, wr, &seg, &size, &sg_copy_ptr);
				if (unlikely(err)) {
					*bad_wr = wr;
					goto out;
				}
			}
			break;

		case IBV_QPT_RAW_PACKET:
			memset(seg, 0, sizeof(struct mlx5_wqe_eth_seg));
			eseg = seg;

			if (wr->send_flags & IBV_SEND_IP_CSUM) {
				if (!(qp->qp_cap_cache & MLX5_CSUM_SUPPORT_RAW_OVER_ETH)) {
					err = EINVAL;
					*bad_wr = wr;
					goto out;
				}

				eseg->cs_flags |= MLX5_ETH_WQE_L3_CSUM | MLX5_ETH_WQE_L4_CSUM;
			}

			if (wr->opcode == IBV_WR_TSO) {
				max_tso = qp->max_tso;
				err = set_tso_eth_seg(&seg, wr->tso.hdr,
						      wr->tso.hdr_sz,
						      wr->tso.mss, qp, &size);
				if (unlikely(err)) {
					*bad_wr = wr;
					goto out;
				}

				/* For TSO WR we always copy at least MLX5_ETH_L2_MIN_HEADER_SIZE
				 * bytes of inline header which is included in struct mlx5_wqe_eth_seg.
				 * If additional bytes are copied, 'seg' and 'size' are adjusted
				 * inside set_tso_eth_seg().
				 */

				seg += sizeof(struct mlx5_wqe_eth_seg);
				size += sizeof(struct mlx5_wqe_eth_seg) / 16;
			} else {
				uint32_t inl_hdr_size =
					to_mctx(ibqp->context)->eth_min_inline_size;

				err = copy_eth_inline_headers(ibqp, wr->sg_list,
							      wr->num_sge, seg,
							      &sg_copy_ptr, 1);
				if (unlikely(err)) {
					*bad_wr = wr;
					mlx5_dbg(fp, MLX5_DBG_QP_SEND,
						 "copy_eth_inline_headers failed, err: %d\n",
						 err);
					goto out;
				}

				/* The eth segment size depends on the device's min inline
				 * header requirement which can be 0 or 18. The basic eth segment
				 * always includes room for first 2 inline header bytes (even if
				 * copy size is 0) so the additional seg size is adjusted accordingly.
				 */

				seg += (offsetof(struct mlx5_wqe_eth_seg, inline_hdr) +
						inl_hdr_size) & ~0xf;
				size += (offsetof(struct mlx5_wqe_eth_seg, inline_hdr) +
						inl_hdr_size) >> 4;
			}
			break;

		default:
			break;
		}

		if (wr->send_flags & IBV_SEND_INLINE && wr->num_sge) {
			int uninitialized_var(sz);

			err = set_data_inl_seg(qp, wr, seg, &sz, &sg_copy_ptr);
			if (unlikely(err)) {
				*bad_wr = wr;
				mlx5_dbg(fp, MLX5_DBG_QP_SEND,
					 "inline layout failed, err %d\n", err);
				goto out;
			}
			inl = 1;
			size += sz;
		} else {
			dpseg = seg;
			for (i = sg_copy_ptr.index; i < wr->num_sge; ++i) {
				if (unlikely(dpseg == qend)) {
					seg = mlx5_get_send_wqe(qp, 0);
					dpseg = seg;
				}
				if (likely(wr->sg_list[i].length)) {
					if (unlikely(wr->opcode ==
						   IBV_WR_ATOMIC_CMP_AND_SWP ||
						   wr->opcode ==
						   IBV_WR_ATOMIC_FETCH_AND_ADD))
						set_data_ptr_seg_atomic(dpseg, wr->sg_list + i);
					else {
						if (unlikely(wr->opcode == IBV_WR_TSO)) {
							if (max_tso < wr->sg_list[i].length) {
								err = EINVAL;
								*bad_wr = wr;
								goto out;
							}
							max_tso -= wr->sg_list[i].length;
						}
						set_data_ptr_seg(dpseg, wr->sg_list + i,
								 sg_copy_ptr.offset);
					}
					sg_copy_ptr.offset = 0;
					++dpseg;
					size += sizeof(struct mlx5_wqe_data_seg) / 16;
				}
			}
		}

		mlx5_opcode = mlx5_ib_opcode[wr->opcode];
		ctrl->opmod_idx_opcode = htobe32(((qp->sq.cur_post & 0xffff) << 8) |
					       mlx5_opcode			 |
					       (opmod << 24));
		ctrl->qpn_ds = htobe32(size | (ibqp->qp_num << 8));

		if (unlikely(qp->wq_sig))
			ctrl->signature = wq_sig(ctrl);

		qp->sq.wrid[idx] = wr->wr_id;
		qp->sq.wqe_head[idx] = qp->sq.head + nreq;
		qp->sq.cur_post += DIV_ROUND_UP(size * 16, MLX5_SEND_WQE_BB);

#ifdef MLX5_DEBUG
		if (mlx5_debug_mask & MLX5_DBG_QP_SEND)
			dump_wqe(to_mctx(ibqp->context)->dbg_fp, idx, size, qp);
#endif
	}

out:
	qp->fm_cache = next_fence;
	post_send_db(qp, bf, nreq, inl, size, ctrl);

	mlx5_spin_unlock(&qp->sq.lock);

	return err;
}

int mlx5_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		   struct ibv_send_wr **bad_wr)
{
#ifdef MW_DEBUG
	if (wr->opcode == IBV_WR_BIND_MW) {
		if (wr->bind_mw.mw->type == IBV_MW_TYPE_1)
			return EINVAL;

		if (!wr->bind_mw.bind_info.mr ||
		    !wr->bind_mw.bind_info.addr ||
		    !wr->bind_mw.bind_info.length)
			return EINVAL;

		if (wr->bind_mw.bind_info.mr->pd != wr->bind_mw.mw->pd)
			return EINVAL;
	}
#endif

	return _mlx5_post_send(ibqp, wr, bad_wr);
}

enum {
	WQE_REQ_SETTERS_UD_XRC_DC = 2,
};

static void mlx5_send_wr_start(struct ibv_qp_ex *ibqp)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);

	mlx5_spin_lock(&mqp->sq.lock);

	mqp->cur_post_rb = mqp->sq.cur_post;
	mqp->fm_cache_rb = mqp->fm_cache;
	mqp->err = 0;
	mqp->nreq = 0;
	mqp->inl_wqe = 0;
}

static int mlx5_send_wr_complete(struct ibv_qp_ex *ibqp)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);
	int err = mqp->err;

	if (unlikely(err)) {
		/* Rolling back */
		mqp->sq.cur_post = mqp->cur_post_rb;
		mqp->fm_cache = mqp->fm_cache_rb;
		goto out;
	}

	post_send_db(mqp, mqp->bf, mqp->nreq, mqp->inl_wqe, mqp->cur_size,
		     mqp->cur_ctrl);

out:
	mlx5_spin_unlock(&mqp->sq.lock);

	return err;
}

static void mlx5_send_wr_abort(struct ibv_qp_ex *ibqp)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);

	/* Rolling back */
	mqp->sq.cur_post = mqp->cur_post_rb;
	mqp->fm_cache = mqp->fm_cache_rb;

	mlx5_spin_unlock(&mqp->sq.lock);
}

static inline void _common_wqe_init(struct ibv_qp_ex *ibqp,
				    enum ibv_wr_opcode ib_op)
				    ALWAYS_INLINE;
static inline void _common_wqe_init(struct ibv_qp_ex *ibqp,
				    enum ibv_wr_opcode ib_op)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);
	struct mlx5_wqe_ctrl_seg *ctrl;
	uint8_t fence;
	uint32_t idx;

	if (unlikely(mlx5_wq_overflow(&mqp->sq, mqp->nreq, to_mcq(ibqp->qp_base.send_cq)))) {
		FILE *fp = to_mctx(((struct ibv_qp *)ibqp)->context)->dbg_fp;

		mlx5_dbg(fp, MLX5_DBG_QP_SEND, "Work queue overflow\n");

		if (!mqp->err)
			mqp->err = ENOMEM;

		return;
	}

	idx = mqp->sq.cur_post & (mqp->sq.wqe_cnt - 1);
	mqp->sq.wrid[idx] = ibqp->wr_id;
	mqp->sq.wqe_head[idx] = mqp->sq.head + mqp->nreq;
	if (ib_op == IBV_WR_BIND_MW)
		mqp->sq.wr_data[idx] = IBV_WC_BIND_MW;
	else if (ib_op == IBV_WR_LOCAL_INV)
		mqp->sq.wr_data[idx] = IBV_WC_LOCAL_INV;
	else if (ib_op == IBV_WR_DRIVER1)
		mqp->sq.wr_data[idx] = IBV_WC_DRIVER1;

	ctrl = mlx5_get_send_wqe(mqp, idx);
	*(uint32_t *)((void *)ctrl + 8) = 0;

	fence = (ibqp->wr_flags & IBV_SEND_FENCE) ? MLX5_WQE_CTRL_FENCE :
						    mqp->fm_cache;
	mqp->fm_cache = 0;

	ctrl->fm_ce_se =
		mqp->sq_signal_bits | fence |
		(ibqp->wr_flags & IBV_SEND_SIGNALED ?
		 MLX5_WQE_CTRL_CQ_UPDATE : 0) |
		(ibqp->wr_flags & IBV_SEND_SOLICITED ?
		 MLX5_WQE_CTRL_SOLICITED : 0);

	ctrl->opmod_idx_opcode = htobe32(((mqp->sq.cur_post & 0xffff) << 8) |
					 mlx5_ib_opcode[ib_op]);

	mqp->cur_ctrl = ctrl;
}

static inline void _common_wqe_finilize(struct mlx5_qp *mqp)
{
	mqp->cur_ctrl->qpn_ds = htobe32(mqp->cur_size | (mqp->ibv_qp->qp_num << 8));

	if (unlikely(mqp->wq_sig))
		mqp->cur_ctrl->signature = wq_sig(mqp->cur_ctrl);

#ifdef MLX5_DEBUG
	if (mlx5_debug_mask & MLX5_DBG_QP_SEND) {
		int idx = mqp->sq.cur_post & (mqp->sq.wqe_cnt - 1);
		FILE *fp = to_mctx(mqp->ibv_qp->context)->dbg_fp;

		dump_wqe(fp, idx, mqp->cur_size, mqp);
	}
#endif

	mqp->sq.cur_post += DIV_ROUND_UP(mqp->cur_size, 4);
}

static inline void _mlx5_send_wr_send(struct ibv_qp_ex *ibqp,
				      enum ibv_wr_opcode ib_op)
				      ALWAYS_INLINE;
static inline void _mlx5_send_wr_send(struct ibv_qp_ex *ibqp,
				      enum ibv_wr_opcode ib_op)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);
	size_t transport_seg_sz = 0;

	_common_wqe_init(ibqp, ib_op);

	if (ibqp->qp_base.qp_type == IBV_QPT_UD ||
	    ibqp->qp_base.qp_type == IBV_QPT_DRIVER)
		transport_seg_sz = sizeof(struct mlx5_wqe_datagram_seg);
	else if (ibqp->qp_base.qp_type == IBV_QPT_XRC_SEND)
		transport_seg_sz = sizeof(struct mlx5_wqe_xrc_seg);

	mqp->cur_data = (void *)mqp->cur_ctrl + sizeof(struct mlx5_wqe_ctrl_seg) +
			transport_seg_sz;
	/* In UD/DC cur_data may overrun the SQ */
	if (unlikely(mqp->cur_data == mqp->sq.qend))
		mqp->cur_data = mlx5_get_send_wqe(mqp, 0);

	mqp->cur_size = (sizeof(struct mlx5_wqe_ctrl_seg) + transport_seg_sz) / 16;
	mqp->nreq++;

	/* Relevant just for WQE construction which requires more than 1 setter */
	mqp->cur_setters_cnt = 0;
}

static void mlx5_send_wr_send_other(struct ibv_qp_ex *ibqp)
{
	_mlx5_send_wr_send(ibqp, IBV_WR_SEND);
}

static void mlx5_send_wr_send_eth(struct ibv_qp_ex *ibqp)
{
	uint32_t inl_hdr_size =
		to_mctx(((struct ibv_qp *)ibqp)->context)->eth_min_inline_size;
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);
	struct mlx5_wqe_eth_seg *eseg;
	size_t eseg_sz;

	_common_wqe_init(ibqp, IBV_WR_SEND);

	eseg = (void *)mqp->cur_ctrl + sizeof(struct mlx5_wqe_ctrl_seg);
	memset(eseg, 0, sizeof(struct mlx5_wqe_eth_seg));
	if (inl_hdr_size)
		mqp->cur_eth = eseg;

	if (ibqp->wr_flags & IBV_SEND_IP_CSUM) {
		if (unlikely(!(mqp->qp_cap_cache &
			       MLX5_CSUM_SUPPORT_RAW_OVER_ETH))) {
			if (!mqp->err)
				mqp->err = EINVAL;

			return;
		}

		eseg->cs_flags |= MLX5_ETH_WQE_L3_CSUM | MLX5_ETH_WQE_L4_CSUM;
	}

	/* The eth segment size depends on the device's min inline
	 * header requirement which can be 0 or 18. The basic eth segment
	 * always includes room for first 2 inline header bytes (even if
	 * copy size is 0) so the additional seg size is adjusted accordingly.
	 */
	eseg_sz = (offsetof(struct mlx5_wqe_eth_seg, inline_hdr) +
		   inl_hdr_size) & ~0xf;
	mqp->cur_data = (void *)eseg + eseg_sz;
	mqp->cur_size = (sizeof(struct mlx5_wqe_ctrl_seg) + eseg_sz) >> 4;
	mqp->nreq++;
}

static void mlx5_send_wr_send_imm(struct ibv_qp_ex *ibqp, __be32 imm_data)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);

	_mlx5_send_wr_send(ibqp, IBV_WR_SEND_WITH_IMM);

	mqp->cur_ctrl->imm = imm_data;
}

static void mlx5_send_wr_send_inv(struct ibv_qp_ex *ibqp,
				  uint32_t invalidate_rkey)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);

	_mlx5_send_wr_send(ibqp, IBV_WR_SEND_WITH_INV);

	mqp->cur_ctrl->imm = htobe32(invalidate_rkey);
}

static void mlx5_send_wr_send_tso(struct ibv_qp_ex *ibqp, void *hdr,
				  uint16_t hdr_sz, uint16_t mss)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);
	struct mlx5_wqe_eth_seg *eseg;
	int size = 0;
	int err;

	_common_wqe_init(ibqp, IBV_WR_TSO);

	eseg = (void *)mqp->cur_ctrl + sizeof(struct mlx5_wqe_ctrl_seg);
	memset(eseg, 0, sizeof(struct mlx5_wqe_eth_seg));

	if (ibqp->wr_flags & IBV_SEND_IP_CSUM) {
		if (unlikely(!(mqp->qp_cap_cache & MLX5_CSUM_SUPPORT_RAW_OVER_ETH))) {
			if (!mqp->err)
				mqp->err = EINVAL;

			return;
		}

		eseg->cs_flags |= MLX5_ETH_WQE_L3_CSUM | MLX5_ETH_WQE_L4_CSUM;
	}

	err = set_tso_eth_seg((void *)&eseg, hdr, hdr_sz, mss, mqp, &size);
	if (unlikely(err)) {
		if (!mqp->err)
			mqp->err = err;

		return;
	}

	/* eseg and cur_size was updated with hdr size inside set_tso_eth_seg */
	mqp->cur_data = (void *)eseg + sizeof(struct mlx5_wqe_eth_seg);
	mqp->cur_size = size +
			((sizeof(struct mlx5_wqe_ctrl_seg) +
			  sizeof(struct mlx5_wqe_eth_seg)) >> 4);

	mqp->cur_eth = NULL;
	mqp->nreq++;
}

static inline void _mlx5_send_wr_rdma(struct ibv_qp_ex *ibqp,
				      uint32_t rkey,
				      uint64_t remote_addr,
				      enum ibv_wr_opcode ib_op)
				      ALWAYS_INLINE;
static inline void _mlx5_send_wr_rdma(struct ibv_qp_ex *ibqp,
				      uint32_t rkey,
				      uint64_t remote_addr,
				      enum ibv_wr_opcode ib_op)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);
	size_t transport_seg_sz = 0;
	void *raddr_seg;

	_common_wqe_init(ibqp, ib_op);

	if (ibqp->qp_base.qp_type == IBV_QPT_DRIVER)
		transport_seg_sz = sizeof(struct mlx5_wqe_datagram_seg);
	else if (ibqp->qp_base.qp_type == IBV_QPT_XRC_SEND)
		transport_seg_sz = sizeof(struct mlx5_wqe_xrc_seg);

	raddr_seg = (void *)mqp->cur_ctrl + sizeof(struct mlx5_wqe_ctrl_seg) +
		    transport_seg_sz;
	/* In DC raddr_seg may overrun the SQ */
	if (unlikely(raddr_seg == mqp->sq.qend))
		raddr_seg = mlx5_get_send_wqe(mqp, 0);

	set_raddr_seg(raddr_seg, remote_addr, rkey);

	mqp->cur_data = raddr_seg + sizeof(struct mlx5_wqe_raddr_seg);
	mqp->cur_size = (sizeof(struct mlx5_wqe_ctrl_seg) + transport_seg_sz +
			 sizeof(struct mlx5_wqe_raddr_seg)) / 16;
	mqp->nreq++;

	/* Relevant just for WQE construction which requires more than 1 setter */
	mqp->cur_setters_cnt = 0;
}

static void mlx5_send_wr_rdma_write(struct ibv_qp_ex *ibqp, uint32_t rkey,
				    uint64_t remote_addr)
{
	_mlx5_send_wr_rdma(ibqp, rkey, remote_addr, IBV_WR_RDMA_WRITE);
}

static void mlx5_send_wr_rdma_write_imm(struct ibv_qp_ex *ibqp, uint32_t rkey,
					uint64_t remote_addr, __be32 imm_data)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);

	_mlx5_send_wr_rdma(ibqp, rkey, remote_addr, IBV_WR_RDMA_WRITE_WITH_IMM);

	mqp->cur_ctrl->imm = imm_data;
}

static void mlx5_send_wr_rdma_read(struct ibv_qp_ex *ibqp, uint32_t rkey,
				   uint64_t remote_addr)
{
	_mlx5_send_wr_rdma(ibqp, rkey, remote_addr, IBV_WR_RDMA_READ);
}

static inline void _mlx5_send_wr_atomic(struct ibv_qp_ex *ibqp, uint32_t rkey,
					uint64_t remote_addr,
					uint64_t compare_add,
					uint64_t swap, enum ibv_wr_opcode ib_op)
					ALWAYS_INLINE;
static inline void _mlx5_send_wr_atomic(struct ibv_qp_ex *ibqp, uint32_t rkey,
					uint64_t remote_addr,
					uint64_t compare_add,
					uint64_t swap, enum ibv_wr_opcode ib_op)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);
	size_t transport_seg_sz = 0;
	void *raddr_seg;

	_common_wqe_init(ibqp, ib_op);

	if (ibqp->qp_base.qp_type == IBV_QPT_DRIVER)
		transport_seg_sz = sizeof(struct mlx5_wqe_datagram_seg);
	else if (ibqp->qp_base.qp_type == IBV_QPT_XRC_SEND)
		transport_seg_sz = sizeof(struct mlx5_wqe_xrc_seg);

	raddr_seg = (void *)mqp->cur_ctrl + sizeof(struct mlx5_wqe_ctrl_seg) +
		    transport_seg_sz;
	/* In DC raddr_seg may overrun the SQ */
	if (unlikely(raddr_seg == mqp->sq.qend))
		raddr_seg = mlx5_get_send_wqe(mqp, 0);

	set_raddr_seg(raddr_seg, remote_addr, rkey);

	_set_atomic_seg((struct mlx5_wqe_atomic_seg *)(raddr_seg + sizeof(struct mlx5_wqe_raddr_seg)),
			ib_op, swap, compare_add);

	mqp->cur_data = raddr_seg + sizeof(struct mlx5_wqe_raddr_seg) +
			sizeof(struct mlx5_wqe_atomic_seg);
	/* In XRC, cur_data may overrun the SQ */
	if (unlikely(mqp->cur_data == mqp->sq.qend))
		mqp->cur_data = mlx5_get_send_wqe(mqp, 0);

	mqp->cur_size = (sizeof(struct mlx5_wqe_ctrl_seg) + transport_seg_sz +
			 sizeof(struct mlx5_wqe_raddr_seg) +
			 sizeof(struct mlx5_wqe_atomic_seg)) / 16;
	mqp->nreq++;

	/* Relevant just for WQE construction which requires more than 1 setter */
	mqp->cur_setters_cnt = 0;
}

static void mlx5_send_wr_atomic_cmp_swp(struct ibv_qp_ex *ibqp, uint32_t rkey,
					uint64_t remote_addr, uint64_t compare,
					uint64_t swap)
{
	_mlx5_send_wr_atomic(ibqp, rkey, remote_addr, compare, swap,
			     IBV_WR_ATOMIC_CMP_AND_SWP);
}

static void mlx5_send_wr_atomic_fetch_add(struct ibv_qp_ex *ibqp, uint32_t rkey,
					  uint64_t remote_addr, uint64_t add)
{
	_mlx5_send_wr_atomic(ibqp, rkey, remote_addr, add, 0,
			     IBV_WR_ATOMIC_FETCH_AND_ADD);
}

static inline void _build_umr_wqe(struct ibv_qp_ex *ibqp, uint32_t orig_rkey,
				  uint32_t new_rkey,
				  const struct ibv_mw_bind_info *bind_info,
				  enum ibv_wr_opcode ib_op)
				  ALWAYS_INLINE;
static inline void _build_umr_wqe(struct ibv_qp_ex *ibqp, uint32_t orig_rkey,
				  uint32_t new_rkey,
				  const struct ibv_mw_bind_info *bind_info,
				  enum ibv_wr_opcode ib_op)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);
	void *umr_seg;
	int err = 0;
	int size = sizeof(struct mlx5_wqe_ctrl_seg) / 16;

	_common_wqe_init(ibqp, ib_op);

	mqp->cur_ctrl->imm = htobe32(orig_rkey);

	umr_seg = (void *)mqp->cur_ctrl + sizeof(struct mlx5_wqe_ctrl_seg);
	err = set_bind_wr(mqp, IBV_MW_TYPE_2, new_rkey, bind_info,
			  ((struct ibv_qp *)ibqp)->qp_num, &umr_seg, &size);
	if (unlikely(err)) {
		if (!mqp->err)
			mqp->err = err;

		return;
	}

	mqp->cur_size = size;
	mqp->fm_cache = MLX5_WQE_CTRL_INITIATOR_SMALL_FENCE;
	mqp->nreq++;
	_common_wqe_finilize(mqp);
}

static void mlx5_send_wr_bind_mw(struct ibv_qp_ex *ibqp, struct ibv_mw *mw,
				 uint32_t rkey,
				 const struct ibv_mw_bind_info *bind_info)
{
	_build_umr_wqe(ibqp, mw->rkey, rkey, bind_info, IBV_WR_BIND_MW);
}

static void mlx5_send_wr_local_inv(struct ibv_qp_ex *ibqp,
				   uint32_t invalidate_rkey)
{
	const struct ibv_mw_bind_info bind_info = {};

	_build_umr_wqe(ibqp, invalidate_rkey, 0, &bind_info, IBV_WR_LOCAL_INV);
}

static inline void
_mlx5_send_wr_set_sge(struct mlx5_qp *mqp, uint32_t lkey, uint64_t addr,
		      uint32_t length)
{
	struct mlx5_wqe_data_seg *dseg;

	if (unlikely(!length))
		return;

	dseg = mqp->cur_data;
	dseg->byte_count = htobe32(length);
	dseg->lkey = htobe32(lkey);
	dseg->addr = htobe64(addr);
	mqp->cur_size += sizeof(*dseg) / 16;
}

static void
mlx5_send_wr_set_sge_rc_uc(struct ibv_qp_ex *ibqp, uint32_t lkey,
			   uint64_t addr, uint32_t length)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);

	_mlx5_send_wr_set_sge(mqp, lkey, addr, length);
	_common_wqe_finilize(mqp);
}

static void
mlx5_send_wr_set_sge_ud_xrc_dc(struct ibv_qp_ex *ibqp, uint32_t lkey,
			       uint64_t addr, uint32_t length)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);

	_mlx5_send_wr_set_sge(mqp, lkey, addr, length);

	if (mqp->cur_setters_cnt == WQE_REQ_SETTERS_UD_XRC_DC - 1)
		_common_wqe_finilize(mqp);
	else
		mqp->cur_setters_cnt++;
}

static void
mlx5_send_wr_set_sge_eth(struct ibv_qp_ex *ibqp, uint32_t lkey,
			 uint64_t addr, uint32_t length)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);
	struct mlx5_wqe_eth_seg *eseg = mqp->cur_eth;
	int err;

	if (eseg) { /* Inline-headers was set */
		struct mlx5_sg_copy_ptr sg_copy_ptr = {.index = 0, .offset = 0};
		struct ibv_sge sge = {.addr = addr, .length = length};

		err = copy_eth_inline_headers((struct ibv_qp *)ibqp, &sge, 1,
					      eseg, &sg_copy_ptr, 1);
		if (unlikely(err)) {
			if (!mqp->err)
				mqp->err = err;

			return;
		}

		addr += sg_copy_ptr.offset;
		length -= sg_copy_ptr.offset;
	}

	_mlx5_send_wr_set_sge(mqp, lkey, addr, length);

	_common_wqe_finilize(mqp);
}

static inline void
_mlx5_send_wr_set_sge_list(struct mlx5_qp *mqp, size_t num_sge,
			   const struct ibv_sge *sg_list)
{
	struct mlx5_wqe_data_seg *dseg = mqp->cur_data;
	size_t i;

	if (unlikely(num_sge > mqp->sq.max_gs)) {
		FILE *fp = to_mctx(mqp->ibv_qp->context)->dbg_fp;

		mlx5_dbg(fp, MLX5_DBG_QP_SEND, "Num SGEs %zu exceeds the maximum (%d)\n",
			 num_sge, mqp->sq.max_gs);

		if (!mqp->err)
			mqp->err = ENOMEM;

		return;
	}

	for (i = 0; i < num_sge; i++) {
		if (unlikely(dseg == mqp->sq.qend))
			dseg = mlx5_get_send_wqe(mqp, 0);

		if (unlikely(!sg_list[i].length))
			continue;

		dseg->byte_count = htobe32(sg_list[i].length);
		dseg->lkey = htobe32(sg_list[i].lkey);
		dseg->addr = htobe64(sg_list[i].addr);
		dseg++;
		mqp->cur_size += (sizeof(*dseg) / 16);
	}
}

static void
mlx5_send_wr_set_sge_list_rc_uc(struct ibv_qp_ex *ibqp, size_t num_sge,
				const struct ibv_sge *sg_list)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);

	_mlx5_send_wr_set_sge_list(mqp, num_sge, sg_list);
	_common_wqe_finilize(mqp);
}

static void
mlx5_send_wr_set_sge_list_ud_xrc_dc(struct ibv_qp_ex *ibqp, size_t num_sge,
				    const struct ibv_sge *sg_list)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);

	_mlx5_send_wr_set_sge_list(mqp, num_sge, sg_list);

	if (mqp->cur_setters_cnt == WQE_REQ_SETTERS_UD_XRC_DC - 1)
		_common_wqe_finilize(mqp);
	else
		mqp->cur_setters_cnt++;
}

static void
mlx5_send_wr_set_sge_list_eth(struct ibv_qp_ex *ibqp, size_t num_sge,
			      const struct ibv_sge *sg_list)
{
	struct mlx5_sg_copy_ptr sg_copy_ptr = {.index = 0, .offset = 0};
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);
	struct mlx5_wqe_data_seg *dseg = mqp->cur_data;
	struct mlx5_wqe_eth_seg *eseg = mqp->cur_eth;
	size_t i;

	if (unlikely(num_sge > mqp->sq.max_gs)) {
		FILE *fp = to_mctx(mqp->ibv_qp->context)->dbg_fp;

		mlx5_dbg(fp, MLX5_DBG_QP_SEND, "Num SGEs %zu exceeds the maximum (%d)\n",
			 num_sge, mqp->sq.max_gs);

		if (!mqp->err)
			mqp->err = ENOMEM;

		return;
	}

	if (eseg) { /* Inline-headers was set */
		int err;

		err = copy_eth_inline_headers((struct ibv_qp *)ibqp, sg_list,
					      num_sge, eseg, &sg_copy_ptr, 1);
		if (unlikely(err)) {
			if (!mqp->err)
				mqp->err = err;

			return;
		}
	}

	for (i = sg_copy_ptr.index; i < num_sge; i++) {
		uint32_t length = sg_list[i].length - sg_copy_ptr.offset;

		if (unlikely(!length))
			continue;

		if (unlikely(dseg == mqp->sq.qend))
			dseg = mlx5_get_send_wqe(mqp, 0);

		dseg->addr = htobe64(sg_list[i].addr + sg_copy_ptr.offset);
		dseg->byte_count = htobe32(length);
		dseg->lkey = htobe32(sg_list[i].lkey);
		dseg++;
		mqp->cur_size += (sizeof(*dseg) / 16);
		sg_copy_ptr.offset = 0;
	}

	_common_wqe_finilize(mqp);
}

static inline void memcpy_to_wqe(struct mlx5_qp *mqp, void *dest, void *src,
				 size_t n)
{
	if (unlikely(dest + n > mqp->sq.qend)) {
		size_t copy = mqp->sq.qend - dest;

		memcpy(dest, src, copy);
		src += copy;
		n -= copy;
		dest = mlx5_get_send_wqe(mqp, 0);
	}
	memcpy(dest, src, n);
}

static inline void memcpy_to_wqe_and_update(struct mlx5_qp *mqp, void **dest,
					    void *src, size_t n)
{
	if (unlikely(*dest + n > mqp->sq.qend)) {
		size_t copy = mqp->sq.qend - *dest;

		memcpy(*dest, src, copy);
		src += copy;
		n -= copy;
		*dest = mlx5_get_send_wqe(mqp, 0);
	}
	memcpy(*dest, src, n);

	*dest += n;
}

static inline void
_mlx5_send_wr_set_inline_data(struct mlx5_qp *mqp, void *addr, size_t length)
{
	struct mlx5_wqe_inline_seg *dseg = mqp->cur_data;

	if (unlikely(length > mqp->max_inline_data)) {
		FILE *fp = to_mctx(mqp->ibv_qp->context)->dbg_fp;

		mlx5_dbg(fp, MLX5_DBG_QP_SEND,
			 "Inline data %zu exceeds the maximum (%d)\n",
			 length, mqp->max_inline_data);

		if (!mqp->err)
			mqp->err = ENOMEM;

		return;
	}

	mqp->inl_wqe = 1; /* Encourage a BlueFlame usage */

	if (unlikely(!length))
		return;

	memcpy_to_wqe(mqp, (void *)dseg + sizeof(*dseg), addr, length);
	dseg->byte_count = htobe32(length | MLX5_INLINE_SEG);
	mqp->cur_size += DIV_ROUND_UP(length + sizeof(*dseg), 16);
}

static void
mlx5_send_wr_set_inline_data_rc_uc(struct ibv_qp_ex *ibqp, void *addr,
				   size_t length)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);

	_mlx5_send_wr_set_inline_data(mqp, addr, length);
	_common_wqe_finilize(mqp);
}

static void
mlx5_send_wr_set_inline_data_ud_xrc_dc(struct ibv_qp_ex *ibqp, void *addr,
				       size_t length)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);

	_mlx5_send_wr_set_inline_data(mqp, addr, length);

	if (mqp->cur_setters_cnt == WQE_REQ_SETTERS_UD_XRC_DC - 1)
		_common_wqe_finilize(mqp);
	else
		mqp->cur_setters_cnt++;
}

static void
mlx5_send_wr_set_inline_data_eth(struct ibv_qp_ex *ibqp, void *addr,
				 size_t length)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);
	struct mlx5_wqe_eth_seg *eseg = mqp->cur_eth;

	if (eseg) { /* Inline-headers was set */
		struct mlx5_sg_copy_ptr sg_copy_ptr = {.index = 0, .offset = 0};
		struct ibv_data_buf buf = {.addr = addr, .length = length};
		int err;

		err = copy_eth_inline_headers((struct ibv_qp *)ibqp, &buf, 1,
					      eseg, &sg_copy_ptr, 0);
		if (unlikely(err)) {
			if (!mqp->err)
				mqp->err = err;

			return;
		}

		addr += sg_copy_ptr.offset;
		length -= sg_copy_ptr.offset;
	}

	_mlx5_send_wr_set_inline_data(mqp, addr, length);
	_common_wqe_finilize(mqp);
}

static inline void
_mlx5_send_wr_set_inline_data_list(struct mlx5_qp *mqp,
				   size_t num_buf,
				   const struct ibv_data_buf *buf_list)
{
	struct mlx5_wqe_inline_seg *dseg = mqp->cur_data;
	void *wqe = (void *)dseg + sizeof(*dseg);
	size_t inl_size = 0;
	int i;

	for (i = 0; i < num_buf; i++) {
		size_t length = buf_list[i].length;

		inl_size += length;

		if (unlikely(inl_size > mqp->max_inline_data)) {
			FILE *fp = to_mctx(mqp->ibv_qp->context)->dbg_fp;

			mlx5_dbg(fp, MLX5_DBG_QP_SEND,
				 "Inline data %zu exceeds the maximum (%d)\n",
				 inl_size, mqp->max_inline_data);

			if (!mqp->err)
				mqp->err = ENOMEM;

			return;
		}

		memcpy_to_wqe_and_update(mqp, &wqe, buf_list[i].addr, length);
	}

	mqp->inl_wqe = 1; /* Encourage a BlueFlame usage */

	if (unlikely(!inl_size))
		return;

	dseg->byte_count = htobe32(inl_size | MLX5_INLINE_SEG);
	mqp->cur_size += DIV_ROUND_UP(inl_size + sizeof(*dseg), 16);
}

static void
mlx5_send_wr_set_inline_data_list_rc_uc(struct ibv_qp_ex *ibqp,
					size_t num_buf,
					const struct ibv_data_buf *buf_list)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);

	_mlx5_send_wr_set_inline_data_list(mqp, num_buf, buf_list);
	_common_wqe_finilize(mqp);
}

static void
mlx5_send_wr_set_inline_data_list_ud_xrc_dc(struct ibv_qp_ex *ibqp,
					    size_t num_buf,
					    const struct ibv_data_buf *buf_list)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);

	_mlx5_send_wr_set_inline_data_list(mqp, num_buf, buf_list);

	if (mqp->cur_setters_cnt == WQE_REQ_SETTERS_UD_XRC_DC - 1)
		_common_wqe_finilize(mqp);
	else
		mqp->cur_setters_cnt++;
}

static void
mlx5_send_wr_set_inline_data_list_eth(struct ibv_qp_ex *ibqp,
				      size_t num_buf,
				      const struct ibv_data_buf *buf_list)
{
	struct mlx5_sg_copy_ptr sg_copy_ptr = {.index = 0, .offset = 0};
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);
	struct mlx5_wqe_inline_seg *dseg = mqp->cur_data;
	struct mlx5_wqe_eth_seg *eseg = mqp->cur_eth;
	void *wqe = (void *)dseg + sizeof(*dseg);
	size_t inl_size = 0;
	size_t i;

	if (eseg) { /* Inline-headers was set */
		int err;

		err = copy_eth_inline_headers((struct ibv_qp *)ibqp, buf_list,
					      num_buf, eseg, &sg_copy_ptr, 0);
		if (unlikely(err)) {
			if (!mqp->err)
				mqp->err = err;

			return;
		}
	}

	for (i = sg_copy_ptr.index; i < num_buf; i++) {
		size_t length = buf_list[i].length - sg_copy_ptr.offset;

		inl_size += length;

		if (unlikely(inl_size > mqp->max_inline_data)) {
			FILE *fp = to_mctx(mqp->ibv_qp->context)->dbg_fp;

			mlx5_dbg(fp, MLX5_DBG_QP_SEND,
				 "Inline data %zu exceeds the maximum (%d)\n",
				 inl_size, mqp->max_inline_data);

			if (!mqp->err)
				mqp->err = EINVAL;

			return;
		}

		memcpy_to_wqe_and_update(mqp, &wqe,
					 buf_list[i].addr + sg_copy_ptr.offset,
					 length);

		sg_copy_ptr.offset = 0;
	}

	if (likely(inl_size)) {
		dseg->byte_count = htobe32(inl_size | MLX5_INLINE_SEG);
		mqp->cur_size += DIV_ROUND_UP(inl_size + sizeof(*dseg), 16);
	}

	mqp->inl_wqe = 1; /* Encourage a BlueFlame usage */
	_common_wqe_finilize(mqp);
}

static void
mlx5_send_wr_set_ud_addr(struct ibv_qp_ex *ibqp, struct ibv_ah *ah,
			 uint32_t remote_qpn, uint32_t remote_qkey)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);
	struct mlx5_wqe_datagram_seg *dseg =
		(void *)mqp->cur_ctrl +	sizeof(struct mlx5_wqe_ctrl_seg);
	struct mlx5_ah *mah = to_mah(ah);

	_set_datagram_seg(dseg, &mah->av, remote_qpn, remote_qkey);

	if (mqp->cur_setters_cnt == WQE_REQ_SETTERS_UD_XRC_DC - 1)
		_common_wqe_finilize(mqp);
	else
		mqp->cur_setters_cnt++;
}

static void
mlx5_send_wr_set_xrc_srqn(struct ibv_qp_ex *ibqp, uint32_t remote_srqn)
{
	struct mlx5_qp *mqp = to_mqp((struct ibv_qp *)ibqp);
	struct mlx5_wqe_xrc_seg *xrc_seg =
		(void *)mqp->cur_ctrl + sizeof(struct mlx5_wqe_ctrl_seg);

	xrc_seg->xrc_srqn = htobe32(remote_srqn);

	if (mqp->cur_setters_cnt == WQE_REQ_SETTERS_UD_XRC_DC - 1)
		_common_wqe_finilize(mqp);
	else
		mqp->cur_setters_cnt++;
}

static uint8_t get_umr_mr_flags(uint32_t acc)
{
	return ((acc & IBV_ACCESS_REMOTE_ATOMIC ?
		MLX5_WQE_MKEY_CONTEXT_ACCESS_FLAGS_ATOMIC : 0) |
		(acc & IBV_ACCESS_REMOTE_WRITE ?
		MLX5_WQE_MKEY_CONTEXT_ACCESS_FLAGS_REMOTE_WRITE : 0) |
		(acc & IBV_ACCESS_REMOTE_READ ?
		MLX5_WQE_MKEY_CONTEXT_ACCESS_FLAGS_REMOTE_READ  : 0) |
		(acc & IBV_ACCESS_LOCAL_WRITE ?
		MLX5_WQE_MKEY_CONTEXT_ACCESS_FLAGS_LOCAL_WRITE  : 0));
}

static int umr_sg_list_create(struct mlx5_qp *qp,
			      uint16_t num_sges,
			      struct ibv_sge *sge,
			      void *seg,
			      void *qend, int *size, int *xlat_size,
			      uint64_t *reglen)
{
	struct mlx5_wqe_data_seg *dseg;
	int byte_count = 0;
	int i;
	size_t tmp;

	dseg = seg;

	for (i = 0; i < num_sges; i++, dseg++) {
		if (unlikely(dseg == qend))
			dseg = mlx5_get_send_wqe(qp, 0);

		dseg->addr =  htobe64(sge[i].addr);
		dseg->lkey = htobe32(sge[i].lkey);
		dseg->byte_count = htobe32(sge[i].length);
		byte_count += sge[i].length;
	}

	tmp = align(num_sges, 4) - num_sges;
	memset(dseg, 0, tmp * sizeof(*dseg));

	*size = align(num_sges * sizeof(*dseg), 64);
	*reglen = byte_count;
	*xlat_size = num_sges * sizeof(*dseg);

	return 0;
}

/* The strided block format is as the following:
 * | repeat_block | entry_block | entry_block |...| entry_block |
 * While the repeat entry contains details on the list of the block_entries.
 */
static void umr_strided_seg_create(struct mlx5_qp *qp,
				   uint32_t repeat_count,
				   uint16_t num_interleaved,
				   struct mlx5dv_mr_interleaved *data,
				   void *seg,
				   void *qend, int *wqe_size, int *xlat_size,
				   uint64_t *reglen)
{
	struct mlx5_wqe_umr_repeat_block_seg *rb = seg;
	struct mlx5_wqe_umr_repeat_ent_seg *eb;
	int byte_count = 0;
	int tmp;
	int i;

	rb->op = htobe32(0x400);
	rb->reserved = 0;
	rb->num_ent = htobe16(num_interleaved);
	rb->repeat_count = htobe32(repeat_count);
	eb = rb->entries;

	/*
	 * ------------------------------------------------------------
	 * | repeat_block | entry_block | entry_block |...| entry_block
	 * ------------------------------------------------------------
	 */
	for (i = 0; i < num_interleaved; i++, eb++) {
		if (unlikely(eb == qend))
			eb = mlx5_get_send_wqe(qp, 0);

		byte_count += data[i].bytes_count;
		eb->va = htobe64(data[i].addr);
		eb->byte_count = htobe16(data[i].bytes_count);
		eb->stride = htobe16(data[i].bytes_count + data[i].bytes_skip);
		eb->memkey = htobe32(data[i].lkey);
	}

	rb->byte_count = htobe32(byte_count);
	*reglen = byte_count * repeat_count;

	tmp = align(num_interleaved + 1, 4) - num_interleaved - 1;
	memset(eb, 0, tmp * sizeof(*eb));

	*wqe_size = align(sizeof(*rb) + sizeof(*eb) * num_interleaved, 64);
	*xlat_size = (num_interleaved + 1) * sizeof(*eb);
}

static void mlx5_send_wr_mr(struct mlx5dv_qp_ex *dv_qp,
			    struct mlx5dv_mkey *dv_mkey,
			    uint32_t access_flags,
			    uint32_t repeat_count,
			    uint16_t num_entries,
			    struct mlx5dv_mr_interleaved *data,
			    struct ibv_sge *sge)
{
	struct mlx5_qp *mqp = mqp_from_mlx5dv_qp_ex(dv_qp);
	struct ibv_qp_ex *ibqp = &mqp->verbs_qp.qp_ex;
	struct mlx5_wqe_umr_ctrl_seg *umr_ctrl_seg;
	struct mlx5_wqe_mkey_context_seg *mk;
	struct mlx5_mkey *mkey = container_of(dv_mkey, struct mlx5_mkey,
					      dv_mkey);
	int xlat_size;
	int size;
	uint64_t reglen = 0;
	void *qend = mqp->sq.qend;
	void *seg;
	uint16_t max_entries;

	if (unlikely(!(ibqp->wr_flags & IBV_SEND_INLINE))) {
		mqp->err = EOPNOTSUPP;
		return;
	}

	max_entries = data ?
		min_t(size_t,
		      (mqp->max_inline_data + sizeof(struct mlx5_wqe_inl_data_seg)) /
				sizeof(struct mlx5_wqe_umr_repeat_ent_seg) - 1,
		       mkey->num_desc) :
		min_t(size_t,
		      (mqp->max_inline_data + sizeof(struct mlx5_wqe_inl_data_seg)) /
				sizeof(struct mlx5_wqe_data_seg),
		       mkey->num_desc);

	if (unlikely(num_entries > max_entries)) {
		mqp->err = ENOMEM;
		return;
	}

	if (unlikely(!check_comp_mask(access_flags,
				      IBV_ACCESS_LOCAL_WRITE |
				      IBV_ACCESS_REMOTE_WRITE |
				      IBV_ACCESS_REMOTE_READ |
				      IBV_ACCESS_REMOTE_ATOMIC))) {
		mqp->err = EINVAL;
		return;
	}

	_common_wqe_init(ibqp, IBV_WR_DRIVER1);
	mqp->cur_size = sizeof(struct mlx5_wqe_ctrl_seg) / 16;
	mqp->cur_ctrl->imm = htobe32(dv_mkey->lkey);
	seg = umr_ctrl_seg = (void *)mqp->cur_ctrl + sizeof(struct mlx5_wqe_ctrl_seg);

	memset(umr_ctrl_seg, 0, sizeof(*umr_ctrl_seg));
	umr_ctrl_seg->flags = MLX5_WQE_UMR_CTRL_FLAG_INLINE;
	umr_ctrl_seg->mkey_mask = htobe64(MLX5_WQE_UMR_CTRL_MKEY_MASK_LEN	|
		MLX5_WQE_UMR_CTRL_MKEY_MASK_ACCESS_LOCAL_WRITE	|
		MLX5_WQE_UMR_CTRL_MKEY_MASK_ACCESS_REMOTE_READ	|
		MLX5_WQE_UMR_CTRL_MKEY_MASK_ACCESS_REMOTE_WRITE	|
		MLX5_WQE_UMR_CTRL_MKEY_MASK_ACCESS_ATOMIC	|
		MLX5_WQE_UMR_CTRL_MKEY_MASK_FREE);

	seg += sizeof(struct mlx5_wqe_umr_ctrl_seg);
	mqp->cur_size += sizeof(struct mlx5_wqe_umr_ctrl_seg) / 16;

	if (unlikely(seg == qend))
		seg = mlx5_get_send_wqe(mqp, 0);

	mk = seg;
	memset(mk, 0, sizeof(*mk));
	mk->access_flags = get_umr_mr_flags(access_flags);
	mk->qpn_mkey = htobe32(0xffffff00 | (dv_mkey->lkey & 0xff));

	seg += sizeof(*mk);
	mqp->cur_size += (sizeof(*mk) / 16);

	if (unlikely(seg == qend))
		seg = mlx5_get_send_wqe(mqp, 0);

	if (data)
		umr_strided_seg_create(mqp, repeat_count, num_entries, data,
				       seg, qend, &size, &xlat_size, &reglen);
	else
		umr_sg_list_create(mqp, num_entries, sge, seg,
				   qend, &size, &xlat_size, &reglen);

	mk->len = htobe64(reglen);
	umr_ctrl_seg->klm_octowords = htobe16(align(xlat_size, 64) / 16);
	mqp->cur_size += size / 16;

	mqp->fm_cache = MLX5_WQE_CTRL_INITIATOR_SMALL_FENCE;
	mqp->nreq++;
	mqp->inl_wqe = 1;

	_common_wqe_finilize(mqp);
}

static void mlx5_send_wr_mr_interleaved(struct mlx5dv_qp_ex *dv_qp,
					struct mlx5dv_mkey *mkey,
					uint32_t access_flags,
					uint32_t repeat_count,
					uint16_t num_interleaved,
					struct mlx5dv_mr_interleaved *data)
{
	mlx5_send_wr_mr(dv_qp, mkey, access_flags, repeat_count,
			num_interleaved, data, NULL);
}

static inline void mlx5_send_wr_mr_list(struct mlx5dv_qp_ex *dv_qp,
					struct mlx5dv_mkey *mkey,
					uint32_t access_flags,
					uint16_t num_sges,
					struct ibv_sge *sge)
{
	mlx5_send_wr_mr(dv_qp, mkey, access_flags, 0, num_sges, NULL, sge);
}

static void mlx5_send_wr_set_dc_addr(struct mlx5dv_qp_ex *dv_qp,
				     struct ibv_ah *ah,
				     uint32_t remote_dctn,
				     uint64_t remote_dc_key)
{
	struct mlx5_qp *mqp = mqp_from_mlx5dv_qp_ex(dv_qp);
	struct mlx5_wqe_datagram_seg *dseg =
		(void *)mqp->cur_ctrl + sizeof(struct mlx5_wqe_ctrl_seg);
	struct mlx5_ah *mah = to_mah(ah);

	memcpy(&dseg->av, &mah->av, sizeof(dseg->av));
	dseg->av.dqp_dct |= htobe32(remote_dctn | MLX5_EXTENDED_UD_AV);
	dseg->av.key.dc_key = htobe64(remote_dc_key);

	if (mqp->cur_setters_cnt == WQE_REQ_SETTERS_UD_XRC_DC - 1)
		_common_wqe_finilize(mqp);
	else
		mqp->cur_setters_cnt++;
}

enum {
	MLX5_SUPPORTED_SEND_OPS_FLAGS_RC =
		IBV_QP_EX_WITH_SEND |
		IBV_QP_EX_WITH_SEND_WITH_INV |
		IBV_QP_EX_WITH_SEND_WITH_IMM |
		IBV_QP_EX_WITH_RDMA_WRITE |
		IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM |
		IBV_QP_EX_WITH_RDMA_READ |
		IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP |
		IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD |
		IBV_QP_EX_WITH_LOCAL_INV |
		IBV_QP_EX_WITH_BIND_MW,
	MLX5_SUPPORTED_SEND_OPS_FLAGS_XRC =
		MLX5_SUPPORTED_SEND_OPS_FLAGS_RC,
	MLX5_SUPPORTED_SEND_OPS_FLAGS_DCI =
		MLX5_SUPPORTED_SEND_OPS_FLAGS_RC,
	MLX5_SUPPORTED_SEND_OPS_FLAGS_UD =
		IBV_QP_EX_WITH_SEND |
		IBV_QP_EX_WITH_SEND_WITH_IMM,
	MLX5_SUPPORTED_SEND_OPS_FLAGS_UC =
		IBV_QP_EX_WITH_SEND |
		IBV_QP_EX_WITH_SEND_WITH_INV |
		IBV_QP_EX_WITH_SEND_WITH_IMM |
		IBV_QP_EX_WITH_RDMA_WRITE |
		IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM |
		IBV_QP_EX_WITH_LOCAL_INV |
		IBV_QP_EX_WITH_BIND_MW,
	MLX5_SUPPORTED_SEND_OPS_FLAGS_RAW_PACKET =
		IBV_QP_EX_WITH_SEND |
		IBV_QP_EX_WITH_TSO,
};

static void fill_wr_builders_rc_xrc_dc(struct ibv_qp_ex *ibqp)
{
	ibqp->wr_send = mlx5_send_wr_send_other;
	ibqp->wr_send_imm = mlx5_send_wr_send_imm;
	ibqp->wr_send_inv = mlx5_send_wr_send_inv;
	ibqp->wr_rdma_write = mlx5_send_wr_rdma_write;
	ibqp->wr_rdma_write_imm = mlx5_send_wr_rdma_write_imm;
	ibqp->wr_rdma_read = mlx5_send_wr_rdma_read;
	ibqp->wr_atomic_cmp_swp = mlx5_send_wr_atomic_cmp_swp;
	ibqp->wr_atomic_fetch_add = mlx5_send_wr_atomic_fetch_add;
	ibqp->wr_bind_mw = mlx5_send_wr_bind_mw;
	ibqp->wr_local_inv = mlx5_send_wr_local_inv;
}

static void fill_wr_builders_uc(struct ibv_qp_ex *ibqp)
{
	ibqp->wr_send = mlx5_send_wr_send_other;
	ibqp->wr_send_imm = mlx5_send_wr_send_imm;
	ibqp->wr_send_inv = mlx5_send_wr_send_inv;
	ibqp->wr_rdma_write = mlx5_send_wr_rdma_write;
	ibqp->wr_rdma_write_imm = mlx5_send_wr_rdma_write_imm;
	ibqp->wr_bind_mw = mlx5_send_wr_bind_mw;
	ibqp->wr_local_inv = mlx5_send_wr_local_inv;
}

static void fill_wr_builders_ud(struct ibv_qp_ex *ibqp)
{
	ibqp->wr_send = mlx5_send_wr_send_other;
	ibqp->wr_send_imm = mlx5_send_wr_send_imm;
}

static void fill_wr_builders_eth(struct ibv_qp_ex *ibqp)
{
	ibqp->wr_send = mlx5_send_wr_send_eth;
	ibqp->wr_send_tso = mlx5_send_wr_send_tso;
}

static void fill_wr_setters_rc_uc(struct ibv_qp_ex *ibqp)
{
	ibqp->wr_set_sge = mlx5_send_wr_set_sge_rc_uc;
	ibqp->wr_set_sge_list = mlx5_send_wr_set_sge_list_rc_uc;
	ibqp->wr_set_inline_data = mlx5_send_wr_set_inline_data_rc_uc;
	ibqp->wr_set_inline_data_list = mlx5_send_wr_set_inline_data_list_rc_uc;
}

static void fill_wr_setters_ud_xrc_dc(struct ibv_qp_ex *ibqp)
{
	ibqp->wr_set_sge = mlx5_send_wr_set_sge_ud_xrc_dc;
	ibqp->wr_set_sge_list = mlx5_send_wr_set_sge_list_ud_xrc_dc;
	ibqp->wr_set_inline_data = mlx5_send_wr_set_inline_data_ud_xrc_dc;
	ibqp->wr_set_inline_data_list = mlx5_send_wr_set_inline_data_list_ud_xrc_dc;
}

static void fill_wr_setters_eth(struct ibv_qp_ex *ibqp)
{
	ibqp->wr_set_sge = mlx5_send_wr_set_sge_eth;
	ibqp->wr_set_sge_list = mlx5_send_wr_set_sge_list_eth;
	ibqp->wr_set_inline_data = mlx5_send_wr_set_inline_data_eth;
	ibqp->wr_set_inline_data_list = mlx5_send_wr_set_inline_data_list_eth;
}

int mlx5_qp_fill_wr_pfns(struct mlx5_qp *mqp,
			 const struct ibv_qp_init_attr_ex *attr,
			 const struct mlx5dv_qp_init_attr *mlx5_attr)
{
	struct ibv_qp_ex *ibqp = &mqp->verbs_qp.qp_ex;
	uint64_t ops = attr->send_ops_flags;
	struct mlx5dv_qp_ex *dv_qp;
	uint64_t mlx5_ops = 0;

	ibqp->wr_start = mlx5_send_wr_start;
	ibqp->wr_complete = mlx5_send_wr_complete;
	ibqp->wr_abort = mlx5_send_wr_abort;

	if (!mqp->atomics_enabled &&
	    (ops & IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP ||
	     ops & IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD))
		return EOPNOTSUPP;

	if (mlx5_attr &&
	    mlx5_attr->comp_mask & MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS)
		mlx5_ops = mlx5_attr->send_ops_flags;

	/* Set all supported micro-functions regardless user request */
	switch (attr->qp_type) {
	case IBV_QPT_RC:
		if (ops & ~MLX5_SUPPORTED_SEND_OPS_FLAGS_RC)
			return EOPNOTSUPP;

		fill_wr_builders_rc_xrc_dc(ibqp);
		fill_wr_setters_rc_uc(ibqp);

		if (mlx5_ops) {
			if (!check_comp_mask(mlx5_ops,
					     MLX5DV_QP_EX_WITH_MR_INTERLEAVED |
					     MLX5DV_QP_EX_WITH_MR_LIST))
				return EOPNOTSUPP;

			dv_qp = &mqp->dv_qp;
			dv_qp->wr_mr_interleaved = mlx5_send_wr_mr_interleaved;
			dv_qp->wr_mr_list = mlx5_send_wr_mr_list;
		}

		break;

	case IBV_QPT_UC:
		if (ops & ~MLX5_SUPPORTED_SEND_OPS_FLAGS_UC || mlx5_ops)
			return EOPNOTSUPP;

		fill_wr_builders_uc(ibqp);
		fill_wr_setters_rc_uc(ibqp);
		break;

	case IBV_QPT_XRC_SEND:
		if (ops & ~MLX5_SUPPORTED_SEND_OPS_FLAGS_XRC || mlx5_ops)
			return EOPNOTSUPP;

		fill_wr_builders_rc_xrc_dc(ibqp);
		fill_wr_setters_ud_xrc_dc(ibqp);
		ibqp->wr_set_xrc_srqn = mlx5_send_wr_set_xrc_srqn;
		break;

	case IBV_QPT_UD:
		if (ops & ~MLX5_SUPPORTED_SEND_OPS_FLAGS_UD || mlx5_ops)
			return EOPNOTSUPP;

		if (mqp->flags & MLX5_QP_FLAGS_USE_UNDERLAY)
			return EOPNOTSUPP;

		fill_wr_builders_ud(ibqp);
		fill_wr_setters_ud_xrc_dc(ibqp);
		ibqp->wr_set_ud_addr = mlx5_send_wr_set_ud_addr;
		break;

	case IBV_QPT_RAW_PACKET:
		if (ops & ~MLX5_SUPPORTED_SEND_OPS_FLAGS_RAW_PACKET || mlx5_ops)
			return EOPNOTSUPP;

		fill_wr_builders_eth(ibqp);
		fill_wr_setters_eth(ibqp);
		break;

	case IBV_QPT_DRIVER:
		dv_qp = &mqp->dv_qp;

		if (!(mlx5_attr->comp_mask & MLX5DV_QP_INIT_ATTR_MASK_DC &&
		      mlx5_attr->dc_init_attr.dc_type == MLX5DV_DCTYPE_DCI))
			return EOPNOTSUPP;

		if (ops & ~MLX5_SUPPORTED_SEND_OPS_FLAGS_DCI || mlx5_ops)
			return EOPNOTSUPP;

		fill_wr_builders_rc_xrc_dc(ibqp);
		fill_wr_setters_ud_xrc_dc(ibqp);
		dv_qp->wr_set_dc_addr = mlx5_send_wr_set_dc_addr;
		break;

	default:
		return EOPNOTSUPP;
	}

	return 0;
}

int mlx5_bind_mw(struct ibv_qp *qp, struct ibv_mw *mw,
		 struct ibv_mw_bind *mw_bind)
{
	struct ibv_mw_bind_info	*bind_info = &mw_bind->bind_info;
	struct ibv_send_wr wr = {};
	struct ibv_send_wr *bad_wr = NULL;
	int ret;

	if (!bind_info->mr && (bind_info->addr || bind_info->length)) {
		errno = EINVAL;
		return errno;
	}

	if (bind_info->mw_access_flags & IBV_ACCESS_ZERO_BASED) {
		errno = EINVAL;
		return errno;
	}

	if (bind_info->mr) {
		if (verbs_get_mr(bind_info->mr)->mr_type != IBV_MR_TYPE_MR) {
			errno = ENOTSUP;
			return errno;
		}

		if (to_mmr(bind_info->mr)->alloc_flags & IBV_ACCESS_ZERO_BASED) {
			errno = EINVAL;
			return errno;
		}

		if (mw->pd != bind_info->mr->pd) {
			errno = EPERM;
			return errno;
		}
	}

	wr.opcode = IBV_WR_BIND_MW;
	wr.next = NULL;
	wr.wr_id = mw_bind->wr_id;
	wr.send_flags = mw_bind->send_flags;
	wr.bind_mw.bind_info = mw_bind->bind_info;
	wr.bind_mw.mw = mw;
	wr.bind_mw.rkey = ibv_inc_rkey(mw->rkey);

	ret = _mlx5_post_send(qp, &wr, &bad_wr);
	if (ret)
		return ret;

	mw->rkey = wr.bind_mw.rkey;

	return 0;
}

static void set_sig_seg(struct mlx5_qp *qp, struct mlx5_rwqe_sig *sig,
			int size, uint16_t idx)
{
	uint8_t  sign;
	uint32_t qpn = qp->ibv_qp->qp_num;

	sign = calc_sig(sig, size);
	sign ^= calc_sig(&qpn, 4);
	sign ^= calc_sig(&idx, 2);
	sig->signature = sign;
}

static void set_wq_sig_seg(struct mlx5_rwq *rwq, struct mlx5_rwqe_sig *sig,
			   int size, uint16_t idx)
{
	uint8_t  sign;
	uint32_t qpn = rwq->wq.wq_num;

	sign = calc_sig(sig, size);
	sign ^= calc_sig(&qpn, 4);
	sign ^= calc_sig(&idx, 2);
	sig->signature = sign;
}

int mlx5_post_wq_recv(struct ibv_wq *ibwq, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad_wr)
{
	struct mlx5_rwq *rwq = to_mrwq(ibwq);
	struct mlx5_wqe_data_seg *scat;
	int err = 0;
	int nreq;
	int ind;
	int i, j;
	struct mlx5_rwqe_sig *sig;

	mlx5_spin_lock(&rwq->rq.lock);

	ind = rwq->rq.head & (rwq->rq.wqe_cnt - 1);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (unlikely(mlx5_wq_overflow(&rwq->rq, nreq,
					      to_mcq(rwq->wq.cq)))) {
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->num_sge > rwq->rq.max_gs)) {
			err = EINVAL;
			*bad_wr = wr;
			goto out;
		}

		scat = get_wq_recv_wqe(rwq, ind);
		sig = (struct mlx5_rwqe_sig *)scat;
		if (unlikely(rwq->wq_sig)) {
			memset(sig, 0, 1 << rwq->rq.wqe_shift);
			++scat;
		}

		for (i = 0, j = 0; i < wr->num_sge; ++i) {
			if (unlikely(!wr->sg_list[i].length))
				continue;
			set_data_ptr_seg(scat + j++, wr->sg_list + i, 0);
		}

		if (j < rwq->rq.max_gs) {
			scat[j].byte_count = 0;
			scat[j].lkey       = htobe32(MLX5_INVALID_LKEY);
			scat[j].addr       = 0;
		}

		if (unlikely(rwq->wq_sig))
			set_wq_sig_seg(rwq, sig, (wr->num_sge + 1) << 4,
				       rwq->rq.head & 0xffff);

		rwq->rq.wrid[ind] = wr->wr_id;

		ind = (ind + 1) & (rwq->rq.wqe_cnt - 1);
	}

out:
	if (likely(nreq)) {
		rwq->rq.head += nreq;
		/*
		 * Make sure that descriptors are written before
		 * doorbell record.
		 */
		udma_to_device_barrier();
		*(rwq->recv_db) = htobe32(rwq->rq.head & 0xffff);
	}

	mlx5_spin_unlock(&rwq->rq.lock);

	return err;
}

int mlx5_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		   struct ibv_recv_wr **bad_wr)
{
	struct mlx5_qp *qp = to_mqp(ibqp);
	struct mlx5_wqe_data_seg *scat;
	int err = 0;
	int nreq;
	int ind;
	int i, j;
	struct mlx5_rwqe_sig *sig;

	mlx5_spin_lock(&qp->rq.lock);

	ind = qp->rq.head & (qp->rq.wqe_cnt - 1);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (unlikely(mlx5_wq_overflow(&qp->rq, nreq,
					      to_mcq(qp->ibv_qp->recv_cq)))) {
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->num_sge > qp->rq.max_gs)) {
			err = EINVAL;
			*bad_wr = wr;
			goto out;
		}

		scat = get_recv_wqe(qp, ind);
		sig = (struct mlx5_rwqe_sig *)scat;
		if (unlikely(qp->wq_sig)) {
			memset(sig, 0, 1 << qp->rq.wqe_shift);
			++scat;
		}

		for (i = 0, j = 0; i < wr->num_sge; ++i) {
			if (unlikely(!wr->sg_list[i].length))
				continue;
			set_data_ptr_seg(scat + j++, wr->sg_list + i, 0);
		}

		if (j < qp->rq.max_gs) {
			scat[j].byte_count = 0;
			scat[j].lkey       = htobe32(MLX5_INVALID_LKEY);
			scat[j].addr       = 0;
		}

		if (unlikely(qp->wq_sig))
			set_sig_seg(qp, sig, (wr->num_sge + 1) << 4,
				    qp->rq.head & 0xffff);

		qp->rq.wrid[ind] = wr->wr_id;

		ind = (ind + 1) & (qp->rq.wqe_cnt - 1);
	}

out:
	if (likely(nreq)) {
		qp->rq.head += nreq;

		/*
		 * Make sure that descriptors are written before
		 * doorbell record.
		 */
		udma_to_device_barrier();

		/*
		 * For Raw Packet QP, avoid updating the doorbell record
		 * as long as the QP isn't in RTR state, to avoid receiving
		 * packets in illegal states.
		 * This is only for Raw Packet QPs since they are represented
		 * differently in the hardware.
		 */
		if (likely(!((ibqp->qp_type == IBV_QPT_RAW_PACKET ||
			      qp->flags & MLX5_QP_FLAGS_USE_UNDERLAY) &&
			     ibqp->state < IBV_QPS_RTR)))
			qp->db[MLX5_RCV_DBR] = htobe32(qp->rq.head & 0xffff);
	}

	mlx5_spin_unlock(&qp->rq.lock);

	return err;
}

static void mlx5_tm_add_op(struct mlx5_srq *srq, struct mlx5_tag_entry *tag,
			   uint64_t wr_id, int nreq)
{
	struct mlx5_qp *qp = to_mqp(srq->cmd_qp);
	struct mlx5_srq_op *op;

	op = srq->op + (srq->op_tail++ & (qp->sq.wqe_cnt - 1));
	op->tag = tag;
	op->wr_id = wr_id;
	/* Will point to next available WQE */
	op->wqe_head = qp->sq.head + nreq;
	if (tag)
		tag->expect_cqe++;
}

int mlx5_post_srq_ops(struct ibv_srq *ibsrq, struct ibv_ops_wr *wr,
		      struct ibv_ops_wr **bad_wr)
{
	struct mlx5_context *ctx = to_mctx(ibsrq->context);
	struct mlx5_srq *srq = to_msrq(ibsrq);
	struct mlx5_wqe_ctrl_seg *ctrl = NULL;
	struct mlx5_tag_entry *tag;
	struct mlx5_bf *bf;
	struct mlx5_qp *qp;
	unsigned int idx;
	int size = 0;
	int nreq = 0;
	int err = 0;
	void *qend;
	void *seg;
	FILE *fp = ctx->dbg_fp;

	if (unlikely(!srq->cmd_qp)) {
		*bad_wr = wr;
		return EINVAL;
	}

	qp = to_mqp(srq->cmd_qp);
	bf = qp->bf;
	qend = qp->sq.qend;
	mlx5_spin_lock(&srq->lock);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (unlikely(mlx5_wq_overflow(&qp->sq, nreq,
					      to_mcq(qp->ibv_qp->send_cq)))) {
			mlx5_dbg(fp, MLX5_DBG_QP_SEND, "work queue overflow\n");
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		idx = qp->sq.cur_post & (qp->sq.wqe_cnt - 1);
		ctrl = seg = mlx5_get_send_wqe(qp, idx);
		*(uint32_t *)(seg + 8) = 0;
		ctrl->imm = 0;
		ctrl->fm_ce_se = 0;

		seg += sizeof(*ctrl);
		size = sizeof(*ctrl) / 16;

		switch (wr->opcode) {
		case IBV_WR_TAG_ADD:
			if (unlikely(!srq->tm_head->next)) {
				mlx5_dbg(fp, MLX5_DBG_QP_SEND, "tag matching list is full\n");
				err = ENOMEM;
				*bad_wr = wr;
				goto out;
			}
			tag = srq->tm_head;
#ifdef MLX5_DEBUG
			if (wr->tm.add.num_sge > 1) {
				mlx5_dbg(fp, MLX5_DBG_QP_SEND, "num_sge must be at most 1\n");
				err = EINVAL;
				*bad_wr = wr;
				goto out;
			}

			if (tag->expect_cqe) {
				mlx5_dbg(fp, MLX5_DBG_QP_SEND, "tag matching list is corrupted\n");
				err = ENOMEM;
				*bad_wr = wr;
				goto out;
			}
#endif
			srq->tm_head = tag->next;
			/* place index of next entry into TM segment */
			set_tm_seg(seg, MLX5_TM_OPCODE_APPEND, wr,
				   tag->next - srq->tm_list);
			tag->next = NULL;
			tag->wr_id = wr->tm.add.recv_wr_id;
			if (wr->flags & IBV_OPS_TM_SYNC)
				srq->unexp_out = wr->tm.unexpected_cnt;
			tag->phase_cnt = srq->unexp_out;
			tag->expect_cqe++;

			if (wr->flags & IBV_OPS_SIGNALED)
				mlx5_tm_add_op(srq, tag, wr->wr_id, nreq);

			wr->tm.handle = tag - srq->tm_list;
			seg += sizeof(struct mlx5_wqe_tm_seg);
			size += sizeof(struct mlx5_wqe_tm_seg) / 16;

			if (unlikely(seg == qend))
				seg = mlx5_get_send_wqe(qp, 0);

			/* message is allowed to be empty */
			if (wr->tm.add.num_sge && wr->tm.add.sg_list->length) {
				set_data_ptr_seg(seg, wr->tm.add.sg_list, 0);
				tag->ptr = (void *)(uintptr_t)wr->tm.add.sg_list->addr;
				tag->size = wr->tm.add.sg_list->length;
			} else {
				set_data_ptr_seg_end(seg);
			}
			size += sizeof(struct mlx5_wqe_data_seg) / 16;
			break;

		case IBV_WR_TAG_DEL:
			tag = &srq->tm_list[wr->tm.handle];

#ifdef MLX5_DEBUG
			if (!tag->expect_cqe) {
				mlx5_dbg(fp, MLX5_DBG_QP_SEND, "removing tag which isn't in HW ownership\n");
				err = ENOMEM;
				*bad_wr = wr;
				goto out;
			}
#endif
			set_tm_seg(seg, MLX5_TM_OPCODE_REMOVE, wr,
				   wr->tm.handle);

			if (wr->flags & IBV_OPS_SIGNALED)
				mlx5_tm_add_op(srq, tag, wr->wr_id, nreq);
			else
				mlx5_tm_release_tag(srq, tag);

			seg += sizeof(struct mlx5_wqe_tm_seg);
			size += sizeof(struct mlx5_wqe_tm_seg) / 16;
			break;

		case IBV_WR_TAG_SYNC:
			set_tm_seg(seg, MLX5_TM_OPCODE_NOP, wr, 0);

			if (wr->flags & IBV_OPS_SIGNALED)
				mlx5_tm_add_op(srq, NULL, wr->wr_id, nreq);

			seg += sizeof(struct mlx5_wqe_tm_seg);
			size += sizeof(struct mlx5_wqe_tm_seg) / 16;
			break;

		default:
			mlx5_dbg(fp, MLX5_DBG_QP_SEND, "bad opcode %d\n",
				 wr->opcode);
			err = EINVAL;
			*bad_wr = wr;
			goto out;
		}

		ctrl->opmod_idx_opcode = htobe32(MLX5_OPCODE_TAG_MATCHING |
				((qp->sq.cur_post & 0xffff) << 8));
		ctrl->qpn_ds = htobe32(size | (srq->cmd_qp->qp_num << 8));

		if (unlikely(qp->wq_sig))
			ctrl->signature = wq_sig(ctrl);

		qp->sq.cur_post += DIV_ROUND_UP(size * 16, MLX5_SEND_WQE_BB);

#ifdef MLX5_DEBUG
		if (mlx5_debug_mask & MLX5_DBG_QP_SEND)
			dump_wqe(fp, idx, size, qp);
#endif
	}

out:
	qp->fm_cache = 0;
	post_send_db(qp, bf, nreq, 0, size, ctrl);

	mlx5_spin_unlock(&srq->lock);

	return err;
}

int mlx5_use_huge(const char *key)
{
	char *e;
	e = getenv(key);
	if (e && !strcmp(e, "y"))
		return 1;

	return 0;
}

struct mlx5_qp *mlx5_find_qp(struct mlx5_context *ctx, uint32_t qpn)
{
	int tind = qpn >> MLX5_QP_TABLE_SHIFT;

	if (ctx->qp_table[tind].refcnt)
		return ctx->qp_table[tind].table[qpn & MLX5_QP_TABLE_MASK];
	else
		return NULL;
}

int mlx5_store_qp(struct mlx5_context *ctx, uint32_t qpn, struct mlx5_qp *qp)
{
	int tind = qpn >> MLX5_QP_TABLE_SHIFT;

	if (!ctx->qp_table[tind].refcnt) {
		ctx->qp_table[tind].table = calloc(MLX5_QP_TABLE_MASK + 1,
						   sizeof(struct mlx5_qp *));
		if (!ctx->qp_table[tind].table)
			return -1;
	}

	++ctx->qp_table[tind].refcnt;
	ctx->qp_table[tind].table[qpn & MLX5_QP_TABLE_MASK] = qp;
	return 0;
}

void mlx5_clear_qp(struct mlx5_context *ctx, uint32_t qpn)
{
	int tind = qpn >> MLX5_QP_TABLE_SHIFT;

	if (!--ctx->qp_table[tind].refcnt)
		free(ctx->qp_table[tind].table);
	else
		ctx->qp_table[tind].table[qpn & MLX5_QP_TABLE_MASK] = NULL;
}
