/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

/*
 * post_send body shared by the generic (qp.c) and adversarial
 * (mlx5_adversarial.c) variants. Define ADVERSARIAL_POST_SEND before
 * including it to build the adversarial variant.
 */

#ifndef MLX5_POST_SEND_BODY_H
#define MLX5_POST_SEND_BODY_H

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

static inline void mlx5_set_raddr_seg(struct mlx5_wqe_raddr_seg *rseg,
				      uint64_t remote_addr, uint32_t rkey)
{
	rseg->raddr    = htobe64(remote_addr);
	rseg->rkey     = htobe32(rkey);
	rseg->reserved = 0;
}

static inline void mlx5_set_atomic_seg(struct mlx5_wqe_atomic_seg *aseg,
				       enum ibv_wr_opcode opcode,
				       uint64_t swap,
				       uint64_t compare_add)
				       ALWAYS_INLINE;
static inline void mlx5_set_atomic_seg(struct mlx5_wqe_atomic_seg *aseg,
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

static inline void
mlx5_set_data_ptr_seg_atomic(struct mlx5_wqe_data_seg *dseg,
			     struct ibv_sge *sg)
{
	dseg->byte_count = htobe32(MLX5_ATOMIC_SIZE);
	dseg->lkey       = htobe32(sg->lkey);
	dseg->addr       = htobe64(sg->addr);
}

static inline __be32 mlx5_send_ieth(struct ibv_send_wr *wr)
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

static inline int mlx5_set_data_inl_seg(struct mlx5_qp *qp,
					struct ibv_send_wr *wr,
					void *wqe, int *sz,
					struct mlx5_sg_copy_ptr *sg_copy_ptr)
{
	struct mlx5_wqe_inline_seg *seg;
	void *addr;
	uint32_t len;
	int i;
	uint64_t inl = 0;
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

/*
 * Avoid using memcpy() to copy to BlueFlame page, since memcpy()
 * implementations may use move-string-buffer assembler instructions,
 * which do not guarantee order of copying.
 */
static inline void mlx5_bf_copy(uint64_t *dst, const uint64_t *src,
				unsigned bytecnt, struct mlx5_qp *qp)
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

static inline void mlx5_post_send_db(struct mlx5_qp *qp, struct mlx5_bf *bf,
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

static inline __attribute__((always_inline))
int _mlx5_post_send_body(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
			 struct ibv_send_wr **bad_wr)
{
	struct mlx5_qp *qp = to_mqp(ibqp);
	void *seg;
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
	uint8_t fence;
	uint8_t next_fence;
#ifndef ADVERSARIAL_POST_SEND
	struct mlx5_wqe_eth_seg *eseg;
	struct mlx5_wqe_xrc_seg *xrc;
#endif
	uint32_t max_tso = 0;
	FILE *fp = to_mctx(ibqp->context)->dbg_fp; /* The compiler ignores in non-debug mode */

	mlx5_spin_lock(&qp->sq.lock);

	next_fence = qp->fm_cache;

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
#ifdef ADVERSARIAL_POST_SEND
		/* Only these opcodes are supported in adversarial mode */
		if (unlikely(wr->opcode != IBV_WR_RDMA_WRITE &&
			     wr->opcode != IBV_WR_RDMA_WRITE_WITH_IMM &&
			     wr->opcode != IBV_WR_RDMA_READ &&
			     wr->opcode != IBV_WR_ATOMIC_FETCH_AND_ADD)) {
			err = EOPNOTSUPP;
			*bad_wr = wr;
			goto out;
		}
#endif

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

		if (unlikely(wr->num_sge > qp->sq.qp_state_max_gs)) {
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
		ctrl->imm = mlx5_send_ieth(wr);
		ctrl->fm_ce_se = qp->sq_signal_bits | fence |
			(wr->send_flags & IBV_SEND_SIGNALED ?
			 MLX5_WQE_CTRL_CQ_UPDATE : 0) |
			(wr->send_flags & IBV_SEND_SOLICITED ?
			 MLX5_WQE_CTRL_SOLICITED : 0);

		seg += sizeof *ctrl;
		size = sizeof *ctrl / 16;
		qp->sq.wr_data[idx] = 0;

		switch (ibqp->qp_type) {
#ifndef ADVERSARIAL_POST_SEND
		case IBV_QPT_XRC_SEND:
			if (unlikely(wr->opcode != IBV_WR_BIND_MW &&
				     wr->opcode != IBV_WR_LOCAL_INV)) {
				xrc = seg;
				xrc->xrc_srqn = htobe32(wr->qp_type.xrc.remote_srqn);
				seg += sizeof(*xrc);
				size += sizeof(*xrc) / 16;
			}
			SWITCH_FALLTHROUGH;
#endif
		case IBV_QPT_RC:
			switch (wr->opcode) {
			case IBV_WR_RDMA_READ:
			case IBV_WR_RDMA_WRITE:
			case IBV_WR_RDMA_WRITE_WITH_IMM:
				mlx5_set_raddr_seg(seg,
						   wr->wr.rdma.remote_addr,
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
				mlx5_set_raddr_seg(seg,
						   wr->wr.atomic.remote_addr,
						   wr->wr.atomic.rkey);
				seg  += sizeof(struct mlx5_wqe_raddr_seg);

				mlx5_set_atomic_seg(seg, wr->opcode,
						    wr->wr.atomic.swap,
						    wr->wr.atomic.compare_add);
				seg  += sizeof(struct mlx5_wqe_atomic_seg);

				size += (sizeof(struct mlx5_wqe_raddr_seg) +
				sizeof(struct mlx5_wqe_atomic_seg)) / 16;
				break;

#ifndef ADVERSARIAL_POST_SEND
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
#endif

			default:
				break;
			}
			break;

#ifndef ADVERSARIAL_POST_SEND
		case IBV_QPT_UC:
			switch (wr->opcode) {
			case IBV_WR_RDMA_WRITE:
			case IBV_WR_RDMA_WRITE_WITH_IMM:
				mlx5_set_raddr_seg(seg,
						   wr->wr.rdma.remote_addr,
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
#endif

		default:
			break;
		}

		if (wr->send_flags & IBV_SEND_INLINE && wr->num_sge) {
			int uninitialized_var(sz);

			err = mlx5_set_data_inl_seg(qp, wr, seg, &sz, &sg_copy_ptr);
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
						mlx5_set_data_ptr_seg_atomic(dpseg, wr->sg_list + i);
					else {
						if (unlikely(wr->opcode == IBV_WR_TSO)) {
							if (max_tso < wr->sg_list[i].length) {
								err = EINVAL;
								*bad_wr = wr;
								goto out;
							}
							max_tso -= wr->sg_list[i].length;
						}
						mlx5_set_data_ptr_seg(dpseg, wr->sg_list + i,
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

#ifndef ADVERSARIAL_POST_SEND
		if (unlikely(qp->wq_sig))
			ctrl->signature = wq_sig(ctrl, qp->sq_start,
						 qp->sq.qend);
#endif

		qp->sq.wrid[idx] = wr->wr_id;
		qp->sq.wqe_head[idx] = qp->sq.head + nreq;

#ifdef ADVERSARIAL_POST_SEND
		/* Record the WR for the adversarial poll_cq checks */
		{
			unsigned slot = qp->sq.shadow_head &
					(qp->sq.wqe_cnt - 1);
			/* sq_sig_all QPs generate a CQE for every WR */
			bool signaled = qp->sq_signal_bits ||
				(wr->send_flags & IBV_SEND_SIGNALED);

			qp->sq.adv_mlx5_opcodes[idx] = mlx5_opcode;
			if (wr->opcode == IBV_WR_RDMA_READ) {
				uint32_t rlen = 0;

				for (i = 0; i < wr->num_sge; ++i)
					rlen += wr->sg_list[i].length;
				qp->sq.adv_read_len[idx] = rlen;
			}
			/* The device reports this as cqe->wqe_counter */
			qp->sq.shadow_queue[slot] = qp->sq.cur_post & 0xffff;
			if (signaled) {
				qp->sq.signaled_ring[qp->sq.signaled_head &
						     (qp->sq.wqe_cnt - 1)] =
					qp->sq.shadow_head;
				qp->sq.signaled_head++;
			}
			/* Free-running; all uses mask it with wqe_cnt - 1 */
			qp->sq.shadow_head++;
		}
#endif

		qp->sq.cur_post += DIV_ROUND_UP(size * 16, MLX5_SEND_WQE_BB);

#ifdef MLX5_DEBUG
		if (mlx5_debug_mask & MLX5_DBG_QP_SEND)
			mlx5_dump_wqe(to_mctx(ibqp->context), idx, size, qp);
#endif

		rdma_tracepoint(rdma_core_mlx5, post_send,
				ibqp->context->device->name,
				ibqp->qp_num,
				(char *)ibv_wr_opcode_str(wr->opcode),
				wr->num_sge);
	}

out:
	qp->fm_cache = next_fence;
	mlx5_post_send_db(qp, bf, nreq, inl, size, ctrl);

	mlx5_spin_unlock(&qp->sq.lock);

	return err;
}

#endif /* MLX5_POST_SEND_BODY_H */
