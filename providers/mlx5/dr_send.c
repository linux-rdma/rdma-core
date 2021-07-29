/*
 * Copyright (c) 2019 Mellanox Technologies, Inc.  All rights reserved.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <util/mmio.h>
#include "mlx5dv_dr.h"
#include "wqe.h"

#define QUEUE_SIZE		128
#define SIGNAL_PER_DIV_QUEUE	16
#define TH_NUMS_TO_DRAIN	2

enum {
	CQ_OK = 0,
	CQ_EMPTY = -1,
	CQ_POLL_ERR = -2
};

struct dr_qp_init_attr {
	uint32_t		cqn;
	uint32_t		pdn;
	struct mlx5dv_devx_uar	*uar;
	struct ibv_qp_cap	cap;
	bool			isolate_vl_tc;
	uint8_t			qp_ts_format;
};

static void *dr_cq_get_cqe(struct dr_cq *dr_cq, int n)
{
	return dr_cq->buf + n * dr_cq->cqe_sz;
}

static void *dr_cq_get_sw_cqe(struct dr_cq *dr_cq, int n)
{
	void *cqe = dr_cq_get_cqe(dr_cq, n & (dr_cq->ncqe - 1));
	struct mlx5_cqe64 *cqe64;

	cqe64 = (dr_cq->cqe_sz == 64) ? cqe : cqe + 64;

	if (likely(mlx5dv_get_cqe_opcode(cqe64) != MLX5_CQE_INVALID) &&
	    !((cqe64->op_own & MLX5_CQE_OWNER_MASK) ^
	      !!(n & dr_cq->ncqe)))
		return cqe64;
	else
		return NULL;
}

static int dr_get_next_cqe(struct dr_cq *dr_cq,
			   struct mlx5_cqe64 **pcqe64)
{
	struct mlx5_cqe64 *cqe64;

	cqe64 = dr_cq_get_sw_cqe(dr_cq, dr_cq->cons_index);
	if (!cqe64)
		return CQ_EMPTY;

	++dr_cq->cons_index;
	/*
	 * Make sure we read CQ entry contents after we've checked the
	 * ownership bit.
	 */
	udma_from_device_barrier();

	*pcqe64 = cqe64;

	return CQ_OK;
}

static int dr_parse_cqe(struct dr_cq *dr_cq, struct mlx5_cqe64 *cqe64)
{
	uint16_t wqe_ctr;
	uint8_t opcode;
	int idx;

	wqe_ctr = be16toh(cqe64->wqe_counter);
	opcode = mlx5dv_get_cqe_opcode(cqe64);
	if (opcode == MLX5_CQE_REQ_ERR) {
		idx = wqe_ctr & (dr_cq->qp->sq.wqe_cnt - 1);
		dr_cq->qp->sq.tail = dr_cq->qp->sq.wqe_head[idx] + 1;
	} else if (opcode == MLX5_CQE_RESP_ERR) {
		++dr_cq->qp->sq.tail;
	} else {
		idx = wqe_ctr & (dr_cq->qp->sq.wqe_cnt - 1);
		dr_cq->qp->sq.tail = dr_cq->qp->sq.wqe_head[idx] + 1;

		return CQ_OK;
	}

	return CQ_POLL_ERR;
}

static int dr_cq_poll_one(struct dr_cq *dr_cq)
{
	struct mlx5_cqe64 *cqe64;
	int err;

	err = dr_get_next_cqe(dr_cq, &cqe64);
	if (err == CQ_EMPTY)
		return err;

	return dr_parse_cqe(dr_cq, cqe64);
}

static int dr_poll_cq(struct dr_cq *dr_cq, int ne)
{
	int npolled;
	int err = 0;

	for (npolled = 0; npolled < ne; ++npolled) {
		err = dr_cq_poll_one(dr_cq);
		if (err != CQ_OK)
			break;
	}
	dr_cq->db[MLX5_CQ_SET_CI] = htobe32(dr_cq->cons_index &
					    0xffffff);
	return err == CQ_POLL_ERR ? err : npolled;
}

/* We calculate for specific RC QP with the required functionality */
static int dr_qp_calc_rc_send_wqe(struct dr_qp_init_attr *attr)
{
	int size;
	int inl_size = 0;
	int tot_size;

	size = sizeof(struct mlx5_wqe_ctrl_seg) +
		sizeof(struct mlx5_wqe_raddr_seg);
	if (attr->cap.max_inline_data)
		inl_size = size + align(sizeof(struct mlx5_wqe_inl_data_seg) +
					attr->cap.max_inline_data, 16);

	size += attr->cap.max_send_sge * sizeof(struct mlx5_wqe_data_seg);
	tot_size = max_int(size, inl_size);

	return align(tot_size, MLX5_SEND_WQE_BB);
}

static int dr_calc_sq_size(struct dr_qp *dr_qp,
			   struct dr_qp_init_attr *attr)
{
	int wqe_size;
	int wq_size;

	wqe_size = dr_qp_calc_rc_send_wqe(attr);

	dr_qp->max_inline_data = wqe_size -
		(sizeof(struct  mlx5_wqe_ctrl_seg) +
		 sizeof(struct mlx5_wqe_raddr_seg)) -
		sizeof(struct mlx5_wqe_inl_data_seg);

	wq_size = roundup_pow_of_two(attr->cap.max_send_wr * wqe_size);
	dr_qp->sq.wqe_cnt = wq_size / MLX5_SEND_WQE_BB;
	dr_qp->sq.wqe_shift = STATIC_ILOG_32(MLX5_SEND_WQE_BB) - 1;
	dr_qp->sq.max_gs = attr->cap.max_send_sge;
	dr_qp->sq.max_post = wq_size / wqe_size;

	return wq_size;
}

static int dr_qp_calc_recv_wqe(struct dr_qp_init_attr *attr)
{
	uint32_t size;
	int num_scatter;

	num_scatter = max_t(uint32_t, attr->cap.max_recv_sge, 1);
	size = sizeof(struct mlx5_wqe_data_seg) * num_scatter;

	size = roundup_pow_of_two(size);

	return size;
}

static int dr_calc_rq_size(struct dr_qp *dr_qp,
			   struct dr_qp_init_attr *attr)
{
	int wqe_size;
	int wq_size;

	wqe_size = dr_qp_calc_recv_wqe(attr);

	wq_size = roundup_pow_of_two(attr->cap.max_recv_wr) * wqe_size;
	wq_size = max(wq_size, MLX5_SEND_WQE_BB);
	dr_qp->rq.wqe_cnt = wq_size / wqe_size;
	dr_qp->rq.wqe_shift = ilog32(wqe_size - 1);
	dr_qp->rq.max_post = 1 << ilog32(wq_size / wqe_size - 1);
	dr_qp->rq.max_gs = wqe_size / sizeof(struct mlx5_wqe_data_seg);

	return wq_size;
}

static int dr_calc_wq_size(struct dr_qp *dr_qp, struct dr_qp_init_attr *attr)
{
	int result;
	int ret;

	result = dr_calc_sq_size(dr_qp, attr);

	ret = dr_calc_rq_size(dr_qp, attr);

	result += ret;
	dr_qp->sq.offset = ret;
	dr_qp->rq.offset = 0;

	return result;
}

static int dr_qp_alloc_buf(struct dr_qp *dr_qp, int size)
{
	int al_size;
	int ret;

	dr_qp->sq.wqe_head = malloc(dr_qp->sq.wqe_cnt *
				    sizeof(*dr_qp->sq.wqe_head));
	if (!dr_qp->sq.wqe_head) {
		errno = ENOMEM;
		return errno;
	}

	al_size = align(size, sysconf(_SC_PAGESIZE));
	ret = posix_memalign(&dr_qp->buf.buf, sysconf(_SC_PAGESIZE), al_size);
	if (ret) {
		errno = ret;
		goto free_wqe_head;
	}

	dr_qp->buf.length = al_size;
	dr_qp->buf.type = MLX5_ALLOC_TYPE_ANON;
	memset(dr_qp->buf.buf, 0, dr_qp->buf.length);

	return 0;

free_wqe_head:
	free(dr_qp->sq.wqe_head);
	return ret;
}

static struct dr_qp *dr_create_rc_qp(struct ibv_context *ctx,
				     struct dr_qp_init_attr *attr)
{
	struct dr_devx_qp_create_attr qp_create_attr;
	struct mlx5dv_devx_obj *obj;
	struct dr_qp *dr_qp;
	int size;
	int ret;

	dr_qp = calloc(1, sizeof(*dr_qp));
	if (!dr_qp) {
		errno = ENOMEM;
		return NULL;
	}

	size = dr_calc_wq_size(dr_qp, attr);

	if (dr_qp_alloc_buf(dr_qp, size))
		goto err_alloc_bufs;

	dr_qp->sq_start = dr_qp->buf.buf + dr_qp->sq.offset;
	dr_qp->sq.qend = dr_qp->buf.buf + dr_qp->sq.offset +
		(dr_qp->sq.wqe_cnt << dr_qp->sq.wqe_shift);
	dr_qp->rq.head = 0;
	dr_qp->rq.tail = 0;
	dr_qp->sq.cur_post = 0;

	ret = posix_memalign((void **)&dr_qp->db, 8, 8);
	if (ret) {
		errno = ret;
		goto err_db_alloc;
	}

	dr_qp->db[MLX5_RCV_DBR] = 0;
	dr_qp->db[MLX5_SND_DBR] = 0;
	dr_qp->db_umem = mlx5dv_devx_umem_reg(ctx, dr_qp->db, 8,
					      IBV_ACCESS_LOCAL_WRITE |
					      IBV_ACCESS_REMOTE_WRITE |
					      IBV_ACCESS_REMOTE_READ);
	if (!dr_qp->db_umem)
		goto err_db_umem;

	dr_qp->buf_umem = mlx5dv_devx_umem_reg(ctx, dr_qp->buf.buf,
					       dr_qp->buf.length,
					       IBV_ACCESS_LOCAL_WRITE |
					       IBV_ACCESS_REMOTE_WRITE |
					       IBV_ACCESS_REMOTE_READ);
	if (!dr_qp->buf_umem)
		goto err_buf_umem;

	qp_create_attr.page_id = attr->uar->page_id;
	qp_create_attr.pdn = attr->pdn;
	qp_create_attr.cqn = attr->cqn;
	qp_create_attr.pm_state = MLX5_QPC_PM_STATE_MIGRATED;
	qp_create_attr.service_type = MLX5_QPC_ST_RC;
	qp_create_attr.buff_umem_id = dr_qp->buf_umem->umem_id;
	qp_create_attr.db_umem_id = dr_qp->db_umem->umem_id;
	qp_create_attr.sq_wqe_cnt = dr_qp->sq.wqe_cnt;
	qp_create_attr.rq_wqe_cnt = dr_qp->rq.wqe_cnt;
	qp_create_attr.rq_wqe_shift = dr_qp->rq.wqe_shift;
	qp_create_attr.isolate_vl_tc = attr->isolate_vl_tc;
	qp_create_attr.qp_ts_format = attr->qp_ts_format;

	obj = dr_devx_create_qp(ctx, &qp_create_attr);
	if (!obj)
		goto err_qp_create;

	dr_qp->uar = attr->uar;
	dr_qp->nc_uar = container_of(attr->uar, struct mlx5_bf,
				     devx_uar.dv_devx_uar)->nc_mode;
	dr_qp->obj = obj;

	return dr_qp;

err_qp_create:
	mlx5dv_devx_umem_dereg(dr_qp->buf_umem);
err_buf_umem:
	mlx5dv_devx_umem_dereg(dr_qp->db_umem);
err_db_umem:
	free(dr_qp->db);
err_db_alloc:
	free(dr_qp->sq.wqe_head);
	free(dr_qp->buf.buf);
err_alloc_bufs:
	free(dr_qp);
	return NULL;
}

static int dr_destroy_qp(struct dr_qp *dr_qp)
{
	int ret;

	ret = mlx5dv_devx_obj_destroy(dr_qp->obj);
	if (ret)
		return ret;

	ret = mlx5dv_devx_umem_dereg(dr_qp->buf_umem);
	if (ret)
		return ret;

	ret = mlx5dv_devx_umem_dereg(dr_qp->db_umem);
	if (ret)
		return ret;

	free(dr_qp->db);
	free(dr_qp->sq.wqe_head);
	free(dr_qp->buf.buf);
	free(dr_qp);

	return 0;
}

static void dr_set_raddr_seg(struct mlx5_wqe_raddr_seg *rseg,
			     uint64_t remote_addr, uint32_t rkey)
{
	rseg->raddr    = htobe64(remote_addr);
	rseg->rkey     = htobe32(rkey);
	rseg->reserved = 0;
}

static void dr_post_send_db(struct dr_qp *dr_qp, int size, void *ctrl)
{
	dr_qp->sq.head += 2; /* RDMA_WRITE + RDMA_READ */

	/*
	 * Make sure that descriptors are written before
	 * updating doorbell record and ringing the doorbell
	 */
	udma_to_device_barrier();
	dr_qp->db[MLX5_SND_DBR] = htobe32(dr_qp->sq.cur_post & 0xffff);
	if (dr_qp->nc_uar) {
		udma_to_device_barrier();
		mmio_write64_be((uint8_t *)dr_qp->uar->reg_addr, *(__be64 *)ctrl);
		return;
	}

	/* Make sure that the doorbell write happens before the memcpy
	 * to WC memory below
	 */
	mmio_wc_start();
	mmio_write64_be((uint8_t *)dr_qp->uar->reg_addr, *(__be64 *)ctrl);
	mmio_flush_writes();
}

static void dr_set_data_ptr_seg(struct mlx5_wqe_data_seg *dseg,
				struct dr_data_seg *data_seg)
{
	dseg->byte_count = htobe32(data_seg->length);
	dseg->lkey       = htobe32(data_seg->lkey);
	dseg->addr       = htobe64(data_seg->addr);
}

static int dr_set_data_inl_seg(struct dr_qp *dr_qp,
			       struct dr_data_seg *data_seg,
			       void *wqe, uint32_t opcode, int *sz)
{
	struct mlx5_wqe_inline_seg *seg;
	void *qend = dr_qp->sq.qend;
	int inl = 0;
	void *addr;
	int copy;
	int len;

	seg = wqe;
	wqe += sizeof(*seg);
	addr = (void *)(unsigned long)(data_seg->addr);
	len  = data_seg->length;
	inl += len;

	if (unlikely(wqe + len > qend)) {
		copy = qend - wqe;
		memcpy(wqe, addr, copy);
		addr += copy;
		len -= copy;
		wqe = dr_qp->sq_start;
	}
	memcpy(wqe, addr, len);
	wqe += len;

	if (likely(inl)) {
		seg->byte_count = htobe32(inl | MLX5_INLINE_SEG);
		*sz = align(inl + sizeof(seg->byte_count), 16) / 16;
	} else {
		*sz = 0;
	}

	return 0;
}

static void dr_set_ctrl_seg(struct mlx5_wqe_ctrl_seg *ctrl,
			    struct dr_data_seg *data_seg)
{
	*(uint32_t *)((void *)ctrl + 8) = 0;
	ctrl->imm = 0;
	ctrl->fm_ce_se = data_seg->send_flags & IBV_SEND_SIGNALED ?
		MLX5_WQE_CTRL_CQ_UPDATE : 0;
}

static void dr_rdma_segments(struct dr_qp *dr_qp, uint64_t remote_addr,
			     uint32_t rkey, struct dr_data_seg *data_seg,
			     uint32_t opcode, int nreq)
{
	struct mlx5_wqe_ctrl_seg *ctrl = NULL;
	void *qend = dr_qp->sq.qend;
	unsigned idx;
	int size = 0;
	void *seg;

	idx = dr_qp->sq.cur_post & (dr_qp->sq.wqe_cnt - 1);
	ctrl = dr_qp->sq_start + (idx << MLX5_SEND_WQE_SHIFT);
	seg = ctrl;
	dr_set_ctrl_seg(ctrl, data_seg);
	seg += sizeof(*ctrl);
	size = sizeof(*ctrl) / 16;

	dr_set_raddr_seg(seg, remote_addr, rkey);
	seg  += sizeof(struct mlx5_wqe_raddr_seg);
	size += sizeof(struct mlx5_wqe_raddr_seg) / 16;

	if (data_seg->send_flags & IBV_SEND_INLINE) {
		int uninitialized_var(sz);

		dr_set_data_inl_seg(dr_qp, data_seg, seg, opcode, &sz);
		size += sz;
	} else {
		if (unlikely(seg == qend))
			seg = dr_qp->sq_start;
		dr_set_data_ptr_seg(seg, data_seg);
		size += sizeof(struct mlx5_wqe_data_seg) / 16;
	}
	ctrl->opmod_idx_opcode =
		htobe32(((dr_qp->sq.cur_post & 0xffff) << 8) | opcode);
	ctrl->qpn_ds = htobe32(size | (dr_qp->obj->object_id << 8));
	dr_qp->sq.wqe_head[idx] = dr_qp->sq.head + nreq;
	dr_qp->sq.cur_post += DIV_ROUND_UP(size * 16, MLX5_SEND_WQE_BB);

	if (nreq)
		dr_post_send_db(dr_qp, size, ctrl);
}

static void dr_post_send(struct dr_qp *dr_qp, struct postsend_info *send_info)
{
	dr_rdma_segments(dr_qp, send_info->remote_addr, send_info->rkey,
			 &send_info->write, MLX5_OPCODE_RDMA_WRITE, 0);
	dr_rdma_segments(dr_qp, send_info->remote_addr, send_info->rkey,
			 &send_info->read, MLX5_OPCODE_RDMA_READ, 1);
}

/*
 * dr_send_fill_and_append_ste_send_info: Add data to be sent with send_list
 * parameters:
 * @ste - The data that attached to this specific ste
 * @size - of data to write
 * @offset - of the data from start of the hw_ste entry
 * @data - data
 * @ste_info - ste to be sent with send_list
 * @send_list - to append into it
 * @copy_data - if true indicates that the data should be kept because it's not
 *	       backuped any where (like in re-hash).
 *	       if false, it lets the data to be updated after it was added to
 *	       the list.
 */
void dr_send_fill_and_append_ste_send_info(struct dr_ste *ste, uint16_t size,
					   uint16_t offset, uint8_t *data,
					   struct dr_ste_send_info *ste_info,
					   struct list_head *send_list,
					   bool copy_data)
{
	ste_info->size		= size;
	ste_info->ste		= ste;
	ste_info->offset	= offset;

	if (copy_data) {
		memcpy(ste_info->data_cont, data, size);
		ste_info->data = ste_info->data_cont;
	} else {
		ste_info->data = data;
	}

	list_add_tail(send_list, &ste_info->send_list);
}

static bool dr_is_device_fatal(struct mlx5dv_dr_domain *dmn)
{
	struct mlx5_context *mlx5_ctx = to_mctx(dmn->ctx);

	if (mlx5_ctx->flags & MLX5_CTX_FLAGS_FATAL_STATE)
		return true;
	return false;
}

/*
 * The function tries to consume one wc each time, unless the queue is full, in
 * that case, which means that the hw is behind the sw in a full queue len
 * the function will drain the cq till it empty.
 */
static int dr_handle_pending_wc(struct mlx5dv_dr_domain *dmn,
				struct dr_send_ring *send_ring)
{
	bool is_drain = false;
	int ne;

	if (send_ring->pending_wqe >= send_ring->signal_th) {
		/* Queue is full start drain it */
		if (send_ring->pending_wqe >= send_ring->signal_th * TH_NUMS_TO_DRAIN)
			is_drain = true;

		do {
			/*
			 * On IBV_EVENT_DEVICE_FATAL a success is returned to
			 * let the application free its resources successfully
			 */
			if (dr_is_device_fatal(dmn))
				return 0;

			ne = dr_poll_cq(&send_ring->cq, 1);
			if (ne < 0) {
				dr_dbg(dmn, "poll CQ failed\n");
				return ne;
			} else if (ne == 1) {
				send_ring->pending_wqe -= send_ring->signal_th;
			}
		} while (is_drain && send_ring->pending_wqe);
	}

	return 0;
}

static void dr_fill_data_segs(struct dr_send_ring *send_ring,
			      struct postsend_info *send_info)
{
	unsigned int inline_flag;

	send_ring->pending_wqe++;
	if (!send_info->write.lkey)
		inline_flag = IBV_SEND_INLINE;
	else
		inline_flag = 0;

	send_info->write.send_flags = inline_flag;

	if (send_ring->pending_wqe % send_ring->signal_th == 0)
		send_info->write.send_flags |= IBV_SEND_SIGNALED;

	send_ring->pending_wqe++;
	send_info->read.length = send_info->write.length;

	/* Read into dedicated buffer */
	send_info->read.addr = (uintptr_t)send_ring->sync_buff;
	send_info->read.lkey = send_ring->sync_mr->lkey;

	if (send_ring->pending_wqe % send_ring->signal_th == 0)
		send_info->read.send_flags = IBV_SEND_SIGNALED;
	else
		send_info->read.send_flags = 0;
}

static int dr_postsend_icm_data(struct mlx5dv_dr_domain *dmn,
				struct postsend_info *send_info,
				int ring_idx)
{
	struct dr_send_ring *send_ring =
		dmn->send_ring[ring_idx % DR_MAX_SEND_RINGS];
	uint32_t buff_offset;
	int ret;

	pthread_spin_lock(&send_ring->lock);
	ret = dr_handle_pending_wc(dmn, send_ring);
	if (ret)
		goto out_unlock;

	if (send_info->write.length > dmn->info.max_inline_size) {
		buff_offset = (send_ring->tx_head & (send_ring->signal_th - 1)) *
			dmn->info.max_send_size;
		/* Copy to ring mr */
		memcpy(send_ring->buf + buff_offset,
		       (void *) (uintptr_t)send_info->write.addr,
		       send_info->write.length);
		send_info->write.addr	= (uintptr_t)send_ring->buf + buff_offset;
		send_info->write.lkey	= send_ring->mr->lkey;
	}

	send_ring->tx_head++;
	dr_fill_data_segs(send_ring, send_info);
	dr_post_send(send_ring->qp, send_info);

out_unlock:
	pthread_spin_unlock(&send_ring->lock);
	return ret;
}

static int dr_get_tbl_copy_details(struct mlx5dv_dr_domain *dmn,
				   struct dr_ste_htbl *htbl,
				   uint8_t **data,
				   uint32_t *byte_size,
				   int *iterations,
				   int *num_stes)
{
	int alloc_size;

	if (htbl->chunk->byte_size > dmn->info.max_send_size) {
		*iterations = htbl->chunk->byte_size / dmn->info.max_send_size;
		*byte_size = dmn->info.max_send_size;
		alloc_size = *byte_size;
		*num_stes = *byte_size / DR_STE_SIZE;
	} else {
		*iterations = 1;
		*num_stes = htbl->chunk->num_of_entries;
		alloc_size = *num_stes * DR_STE_SIZE;
	}

	*data = calloc(1, alloc_size);
	if (!*data) {
		errno = ENOMEM;
		return errno;
	}

	return 0;
}

/*
 * dr_postsend_ste: write size bytes into offset from the hw icm.
 *
 * Input:
 *     dmn     - Domain
 *     ste     - The ste struct that contains the data (at least part of it)
 *     data    - The real data to send
 *     size    - data size for writing.
 *     offset  - The offset from the icm mapped data to start write to.
 *               this for write only part of the buffer.
 *
 * Return: 0 on success.
 */
int dr_send_postsend_ste(struct mlx5dv_dr_domain *dmn, struct dr_ste *ste,
			 uint8_t *data, uint16_t size, uint16_t offset,
			 uint8_t ring_idx)
{
	struct postsend_info send_info = {};

	dr_ste_prepare_for_postsend(dmn->ste_ctx, data, size);

	send_info.write.addr    = (uintptr_t) data;
	send_info.write.length  = size;
	send_info.write.lkey    = 0;
	send_info.remote_addr   = dr_ste_get_mr_addr(ste) + offset;
	send_info.rkey          = ste->htbl->chunk->rkey;

	return dr_postsend_icm_data(dmn, &send_info, ring_idx);
}

int dr_send_postsend_htbl(struct mlx5dv_dr_domain *dmn, struct dr_ste_htbl *htbl,
			  uint8_t *formated_ste, uint8_t *mask,
			  uint8_t send_ring_idx)
{
	bool legacy_htbl = htbl->type == DR_STE_HTBL_TYPE_LEGACY;
	uint32_t byte_size = htbl->chunk->byte_size;
	int i, j, num_stes_per_iter, iterations;
	uint8_t ste_sz = htbl->ste_arr->size;
	uint8_t *data;
	int ret;

	ret = dr_get_tbl_copy_details(dmn, htbl, &data, &byte_size,
				      &iterations, &num_stes_per_iter);
	if (ret)
		return ret;

	dr_ste_prepare_for_postsend(dmn->ste_ctx, formated_ste, DR_STE_SIZE);

	/* Send the data iteration times */
	for (i = 0; i < iterations; i++) {
		uint32_t ste_index = i * (byte_size / DR_STE_SIZE);
		struct postsend_info send_info = {};

		/* Copy all ste's on the data buffer, need to add the bit_mask */
		for (j = 0; j < num_stes_per_iter; j++) {
			if (dr_ste_is_not_used(&htbl->ste_arr[ste_index + j])) {
				memcpy(data + (j * DR_STE_SIZE),
				       formated_ste, DR_STE_SIZE);
			} else {
				/* Copy data */
				memcpy(data + (j * DR_STE_SIZE),
				       htbl->ste_arr[ste_index + j].hw_ste,
				       ste_sz);
				/* Copy bit_mask on legacy tables */
				if (legacy_htbl)
					memcpy(data + (j * DR_STE_SIZE) + ste_sz,
					       mask, DR_STE_SIZE_MASK);

				/* Prepare STE to specific HW format */
				dr_ste_prepare_for_postsend(dmn->ste_ctx,
							    data + (j * DR_STE_SIZE),
							    DR_STE_SIZE);
			}
		}

		send_info.write.addr	= (uintptr_t) data;
		send_info.write.length	= byte_size;
		send_info.write.lkey	= 0;
		send_info.remote_addr	= dr_ste_get_mr_addr(htbl->ste_arr + ste_index);
		send_info.rkey		= htbl->chunk->rkey;

		ret = dr_postsend_icm_data(dmn, &send_info, send_ring_idx);
		if (ret)
			goto out_free;
	}

out_free:
	free(data);
	return ret;
}

/* Initialize htble with default STEs */
int dr_send_postsend_formated_htbl(struct mlx5dv_dr_domain *dmn,
				   struct dr_ste_htbl *htbl,
				   uint8_t *ste_init_data,
				   bool update_hw_ste,
				   uint8_t send_ring_idx)
{
	uint32_t byte_size = htbl->chunk->byte_size;
	int i, num_stes, iterations, ret;
	uint8_t *copy_dst;
	uint8_t *data;

	ret = dr_get_tbl_copy_details(dmn, htbl, &data, &byte_size,
				      &iterations, &num_stes);
	if (ret)
		return ret;

	if (update_hw_ste) {
		/* Copy the STE to hash table ste_arr */
		for (i = 0; i < num_stes; i++) {
			copy_dst = htbl->hw_ste_arr + i * htbl->ste_arr->size;
			memcpy(copy_dst, ste_init_data, htbl->ste_arr->size);
		}
	}

	dr_ste_prepare_for_postsend(dmn->ste_ctx, ste_init_data, DR_STE_SIZE);

	/* Copy the same STE on the data buffer */
	for (i = 0; i < num_stes; i++) {
		copy_dst = data + i * DR_STE_SIZE;
		memcpy(copy_dst, ste_init_data, DR_STE_SIZE);
	}

	/* Send the data iteration times */
	for (i = 0; i < iterations; i++) {
		uint32_t ste_index = i * (byte_size / DR_STE_SIZE);
		struct postsend_info send_info = {};

		send_info.write.addr	= (uintptr_t) data;
		send_info.write.length	= byte_size;
		send_info.write.lkey	= 0;
		send_info.remote_addr	= dr_ste_get_mr_addr(htbl->ste_arr + ste_index);
		send_info.rkey		= htbl->chunk->rkey;

		ret = dr_postsend_icm_data(dmn, &send_info, send_ring_idx);
		if (ret)
			goto out_free;
	}

out_free:
	free(data);
	return ret;
}

int dr_send_postsend_action(struct mlx5dv_dr_domain *dmn,
			    struct mlx5dv_dr_action *action)
{
	struct postsend_info send_info = {};
	int num_qps;
	int i, ret;

	num_qps = dmn->info.use_mqs ? DR_MAX_SEND_RINGS : 1;

	send_info.write.addr	= (uintptr_t) action->rewrite.data;
	send_info.write.length	= action->rewrite.num_of_actions *
				  DR_MODIFY_ACTION_SIZE;
	send_info.write.lkey	= 0;
	send_info.remote_addr	= action->rewrite.chunk->mr_addr;
	send_info.rkey		= action->rewrite.chunk->rkey;

	/* To avoid race between action creation and its use in other QP
	 * write it in all QP's.
	 */
	for (i = 0; i < num_qps; i++) {
		ret = dr_postsend_icm_data(dmn, &send_info, i);
		if (ret)
			return ret;
	}

	return 0;
}

bool dr_send_allow_fl(struct dr_devx_caps *caps)
{
	return ((caps->roce_caps.roce_en &&
		 caps->roce_caps.fl_rc_qp_when_roce_enabled) ||
		(!caps->roce_caps.roce_en &&
		 caps->roce_caps.fl_rc_qp_when_roce_disabled));
}

static int dr_send_get_qp_ts_format(struct dr_devx_caps *caps)
{
	/* Set the default TS format in case TS format is supported */
	return !caps->roce_caps.qp_ts_format ?
		MLX5_QPC_TIMESTAMP_FORMAT_FREE_RUNNING :
		MLX5_QPC_TIMESTAMP_FORMAT_DEFAULT;
}

static int dr_prepare_qp_to_rts(struct mlx5dv_dr_domain *dmn,
				struct dr_qp *dr_qp)
{
	struct dr_devx_qp_rts_attr rts_attr = {};
	struct dr_devx_qp_rtr_attr rtr_attr = {};
	enum ibv_mtu mtu = IBV_MTU_1024;
	uint16_t gid_index = 0;
	int port = 1;
	int ret;

	/* Init */
	ret = dr_devx_modify_qp_rst2init(dmn->ctx, dr_qp->obj, port);
	if (ret) {
		dr_dbg(dmn, "Failed to modify QP to INIT, ret: %d\n", ret);
		return ret;
	}

	/* RTR */
	rtr_attr.mtu		= mtu;
	rtr_attr.qp_num		= dr_qp->obj->object_id;
	rtr_attr.min_rnr_timer	= 12;
	rtr_attr.port_num	= port;

	/* Enable force-loopback on the QP */
	if (dr_send_allow_fl(&dmn->info.caps)) {
		rtr_attr.fl = true;
	} else {
		ret = dr_devx_query_gid(dmn->ctx, port, gid_index, &rtr_attr.dgid_attr);
		if (ret) {
			dr_dbg(dmn, "can't read sgid of index %d\n", gid_index);
			return ret;
		}
		rtr_attr.sgid_index = gid_index;
	}

	ret = dr_devx_modify_qp_init2rtr(dmn->ctx, dr_qp->obj,  &rtr_attr);
	if (ret) {
		dr_dbg(dmn, "Failed to modify QP to RTR, ret: %d\n", ret);
		return ret;
	}

	/* RTS */
	rts_attr.timeout	= 14;
	rts_attr.retry_cnt	= 7;
	rts_attr.rnr_retry	= 7;

	ret = dr_devx_modify_qp_rtr2rts(dmn->ctx, dr_qp->obj, &rts_attr);
	if (ret) {
		dr_dbg(dmn, "Failed to modify QP to RTS, ret: %d\n", ret);
		return ret;
	}

	return 0;
}

static void dr_send_ring_free_one(struct dr_send_ring *send_ring)
{
	dr_destroy_qp(send_ring->qp);
	ibv_destroy_cq(send_ring->cq.ibv_cq);
	ibv_dereg_mr(send_ring->sync_mr);
	ibv_dereg_mr(send_ring->mr);
	free(send_ring->buf);
	free(send_ring->sync_buff);
	free(send_ring);
}

void dr_send_ring_free(struct mlx5dv_dr_domain *dmn)
{
	int i;

	for (i = 0; i < DR_MAX_SEND_RINGS; i++)
		dr_send_ring_free_one(dmn->send_ring[i]);
}

/* Each domain has its own ib resources */
static int dr_send_ring_alloc_one(struct mlx5dv_dr_domain *dmn,
				  struct dr_send_ring **curr_send_ring)
{
	struct dr_qp_init_attr init_attr = {};
	struct dr_send_ring *send_ring;
	struct mlx5dv_pd mlx5_pd = {};
	struct mlx5dv_cq mlx5_cq = {};
	int cq_size, page_size;
	struct mlx5dv_obj obj;
	int size;
	int access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
			   IBV_ACCESS_REMOTE_READ;
	int ret;

	send_ring = calloc(1, sizeof(*send_ring));
	if (!send_ring) {
		dr_dbg(dmn, "Couldn't allocate send-ring\n");
		errno = ENOMEM;
		return errno;
	}

	ret = pthread_spin_init(&send_ring->lock, PTHREAD_PROCESS_PRIVATE);
	if (ret) {
		errno = ret;
		goto free_send_ring;
	}

	cq_size = QUEUE_SIZE + 1;
	send_ring->cq.ibv_cq = ibv_create_cq(dmn->ctx, cq_size, NULL, NULL, 0);
	if (!send_ring->cq.ibv_cq) {
		dr_dbg(dmn, "Failed to create CQ with %u entries\n", cq_size);
		ret = ENODEV;
		errno = ENODEV;
		goto free_send_ring;
	}

	obj.cq.in = send_ring->cq.ibv_cq;
	obj.cq.out = &mlx5_cq;

	ret = mlx5dv_init_obj(&obj, MLX5DV_OBJ_CQ);
	if (ret)
		goto clean_cq;

	send_ring->cq.buf = mlx5_cq.buf;
	send_ring->cq.db = mlx5_cq.dbrec;
	send_ring->cq.ncqe = mlx5_cq.cqe_cnt;
	send_ring->cq.cqe_sz = mlx5_cq.cqe_size;

	obj.pd.in = dmn->pd;
	obj.pd.out = &mlx5_pd;

	ret = mlx5dv_init_obj(&obj, MLX5DV_OBJ_PD);
	if (ret)
		goto clean_cq;

	init_attr.cqn			= mlx5_cq.cqn;
	init_attr.pdn			= mlx5_pd.pdn;
	init_attr.uar			= dmn->uar;
	init_attr.cap.max_send_wr	= QUEUE_SIZE;
	init_attr.cap.max_recv_wr	= 1;
	init_attr.cap.max_send_sge	= 1;
	init_attr.cap.max_recv_sge	= 1;
	init_attr.cap.max_inline_data	= DR_STE_SIZE;
	init_attr.qp_ts_format		= dr_send_get_qp_ts_format(&dmn->info.caps);

	/* Isolated VL is applicable only if force LB is supported */
	if (dr_send_allow_fl(&dmn->info.caps))
		init_attr.isolate_vl_tc = dmn->info.caps.isolate_vl_tc;

	send_ring->qp = dr_create_rc_qp(dmn->ctx, &init_attr);
	if (!send_ring->qp)  {
		dr_dbg(dmn, "Couldn't create QP\n");
		ret = errno;
		goto clean_cq;
	}

	send_ring->cq.qp = send_ring->qp;
	send_ring->max_inline_size = min(send_ring->qp->max_inline_data, DR_STE_SIZE);
	send_ring->signal_th = QUEUE_SIZE / SIGNAL_PER_DIV_QUEUE;

	/* Prepare qp to be used */
	ret = dr_prepare_qp_to_rts(dmn, send_ring->qp);
	if (ret) {
		dr_dbg(dmn, "Couldn't prepare QP\n");
		goto clean_qp;
	}

	/* Allocating the max size as a buffer for writing */
	size = send_ring->signal_th * dmn->info.max_send_size;
	page_size = sysconf(_SC_PAGESIZE);
	ret = posix_memalign(&send_ring->buf, page_size, size);
	if (ret) {
		dr_dbg(dmn, "Couldn't allocate send-ring buf.\n");
		errno = ret;
		goto clean_qp;
	}

	memset(send_ring->buf, 0, size);
	send_ring->buf_size = size;

	send_ring->mr = ibv_reg_mr(dmn->pd, send_ring->buf, size, access_flags);
	if (!send_ring->mr) {
		dr_dbg(dmn, "Couldn't register send-ring MR\n");
		ret = errno;
		goto free_mem;
	}

	ret = posix_memalign(&send_ring->sync_buff, page_size,
			     dmn->info.max_send_size);
	if (ret) {
		dr_dbg(dmn, "Couldn't allocate send-ring sync_buf.\n");
		errno = ret;
		goto clean_mr;
	}

	send_ring->sync_mr = ibv_reg_mr(dmn->pd, send_ring->sync_buff,
					dmn->info.max_send_size,
					IBV_ACCESS_LOCAL_WRITE |
					IBV_ACCESS_REMOTE_READ |
					IBV_ACCESS_REMOTE_WRITE);
	if (!send_ring->sync_mr) {
		dr_dbg(dmn, "Couldn't register sync mr\n");
		ret = errno;
		goto clean_sync_buf;
	}

	*curr_send_ring = send_ring;

	return 0;

clean_sync_buf:
	free(send_ring->sync_buff);
clean_mr:
	ibv_dereg_mr(send_ring->mr);
free_mem:
	free(send_ring->buf);
clean_qp:
	dr_destroy_qp(send_ring->qp);
clean_cq:
	ibv_destroy_cq(send_ring->cq.ibv_cq);
free_send_ring:
	free(send_ring);

	return ret;
}

int dr_send_ring_alloc(struct mlx5dv_dr_domain *dmn)
{
	int i, ret;

	dmn->info.max_send_size =
		dr_icm_pool_chunk_size_to_byte(DR_CHUNK_SIZE_1K,
					       DR_ICM_TYPE_STE);

	for (i = 0; i < DR_MAX_SEND_RINGS; i++) {
		ret = dr_send_ring_alloc_one(dmn, &dmn->send_ring[i]);
		if (ret) {
			dr_dbg(dmn, "Couldn't allocate send-rings id[%d]\n", i);
			goto free_send_ring;
		}
	}

	return 0;

free_send_ring:
	for (; i > 0; i--)
		dr_send_ring_free_one(dmn->send_ring[i - 1]);

	return ret;
}

int dr_send_ring_force_drain(struct mlx5dv_dr_domain *dmn)
{
	struct dr_send_ring *send_ring = dmn->send_ring[0];
	struct postsend_info send_info = {};
	int i, j, num_of_sends_req;
	uint8_t data[DR_STE_SIZE];
	int num_qps;
	int ret;

	num_qps = dmn->info.use_mqs ? DR_MAX_SEND_RINGS : 1;

	/* Sending this amount of requests makes sure we will get drain */
	num_of_sends_req = send_ring->signal_th * TH_NUMS_TO_DRAIN / 2;

	/* Send fake requests forcing the last to be signaled */
	send_info.write.addr	= (uintptr_t) data;
	send_info.write.length	= DR_STE_SIZE;
	send_info.write.lkey	= 0;
	/* Using the sync_mr in order to write/read */
	send_info.remote_addr	= (uintptr_t) send_ring->sync_mr->addr;
	send_info.rkey		= send_ring->sync_mr->rkey;

	for (i = 0; i < num_of_sends_req; i++) {
		for (j = 0; j < num_qps; j++) {
			ret = dr_postsend_icm_data(dmn, &send_info, j);
			if (ret)
				return ret;
		}
	}

	return 0;
}
