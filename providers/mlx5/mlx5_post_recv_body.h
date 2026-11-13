/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

/*
 * post_recv body shared by the generic (qp.c) and adversarial
 * (mlx5_adversarial.c) variants. Define ADVERSARIAL_POST_RECV before
 * including it to build the adversarial variant.
 */

#ifndef MLX5_POST_RECV_BODY_H
#define MLX5_POST_RECV_BODY_H

static inline __attribute__((always_inline))
int _mlx5_post_recv_body(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
			 struct ibv_recv_wr **bad_wr)
{
	struct mlx5_qp *qp = to_mqp(ibqp);
	struct mlx5_wqe_data_seg *scat;
	int err = 0;
	int nreq;
	int ind;
	int i, j;
#ifndef ADVERSARIAL_POST_RECV
	struct mlx5_rwqe_sig *sig;
#endif

	mlx5_spin_lock(&qp->rq.lock);

	ind = qp->rq.head & (qp->rq.wqe_cnt - 1);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (unlikely(mlx5_wq_overflow(&qp->rq, nreq,
					      to_mcq(qp->ibv_qp->recv_cq)))) {
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->num_sge > qp->rq.qp_state_max_gs)) {
			err = EINVAL;
			*bad_wr = wr;
			goto out;
		}

#ifdef ADVERSARIAL_POST_RECV
		/* The device may leave an old slot in flight past an rq.head
		 * wrap; refuse rather than overwrite its WQE and wr_id. The
		 * acquire pairs with the release in adv_rq_commit().
		 */
		if (qp->rq.in_flight &&
		    unlikely(__atomic_load_n(&qp->rq.in_flight[ind],
					     __ATOMIC_ACQUIRE))) {
			err = ENOMEM;
			*bad_wr = wr;
			goto out;
		}
#endif

		scat = mlx5_get_recv_wqe(qp, ind);
#ifndef ADVERSARIAL_POST_RECV
		sig = (struct mlx5_rwqe_sig *)scat;
		if (unlikely(qp->wq_sig)) {
			memset(sig, 0, 1 << qp->rq.wqe_shift);
			++scat;
		}
#endif

		for (i = 0, j = 0; i < wr->num_sge; ++i) {
			if (unlikely(!wr->sg_list[i].length))
				continue;
			mlx5_set_data_ptr_seg(scat + j++, wr->sg_list + i, 0);
		}

		if (j < qp->rq.max_gs) {
			scat[j].byte_count = 0;
			scat[j].lkey       = htobe32(MLX5_INVALID_LKEY);
			scat[j].addr       = 0;
		}

#ifndef ADVERSARIAL_POST_RECV
		if (unlikely(qp->wq_sig))
			set_sig_seg(qp, sig, (wr->num_sge + 1) << 4,
				    qp->rq.head & 0xffff);
#endif

		qp->rq.wrid[ind] = wr->wr_id;
#ifdef ADVERSARIAL_POST_RECV
		if (qp->rq.in_flight)
			qp->rq.in_flight[ind] = 1;
#endif

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

#ifndef ADVERSARIAL_POST_RECV
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
#endif
			qp->db[MLX5_RCV_DBR] = htobe32(qp->rq.head & 0xffff);
	}

	mlx5_spin_unlock(&qp->rq.lock);

	return err;
}

#endif /* MLX5_POST_RECV_BODY_H */
