// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause

// Authors: Bernard Metzler <bmt@zurich.ibm.com>
// Copyright (c) 2008-2019, IBM Corporation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <net/if.h>
#include <pthread.h>
#include <stdatomic.h>
#include <assert.h>

#include "siw_abi.h"
#include "siw.h"

static const int siw_debug;
static void siw_free_context(struct ibv_context *ibv_ctx);

static int siw_query_device(struct ibv_context *ctx,
			    struct ibv_device_attr *attr)
{
	struct ibv_query_device cmd;
	uint64_t raw_fw_ver;
	unsigned int major, minor, sub_minor;
	int rv;

	memset(&cmd, 0, sizeof(cmd));

	rv = ibv_cmd_query_device(ctx, attr, &raw_fw_ver, &cmd, sizeof(cmd));
	if (rv)
		return rv;

	major = (raw_fw_ver >> 32) & 0xffff;
	minor = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(attr->fw_ver, sizeof(attr->fw_ver), "%d.%d.%d", major, minor,
		 sub_minor);

	return 0;
}

static int siw_query_port(struct ibv_context *ctx, uint8_t port,
			  struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	memset(&cmd, 0, sizeof(cmd));

	return ibv_cmd_query_port(ctx, port, attr, &cmd, sizeof(cmd));
}

static int siw_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
			int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	memset(&cmd, 0, sizeof(cmd));

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr, &cmd,
				sizeof(cmd));
}

static struct ibv_pd *siw_alloc_pd(struct ibv_context *ctx)
{
	struct ibv_alloc_pd cmd;
	struct ib_uverbs_alloc_pd_resp resp;
	struct ibv_pd *pd;

	memset(&cmd, 0, sizeof(cmd));

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(ctx, pd, &cmd, sizeof(cmd), &resp, sizeof(resp))) {
		free(pd);
		return NULL;
	}
	return pd;
}

static int siw_free_pd(struct ibv_pd *pd)
{
	int rv;

	rv = ibv_cmd_dealloc_pd(pd);
	if (rv)
		return rv;

	free(pd);
	return 0;
}

static struct ibv_mr *siw_reg_mr(struct ibv_pd *pd, void *addr, size_t len,
				 uint64_t hca_va, int access)
{
	struct siw_cmd_reg_mr cmd = {};
	struct siw_cmd_reg_mr_resp resp = {};
	struct siw_mr *mr;
	int rv;

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return NULL;

	rv = ibv_cmd_reg_mr(pd, addr, len, hca_va, access,
			    &mr->base_mr, &cmd.ibv_cmd, sizeof(cmd),
			    &resp.ibv_resp, sizeof(resp));
	if (rv) {
		free(mr);
		return NULL;
	}
	return &mr->base_mr.ibv_mr;
}

static int siw_dereg_mr(struct verbs_mr *base_mr)
{
	struct siw_mr *mr = mr_base2siw(base_mr);
	int rv;

	rv = ibv_cmd_dereg_mr(base_mr);
	if (rv)
		return rv;

	free(mr);
	return 0;
}

static struct ibv_cq *siw_create_cq(struct ibv_context *ctx, int num_cqe,
				    struct ibv_comp_channel *channel,
				    int comp_vector)
{
	struct siw_cmd_create_cq cmd = {};
	struct siw_cmd_create_cq_resp resp = {};
	struct siw_cq *cq;
	int cq_size, rv;

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	rv = ibv_cmd_create_cq(ctx, num_cqe, channel, comp_vector, &cq->base_cq,
			       &cmd.ibv_cmd, sizeof(cmd), &resp.ibv_resp,
			       sizeof(resp));
	if (rv) {
		if (siw_debug)
			printf("libsiw: CQ creation failed: %d\n", rv);
		free(cq);
		return NULL;
	}
	if (resp.cq_key == SIW_INVAL_UOBJ_KEY) {
		if (siw_debug)
			printf("libsiw: prepare CQ mapping failed\n");
		goto fail;
	}
	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);
	cq->id = resp.cq_id;
	cq->num_cqe = resp.num_cqe;

	cq_size = resp.num_cqe * sizeof(struct siw_cqe) +
		  sizeof(struct siw_cq_ctrl);

	cq->queue = mmap(NULL, cq_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, ctx->cmd_fd, resp.cq_key);

	if (cq->queue == MAP_FAILED) {
		if (siw_debug)
			printf("libsiw: CQ mapping failed: %d", errno);
		goto fail;
	}
	cq->ctrl = (struct siw_cq_ctrl *)&cq->queue[cq->num_cqe];
	cq->ctrl->flags = SIW_NOTIFY_NOT;

	return &cq->base_cq;
fail:
	ibv_cmd_destroy_cq(&cq->base_cq);
	free(cq);

	return NULL;
}

static int siw_resize_cq(struct ibv_cq *base_cq, int num_cqe)
{
	return -EOPNOTSUPP;
}

static int siw_destroy_cq(struct ibv_cq *base_cq)
{
	struct siw_cq *cq = cq_base2siw(base_cq);
	int rv;

	assert(pthread_spin_trylock(&cq->lock));

	if (cq->queue)
		munmap(cq->queue, cq->num_cqe * sizeof(struct siw_cqe) +
					  sizeof(struct siw_cq_ctrl));

	rv = ibv_cmd_destroy_cq(base_cq);
	if (rv) {
		pthread_spin_unlock(&cq->lock);
		return rv;
	}
	pthread_spin_destroy(&cq->lock);

	free(cq);

	return 0;
}

static struct ibv_srq *siw_create_srq(struct ibv_pd *pd,
				      struct ibv_srq_init_attr *attr)
{
	struct siw_cmd_create_srq cmd = {};
	struct siw_cmd_create_srq_resp resp = {};
	struct ibv_context *ctx = pd->context;
	struct siw_srq *srq;
	int rv, rq_size;

	srq = calloc(1, sizeof(*srq));
	if (!srq)
		return NULL;

	rv = ibv_cmd_create_srq(pd, &srq->base_srq, attr, &cmd.ibv_cmd,
				sizeof(cmd), &resp.ibv_resp, sizeof(resp));
	if (rv) {
		if (siw_debug)
			printf("libsiw: creating SRQ failed\n");
		free(srq);
		return NULL;
	}
	if (resp.srq_key == SIW_INVAL_UOBJ_KEY) {
		if (siw_debug)
			printf("libsiw: prepare SRQ mapping failed\n");
		goto fail;
	}
	pthread_spin_init(&srq->lock, PTHREAD_PROCESS_PRIVATE);
	rq_size = resp.num_rqe * sizeof(struct siw_rqe);
	srq->num_rqe = resp.num_rqe;

	srq->recvq = mmap(NULL, rq_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, ctx->cmd_fd, resp.srq_key);

	if (srq->recvq == MAP_FAILED) {
		if (siw_debug)
			printf("libsiw: SRQ mapping failed: %d", errno);
		goto fail;
	}
	return &srq->base_srq;
fail:
	ibv_cmd_destroy_srq(&srq->base_srq);
	free(srq);

	return NULL;
}

static int siw_modify_srq(struct ibv_srq *base_srq, struct ibv_srq_attr *attr,
			  int attr_mask)
{
	struct ibv_modify_srq cmd = {};
	struct siw_srq *srq = srq_base2siw(base_srq);
	int rv;

	pthread_spin_lock(&srq->lock);
	rv = ibv_cmd_modify_srq(base_srq, attr, attr_mask, &cmd, sizeof(cmd));
	pthread_spin_unlock(&srq->lock);

	return rv;
}

static int siw_destroy_srq(struct ibv_srq *base_srq)
{
	struct siw_srq *srq = srq_base2siw(base_srq);
	int rv;

	assert(pthread_spin_trylock(&srq->lock));

	rv = ibv_cmd_destroy_srq(base_srq);
	if (rv) {
		pthread_spin_unlock(&srq->lock);
		return rv;
	}
	if (srq->recvq)
		munmap(srq->recvq, srq->num_rqe * sizeof(struct siw_rqe));

	pthread_spin_destroy(&srq->lock);

	free(srq);

	return 0;
}

static struct ibv_qp *siw_create_qp(struct ibv_pd *pd,
				    struct ibv_qp_init_attr *attr)
{
	struct siw_cmd_create_qp cmd = {};
	struct siw_cmd_create_qp_resp resp = {};
	struct siw_qp *qp;
	struct ibv_context *base_ctx = pd->context;
	int sq_size, rq_size, rv;

	memset(&cmd, 0, sizeof(cmd));
	memset(&resp, 0, sizeof(resp));

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	rv = ibv_cmd_create_qp(pd, &qp->base_qp, attr, &cmd.ibv_cmd,
			       sizeof(cmd), &resp.ibv_resp, sizeof(resp));

	if (rv) {
		if (siw_debug)
			printf("libsiw: QP creation failed\n");
		free(qp);
		return NULL;
	}
	if (resp.sq_key == SIW_INVAL_UOBJ_KEY ||
	    resp.rq_key == SIW_INVAL_UOBJ_KEY) {
		if (siw_debug)
			printf("libsiw: prepare QP mapping failed\n");
		goto fail;
	}
	qp->id = resp.qp_id;
	qp->num_sqe = resp.num_sqe;
	qp->num_rqe = resp.num_rqe;
	qp->sq_sig_all = attr->sq_sig_all;

	/* Init doorbell request structure */
	qp->db_req.hdr.command = IB_USER_VERBS_CMD_POST_SEND;
	qp->db_req.hdr.in_words = sizeof(qp->db_req) / 4;
	qp->db_req.hdr.out_words = sizeof(qp->db_resp) / 4;
	qp->db_req.response = (uintptr_t)&qp->db_resp;
	qp->db_req.wr_count = 0;
	qp->db_req.sge_count = 0;
	qp->db_req.wqe_size = sizeof(struct ibv_send_wr);

	pthread_spin_init(&qp->sq_lock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&qp->rq_lock, PTHREAD_PROCESS_PRIVATE);

	sq_size = resp.num_sqe * sizeof(struct siw_sqe);

	qp->sendq = mmap(NULL, sq_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, base_ctx->cmd_fd, resp.sq_key);

	if (qp->sendq == MAP_FAILED) {
		if (siw_debug)
			printf("libsiw: SQ mapping failed: %d", errno);

		qp->sendq = NULL;
		goto fail;
	}
	if (attr->srq) {
		qp->srq = srq_base2siw(attr->srq);
	} else {
		rq_size = resp.num_rqe * sizeof(struct siw_rqe);

		qp->recvq = mmap(NULL, rq_size, PROT_READ | PROT_WRITE,
				 MAP_SHARED, base_ctx->cmd_fd, resp.rq_key);

		if (qp->recvq == MAP_FAILED) {
			if (siw_debug)
				printf("libsiw: RQ mapping failed: %d\n",
				       resp.num_rqe);
			qp->recvq = NULL;
			goto fail;
		}
	}
	qp->db_req.qp_handle = qp->base_qp.handle;

	return &qp->base_qp;
fail:
	ibv_cmd_destroy_qp(&qp->base_qp);

	if (qp->sendq)
		munmap(qp->sendq, qp->num_sqe * sizeof(struct siw_sqe));
	if (qp->recvq)
		munmap(qp->recvq, qp->num_rqe * sizeof(struct siw_rqe));

	free(qp);

	return NULL;
}

static int siw_modify_qp(struct ibv_qp *base_qp, struct ibv_qp_attr *attr,
			 int attr_mask)
{
	struct ibv_modify_qp cmd;
	struct siw_qp *qp = qp_base2siw(base_qp);
	int rv;

	memset(&cmd, 0, sizeof(cmd));

	pthread_spin_lock(&qp->sq_lock);
	pthread_spin_lock(&qp->rq_lock);

	rv = ibv_cmd_modify_qp(base_qp, attr, attr_mask, &cmd, sizeof(cmd));

	pthread_spin_unlock(&qp->rq_lock);
	pthread_spin_unlock(&qp->sq_lock);

	return rv;
}

static int siw_destroy_qp(struct ibv_qp *base_qp)
{
	struct siw_qp *qp = qp_base2siw(base_qp);
	int rv;

	assert(pthread_spin_trylock(&qp->sq_lock));
	assert(pthread_spin_trylock(&qp->rq_lock));

	if (qp->sendq)
		munmap(qp->sendq, qp->num_sqe * sizeof(struct siw_sqe));
	if (qp->recvq)
		munmap(qp->recvq, qp->num_rqe * sizeof(struct siw_rqe));

	rv = ibv_cmd_destroy_qp(base_qp);
	if (rv) {
		pthread_spin_unlock(&qp->rq_lock);
		pthread_spin_unlock(&qp->sq_lock);
		return rv;
	}
	pthread_spin_destroy(&qp->rq_lock);
	pthread_spin_destroy(&qp->sq_lock);

	free(qp);

	return 0;
}

static struct ibv_ah *siw_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	return NULL;
}

static int siw_destroy_ah(struct ibv_ah *ah)
{
	return -EOPNOTSUPP;
}

static void siw_async_event(struct ibv_context *ctx,
			    struct ibv_async_event *event)
{
	struct ibv_qp *base_qp = event->element.qp;
	struct ibv_cq *base_cq = event->element.cq;

	switch (event->event_type) {
	case IBV_EVENT_CQ_ERR:
		printf("libsiw: CQ[%d] event: error\n",
		       cq_base2siw(base_cq)->id);
		break;

	case IBV_EVENT_QP_FATAL:
		printf("libsiw: QP[%d] event: fatal error\n",
		       qp_base2siw(base_qp)->id);
		break;

	case IBV_EVENT_QP_REQ_ERR:
		printf("libsiw: QP[%d] event: request error\n",
		       qp_base2siw(base_qp)->id);
		break;

	case IBV_EVENT_QP_ACCESS_ERR:
		printf("libsiw: QP[%d] event: access error\n",
		       qp_base2siw(base_qp)->id);
		break;

	case IBV_EVENT_SQ_DRAINED:
	case IBV_EVENT_COMM_EST:
	case IBV_EVENT_QP_LAST_WQE_REACHED:
		break;

	default:
		break;
	}
}

static int siw_notify_cq(struct ibv_cq *ibcq, int solicited)
{
	struct siw_cq *cq = cq_base2siw(ibcq);
	int rv = 0;

	if (solicited)
		atomic_store((_Atomic(uint32_t) *)&cq->ctrl->flags,
			SIW_NOTIFY_SOLICITED);
	else
		atomic_store((_Atomic(uint32_t) *)&cq->ctrl->flags,
			SIW_NOTIFY_SOLICITED | SIW_NOTIFY_NEXT_COMPLETION);
	return rv;
}

static const struct {
	enum ibv_wr_opcode base;
	enum siw_opcode siw;
} map_send_opcode[IBV_WR_DRIVER1 + 1] = {
	{ IBV_WR_RDMA_WRITE, SIW_OP_WRITE},
	{ IBV_WR_RDMA_WRITE_WITH_IMM, SIW_NUM_OPCODES + 1 },
	{ IBV_WR_SEND, SIW_OP_SEND },
	{ IBV_WR_SEND_WITH_IMM, SIW_NUM_OPCODES + 1 },
	{ IBV_WR_RDMA_READ, SIW_OP_READ },
	{ IBV_WR_ATOMIC_CMP_AND_SWP, SIW_NUM_OPCODES + 1 },
	{ IBV_WR_ATOMIC_FETCH_AND_ADD, SIW_NUM_OPCODES + 1 },
	{ IBV_WR_LOCAL_INV, SIW_NUM_OPCODES + 1 },
	{ IBV_WR_BIND_MW, SIW_NUM_OPCODES + 1 },
	{ IBV_WR_SEND_WITH_INV, SIW_OP_SEND_REMOTE_INV },
	{ IBV_WR_TSO, SIW_NUM_OPCODES + 1 },
	{ IBV_WR_DRIVER1, SIW_NUM_OPCODES + 1 }
};

static inline uint16_t map_send_flags(int ibv_flags)
{
	uint16_t flags = SIW_WQE_VALID;

	if (ibv_flags & IBV_SEND_SIGNALED)
		flags |= SIW_WQE_SIGNALLED;
	if (ibv_flags & IBV_SEND_SOLICITED)
		flags |= SIW_WQE_SOLICITED;
	if (ibv_flags & IBV_SEND_INLINE)
		flags |= SIW_WQE_INLINE;
	if (ibv_flags & IBV_SEND_FENCE)
		flags |= SIW_WQE_READ_FENCE;

	return flags;
}

static inline int push_send_wqe(struct ibv_send_wr *base_wr,
				struct siw_sqe *siw_sqe, int sig_all)
{
	uint32_t flags = map_send_flags(base_wr->send_flags);
	atomic_ushort *fp = (atomic_ushort *)&siw_sqe->flags;

	siw_sqe->id = base_wr->wr_id;
	siw_sqe->num_sge = base_wr->num_sge;
	siw_sqe->raddr = base_wr->wr.rdma.remote_addr;
	siw_sqe->rkey = base_wr->wr.rdma.rkey;

	siw_sqe->opcode = map_send_opcode[base_wr->opcode].siw;
	if (siw_sqe->opcode > SIW_NUM_OPCODES) {
		if (siw_debug)
			printf("libsiw: opcode %d unsupported\n",
			       base_wr->opcode);
		return -EINVAL;
	}
	if (sig_all)
		flags |= SIW_WQE_SIGNALLED;

	if (flags & SIW_WQE_INLINE) {
		char *data = (char *)&siw_sqe->sge[1];
		int bytes = 0, i = 0;

		/* Allow more than SIW_MAX_SGE, since content copied here */
		while (i < base_wr->num_sge) {
			bytes += base_wr->sg_list[i].length;
			if (bytes > (int)SIW_MAX_INLINE) {
				if (siw_debug)
					printf("libsiw: inline data: %d:%d\n",
					       bytes, (int)SIW_MAX_INLINE);
				return -EINVAL;
			}
			memcpy(data,
			       (void *)(uintptr_t)base_wr->sg_list[i].addr,
			       base_wr->sg_list[i].length);
			data += base_wr->sg_list[i++].length;
		}
		siw_sqe->sge[0].length = bytes;

	} else {
		if (siw_sqe->num_sge > SIW_MAX_SGE)
			return -EINVAL;

		/* this assumes same layout of siw and base SGE */
		memcpy(siw_sqe->sge, base_wr->sg_list,
		       siw_sqe->num_sge * sizeof(struct ibv_sge));
	}
	atomic_store(fp, flags);

	return 0;
}

static int siw_post_send(struct ibv_qp *base_qp, struct ibv_send_wr *wr,
			 struct ibv_send_wr **bad_wr)
{
	struct siw_qp *qp = qp_base2siw(base_qp);
	uint32_t sq_put;
	atomic_ushort *fp;
	int new_sqe = 0, rv = 0;

	*bad_wr = NULL;

	pthread_spin_lock(&qp->sq_lock);

	sq_put = qp->sq_put;

	/*
	 * Push all current work requests into mmapped SQ
	 */
	while (wr) {
		uint32_t idx = sq_put % qp->num_sqe;
		struct siw_sqe *sqe = &qp->sendq[idx];
		uint16_t sqe_flags;

		fp = (atomic_ushort *)&sqe->flags;
		sqe_flags = atomic_load(fp);

		if (!(sqe_flags & SIW_WQE_VALID)) {
			rv = push_send_wqe(wr, sqe, qp->sq_sig_all);
			if (rv) {
				*bad_wr = wr;
				break;
			}
			new_sqe++;
		} else {
			if (siw_debug)
				printf("libsiw: QP[%d]: SQ overflow, idx %d\n",
				       qp->id, idx);
			rv = -ENOMEM;
			*bad_wr = wr;
			break;
		}
		sq_put++;
		wr = wr->next;
	}
	if (new_sqe) {
		/*
		 * If last WQE pushed before position where current post_send
		 * started is idle, we assume SQ is not being actively
		 * processed. Only then, the doorbell call will be issued.
		 * This may significantly reduce unnecessary doorbell calls
		 * on a busy SQ. We also always ring the doorbell, if the
		 * complete SQ was re-written during current post_send.
		 */
		if (new_sqe < qp->num_sqe) {
			uint32_t old_idx = (qp->sq_put - 1) % qp->num_sqe;
			struct siw_sqe *old_sqe = &qp->sendq[old_idx];

			fp = (atomic_ushort *)&old_sqe->flags;
			if (!(atomic_load(fp) & SIW_WQE_VALID))
				rv = siw_db(qp);
		} else {
			rv = siw_db(qp);
		}
		if (rv)
			*bad_wr = wr;

		qp->sq_put = sq_put;
	}
	pthread_spin_unlock(&qp->sq_lock);

	return rv;
}

static inline int push_recv_wqe(struct ibv_recv_wr *base_wr,
				struct siw_rqe *siw_rqe)
{
	atomic_ushort *fp = (atomic_ushort *)&siw_rqe->flags;

	siw_rqe->id = base_wr->wr_id;
	siw_rqe->num_sge = base_wr->num_sge;

	if (base_wr->num_sge == 1) {
		siw_rqe->sge[0].laddr = base_wr->sg_list[0].addr;
		siw_rqe->sge[0].length = base_wr->sg_list[0].length;
		siw_rqe->sge[0].lkey = base_wr->sg_list[0].lkey;
	} else if (base_wr->num_sge && base_wr->num_sge <= SIW_MAX_SGE)
		/* this assumes same layout of siw and base SGE */
		memcpy(siw_rqe->sge, base_wr->sg_list,
		       sizeof(struct ibv_sge) * base_wr->num_sge);
	else
		return -EINVAL;

	atomic_store(fp, SIW_WQE_VALID);

	return 0;
}

static int siw_post_recv(struct ibv_qp *base_qp, struct ibv_recv_wr *wr,
			 struct ibv_recv_wr **bad_wr)
{
	struct siw_qp *qp = qp_base2siw(base_qp);
	uint32_t rq_put;
	int rv = 0;

	pthread_spin_lock(&qp->rq_lock);

	rq_put = qp->rq_put;

	while (wr) {
		int idx = rq_put % qp->num_rqe;
		struct siw_rqe *rqe = &qp->recvq[idx];
		atomic_ushort *fp = (atomic_ushort *)&rqe->flags;
		uint16_t rqe_flags = atomic_load(fp);

		if (!(rqe_flags & SIW_WQE_VALID)) {
			if (push_recv_wqe(wr, rqe)) {
				*bad_wr = wr;
				rv = -EINVAL;
				break;
			}
		} else {
			if (siw_debug)
				printf("libsiw: QP[%d]: RQ overflow, idx %d\n",
				       qp->id, idx);
			rv = -ENOMEM;
			*bad_wr = wr;
			break;
		}
		rq_put++;
		wr = wr->next;
	}
	qp->rq_put = rq_put;

	pthread_spin_unlock(&qp->rq_lock);

	return rv;
}

static int siw_post_srq_recv(struct ibv_srq *base_srq, struct ibv_recv_wr *wr,
			     struct ibv_recv_wr **bad_wr)
{
	struct siw_srq *srq = srq_base2siw(base_srq);
	uint32_t srq_put;
	int rv = 0;

	pthread_spin_lock(&srq->lock);

	srq_put = srq->rq_put;

	while (wr) {
		int idx = srq_put % srq->num_rqe;
		struct siw_rqe *rqe = &srq->recvq[idx];
		atomic_ushort *fp = (atomic_ushort *)&rqe->flags;
		uint16_t rqe_flags = atomic_load(fp);

		if (!(rqe_flags & SIW_WQE_VALID)) {
			if (push_recv_wqe(wr, rqe)) {
				*bad_wr = wr;
				rv = -EINVAL;
				break;
			}
		} else {
			if (siw_debug)
				printf("libsiw: SRQ[%p]: SRQ overflow\n", srq);
			rv = -ENOMEM;
			*bad_wr = wr;
			break;
		}
		srq_put++;
		wr = wr->next;
	}
	srq->rq_put = srq_put;

	pthread_spin_unlock(&srq->lock);

	return rv;
}

static const struct {
	enum siw_opcode siw;
	enum ibv_wc_opcode base;
} map_cqe_opcode[SIW_NUM_OPCODES] = {
	{ SIW_OP_WRITE, IBV_WC_RDMA_WRITE },
	{ SIW_OP_READ, IBV_WC_RDMA_READ },
	{ SIW_OP_READ_LOCAL_INV, IBV_WC_RDMA_READ },
	{ SIW_OP_SEND, IBV_WC_SEND },
	{ SIW_OP_SEND_WITH_IMM, IBV_WC_SEND },
	{ SIW_OP_SEND_REMOTE_INV, IBV_WC_SEND },
	{ SIW_OP_FETCH_AND_ADD, IBV_WC_FETCH_ADD },
	{ SIW_OP_COMP_AND_SWAP, IBV_WC_COMP_SWAP },
	{ SIW_OP_RECEIVE, IBV_WC_RECV }
};

static const struct {
	enum siw_wc_status siw;
	enum ibv_wc_status base;
} map_cqe_status[SIW_NUM_WC_STATUS] = {
	{ SIW_WC_SUCCESS, IBV_WC_SUCCESS },
	{ SIW_WC_LOC_LEN_ERR, IBV_WC_LOC_LEN_ERR },
	{ SIW_WC_LOC_PROT_ERR, IBV_WC_LOC_PROT_ERR },
	{ SIW_WC_LOC_QP_OP_ERR, IBV_WC_LOC_QP_OP_ERR },
	{ SIW_WC_WR_FLUSH_ERR, IBV_WC_WR_FLUSH_ERR },
	{ SIW_WC_BAD_RESP_ERR, IBV_WC_BAD_RESP_ERR },
	{ SIW_WC_LOC_ACCESS_ERR, IBV_WC_LOC_ACCESS_ERR },
	{ SIW_WC_REM_ACCESS_ERR, IBV_WC_REM_ACCESS_ERR },
	{ SIW_WC_REM_INV_REQ_ERR, IBV_WC_REM_INV_REQ_ERR },
	{ SIW_WC_GENERAL_ERR, IBV_WC_GENERAL_ERR }
};

static inline void copy_cqe(struct siw_cqe *cqe, struct ibv_wc *wc)
{
	wc->wr_id = cqe->id;
	wc->byte_len = cqe->bytes;

	/* No immediate data supported yet */
	wc->wc_flags = 0;
	wc->imm_data = 0;

	wc->vendor_err = 0;
	wc->opcode = map_cqe_opcode[cqe->opcode].base;
	wc->status = map_cqe_status[cqe->status].base;
	wc->qp_num = (uint32_t)cqe->qp_id;
}

static int siw_poll_cq(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc)
{
	struct siw_cq *cq = cq_base2siw(ibcq);
	int new = 0;

	pthread_spin_lock(&cq->lock);

	for (; num_entries--; wc++) {
		struct siw_cqe *cqe = &cq->queue[cq->cq_get % cq->num_cqe];
		atomic_uchar *fp = (atomic_uchar *)&cqe->flags;

		if (atomic_load(fp) & SIW_WQE_VALID) {
			copy_cqe(cqe, wc);
			atomic_store(fp, 0);
			cq->cq_get++;
			new++;
		} else
			break;
	}
	pthread_spin_unlock(&cq->lock);

	return new;
}

static const struct verbs_context_ops siw_context_ops = {
	.alloc_pd = siw_alloc_pd,
	.async_event = siw_async_event,
	.create_ah = siw_create_ah,
	.create_cq = siw_create_cq,
	.create_qp = siw_create_qp,
	.create_srq = siw_create_srq,
	.dealloc_pd = siw_free_pd,
	.dereg_mr = siw_dereg_mr,
	.destroy_ah = siw_destroy_ah,
	.destroy_cq = siw_destroy_cq,
	.destroy_qp = siw_destroy_qp,
	.destroy_srq = siw_destroy_srq,
	.free_context = siw_free_context,
	.modify_qp = siw_modify_qp,
	.modify_srq = siw_modify_srq,
	.poll_cq = siw_poll_cq,
	.post_recv = siw_post_recv,
	.post_send = siw_post_send,
	.post_srq_recv = siw_post_srq_recv,
	.query_device = siw_query_device,
	.query_port = siw_query_port,
	.query_qp = siw_query_qp,
	.reg_mr = siw_reg_mr,
	.req_notify_cq = siw_notify_cq,
	.resize_cq = siw_resize_cq,
};

static struct verbs_context *siw_alloc_context(struct ibv_device *base_dev,
					       int fd, void *pdata)
{
	struct siw_context *ctx;
	struct ibv_get_context cmd = {};
	struct siw_cmd_alloc_context_resp resp = {};

	ctx = verbs_init_and_alloc_context(base_dev, fd, ctx, base_ctx,
					   RDMA_DRIVER_SIW);
	if (!ctx)
		return NULL;

	if (ibv_cmd_get_context(&ctx->base_ctx, &cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp))) {
		verbs_uninit_context(&ctx->base_ctx);
		free(ctx);

		return NULL;
	}
	verbs_set_ops(&ctx->base_ctx, &siw_context_ops);
	ctx->dev_id = resp.dev_id;

	return &ctx->base_ctx;
}

static void siw_free_context(struct ibv_context *ibv_ctx)
{
	struct siw_context *ctx = ctx_ibv2siw(ibv_ctx);

	verbs_uninit_context(&ctx->base_ctx);
	free(ctx);
}

static struct verbs_device *siw_device_alloc(struct verbs_sysfs_dev *unused)
{
	struct siw_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	return &dev->base_dev;
}

static void siw_device_free(struct verbs_device *vdev)
{
	struct siw_device *dev =
		container_of(vdev, struct siw_device, base_dev);
	free(dev);
}

static const struct verbs_match_ent rnic_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_SIW),
	{},
};

static const struct verbs_device_ops siw_dev_ops = {
	.name = "siw",
	.match_min_abi_version = SIW_ABI_VERSION,
	.match_max_abi_version = SIW_ABI_VERSION,
	.match_table = rnic_table,
	.alloc_device = siw_device_alloc,
	.uninit_device = siw_device_free,
	.alloc_context = siw_alloc_context,
};

PROVIDER_DRIVER(siw, siw_dev_ops);
