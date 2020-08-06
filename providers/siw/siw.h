/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */

/* Authors: Bernard Metzler <bmt@zurich.ibm.com> */
/* Copyright (c) 2008-2019, IBM Corporation */

#ifndef _SIW_H
#define _SIW_H

#include <pthread.h>
#include <inttypes.h>
#include <stddef.h>

#include <infiniband/driver.h>
#include <infiniband/kern-abi.h>

struct siw_device {
	struct verbs_device base_dev;
};

struct siw_srq {
	struct ibv_srq base_srq;
	struct siw_rqe *recvq;
	uint32_t rq_put;
	uint32_t num_rqe;
	pthread_spinlock_t lock;
};

struct siw_mr {
	struct verbs_mr base_mr;
};

struct siw_qp {
	struct ibv_qp base_qp;
	struct siw_device *siw_dev;

	uint32_t id;

	pthread_spinlock_t sq_lock;
	pthread_spinlock_t rq_lock;

	struct ibv_post_send db_req;
	struct ib_uverbs_post_send_resp db_resp;

	uint32_t num_sqe;
	uint32_t sq_put;
	int sq_sig_all;
	struct siw_sqe *sendq;

	uint32_t num_rqe;
	uint32_t rq_put;
	struct siw_rqe *recvq;
	struct siw_srq *srq;
};

struct siw_cq {
	struct ibv_cq base_cq;
	struct siw_device *siw_dev;
	uint32_t id;

	/* Points to kernel shared control
	 * object at the end of CQE array
	 */
	struct siw_cq_ctrl *ctrl;

	int num_cqe;
	uint32_t cq_get;
	struct siw_cqe *queue;
	pthread_spinlock_t lock;
};

struct siw_context {
	struct verbs_context base_ctx;
	uint32_t dev_id;
};

static inline struct siw_context *ctx_ibv2siw(struct ibv_context *base)
{
	return container_of(base, struct siw_context, base_ctx.context);
}

static inline struct siw_qp *qp_base2siw(struct ibv_qp *base)
{
	return container_of(base, struct siw_qp, base_qp);
}

static inline struct siw_cq *cq_base2siw(struct ibv_cq *base)
{
	return container_of(base, struct siw_cq, base_cq);
}

static inline struct siw_mr *mr_base2siw(struct verbs_mr *base)
{
	return container_of(base, struct siw_mr, base_mr);
}

static inline struct siw_srq *srq_base2siw(struct ibv_srq *base)
{
	return container_of(base, struct siw_srq, base_srq);
}

static inline int siw_db(struct siw_qp *qp)
{
	int rv = write(qp->base_qp.context->cmd_fd, &qp->db_req,
		       sizeof(qp->db_req));

	return rv == sizeof(qp->db_req) ? 0 : rv;
}

#endif /* _SIW_H */
