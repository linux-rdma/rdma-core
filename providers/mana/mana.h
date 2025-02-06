/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2022, Microsoft Corporation. All rights reserved.
 */

#ifndef _MANA_H_
#define _MANA_H_

#include "manadv.h"
#include <ccan/minmax.h>
#include "shadow_queue.h"

#define COMP_ENTRY_SIZE 64
#define MANA_IB_TOEPLITZ_HASH_KEY_SIZE_IN_BYTES 40

#define DMA_OOB_SIZE 8

#define INLINE_OOB_SMALL_SIZE 8
#define INLINE_OOB_LARGE_SIZE 24

#define GDMA_WQE_ALIGNMENT_UNIT_SIZE 32

/* The size of a SGE in WQE */
#define SGE_SIZE 16

#define DOORBELL_PAGE_SIZE 4096
#define MANA_PAGE_SIZE 4096

#define MANA_QP_TABLE_SIZE 4096
#define MANA_QP_TABLE_SHIFT 12
#define MANA_QP_TABLE_MASK (MANA_QP_TABLE_SIZE - 1)

/* PSN 24 bit arithmetic comparisons */
#define PSN_MASK 0xFFFFFF
#define PSN_SIGN_BIT 0x800000
#define PSN_GE(PSN1, PSN2) ((((PSN1) - (PSN2)) & PSN_SIGN_BIT) == 0)
#define PSN_GT(PSN1, PSN2) PSN_GE(PSN1, (PSN2) + 1)
#define PSN_LE(PSN1, PSN2) PSN_GE(PSN2, PSN1)
#define PSN_LT(PSN1, PSN2) PSN_GT(PSN2, PSN1)
#define MTU_SIZE(MTU) (1U << ((MTU) + 7))
#define PSN_DELTA(MSG_SIZE, MTU) max(1U, ((MSG_SIZE) + MTU_SIZE(MTU) - 1) >> (MTU + 7))
#define PSN_DEC(PSN) (((PSN) - 1) & PSN_MASK)
#define PSN_INC(PSN) (((PSN) + 1) & PSN_MASK)
#define PSN_ADD(PSN, DELTA) (((PSN) + (DELTA)) & PSN_MASK)

enum user_queue_types {
	USER_RC_SEND_QUEUE_REQUESTER = 0,
	USER_RC_SEND_QUEUE_RESPONDER = 1,
	USER_RC_RECV_QUEUE_REQUESTER = 2,
	USER_RC_RECV_QUEUE_RESPONDER = 3,
	USER_RC_QUEUE_TYPE_MAX = 4,
};

static inline uint32_t align_hw_size(uint32_t size)
{
	size = roundup_pow_of_two(size);
	return align(size, MANA_PAGE_SIZE);
}

static inline uint32_t get_wqe_size(uint32_t sge)
{
	uint32_t wqe_size = sge * SGE_SIZE + DMA_OOB_SIZE + INLINE_OOB_SMALL_SIZE;

	return align(wqe_size, GDMA_WQE_ALIGNMENT_UNIT_SIZE);
}

static inline uint32_t get_large_wqe_size(uint32_t sge)
{
	uint32_t wqe_size = sge * SGE_SIZE + DMA_OOB_SIZE + INLINE_OOB_LARGE_SIZE;

	return align(wqe_size, GDMA_WQE_ALIGNMENT_UNIT_SIZE);
}

struct mana_table {
	struct mana_qp **table;
	int refcnt;
};

struct mana_context {
	struct verbs_context ibv_ctx;
	struct mana_table qp_rtable[MANA_QP_TABLE_SIZE];
	struct mana_table qp_stable[MANA_QP_TABLE_SIZE];
	pthread_mutex_t qp_table_mutex;

	struct manadv_ctx_allocators extern_alloc;
	void *db_page;
};

struct mana_rwq_ind_table {
	struct ibv_rwq_ind_table ib_ind_table;

	uint32_t ind_tbl_size;
	struct ibv_wq **ind_tbl;
};

struct mana_gdma_queue {
	uint32_t id;
	uint32_t size;
	uint32_t prod_idx;
	uint32_t cons_idx;

	void *db_page;
	void *buffer;
};

struct mana_ib_raw_qp {
	void *send_buf;
	uint32_t send_buf_size;
	int send_wqe_count;
	uint32_t sqid;
	uint32_t tx_vp_offset;
};

struct mana_ib_rc_qp {
	struct mana_gdma_queue queues[USER_RC_QUEUE_TYPE_MAX];
	uint32_t sq_ssn;
	uint32_t sq_psn;
};

struct mana_qp {
	struct verbs_qp ibqp;
	pthread_spinlock_t sq_lock;
	pthread_spinlock_t rq_lock;

	union {
		struct mana_ib_raw_qp raw_qp;
		struct mana_ib_rc_qp rc_qp;
	};

	enum ibv_mtu mtu;
	int sq_sig_all;

	struct shadow_queue shadow_rq;
	struct shadow_queue shadow_sq;

	struct list_node send_cq_node;
	struct list_node recv_cq_node;
};

struct mana_wq {
	struct ibv_wq ibwq;

	void *buf;
	uint32_t buf_size;

	uint32_t wqe;
	uint32_t sge;

	uint32_t wqid;
};

struct mana_cq {
	struct ibv_cq ibcq;
	uint32_t cqe;
	uint32_t cqid;
	void *buf;

	pthread_spinlock_t lock;
	uint32_t head;
	uint32_t last_armed_head;
	void *db_page;
	/* list of qp's that use this cq for send completions */
	struct list_head send_qp_list;
	/* list of qp's that use this cq for recv completions */
	struct list_head recv_qp_list;
	bool buf_external;
};

struct mana_device {
	struct verbs_device verbs_dev;
};

struct mana_pd {
	struct ibv_pd ibv_pd;
	struct mana_pd *mprotection_domain;
};

struct mana_parent_domain {
	struct mana_pd mpd;
	void *pd_context;
};

struct mana_context *to_mctx(struct ibv_context *ibctx);

void *mana_alloc_mem(uint32_t size);

int mana_query_device_ex(struct ibv_context *context,
			 const struct ibv_query_device_ex_input *input,
			 struct ibv_device_attr_ex *attr, size_t attr_size);

int mana_query_port(struct ibv_context *context, uint8_t port,
		    struct ibv_port_attr *attr);

struct ibv_pd *mana_alloc_pd(struct ibv_context *context);
struct ibv_pd *
mana_alloc_parent_domain(struct ibv_context *context,
			 struct ibv_parent_domain_init_attr *attr);

int mana_dealloc_pd(struct ibv_pd *pd);

struct ibv_mr *mana_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset,
				  size_t length, uint64_t iova, int fd,
				  int access);

struct ibv_mr *mana_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			   uint64_t hca_va, int access);

int mana_dereg_mr(struct verbs_mr *vmr);

struct ibv_cq *mana_create_cq(struct ibv_context *context, int cqe,
			      struct ibv_comp_channel *channel,
			      int comp_vector);

int mana_destroy_cq(struct ibv_cq *cq);

int mana_poll_cq(struct ibv_cq *ibcq, int nwc, struct ibv_wc *wc);

struct ibv_wq *mana_create_wq(struct ibv_context *context,
			      struct ibv_wq_init_attr *attr);

int mana_destroy_wq(struct ibv_wq *wq);
int mana_modify_wq(struct ibv_wq *ibwq, struct ibv_wq_attr *attr);

struct ibv_rwq_ind_table *
mana_create_rwq_ind_table(struct ibv_context *context,
			  struct ibv_rwq_ind_table_init_attr *init_attr);

int mana_destroy_rwq_ind_table(struct ibv_rwq_ind_table *rwq_ind_table);

struct ibv_qp *mana_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr);

struct ibv_qp *mana_create_qp_ex(struct ibv_context *context,
				 struct ibv_qp_init_attr_ex *attr);

int mana_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask);

int mana_destroy_qp(struct ibv_qp *ibqp);

int mana_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		   struct ibv_recv_wr **bad);

int mana_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		   struct ibv_send_wr **bad);

int mana_arm_cq(struct ibv_cq *ibcq, int solicited);

struct mana_qp *mana_get_qp(struct mana_context *ctx, uint32_t qpn, bool is_sq);

void mana_qp_move_flush_err(struct ibv_qp *ibqp);
#endif
