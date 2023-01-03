/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2022, Microsoft Corporation. All rights reserved.
 */

#ifndef _MANA_H_
#define _MANA_H_

#include "manadv.h"

#define MAX_SEND_BUFFERS_PER_QUEUE 256
#define COMP_ENTRY_SIZE 64
#define MANA_IB_TOEPLITZ_HASH_KEY_SIZE_IN_BYTES 40

#define DMA_OOB_SIZE 8

#define INLINE_OOB_SMALL_SIZE 8
#define INLINE_OOB_LARGE_SIZE 24

#define GDMA_WQE_ALIGNMENT_UNIT_SIZE 32
#define MAX_TX_WQE_SIZE 512
#define MAX_RX_WQE_SIZE 256

/* The size of a SGE in WQE */
#define SGE_SIZE 16

#define DOORBELL_PAGE_SIZE 4096
#define MANA_PAGE_SIZE 4096

static inline int align_next_power2(int size)
{
	int val = 1;

	while (val < size)
		val <<= 1;

	return val;
}

static inline int align_hw_size(int size)
{
	size = align(size, MANA_PAGE_SIZE);
	return align_next_power2(size);
}

static inline int get_wqe_size(int sge)
{
	int wqe_size = sge * SGE_SIZE + DMA_OOB_SIZE + INLINE_OOB_SMALL_SIZE;

	return align(wqe_size, GDMA_WQE_ALIGNMENT_UNIT_SIZE);
}

struct mana_context {
	struct verbs_context ibv_ctx;
	struct manadv_ctx_allocators extern_alloc;
	void *db_page;
};

struct mana_rwq_ind_table {
	struct ibv_rwq_ind_table ib_ind_table;

	uint32_t ind_tbl_size;
	struct ibv_wq **ind_tbl;
};

struct mana_qp {
	struct verbs_qp ibqp;

	void *send_buf;
	uint32_t send_buf_size;

	int send_wqe_count;

	uint32_t sqid;
	uint32_t tx_vp_offset;
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
	void *buf;

	uint32_t cqid;
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

struct ibv_mr *mana_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			   uint64_t hca_va, int access);

int mana_dereg_mr(struct verbs_mr *vmr);

struct ibv_cq *mana_create_cq(struct ibv_context *context, int cqe,
			      struct ibv_comp_channel *channel,
			      int comp_vector);

int mana_destroy_cq(struct ibv_cq *cq);

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

#endif
