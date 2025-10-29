/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSCALE_H
#define XSCALE_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdatomic.h>
#include <util/compiler.h>

#include <infiniband/driver.h>
#include <util/udma_barrier.h>
#include <ccan/list.h>
#include <ccan/minmax.h>
#include <valgrind/memcheck.h>

#include "xsc-abi.h"

typedef uint8_t   u8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef uint64_t  u64;

enum {
	XSC_QP_FLAG_RAWPACKET_TSO = 1 << 9,
	XSC_QP_FLAG_RAWPACKET_TX = 1 << 10,
};

enum xsc_qp_create_flags {
	XSC_QP_CREATE_RAWPACKET_TSO = 1 << 0,
	XSC_QP_CREATE_RAWPACKET_TX = 1 << 1,
};

enum {
	XSC_DBG_QP = 1 << 0,
	XSC_DBG_CQ = 1 << 1,
	XSC_DBG_QP_SEND = 1 << 2,
	XSC_DBG_QP_SEND_ERR = 1 << 3,
	XSC_DBG_CQ_CQE = 1 << 4,
	XSC_DBG_CONTIG = 1 << 5,
	XSC_DBG_DR = 1 << 6,
	XSC_DBG_CTX = 1 << 7,
	XSC_DBG_PD = 1 << 8,
	XSC_DBG_MR = 1 << 9,
};

extern u32 xsc_debug_mask;

#define xsc_dbg(fp, mask, fmt, args...)                                        \
	do {                                                                   \
		if (xsc_debug_mask & (mask)) {                                 \
			char host[256];                                        \
			char timestr[32];                                      \
			struct tm now_tm;                                      \
			time_t now_time;                                       \
			time(&now_time);                                       \
			localtime_r(&now_time, &now_tm);                       \
			strftime(timestr, sizeof(timestr), "%Y-%m-%d %X",      \
				 &now_tm);                                     \
			gethostname(host, 256);                                \
			fprintf(fp, "[%s %s %s %d] " fmt, timestr, host,       \
				__func__, __LINE__, ##args);                   \
		}                                                              \
	} while (0)

#define xsc_err(fmt, args...)                                                  \
	do {                                                                   \
		char host[256];                                                \
		char timestr[32];                                              \
		struct tm now_tm;                                              \
		time_t now_time;                                               \
		time(&now_time);                                               \
		localtime_r(&now_time, &now_tm);                               \
		strftime(timestr, sizeof(timestr), "%Y-%m-%d %X", &now_tm);    \
		gethostname(host, 256);                                        \
		printf("[%s %s %s %d] " fmt, timestr, host, __func__,          \
		       __LINE__, ##args);                                      \
	} while (0)

enum {
	XSC_QP_TABLE_SHIFT = 12,
	XSC_QP_TABLE_MASK = (1 << XSC_QP_TABLE_SHIFT) - 1,
	XSC_QP_TABLE_SIZE = 1 << (24 - XSC_QP_TABLE_SHIFT),
};

struct xsc_resource {
	u32 rsn;
};

struct xsc_device {
	struct verbs_device verbs_dev;
	int page_size;
};

struct xsc_spinlock {
	pthread_spinlock_t lock;
};

#define NAME_BUFFER_SIZE 64

struct xsc_context {
	struct verbs_context ibv_ctx;
	int max_num_qps;
	struct {
		struct xsc_qp **table;
		int refcnt;
	} qp_table[XSC_QP_TABLE_SIZE];
	pthread_mutex_t qp_table_mutex;

	int max_sq_desc_sz;
	int max_rq_desc_sz;
	int max_send_wr;
	int max_recv_wr;
	int num_ports;
	char hostname[NAME_BUFFER_SIZE];
	u32 max_cqe;
	void *sqm_reg_va;
	void *rqm_reg_va;
	void *cqm_reg_va;
	void *cqm_armdb_va;
	int db_mmap_size;
	u32 page_size;
	u64 qpm_tx_db;
	u64 qpm_rx_db;
	u64 cqm_next_cid_reg;
	u64 cqm_armdb;
	u32 send_ds_num;
	u32 recv_ds_num;
	u32 send_ds_shift;
	u32 recv_ds_shift;
	FILE *dbg_fp;
	struct xsc_hw_ops *hw_ops;
};

struct xsc_buf {
	void *buf;
	size_t length;
};

struct xsc_pd {
	struct ibv_pd ibv_pd;
	u32 pdn;
	atomic_int refcount;
};

struct xsc_err_state_qp_node {
	struct list_node entry;
	u32 qp_id;
	int is_sq;
};

struct xsc_cq {
	/* ibv_cq should always be subset of ibv_cq_ex */
	struct verbs_cq verbs_cq;
	struct xsc_buf buf;
	struct xsc_buf *active_buf;
	struct xsc_buf *resize_buf;
	int resize_cqes;
	int active_cqes;
	struct xsc_spinlock lock;
	u32 cqn;
	u32 cons_index;
	__le32 *db;
	__le32 *armdb;
	u32 cqe_cnt;
	int log2_cq_ring_sz;
	int cqe_sz;
	int resize_cqe_sz;
	struct xsc_resource *cur_rsc;
	u32 flags;
	int disable_flush_error_cqe;
	struct list_head err_state_qp_list;
};

struct xsc_wq {
	u64 *wrid;
	unsigned int *wqe_head;
	struct xsc_spinlock lock;
	unsigned int wqe_cnt;
	unsigned int max_post;
	unsigned int head;
	unsigned int tail;
	unsigned int cur_post;
	int max_gs;
	int wqe_shift;
	int offset;
	void *qend;
	__le32 *db;
	unsigned int ds_cnt;
	unsigned int seg_cnt;
	unsigned int *wr_opcode;
	unsigned int *need_flush;
	unsigned int flush_wqe_cnt;
};

struct xsc_mr {
	struct verbs_mr vmr;
	u32 alloc_flags;
};

struct xsc_qp {
	struct xsc_resource rsc; /* This struct must be first */
	struct verbs_qp verbs_qp;
	struct ibv_qp *ibv_qp;
	struct xsc_buf buf;
	void *sq_start;
	void *rq_start;
	int max_inline_data;
	int buf_size;
	/* For Raw Packet QP, use different buffers for the SQ and RQ */
	struct xsc_buf sq_buf;
	int sq_buf_size;
	u8 sq_signal_bits;
	struct xsc_wq sq;
	struct xsc_wq rq;
	u32 flags; /* Use enum xsc_qp_flags */
	u32 rqn;
	u32 sqn;
};

union xsc_ib_fw_ver {
	u64 data;
	struct {
		u8 ver_major;
		u8 ver_minor;
		u16 ver_patch;
		u32 ver_tweak;
	} s;
};

static inline int xsc_ilog2(int n)
{
	int t;

	if (n <= 0)
		return -1;

	t = 0;
	while ((1 << t) < n)
		++t;

	return t;
}

static inline struct xsc_device *to_xdev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct xsc_device, verbs_dev.device);
}

static inline struct xsc_context *to_xctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct xsc_context, ibv_ctx.context);
}

/* to_xpd always returns the real xsc_pd object ie the protection domain. */
static inline struct xsc_pd *to_xpd(struct ibv_pd *ibpd)
{
	return container_of(ibpd, struct xsc_pd, ibv_pd);
}

static inline struct xsc_cq *to_xcq(struct ibv_cq *ibcq)
{
	return container_of((struct ibv_cq_ex *)ibcq, struct xsc_cq,
			    verbs_cq.cq_ex);
}

static inline struct xsc_qp *to_xqp(struct ibv_qp *ibqp)
{
	struct verbs_qp *vqp = (struct verbs_qp *)ibqp;

	return container_of(vqp, struct xsc_qp, verbs_qp);
}

static inline struct xsc_mr *to_xmr(struct ibv_mr *ibmr)
{
	return container_of(ibmr, struct xsc_mr, vmr.ibv_mr);
}

static inline struct xsc_qp *rsc_to_xqp(struct xsc_resource *rsc)
{
	return (struct xsc_qp *)rsc;
}

int xsc_alloc_buf(struct xsc_buf *buf, size_t size, int page_size);
void xsc_free_buf(struct xsc_buf *buf);

int xsc_query_device(struct ibv_context *context, struct ibv_device_attr *attr);
int xsc_query_device_ex(struct ibv_context *context,
			const struct ibv_query_device_ex_input *input,
			struct ibv_device_attr_ex *attr, size_t attr_size);
int xsc_query_port(struct ibv_context *context, u8 port,
		   struct ibv_port_attr *attr);

struct ibv_pd *xsc_alloc_pd(struct ibv_context *context);
int xsc_free_pd(struct ibv_pd *pd);

struct ibv_mr *xsc_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			  u64 hca_va, int access);
int xsc_dereg_mr(struct verbs_mr *mr);
struct ibv_cq *xsc_create_cq(struct ibv_context *context, int cqe,
			     struct ibv_comp_channel *channel, int comp_vector);
struct ibv_cq_ex *xsc_create_cq_ex(struct ibv_context *context,
				   struct ibv_cq_init_attr_ex *cq_attr);
int xsc_alloc_cq_buf(struct xsc_context *xctx, struct xsc_cq *cq,
		     struct xsc_buf *buf, int nent, int cqe_sz);
void xsc_free_cq_buf(struct xsc_context *ctx, struct xsc_buf *buf);
int xsc_resize_cq(struct ibv_cq *cq, int cqe);
int xsc_destroy_cq(struct ibv_cq *cq);
int xsc_poll_cq(struct ibv_cq *cq, int ne, struct ibv_wc *wc);
int xsc_arm_cq(struct ibv_cq *cq, int solicited);
void __xsc_cq_clean(struct xsc_cq *cq, u32 qpn);
void xsc_cq_clean(struct xsc_cq *cq, u32 qpn);

struct ibv_qp *xsc_create_qp_ex(struct ibv_context *context,
				struct ibv_qp_init_attr_ex *attr);
struct ibv_qp *xsc_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr);
int xsc_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		 struct ibv_qp_init_attr *init_attr);
int xsc_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask);
int xsc_destroy_qp(struct ibv_qp *qp);
void xsc_init_qp_indices(struct xsc_qp *qp);
int xsc_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		  struct ibv_send_wr **bad_wr);
int xsc_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		  struct ibv_recv_wr **bad_wr);
struct xsc_qp *xsc_find_qp(struct xsc_context *ctx, u32 qpn);
int xsc_store_qp(struct xsc_context *ctx, u32 qpn, struct xsc_qp *qp);
void xsc_clear_qp(struct xsc_context *ctx, u32 qpn);
int xsc_err_state_qp(struct ibv_qp *qp, enum ibv_qp_state cur_state,
		     enum ibv_qp_state state);
int xsc_round_up_power_of_two(long long sz);
void *xsc_get_send_wqe(struct xsc_qp *qp, int n);

static inline int xsc_spin_lock(struct xsc_spinlock *lock)
{
	return pthread_spin_lock(&lock->lock);
}

static inline int xsc_spin_unlock(struct xsc_spinlock *lock)
{
	return pthread_spin_unlock(&lock->lock);
}

static inline int xsc_spinlock_init(struct xsc_spinlock *lock)
{
	return pthread_spin_init(&lock->lock, PTHREAD_PROCESS_PRIVATE);
}

static inline int xsc_spinlock_destroy(struct xsc_spinlock *lock)
{
	return pthread_spin_destroy(&lock->lock);
}

#endif /* XSC_H */
