/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Cisco Systems.  All rights reserved.
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
 *
 * $Id$
 */

#ifndef MTHCA_H
#define MTHCA_H

#include <endian.h>
#include <byteswap.h>

#include <infiniband/driver.h>
#include <infiniband/arch.h>

#define HIDDEN		__attribute__((visibility ("hidden")))

#define PFX		"mthca: "

enum mthca_hca_type {
	MTHCA_TAVOR,
	MTHCA_ARBEL
};

enum {
	MTHCA_CQ_ENTRY_SIZE = 0x20
};

enum {
	MTHCA_QP_TABLE_BITS = 8,
	MTHCA_QP_TABLE_SIZE = 1 << MTHCA_QP_TABLE_BITS,
	MTHCA_QP_TABLE_MASK = MTHCA_QP_TABLE_SIZE - 1
};

enum {
	MTHCA_DB_REC_PAGE_SIZE = 4096,
	MTHCA_DB_REC_PER_PAGE  = MTHCA_DB_REC_PAGE_SIZE / 8
};

enum mthca_db_type {
	MTHCA_DB_TYPE_INVALID   = 0x0,
	MTHCA_DB_TYPE_CQ_SET_CI = 0x1,
	MTHCA_DB_TYPE_CQ_ARM    = 0x2,
	MTHCA_DB_TYPE_SQ        = 0x3,
	MTHCA_DB_TYPE_RQ        = 0x4,
	MTHCA_DB_TYPE_SRQ       = 0x5,
	MTHCA_DB_TYPE_GROUP_SEP = 0x7
};

enum {
	MTHCA_OPCODE_NOP            = 0x00,
	MTHCA_OPCODE_RDMA_WRITE     = 0x08,
	MTHCA_OPCODE_RDMA_WRITE_IMM = 0x09,
	MTHCA_OPCODE_SEND           = 0x0a,
	MTHCA_OPCODE_SEND_IMM       = 0x0b,
	MTHCA_OPCODE_RDMA_READ      = 0x10,
	MTHCA_OPCODE_ATOMIC_CS      = 0x11,
	MTHCA_OPCODE_ATOMIC_FA      = 0x12,
	MTHCA_OPCODE_BIND_MW        = 0x18,
	MTHCA_OPCODE_INVALID        = 0xff
};

struct mthca_ah_page;

struct mthca_device {
	struct ibv_device   ibv_dev;
	enum mthca_hca_type hca_type;
	int                 page_size;
};

struct mthca_db_table;

struct mthca_context {
	void                  *uar;
	pthread_spinlock_t     uar_lock;
	struct mthca_db_table *db_tab;
	struct ibv_pd         *pd;
	struct {
		struct mthca_qp	**table;
		int		  refcnt;
	}		       qp_table[MTHCA_QP_TABLE_SIZE];
	pthread_mutex_t        qp_table_mutex;
	int                    num_qps;
	int		       qp_table_shift;
	int		       qp_table_mask;
	/*
	 * ibv_ctx must be last because we size it dynamically
	 * depending on the number of CQ events available.
	 */
	struct ibv_context     ibv_ctx;
};

struct mthca_pd {
	struct ibv_pd         ibv_pd;
	struct mthca_ah_page *ah_list;
	pthread_mutex_t       ah_mutex;
	uint32_t              pdn;
};

struct mthca_cq {
	struct ibv_cq  	   ibv_cq;
	void           	  *buf;
	pthread_spinlock_t lock;
	struct ibv_mr  	  *mr;
	uint32_t       	   cqn;
	uint32_t       	   cons_index;

	/* Next fields are mem-free only */
	int                set_ci_db_index;
	uint32_t          *set_ci_db;
	int                arm_db_index;
	uint32_t          *arm_db;
	int                arm_sn;
};

struct mthca_srq {
	struct ibv_srq     ibv_srq;
	void              *buf;
	void           	  *last;
	pthread_spinlock_t lock;
	struct ibv_mr 	  *mr;
	uint64_t      	  *wrid;
	uint32_t       	   srqn;
	int            	   max;
	int            	   max_gs;
	int            	   wqe_shift;
	int            	   first_free;
	int            	   last_free;
	int                buf_size;

	/* Next fields are mem-free only */
	int           	   db_index;
	uint32_t      	  *db;
	uint16_t      	   counter;
};

struct mthca_wq {
	pthread_spinlock_t lock;
	int            	   max;
	unsigned       	   next_ind;
	unsigned       	   last_comp;
	unsigned       	   head;
	unsigned       	   tail;
	void           	  *last;
	int            	   max_gs;
	int            	   wqe_shift;

	/* Next fields are mem-free only */
	int                db_index;
	uint32_t          *db;
};

struct mthca_qp {
	struct ibv_qp    ibv_qp;
	void            *buf;
	uint64_t        *wrid;
	int              send_wqe_offset;
	int              buf_size;
	struct mthca_wq  sq;
	struct mthca_wq  rq;
	struct ibv_mr   *mr;
	enum ibv_qp_type qpt;
	int              sq_sig_all;
};

struct mthca_av {
	uint32_t port_pd;
	uint8_t  reserved1;
	uint8_t  g_slid;
	uint16_t dlid;
	uint8_t  reserved2;
	uint8_t  gid_index;
	uint8_t  msg_sr;
	uint8_t  hop_limit;
	uint32_t sl_tclass_flowlabel;
	uint32_t dgid[4];
};

struct mthca_ah {
	struct ibv_ah         ibv_ah;
	struct mthca_av      *av;
	struct mthca_ah_page *page;
	uint32_t              key;
};

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) { return bswap_64(x); }
static inline uint64_t ntohll(uint64_t x) { return bswap_64(x); }
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x) { return x; }
static inline uint64_t ntohll(uint64_t x) { return x; }
#endif

static inline unsigned long align(unsigned long val, unsigned long align)
{
	return (val + align - 1) & ~(align - 1);
}

static inline uintptr_t db_align(uint32_t *db)
{
	return (uintptr_t) db & ~((uintptr_t) MTHCA_DB_REC_PAGE_SIZE - 1);
}

#define to_mxxx(xxx, type)						\
	((struct mthca_##type *)					\
	 ((void *) ib##xxx - offsetof(struct mthca_##type, ibv_##xxx)))

static inline struct mthca_device *to_mdev(struct ibv_device *ibdev)
{
	return to_mxxx(dev, device);
}

static inline struct mthca_context *to_mctx(struct ibv_context *ibctx)
{
	return to_mxxx(ctx, context);
}

static inline struct mthca_pd *to_mpd(struct ibv_pd *ibpd)
{
	return to_mxxx(pd, pd);
}

static inline struct mthca_cq *to_mcq(struct ibv_cq *ibcq)
{
	return to_mxxx(cq, cq);
}

static inline struct mthca_srq *to_msrq(struct ibv_srq *ibsrq)
{
	return to_mxxx(srq, srq);
}

static inline struct mthca_qp *to_mqp(struct ibv_qp *ibqp)
{
	return to_mxxx(qp, qp);
}

static inline struct mthca_ah *to_mah(struct ibv_ah *ibah)
{
	return to_mxxx(ah, ah);
}

static inline int mthca_is_memfree(struct ibv_context *ibctx)
{
	return to_mdev(ibctx->device)->hca_type == MTHCA_ARBEL;
}

extern int mthca_alloc_db(struct mthca_db_table *db_tab, enum mthca_db_type type,
			  uint32_t **db);
extern void mthca_set_db_qn(uint32_t *db, enum mthca_db_type type, uint32_t qn);
extern void mthca_free_db(struct mthca_db_table *db_tab, enum mthca_db_type type, int db_index);
extern struct mthca_db_table *mthca_alloc_db_tab(int uarc_size);
extern void mthca_free_db_tab(struct mthca_db_table *db_tab);

extern int mthca_query_device(struct ibv_context *context,
			      struct ibv_device_attr *attr);
extern int mthca_query_port(struct ibv_context *context, uint8_t port,
			    struct ibv_port_attr *attr);
extern int mthca_query_gid(struct ibv_context *context, uint8_t port_num,
			   int index, union ibv_gid *gid);
extern int mthca_query_pkey(struct ibv_context *context, uint8_t port_num,
			    int index, uint16_t *pkey);

extern struct ibv_pd *mthca_alloc_pd(struct ibv_context *context);
extern int mthca_free_pd(struct ibv_pd *pd);

extern struct ibv_mr *mthca_reg_mr(struct ibv_pd *pd, void *addr,
				   size_t length, enum ibv_access_flags access);
extern int mthca_dereg_mr(struct ibv_mr *mr);

struct ibv_cq *mthca_create_cq(struct ibv_context *context, int cqe);
extern int mthca_destroy_cq(struct ibv_cq *cq);
extern int mthca_poll_cq(struct ibv_cq *cq, int ne, struct ibv_wc *wc);
extern int mthca_tavor_arm_cq(struct ibv_cq *cq, int solicited);
extern int mthca_arbel_arm_cq(struct ibv_cq *cq, int solicited);
extern void mthca_arbel_cq_event(struct ibv_cq *cq);
extern void mthca_init_cq_buf(struct mthca_cq *cq, int nent);

extern struct ibv_srq *mthca_create_srq(struct ibv_pd *pd,
					struct ibv_srq_init_attr *attr);
extern int mthca_modify_srq(struct ibv_srq *srq,
			    struct ibv_srq_attr *attr,
			    enum ibv_srq_attr_mask mask);
extern int mthca_destroy_srq(struct ibv_srq *srq);
extern int mthca_alloc_srq_buf(struct ibv_pd *pd, struct ibv_srq_attr *attr,
			       struct mthca_srq *srq);
extern void mthca_free_srq_wqe(struct mthca_srq *srq, uint32_t wqe_addr);
extern int mthca_tavor_post_srq_recv(struct ibv_srq *ibsrq,
				     struct ibv_recv_wr *wr,
				     struct ibv_recv_wr **bad_wr);
extern int mthca_arbel_post_srq_recv(struct ibv_srq *ibsrq,
				     struct ibv_recv_wr *wr,
				     struct ibv_recv_wr **bad_wr);

extern struct ibv_qp *mthca_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr);
extern int mthca_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
			   enum ibv_qp_attr_mask attr_mask);
extern int mthca_destroy_qp(struct ibv_qp *qp);
extern int mthca_tavor_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
				 struct ibv_send_wr **bad_wr);
extern int mthca_tavor_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
				 struct ibv_recv_wr **bad_wr);
extern int mthca_arbel_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
				 struct ibv_send_wr **bad_wr);
extern int mthca_arbel_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
				 struct ibv_recv_wr **bad_wr);
extern int mthca_alloc_qp_buf(struct ibv_pd *pd, struct ibv_qp_cap *cap,
			      struct mthca_qp *qp);
extern void mthca_return_cap(struct ibv_pd *pd, struct mthca_qp *qp,
			     struct ibv_qp_cap *cap);
extern struct mthca_qp *mthca_find_qp(struct mthca_context *ctx, uint32_t qpn);
extern int mthca_store_qp(struct mthca_context *ctx, uint32_t qpn, struct mthca_qp *qp);
extern void mthca_clear_qp(struct mthca_context *ctx, uint32_t qpn);
extern int mthca_free_err_wqe(struct mthca_qp *qp, int is_send,
			      int index, int *dbd, uint32_t *new_wqe);
extern struct ibv_ah *mthca_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr);
extern int mthca_destroy_ah(struct ibv_ah *ah);
extern int mthca_alloc_av(struct mthca_pd *pd, struct ibv_ah_attr *attr,
			  struct mthca_ah *ah);
extern void mthca_free_av(struct mthca_ah *ah);
extern int mthca_attach_mcast(struct ibv_qp *qp, union ibv_gid *gid, uint16_t lid);
extern int mthca_detach_mcast(struct ibv_qp *qp, union ibv_gid *gid, uint16_t lid);

#endif /* MTHCA_H */
