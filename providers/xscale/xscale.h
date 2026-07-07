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
#include "xscdv.h"

enum xsc_qp_ex_attr_mask {
	XSC_QP_FLUSH		= 1 << 21,
};

enum {
	XSC_IB_MMAP_CMD_SHIFT	= 8,
	XSC_IB_MMAP_CMD_MASK	= 0xff,
};

enum {
	XSC_QP_FLAG_RAWPACKET_TSO           = 1 << 9,
	XSC_QP_FLAG_RAWPACKET_TX            = 1 << 10,
	XSC_QP_FLAG_RAWPACKET_SNIFFER       = 1 << 11,
	XSC_QP_FLAG_WORC		    = 1 << 12,
	XSC_QP_FLAG_OWNED_BY_GPU	    = 1 << 13,
};

#define XSC_CQ_PREFIX "XSC_CQ"
#define XSC_QP_PREFIX "XSC_QP"
#define XSC_MR_PREFIX "XSC_MR"
#define XSC_RWQ_PREFIX "XSC_RWQ"
#define XSC_MAX_LOG2_CONTIG_BLOCK_SIZE 23
#define XSC_MIN_LOG2_CONTIG_BLOCK_SIZE 12

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

extern uint32_t xsc_debug_mask;

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

enum xsc_alloc_type {
	XSC_ALLOC_TYPE_ANON,
	XSC_ALLOC_TYPE_HUGE,
	XSC_ALLOC_TYPE_CONTIG,
	XSC_ALLOC_TYPE_PREFER_HUGE,
	XSC_ALLOC_TYPE_PREFER_CONTIG,
	XSC_ALLOC_TYPE_EXTERNAL,
	XSC_ALLOC_TYPE_GPU,
	XSC_ALLOC_TYPE_ALL
};

enum xsc_rsc_type {
	XSC_RSC_TYPE_QP,
	XSC_RSC_TYPE_XSRQ,
	XSC_RSC_TYPE_SRQ,
	XSC_RSC_TYPE_RWQ,
	XSC_RSC_TYPE_INVAL,
};

struct xsc_resource {
	enum xsc_rsc_type	type;
	uint32_t		rsn;
};

struct xsc_device {
	struct verbs_device verbs_dev;
	int page_size;
};

struct xsc_spinlock {
	pthread_spinlock_t lock;
	int				in_use;
	int				need_lock;
};

#define XSC_PCI_VENDOR_ID		0x1f67

#define XSC_MC_PF_DEV_ID		0x1011
#define XSC_MC_VF_DEV_ID		0x1012
#define XSC_MC_PF_DEV_ID_DIAMOND	0x1021
#define XSC_MC_PF_DEV_ID_DIAMOND_NEXT	0x1023

#define XSC_MF_HOST_PF_DEV_ID		0x1051
#define XSC_MF_HOST_VF_DEV_ID		0x1052
#define XSC_MF_SOC_PF_DEV_ID		0x1053

#define XSC_MS_PF_DEV_ID		0x1111
#define XSC_MS_VF_DEV_ID		0x1112

#define XSC_MV_HOST_PF_DEV_ID		0x1151
#define XSC_MV_HOST_VF_DEV_ID		0x1152
#define XSC_MV_SOC_PF_DEV_ID		0x1153

#define NAME_BUFFER_SIZE 64

struct xsc_context {
	struct verbs_context		ibv_ctx;
	int				max_num_qps;
	struct {
		struct xsc_qp		**table;
		int			refcnt;
	}				qp_table[XSC_QP_TABLE_SIZE];
	pthread_mutex_t			qp_table_mutex;

	int				max_sq_desc_sz;
	int				max_rq_desc_sz;
	int				max_send_wqebb;
	int				max_recv_wr;
	int				num_ports;
	int				stall_enable;
	int				stall_adaptive_enable;
	int				stall_cycles;
	char				hostname[NAME_BUFFER_SIZE];
	struct xsc_spinlock		hugetlb_lock;
	struct list_head		hugetlb_list;
	enum ibv_atomic_cap		atomic_cap;
	struct xscdv_ctx_allocators	extern_alloc;
	uint32_t			max_cqe;
	void				*sqm_reg_va;
	void				*rqm_reg_va;
	void				*cqm_reg_va;
	void				*cqm_armdb_va;
	int				db_mmap_size;
	uint32_t			page_size;
	uint64_t			qpm_tx_db;
	uint64_t			qpm_rx_db;
	uint64_t			cqm_next_cid_reg;
	uint64_t			cqm_armdb;
	uint32_t			send_ds_num;
	uint32_t			recv_ds_num;
	uint32_t			send_ds_shift;
	uint32_t			recv_ds_shift;
	FILE				*dbg_fp;
	uint16_t			device_id;
	uint32_t			multidb_num;
	uint32_t			tx_multidb_base;
	void				*mdb_base;
	uint32_t			tx_mdb_idx;
	uint32_t			hw_feature_flag;
	uint32_t			mdb_mmap_size;
};

struct xsc_bitmap {
	uint32_t		last;
	uint32_t		top;
	uint32_t		max;
	uint32_t		avail;
	uint32_t		mask;
	unsigned long	       *table;
};

struct xsc_hugetlb_mem {
	int			shmid;
	void		       *shmaddr;
	struct xsc_bitmap	bitmap;
	struct list_node	entry;
};

struct xsc_buf {
	void			       *buf;
	size_t				length;
	int                             base;
	struct xsc_hugetlb_mem	       *hmem;
	enum xsc_alloc_type		type;
};

struct xsc_pd {
	struct ibv_pd			ibv_pd;
	uint32_t			pdn;
	atomic_int			refcount;
	struct xsc_pd			*xprotection_domain;
};

struct xsc_parent_domain {
	struct xsc_pd xpd;
};

enum {
	XSC_CQ_FLAGS_RX_CSUM_VALID = 1 << 0,
	XSC_CQ_FLAGS_EMPTY_DURING_POLL = 1 << 1,
	XSC_CQ_FLAGS_FOUND_CQES = 1 << 2,
	XSC_CQ_FLAGS_EXTENDED = 1 << 3,
	XSC_CQ_FLAGS_SINGLE_THREADED = 1 << 4,
	XSC_CQ_FLAGS_DV_OWNED = 1 << 5,
	XSC_CQ_FLAGS_TM_SYNC_REQ = 1 << 6,
	XSC_CQ_FLAGS_OWNED_BY_GPU = 1 << 7,
};

struct xsc_err_state_qp_node {
	struct list_node entry;
	uint32_t qp_id;
	int is_sq;
};

struct xsc_cq {
	/* ibv_cq should always be subset of ibv_cq_ex */
	struct verbs_cq			verbs_cq;
	struct xsc_buf			buf_a;
	struct xsc_buf			buf_b;
	struct xsc_buf		       *active_buf;
	struct xsc_buf		       *resize_buf;
	int				resize_cqes;
	int				active_cqes;
	struct xsc_spinlock		lock;
	uint32_t			cqn;
	uint32_t			cons_index;
	__le32			       *dbrec;
	__le32				*db;
	__le32				*armdb;
	uint32_t			cqe_cnt;
	int				log2_cq_ring_sz;
	int				arm_sn;
	int				cqe_sz;
	int				resize_cqe_sz;
	int				stall_next_poll;
	int				stall_enable;
	uint64_t			stall_last_count;
	int				stall_adaptive_enable;
	int				stall_cycles;
	struct xsc_resource		*cur_rsc;
	struct xsc_cqe			*cqe;
	uint32_t			flags;
	int				umr_opcode;
	bool				disable_flush_error_cqe;
	struct list_head		err_state_qp_list;
};

struct xsc_mr {
	struct verbs_mr vmr;
	uint32_t alloc_flags;
};

struct xsc_wq {
	uint64_t			*wrid;
	uint32_t			*wqe_head;
	struct xsc_spinlock		lock;
	uint32_t			wqe_cnt;
	uint32_t			max_post;
	uint32_t			head;
	uint32_t			tail;
	uint32_t			cur_post;
	int				max_gs;
	int				wqe_shift;
	int				offset;
	void				*qend;
	uint32_t			*wr_data;
	__le32				*db;
	unsigned int			ds_cnt;
	unsigned int			seg_cnt;
	unsigned int			*wr_opcode;
	unsigned int			*need_flush;
};

enum xsc_qp_flags {
	XSC_QP_FLAGS_USE_UNDERLAY = 0x01,
};

struct xsc_qp {
	struct xsc_resource		rsc; /* This struct must be first */
	struct verbs_qp			verbs_qp;
	struct ibv_qp			*ibv_qp;
	struct xsc_buf			buf;
	void				*sq_start;
	void				*rq_start;
	int				max_inline_data;
	int				buf_size;
	/* For Raw Packet QP, use different buffers for the SQ and RQ */
	struct xsc_buf			sq_buf;
	int				sq_buf_size;

	int				err;
	/* Number of WR entries posted in the current wr session */
	int				nreq;
	uint32_t			cur_post_rb;
	void				*cur_ctrl;
	void				*cur_data;
	int				cur_ds_num;
	uint32_t			cur_data_len;
	uint64_t			cur_remote_addr;
	uint32_t			cur_remote_key;

	uint8_t				fm_cache;
	uint8_t				sq_signal_bits;
	struct xsc_wq			sq;

	__le32				*db;
	struct xsc_wq			rq;
	int				wq_sig;
	uint32_t			qp_cap_cache;
	int				atomics_enabled;
	uint32_t			max_tso;
	uint16_t			max_tso_header;
	int				rss_qp;
	uint32_t			flags; /* Use enum xsc_qp_flags */
	enum xscdv_dc_type		dc_type;
	uint32_t			tirn;
	uint32_t			tisn;
	uint32_t			rqn;
	uint32_t			sqn;
	unsigned int			err_occurred;
	bool				has_trig_cq_evt;
};

union xsc_ib_fw_ver {
	uint64_t data;
	struct {
		uint8_t ver_major;
		uint8_t ver_minor;
		uint16_t ver_patch;
		uint32_t ver_tweak;
	} s;
};

extern int xsc_single_threaded;

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
	struct xsc_pd *xpd = container_of(ibpd, struct xsc_pd, ibv_pd);

	if (xpd->xprotection_domain)
		return xpd->xprotection_domain;

	return xpd;
}

static inline struct xsc_parent_domain *to_xparent_domain(struct ibv_pd *ibpd)
{
	struct xsc_parent_domain *xparent_domain =
	    ibpd ? container_of(ibpd, struct xsc_parent_domain, xpd.ibv_pd) : NULL;

	if (xparent_domain && xparent_domain->xpd.xprotection_domain)
		return xparent_domain;

	/* Otherwise ibpd isn't a parent_domain */
	return NULL;
}

static inline struct xsc_qp *to_xqp(struct ibv_qp *ibqp)
{
	struct verbs_qp *vqp = (struct verbs_qp *)ibqp;

	return container_of(vqp, struct xsc_qp, verbs_qp);
}

static inline struct xsc_cq *to_xcq(struct ibv_cq *ibcq)
{
	return container_of((struct ibv_cq_ex *)ibcq, struct xsc_cq,
			    verbs_cq.cq_ex);
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
int xsc_alloc_buf_contig(struct xsc_context *xctx, struct xsc_buf *buf,
			  size_t size, int page_size, const char *component);
void xsc_free_buf_contig(struct xsc_context *xctx, struct xsc_buf *buf);
int xsc_alloc_prefered_buf(struct xsc_context *xctx,
			    struct xsc_buf *buf,
			    size_t size, int page_size,
			    enum xsc_alloc_type alloc_type,
			    const char *component);
int xsc_free_actual_buf(struct xsc_context *ctx, struct xsc_buf *buf);
int xsc_use_huge(const char *key);
void xsc_get_alloc_type(struct xsc_context *context,
			 const char *component,
			 enum xsc_alloc_type *alloc_type,
			 enum xsc_alloc_type default_alloc_type);
int xsc_query_device(struct ibv_context *context, struct ibv_device_attr *attr);
int xsc_query_device_ex(struct ibv_context *context,
			const struct ibv_query_device_ex_input *input,
			struct ibv_device_attr_ex *attr, size_t attr_size);
int xsc_query_port(struct ibv_context *context, uint8_t port,
		   struct ibv_port_attr *attr);

struct ibv_pd *xsc_alloc_pd(struct ibv_context *context);
int xsc_free_pd(struct ibv_pd *pd);

struct ibv_mr *xsc_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			  uint64_t hca_va, int access);
int xsc_dereg_mr(struct verbs_mr *mr);
struct ibv_cq *xsc_create_cq(struct ibv_context *context, int cqe,
			     struct ibv_comp_channel *channel, int comp_vector);
struct ibv_cq_ex *xsc_create_cq_ex(struct ibv_context *context,
				   struct ibv_cq_init_attr_ex *cq_attr);
void xsc_cq_fill_pfns(struct xsc_cq *cq,
		      const struct ibv_cq_init_attr_ex *cq_attr);
int xsc_alloc_cq_buf(struct xsc_context *xctx, struct xsc_cq *cq,
		     struct xsc_buf *buf, int nent, int cqe_sz,
		     struct xscdv_devx_umem_in *umem_in);
int xsc_free_cq_buf(struct xsc_context *ctx, struct xsc_buf *buf);
int xsc_resize_cq(struct ibv_cq *cq, int cqe);
int xsc_destroy_cq(struct ibv_cq *cq);
void __xsc_cq_clean(struct xsc_cq *cq, uint32_t qpn);
void xsc_cq_clean(struct xsc_cq *cq, uint32_t qpn);

struct ibv_qp *xsc_create_qp_ex(struct ibv_context *context,
				struct ibv_qp_init_attr_ex *attr);
struct ibv_qp *xsc_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr);
int xsc_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		 struct ibv_qp_init_attr *init_attr);
int xsc_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask);
int xsc_destroy_qp(struct ibv_qp *qp);
void xsc_init_qp_indices(struct xsc_qp *qp);
struct xsc_qp *xsc_find_qp(struct xsc_context *ctx, uint32_t qpn);
int xsc_store_qp(struct xsc_context *ctx, uint32_t qpn, struct xsc_qp *qp);
void xsc_clear_qp(struct xsc_context *ctx, uint32_t qpn);
int xsc_err_state_qp(struct ibv_qp *qp, enum ibv_qp_state cur_state,
		     enum ibv_qp_state state);
int xsc_qp_fill_wr_pfns(struct xsc_context *ctx,
			struct xsc_qp *xqp,
			const struct ibv_qp_init_attr_ex *attr);

static inline int xsc_spin_lock(struct xsc_spinlock *lock)
{
	return pthread_spin_lock(&lock->lock);
}

static inline int xsc_spin_unlock(struct xsc_spinlock *lock)
{
	return pthread_spin_unlock(&lock->lock);
}

static inline int xsc_spinlock_init(struct xsc_spinlock *lock, int need_lock)
{
	lock->in_use = 0;
	lock->need_lock = need_lock;
	return pthread_spin_init(&lock->lock, PTHREAD_PROCESS_PRIVATE);
}

static inline int xsc_spinlock_init_pd(struct xsc_spinlock *lock, struct ibv_pd *pd)
{
	int thread_safe = xsc_single_threaded;

	return xsc_spinlock_init(lock, !thread_safe);
}

static inline int xsc_spinlock_destroy(struct xsc_spinlock *lock)
{
	return pthread_spin_destroy(&lock->lock);
}

static inline void set_command(int command, off_t *offset)
{
	*offset |= (command << XSC_IB_MMAP_CMD_SHIFT);
}

static inline void set_arg(int arg, off_t *offset)
{
	*offset |= arg;
}

static inline void set_order(int order, off_t *offset)
{
	set_arg(order, offset);
}

#endif /* XSC_H */
