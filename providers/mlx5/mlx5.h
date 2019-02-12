/*
 * Copyright (c) 2012 Mellanox Technologies, Inc.  All rights reserved.
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

#ifndef MLX5_H
#define MLX5_H

#include <stddef.h>
#include <stdio.h>
#include <stdatomic.h>
#include <util/compiler.h>

#include <infiniband/driver.h>
#include <util/udma_barrier.h>
#include "mlx5-abi.h"
#include <ccan/list.h>
#include "bitmap.h"
#include <ccan/minmax.h>
#include "mlx5dv.h"

#include <valgrind/memcheck.h>

#define PFX		"mlx5: "

typedef _Atomic(uint32_t) atomic_uint32_t;

enum {
	MLX5_IB_MMAP_CMD_SHIFT	= 8,
	MLX5_IB_MMAP_CMD_MASK	= 0xff,
};

enum {
	MLX5_CQE_VERSION_V0	= 0,
	MLX5_CQE_VERSION_V1	= 1,
};

enum {
	MLX5_ADAPTER_PAGE_SIZE		= 4096,
};

#define MLX5_CQ_PREFIX "MLX_CQ"
#define MLX5_QP_PREFIX "MLX_QP"
#define MLX5_MR_PREFIX "MLX_MR"
#define MLX5_RWQ_PREFIX "MLX_RWQ"
#define MLX5_MAX_LOG2_CONTIG_BLOCK_SIZE 23
#define MLX5_MIN_LOG2_CONTIG_BLOCK_SIZE 12

enum {
	MLX5_DBG_QP		= 1 << 0,
	MLX5_DBG_CQ		= 1 << 1,
	MLX5_DBG_QP_SEND	= 1 << 2,
	MLX5_DBG_QP_SEND_ERR	= 1 << 3,
	MLX5_DBG_CQ_CQE		= 1 << 4,
	MLX5_DBG_CONTIG		= 1 << 5,
};

extern uint32_t mlx5_debug_mask;
extern int mlx5_freeze_on_error_cqe;

#ifdef MLX5_DEBUG
#define mlx5_dbg(fp, mask, format, arg...)				\
do {									\
	if (mask & mlx5_debug_mask)					\
		fprintf(fp, "%s:%d: " format, __func__, __LINE__, ##arg);	\
} while (0)

#else
static inline void mlx5_dbg(FILE *fp, uint32_t mask, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));
static inline void mlx5_dbg(FILE *fp, uint32_t mask, const char *fmt, ...)
{
}
#endif

enum {
	MLX5_STAT_RATE_OFFSET		= 5
};

enum {
	MLX5_QP_TABLE_SHIFT		= 12,
	MLX5_QP_TABLE_MASK		= (1 << MLX5_QP_TABLE_SHIFT) - 1,
	MLX5_QP_TABLE_SIZE		= 1 << (24 - MLX5_QP_TABLE_SHIFT),
};

enum {
	MLX5_UIDX_TABLE_SHIFT		= 12,
	MLX5_UIDX_TABLE_MASK		= (1 << MLX5_UIDX_TABLE_SHIFT) - 1,
	MLX5_UIDX_TABLE_SIZE		= 1 << (24 - MLX5_UIDX_TABLE_SHIFT),
};

enum {
	MLX5_SRQ_TABLE_SHIFT		= 12,
	MLX5_SRQ_TABLE_MASK		= (1 << MLX5_SRQ_TABLE_SHIFT) - 1,
	MLX5_SRQ_TABLE_SIZE		= 1 << (24 - MLX5_SRQ_TABLE_SHIFT),
};

enum {
	MLX5_BF_OFFSET	= 0x800
};

enum {
	MLX5_TM_OPCODE_NOP		= 0x00,
	MLX5_TM_OPCODE_APPEND		= 0x01,
	MLX5_TM_OPCODE_REMOVE		= 0x02,
};

enum {
	MLX5_RECV_OPCODE_RDMA_WRITE_IMM	= 0x00,
	MLX5_RECV_OPCODE_SEND		= 0x01,
	MLX5_RECV_OPCODE_SEND_IMM	= 0x02,
	MLX5_RECV_OPCODE_SEND_INVAL	= 0x03,

	MLX5_CQE_OPCODE_ERROR		= 0x1e,
	MLX5_CQE_OPCODE_RESIZE		= 0x16,
};

enum {
	MLX5_SRQ_FLAG_TM_SW_CNT		= (1 << 6),
	MLX5_SRQ_FLAG_TM_CQE_REQ	= (1 << 7),
};

enum {
	MLX5_MAX_PORTS_NUM = 2,
};

enum {
	MLX5_CSUM_SUPPORT_RAW_OVER_ETH  = (1 << 0),
	MLX5_CSUM_SUPPORT_UNDERLAY_UD   = (1 << 1),
	/*
	 * Only report rx checksum when the validation
	 * is valid.
	 */
	MLX5_RX_CSUM_VALID              = (1 << 16),
};

enum mlx5_alloc_type {
	MLX5_ALLOC_TYPE_ANON,
	MLX5_ALLOC_TYPE_HUGE,
	MLX5_ALLOC_TYPE_CONTIG,
	MLX5_ALLOC_TYPE_PREFER_HUGE,
	MLX5_ALLOC_TYPE_PREFER_CONTIG,
	MLX5_ALLOC_TYPE_EXTERNAL,
	MLX5_ALLOC_TYPE_ALL
};

enum mlx5_rsc_type {
	MLX5_RSC_TYPE_QP,
	MLX5_RSC_TYPE_XSRQ,
	MLX5_RSC_TYPE_SRQ,
	MLX5_RSC_TYPE_RWQ,
	MLX5_RSC_TYPE_INVAL,
};

enum mlx5_vendor_cap_flags {
	MLX5_VENDOR_CAP_FLAGS_MPW		= 1 << 0, /* Obsoleted */
	MLX5_VENDOR_CAP_FLAGS_MPW_ALLOWED	= 1 << 1,
	MLX5_VENDOR_CAP_FLAGS_ENHANCED_MPW	= 1 << 2,
	MLX5_VENDOR_CAP_FLAGS_CQE_128B_COMP	= 1 << 3,
	MLX5_VENDOR_CAP_FLAGS_CQE_128B_PAD	= 1 << 4,
	MLX5_VENDOR_CAP_FLAGS_PACKET_BASED_CREDIT_MODE	= 1 << 5,
};

enum {
	MLX5_FLOW_TAG_MASK	= 0x00ffffff,
};

struct mlx5_resource {
	enum mlx5_rsc_type	type;
	uint32_t		rsn;
};

struct mlx5_device {
	struct verbs_device	verbs_dev;
	int			page_size;
	int			driver_abi_ver;
};

struct mlx5_db_page;

struct mlx5_spinlock {
	pthread_spinlock_t		lock;
	int				in_use;
	int				need_lock;
};

enum mlx5_uar_type {
	MLX5_UAR_TYPE_REGULAR,
	MLX5_UAR_TYPE_NC,
	MLX5_UAR_TYPE_REGULAR_DYN,
};

struct mlx5_uar_info {
	void				*reg;
	enum mlx5_uar_type		type;
};

struct mlx5_context {
	struct verbs_context		ibv_ctx;
	int				max_num_qps;
	int				bf_reg_size;
	int				tot_uuars;
	int				low_lat_uuars;
	int				num_uars_per_page;
	int				bf_regs_per_page;
	int				num_bf_regs;
	int				prefer_bf;
	int				shut_up_bf;
	struct {
		struct mlx5_qp        **table;
		int			refcnt;
	}				qp_table[MLX5_QP_TABLE_SIZE];
	pthread_mutex_t			qp_table_mutex;

	struct {
		struct mlx5_srq	      **table;
		int			refcnt;
	}				srq_table[MLX5_SRQ_TABLE_SIZE];
	pthread_mutex_t			srq_table_mutex;

	struct {
		struct mlx5_resource  **table;
		int                     refcnt;
	}				uidx_table[MLX5_UIDX_TABLE_SIZE];
	pthread_mutex_t                 uidx_table_mutex;

	struct mlx5_uar_info		uar[MLX5_MAX_UARS];
	struct mlx5_db_page	       *db_list;
	pthread_mutex_t			db_list_mutex;
	int				cache_line_size;
	int				max_sq_desc_sz;
	int				max_rq_desc_sz;
	int				max_send_wqebb;
	int				max_recv_wr;
	unsigned			max_srq_recv_wr;
	int				num_ports;
	int				stall_enable;
	int				stall_adaptive_enable;
	int				stall_cycles;
	struct mlx5_bf		       *bfs;
	FILE			       *dbg_fp;
	char				hostname[40];
	struct mlx5_spinlock            hugetlb_lock;
	struct list_head                hugetlb_list;
	int				cqe_version;
	uint8_t				cached_link_layer[MLX5_MAX_PORTS_NUM];
	uint8_t				cached_port_flags[MLX5_MAX_PORTS_NUM];
	unsigned int			cached_device_cap_flags;
	enum ibv_atomic_cap		atomic_cap;
	struct {
		uint64_t                offset;
		uint64_t                mask;
	} core_clock;
	void			       *hca_core_clock;
	const struct mlx5_ib_clock_info *clock_info_page;
	struct ibv_tso_caps		cached_tso_caps;
	int				cmds_supp_uhw;
	uint32_t			uar_size;
	uint64_t			vendor_cap_flags; /* Use enum mlx5_vendor_cap_flags */
	struct mlx5dv_cqe_comp_caps	cqe_comp_caps;
	struct mlx5dv_ctx_allocators	extern_alloc;
	struct mlx5dv_sw_parsing_caps	sw_parsing_caps;
	struct mlx5dv_striding_rq_caps	striding_rq_caps;
	uint32_t			tunnel_offloads_caps;
	struct mlx5_packet_pacing_caps	packet_pacing_caps;
	pthread_mutex_t			dyn_bfregs_mutex; /* protects the dynamic bfregs allocation */
	uint32_t			num_dyn_bfregs;
	uint32_t			*count_dyn_bfregs;
	uint32_t			start_dyn_bfregs_index;
	uint16_t			flow_action_flags;
	uint64_t			max_dm_size;
	uint32_t                        eth_min_inline_size;
	uint32_t                        dump_fill_mkey;
	__be32                          dump_fill_mkey_be;
};

struct mlx5_bitmap {
	uint32_t		last;
	uint32_t		top;
	uint32_t		max;
	uint32_t		avail;
	uint32_t		mask;
	unsigned long	       *table;
};

struct mlx5_hugetlb_mem {
	int			shmid;
	void		       *shmaddr;
	struct mlx5_bitmap	bitmap;
	struct list_node	entry;
};

struct mlx5_buf {
	void			       *buf;
	size_t				length;
	int                             base;
	struct mlx5_hugetlb_mem	       *hmem;
	enum mlx5_alloc_type		type;
};

struct mlx5_td {
	struct ibv_td			ibv_td;
	struct mlx5_bf			*bf;
	atomic_int			refcount;
};

struct mlx5_pd {
	struct ibv_pd			ibv_pd;
	uint32_t			pdn;
	atomic_int			refcount;
	struct mlx5_pd			*mprotection_domain;
};

struct mlx5_parent_domain {
	struct mlx5_pd mpd;
	struct mlx5_td *mtd;
};

enum {
	MLX5_CQ_SET_CI	= 0,
	MLX5_CQ_ARM_DB	= 1,
};

enum {
	MLX5_CQ_FLAGS_RX_CSUM_VALID = 1 << 0,
	MLX5_CQ_FLAGS_EMPTY_DURING_POLL = 1 << 1,
	MLX5_CQ_FLAGS_FOUND_CQES = 1 << 2,
	MLX5_CQ_FLAGS_EXTENDED = 1 << 3,
	MLX5_CQ_FLAGS_SINGLE_THREADED = 1 << 4,
	MLX5_CQ_FLAGS_DV_OWNED = 1 << 5,
	MLX5_CQ_FLAGS_TM_SYNC_REQ = 1 << 6,
};

struct mlx5_cq {
	/* ibv_cq should always be subset of ibv_cq_ex */
	struct ibv_cq_ex		ibv_cq;
	struct mlx5_buf			buf_a;
	struct mlx5_buf			buf_b;
	struct mlx5_buf		       *active_buf;
	struct mlx5_buf		       *resize_buf;
	int				resize_cqes;
	int				active_cqes;
	struct mlx5_spinlock		lock;
	uint32_t			cqn;
	uint32_t			cons_index;
	__be32			       *dbrec;
	int				arm_sn;
	int				cqe_sz;
	int				resize_cqe_sz;
	int				stall_next_poll;
	int				stall_enable;
	uint64_t			stall_last_count;
	int				stall_adaptive_enable;
	int				stall_cycles;
	struct mlx5_resource		*cur_rsc;
	struct mlx5_srq			*cur_srq;
	struct mlx5_cqe64		*cqe64;
	uint32_t			flags;
	int			umr_opcode;
	struct mlx5dv_clock_info	last_clock_info;
};

struct mlx5_tag_entry {
	struct mlx5_tag_entry *next;
	uint64_t	       wr_id;
	int		       phase_cnt;
	void		      *ptr;
	uint32_t	       size;
	int8_t		       expect_cqe;
};

struct mlx5_srq_op {
	struct mlx5_tag_entry *tag;
	uint64_t	       wr_id;
	/* we need to advance tail pointer */
	uint32_t	       wqe_head;
};

struct mlx5_srq {
	struct mlx5_resource            rsc;  /* This struct must be first */
	struct verbs_srq		vsrq;
	struct mlx5_buf			buf;
	struct mlx5_spinlock		lock;
	uint64_t		       *wrid;
	uint32_t			srqn;
	int				max;
	int				max_gs;
	int				wqe_shift;
	int				head;
	int				tail;
	int				waitq_head;
	int				waitq_tail;
	__be32			       *db;
	uint16_t			counter;
	int				wq_sig;
	struct ibv_qp		       *cmd_qp;
	struct mlx5_tag_entry	       *tm_list; /* vector of all tags */
	struct mlx5_tag_entry	       *tm_head; /* queue of free tags */
	struct mlx5_tag_entry	       *tm_tail;
	struct mlx5_srq_op	       *op;
	int				op_head;
	int				op_tail;
	int				unexp_in;
	int				unexp_out;
};


static inline void mlx5_tm_release_tag(struct mlx5_srq *srq,
				       struct mlx5_tag_entry *tag)
{
	if (!--tag->expect_cqe) {
		tag->next = NULL;
		srq->tm_tail->next = tag;
		srq->tm_tail = tag;
	}
}

struct wr_list {
	uint16_t	opcode;
	uint16_t	next;
};

struct mlx5_wq {
	uint64_t		       *wrid;
	unsigned		       *wqe_head;
	struct mlx5_spinlock		lock;
	unsigned			wqe_cnt;
	unsigned			max_post;
	unsigned			head;
	unsigned			tail;
	unsigned			cur_post;
	int				max_gs;
	int				wqe_shift;
	int				offset;
	void			       *qend;
	uint32_t			*wr_data;
};

struct mlx5_devx_uar {
	struct mlx5dv_devx_uar dv_devx_uar;
	struct ibv_context *context;
};

struct mlx5_bf {
	void			       *reg;
	int				need_lock;
	struct mlx5_spinlock		lock;
	unsigned			offset;
	unsigned			buf_size;
	unsigned			uuarn;
	off_t				uar_mmap_offset;
	/* The virtual address of the mmaped uar, applicable for the dynamic use case */
	void				*uar;
	/* Index in the dynamic bfregs portion */
	uint32_t			bfreg_dyn_index;
	struct mlx5_devx_uar		devx_uar;
};

struct mlx5_dm {
	struct verbs_dm			verbs_dm;
	size_t				length;
	void			       *mmap_va;
	void			       *start_va;
};

struct mlx5_mr {
	struct verbs_mr                 vmr;
	struct mlx5_buf			buf;
	uint32_t			alloc_flags;
};

enum mlx5_qp_flags {
	MLX5_QP_FLAGS_USE_UNDERLAY = 0x01,
};

struct mlx5_qp {
	struct mlx5_resource            rsc; /* This struct must be first */
	struct verbs_qp			verbs_qp;
	struct ibv_qp		       *ibv_qp;
	struct mlx5_buf                 buf;
	void				*sq_start;
	int                             max_inline_data;
	int                             buf_size;
	/* For Raw Packet QP, use different buffers for the SQ and RQ */
	struct mlx5_buf                 sq_buf;
	int				sq_buf_size;
	struct mlx5_bf		       *bf;

	uint8_t				fm_cache;
	uint8_t	                        sq_signal_bits;
	struct mlx5_wq                  sq;

	__be32                         *db;
	struct mlx5_wq                  rq;
	int                             wq_sig;
	uint32_t			qp_cap_cache;
	int				atomics_enabled;
	uint32_t			max_tso;
	uint16_t			max_tso_header;
	int                             rss_qp;
	uint32_t			flags; /* Use enum mlx5_qp_flags */
	enum mlx5dv_dc_type		dc_type;
	uint32_t			tirn;
	uint32_t			tisn;
	uint32_t			rqn;
	uint32_t			sqn;
};

struct mlx5_ah {
	struct ibv_ah			ibv_ah;
	struct mlx5_wqe_av		av;
	bool				kern_ah;
};

struct mlx5_rwq {
	struct mlx5_resource rsc;
	struct ibv_wq wq;
	struct mlx5_buf buf;
	int buf_size;
	struct mlx5_wq rq;
	__be32  *db;
	void	*pbuff;
	__be32	*recv_db;
	int wq_sig;
};

struct mlx5_counter_node {
	uint32_t index;
	struct list_node entry;
	enum ibv_counter_description desc;
};

struct mlx5_counters {
	struct verbs_counters vcounters;
	struct list_head counters_list;
	pthread_mutex_t lock;
	uint32_t ncounters;
	/* number of bounded objects */
	int refcount;
};

struct mlx5_flow {
	struct ibv_flow flow_id;
	struct mlx5_counters *mcounters;
};

struct mlx5dv_flow_matcher {
	struct ibv_context *context;
	uint32_t handle;
};

struct mlx5dv_devx_obj {
	struct ibv_context *context;
	uint32_t handle;
};

struct mlx5_devx_umem {
	struct mlx5dv_devx_umem dv_devx_umem;
	struct ibv_context *context;
	uint32_t handle;
};

static inline int mlx5_ilog2(int n)
{
	int t;

	if (n <= 0)
		return -1;

	t = 0;
	while ((1 << t) < n)
		++t;

	return t;
}

extern int mlx5_stall_num_loop;
extern int mlx5_stall_cq_poll_min;
extern int mlx5_stall_cq_poll_max;
extern int mlx5_stall_cq_inc_step;
extern int mlx5_stall_cq_dec_step;
extern int mlx5_single_threaded;

static inline unsigned DIV_ROUND_UP(unsigned n, unsigned d)
{
	return (n + d - 1u) / d;
}

static inline unsigned long align(unsigned long val, unsigned long align)
{
	return (val + align - 1) & ~(align - 1);
}

#define to_mxxx(xxx, type) container_of(ib##xxx, struct mlx5_##type, ibv_##xxx)

static inline struct mlx5_device *to_mdev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct mlx5_device, verbs_dev.device);
}

static inline struct mlx5_context *to_mctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct mlx5_context, ibv_ctx.context);
}

/* to_mpd always returns the real mlx5_pd object ie the protection domain. */
static inline struct mlx5_pd *to_mpd(struct ibv_pd *ibpd)
{
	struct mlx5_pd *mpd = to_mxxx(pd, pd);

	if (mpd->mprotection_domain)
		return mpd->mprotection_domain;

	return mpd;
}

static inline struct mlx5_parent_domain *to_mparent_domain(struct ibv_pd *ibpd)
{
	struct mlx5_parent_domain *mparent_domain =
	    ibpd ? container_of(ibpd, struct mlx5_parent_domain, mpd.ibv_pd) : NULL;

	if (mparent_domain && mparent_domain->mpd.mprotection_domain)
		return mparent_domain;

	/* Otherwise ibpd isn't a parent_domain */
	return NULL;
}

static inline struct mlx5_cq *to_mcq(struct ibv_cq *ibcq)
{
	return container_of((struct ibv_cq_ex *)ibcq, struct mlx5_cq, ibv_cq);
}

static inline struct mlx5_srq *to_msrq(struct ibv_srq *ibsrq)
{
	struct verbs_srq *vsrq = (struct verbs_srq *)ibsrq;

	return container_of(vsrq, struct mlx5_srq, vsrq);
}

static inline struct mlx5_td *to_mtd(struct ibv_td *ibtd)
{
	return to_mxxx(td, td);
}

static inline struct mlx5_qp *to_mqp(struct ibv_qp *ibqp)
{
	struct verbs_qp *vqp = (struct verbs_qp *)ibqp;

	return container_of(vqp, struct mlx5_qp, verbs_qp);
}

static inline struct mlx5_rwq *to_mrwq(struct ibv_wq *ibwq)
{
	return container_of(ibwq, struct mlx5_rwq, wq);
}

static inline struct mlx5_dm *to_mdm(struct ibv_dm *ibdm)
{
	return container_of(ibdm, struct mlx5_dm, verbs_dm.dm);
}

static inline struct mlx5_mr *to_mmr(struct ibv_mr *ibmr)
{
	return container_of(ibmr, struct mlx5_mr, vmr.ibv_mr);
}

static inline struct mlx5_ah *to_mah(struct ibv_ah *ibah)
{
	return to_mxxx(ah, ah);
}

static inline int max_int(int a, int b)
{
	return a > b ? a : b;
}

static inline struct mlx5_qp *rsc_to_mqp(struct mlx5_resource *rsc)
{
	return (struct mlx5_qp *)rsc;
}

static inline struct mlx5_srq *rsc_to_msrq(struct mlx5_resource *rsc)
{
	return (struct mlx5_srq *)rsc;
}

static inline struct mlx5_rwq *rsc_to_mrwq(struct mlx5_resource *rsc)
{
	return (struct mlx5_rwq *)rsc;
}

static inline struct mlx5_counters *to_mcounters(struct ibv_counters *ibcounters)
{
	return container_of(ibcounters, struct mlx5_counters, vcounters.counters);
}

static inline struct mlx5_flow *to_mflow(struct ibv_flow *flow_id)
{
	return container_of(flow_id, struct mlx5_flow, flow_id);
}

bool is_mlx5_dev(struct ibv_device *device);

int mlx5_alloc_buf(struct mlx5_buf *buf, size_t size, int page_size);
void mlx5_free_buf(struct mlx5_buf *buf);
int mlx5_alloc_buf_contig(struct mlx5_context *mctx, struct mlx5_buf *buf,
			  size_t size, int page_size, const char *component);
void mlx5_free_buf_contig(struct mlx5_context *mctx, struct mlx5_buf *buf);
int mlx5_alloc_prefered_buf(struct mlx5_context *mctx,
			    struct mlx5_buf *buf,
			    size_t size, int page_size,
			    enum mlx5_alloc_type alloc_type,
			    const char *component);
int mlx5_free_actual_buf(struct mlx5_context *ctx, struct mlx5_buf *buf);
void mlx5_get_alloc_type(struct mlx5_context *context,
			 const char *component,
			 enum mlx5_alloc_type *alloc_type,
			 enum mlx5_alloc_type default_alloc_type);
int mlx5_use_huge(const char *key);
bool mlx5_is_extern_alloc(struct mlx5_context *context);
int mlx5_alloc_buf_extern(struct mlx5_context *ctx, struct mlx5_buf *buf,
			  size_t size);
void mlx5_free_buf_extern(struct mlx5_context *ctx, struct mlx5_buf *buf);

__be32 *mlx5_alloc_dbrec(struct mlx5_context *context);
void mlx5_free_db(struct mlx5_context *context, __be32 *db);

int mlx5_query_device(struct ibv_context *context,
		       struct ibv_device_attr *attr);
int mlx5_query_device_ex(struct ibv_context *context,
			 const struct ibv_query_device_ex_input *input,
			 struct ibv_device_attr_ex *attr,
			 size_t attr_size);
int mlx5_query_rt_values(struct ibv_context *context,
			 struct ibv_values_ex *values);
struct ibv_qp *mlx5_create_qp_ex(struct ibv_context *context,
				 struct ibv_qp_init_attr_ex *attr);
int mlx5_query_port(struct ibv_context *context, uint8_t port,
		     struct ibv_port_attr *attr);

struct ibv_pd *mlx5_alloc_pd(struct ibv_context *context);
int mlx5_free_pd(struct ibv_pd *pd);

struct ibv_mr *mlx5_alloc_null_mr(struct ibv_pd *pd);
struct ibv_mr *mlx5_reg_mr(struct ibv_pd *pd, void *addr,
			   size_t length, int access);
int mlx5_rereg_mr(struct verbs_mr *mr, int flags, struct ibv_pd *pd, void *addr,
		  size_t length, int access);
int mlx5_dereg_mr(struct verbs_mr *mr);
struct ibv_mw *mlx5_alloc_mw(struct ibv_pd *pd, enum ibv_mw_type);
int mlx5_dealloc_mw(struct ibv_mw *mw);
int mlx5_bind_mw(struct ibv_qp *qp, struct ibv_mw *mw,
		 struct ibv_mw_bind *mw_bind);

struct ibv_cq *mlx5_create_cq(struct ibv_context *context, int cqe,
			       struct ibv_comp_channel *channel,
			       int comp_vector);
struct ibv_cq_ex *mlx5_create_cq_ex(struct ibv_context *context,
				    struct ibv_cq_init_attr_ex *cq_attr);
int mlx5_cq_fill_pfns(struct mlx5_cq *cq,
		      const struct ibv_cq_init_attr_ex *cq_attr,
		      struct mlx5_context *mctx);
int mlx5_alloc_cq_buf(struct mlx5_context *mctx, struct mlx5_cq *cq,
		      struct mlx5_buf *buf, int nent, int cqe_sz);
int mlx5_free_cq_buf(struct mlx5_context *ctx, struct mlx5_buf *buf);
int mlx5_resize_cq(struct ibv_cq *cq, int cqe);
int mlx5_modify_cq(struct ibv_cq *cq, struct ibv_modify_cq_attr *attr);
int mlx5_destroy_cq(struct ibv_cq *cq);
int mlx5_poll_cq(struct ibv_cq *cq, int ne, struct ibv_wc *wc);
int mlx5_poll_cq_v1(struct ibv_cq *cq, int ne, struct ibv_wc *wc);
int mlx5_arm_cq(struct ibv_cq *cq, int solicited);
void mlx5_cq_event(struct ibv_cq *cq);
void __mlx5_cq_clean(struct mlx5_cq *cq, uint32_t qpn, struct mlx5_srq *srq);
void mlx5_cq_clean(struct mlx5_cq *cq, uint32_t qpn, struct mlx5_srq *srq);
void mlx5_cq_resize_copy_cqes(struct mlx5_cq *cq);

struct ibv_srq *mlx5_create_srq(struct ibv_pd *pd,
				 struct ibv_srq_init_attr *attr);
int mlx5_modify_srq(struct ibv_srq *srq, struct ibv_srq_attr *attr,
		    int mask);
int mlx5_query_srq(struct ibv_srq *srq,
			   struct ibv_srq_attr *attr);
int mlx5_destroy_srq(struct ibv_srq *srq);
int mlx5_alloc_srq_buf(struct ibv_context *context, struct mlx5_srq *srq,
		       uint32_t nwr);
void mlx5_complete_odp_fault(struct mlx5_srq *srq, int ind);
void mlx5_free_srq_wqe(struct mlx5_srq *srq, int ind);
int mlx5_post_srq_recv(struct ibv_srq *ibsrq,
		       struct ibv_recv_wr *wr,
		       struct ibv_recv_wr **bad_wr);

struct ibv_qp *mlx5_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr);
int mlx5_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		  int attr_mask,
		  struct ibv_qp_init_attr *init_attr);
int mlx5_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		   int attr_mask);
int mlx5_modify_qp_rate_limit(struct ibv_qp *qp,
			      struct ibv_qp_rate_limit_attr *attr);
int mlx5_destroy_qp(struct ibv_qp *qp);
void mlx5_init_qp_indices(struct mlx5_qp *qp);
void mlx5_init_rwq_indices(struct mlx5_rwq *rwq);
int mlx5_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
			  struct ibv_send_wr **bad_wr);
int mlx5_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
			  struct ibv_recv_wr **bad_wr);
int mlx5_post_wq_recv(struct ibv_wq *ibwq, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad_wr);
void mlx5_calc_sq_wqe_size(struct ibv_qp_cap *cap, enum ibv_qp_type type,
			   struct mlx5_qp *qp);
void mlx5_set_sq_sizes(struct mlx5_qp *qp, struct ibv_qp_cap *cap,
		       enum ibv_qp_type type);
struct mlx5_qp *mlx5_find_qp(struct mlx5_context *ctx, uint32_t qpn);
int mlx5_store_qp(struct mlx5_context *ctx, uint32_t qpn, struct mlx5_qp *qp);
void mlx5_clear_qp(struct mlx5_context *ctx, uint32_t qpn);
int32_t mlx5_store_uidx(struct mlx5_context *ctx, void *rsc);
void mlx5_clear_uidx(struct mlx5_context *ctx, uint32_t uidx);
struct mlx5_srq *mlx5_find_srq(struct mlx5_context *ctx, uint32_t srqn);
int mlx5_store_srq(struct mlx5_context *ctx, uint32_t srqn,
		   struct mlx5_srq *srq);
void mlx5_clear_srq(struct mlx5_context *ctx, uint32_t srqn);
struct ibv_ah *mlx5_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr);
int mlx5_destroy_ah(struct ibv_ah *ah);
int mlx5_alloc_av(struct mlx5_pd *pd, struct ibv_ah_attr *attr,
		   struct mlx5_ah *ah);
void mlx5_free_av(struct mlx5_ah *ah);
int mlx5_attach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid);
int mlx5_detach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid);
int mlx5_round_up_power_of_two(long long sz);
void *mlx5_get_atomic_laddr(struct mlx5_qp *qp, uint16_t idx, int *byte_count);
void *mlx5_get_send_wqe(struct mlx5_qp *qp, int n);
int mlx5_copy_to_recv_wqe(struct mlx5_qp *qp, int idx, void *buf, int size);
int mlx5_copy_to_send_wqe(struct mlx5_qp *qp, int idx, void *buf, int size);
int mlx5_copy_to_recv_srq(struct mlx5_srq *srq, int idx, void *buf, int size);
struct ibv_xrcd *mlx5_open_xrcd(struct ibv_context *context,
				struct ibv_xrcd_init_attr *xrcd_init_attr);
int mlx5_get_srq_num(struct ibv_srq *srq, uint32_t *srq_num);
int mlx5_close_xrcd(struct ibv_xrcd *ib_xrcd);
struct ibv_wq *mlx5_create_wq(struct ibv_context *context,
			      struct ibv_wq_init_attr *attr);
int mlx5_modify_wq(struct ibv_wq *wq, struct ibv_wq_attr *attr);
int mlx5_destroy_wq(struct ibv_wq *wq);
struct ibv_rwq_ind_table *mlx5_create_rwq_ind_table(struct ibv_context *context,
						    struct ibv_rwq_ind_table_init_attr *init_attr);
int mlx5_destroy_rwq_ind_table(struct ibv_rwq_ind_table *rwq_ind_table);
struct ibv_flow *mlx5_create_flow(struct ibv_qp *qp, struct ibv_flow_attr *flow_attr);
int mlx5_destroy_flow(struct ibv_flow *flow_id);
struct ibv_srq *mlx5_create_srq_ex(struct ibv_context *context,
				   struct ibv_srq_init_attr_ex *attr);
int mlx5_post_srq_ops(struct ibv_srq *srq,
		      struct ibv_ops_wr *wr,
		      struct ibv_ops_wr **bad_wr);
struct ibv_flow_action *mlx5_create_flow_action_esp(struct ibv_context *ctx,
						    struct ibv_flow_action_esp_attr *attr);
int mlx5_destroy_flow_action(struct ibv_flow_action *action);
int mlx5_modify_flow_action_esp(struct ibv_flow_action *action,
				struct ibv_flow_action_esp_attr *attr);

struct ibv_dm *mlx5_alloc_dm(struct ibv_context *context,
			     struct ibv_alloc_dm_attr *dm_attr);
int mlx5_free_dm(struct ibv_dm *ibdm);
struct ibv_mr *mlx5_reg_dm_mr(struct ibv_pd *pd, struct ibv_dm *ibdm,
			      uint64_t dm_offset, size_t length,
			      unsigned int acc);

struct ibv_td *mlx5_alloc_td(struct ibv_context *context, struct ibv_td_init_attr *init_attr);
int mlx5_dealloc_td(struct ibv_td *td);

struct ibv_pd *mlx5_alloc_parent_domain(struct ibv_context *context,
					struct ibv_parent_domain_init_attr *attr);


void *mlx5_mmap(struct mlx5_uar_info *uar, int index,
		int cmd_fd, int page_size, int uar_type);

struct ibv_counters *mlx5_create_counters(struct ibv_context *context,
					  struct ibv_counters_init_attr *init_attr);
int mlx5_destroy_counters(struct ibv_counters *counters);
int mlx5_attach_counters_point_flow(struct ibv_counters *counters,
				    struct ibv_counter_attach_attr *attr,
				    struct ibv_flow *flow);
int mlx5_read_counters(struct ibv_counters *counters,
		       uint64_t *counters_value,
		       uint32_t ncounters,
		       uint32_t flags);
int mlx5_advise_mr(struct ibv_pd *pd,
		   enum ibv_advise_mr_advice advice,
		   uint32_t flags,
		   struct ibv_sge *sg_list,
		   uint32_t num_sges);
static inline void *mlx5_find_uidx(struct mlx5_context *ctx, uint32_t uidx)
{
	int tind = uidx >> MLX5_UIDX_TABLE_SHIFT;

	if (likely(ctx->uidx_table[tind].refcnt))
		return ctx->uidx_table[tind].table[uidx & MLX5_UIDX_TABLE_MASK];

	return NULL;
}

static inline int mlx5_spin_lock(struct mlx5_spinlock *lock)
{
	if (lock->need_lock)
		return pthread_spin_lock(&lock->lock);

	if (unlikely(lock->in_use)) {
		fprintf(stderr, "*** ERROR: multithreading vilation ***\n"
			"You are running a multithreaded application but\n"
			"you set MLX5_SINGLE_THREADED=1. Please unset it.\n");
		abort();
	} else {
		lock->in_use = 1;
		/*
		 * This fence is not at all correct, but it increases the
		 * chance that in_use is detected by another thread without
		 * much runtime cost. */
		atomic_thread_fence(memory_order_acq_rel);
	}

	return 0;
}

static inline int mlx5_spin_unlock(struct mlx5_spinlock *lock)
{
	if (lock->need_lock)
		return pthread_spin_unlock(&lock->lock);

	lock->in_use = 0;

	return 0;
}

static inline int mlx5_spinlock_init(struct mlx5_spinlock *lock, int need_lock)
{
	lock->in_use = 0;
	lock->need_lock = need_lock;
	return pthread_spin_init(&lock->lock, PTHREAD_PROCESS_PRIVATE);
}

static inline int mlx5_spinlock_init_pd(struct mlx5_spinlock *lock, struct ibv_pd *pd)
{
	struct mlx5_parent_domain *mparent_domain;
	int thread_safe;

	mparent_domain = to_mparent_domain(pd);
	if (mparent_domain && mparent_domain->mtd)
		thread_safe = 1;
	else
		thread_safe = mlx5_single_threaded;

	return mlx5_spinlock_init(lock, !thread_safe);
}

static inline int mlx5_spinlock_destroy(struct mlx5_spinlock *lock)
{
	return pthread_spin_destroy(&lock->lock);
}

static inline void set_command(int command, off_t *offset)
{
	*offset |= (command << MLX5_IB_MMAP_CMD_SHIFT);
}

static inline void set_arg(int arg, off_t *offset)
{
	*offset |= arg;
}

static inline void set_order(int order, off_t *offset)
{
	set_arg(order, offset);
}

static inline void set_index(int index, off_t *offset)
{
	set_arg(index, offset);
}

static inline void set_extended_index(int index, off_t *offset)
{
	*offset |= (index & 0xff) | ((index >> 8) << 16);
}

static inline uint8_t calc_sig(void *wqe, int size)
{
	int i;
	uint8_t *p = wqe;
	uint8_t res = 0;

	for (i = 0; i < size; ++i)
		res ^= p[i];

	return ~res;
}

static inline int align_queue_size(long long req)
{
	return mlx5_round_up_power_of_two(req);
}

static inline bool srq_has_waitq(struct mlx5_srq *srq)
{
	return srq->waitq_head >= 0;
}

bool srq_cooldown_wqe(struct mlx5_srq *srq, int ind);

#endif /* MLX5_H */
