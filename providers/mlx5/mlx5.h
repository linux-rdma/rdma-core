/*
 * Copyright (c) 2012 Mellanox Technologies, Inc.  All rights reserved.
 * Copyright (c) 2020 Intel Corporation.  All rights reserved.
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
#include <stdarg.h>
#include <stdatomic.h>
#include <util/compiler.h>

#include <infiniband/driver.h>
#include <util/udma_barrier.h>
#include <util/util.h>
#include "mlx5-abi.h"
#include <ccan/bitmap.h>
#include <ccan/list.h>
#include "bitmap.h"
#include <ccan/minmax.h>
#include "mlx5dv.h"

#include <valgrind/memcheck.h>

#define PFX		"mlx5: "

#ifndef PCI_VENDOR_ID_MELLANOX
#define PCI_VENDOR_ID_MELLANOX 0x15b3
#endif

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
	MLX5_ADAPTER_PAGE_SHIFT		= 12,
};

#define MLX5_CQ_PREFIX "MLX_CQ"
#define MLX5_QP_PREFIX "MLX_QP"
#define MLX5_MR_PREFIX "MLX_MR"
#define MLX5_RWQ_PREFIX "MLX_RWQ"
#define MLX5_SRQ_PREFIX "MLX_SRQ"
#define MLX5_MAX_LOG2_CONTIG_BLOCK_SIZE 23
#define MLX5_MIN_LOG2_CONTIG_BLOCK_SIZE 12

enum {
	MLX5_DBG_QP		= 1 << 0,
	MLX5_DBG_CQ		= 1 << 1,
	MLX5_DBG_QP_SEND	= 1 << 2,
	MLX5_DBG_QP_SEND_ERR	= 1 << 3,
	MLX5_DBG_CQ_CQE		= 1 << 4,
	MLX5_DBG_CONTIG		= 1 << 5,
	MLX5_DBG_DR		= 1 << 6,
};

extern uint32_t mlx5_debug_mask;
extern int mlx5_freeze_on_error_cqe;
extern const struct verbs_match_ent mlx5_hca_table[];

#ifdef MLX5_DEBUG
#define mlx5_dbg(fp, mask, format, arg...)				\
do {									\
	if (mask & mlx5_debug_mask) {					\
		int tmp = errno;					\
		fprintf(fp, "%s:%d: " format, __func__, __LINE__, ##arg);	\
		errno = tmp;						\
	}								\
} while (0)

#else
static inline void mlx5_dbg(FILE *fp, uint32_t mask, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));
static inline void mlx5_dbg(FILE *fp, uint32_t mask, const char *fmt, ...)
{
}
#endif

__attribute__((format(printf, 2, 3)))
static inline void mlx5_err(FILE *fp, const char *fmt, ...)
{
	va_list args;

	if (!fp)
		return;
	va_start(args, fmt);
	vfprintf(fp, fmt, args);
	va_end(args);
}

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
	MLX5_MKEY_TABLE_SHIFT		= 12,
	MLX5_MKEY_TABLE_MASK		= (1 << MLX5_MKEY_TABLE_SHIFT) - 1,
	MLX5_MKEY_TABLE_SIZE		= 1 << (24 - MLX5_MKEY_TABLE_SHIFT),
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
	MLX5_ALLOC_TYPE_CUSTOM,
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
	MLX5_VENDOR_CAP_FLAGS_SCAT2CQE_DCT = 1 << 6,
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

enum mlx5_ctx_flags {
	MLX5_CTX_FLAGS_FATAL_STATE = 1 << 0,
	MLX5_CTX_FLAGS_NO_KERN_DYN_UAR = 1 << 1,
	MLX5_CTX_FLAGS_ECE_SUPPORTED = 1 << 2,
	MLX5_CTX_FLAGS_SQD2RTS_SUPPORTED = 1 << 3,
	MLX5_CTX_FLAGS_REAL_TIME_TS_SUPPORTED = 1 << 4,
};

struct mlx5_entropy_caps {
	uint8_t num_lag_ports;
	uint8_t lag_tx_port_affinity:1;
	uint8_t rts2rts_qp_udp_sport:1;
	uint8_t rts2rts_lag_tx_port_affinity:1;
};

struct mlx5_qos_caps {
	uint8_t qos:1;

	uint8_t nic_sq_scheduling:1;
	uint8_t nic_bw_share:1;
	uint8_t nic_rate_limit:1;
	uint8_t nic_qp_scheduling:1;

	uint32_t nic_element_type;
	uint32_t nic_tsar_type;
};

struct mlx5_hca_cap_2_caps {
	uint32_t log_reserved_qpns_per_obj;
};

struct reserved_qpn_blk {
	bitmap *bmp;
	uint32_t first_qpn;
	struct list_node entry;
	unsigned int next_avail_slot;
	struct mlx5dv_devx_obj *obj;
};

struct mlx5_reserved_qpns {
	struct list_head blk_list;
	pthread_mutex_t mutex;
};

struct mlx5_dv_context_ops;

#define MLX5_DMA_MMO_MAX_SIZE	(1ULL << 31)
struct mlx5_dma_mmo_caps {
	uint8_t dma_mmo_sq:1; /* Indicates that RC and DCI support DMA MMO */
	uint8_t dma_mmo_qp:1;
	uint64_t dma_max_size;
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

	struct {
		struct mlx5_mkey      **table;
		int			refcnt;
	}				mkey_table[MLX5_MKEY_TABLE_SIZE];
	pthread_mutex_t			mkey_table_mutex;

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
	struct mlx5_ib_tso_caps		cached_tso_caps;
	int				cmds_supp_uhw;
	uint32_t			uar_size;
	uint64_t			vendor_cap_flags; /* Use enum mlx5_vendor_cap_flags */
	struct mlx5dv_cqe_comp_caps	cqe_comp_caps;
	struct mlx5dv_ctx_allocators	extern_alloc;
	struct mlx5dv_sw_parsing_caps	sw_parsing_caps;
	struct mlx5dv_striding_rq_caps	striding_rq_caps;
	struct mlx5dv_dci_streams_caps  dci_streams_caps;
	uint32_t			tunnel_offloads_caps;
	struct mlx5_packet_pacing_caps	packet_pacing_caps;
	struct mlx5_entropy_caps	entropy_caps;
	struct mlx5_qos_caps		qos_caps;
	struct mlx5_hca_cap_2_caps	hca_cap_2_caps;
	uint64_t			general_obj_types_caps;
	uint8_t				qpc_extension_cap:1;
	struct mlx5dv_sig_caps		sig_caps;
	struct mlx5_dma_mmo_caps	dma_mmo_caps;
	struct mlx5dv_crypto_caps	crypto_caps;
	pthread_mutex_t			dyn_bfregs_mutex; /* protects the dynamic bfregs allocation */
	uint32_t			num_dyn_bfregs;
	uint32_t			max_num_legacy_dyn_uar_sys_page;
	uint32_t			curr_legacy_dyn_sys_uar_page;
	uint16_t			flow_action_flags;
	uint64_t			max_dm_size;
	uint32_t                        eth_min_inline_size;
	uint32_t                        dump_fill_mkey;
	__be32                          dump_fill_mkey_be;
	uint32_t			flags;
	struct list_head		dyn_uar_bf_list;
	struct list_head		dyn_uar_qp_shared_list;
	struct list_head		dyn_uar_qp_dedicated_list;
	uint16_t			qp_max_dedicated_uuars;
	uint16_t			qp_alloc_dedicated_uuars;
	uint16_t			qp_max_shared_uuars;
	uint16_t			qp_alloc_shared_uuars;
	struct mlx5_bf			*nc_uar;
	void				*cq_uar_reg;
	struct mlx5_reserved_qpns	reserved_qpns;
	uint8_t				qp_data_in_order_cap:1;
	struct mlx5_dv_context_ops	*dv_ctx_ops;
	struct mlx5dv_devx_obj		*crypto_login;
	pthread_mutex_t			crypto_login_mutex;
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
	uint64_t			resource_type;
	size_t				req_alignment;
	struct mlx5_parent_domain	*mparent_domain;
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
	struct {
		void			*opaque_buf;
		struct ibv_mr		*opaque_mr;
		pthread_mutex_t		opaque_mr_mutex;
	};
};

struct mlx5_parent_domain {
	struct mlx5_pd mpd;
	struct mlx5_td *mtd;
	void *(*alloc)(struct ibv_pd *pd, void *pd_context, size_t size,
		       size_t alignment, uint64_t resource_type);
	void (*free)(struct ibv_pd *pd, void *pd_context, void *ptr,
		     uint64_t resource_type);
	void *pd_context;
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
	MLX5_CQ_FLAGS_RAW_WQE = 1 << 7,
};

struct mlx5_cq {
	struct verbs_cq			verbs_cq;
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
	bool				custom_db;
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
	int				cached_opcode;
	struct mlx5dv_clock_info	last_clock_info;
	struct ibv_pd			*parent_domain;
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
	bool				custom_db;
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
	uint8_t				dyn_alloc_uar : 1;
	uint8_t				mmaped_entry : 1;
	uint8_t				nc_mode : 1;
	uint8_t				qp_dedicated : 1;
	uint8_t				qp_shared : 1;
	uint32_t			count;
	struct list_node		uar_entry;
	uint32_t			uar_handle;
	uint32_t			length;
	uint32_t			page_id;
};

struct mlx5_dm {
	struct verbs_dm			verbs_dm;
	size_t				length;
	void			       *mmap_va;
	void			       *start_va;
	uint64_t			remote_va;
};

struct mlx5_mr {
	struct verbs_mr                 vmr;
	uint32_t			alloc_flags;
};

enum mlx5_qp_flags {
	MLX5_QP_FLAGS_USE_UNDERLAY = 0x01,
	MLX5_QP_FLAGS_DRAIN_SIGERR = 0x02,
};

struct mlx5_qp {
	struct mlx5_resource            rsc; /* This struct must be first */
	struct verbs_qp			verbs_qp;
	struct mlx5dv_qp_ex		dv_qp;
	struct ibv_qp		       *ibv_qp;
	struct mlx5_buf                 buf;
	int                             max_inline_data;
	int                             buf_size;
	/* For Raw Packet QP, use different buffers for the SQ and RQ */
	struct mlx5_buf                 sq_buf;
	int				sq_buf_size;
	struct mlx5_bf		       *bf;

	/* Start of new post send API specific fields */
	bool				inl_wqe;
	uint8_t				cur_setters_cnt;
	uint8_t				num_mkey_setters;
	uint8_t				fm_cache_rb;
	int				err;
	int				nreq;
	uint32_t			cur_size;
	uint32_t			cur_post_rb;
	void				*cur_eth;
	void				*cur_data;
	struct mlx5_wqe_ctrl_seg	*cur_ctrl;
	struct mlx5_mkey		*cur_mkey;
	/* End of new post send API specific fields */

	uint8_t				fm_cache;
	uint8_t	                        sq_signal_bits;
	void				*sq_start;
	struct mlx5_wq                  sq;

	__be32                         *db;
	bool				custom_db;
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
	uint64_t			tir_icm_addr;
	/*
	 * ECE configuration is done in create/modify QP stages,
	 * so this value is cached version of the requested ECE prior
	 * to its execution. This field will be cleared after successful
	 * call to relevant "executor".
	 */
	uint32_t			set_ece;
	/*
	 * This field indicates returned ECE options from the device
	 * as were received from the HW in previous stage. Every
	 * write to the set_ece will clear this field.
	 */
	uint32_t			get_ece;

	uint8_t				need_mmo_enable:1;
};

struct mlx5_ah {
	struct ibv_ah			ibv_ah;
	struct mlx5_wqe_av		av;
	bool				kern_ah;
	pthread_mutex_t			mutex;
	uint8_t				is_global;
	struct mlx5dv_devx_obj		*ah_qp_mapping;
};

struct mlx5_rwq {
	struct mlx5_resource rsc;
	struct ibv_wq wq;
	struct mlx5_buf buf;
	int buf_size;
	struct mlx5_wq rq;
	__be32  *db;
	bool	custom_db;
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

enum mlx5_devx_obj_type {
	MLX5_DEVX_FLOW_TABLE		= 1,
	MLX5_DEVX_FLOW_COUNTER		= 2,
	MLX5_DEVX_FLOW_METER		= 3,
	MLX5_DEVX_QP			= 4,
	MLX5_DEVX_PKT_REFORMAT_CTX	= 5,
	MLX5_DEVX_TIR			= 6,
	MLX5_DEVX_FLOW_GROUP		= 7,
	MLX5_DEVX_FLOW_TABLE_ENTRY	= 8,
	MLX5_DEVX_FLOW_SAMPLER		= 9,
	MLX5_DEVX_ASO_FIRST_HIT		= 10,
	MLX5_DEVX_ASO_FLOW_METER	= 11,
	MLX5_DEVX_ASO_CT		= 12,
};

struct mlx5dv_devx_obj {
	struct ibv_context *context;
	uint32_t handle;
	enum mlx5_devx_obj_type type;
	uint32_t object_id;
	uint64_t rx_icm_addr;
	uint8_t log_obj_range;
	void *priv;
};

struct mlx5_var_obj {
	struct mlx5dv_var dv_var;
	struct ibv_context *context;
	uint32_t handle;
};

struct mlx5_pp_obj {
	struct mlx5dv_pp dv_pp;
	struct ibv_context *context;
	uint32_t handle;
};

struct mlx5_devx_umem {
	struct mlx5dv_devx_umem dv_devx_umem;
	struct ibv_context *context;
	uint32_t handle;
	void *addr;
	size_t size;
};

/*
 * The BSF state is used in signature and crypto attributes. It indicates the
 * state the attributes are in, and helps constructing the signature and crypto
 * BSFs during MKey configuration.
 *
 * INIT state indicates that the attributes are not configured.
 * RESET state indicates that the attributes should be reset in current MKey
 * configuration.
 * SET state indicates that the attributes have been set before.
 * UPDATED state indicates that the attributes have been updated in current
 * MKey configuration.
 */
enum mlx5_mkey_bsf_state {
	MLX5_MKEY_BSF_STATE_INIT,
	MLX5_MKEY_BSF_STATE_RESET,
	MLX5_MKEY_BSF_STATE_SET,
	MLX5_MKEY_BSF_STATE_UPDATED,
};

struct mlx5_psv {
	uint32_t index;
	struct mlx5dv_devx_obj *devx_obj;
};

enum mlx5_sig_type {
	MLX5_SIG_TYPE_NONE = 0,
	MLX5_SIG_TYPE_CRC,
	MLX5_SIG_TYPE_T10DIF,
};

struct mlx5_sig_block_domain {
	enum mlx5_sig_type sig_type;
	union {
		struct mlx5dv_sig_t10dif dif;
		struct mlx5dv_sig_crc crc;
	} sig;
	enum mlx5dv_block_size block_size;
};

struct mlx5_sig_block_attr {
	struct mlx5_sig_block_domain mem;
	struct mlx5_sig_block_domain wire;
	uint32_t flags;
	uint8_t check_mask;
	uint8_t copy_mask;
};

struct mlx5_sig_block {
	struct mlx5_psv *mem_psv;
	struct mlx5_psv *wire_psv;
	struct mlx5_sig_block_attr attr;
	enum mlx5_mkey_bsf_state state;
};

struct mlx5_sig_err {
	uint16_t syndrome;
	uint64_t expected;
	uint64_t actual;
	uint64_t offset;
	uint8_t sig_type;
	uint8_t domain;
};

struct mlx5_sig_ctx {
	struct mlx5_sig_block block;
	struct mlx5_sig_err err_info;
	uint32_t err_count;
	bool err_exists;
	bool err_count_updated;
};

struct mlx5_crypto_attr {
	enum mlx5dv_crypto_standard crypto_standard;
	bool encrypt_on_tx;
	enum mlx5dv_signature_crypto_order signature_crypto_order;
	enum mlx5dv_block_size data_unit_size;
	char initial_tweak[16];
	struct mlx5dv_dek *dek;
	char keytag[8];
	enum mlx5_mkey_bsf_state state;
};

struct mlx5_mkey {
	struct mlx5dv_mkey dv_mkey;
	struct mlx5dv_devx_obj *devx_obj;
	uint16_t num_desc;
	uint64_t length;
	struct mlx5_sig_ctx *sig;
	struct mlx5_crypto_attr *crypto;
};

struct mlx5dv_dek {
	struct mlx5dv_devx_obj *devx_obj;
};

struct mlx5_devx_event_channel {
	struct ibv_context *context;
	struct mlx5dv_devx_event_channel dv_event_channel;
};

enum mlx5_flow_action_type {
	MLX5_FLOW_ACTION_COUNTER_OFFSET = 1,
};

struct mlx5_flow_action_attr_aux {
	enum mlx5_flow_action_type type;
	uint32_t offset;
};

struct mlx5dv_sched_node {
	struct mlx5dv_sched_node *parent;
	struct mlx5dv_devx_obj *obj;
};

struct mlx5dv_sched_leaf {
	struct mlx5dv_sched_node *parent;
	struct mlx5dv_devx_obj *obj;
};

struct ibv_flow *
_mlx5dv_create_flow(struct mlx5dv_flow_matcher *flow_matcher,
		    struct mlx5dv_flow_match_parameters *match_value,
		    size_t num_actions,
		    struct mlx5dv_flow_action_attr actions_attr[],
		    struct mlx5_flow_action_attr_aux actions_attr_aux[]);

extern int mlx5_stall_num_loop;
extern int mlx5_stall_cq_poll_min;
extern int mlx5_stall_cq_poll_max;
extern int mlx5_stall_cq_inc_step;
extern int mlx5_stall_cq_dec_step;
extern int mlx5_single_threaded;

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
	return container_of(ibcq, struct mlx5_cq, verbs_cq.cq);
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

static inline struct mlx5_qp *mqp_from_mlx5dv_qp_ex(struct mlx5dv_qp_ex *dv_qp)
{
	return container_of(dv_qp, struct mlx5_qp, dv_qp);
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

bool is_mlx5_vfio_dev(struct ibv_device *device);

void mlx5_open_debug_file(FILE **dbg_fp);
void mlx5_close_debug_file(FILE *dbg_fp);
void mlx5_set_debug_mask(void);

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
			 struct ibv_pd *pd,
			 const char *component,
			 enum mlx5_alloc_type *alloc_type,
			 enum mlx5_alloc_type default_alloc_type);
int mlx5_use_huge(const char *key);
bool mlx5_is_custom_alloc(struct ibv_pd *pd);
bool mlx5_is_extern_alloc(struct mlx5_context *context);
int mlx5_alloc_buf_extern(struct mlx5_context *ctx, struct mlx5_buf *buf,
			  size_t size);
void mlx5_free_buf_extern(struct mlx5_context *ctx, struct mlx5_buf *buf);

__be32 *mlx5_alloc_dbrec(struct mlx5_context *context, struct ibv_pd *pd,
			 bool *custom_alloc);
void mlx5_free_db(struct mlx5_context *context, __be32 *db, struct ibv_pd *pd,
		  bool custom_alloc);

void mlx5_query_device_ctx(struct mlx5_context *mctx);
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

void mlx5_async_event(struct ibv_context *context,
		      struct ibv_async_event *event);

struct ibv_mr *mlx5_alloc_null_mr(struct ibv_pd *pd);
struct ibv_mr *mlx5_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			   uint64_t hca_va, int access);
struct ibv_mr *mlx5_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset, size_t length,
				  uint64_t iova, int fd, int access);
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
void mlx5_cq_resize_copy_cqes(struct mlx5_context *mctx, struct mlx5_cq *cq);

struct ibv_srq *mlx5_create_srq(struct ibv_pd *pd,
				 struct ibv_srq_init_attr *attr);
int mlx5_modify_srq(struct ibv_srq *srq, struct ibv_srq_attr *attr,
		    int mask);
int mlx5_query_srq(struct ibv_srq *srq,
			   struct ibv_srq_attr *attr);
int mlx5_destroy_srq(struct ibv_srq *srq);
int mlx5_alloc_srq_buf(struct ibv_context *context, struct mlx5_srq *srq,
		       uint32_t nwr, struct ibv_pd *pd);
void mlx5_complete_odp_fault(struct mlx5_srq *srq, int ind);
void mlx5_free_srq_wqe(struct mlx5_srq *srq, int ind);
int mlx5_post_srq_recv(struct ibv_srq *ibsrq,
		       struct ibv_recv_wr *wr,
		       struct ibv_recv_wr **bad_wr);

struct ibv_qp *mlx5_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr);
int mlx5_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		  int attr_mask,
		  struct ibv_qp_init_attr *init_attr);
int mlx5_query_qp_data_in_order(struct ibv_qp *qp, enum ibv_wr_opcode op,
				uint32_t flags);
int mlx5_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		   int attr_mask);
int mlx5_modify_qp_rate_limit(struct ibv_qp *qp,
			      struct ibv_qp_rate_limit_attr *attr);
int mlx5_modify_qp_drain_sigerr(struct ibv_qp *qp);
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
struct mlx5_mkey *mlx5_find_mkey(struct mlx5_context *ctx, uint32_t mkeyn);
int mlx5_store_mkey(struct mlx5_context *ctx, uint32_t mkeyn,
		    struct mlx5_mkey *mkey);
void mlx5_clear_mkey(struct mlx5_context *ctx, uint32_t mkeyn);
struct ibv_ah *mlx5_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr);
int mlx5_destroy_ah(struct ibv_ah *ah);
int mlx5_alloc_av(struct mlx5_pd *pd, struct ibv_ah_attr *attr,
		   struct mlx5_ah *ah);
void mlx5_free_av(struct mlx5_ah *ah);
int mlx5_attach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid);
int mlx5_detach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid);
void *mlx5_get_atomic_laddr(struct mlx5_qp *qp, uint16_t idx, int *byte_count);
void *mlx5_get_send_wqe(struct mlx5_qp *qp, int n);
int mlx5_copy_to_recv_wqe(struct mlx5_qp *qp, int idx, void *buf, int size);
int mlx5_copy_to_send_wqe(struct mlx5_qp *qp, int idx, void *buf, int size);
int mlx5_copy_to_recv_srq(struct mlx5_srq *srq, int idx, void *buf, int size);
struct ibv_xrcd *mlx5_open_xrcd(struct ibv_context *context,
				struct ibv_xrcd_init_attr *xrcd_init_attr);
int mlx5_get_srq_num(struct ibv_srq *srq, uint32_t *srq_num);
struct ibv_qp *mlx5_open_qp(struct ibv_context *context,
			    struct ibv_qp_open_attr *attr);
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
off_t get_uar_mmap_offset(int idx, int page_size, int command);

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
struct ibv_dm *mlx5_import_dm(struct ibv_context *context,
			      uint32_t dm_handle);
void mlx5_unimport_dm(struct ibv_dm *dm);
struct ibv_mr *mlx5_import_mr(struct ibv_pd *pd,
			      uint32_t mr_handle);
void mlx5_unimport_mr(struct ibv_mr *mr);
struct ibv_pd *mlx5_import_pd(struct ibv_context *context,
			      uint32_t pd_handle);
void mlx5_unimport_pd(struct ibv_pd *pd);
int mlx5_qp_fill_wr_pfns(struct mlx5_qp *mqp,
			 const struct ibv_qp_init_attr_ex *attr,
			 const struct mlx5dv_qp_init_attr *mlx5_attr);
void clean_dyn_uars(struct ibv_context *context);
void mlx5_set_singleton_nc_uar(struct ibv_context *context);

int mlx5_set_ece(struct ibv_qp *qp, struct ibv_ece *ece);
int mlx5_query_ece(struct ibv_qp *qp, struct ibv_ece *ece);

struct mlx5_psv *mlx5_create_psv(struct ibv_pd *pd);
int mlx5_destroy_psv(struct mlx5_psv *psv);

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
		fprintf(stderr, "*** ERROR: multithreading violation ***\n"
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
	return roundup_pow_of_two(req);
}

static inline bool srq_has_waitq(struct mlx5_srq *srq)
{
	return srq->waitq_head >= 0;
}

bool srq_cooldown_wqe(struct mlx5_srq *srq, int ind);

struct mlx5_dv_context_ops {
	int (*devx_general_cmd)(struct ibv_context *context, const void *in,
				size_t inlen, void *out, size_t outlen);

	struct mlx5dv_devx_obj *(*devx_obj_create)(struct ibv_context *context,
						   const void *in, size_t inlen,
						   void *out, size_t outlen);
	int (*devx_obj_query)(struct mlx5dv_devx_obj *obj, const void *in,
			      size_t inlen, void *out, size_t outlen);
	int (*devx_obj_modify)(struct mlx5dv_devx_obj *obj, const void *in,
			       size_t inlen, void *out, size_t outlen);
	int (*devx_obj_destroy)(struct mlx5dv_devx_obj *obj);

	int (*devx_query_eqn)(struct ibv_context *context, uint32_t vector,
			      uint32_t *eqn);

	int (*devx_cq_query)(struct ibv_cq *cq, const void *in, size_t inlen,
			     void *out, size_t outlen);
	int (*devx_cq_modify)(struct ibv_cq *cq, const void *in, size_t inlen,
			      void *out, size_t outlen);

	int (*devx_qp_query)(struct ibv_qp *qp, const void *in, size_t inlen,
			     void *out, size_t outlen);
	int (*devx_qp_modify)(struct ibv_qp *qp, const void *in, size_t inlen,
			      void *out, size_t outlen);

	int (*devx_srq_query)(struct ibv_srq *srq, const void *in, size_t inlen,
			      void *out, size_t outlen);
	int (*devx_srq_modify)(struct ibv_srq *srq, const void *in, size_t inlen,
			       void *out, size_t outlen);

	int (*devx_wq_query)(struct ibv_wq *wq, const void *in, size_t inlen,
			     void *out, size_t outlen);
	int (*devx_wq_modify)(struct ibv_wq *wq, const void *in, size_t inlen,
			      void *out, size_t outlen);

	int (*devx_ind_tbl_query)(struct ibv_rwq_ind_table *ind_tbl, const void *in,
				  size_t inlen, void *out, size_t outlen);
	int (*devx_ind_tbl_modify)(struct ibv_rwq_ind_table *ind_tbl, const void *in,
				   size_t inlen, void *out, size_t outlen);

	struct mlx5dv_devx_cmd_comp *(*devx_create_cmd_comp)(struct ibv_context *context);
	void (*devx_destroy_cmd_comp)(struct mlx5dv_devx_cmd_comp *cmd_comp);

	struct mlx5dv_devx_event_channel *(*devx_create_event_channel)(struct ibv_context *context,
								       enum mlx5dv_devx_create_event_channel_flags flags);
	void (*devx_destroy_event_channel)(struct mlx5dv_devx_event_channel *dv_event_channel);
	int (*devx_subscribe_devx_event)(struct mlx5dv_devx_event_channel *dv_event_channel,
					 struct mlx5dv_devx_obj *obj,
					 uint16_t events_sz,
					 uint16_t events_num[],
					 uint64_t cookie);
	int (*devx_subscribe_devx_event_fd)(struct mlx5dv_devx_event_channel *dv_event_channel,
					    int fd,
					    struct mlx5dv_devx_obj *obj,
					    uint16_t event_num);

	int (*devx_obj_query_async)(struct mlx5dv_devx_obj *obj, const void *in,
				    size_t inlen, size_t outlen,
				    uint64_t wr_id,
				    struct mlx5dv_devx_cmd_comp *cmd_comp);
	int (*devx_get_async_cmd_comp)(struct mlx5dv_devx_cmd_comp *cmd_comp,
				       struct mlx5dv_devx_async_cmd_hdr *cmd_resp,
				       size_t cmd_resp_len);

	ssize_t (*devx_get_event)(struct mlx5dv_devx_event_channel *event_channel,
				  struct mlx5dv_devx_async_event_hdr *event_data,
				  size_t event_resp_len);

	struct mlx5dv_devx_uar *(*devx_alloc_uar)(struct ibv_context *context,
						       uint32_t flags);
	void (*devx_free_uar)(struct mlx5dv_devx_uar *dv_devx_uar);

	struct mlx5dv_devx_umem *(*devx_umem_reg)(struct ibv_context *context,
						  void *addr, size_t size, uint32_t access);
	struct mlx5dv_devx_umem *(*devx_umem_reg_ex)(struct ibv_context *ctx,
						     struct mlx5dv_devx_umem_in *umem_in);
	int (*devx_umem_dereg)(struct mlx5dv_devx_umem *dv_devx_umem);

	struct mlx5dv_mkey *(*create_mkey)(struct mlx5dv_mkey_init_attr *mkey_init_attr);
	int (*destroy_mkey)(struct mlx5dv_mkey *dv_mkey);

	int (*crypto_login)(struct ibv_context *context,
			    struct mlx5dv_crypto_login_attr *login_attr);
	int (*crypto_login_query_state)(struct ibv_context *context,
					enum mlx5dv_crypto_login_state *state);
	int (*crypto_logout)(struct ibv_context *context);

	struct mlx5dv_dek *(*dek_create)(struct ibv_context *context,
					 struct mlx5dv_dek_init_attr *init_attr);
	int (*dek_query)(struct mlx5dv_dek *dek,
			 struct mlx5dv_dek_attr *dek_attr);
	int (*dek_destroy)(struct mlx5dv_dek *dek);

	struct mlx5dv_var *(*alloc_var)(struct ibv_context *context, uint32_t flags);
	void (*free_var)(struct mlx5dv_var *dv_var);

	struct mlx5dv_pp *(*pp_alloc)(struct ibv_context *context, size_t pp_context_sz,
				      const void *pp_context, uint32_t flags);
	void (*pp_free)(struct mlx5dv_pp *dv_pp);

	int (*init_obj)(struct mlx5dv_obj *obj, uint64_t obj_type);
	struct ibv_cq_ex *(*create_cq)(struct ibv_context *context,
				       struct ibv_cq_init_attr_ex *cq_attr,
				       struct mlx5dv_cq_init_attr *mlx5_cq_attr);
	struct ibv_qp *(*create_qp)(struct ibv_context *context,
				    struct ibv_qp_init_attr_ex *qp_attr,
				    struct mlx5dv_qp_init_attr *mlx5_qp_attr);
	struct mlx5dv_qp_ex *(*qp_ex_from_ibv_qp_ex)(struct ibv_qp_ex *qp); /* Is this needed? */
	struct ibv_wq *(*create_wq)(struct ibv_context *context,
				    struct ibv_wq_init_attr *attr,
				    struct mlx5dv_wq_init_attr *mlx5_wq_attr);

	struct ibv_dm *(*alloc_dm)(struct ibv_context *context,
				   struct ibv_alloc_dm_attr *dm_attr,
				   struct mlx5dv_alloc_dm_attr *mlx5_dm_attr);
	void *(*dm_map_op_addr)(struct ibv_dm *dm, uint8_t op);

	struct ibv_flow_action *
	(*create_flow_action_esp)(struct ibv_context *ctx,
				  struct ibv_flow_action_esp_attr *esp,
				  struct mlx5dv_flow_action_esp *mlx5_attr);
	struct ibv_flow_action *
	(*create_flow_action_modify_header)(struct ibv_context *ctx,
					    size_t actions_sz,
					    uint64_t actions[],
					    enum mlx5dv_flow_table_type ft_type);
	struct ibv_flow_action *
	(*create_flow_action_packet_reformat)(struct ibv_context *ctx,
					      size_t data_sz,
					      void *data,
					      enum mlx5dv_flow_action_packet_reformat_type reformat_type,
					      enum mlx5dv_flow_table_type ft_type);

	struct mlx5dv_flow_matcher *(*create_flow_matcher)(struct ibv_context *context,
							   struct mlx5dv_flow_matcher_attr *attr);
	int (*destroy_flow_matcher)(struct mlx5dv_flow_matcher *flow_matcher);
	struct ibv_flow *(*create_flow)(struct mlx5dv_flow_matcher *flow_matcher,
					struct mlx5dv_flow_match_parameters *match_value,
					size_t num_actions,
					struct mlx5dv_flow_action_attr actions_attr[],
					struct mlx5_flow_action_attr_aux actions_attr_aux[]);

	int (*query_device)(struct ibv_context *ctx_in, struct mlx5dv_context *attrs_out);

	int (*query_qp_lag_port)(struct ibv_qp *qp, uint8_t *port_num,
				 uint8_t *active_port_num);
	int (*modify_qp_lag_port)(struct ibv_qp *qp, uint8_t port_num);
	int (*modify_qp_udp_sport)(struct ibv_qp *qp, uint16_t udp_sport);

	struct mlx5dv_sched_node *(*sched_node_create)(struct ibv_context *ctx,
						       const struct mlx5dv_sched_attr *attr);
	struct mlx5dv_sched_leaf *(*sched_leaf_create)(struct ibv_context *ctx,
						       const struct mlx5dv_sched_attr *attr);
	int (*sched_node_modify)(struct mlx5dv_sched_node *node,
				 const struct mlx5dv_sched_attr *attr);
	int (*sched_leaf_modify)(struct mlx5dv_sched_leaf *leaf,
				 const struct mlx5dv_sched_attr *attr);
	int (*sched_node_destroy)(struct mlx5dv_sched_node *node);
	int (*sched_leaf_destroy)(struct mlx5dv_sched_leaf *leaf);
	int (*modify_qp_sched_elem)(struct ibv_qp *qp,
				    const struct mlx5dv_sched_leaf *requestor,
				    const struct mlx5dv_sched_leaf *responder);
	int (*reserved_qpn_alloc)(struct ibv_context *ctx, uint32_t *qpn);
	int (*reserved_qpn_dealloc)(struct ibv_context *ctx, uint32_t qpn);
	int (*set_context_attr)(struct ibv_context *ibv_ctx,
				enum mlx5dv_set_ctx_attr_type type, void *attr);
	int (*get_clock_info)(struct ibv_context *ctx_in,
			      struct mlx5dv_clock_info *clock_info);
	int (*query_port)(struct ibv_context *context, uint32_t port_num,
			  struct mlx5dv_port *info, size_t info_len);
	int (*map_ah_to_qp)(struct ibv_ah *ah, uint32_t qp_num);
};

struct mlx5_dv_context_ops *mlx5_get_dv_ops(struct ibv_context *context);
void mlx5_set_dv_ctx_ops(struct mlx5_dv_context_ops *ops);

#endif /* MLX5_H */
