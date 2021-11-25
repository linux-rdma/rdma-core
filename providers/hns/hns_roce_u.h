/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
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

#ifndef _HNS_ROCE_U_H
#define _HNS_ROCE_U_H

#include <stddef.h>
#include <endian.h>
#include <util/compiler.h>

#include <infiniband/driver.h>
#include <util/udma_barrier.h>
#include <util/util.h>
#include <infiniband/verbs.h>
#include <ccan/array_size.h>
#include <ccan/bitmap.h>
#include <ccan/container_of.h>
#include <linux/if_ether.h>
#include "hns_roce_u_abi.h"

#define HNS_ROCE_HW_VER1		('h' << 24 | 'i' << 16 | '0' << 8 | '6')

#define HNS_ROCE_HW_VER2		('h' << 24 | 'i' << 16 | '0' << 8 | '8')
#define HNS_ROCE_HW_VER3		0x130

#define PFX				"hns: "

/* The minimum page size is 4K for hardware */
#define HNS_HW_PAGE_SHIFT 12
#define HNS_HW_PAGE_SIZE (1 << HNS_HW_PAGE_SHIFT)

#define HNS_ROCE_MAX_RC_INL_INN_SZ	32
#define HNS_ROCE_MAX_UD_INL_INN_SZ	8
#define HNS_ROCE_MAX_CQ_NUM		0x10000
#define HNS_ROCE_MIN_CQE_NUM		0x40
#define HNS_ROCE_V1_MIN_WQE_NUM		0x20
#define HNS_ROCE_V2_MIN_WQE_NUM		0x40
#define HNS_ROCE_MIN_SRQ_WQE_NUM	1

#define HNS_ROCE_CQE_SIZE 0x20
#define HNS_ROCE_V3_CQE_SIZE 0x40

#define HNS_ROCE_SQWQE_SHIFT		6
#define HNS_ROCE_SGE_IN_WQE		2
#define HNS_ROCE_SGE_SIZE		16
#define HNS_ROCE_SGE_SHIFT		4

#define HNS_ROCE_GID_SIZE		16

#define HNS_ROCE_CQ_DB_BUF_SIZE		((HNS_ROCE_MAX_CQ_NUM >> 11) << 12)
#define HNS_ROCE_STATIC_RATE		3 /* Gbps */

#define INVALID_SGE_LENGTH 0x80000000

#define HNS_ROCE_ADDRESS_MASK 0xFFFFFFFF
#define HNS_ROCE_ADDRESS_SHIFT 32

#define roce_get_field(origin, mask, shift) \
	(((le32toh(origin)) & (mask)) >> (shift))

#define roce_get_bit(origin, shift) \
	roce_get_field((origin), (1ul << (shift)), (shift))

#define roce_set_field(origin, mask, shift, val) \
	do { \
		(origin) &= ~htole32(mask); \
		(origin) |= htole32(((unsigned int)(val) << (shift)) & (mask)); \
	} while (0)

#define roce_set_bit(origin, shift, val) \
	roce_set_field((origin), (1ul << (shift)), (shift), (val))

enum {
	HNS_ROCE_QP_TABLE_BITS		= 8,
	HNS_ROCE_QP_TABLE_SIZE		= 1 << HNS_ROCE_QP_TABLE_BITS,
};

#define HNS_ROCE_SRQ_TABLE_BITS 8
#define HNS_ROCE_SRQ_TABLE_SIZE BIT(HNS_ROCE_SRQ_TABLE_BITS)

/* operation type list */
enum {
	/* rq&srq operation */
	HNS_ROCE_OPCODE_SEND_DATA_RECEIVE         = 0x06,
	HNS_ROCE_OPCODE_RDMA_WITH_IMM_RECEIVE     = 0x07,
};

struct hns_roce_device {
	struct verbs_device		ibv_dev;
	int				page_size;
	const struct hns_roce_u_hw	*u_hw;
	int				hw_version;
};

struct hns_roce_buf {
	void				*buf;
	unsigned int			length;
};

#define BIT_CNT_PER_BYTE       8
#define BIT_CNT_PER_LONG       (BIT_CNT_PER_BYTE * sizeof(unsigned long))

/* the sw doorbell type; */
enum hns_roce_db_type {
	HNS_ROCE_QP_TYPE_DB,
	HNS_ROCE_CQ_TYPE_DB,
	HNS_ROCE_DB_TYPE_NUM
};

struct hns_roce_db_page {
	struct hns_roce_db_page	*prev, *next;
	struct hns_roce_buf	buf;
	unsigned int		num_db;
	unsigned int		use_cnt;
	bitmap			*bitmap;
};

struct hns_roce_context {
	struct verbs_context		ibv_ctx;
	void				*uar;
	pthread_spinlock_t		uar_lock;

	void				*cq_tptr_base;

	struct {
		struct hns_roce_qp	**table;
		int			refcnt;
	} qp_table[HNS_ROCE_QP_TABLE_SIZE];
	pthread_mutex_t			qp_table_mutex;
	uint32_t			num_qps;
	uint32_t			qp_table_shift;
	uint32_t			qp_table_mask;

	struct {
		struct hns_roce_srq	**table;
		int			refcnt;
	} srq_table[HNS_ROCE_SRQ_TABLE_SIZE];
	pthread_mutex_t			srq_table_mutex;
	uint32_t			num_srqs;
	uint32_t			srq_table_shift;
	uint32_t			srq_table_mask;

	struct hns_roce_db_page		*db_list[HNS_ROCE_DB_TYPE_NUM];
	pthread_mutex_t			db_list_mutex;

	unsigned int			max_qp_wr;
	unsigned int			max_sge;
	unsigned int			max_srq_wr;
	unsigned int			max_srq_sge;
	int				max_cqe;
	unsigned int			cqe_size;
};

struct hns_roce_pd {
	struct ibv_pd			ibv_pd;
	unsigned int			pdn;
};

struct hns_roce_cq {
	struct ibv_cq			ibv_cq;
	struct hns_roce_buf		buf;
	pthread_spinlock_t		lock;
	unsigned int			cqn;
	unsigned int			cq_depth;
	unsigned int			cons_index;
	unsigned int			*db;
	unsigned int			*arm_db;
	int				arm_sn;
	unsigned long			flags;
	unsigned int			cqe_size;
};

struct hns_roce_idx_que {
	struct hns_roce_buf		buf;
	unsigned int			entry_shift;
	unsigned long			*bitmap;
	int				bitmap_cnt;
	unsigned int			head;
	unsigned int			tail;
};

struct hns_roce_srq {
	struct verbs_srq		verbs_srq;
	struct hns_roce_idx_que		idx_que;
	struct hns_roce_buf		wqe_buf;
	pthread_spinlock_t		lock;
	unsigned long			*wrid;
	unsigned int			srqn;
	unsigned int			wqe_cnt;
	unsigned int			max_gs;
	unsigned int			rsv_sge;
	unsigned int			wqe_shift;
	unsigned int			*db;
	unsigned short			counter;
};

struct hns_roce_wq {
	unsigned long			*wrid;
	pthread_spinlock_t		lock;
	unsigned int			wqe_cnt;
	int				max_post;
	unsigned int			head;
	unsigned int			tail;
	unsigned int			max_gs;
	unsigned int			rsv_sge;
	unsigned int			wqe_shift;
	unsigned int			shift; /* wq size is 2^shift */
	int				offset;
};

/* record the result of sge process */
struct hns_roce_sge_info {
	unsigned int valid_num; /* sge length is not 0 */
	unsigned int start_idx; /* start position of extend sge */
	unsigned int total_len; /* total length of valid sges */
};

struct hns_roce_sge_ex {
	int				offset;
	unsigned int			sge_cnt;
	unsigned int			sge_shift;
};

struct hns_roce_rinl_sge {
	void				*addr;
	unsigned int			len;
};

struct hns_roce_rinl_wqe {
	struct hns_roce_rinl_sge	*sg_list;
	unsigned int			sge_cnt;
};

struct hns_roce_rinl_buf {
	struct hns_roce_rinl_wqe	*wqe_list;
	unsigned int			wqe_cnt;
};

struct hns_roce_qp {
	struct verbs_qp			verbs_qp;
	struct hns_roce_buf		buf;
	int				max_inline_data;
	int				buf_size;
	unsigned int			sq_signal_bits;
	struct hns_roce_wq		sq;
	struct hns_roce_wq		rq;
	unsigned int			*rdb;
	unsigned int			*sdb;
	struct hns_roce_sge_ex		ex_sge;
	unsigned int			next_sge;
	int				port_num;
	int				sl;
	unsigned int			qkey;
	enum ibv_mtu			path_mtu;

	struct hns_roce_rinl_buf	rq_rinl_buf;
	unsigned long			flags;
	int				refcnt; /* specially used for XRC */
};

struct hns_roce_av {
	uint8_t port;
	uint8_t gid_index;
	uint8_t hop_limit;
	uint32_t flowlabel;
	uint16_t udp_sport;
	uint8_t sl;
	uint8_t tclass;
	uint8_t dgid[HNS_ROCE_GID_SIZE];
	uint8_t mac[ETH_ALEN];
};

struct hns_roce_ah {
	struct ibv_ah ibv_ah;
	struct hns_roce_av av;
};

struct hns_roce_u_hw {
	uint32_t hw_version;
	struct verbs_context_ops hw_ops;
};

/*
 * The entries's buffer should be aligned to a multiple of the hardware's
 * minimum page size.
 */
#define hr_hw_page_align(x) align(x, HNS_HW_PAGE_SIZE)

static inline unsigned int to_hr_hem_entries_size(int count, int buf_shift)
{
	return hr_hw_page_align(count << buf_shift);
}

static inline unsigned int hr_ilog32(unsigned int count)
{
	return ilog32(count - 1);
}

static inline struct hns_roce_device *to_hr_dev(struct ibv_device *ibv_dev)
{
	return container_of(ibv_dev, struct hns_roce_device, ibv_dev.device);
}

static inline struct hns_roce_context *to_hr_ctx(struct ibv_context *ibv_ctx)
{
	return container_of(ibv_ctx, struct hns_roce_context, ibv_ctx.context);
}

static inline struct hns_roce_pd *to_hr_pd(struct ibv_pd *ibv_pd)
{
	return container_of(ibv_pd, struct hns_roce_pd, ibv_pd);
}

static inline struct hns_roce_cq *to_hr_cq(struct ibv_cq *ibv_cq)
{
	return container_of(ibv_cq, struct hns_roce_cq, ibv_cq);
}

static inline struct hns_roce_srq *to_hr_srq(struct ibv_srq *ibv_srq)
{
	return container_of(ibv_srq, struct hns_roce_srq, verbs_srq.srq);
}

static inline struct hns_roce_qp *to_hr_qp(struct ibv_qp *ibv_qp)
{
	return container_of(ibv_qp, struct hns_roce_qp, verbs_qp.qp);
}

static inline struct hns_roce_ah *to_hr_ah(struct ibv_ah *ibv_ah)
{
	return container_of(ibv_ah, struct hns_roce_ah, ibv_ah);
}

int hns_roce_u_query_device(struct ibv_context *context,
			    const struct ibv_query_device_ex_input *input,
			    struct ibv_device_attr_ex *attr, size_t attr_size);
int hns_roce_u_query_port(struct ibv_context *context, uint8_t port,
			  struct ibv_port_attr *attr);

struct ibv_pd *hns_roce_u_alloc_pd(struct ibv_context *context);
int hns_roce_u_free_pd(struct ibv_pd *pd);

struct ibv_mr *hns_roce_u_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
				 uint64_t hca_va, int access);
int hns_roce_u_rereg_mr(struct verbs_mr *vmr, int flags, struct ibv_pd *pd,
			void *addr, size_t length, int access);
int hns_roce_u_dereg_mr(struct verbs_mr *vmr);

struct ibv_mw *hns_roce_u_alloc_mw(struct ibv_pd *pd, enum ibv_mw_type type);
int hns_roce_u_dealloc_mw(struct ibv_mw *mw);
int hns_roce_u_bind_mw(struct ibv_qp *qp, struct ibv_mw *mw,
		       struct ibv_mw_bind *mw_bind);

struct ibv_cq *hns_roce_u_create_cq(struct ibv_context *context, int cqe,
				    struct ibv_comp_channel *channel,
				    int comp_vector);

int hns_roce_u_modify_cq(struct ibv_cq *cq, struct ibv_modify_cq_attr *attr);
int hns_roce_u_destroy_cq(struct ibv_cq *cq);
void hns_roce_u_cq_event(struct ibv_cq *cq);

struct ibv_srq *hns_roce_u_create_srq(struct ibv_pd *pd,
				      struct ibv_srq_init_attr *srq_init_attr);
struct ibv_srq *hns_roce_u_create_srq_ex(struct ibv_context *context,
					 struct ibv_srq_init_attr_ex *attr);
int hns_roce_u_get_srq_num(struct ibv_srq *ibv_srq, uint32_t *srq_num);
int hns_roce_u_modify_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr,
			  int srq_attr_mask);
int hns_roce_u_query_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr);
struct hns_roce_srq *hns_roce_find_srq(struct hns_roce_context *ctx,
				       uint32_t srqn);
int hns_roce_u_destroy_srq(struct ibv_srq *ibv_srq);

struct ibv_qp *hns_roce_u_create_qp(struct ibv_pd *pd,
				    struct ibv_qp_init_attr *attr);
struct ibv_qp *
hns_roce_u_create_qp_ex(struct ibv_context *context,
			struct ibv_qp_init_attr_ex *qp_init_attr_ex);

struct ibv_qp *hns_roce_u_open_qp(struct ibv_context *context,
				  struct ibv_qp_open_attr *attr);

int hns_roce_u_query_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
			int attr_mask, struct ibv_qp_init_attr *init_attr);

struct ibv_ah *hns_roce_u_create_ah(struct ibv_pd *pd,
				    struct ibv_ah_attr *attr);
int hns_roce_u_destroy_ah(struct ibv_ah *ah);

struct ibv_xrcd *
hns_roce_u_open_xrcd(struct ibv_context *context,
		     struct ibv_xrcd_init_attr *xrcd_init_attr);
int hns_roce_u_close_xrcd(struct ibv_xrcd *ibv_xrcd);

int hns_roce_alloc_buf(struct hns_roce_buf *buf, unsigned int size,
		       int page_size);
void hns_roce_free_buf(struct hns_roce_buf *buf);

void hns_roce_free_qp_buf(struct hns_roce_qp *qp, struct hns_roce_context *ctx);

void hns_roce_init_qp_indices(struct hns_roce_qp *qp);

extern const struct hns_roce_u_hw hns_roce_u_hw_v1;
extern const struct hns_roce_u_hw hns_roce_u_hw_v2;

#endif /* _HNS_ROCE_U_H */
