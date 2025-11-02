/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * Copyright (c) 2024 ZTE Corporation.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef __ZXDH_ZRDMA_H__
#define __ZXDH_ZRDMA_H__

#include <inttypes.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <infiniband/driver.h>

#include "zxdh_defs.h"
#include "zxdh_status.h"
#include "zxdh_verbs.h"

#define ZXDH_BASE_PUSH_PAGE 1
#define ZXDH_U_MINCQ_SIZE 4
#define ZXDH_DB_SHADOW_AREA_SIZE 8
#define ZXDH_DB_SQ_OFFSET 0x404
#define ZXDH_DB_CQ_OFFSET 0x588

#define MIN_UDP_SPORT 1024
#define MIN_QP_QPN 1

enum zxdh_supported_wc_flags {
	ZXDH_CQ_SUPPORTED_WC_FLAGS =
		IBV_WC_EX_WITH_BYTE_LEN | IBV_WC_EX_WITH_IMM |
		IBV_WC_EX_WITH_QP_NUM | IBV_WC_EX_WITH_SRC_QP |
		IBV_WC_EX_WITH_SLID | IBV_WC_EX_WITH_SL |
		IBV_WC_EX_WITH_DLID_PATH_BITS |
		IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK |
		IBV_WC_EX_WITH_COMPLETION_TIMESTAMP,
};

enum {
	ZXDH_DBG_QP = 1 << 0,
	ZXDH_DBG_CQ = 1 << 1,
	ZXDH_DBG_SRQ = 1 << 2,
};
extern uint32_t zxdh_debug_mask;
#define zxdh_dbg(mask, format, arg...)                                         \
	do {                                                                   \
		if (mask & zxdh_debug_mask) {                                  \
			int tmp = errno;                                       \
			fprintf(stdout, "%s:%d: " format, __func__, __LINE__,  \
				##arg);                                        \
			errno = tmp;                                           \
		}                                                              \
	} while (0)


struct zxdh_udevice {
	struct verbs_device ibv_dev;
};

struct zxdh_uah {
	struct ibv_ah ibv_ah;
	uint32_t ah_id;
	struct ibv_global_route grh;
};

struct zxdh_upd {
	struct ibv_pd ibv_pd;
	uint32_t pd_id;
};

struct zxdh_uvcontext {
	struct verbs_context ibv_ctx;
	struct zxdh_upd *iwupd;
	struct zxdh_dev_attrs dev_attrs;
	void *db;
	void *sq_db;
	void *cq_db;
	int abi_ver;
	bool legacy_mode;
	uint8_t zxdh_write_imm_split_switch;
	struct zxdh_uvcontext_ops *cxt_ops;
};

struct zxdh_uqp;

struct zxdh_cq_buf {
	struct list_node list;
	struct zxdh_cq cq;
	struct verbs_mr vmr;
};

struct zxdh_ucq {
	struct verbs_cq verbs_cq;
	struct verbs_mr vmr;
	struct verbs_mr vmr_shadow_area;
	pthread_spinlock_t lock;
	size_t buf_size;
	bool is_armed;
	enum zxdh_cmpl_notify last_notify;
	int comp_vector;
	uint32_t report_rtt;
	struct zxdh_uqp *uqp;
	struct zxdh_cq cq;
	struct list_head resize_list;
	/* for extended CQ completion fields */
	struct zxdh_cq_poll_info cur_cqe;
	bool resize_enable;
};

struct zxdh_usrq {
	struct ibv_srq ibv_srq;
	struct verbs_mr vmr;
	struct verbs_mr list_vmr;
	struct verbs_mr db_vmr;
	size_t total_buf_size;
	size_t buf_size;
	size_t list_buf_size;
	size_t db_buf_size;
	size_t srq_size;
	size_t srq_list_size;
	uint32_t srq_id;
	uint32_t max_wr;
	uint32_t max_sge;
	uint32_t srq_limit;
	pthread_spinlock_t lock;
	uint32_t wq_size;
	struct ibv_recv_wr *pend_rx_wr;
	struct zxdh_srq srq;
};

struct zxdh_uqp {
	struct verbs_qp vqp;
	struct zxdh_ucq *send_cq;
	struct zxdh_ucq *recv_cq;
	struct zxdh_usrq *srq;
	struct verbs_mr vmr;
	size_t buf_size;
	uint32_t zxdh_drv_opt;
	pthread_spinlock_t lock;
	uint16_t sq_sig_all;
	uint16_t qperr;
	uint16_t rsvd;
	uint32_t pending_rcvs;
	uint32_t wq_size;
	struct ibv_recv_wr *pend_rx_wr;
	struct zxdh_qp qp;
	enum ibv_qp_type qp_type;
	struct zxdh_sge *recv_sges;
	uint8_t is_srq;
	uint8_t inline_data[ZXDH_MAX_INLINE_DATA_SIZE];
};

struct zxdh_umr {
	struct verbs_mr vmr;
	uint32_t acc_flags;
	uint8_t leaf_pbl_size;
	uint8_t host_page_size;
	uint64_t mr_pa_pble_index;
};

/* zxdh_verbs.c */
int zxdh_uquery_device_ex(struct ibv_context *context,
			  const struct ibv_query_device_ex_input *input,
			  struct ibv_device_attr_ex *attr, size_t attr_size);
int zxdh_uquery_port(struct ibv_context *context, uint8_t port,
		     struct ibv_port_attr *attr);
struct ibv_pd *zxdh_ualloc_pd(struct ibv_context *context);
int zxdh_ufree_pd(struct ibv_pd *pd);
struct ibv_mr *zxdh_ureg_mr(struct ibv_pd *pd, void *addr, size_t length,
			    uint64_t hca_va, int access);
int zxdh_udereg_mr(struct verbs_mr *vmr);

int zxdh_urereg_mr(struct verbs_mr *mr, int flags, struct ibv_pd *pd,
		   void *addr, size_t length, int access);

struct ibv_mw *zxdh_ualloc_mw(struct ibv_pd *pd, enum ibv_mw_type type);
int zxdh_ubind_mw(struct ibv_qp *qp, struct ibv_mw *mw,
		  struct ibv_mw_bind *mw_bind);
int zxdh_udealloc_mw(struct ibv_mw *mw);
struct ibv_cq *zxdh_ucreate_cq(struct ibv_context *context, int cqe,
			       struct ibv_comp_channel *channel,
			       int comp_vector);
struct ibv_cq_ex *zxdh_ucreate_cq_ex(struct ibv_context *context,
				     struct ibv_cq_init_attr_ex *attr_ex);
void zxdh_ibvcq_ex_fill_priv_funcs(struct zxdh_ucq *iwucq,
				   struct ibv_cq_init_attr_ex *attr_ex);
int zxdh_uresize_cq(struct ibv_cq *cq, int cqe);
int zxdh_udestroy_cq(struct ibv_cq *cq);
int zxdh_umodify_cq(struct ibv_cq *cq, struct ibv_modify_cq_attr *attr);
int zxdh_upoll_cq(struct ibv_cq *cq, int entries, struct ibv_wc *entry);
int zxdh_uarm_cq(struct ibv_cq *cq, int solicited);
void zxdh_cq_event(struct ibv_cq *cq);
struct ibv_qp *zxdh_ucreate_qp(struct ibv_pd *pd,
			       struct ibv_qp_init_attr *attr);
struct ibv_qp *zxdh_ucreate_qp_ex(struct ibv_context *context,
				  struct ibv_qp_init_attr_ex *attr);
int zxdh_uquery_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		   struct ibv_qp_init_attr *init_attr);
int zxdh_umodify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask);
int zxdh_udestroy_qp(struct ibv_qp *qp);
int zxdh_upost_send(struct ibv_qp *ib_qp, struct ibv_send_wr *ib_wr,
		    struct ibv_send_wr **bad_wr);
int zxdh_upost_recv(struct ibv_qp *ib_qp, struct ibv_recv_wr *ib_wr,
		    struct ibv_recv_wr **bad_wr);
struct ibv_srq *zxdh_ucreate_srq(struct ibv_pd *pd,
				 struct ibv_srq_init_attr *srq_init_attr);
int zxdh_udestroy_srq(struct ibv_srq *srq);
int zxdh_umodify_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr,
		     int srq_attr_mask);
int zxdh_uquery_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr);
int zxdh_upost_srq_recv(struct ibv_srq *srq, struct ibv_recv_wr *recv_wr,
			struct ibv_recv_wr **bad_recv_wr);
int zxdh_uget_srq_num(struct ibv_srq *srq, uint32_t *srq_num);
struct ibv_ah *zxdh_ucreate_ah(struct ibv_pd *ibpd, struct ibv_ah_attr *attr);
int zxdh_udestroy_ah(struct ibv_ah *ibah);
int zxdh_uattach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
		       uint16_t lid);
int zxdh_udetach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
		       uint16_t lid);
void zxdh_async_event(struct ibv_context *context,
		      struct ibv_async_event *event);
void zxdh_set_hw_attrs(struct zxdh_hw_attrs *attrs);
void *zxdh_mmap(int fd, off_t offset);
void zxdh_munmap(void *map);
void zxdh_set_debug_mask(void);
int zxdh_get_write_imm_split_switch(void);
#endif /* __ZXDH_ZRDMA_H__ */
