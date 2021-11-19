/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (C) 2019 - 2020 Intel Corporation */
#ifndef IRDMA_UMAIN_H
#define IRDMA_UMAIN_H

#include <inttypes.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <infiniband/driver.h>

#include "osdep.h"
#include "irdma.h"
#include "defs.h"
#include "i40iw_hw.h"
#include "status.h"
#include "user.h"

#define IRDMA_BASE_PUSH_PAGE		1
#define IRDMA_U_MINCQ_SIZE		4
#define IRDMA_DB_SHADOW_AREA_SIZE	64
#define IRDMA_DB_CQ_OFFSET		64

enum irdma_supported_wc_flags {
	IRDMA_CQ_SUPPORTED_WC_FLAGS = IBV_WC_EX_WITH_BYTE_LEN
				    | IBV_WC_EX_WITH_IMM
				    | IBV_WC_EX_WITH_QP_NUM
				    | IBV_WC_EX_WITH_SRC_QP
				    | IBV_WC_EX_WITH_SLID
				    | IBV_WC_EX_WITH_SL
				    | IBV_WC_EX_WITH_DLID_PATH_BITS
				    | IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK
				    | IBV_WC_EX_WITH_COMPLETION_TIMESTAMP,
};

struct irdma_udevice {
	struct verbs_device ibv_dev;
};

struct irdma_uah {
	struct ibv_ah ibv_ah;
	uint32_t ah_id;
	struct ibv_global_route grh;
};

struct irdma_upd {
	struct ibv_pd ibv_pd;
	void *arm_cq_page;
	void *arm_cq;
	uint32_t pd_id;
};

struct irdma_uvcontext {
	struct verbs_context ibv_ctx;
	struct irdma_upd *iwupd;
	struct irdma_uk_attrs uk_attrs;
	void *db;
	int abi_ver;
	bool legacy_mode;
};

struct irdma_uqp;

struct irdma_cq_buf {
	struct list_node list;
	struct irdma_cq_uk cq;
	struct verbs_mr vmr;
};

struct irdma_ucq {
	struct verbs_cq verbs_cq;
	struct verbs_mr vmr;
	struct verbs_mr vmr_shadow_area;
	pthread_spinlock_t lock;
	size_t buf_size;
	bool is_armed;
	bool skip_arm;
	bool arm_sol;
	bool skip_sol;
	int comp_vector;
	uint32_t report_rtt;
	struct irdma_uqp *uqp;
	struct irdma_cq_uk cq;
	struct list_head resize_list;
	/* for extended CQ completion fields */
	struct irdma_cq_poll_info cur_cqe;
};

struct irdma_uqp {
	struct ibv_qp ibv_qp;
	struct ibv_qp_attr attr;
	struct irdma_ucq *send_cq;
	struct irdma_ucq *recv_cq;
	struct verbs_mr vmr;
	size_t buf_size;
	uint32_t irdma_drv_opt;
	pthread_spinlock_t lock;
	uint16_t sq_sig_all;
	uint16_t qperr;
	uint16_t rsvd;
	uint32_t pending_rcvs;
	uint32_t wq_size;
	struct ibv_recv_wr *pend_rx_wr;
	struct irdma_qp_uk qp;
	enum ibv_qp_type qp_type;
	enum ibv_qp_attr_mask attr_mask;
	struct irdma_sge *recv_sges;
};

struct irdma_umr {
	struct verbs_mr vmr;
	uint32_t acc_flags;
};

/* irdma_uverbs.c */
int irdma_uquery_device_ex(struct ibv_context *context,
			   const struct ibv_query_device_ex_input *input,
			   struct ibv_device_attr_ex *attr, size_t attr_size);
int irdma_uquery_port(struct ibv_context *context, uint8_t port,
		      struct ibv_port_attr *attr);
struct ibv_pd *irdma_ualloc_pd(struct ibv_context *context);
int irdma_ufree_pd(struct ibv_pd *pd);
struct ibv_mr *irdma_ureg_mr(struct ibv_pd *pd, void *addr, size_t length,
			     uint64_t hca_va, int access);
int irdma_udereg_mr(struct verbs_mr *vmr);
struct ibv_mw *irdma_ualloc_mw(struct ibv_pd *pd, enum ibv_mw_type type);
int irdma_ubind_mw(struct ibv_qp *qp, struct ibv_mw *mw,
		   struct ibv_mw_bind *mw_bind);
int irdma_udealloc_mw(struct ibv_mw *mw);
struct ibv_cq *irdma_ucreate_cq(struct ibv_context *context, int cqe,
				struct ibv_comp_channel *channel,
				int comp_vector);
struct ibv_cq_ex *irdma_ucreate_cq_ex(struct ibv_context *context,
				      struct ibv_cq_init_attr_ex *attr_ex);
void irdma_ibvcq_ex_fill_priv_funcs(struct irdma_ucq *iwucq,
				    struct ibv_cq_init_attr_ex *attr_ex);
int irdma_uresize_cq(struct ibv_cq *cq, int cqe);
int irdma_udestroy_cq(struct ibv_cq *cq);
int irdma_upoll_cq(struct ibv_cq *cq, int entries, struct ibv_wc *entry);
int irdma_uarm_cq(struct ibv_cq *cq, int solicited);
void irdma_cq_event(struct ibv_cq *cq);
struct ibv_qp *irdma_ucreate_qp(struct ibv_pd *pd,
				struct ibv_qp_init_attr *attr);
int irdma_uquery_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		    struct ibv_qp_init_attr *init_attr);
int irdma_umodify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		     int attr_mask);
int irdma_udestroy_qp(struct ibv_qp *qp);
int irdma_upost_send(struct ibv_qp *ib_qp, struct ibv_send_wr *ib_wr,
		     struct ibv_send_wr **bad_wr);
int irdma_upost_recv(struct ibv_qp *ib_qp, struct ibv_recv_wr *ib_wr,
		     struct ibv_recv_wr **bad_wr);
struct ibv_ah *irdma_ucreate_ah(struct ibv_pd *ibpd, struct ibv_ah_attr *attr);
int irdma_udestroy_ah(struct ibv_ah *ibah);
int irdma_uattach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
			uint16_t lid);
int irdma_udetach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
			uint16_t lid);
void irdma_async_event(struct ibv_context *context,
		       struct ibv_async_event *event);
void irdma_set_hw_attrs(struct irdma_hw_attrs *attrs);
void *irdma_mmap(int fd, off_t offset);
void irdma_munmap(void *map);
#endif /* IRDMA_UMAIN_H */
