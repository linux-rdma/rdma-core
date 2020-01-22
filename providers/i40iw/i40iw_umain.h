/*******************************************************************************
*
* Copyright (c) 2015-2016 Intel Corporation.  All rights reserved.
*
* This software is available to you under a choice of one of two
* licenses.  You may choose to be licensed under the terms of the GNU
* General Public License (GPL) Version 2, available from the file
* COPYING in the main directory of this source tree, or the
* OpenFabrics.org BSD license below:
*
*   Redistribution and use in source and binary forms, with or
*   without modification, are permitted provided that the following
*   conditions are met:
*
*    - Redistributions of source code must retain the above
*	copyright notice, this list of conditions and the following
*	disclaimer.
*
*    - Redistributions in binary form must reproduce the above
*	copyright notice, this list of conditions and the following
*	disclaimer in the documentation and/or other materials
*	provided with the distribution.
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
*******************************************************************************/

#ifndef I40IW_UMAIN_H
#define I40IW_UMAIN_H

#include <inttypes.h>
#include <stddef.h>
#include <endian.h>
#include <util/compiler.h>

#include <infiniband/driver.h>
#include <util/udma_barrier.h>

#include "i40iw_osdep.h"
#include "i40iw_d.h"
#include "i40iw_status.h"
#include "i40iw_user.h"

#define PFX "libi40iw-"

#define  I40IW_BASE_PUSH_PAGE	1
#define	 I40IW_U_MINCQ_SIZE	4

#define I40IW_WC_WITH_VLAN   (1 << 3)
#define I40IW_UD_RX_BATCH_SZ 64
#define I40IW_UD_MAX_SG_LIST_SZ 1
#define I40IW_CQ_BUF_OV_ERR 0x3

#define MAX_WQ_DEPTH 16384
#define MIN_WQ_DEPTH 4

#define I40E_DB_SHADOW_AREA_SIZE 64
#define I40E_DB_CQ_OFFSET 0x40

struct i40iw_udevice {
	struct verbs_device ibv_dev;
	int page_size;
};

struct i40iw_upd {
	struct ibv_pd ibv_pd;
	void volatile *db;
	void volatile *arm_cq_page;
	void volatile *arm_cq;
	uint32_t pd_id;
};

struct i40iw_uvcontext {
	struct verbs_context ibv_ctx;
	struct i40iw_upd *iwupd;
	uint32_t max_pds;	/* maximum pds allowed for this user process */
	uint32_t max_qps;	/* maximum qps allowed for this user process */
	uint32_t wq_size;	/* size of the WQs (sq+rq) + shadow allocated to the mmaped area */
	struct i40iw_dev_uk dev;
	int abi_ver;
};

struct i40iw_uqp;

struct i40iw_ucq {
	struct ibv_cq ibv_cq;
	struct verbs_mr vmr;
	struct ibv_mr mr_shadow_area;
	pthread_spinlock_t lock;
	uint8_t is_armed;
	uint8_t skip_arm;
	int arm_sol;
	int skip_sol;
	int comp_vector;
	struct i40iw_uqp *udqp;
	struct i40iw_cq_uk cq;
};

struct i40iw_uqp {
	struct ibv_qp ibv_qp;
	struct i40iw_ucq *send_cq;
	struct i40iw_ucq *recv_cq;
	struct verbs_mr vmr;
	uint32_t i40iw_drv_opt;
	pthread_spinlock_t lock;
	u32 *push_db;      /* mapped as uncached memory*/
	u64 *push_wqe;     /* mapped as write combined memory*/
	uint16_t sq_sig_all;
	uint16_t qperr;
	uint16_t rsvd;
	uint32_t pending_rcvs;
	uint32_t wq_size;
	struct ibv_recv_wr *pend_rx_wr;
	struct i40iw_qp_uk qp;

};

#define to_i40iw_uxxx(xxx, type)                                               \
	container_of(ib##xxx, struct i40iw_u##type, ibv_##xxx)

static inline struct i40iw_udevice *to_i40iw_udev(struct ibv_device *ibdev)
{
	return container_of(ibdev, struct i40iw_udevice, ibv_dev.device);
}

static inline struct i40iw_uvcontext *to_i40iw_uctx(struct ibv_context *ibctx)
{
	return container_of(ibctx, struct i40iw_uvcontext, ibv_ctx.context);
}

static inline struct i40iw_upd *to_i40iw_upd(struct ibv_pd *ibpd)
{
	return to_i40iw_uxxx(pd, pd);
}

static inline struct i40iw_ucq *to_i40iw_ucq(struct ibv_cq *ibcq)
{
	return to_i40iw_uxxx(cq, cq);
}

static inline struct i40iw_uqp *to_i40iw_uqp(struct ibv_qp *ibqp)
{
	return to_i40iw_uxxx(qp, qp);
}

/* i40iw_uverbs.c */
int i40iw_uquery_device(struct ibv_context *, struct ibv_device_attr *);
int i40iw_uquery_port(struct ibv_context *, uint8_t, struct ibv_port_attr *);
struct ibv_pd *i40iw_ualloc_pd(struct ibv_context *);
int i40iw_ufree_pd(struct ibv_pd *);
struct ibv_mr *i40iw_ureg_mr(struct ibv_pd *pd, void *addr, size_t length,
			     uint64_t hca_va, int access);
int i40iw_udereg_mr(struct verbs_mr *vmr);
struct ibv_cq *i40iw_ucreate_cq(struct ibv_context *, int, struct ibv_comp_channel *, int);
int i40iw_udestroy_cq(struct ibv_cq *);
int i40iw_upoll_cq(struct ibv_cq *, int, struct ibv_wc *);
int i40iw_uarm_cq(struct ibv_cq *, int);
void i40iw_cq_event(struct ibv_cq *);
struct ibv_srq *i40iw_ucreate_srq(struct ibv_pd *, struct ibv_srq_init_attr *);
int i40iw_umodify_srq(struct ibv_srq *, struct ibv_srq_attr *, int);
int i40iw_udestroy_srq(struct ibv_srq *);
int i40iw_upost_srq_recv(struct ibv_srq *, struct ibv_recv_wr *, struct ibv_recv_wr **);
struct ibv_qp *i40iw_ucreate_qp(struct ibv_pd *, struct ibv_qp_init_attr *);
int i40iw_uquery_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int, struct ibv_qp_init_attr *init_attr);
int i40iw_umodify_qp(struct ibv_qp *, struct ibv_qp_attr *, int);
int i40iw_udestroy_qp(struct ibv_qp *);
int i40iw_upost_send(struct ibv_qp *, struct ibv_send_wr *, struct ibv_send_wr **);
int i40iw_upost_recv(struct ibv_qp *, struct ibv_recv_wr *, struct ibv_recv_wr **);
void i40iw_async_event(struct ibv_context *context,
		       struct ibv_async_event *event);

#endif /* i40iw_umain_H */
