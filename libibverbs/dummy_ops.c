/*
 * Copyright (c) 2017 Mellanox Technologies, Inc.  All rights reserved.
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
#include <infiniband/driver.h>
#include "ibverbs.h"
#include <errno.h>

static int advise_mr(struct ibv_pd *pd,
		     enum ibv_advise_mr_advice advice,
		     uint32_t flags,
		     struct ibv_sge *sg_list,
		     uint32_t num_sges)
{
	return EOPNOTSUPP;
}

static struct ibv_dm *alloc_dm(struct ibv_context *context,
			       struct ibv_alloc_dm_attr *attr)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_mw *alloc_mw(struct ibv_pd *pd, enum ibv_mw_type type)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_mr *alloc_null_mr(struct ibv_pd *pd)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_pd *
alloc_parent_domain(struct ibv_context *context,
		    struct ibv_parent_domain_init_attr *attr)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_pd *alloc_pd(struct ibv_context *context)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_td *alloc_td(struct ibv_context *context,
			       struct ibv_td_init_attr *init_attr)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static void async_event(struct ibv_context *context,
			struct ibv_async_event *event)
{
}

static int attach_counters_point_flow(struct ibv_counters *counters,
				      struct ibv_counter_attach_attr *attr,
				      struct ibv_flow *flow)
{
	return EOPNOTSUPP;
}

static int attach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
			uint16_t lid)
{
	return EOPNOTSUPP;
}

static int bind_mw(struct ibv_qp *qp, struct ibv_mw *mw,
		   struct ibv_mw_bind *mw_bind)
{
	return EOPNOTSUPP;
}

static int close_xrcd(struct ibv_xrcd *xrcd)
{
	return EOPNOTSUPP;
}

static void cq_event(struct ibv_cq *cq)
{
}

static struct ibv_ah *create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_counters *create_counters(struct ibv_context *context,
					    struct ibv_counters_init_attr *init_attr)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_cq *create_cq(struct ibv_context *context, int cqe,
				struct ibv_comp_channel *channel,
				int comp_vector)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_cq_ex *create_cq_ex(struct ibv_context *context,
				      struct ibv_cq_init_attr_ex *init_attr)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_flow *create_flow(struct ibv_qp *qp,
				    struct ibv_flow_attr *flow_attr)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_flow_action *create_flow_action_esp(struct ibv_context *context,
						      struct ibv_flow_action_esp_attr *attr)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_qp *create_qp(struct ibv_pd *pd,
				struct ibv_qp_init_attr *attr)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_qp *create_qp_ex(struct ibv_context *context,
				   struct ibv_qp_init_attr_ex *qp_init_attr_ex)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_rwq_ind_table *
create_rwq_ind_table(struct ibv_context *context,
		     struct ibv_rwq_ind_table_init_attr *init_attr)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_srq *create_srq(struct ibv_pd *pd,
				  struct ibv_srq_init_attr *srq_init_attr)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_srq *
create_srq_ex(struct ibv_context *context,
	      struct ibv_srq_init_attr_ex *srq_init_attr_ex)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_wq *create_wq(struct ibv_context *context,
				struct ibv_wq_init_attr *wq_init_attr)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static int dealloc_mw(struct ibv_mw *mw)
{
	return EOPNOTSUPP;
}

static int dealloc_pd(struct ibv_pd *pd)
{
	return EOPNOTSUPP;
}

static int dealloc_td(struct ibv_td *td)
{
	return EOPNOTSUPP;
}

static int dereg_mr(struct verbs_mr *vmr)
{
	return EOPNOTSUPP;
}

static int destroy_ah(struct ibv_ah *ah)
{
	return EOPNOTSUPP;
}

static int destroy_counters(struct ibv_counters *counters)
{
	return EOPNOTSUPP;
}

static int destroy_cq(struct ibv_cq *cq)
{
	return EOPNOTSUPP;
}

static int destroy_flow(struct ibv_flow *flow)
{
	return EOPNOTSUPP;
}

static int destroy_flow_action(struct ibv_flow_action *action)
{
	return EOPNOTSUPP;
}

static int destroy_qp(struct ibv_qp *qp)
{
	return EOPNOTSUPP;
}

static int destroy_rwq_ind_table(struct ibv_rwq_ind_table *rwq_ind_table)
{
	return EOPNOTSUPP;
}

static int destroy_srq(struct ibv_srq *srq)
{
	return EOPNOTSUPP;
}

static int destroy_wq(struct ibv_wq *wq)
{
	return EOPNOTSUPP;
}

static int detach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
			uint16_t lid)
{
	return EOPNOTSUPP;
}

static void free_context(struct ibv_context *ctx)
{
	return;
}

static int free_dm(struct ibv_dm *dm)
{
	return EOPNOTSUPP;
}

static int get_srq_num(struct ibv_srq *srq, uint32_t *srq_num)
{
	return EOPNOTSUPP;
}

static int modify_cq(struct ibv_cq *cq, struct ibv_modify_cq_attr *attr)
{
	return EOPNOTSUPP;
}

static int modify_flow_action_esp(struct ibv_flow_action *action,
				  struct ibv_flow_action_esp_attr *attr)
{
	return EOPNOTSUPP;
}

static int modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask)
{
	return EOPNOTSUPP;
}

static int modify_qp_rate_limit(struct ibv_qp *qp,
				struct ibv_qp_rate_limit_attr *attr)
{
	return EOPNOTSUPP;
}

static int modify_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr,
		      int srq_attr_mask)
{
	return EOPNOTSUPP;
}

static int modify_wq(struct ibv_wq *wq, struct ibv_wq_attr *wq_attr)
{
	return EOPNOTSUPP;
}

static struct ibv_qp *open_qp(struct ibv_context *context,
			      struct ibv_qp_open_attr *attr)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_xrcd *open_xrcd(struct ibv_context *context,
				  struct ibv_xrcd_init_attr *xrcd_init_attr)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static int poll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *wc)
{
	return EOPNOTSUPP;
}

static int post_recv(struct ibv_qp *qp, struct ibv_recv_wr *wr,
		     struct ibv_recv_wr **bad_wr)
{
	return EOPNOTSUPP;
}

static int post_send(struct ibv_qp *qp, struct ibv_send_wr *wr,
		     struct ibv_send_wr **bad_wr)
{
	return EOPNOTSUPP;
}

static int post_srq_ops(struct ibv_srq *srq, struct ibv_ops_wr *op,
			struct ibv_ops_wr **bad_op)
{
	return EOPNOTSUPP;
}

static int post_srq_recv(struct ibv_srq *srq, struct ibv_recv_wr *recv_wr,
			 struct ibv_recv_wr **bad_recv_wr)
{
	return EOPNOTSUPP;
}

static int query_device(struct ibv_context *context,
			struct ibv_device_attr *device_attr)
{
	return EOPNOTSUPP;
}

static int query_device_ex(struct ibv_context *context,
			   const struct ibv_query_device_ex_input *input,
			   struct ibv_device_attr_ex *attr, size_t attr_size)
{
	return EOPNOTSUPP;
}

static int query_port(struct ibv_context *context, uint8_t port_num,
		      struct ibv_port_attr *port_attr)
{
	return EOPNOTSUPP;
}

static int query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		    struct ibv_qp_init_attr *init_attr)
{
	return EOPNOTSUPP;
}

static int query_rt_values(struct ibv_context *context,
			   struct ibv_values_ex *values)
{
	return EOPNOTSUPP;
}

static int query_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr)
{
	return EOPNOTSUPP;
}

static int read_counters(struct ibv_counters *counters,
			 uint64_t *counters_value,
			 uint32_t ncounters,
			 uint32_t flags)
{
	return EOPNOTSUPP;
}

static struct ibv_mr *reg_dm_mr(struct ibv_pd *pd, struct ibv_dm *dm,
				uint64_t dm_offset, size_t length,
				unsigned int access)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static struct ibv_mr *reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			     uint64_t hca_va,  int access)
{
	errno = EOPNOTSUPP;
	return NULL;
}

static int req_notify_cq(struct ibv_cq *cq, int solicited_only)
{
	return EOPNOTSUPP;
}

static int rereg_mr(struct verbs_mr *vmr, int flags, struct ibv_pd *pd,
		    void *addr, size_t length, int access)
{
	errno = EOPNOTSUPP;
	return IBV_REREG_MR_ERR_INPUT;
}

static int resize_cq(struct ibv_cq *cq, int cqe)
{
	return EOPNOTSUPP;
}

/*
 * Ops in verbs_dummy_ops simply return an EOPNOTSUPP error code when called, or
 * do nothing. They are placed in the ops structures if the provider does not
 * provide an op for the function.
 *
 * NOTE: This deliberately does not use named initializers to trigger a
 * '-Wmissing-field-initializers' warning if the struct is changed without
 * changing this.
 *
 * Keep sorted.
 */
const struct verbs_context_ops verbs_dummy_ops = {
	advise_mr,
	alloc_dm,
	alloc_mw,
	alloc_null_mr,
	alloc_parent_domain,
	alloc_pd,
	alloc_td,
	async_event,
	attach_counters_point_flow,
	attach_mcast,
	bind_mw,
	close_xrcd,
	cq_event,
	create_ah,
	create_counters,
	create_cq,
	create_cq_ex,
	create_flow,
	create_flow_action_esp,
	create_qp,
	create_qp_ex,
	create_rwq_ind_table,
	create_srq,
	create_srq_ex,
	create_wq,
	dealloc_mw,
	dealloc_pd,
	dealloc_td,
	dereg_mr,
	destroy_ah,
	destroy_counters,
	destroy_cq,
	destroy_flow,
	destroy_flow_action,
	destroy_qp,
	destroy_rwq_ind_table,
	destroy_srq,
	destroy_wq,
	detach_mcast,
	free_context,
	free_dm,
	get_srq_num,
	modify_cq,
	modify_flow_action_esp,
	modify_qp,
	modify_qp_rate_limit,
	modify_srq,
	modify_wq,
	open_qp,
	open_xrcd,
	poll_cq,
	post_recv,
	post_send,
	post_srq_ops,
	post_srq_recv,
	query_device,
	query_device_ex,
	query_port,
	query_qp,
	query_rt_values,
	query_srq,
	read_counters,
	reg_dm_mr,
	reg_mr,
	req_notify_cq,
	rereg_mr,
	resize_cq,
};

/*
 * Set the ops in a context. If the function pointer in op is NULL then it is
 * not set. This allows the providers to call the function multiple times in
 * order to have variations of the ops for different HW configurations.
 */
void verbs_set_ops(struct verbs_context *vctx,
		   const struct verbs_context_ops *ops)
{
	struct verbs_ex_private *priv = vctx->priv;
	struct ibv_context_ops *ctx = &vctx->context.ops;

	/*
	 * We retain the function pointer for now, just as 'just-in-case' ABI
	 * compatibility. If any ever get changed incompatibly they should be
	 * set to NULL instead.
	 */
#define SET_PRIV_OP(ptr, name)                                                 \
	do {                                                                   \
		if (ops->name) {                                               \
			priv->ops.name = ops->name;                            \
			(ptr)->_compat_##name = (void *)ops->name;             \
		}                                                              \
	} while (0)

	/* Same as SET_PRIV_OP but without the compatibility pointer */
#define SET_PRIV_OP_IC(ptr, name)                                              \
	do {                                                                   \
		if (ops->name)                                                 \
			priv->ops.name = ops->name;                            \
	} while (0)

#define SET_OP(ptr, name)                                                      \
	do {                                                                   \
		if (ops->name) {                                               \
			priv->ops.name = ops->name;                            \
			(ptr)->name = ops->name;                               \
		}                                                              \
	} while (0)

#define SET_OP2(ptr, iname, name)                                              \
	do {                                                                   \
		if (ops->name) {                                               \
			priv->ops.name = ops->name;                            \
			(ptr)->iname = ops->name;                              \
		}                                                              \
	} while (0)

	SET_OP(vctx, advise_mr);
	SET_OP(vctx, alloc_dm);
	SET_OP(ctx, alloc_mw);
	SET_OP(vctx, alloc_null_mr);
	SET_PRIV_OP(ctx, alloc_pd);
	SET_OP(vctx, alloc_parent_domain);
	SET_OP(vctx, alloc_td);
	SET_OP(vctx, attach_counters_point_flow);
	SET_OP(vctx, create_counters);
	SET_PRIV_OP(ctx, async_event);
	SET_PRIV_OP(ctx, attach_mcast);
	SET_OP(ctx, bind_mw);
	SET_OP(vctx, close_xrcd);
	SET_PRIV_OP(ctx, cq_event);
	SET_PRIV_OP(ctx, create_ah);
	SET_PRIV_OP(ctx, create_cq);
	SET_PRIV_OP_IC(vctx, create_cq_ex);
	SET_OP2(vctx, ibv_create_flow, create_flow);
	SET_OP(vctx, create_flow_action_esp);
	SET_PRIV_OP(ctx, create_qp);
	SET_OP(vctx, create_qp_ex);
	SET_OP(vctx, create_rwq_ind_table);
	SET_PRIV_OP(ctx, create_srq);
	SET_OP(vctx, create_srq_ex);
	SET_OP(vctx, create_wq);
	SET_OP(ctx, dealloc_mw);
	SET_PRIV_OP(ctx, dealloc_pd);
	SET_OP(vctx, dealloc_td);
	SET_OP(vctx, destroy_counters);
	SET_PRIV_OP(ctx, dereg_mr);
	SET_PRIV_OP(ctx, destroy_ah);
	SET_PRIV_OP(ctx, destroy_cq);
	SET_OP2(vctx, ibv_destroy_flow, destroy_flow);
	SET_OP(vctx, destroy_flow_action);
	SET_PRIV_OP(ctx, destroy_qp);
	SET_OP(vctx, destroy_rwq_ind_table);
	SET_PRIV_OP(ctx, destroy_srq);
	SET_OP(vctx, destroy_wq);
	SET_PRIV_OP(ctx, detach_mcast);
	SET_PRIV_OP_IC(ctx, free_context);
	SET_OP(vctx, free_dm);
	SET_OP(vctx, get_srq_num);
	SET_OP(vctx, modify_cq);
	SET_OP(vctx, modify_flow_action_esp);
	SET_PRIV_OP(ctx, modify_qp);
	SET_OP(vctx, modify_qp_rate_limit);
	SET_PRIV_OP(ctx, modify_srq);
	SET_OP(vctx, modify_wq);
	SET_OP(vctx, open_qp);
	SET_OP(vctx, open_xrcd);
	SET_OP(ctx, poll_cq);
	SET_OP(ctx, post_recv);
	SET_OP(ctx, post_send);
	SET_OP(vctx, post_srq_ops);
	SET_OP(ctx, post_srq_recv);
	SET_PRIV_OP(ctx, query_device);
	SET_OP(vctx, query_device_ex);
	SET_PRIV_OP_IC(ctx, query_port);
	SET_PRIV_OP(ctx, query_qp);
	SET_OP(vctx, query_rt_values);
	SET_OP(vctx, read_counters);
	SET_PRIV_OP(ctx, query_srq);
	SET_OP(vctx, reg_dm_mr);
	SET_PRIV_OP(ctx, reg_mr);
	SET_OP(ctx, req_notify_cq);
	SET_PRIV_OP(ctx, rereg_mr);
	SET_PRIV_OP(ctx, resize_cq);

#undef SET_OP
#undef SET_OP2
}
