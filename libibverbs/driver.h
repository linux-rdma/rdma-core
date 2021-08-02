/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005, 2006 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2005 PathScale, Inc.  All rights reserved.
 * Copyright (c) 2020 Intel Corporation. All rights reserved.
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

#ifndef INFINIBAND_DRIVER_H
#define INFINIBAND_DRIVER_H

#include <stdatomic.h>
#include <infiniband/verbs.h>
#include <infiniband/kern-abi.h>
#include <infiniband/cmd_ioctl.h>
#include <ccan/list.h>
#include <config.h>
#include <stdbool.h>
#include <rdma/rdma_user_ioctl_cmds.h>
#include <infiniband/cmd_ioctl.h>
#include <sys/types.h>

struct verbs_device;

enum {
	VERBS_LOG_LEVEL_NONE,
	VERBS_LOG_ERR,
	VERBS_LOG_WARN,
	VERBS_LOG_INFO,
	VERBS_LOG_DEBUG,
};

void __verbs_log(struct verbs_context *ctx, uint32_t level,
		 const char *fmt, ...);

#define verbs_log(ctx, level, format, arg...)                                  \
do {                                                                           \
	int tmp = errno;                                                       \
	__verbs_log(ctx, level, "%s: %s:%d: " format,                          \
		    (ctx)->context.device->name, __func__, __LINE__, ##arg);   \
	errno = tmp;                                                           \
} while (0)

#define verbs_debug(ctx, format, arg...) \
	verbs_log(ctx, VERBS_LOG_DEBUG, format, ##arg)

#define verbs_info(ctx, format, arg...) \
	verbs_log(ctx, VERBS_LOG_INFO, format, ##arg)

#define verbs_warn(ctx, format, arg...) \
	verbs_log(ctx, VERBS_LOG_WARN, format, ##arg)

#define verbs_err(ctx, format, arg...) \
	verbs_log(ctx, VERBS_LOG_ERR, format, ##arg)

#ifdef VERBS_DEBUG
#define verbs_log_datapath(ctx, level, format, arg...) \
	verbs_log(ctx, level, format, ##arg)
#else
#define verbs_log_datapath(ctx, level, format, arg...) {}
#endif

#define verbs_debug_datapath(ctx, format, arg...) \
	verbs_log_datapath(ctx, VERBS_LOG_DEBUG, format, ##arg)

#define verbs_info_datapath(ctx, format, arg...) \
	verbs_log_datapath(ctx, VERBS_LOG_INFO, format, ##arg)

#define verbs_warn_datapath(ctx, format, arg...) \
	verbs_log_datapath(ctx, VERBS_LOG_WARN, format, ##arg)

#define verbs_err_datapath(ctx, format, arg...) \
	verbs_log_datapath(ctx, VERBS_LOG_ERR, format, ##arg)

enum verbs_xrcd_mask {
	VERBS_XRCD_HANDLE	= 1 << 0,
	VERBS_XRCD_RESERVED	= 1 << 1
};

enum create_cq_cmd_flags {
	CREATE_CQ_CMD_FLAGS_TS_IGNORED_EX = 1 << 0,
};

struct verbs_xrcd {
	struct ibv_xrcd		xrcd;
	uint32_t		comp_mask;
	uint32_t		handle;
};

struct verbs_srq {
	struct ibv_srq		srq;
	enum ibv_srq_type	srq_type;
	struct verbs_xrcd      *xrcd;
	struct ibv_cq	       *cq;
	uint32_t		srq_num;
};

enum verbs_qp_mask {
	VERBS_QP_XRCD		= 1 << 0,
	VERBS_QP_EX		= 1 << 1,
};

enum ibv_gid_type_sysfs {
	IBV_GID_TYPE_SYSFS_IB_ROCE_V1,
	IBV_GID_TYPE_SYSFS_ROCE_V2,
};

enum verbs_query_gid_attr_mask {
	VERBS_QUERY_GID_ATTR_GID		= 1 << 0,
	VERBS_QUERY_GID_ATTR_TYPE		= 1 << 1,
	VERBS_QUERY_GID_ATTR_NDEV_IFINDEX	= 1 << 2,
};

enum ibv_mr_type {
	IBV_MR_TYPE_MR,
	IBV_MR_TYPE_NULL_MR,
	IBV_MR_TYPE_IMPORTED_MR,
	IBV_MR_TYPE_DMABUF_MR,
};

struct verbs_mr {
	struct ibv_mr		ibv_mr;
	enum ibv_mr_type        mr_type;
	int access;
};

static inline struct verbs_mr *verbs_get_mr(struct ibv_mr *mr)
{
	return container_of(mr, struct verbs_mr, ibv_mr);
}

struct verbs_qp {
	union {
		struct ibv_qp qp;
		struct ibv_qp_ex qp_ex;
	};
	uint32_t		comp_mask;
	struct verbs_xrcd       *xrcd;
};
static_assert(offsetof(struct ibv_qp_ex, qp_base) == 0, "Invalid qp layout");

struct verbs_cq {
	union {
		struct ibv_cq cq;
		struct ibv_cq_ex cq_ex;
	};
};

enum ibv_flow_action_type {
	IBV_FLOW_ACTION_UNSPECIFIED,
	IBV_FLOW_ACTION_ESP = 1,
};

struct verbs_flow_action {
	struct ibv_flow_action		action;
	uint32_t			handle;
	enum ibv_flow_action_type	type;
};

struct verbs_dm {
	struct ibv_dm		dm;
	uint32_t		handle;
};

enum {
	VERBS_MATCH_SENTINEL = 0,
	VERBS_MATCH_PCI = 1,
	VERBS_MATCH_MODALIAS = 2,
	VERBS_MATCH_DRIVER_ID = 3,
};

struct verbs_match_ent {
	void *driver_data;
	union {
		const char *modalias;
		uint64_t driver_id;
	} u;
	uint16_t vendor;
	uint16_t device;
	uint8_t kind;
};
#define VERBS_DRIVER_ID(_id)                                                   \
	{                                                                      \
		.u.driver_id = (_id), .kind = VERBS_MATCH_DRIVER_ID,           \
	}
/* Note: New drivers should only use VERBS_DRIVER_ID, the below are for legacy
 * drivers
 */
#define VERBS_PCI_MATCH(_vendor, _device, _data)			\
	{                                                                      \
	    .driver_data = (void *)(_data),				       \
	    .vendor = (_vendor),                                               \
	    .device = (_device),                                               \
	    .kind = VERBS_MATCH_PCI,                                           \
	}

#define VERBS_MODALIAS_MATCH(_mod_str, _data)                                  \
	{                                                                      \
	    .driver_data = (void *)(_data),			               \
	    .u.modalias = (_mod_str),                                          \
	    .kind = VERBS_MATCH_MODALIAS,                                      \
	}

/* Matching on the IB device name is STRONGLY discouraged. This will only
 * match if there is no device/modalias file available, and it will eventually
 * be disabled entirely if the kernel supports renaming. Use is strongly
 * discouraged.
 */
#define VERBS_NAME_MATCH(_name_prefix, _data)                                  \
	{                                                                      \
	    .driver_data = (_data),                                            \
	    .u.modalias = "rdma_device:*N" _name_prefix "*",                   \
	    .kind = VERBS_MATCH_MODALIAS,                                      \
	}

enum {
	VSYSFS_READ_MODALIAS = 1 << 0,
	VSYSFS_READ_NODE_GUID = 1 << 1,
};

/* An rdma device detected in sysfs */
struct verbs_sysfs_dev {
	struct list_node entry;
	void *provider_data;
	const struct verbs_match_ent *match;
	unsigned int flags;
	char sysfs_name[IBV_SYSFS_NAME_MAX];
	dev_t sysfs_cdev;
	char ibdev_name[IBV_SYSFS_NAME_MAX];
	char ibdev_path[IBV_SYSFS_PATH_MAX];
	char modalias[512];
	uint64_t node_guid;
	uint32_t driver_id;
	enum ibv_node_type node_type;
	int ibdev_idx;
	uint32_t num_ports;
	uint32_t abi_ver;
	struct timespec time_created;
};

/* Must change the PRIVATE IBVERBS_PRIVATE_ symbol if this is changed */
struct verbs_device_ops {
	const char *name;

	uint32_t match_min_abi_version;
	uint32_t match_max_abi_version;
	const struct verbs_match_ent *match_table;
	const struct verbs_device_ops **static_providers;

	bool (*match_device)(struct verbs_sysfs_dev *sysfs_dev);

	struct verbs_context *(*alloc_context)(struct ibv_device *device,
					       int cmd_fd,
					       void *private_data);
	struct verbs_context *(*import_context)(struct ibv_device *device,
						int cmd_fd);

	struct verbs_device *(*alloc_device)(struct verbs_sysfs_dev *sysfs_dev);
	void (*uninit_device)(struct verbs_device *device);
};

/* Must change the PRIVATE IBVERBS_PRIVATE_ symbol if this is changed */
struct verbs_device {
	struct ibv_device device; /* Must be first */
	const struct verbs_device_ops *ops;
	atomic_int refcount;
	struct list_node entry;
	struct verbs_sysfs_dev *sysfs;
	uint64_t core_support;
};

struct verbs_counters {
	struct ibv_counters counters;
	uint32_t handle;
};

/*
 * Must change the PRIVATE IBVERBS_PRIVATE_ symbol if this is changed. This is
 * the union of every op the driver can support. If new elements are added to
 * this structure then verbs_dummy_ops must also be updated.
 *
 * Keep sorted.
 */
struct verbs_context_ops {
	int (*advise_mr)(struct ibv_pd *pd,
			 enum ibv_advise_mr_advice advice,
			 uint32_t flags,
			 struct ibv_sge *sg_list,
			 uint32_t num_sges);
	struct ibv_dm *(*alloc_dm)(struct ibv_context *context,
				   struct ibv_alloc_dm_attr *attr);
	struct ibv_mw *(*alloc_mw)(struct ibv_pd *pd, enum ibv_mw_type type);
	struct ibv_mr *(*alloc_null_mr)(struct ibv_pd *pd);
	struct ibv_pd *(*alloc_parent_domain)(
		struct ibv_context *context,
		struct ibv_parent_domain_init_attr *attr);
	struct ibv_pd *(*alloc_pd)(struct ibv_context *context);
	struct ibv_td *(*alloc_td)(struct ibv_context *context,
				   struct ibv_td_init_attr *init_attr);
	void (*async_event)(struct ibv_context *context, struct ibv_async_event *event);
	int (*attach_counters_point_flow)(struct ibv_counters *counters,
					  struct ibv_counter_attach_attr *attr,
					  struct ibv_flow *flow);
	int (*attach_mcast)(struct ibv_qp *qp, const union ibv_gid *gid,
			    uint16_t lid);
	int (*bind_mw)(struct ibv_qp *qp, struct ibv_mw *mw,
		       struct ibv_mw_bind *mw_bind);
	int (*close_xrcd)(struct ibv_xrcd *xrcd);
	void (*cq_event)(struct ibv_cq *cq);
	struct ibv_ah *(*create_ah)(struct ibv_pd *pd,
				    struct ibv_ah_attr *attr);
	struct ibv_counters *(*create_counters)(struct ibv_context *context,
						struct ibv_counters_init_attr *init_attr);
	struct ibv_cq *(*create_cq)(struct ibv_context *context, int cqe,
				    struct ibv_comp_channel *channel,
				    int comp_vector);
	struct ibv_cq_ex *(*create_cq_ex)(
		struct ibv_context *context,
		struct ibv_cq_init_attr_ex *init_attr);
	struct ibv_flow *(*create_flow)(struct ibv_qp *qp,
					struct ibv_flow_attr *flow_attr);
	struct ibv_flow_action *(*create_flow_action_esp)(struct ibv_context *context,
							  struct ibv_flow_action_esp_attr *attr);
	struct ibv_qp *(*create_qp)(struct ibv_pd *pd,
				    struct ibv_qp_init_attr *attr);
	struct ibv_qp *(*create_qp_ex)(
		struct ibv_context *context,
		struct ibv_qp_init_attr_ex *qp_init_attr_ex);
	struct ibv_rwq_ind_table *(*create_rwq_ind_table)(
		struct ibv_context *context,
		struct ibv_rwq_ind_table_init_attr *init_attr);
	struct ibv_srq *(*create_srq)(struct ibv_pd *pd,
				      struct ibv_srq_init_attr *srq_init_attr);
	struct ibv_srq *(*create_srq_ex)(
		struct ibv_context *context,
		struct ibv_srq_init_attr_ex *srq_init_attr_ex);
	struct ibv_wq *(*create_wq)(struct ibv_context *context,
				    struct ibv_wq_init_attr *wq_init_attr);
	int (*dealloc_mw)(struct ibv_mw *mw);
	int (*dealloc_pd)(struct ibv_pd *pd);
	int (*dealloc_td)(struct ibv_td *td);
	int (*dereg_mr)(struct verbs_mr *vmr);
	int (*destroy_ah)(struct ibv_ah *ah);
	int (*destroy_counters)(struct ibv_counters *counters);
	int (*destroy_cq)(struct ibv_cq *cq);
	int (*destroy_flow)(struct ibv_flow *flow);
	int (*destroy_flow_action)(struct ibv_flow_action *action);
	int (*destroy_qp)(struct ibv_qp *qp);
	int (*destroy_rwq_ind_table)(struct ibv_rwq_ind_table *rwq_ind_table);
	int (*destroy_srq)(struct ibv_srq *srq);
	int (*destroy_wq)(struct ibv_wq *wq);
	int (*detach_mcast)(struct ibv_qp *qp, const union ibv_gid *gid,
			    uint16_t lid);
	void (*free_context)(struct ibv_context *context);
	int (*free_dm)(struct ibv_dm *dm);
	int (*get_srq_num)(struct ibv_srq *srq, uint32_t *srq_num);
	struct ibv_dm *(*import_dm)(struct ibv_context *context,
				    uint32_t dm_handle);
	struct ibv_mr *(*import_mr)(struct ibv_pd *pd,
				    uint32_t mr_handle);
	struct ibv_pd *(*import_pd)(struct ibv_context *context,
				    uint32_t pd_handle);
	int (*modify_cq)(struct ibv_cq *cq, struct ibv_modify_cq_attr *attr);
	int (*modify_flow_action_esp)(struct ibv_flow_action *action,
				      struct ibv_flow_action_esp_attr *attr);
	int (*modify_qp)(struct ibv_qp *qp, struct ibv_qp_attr *attr,
			 int attr_mask);
	int (*modify_qp_rate_limit)(struct ibv_qp *qp,
				    struct ibv_qp_rate_limit_attr *attr);
	int (*modify_srq)(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr,
			  int srq_attr_mask);
	int (*modify_wq)(struct ibv_wq *wq, struct ibv_wq_attr *wq_attr);
	struct ibv_qp *(*open_qp)(struct ibv_context *context,
				  struct ibv_qp_open_attr *attr);
	struct ibv_xrcd *(*open_xrcd)(
		struct ibv_context *context,
		struct ibv_xrcd_init_attr *xrcd_init_attr);
	int (*poll_cq)(struct ibv_cq *cq, int num_entries, struct ibv_wc *wc);
	int (*post_recv)(struct ibv_qp *qp, struct ibv_recv_wr *wr,
			 struct ibv_recv_wr **bad_wr);
	int (*post_send)(struct ibv_qp *qp, struct ibv_send_wr *wr,
			 struct ibv_send_wr **bad_wr);
	int (*post_srq_ops)(struct ibv_srq *srq, struct ibv_ops_wr *op,
			    struct ibv_ops_wr **bad_op);
	int (*post_srq_recv)(struct ibv_srq *srq, struct ibv_recv_wr *recv_wr,
			     struct ibv_recv_wr **bad_recv_wr);
	int (*query_device_ex)(struct ibv_context *context,
			       const struct ibv_query_device_ex_input *input,
			       struct ibv_device_attr_ex *attr,
			       size_t attr_size);
	int (*query_ece)(struct ibv_qp *qp, struct ibv_ece *ece);
	int (*query_port)(struct ibv_context *context, uint8_t port_num,
			  struct ibv_port_attr *port_attr);
	int (*query_qp)(struct ibv_qp *qp, struct ibv_qp_attr *attr,
			int attr_mask, struct ibv_qp_init_attr *init_attr);
	int (*query_qp_data_in_order)(struct ibv_qp *qp, enum ibv_wr_opcode op,
				      uint32_t flags);
	int (*query_rt_values)(struct ibv_context *context,
			       struct ibv_values_ex *values);
	int (*query_srq)(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr);
	int (*read_counters)(struct ibv_counters *counters,
			     uint64_t *counters_value,
			     uint32_t ncounters,
			     uint32_t flags);
	struct ibv_mr *(*reg_dm_mr)(struct ibv_pd *pd, struct ibv_dm *dm,
				    uint64_t dm_offset, size_t length,
				    unsigned int access);
	struct ibv_mr *(*reg_dmabuf_mr)(struct ibv_pd *pd, uint64_t offset,
					size_t length, uint64_t iova,
					int fd, int access);
	struct ibv_mr *(*reg_mr)(struct ibv_pd *pd, void *addr, size_t length,
				 uint64_t hca_va, int access);
	int (*req_notify_cq)(struct ibv_cq *cq, int solicited_only);
	int (*rereg_mr)(struct verbs_mr *vmr, int flags, struct ibv_pd *pd,
			void *addr, size_t length, int access);
	int (*resize_cq)(struct ibv_cq *cq, int cqe);
	int (*set_ece)(struct ibv_qp *qp, struct ibv_ece *ece);
	void (*unimport_dm)(struct ibv_dm *dm);
	void (*unimport_mr)(struct ibv_mr *mr);
	void (*unimport_pd)(struct ibv_pd *pd);
};

static inline struct verbs_device *
verbs_get_device(const struct ibv_device *dev)
{
	return container_of(dev, struct verbs_device, device);
}

typedef struct verbs_device *(*verbs_driver_init_func)(const char *uverbs_sys_path,
						       int abi_version);

/* Wire the IBVERBS_PRIVATE version number into the verbs_register_driver
 * symbol name.  This guarentees we link to the correct set of symbols even if
 * statically linking or using a dynmic linker with symbol versioning turned
 * off.
 */
#define ___make_verbs_register_driver(x) verbs_register_driver_ ## x
#define __make_verbs_register_driver(x)  ___make_verbs_register_driver(x)
#define verbs_register_driver __make_verbs_register_driver(IBVERBS_PABI_VERSION)

void verbs_register_driver(const struct verbs_device_ops *ops);

/*
 * Macro for providers to use to supply verbs_device_ops to the core code.
 * This creates a global symbol for the provider structure to be used by the
 * ibv_static_providers() machinery, and a global constructor for the dlopen
 * machinery.
 */
#define PROVIDER_DRIVER(provider_name, drv_struct)                             \
	extern const struct verbs_device_ops verbs_provider_##provider_name    \
		__attribute__((alias(stringify(drv_struct))));                 \
	static __attribute__((constructor)) void drv##__register_driver(void)  \
	{                                                                      \
		verbs_register_driver(&drv_struct);                            \
	}

void *_verbs_init_and_alloc_context(struct ibv_device *device, int cmd_fd,
				    size_t alloc_size,
				    struct verbs_context *context_offset,
				    uint32_t driver_id);

#define verbs_init_and_alloc_context(ibdev, cmd_fd, drv_ctx_ptr, ctx_memb,     \
				     driver_id)				       \
	((typeof(drv_ctx_ptr))_verbs_init_and_alloc_context(                   \
		ibdev, cmd_fd, sizeof(*drv_ctx_ptr),                           \
		&((typeof(drv_ctx_ptr))NULL)->ctx_memb, (driver_id)))

int verbs_init_context(struct verbs_context *context_ex,
		       struct ibv_device *device, int cmd_fd,
		       uint32_t driver_id);
void verbs_uninit_context(struct verbs_context *context);
void verbs_set_ops(struct verbs_context *vctx,
		   const struct verbs_context_ops *ops);

void verbs_init_cq(struct ibv_cq *cq, struct ibv_context *context,
		       struct ibv_comp_channel *channel,
		       void *cq_context);

struct ibv_context *verbs_open_device(struct ibv_device *device,
				      void *private_data);
int ibv_cmd_get_context(struct verbs_context *context,
			struct ibv_get_context *cmd, size_t cmd_size,
			struct ib_uverbs_get_context_resp *resp, size_t resp_size);
int ibv_cmd_query_context(struct ibv_context *ctx,
			  struct ibv_command_buffer *driver);
int ibv_cmd_create_flow_action_esp(struct ibv_context *ctx,
				   struct ibv_flow_action_esp_attr *attr,
				   struct verbs_flow_action *flow_action,
				   struct ibv_command_buffer *driver);
int ibv_cmd_modify_flow_action_esp(struct verbs_flow_action *flow_action,
				   struct ibv_flow_action_esp_attr *attr,
				   struct ibv_command_buffer *driver);
int ibv_cmd_query_device_any(struct ibv_context *context,
			     const struct ibv_query_device_ex_input *input,
			     struct ibv_device_attr_ex *attr, size_t attr_size,
			     struct ib_uverbs_ex_query_device_resp *resp,
			     size_t *resp_size);
int ibv_cmd_query_port(struct ibv_context *context, uint8_t port_num,
		       struct ibv_port_attr *port_attr,
		       struct ibv_query_port *cmd, size_t cmd_size);
int ibv_cmd_alloc_async_fd(struct ibv_context *context);
int ibv_cmd_alloc_pd(struct ibv_context *context, struct ibv_pd *pd,
		     struct ibv_alloc_pd *cmd, size_t cmd_size,
		     struct ib_uverbs_alloc_pd_resp *resp, size_t resp_size);
int ibv_cmd_dealloc_pd(struct ibv_pd *pd);
int ibv_cmd_open_xrcd(struct ibv_context *context, struct verbs_xrcd *xrcd,
		      int vxrcd_size,
		      struct ibv_xrcd_init_attr *attr,
		      struct ibv_open_xrcd *cmd, size_t cmd_size,
		      struct ib_uverbs_open_xrcd_resp *resp, size_t resp_size);
int ibv_cmd_close_xrcd(struct verbs_xrcd *xrcd);
int ibv_cmd_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
		   uint64_t hca_va, int access,
		   struct verbs_mr *vmr, struct ibv_reg_mr *cmd,
		   size_t cmd_size,
		   struct ib_uverbs_reg_mr_resp *resp, size_t resp_size);
int ibv_cmd_rereg_mr(struct verbs_mr *vmr, uint32_t flags, void *addr,
		     size_t length, uint64_t hca_va, int access,
		     struct ibv_pd *pd, struct ibv_rereg_mr *cmd,
		     size_t cmd_sz, struct ib_uverbs_rereg_mr_resp *resp,
		     size_t resp_sz);
int ibv_cmd_dereg_mr(struct verbs_mr *vmr);
int ibv_cmd_query_mr(struct ibv_pd *pd, struct verbs_mr *vmr,
		     uint32_t mr_handle);
int ibv_cmd_advise_mr(struct ibv_pd *pd,
		      enum ibv_advise_mr_advice advice,
		      uint32_t flags,
		      struct ibv_sge *sg_list,
		      uint32_t num_sge);
int ibv_cmd_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset, size_t length,
			  uint64_t iova, int fd, int access,
			  struct verbs_mr *vmr);
int ibv_cmd_alloc_mw(struct ibv_pd *pd, enum ibv_mw_type type,
		     struct ibv_mw *mw, struct ibv_alloc_mw *cmd,
		     size_t cmd_size,
		     struct ib_uverbs_alloc_mw_resp *resp, size_t resp_size);
int ibv_cmd_dealloc_mw(struct ibv_mw *mw);
int ibv_cmd_create_cq(struct ibv_context *context, int cqe,
		      struct ibv_comp_channel *channel,
		      int comp_vector, struct ibv_cq *cq,
		      struct ibv_create_cq *cmd, size_t cmd_size,
		      struct ib_uverbs_create_cq_resp *resp, size_t resp_size);
int ibv_cmd_create_cq_ex(struct ibv_context *context,
			 const struct ibv_cq_init_attr_ex *cq_attr,
			 struct verbs_cq *cq,
			 struct ibv_create_cq_ex *cmd,
			 size_t cmd_size,
			 struct ib_uverbs_ex_create_cq_resp *resp,
			 size_t resp_size,
			 uint32_t cmd_flags);
int ibv_cmd_poll_cq(struct ibv_cq *cq, int ne, struct ibv_wc *wc);
int ibv_cmd_req_notify_cq(struct ibv_cq *cq, int solicited_only);
int ibv_cmd_resize_cq(struct ibv_cq *cq, int cqe,
		      struct ibv_resize_cq *cmd, size_t cmd_size,
		      struct ib_uverbs_resize_cq_resp *resp, size_t resp_size);
int ibv_cmd_destroy_cq(struct ibv_cq *cq);
int ibv_cmd_modify_cq(struct ibv_cq *cq,
		      struct ibv_modify_cq_attr *attr,
		      struct ibv_modify_cq *cmd,
		      size_t cmd_size);

int ibv_cmd_create_srq(struct ibv_pd *pd,
		       struct ibv_srq *srq, struct ibv_srq_init_attr *attr,
		       struct ibv_create_srq *cmd, size_t cmd_size,
		       struct ib_uverbs_create_srq_resp *resp, size_t resp_size);
int ibv_cmd_create_srq_ex(struct ibv_context *context,
			  struct verbs_srq *srq,
			  struct ibv_srq_init_attr_ex *attr_ex,
			  struct ibv_create_xsrq *cmd, size_t cmd_size,
			  struct ib_uverbs_create_srq_resp *resp, size_t resp_size);
int ibv_cmd_modify_srq(struct ibv_srq *srq,
		       struct ibv_srq_attr *srq_attr,
		       int srq_attr_mask,
		       struct ibv_modify_srq *cmd, size_t cmd_size);
int ibv_cmd_query_srq(struct ibv_srq *srq,
		      struct ibv_srq_attr *srq_attr,
		      struct ibv_query_srq *cmd, size_t cmd_size);
int ibv_cmd_destroy_srq(struct ibv_srq *srq);

int ibv_cmd_create_qp(struct ibv_pd *pd,
		      struct ibv_qp *qp, struct ibv_qp_init_attr *attr,
		      struct ibv_create_qp *cmd, size_t cmd_size,
		      struct ib_uverbs_create_qp_resp *resp, size_t resp_size);
int ibv_cmd_create_qp_ex(struct ibv_context *context,
			 struct verbs_qp *qp,
			 struct ibv_qp_init_attr_ex *attr_ex,
			 struct ibv_create_qp *cmd, size_t cmd_size,
			 struct ib_uverbs_create_qp_resp *resp, size_t resp_size);
int ibv_cmd_create_qp_ex2(struct ibv_context *context,
			  struct verbs_qp *qp,
			  struct ibv_qp_init_attr_ex *qp_attr,
			  struct ibv_create_qp_ex *cmd,
			  size_t cmd_size,
			  struct ib_uverbs_ex_create_qp_resp *resp,
			  size_t resp_size);
int ibv_cmd_open_qp(struct ibv_context *context,
		    struct verbs_qp *qp,  int vqp_sz,
		    struct ibv_qp_open_attr *attr,
		    struct ibv_open_qp *cmd, size_t cmd_size,
		    struct ib_uverbs_create_qp_resp *resp, size_t resp_size);
int ibv_cmd_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *qp_attr,
		     int attr_mask,
		     struct ibv_qp_init_attr *qp_init_attr,
		     struct ibv_query_qp *cmd, size_t cmd_size);
int ibv_cmd_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		      int attr_mask,
		      struct ibv_modify_qp *cmd, size_t cmd_size);
int ibv_cmd_modify_qp_ex(struct ibv_qp *qp, struct ibv_qp_attr *attr,
			 int attr_mask, struct ibv_modify_qp_ex *cmd,
			 size_t cmd_size,
			 struct ib_uverbs_ex_modify_qp_resp *resp,
			 size_t resp_size);
int ibv_cmd_destroy_qp(struct ibv_qp *qp);
int ibv_cmd_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		      struct ibv_send_wr **bad_wr);
int ibv_cmd_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad_wr);
int ibv_cmd_post_srq_recv(struct ibv_srq *srq, struct ibv_recv_wr *wr,
			  struct ibv_recv_wr **bad_wr);
int ibv_cmd_create_ah(struct ibv_pd *pd, struct ibv_ah *ah,
		      struct ibv_ah_attr *attr,
		      struct ib_uverbs_create_ah_resp *resp,
		      size_t resp_size);
int ibv_cmd_destroy_ah(struct ibv_ah *ah);
int ibv_cmd_attach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid);
int ibv_cmd_detach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid);

int ibv_cmd_create_flow(struct ibv_qp *qp,
				     struct ibv_flow *flow_id,
				     struct ibv_flow_attr *flow_attr,
				     void *ucmd,
				     size_t ucmd_size);
int ibv_cmd_destroy_flow(struct ibv_flow *flow_id);
int ibv_cmd_create_wq(struct ibv_context *context,
		      struct ibv_wq_init_attr *wq_init_attr,
		      struct ibv_wq *wq,
		      struct ibv_create_wq *cmd,
		      size_t cmd_size,
		      struct ib_uverbs_ex_create_wq_resp *resp,
		      size_t resp_size);

int ibv_cmd_destroy_flow_action(struct verbs_flow_action *action);
int ibv_cmd_modify_wq(struct ibv_wq *wq, struct ibv_wq_attr *attr,
		      struct ibv_modify_wq *cmd, size_t cmd_size);
int ibv_cmd_destroy_wq(struct ibv_wq *wq);
int ibv_cmd_create_rwq_ind_table(struct ibv_context *context,
				 struct ibv_rwq_ind_table_init_attr *init_attr,
				 struct ibv_rwq_ind_table *rwq_ind_table,
				 struct ib_uverbs_ex_create_rwq_ind_table_resp *resp,
				 size_t resp_size);
int ibv_cmd_destroy_rwq_ind_table(struct ibv_rwq_ind_table *rwq_ind_table);
int ibv_cmd_create_counters(struct ibv_context *context,
			    struct ibv_counters_init_attr *init_attr,
			    struct verbs_counters *vcounters,
			    struct ibv_command_buffer *link);
int ibv_cmd_destroy_counters(struct verbs_counters *vcounters);
int ibv_cmd_read_counters(struct verbs_counters *vcounters,
			  uint64_t *counters_value,
			  uint32_t ncounters,
			  uint32_t flags,
			  struct ibv_command_buffer *link);
int ibv_dontfork_range(void *base, size_t size);
int ibv_dofork_range(void *base, size_t size);
int ibv_cmd_alloc_dm(struct ibv_context *ctx,
		     const struct ibv_alloc_dm_attr *dm_attr,
		     struct verbs_dm *dm,
		     struct ibv_command_buffer *link);
int ibv_cmd_free_dm(struct verbs_dm *dm);
int ibv_cmd_reg_dm_mr(struct ibv_pd *pd, struct verbs_dm *dm,
		      uint64_t offset, size_t length,
		      unsigned int access, struct verbs_mr *vmr,
		      struct ibv_command_buffer *link);

int __ibv_query_gid_ex(struct ibv_context *context, uint32_t port_num,
			    uint32_t gid_index, struct ibv_gid_entry *entry,
			    uint32_t flags, size_t entry_size,
			    uint32_t fallback_attr_mask);

/*
 * sysfs helper functions
 */
const char *ibv_get_sysfs_path(void);

int ibv_read_sysfs_file(const char *dir, const char *file,
			char *buf, size_t size);
int ibv_read_sysfs_file_at(int dirfd, const char *file, char *buf, size_t size);
int ibv_read_ibdev_sysfs_file(char *buf, size_t size,
			      struct verbs_sysfs_dev *sysfs_dev,
			      const char *fnfmt, ...)
	__attribute__((format(printf, 4, 5)));

static inline bool check_comp_mask(uint64_t input, uint64_t supported)
{
	return (input & ~supported) == 0;
}

int ibv_query_gid_type(struct ibv_context *context, uint8_t port_num,
		       unsigned int index, enum ibv_gid_type_sysfs *type);

static inline int
ibv_check_alloc_parent_domain(struct ibv_parent_domain_init_attr *attr)
{
	/* A valid protection domain must be set */
	if (!attr->pd) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

/*
 * Initialize the ibv_pd which is being used as a parent_domain. From the
 * perspective of the core code the new ibv_pd is completely interchangeable
 * with the passed contained_pd.
 */
static inline void ibv_initialize_parent_domain(struct ibv_pd *parent_domain,
						struct ibv_pd *contained_pd)
{
	parent_domain->context = contained_pd->context;
	parent_domain->handle = contained_pd->handle;
}

#endif /* INFINIBAND_DRIVER_H */
