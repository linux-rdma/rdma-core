/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005, 2006 Cisco Systems.  All rights reserved.
 * Copyright (c) 2005 PathScale, Inc.  All rights reserved.
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

#ifndef INFINIBAND_DRIVER_H
#define INFINIBAND_DRIVER_H

#include <sysfs/libsysfs.h>

#include <infiniband/verbs.h>
#include <infiniband/kern-abi.h>

#ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
#else /* !__cplusplus */
#  define BEGIN_C_DECLS
#  define END_C_DECLS
#endif /* __cplusplus */

/*
 * Device-specific drivers should declare their device init function
 * as below (the name must be "openib_driver_init"):
 *
 * struct ibv_device *openib_driver_init(struct sysfs_class_device *);
 *
 * libibverbs will call each driver's openib_driver_init() function
 * once for each InfiniBand device.  If the device is one that the
 * driver can support, it should return a struct ibv_device * with the
 * ops member filled in.  If the driver does not support the device,
 * it should return NULL from openib_driver_init().
 */

typedef struct ibv_device *(*ibv_driver_init_func)(struct sysfs_class_device *);

int ibv_cmd_get_context(struct ibv_context *context, struct ibv_get_context *cmd,
			size_t cmd_size, struct ibv_get_context_resp *resp,
			size_t resp_size);
int ibv_cmd_query_device(struct ibv_context *context,
			 struct ibv_device_attr *device_attr,
			 uint64_t *raw_fw_ver,
			 struct ibv_query_device *cmd, size_t cmd_size);
int ibv_cmd_query_port(struct ibv_context *context, uint8_t port_num,
		       struct ibv_port_attr *port_attr,
		       struct ibv_query_port *cmd, size_t cmd_size);
int ibv_cmd_query_gid(struct ibv_context *context, uint8_t port_num,
		      int index, union ibv_gid *gid);
int ibv_cmd_query_pkey(struct ibv_context *context, uint8_t port_num,
		       int index, uint16_t *pkey);
int ibv_cmd_alloc_pd(struct ibv_context *context, struct ibv_pd *pd,
		     struct ibv_alloc_pd *cmd, size_t cmd_size,
		     struct ibv_alloc_pd_resp *resp, size_t resp_size);
int ibv_cmd_dealloc_pd(struct ibv_pd *pd);
int ibv_cmd_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
		   uint64_t hca_va, enum ibv_access_flags access,
		   struct ibv_mr *mr, struct ibv_reg_mr *cmd,
		   size_t cmd_size);
int ibv_cmd_dereg_mr(struct ibv_mr *mr);
int ibv_cmd_create_cq(struct ibv_context *context, int cqe,
		      struct ibv_comp_channel *channel,
		      int comp_vector, struct ibv_cq *cq,
		      struct ibv_create_cq *cmd, size_t cmd_size,
		      struct ibv_create_cq_resp *resp, size_t resp_size);
int ibv_cmd_poll_cq(struct ibv_cq *cq, int ne, struct ibv_wc *wc);
int ibv_cmd_req_notify_cq(struct ibv_cq *cq, int solicited_only);
int ibv_cmd_resize_cq(struct ibv_cq *cq, int cqe,
		      struct ibv_resize_cq *cmd, size_t cmd_size);
int ibv_cmd_destroy_cq(struct ibv_cq *cq);

int ibv_cmd_create_srq(struct ibv_pd *pd,
		       struct ibv_srq *srq, struct ibv_srq_init_attr *attr,
		       struct ibv_create_srq *cmd, size_t cmd_size,
		       struct ibv_create_srq_resp *resp, size_t resp_size);
int ibv_cmd_modify_srq(struct ibv_srq *srq,
		       struct ibv_srq_attr *srq_attr,
		       enum ibv_srq_attr_mask srq_attr_mask,
		       struct ibv_modify_srq *cmd, size_t cmd_size);
int ibv_cmd_query_srq(struct ibv_srq *srq,
		      struct ibv_srq_attr *srq_attr,
		      struct ibv_query_srq *cmd, size_t cmd_size);
int ibv_cmd_destroy_srq(struct ibv_srq *srq);

int ibv_cmd_create_qp(struct ibv_pd *pd,
		      struct ibv_qp *qp, struct ibv_qp_init_attr *attr,
		      struct ibv_create_qp *cmd, size_t cmd_size,
		      struct ibv_create_qp_resp *resp, size_t resp_size);
int ibv_cmd_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *qp_attr,
		     enum ibv_qp_attr_mask attr_mask,
		     struct ibv_qp_init_attr *qp_init_attr,
		     struct ibv_query_qp *cmd, size_t cmd_size);
int ibv_cmd_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		      enum ibv_qp_attr_mask attr_mask,
		      struct ibv_modify_qp *cmd, size_t cmd_size);
int ibv_cmd_destroy_qp(struct ibv_qp *qp);
int ibv_cmd_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		      struct ibv_send_wr **bad_wr);
int ibv_cmd_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad_wr);
int ibv_cmd_post_srq_recv(struct ibv_srq *srq, struct ibv_recv_wr *wr,
			  struct ibv_recv_wr **bad_wr);
int ibv_cmd_create_ah(struct ibv_pd *pd, struct ibv_ah *ah,
		      struct ibv_ah_attr *attr);
int ibv_cmd_destroy_ah(struct ibv_ah *ah);
int ibv_cmd_attach_mcast(struct ibv_qp *qp, union ibv_gid *gid, uint16_t lid);
int ibv_cmd_detach_mcast(struct ibv_qp *qp, union ibv_gid *gid, uint16_t lid);

#endif /* INFINIBAND_DRIVER_H */
