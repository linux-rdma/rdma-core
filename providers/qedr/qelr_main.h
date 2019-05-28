/*
 * Copyright (c) 2015-2016  QLogic Corporation
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
 *        disclaimer in the documentation and /or other materials
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

#ifndef __QELR_MAIN_H__
#define __QELR_MAIN_H__

#include <inttypes.h>
#include <stddef.h>
#include <endian.h>

#include <infiniband/driver.h>
#include <util/udma_barrier.h>

int qelr_query_device(struct ibv_context *, struct ibv_device_attr *);
int qelr_query_port(struct ibv_context *, uint8_t, struct ibv_port_attr *);

struct ibv_pd *qelr_alloc_pd(struct ibv_context *);
int qelr_dealloc_pd(struct ibv_pd *);

struct ibv_mr *qelr_reg_mr(struct ibv_pd *ibpd, void *addr, size_t len,
			   uint64_t hca_va, int access);
int qelr_dereg_mr(struct verbs_mr *vmr);

struct ibv_cq *qelr_create_cq(struct ibv_context *, int,
			      struct ibv_comp_channel *, int);
int qelr_destroy_cq(struct ibv_cq *);
int qelr_poll_cq(struct ibv_cq *, int, struct ibv_wc *);
void qelr_cq_event(struct ibv_cq *);
int qelr_arm_cq(struct ibv_cq *, int);

int qelr_query_srq(struct ibv_srq *ibv_srq, struct ibv_srq_attr *attr);
int qelr_modify_srq(struct ibv_srq *ibv_srq, struct ibv_srq_attr *attr,
		    int attr_mask);
struct ibv_srq *qelr_create_srq(struct ibv_pd *, struct ibv_srq_init_attr *);
int qelr_destroy_srq(struct ibv_srq *ibv_srq);
int qelr_post_srq_recv(struct ibv_srq *, struct ibv_recv_wr *,
		       struct ibv_recv_wr **bad_wr);

struct ibv_qp *qelr_create_qp(struct ibv_pd *, struct ibv_qp_init_attr *);
int qelr_modify_qp(struct ibv_qp *, struct ibv_qp_attr *,
		   int ibv_qp_attr_mask);
int qelr_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		  struct ibv_qp_init_attr *init_attr);
int qelr_destroy_qp(struct ibv_qp *);

int qelr_post_send(struct ibv_qp *, struct ibv_send_wr *,
		   struct ibv_send_wr **);
int qelr_post_recv(struct ibv_qp *, struct ibv_recv_wr *,
		   struct ibv_recv_wr **);

void qelr_async_event(struct ibv_context *contex,
		      struct ibv_async_event *event);
#endif /* __QELR_MAIN_H__ */
