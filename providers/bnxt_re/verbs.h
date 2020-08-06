/*
 * Broadcom NetXtreme-E User Space RoCE driver
 *
 * Copyright (c) 2015-2017, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Description: Internal IB-verbs function declaration
 */

#ifndef __VERBS_H__
#define __VERBS_H__

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <unistd.h>

#include <infiniband/driver.h>
#include <infiniband/verbs.h>

int bnxt_re_query_device(struct ibv_context *uctx,
			 struct ibv_device_attr *attr);
int bnxt_re_query_port(struct ibv_context *uctx, uint8_t port,
		       struct ibv_port_attr *attr);
struct ibv_pd *bnxt_re_alloc_pd(struct ibv_context *uctx);
int bnxt_re_free_pd(struct ibv_pd *ibvpd);
struct ibv_mr *bnxt_re_reg_mr(struct ibv_pd *ibvpd, void *buf, size_t len,
			      uint64_t hca_va, int ibv_access_flags);
int bnxt_re_dereg_mr(struct verbs_mr *vmr);

struct ibv_cq *bnxt_re_create_cq(struct ibv_context *uctx, int ncqe,
				 struct ibv_comp_channel *ch, int vec);
int bnxt_re_resize_cq(struct ibv_cq *ibvcq, int ncqe);
int bnxt_re_destroy_cq(struct ibv_cq *ibvcq);
int bnxt_re_poll_cq(struct ibv_cq *ibvcq, int nwc, struct ibv_wc *wc);
void bnxt_re_cq_event(struct ibv_cq *ibvcq);
int bnxt_re_arm_cq(struct ibv_cq *ibvcq, int flags);

struct ibv_qp *bnxt_re_create_qp(struct ibv_pd *ibvpd,
				 struct ibv_qp_init_attr *attr);
int bnxt_re_modify_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr,
		      int ibv_qp_attr_mask);
int bnxt_re_query_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr,
		     int attr_mask, struct ibv_qp_init_attr *init_attr);
int bnxt_re_destroy_qp(struct ibv_qp *ibvqp);
int bnxt_re_post_send(struct ibv_qp *ibvqp, struct ibv_send_wr *wr,
		      struct ibv_send_wr **bad);
int bnxt_re_post_recv(struct ibv_qp *ibvqp, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad);

struct ibv_srq *bnxt_re_create_srq(struct ibv_pd *ibvpd,
				   struct ibv_srq_init_attr *attr);
int bnxt_re_modify_srq(struct ibv_srq *ibvsrq,
		       struct ibv_srq_attr *attr, int mask);
int bnxt_re_destroy_srq(struct ibv_srq *ibvsrq);
int bnxt_re_query_srq(struct ibv_srq *ibvsrq, struct ibv_srq_attr *attr);
int bnxt_re_post_srq_recv(struct ibv_srq *ibvsrq, struct ibv_recv_wr *wr,
			  struct ibv_recv_wr **bad);

struct ibv_ah *bnxt_re_create_ah(struct ibv_pd *ibvpd,
				 struct ibv_ah_attr *attr);
int bnxt_re_destroy_ah(struct ibv_ah *ibvah);

#endif /* __BNXT_RE_VERBS_H__ */
