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
 * Description: Basic device data structures needed for book-keeping
 */

#ifndef __MAIN_H__
#define __MAIN_H__

#include <inttypes.h>
#include <stddef.h>
#include <endian.h>
#include <pthread.h>

#include <infiniband/driver.h>
#include <util/udma_barrier.h>

#include "bnxt_re-abi.h"

struct bnxt_re_pd {
	struct ibv_pd ibvpd;
	uint32_t pdid;
};

struct bnxt_re_cq {
	struct ibv_cq ibvcq;
};

struct bnxt_re_qp {
	struct ibv_qp ibvqp;
};

struct bnxt_re_srq {
	struct ibv_srq ibvsrq;
};

struct bnxt_re_mr {
	struct ibv_mr ibvmr;
};

#define DEV	"bnxt_re : "

struct bnxt_re_dpi {
	__u32 dpindx;
	__u64 *dbpage;
	pthread_spinlock_t db_lock;
};

struct bnxt_re_dev {
	struct verbs_device vdev;
	uint8_t abi_version;
};

struct bnxt_re_context {
	struct ibv_context ibvctx;
	uint32_t dev_id;
	uint32_t max_qp;
	uint32_t max_srq;
	struct bnxt_re_dpi udpi;
};

static inline struct bnxt_re_dev *to_bnxt_re_dev(struct ibv_device *ibvdev)
{
	return container_of(ibvdev, struct bnxt_re_dev, vdev);
}

static inline struct bnxt_re_context *to_bnxt_re_context(
		struct ibv_context *ibvctx)
{
	return container_of(ibvctx, struct bnxt_re_context, ibvctx);
}

static inline struct bnxt_re_pd *to_bnxt_re_pd(struct ibv_pd *ibvpd)
{
	return container_of(ibvpd, struct bnxt_re_pd, ibvpd);
}

#endif
