/*
 * Copyright (c) 2016 Hisilicon Limited.
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

#include <infiniband/driver.h>
#include <infiniband/arch.h>
#include <infiniband/verbs.h>
#include <ccan/container_of.h>

#define HNS_ROCE_HW_VER1		('h' << 24 | 'i' << 16 | '0' << 8 | '6')

#define PFX				"hns: "

enum {
	HNS_ROCE_QP_TABLE_BITS		= 8,
	HNS_ROCE_QP_TABLE_SIZE		= 1 << HNS_ROCE_QP_TABLE_BITS,
};

struct hns_roce_device {
	struct ibv_device		ibv_dev;
	int				page_size;
};

struct hns_roce_context {
	struct ibv_context		ibv_ctx;
	void				*uar;
	pthread_spinlock_t		uar_lock;

	struct {
		int			refcnt;
	} qp_table[HNS_ROCE_QP_TABLE_SIZE];

	pthread_mutex_t			qp_table_mutex;

	int				num_qps;
	int				qp_table_shift;
	int				qp_table_mask;
	unsigned int			max_qp_wr;
	unsigned int			max_sge;
	int				max_cqe;
};

struct hns_roce_pd {
	struct ibv_pd			ibv_pd;
	unsigned int			pdn;
};

static inline struct hns_roce_device *to_hr_dev(struct ibv_device *ibv_dev)
{
	return container_of(ibv_dev, struct hns_roce_device, ibv_dev);
}

static inline struct hns_roce_context *to_hr_ctx(struct ibv_context *ibv_ctx)
{
	return container_of(ibv_ctx, struct hns_roce_context, ibv_ctx);
}

static inline struct hns_roce_pd *to_hr_pd(struct ibv_pd *ibv_pd)
{
	return container_of(ibv_pd, struct hns_roce_pd, ibv_pd);
}

int hns_roce_u_query_device(struct ibv_context *context,
			    struct ibv_device_attr *attr);
int hns_roce_u_query_port(struct ibv_context *context, uint8_t port,
			  struct ibv_port_attr *attr);

struct ibv_pd *hns_roce_u_alloc_pd(struct ibv_context *context);
int hns_roce_u_free_pd(struct ibv_pd *pd);

struct ibv_mr *hns_roce_u_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
				 int access);
int hns_roce_u_dereg_mr(struct ibv_mr *mr);

#endif /* _HNS_ROCE_U_H */
