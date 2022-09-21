/* SPDX-License-Identifier: GPL-2.0 or OpenIB.org BSD (MIT) See COPYING file */
/*
 * Authors: Cheng Xu <chengyou@linux.alibaba.com>
 * Copyright (c) 2020-2021, Alibaba Group.
 */

#ifndef __ERDMA_H__
#define __ERDMA_H__

#include <inttypes.h>
#include <pthread.h>
#include <stddef.h>

#include <infiniband/driver.h>
#include <infiniband/kern-abi.h>
#include <sys/param.h>

#ifndef PCI_VENDOR_ID_ALIBABA
#define PCI_VENDOR_ID_ALIBABA 0x1ded
#endif

#define ERDMA_PAGE_SIZE 4096

struct erdma_device {
	struct verbs_device ibv_dev;
};

#define ERDMA_QP_TABLE_SIZE 4096
#define ERDMA_QP_TABLE_SHIFT 12
#define ERDMA_QP_TABLE_MASK 0xFFF

struct erdma_context {
	struct verbs_context ibv_ctx;
	uint32_t dev_id;

	struct {
		struct erdma_qp **table;
		int refcnt;
	} qp_table[ERDMA_QP_TABLE_SIZE];
	pthread_mutex_t qp_table_mutex;

	uint8_t sdb_type;
	uint32_t sdb_offset;

	void *sdb;
	void *rdb;
	void *cdb;

	uint32_t page_size;
	pthread_mutex_t dbrecord_pages_mutex;
	struct list_head dbrecord_pages_list;
};

static inline struct erdma_context *to_ectx(struct ibv_context *base)
{
	return container_of(base, struct erdma_context, ibv_ctx.context);
}

#endif
