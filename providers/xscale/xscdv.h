/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef _XSCDV_H_
#define _XSCDV_H_

#include <stdio.h>
#include <linux/types.h> /* For the __be64 type */
#include <sys/types.h>
#include <endian.h>
#if defined(__SSE3__)
#include <limits.h>
#include <emmintrin.h>
#include <tmmintrin.h>
#endif /* defined(__SSE3__) */

#include <infiniband/verbs.h>
#include <infiniband/tm_types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum xscdv_cq_init_attr_mask {
	XSCDV_CQ_INIT_ATTR_MASK_COMPRESSED_CQE	= 1 << 0,
	XSCDV_CQ_INIT_ATTR_MASK_FLAGS		= 1 << 1,
	XSCDV_CQ_INIT_ATTR_MASK_CQE_SIZE = 1 << 2,
};

struct xscdv_cq_init_attr {
	uint64_t comp_mask; /* Use enum xscdv_cq_init_attr_mask */
	uint8_t cqe_comp_res_format; /* Use enum xscdv_cqe_comp_res_format */
	uint32_t flags;
	uint16_t cqe_size; /* when XSCDV_CQ_INIT_ATTR_MASK_CQE_SIZE set */
};

enum xscdv_devx_umem_in_mask {
	XSCDV_UMEM_MASK_DMABUF = 1 << 0,
};

struct xscdv_devx_umem_in {
	void *addr;
	size_t size;
	uint32_t access;
	uint64_t pgsz_bitmap;
	uint64_t comp_mask;
	int dmabuf_fd;
};

struct xscdv_ctx_allocators {
	void *(*alloc)(size_t size, void *priv_data);
	void (*free)(void *ptr, void *priv_data);
	void *data;
};

#ifdef __cplusplus
}
#endif

#endif /* _XSCDV_H_ */
