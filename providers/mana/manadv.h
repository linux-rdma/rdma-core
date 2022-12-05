/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2022, Microsoft Corporation. All rights reserved.
 */

#ifndef _MANA_DV_H_
#define _MANA_DV_H_

#include <stdio.h>
#include <linux/types.h>
#include <endian.h>
#include <infiniband/verbs.h>

#ifdef __cplusplus
extern "C" {
#endif

enum manadv_set_ctx_attr_type {
	/* Attribute type uint8_t */
	MANADV_CTX_ATTR_BUF_ALLOCATORS = 0,
};

struct manadv_ctx_allocators {
	void *(*alloc)(size_t size, void *priv_data);
	void (*free)(void *ptr, void *priv_data);
	void *data;
};

int manadv_set_context_attr(struct ibv_context *ibv_ctx,
			    enum manadv_set_ctx_attr_type type, void *attr);

struct manadv_qp {
	void *sq_buf;
	uint32_t sq_count;
	uint32_t sq_size;
	uint32_t sq_id;
	uint32_t tx_vp_offset;
	void *db_page;
};

struct manadv_cq {
	void *buf;
	uint32_t count;
	uint32_t cq_id;
};

struct manadv_rwq {
	void *buf;
	uint32_t count;
	uint32_t size;
	uint32_t wq_id;
	void *db_page;
};

struct manadv_obj {
	struct {
		struct ibv_qp *in;
		struct manadv_qp *out;
	} qp;

	struct {
		struct ibv_cq *in;
		struct manadv_cq *out;
	} cq;

	struct {
		struct ibv_wq *in;
		struct manadv_rwq *out;
	} rwq;
};

enum manadv_obj_type {
	MANADV_OBJ_QP = 1 << 0,
	MANADV_OBJ_CQ = 1 << 1,
	MANADV_OBJ_RWQ = 1 << 2,
};

int manadv_init_obj(struct manadv_obj *obj, uint64_t obj_type);

#ifdef __cplusplus
}
#endif

#endif /* _MANA_DV_H_ */
