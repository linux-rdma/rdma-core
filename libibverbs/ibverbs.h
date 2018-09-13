/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2007 Cisco Systems, Inc.  All rights reserved.
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

#ifndef IB_VERBS_H
#define IB_VERBS_H

#include <pthread.h>

#include <infiniband/driver.h>

#include <valgrind/memcheck.h>

#include <ccan/bitmap.h>

#define INIT		__attribute__((constructor))

#define PFX		"libibverbs: "
#define VERBS_OPS_NUM (sizeof(struct verbs_context_ops) / sizeof(void *))

#define RDMA_CDEV_DIR "/dev/infiniband"

struct ibv_abi_compat_v2 {
	struct ibv_comp_channel	channel;
	pthread_mutex_t		in_use;
};

extern int abi_ver;
extern const struct verbs_context_ops verbs_dummy_ops;

int ibverbs_get_device_list(struct list_head *list);
int ibverbs_init(void);
void ibverbs_device_put(struct ibv_device *dev);
void ibverbs_device_hold(struct ibv_device *dev);

#ifdef _STATIC_LIBRARY_BUILD_
static inline void load_drivers(void)
{
}
#else
void load_drivers(void);
#endif

struct verbs_ex_private {
	BITMAP_DECLARE(unsupported_ioctls, VERBS_OPS_NUM);
	uint32_t driver_id;
	struct verbs_context_ops ops;
};

static inline struct verbs_ex_private *get_priv(struct ibv_context *ctx)
{
	return container_of(ctx, struct verbs_context, context)->priv;
}

static inline const struct verbs_context_ops *get_ops(struct ibv_context *ctx)
{
	return &get_priv(ctx)->ops;
}

#define IBV_INIT_CMD(cmd, size, opcode)					\
	do {								\
		(cmd)->hdr.command = IB_USER_VERBS_CMD_##opcode;	\
		(cmd)->hdr.in_words  = (size) / 4;			\
		(cmd)->hdr.out_words = 0;				\
	} while (0)

#define IBV_INIT_CMD_RESP(cmd, size, opcode, out, outsize)		\
	do {								\
		(cmd)->hdr.command = IB_USER_VERBS_CMD_##opcode;	\
		(cmd)->hdr.in_words  = (size) / 4;			\
		(cmd)->hdr.out_words = (outsize) / 4;			\
		(cmd)->response  = (uintptr_t) (out);			\
	} while (0)

static inline uint32_t _cmd_ex(uint32_t cmd)
{
	return IB_USER_VERBS_CMD_FLAG_EXTENDED | cmd;
}

#define IBV_INIT_CMD_RESP_EX_V(cmd, cmd_size, size, opcode, out, resp_size,\
		outsize)						   \
	do {                                                               \
		size_t c_size = cmd_size - sizeof(struct ex_hdr);	   \
		(cmd)->hdr.hdr.command =				   \
			_cmd_ex(IB_USER_VERBS_EX_CMD_##opcode);		   \
		(cmd)->hdr.hdr.in_words  = ((c_size) / 8);                 \
		(cmd)->hdr.hdr.out_words = ((resp_size) / 8);              \
		(cmd)->hdr.ex_hdr.provider_in_words   = (((size) - (cmd_size))/8);\
		(cmd)->hdr.ex_hdr.provider_out_words  =			   \
			     (((outsize) - (resp_size)) / 8);              \
		(cmd)->hdr.ex_hdr.response  = (uintptr_t) (out);           \
		(cmd)->hdr.ex_hdr.cmd_hdr_reserved = 0;			   \
	} while (0)

#define IBV_INIT_CMD_RESP_EX_VCMD(cmd, cmd_size, size, opcode, out, outsize) \
	IBV_INIT_CMD_RESP_EX_V(cmd, cmd_size, size, opcode, out,	     \
			sizeof(*(out)), outsize)

#define IBV_INIT_CMD_RESP_EX(cmd, size, opcode, out, outsize)		     \
	IBV_INIT_CMD_RESP_EX_V(cmd, sizeof(*(cmd)), size, opcode, out,    \
			sizeof(*(out)), outsize)

#define IBV_INIT_CMD_EX(cmd, size, opcode)				     \
	IBV_INIT_CMD_RESP_EX_V(cmd, sizeof(*(cmd)), size, opcode, NULL, 0, 0)

#endif /* IB_VERBS_H */
