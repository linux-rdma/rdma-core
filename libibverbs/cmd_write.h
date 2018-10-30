/*
 * Copyright (c) 2018 Mellanox Technologies, Ltd.  All rights reserved.
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

#ifndef __INFINIBAND_VERBS_WRITE_H
#define __INFINIBAND_VERBS_WRITE_H

#include <infiniband/cmd_ioctl.h>
#include <infiniband/driver.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_user_ioctl_cmds.h>

#include <stdbool.h>

static inline struct ib_uverbs_cmd_hdr *get_req_hdr(void *req)
{
	return ((struct ib_uverbs_cmd_hdr *)req) - 1;
}

static inline struct ex_hdr *get_req_hdr_ex(void *req)
{
	return ((struct ex_hdr *)req) - 1;
}

void *_write_get_req(struct ibv_command_buffer *link,
		     struct ib_uverbs_cmd_hdr *onstack, size_t size,
		     uint32_t cmdnum);
void *_write_get_req_ex(struct ibv_command_buffer *link, struct ex_hdr *onstack,
			size_t size, uint32_t cmdnum);
void *_write_get_resp(struct ibv_command_buffer *link,
		      struct ib_uverbs_cmd_hdr *hdr, void *onstack,
		      size_t resp_size);
void *_write_get_resp_ex(struct ibv_command_buffer *link,
			 struct ex_hdr *hdr, void *onstack,
			 size_t resp_size);

/*
 * This macro creates 'req' and 'resp' pointers in the local stack frame that
 * point to the core code write command structures patterned off _pattern.
 *
 * This should be done before calling execute_write_bufs
 */
#define DECLARE_LEGACY_UHW_BUFS(_link, _enum)                                  \
	IBV_ABI_REQ(_enum) __req_onstack;                                      \
	IBV_KABI_RESP(_enum) __resp_onstack;                                   \
	static_assert(offsetof(IBV_KABI_REQ(_enum), response) == 0,            \
		      "Bad response offset");                                  \
	IBV_KABI_REQ(_enum) *req = _write_get_req(_link, &__req_onstack.hdr,   \
						  sizeof(*req), _enum);        \
	IBV_KABI_RESP(_enum) *resp = ({                                        \
		void *_resp = _write_get_resp(_link, get_req_hdr(req),         \
					      &__resp_onstack, sizeof(*resp)); \
		_resp;                                                         \
	})

#define DECLARE_LEGACY_UHW_BUFS_EX(_link, _enum)                               \
	IBV_ABI_REQ(_enum) __req_onstack;                                      \
	IBV_KABI_RESP(_enum) __resp_onstack;                                   \
	IBV_KABI_REQ(_enum) *req = _write_get_req_ex(                          \
		_link, &__req_onstack.hdr, sizeof(*req), _enum);               \
	IBV_KABI_RESP(_enum) *resp = _write_get_resp_ex(                       \
		_link, get_req_hdr_ex(req), &__resp_onstack, sizeof(*resp))

/*
 * This macro is used to implement the compatibility command call wrappers.
 * Compatibility calls do not accept a command_buffer, and cannot use the new
 * attribute id mechanism. They accept the legacy kern-abi.h structs that have
 * the embedded header.
 */
void _write_set_uhw(struct ibv_command_buffer *cmdb, const void *req,
		    size_t core_req_size, size_t req_size, void *resp,
		    size_t core_resp_size, size_t resp_size);
#define DECLARE_CMD_BUFFER_COMPAT(_name, _object_id, _method_id, cmd,          \
				  cmd_size, resp, resp_size)                   \
	DECLARE_COMMAND_BUFFER(_name, _object_id, _method_id, 2);              \
	_write_set_uhw(_name, cmd, sizeof(*cmd), cmd_size, resp,               \
		       sizeof(*resp), resp_size)

/*
 * The fallback scheme keeps track of which ioctls succeed in a per-context
 * bitmap. If ENOTTY or EPROTONOSUPPORT is seen then the ioctl is never
 * retried.
 *
 * cmd_name should be the name of the function op from verbs_context_ops
 * that is being implemented.
 */
#define _CMD_BIT(cmd_name)                                                     \
	(offsetof(struct verbs_context_ops, cmd_name) / sizeof(void *))

enum write_fallback { TRY_WRITE, TRY_WRITE_EX, ERROR, SUCCESS };

/*
 * This bitmask indicate the required behavior of execute_ioctl_fallback when
 * the ioctl is not supported. It is a priority list where the highest set bit
 * takes precedence. This approach simplifies the typical required control
 * flow of the user.
 */
static inline void fallback_require_ex(struct ibv_command_buffer *cmdb)
{
	cmdb->fallback_require_ex = 1;
}

static inline void fallback_require_ioctl(struct ibv_command_buffer *cmdb)
{
	cmdb->fallback_ioctl_only = 1;
}

enum write_fallback _check_legacy(struct ibv_command_buffer *cmdb, int *ret);

enum write_fallback _execute_ioctl_fallback(struct ibv_context *ctx,
					    unsigned int cmd_bit,
					    struct ibv_command_buffer *cmdb,
					    int *ret);

#define execute_ioctl_fallback(ctx, cmd_name, cmdb, ret)                       \
	_execute_ioctl_fallback(ctx, _CMD_BIT(cmd_name), cmdb, ret)

/* These helpers replace the raw write() and IBV_INIT_CMD macros */
int _execute_write_raw(struct ibv_context *ctx, struct ib_uverbs_cmd_hdr *req,
		       void *resp);

/* For users of DECLARE_LEGACY_UHW_BUFS */
#define execute_write_bufs(ctx, req, resp)                             \
		_execute_write_raw(ctx, get_req_hdr(req), resp)

int _execute_write_raw_ex(struct ibv_context *ctx, struct ex_hdr *req);

/* For users of DECLARE_LEGACY_UHW_BUFS_EX */
#define execute_write_bufs_ex(ctx, req)                                        \
	_execute_write_raw_ex(ctx, get_req_hdr_ex(req))

/* For users with no possible UHW bufs. */
#define DECLARE_LEGACY_CORE_BUFS(_enum)                                        \
	IBV_ABI_REQ(_enum) __req_onstack;                                      \
	IBV_KABI_RESP(_enum) resp;                                             \
	static_assert(offsetof(IBV_KABI_REQ(_enum), response) == 0,            \
		      "Bad response offset");                                  \
	IBV_KABI_REQ(_enum) *const req = ({                                    \
		__req_onstack.hdr.command = _enum;                             \
		__req_onstack.hdr.in_words = sizeof(__req_onstack) / 4;        \
		__req_onstack.hdr.out_words = sizeof(resp) / 4;                \
		&__req_onstack.core_payload;                                   \
	})
#define DECLARE_LEGACY_CORE_REQ(_enum)                                         \
	IBV_ABI_REQ(_enum) __req_onstack;                                      \
	static_assert(sizeof(IBV_KABI_RESP(_enum)) == 0,                       \
		      "Method has a response!");                               \
	IBV_KABI_REQ(_enum) *const req = ({                                    \
		__req_onstack.hdr.command = _enum;                             \
		__req_onstack.hdr.in_words = sizeof(__req_onstack) / 4;        \
		__req_onstack.hdr.out_words = 0;                               \
		&__req_onstack.core_payload;                                   \
	})

#define DECLARE_LEGACY_CORE_BUFS_EX(_enum)                                     \
	IBV_ABI_REQ(_enum) __req_onstack;                                      \
	IBV_KABI_RESP(_enum) resp;                                             \
	IBV_KABI_REQ(_enum) *const req = ({                                    \
		__req_onstack.hdr.hdr.command =                                \
			IB_USER_VERBS_CMD_FLAG_EXTENDED | _enum;               \
		__req_onstack.hdr.hdr.in_words =                               \
			(sizeof(__req_onstack) - sizeof(struct ex_hdr)) / 8;   \
		__req_onstack.hdr.hdr.out_words = sizeof(resp) / 8;            \
		__req_onstack.hdr.ex_hdr.cmd_hdr_reserved = 0;                 \
		__req_onstack.hdr.ex_hdr.provider_in_words = 0;                \
		__req_onstack.hdr.ex_hdr.provider_out_words = 0;               \
		__req_onstack.hdr.ex_hdr.response =                            \
			(sizeof(resp) == 0) ? 0 : ioctl_ptr_to_u64(&resp);     \
		&__req_onstack.core_payload;                                   \
	})

/*
 * For users with no UHW bufs. To be used in conjunction with
 * DECLARE_LEGACY_CORE_BUFS. req points to the core payload (with headroom for
 * the header).
 */
#define execute_write(ctx, req, resp)                                          \
	_execute_write_raw(ctx, get_req_hdr(req), resp)
#define execute_write_ex(ctx, req)                                             \
	_execute_write_raw_ex(ctx, get_req_hdr_ex(req))

/*
 * For write() only commands that have fixed core structures and may take uhw
 * driver data. The last arguments are the same ones passed into the typical
 * ibv_cmd_* function. execute_cmd_write deduces the length of the core
 * structure based on the KABI struct linked to the enum op code.
 */
int _execute_cmd_write(struct ibv_context *ctx, unsigned int write_method,
		       struct ib_uverbs_cmd_hdr *req, size_t core_req_size,
		       size_t req_size, void *resp, size_t core_resp_size,
		       size_t resp_size);
#define execute_cmd_write(ctx, enum, cmd, cmd_size, resp, resp_size)           \
	({                                                                     \
		(cmd)->core_payload.response = ioctl_ptr_to_u64(resp);         \
		_execute_cmd_write(                                            \
			ctx, enum,                                             \
			&(cmd)->hdr + check_type(cmd, IBV_ABI_REQ(enum) *),    \
			sizeof(*(cmd)), cmd_size,                              \
			resp + check_type(resp, IBV_KABI_RESP(enum) *),        \
			sizeof(*(resp)), resp_size);                           \
	})

/*
 * Execute a write command that does not have a uhw component. The cmd_size
 * and resp_size are the lengths of the core structure. This version is only
 * needed if the core structure ends in a flex array, as the internal sizeof()
 * in execute_cmd_write() will give the wrong size.
 */
#define execute_cmd_write_no_uhw(ctx, enum, cmd, cmd_size, resp, resp_size)    \
	({                                                                     \
		(cmd)->core_payload.response = ioctl_ptr_to_u64(resp);         \
		_execute_cmd_write(                                            \
			ctx, enum,                                             \
			&(cmd)->hdr + check_type(cmd, IBV_ABI_REQ(enum) *),    \
			cmd_size, cmd_size,                                    \
			resp + check_type(resp, IBV_KABI_RESP(enum) *),        \
			resp_size, resp_size);                                 \
	})

/*
 * These two macros are used only with execute_ioctl_fallback - they allow the
 * IOCTL code to be elided by the compiler when disabled.
 */
#define DECLARE_FBCMD_BUFFER DECLARE_COMMAND_BUFFER_LINK

/*
 * Munge the macros above to remove certain paths during compilation based on
 * the cmake flag.
 */
#if VERBS_IOCTL_ONLY
static inline enum write_fallback
_execute_ioctl_only(struct ibv_context *context, struct ibv_command_buffer *cmd,
		    int *ret)
{
	*ret = execute_ioctl(context, cmd);
	if (*ret)
		return ERROR;

	return SUCCESS;
}

#undef execute_ioctl_fallback
#define execute_ioctl_fallback(ctx, cmd_name, cmdb, ret)                       \
	_execute_ioctl_only(ctx, cmdb, ret)

#undef execute_write_bufs
static inline int execute_write_bufs(struct ibv_context *ctx, void *req,
				     void *resp)
{
	return ENOSYS;
}

#undef execute_write_bufs_ex
static inline int execute_write_bufs_ex(struct ibv_context *ctx, void *req)
{
	return ENOSYS;
}

#undef execute_write
static inline int execute_write(struct ibv_context *ctx, void *req,
				void *resp)
{
	return ENOSYS;
}

#endif

#if VERBS_WRITE_ONLY
static inline enum write_fallback
_execute_write_only(struct ibv_context *context, struct ibv_command_buffer *cmd,
		    int *ret)
{
	/*
	 * write only still has the command buffer, and the command buffer
	 * carries the fallback guidance that we need to inspect. This is
	 * written in this odd way so the compiler knows that SUCCESS is not a
	 * possible return and optimizes accordingly.
	 */
	switch (_check_legacy(cmd, ret)) {
	case TRY_WRITE:
		return TRY_WRITE;
	case TRY_WRITE_EX:
		return TRY_WRITE_EX;
	default:
		return ERROR;
	}
}

#undef execute_ioctl_fallback
#define execute_ioctl_fallback(ctx, cmd_name, cmdb, ret)                       \
	_execute_write_only(ctx, cmdb, ret)

#undef DECLARE_FBCMD_BUFFER
#define DECLARE_FBCMD_BUFFER(_name, _object_id, _method_id, _num_attrs, _link) \
	struct ibv_command_buffer _name[1] = {                                 \
		{                                                              \
			.next = _link,                                         \
			.uhw_in_idx = _UHW_NO_INDEX,                           \
			.uhw_out_idx = _UHW_NO_INDEX,                          \
		},                                                             \
	}

#endif

extern bool verbs_allow_disassociate_destroy;

/*
 * Return true if 'ret' indicates that a destroy operation has failed
 * and the function should exit. If the kernel destroy failure is being
 * ignored then this will set ret to 0, so the calling function appears to succeed.
 */
static inline bool verbs_is_destroy_err(int *ret)
{
	if (*ret == EIO && verbs_allow_disassociate_destroy) {
		*ret = 0;
		return true;
	}

	return *ret != 0;
}

#endif
