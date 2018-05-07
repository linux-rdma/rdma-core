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

struct _ib_ex_hdr {
	struct ib_uverbs_cmd_hdr hdr;
	struct ib_uverbs_ex_cmd_hdr ex_hdr;
};

static inline struct _ib_ex_hdr *get_req_hdr_ex(void *req)
{
	return ((struct _ib_ex_hdr *)req) - 1;
}

/*
 * When using these new interfaces the kernel UAPI structs 'ib_uverbs_*' are
 * used, not the structs from kern-abi.h. The only difference between the two
 * is the inclusion of the header in the kern-abi.h struct. This macro creates
 * memory on the stack that includes both the header and the struct.
 */
#define DECLARE_LEGACY_REQ_BUF_CORE(_name, _pattern)                           \
	struct {                                                               \
		struct ib_uverbs_cmd_hdr hdr;                                  \
		struct ib_uverbs_##_pattern core_payload;                      \
	} _name

#define DECLARE_LEGACY_REQ_BUF_CORE_EX(_name, _pattern)                        \
	struct {                                                               \
		struct ib_uverbs_cmd_hdr hdr;                                  \
		struct ib_uverbs_ex_cmd_hdr ex_hdr;                            \
		struct ib_uverbs_ex_##_pattern core_payload;                   \
	} _name

void *_write_get_req(struct ibv_command_buffer *link, void *onstack,
		     size_t size);
void *_write_get_req_ex(struct ibv_command_buffer *link, void *onstack,
			size_t size);
void *_write_get_resp(struct ibv_command_buffer *link,
		      struct ib_uverbs_cmd_hdr *hdr, void *onstack,
		      size_t resp_size);
void *_write_get_resp_ex(struct ibv_command_buffer *link,
			 struct _ib_ex_hdr *hdr, void *onstack,
			 size_t resp_size);

#define DECLARE_LEGACY_REQ_BUF(_name, _link, _pattern)                         \
	DECLARE_LEGACY_REQ_BUF_CORE(__##_name##_onstack, _pattern);            \
	struct ib_uverbs_##_pattern *_name =                                   \
		_write_get_req(_link, &__##_name##_onstack, sizeof(*_name))

#define DECLARE_LEGACY_REQ_BUF_EX(_name, _link, _pattern)                      \
	DECLARE_LEGACY_REQ_BUF_CORE_EX(__##_name##_onstack, _pattern);         \
	struct ib_uverbs_ex_##_pattern *_name =                                \
		_write_get_req_ex(_link, &__##_name##_onstack, sizeof(*_name))

#define DECLARE_LEGACY_RESP_BUF(_name, _link, _req, _pattern)                  \
	struct ib_uverbs_##_pattern##_resp __##_name##_onstack,                \
		*_name = _write_get_resp(_link, get_req_hdr(_req),             \
					 &__##_name##_onstack, sizeof(*_name))

#define DECLARE_LEGACY_RESP_BUF_EX(_name, _link, _req, _pattern)               \
	struct ib_uverbs_ex_##_pattern##_resp __##_name##_onstack,             \
		*_name = _write_get_resp_ex(_link, get_req_hdr_ex(_req),       \
					    &__##_name##_onstack,              \
					    sizeof(*_name))

/*
 * This macro creates 'req' and 'resp' pointers in the local stack frame that
 * point to the core code write command structures patterned off _pattern.
 *
 * This should be done before calling execute_write_bufs
 */
#define DECLARE_LEGACY_UHW_BUFS(_link, _pattern)                               \
	DECLARE_LEGACY_REQ_BUF(req, _link, _pattern);                          \
	DECLARE_LEGACY_RESP_BUF(resp, _link, req, _pattern)

#define DECLARE_LEGACY_UHW_BUFS_EX(_link, _pattern)                            \
	DECLARE_LEGACY_REQ_BUF_EX(req, _link, _pattern);                       \
	DECLARE_LEGACY_RESP_BUF_EX(resp, _link, req, _pattern)

/*
 * This macro is used to implement the compatibility command call wrappers.
 * Compatibility calls do not accept a command_buffer, and cannot use the new
 * attribute id mechanism. They accept the legacy kern-abi.h structs that have
 * the embedded header.
 */
void _write_set_uhw(struct ibv_command_buffer *cmdb, const void *req,
		    size_t core_req_size, size_t req_size, void *resp,
		    size_t core_resp_size, size_t resp_size);
#define DECLARE_CMD_BUFFER_COMPAT(_name, _object_id, _method_id)               \
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
int _execute_write_raw(unsigned int cmdnum, struct ibv_context *ctx,
		       struct ib_uverbs_cmd_hdr *req, void *resp);

/* For users of DECLARE_LEGACY_UHW_BUFS */
#define execute_write_bufs(cmdnum, ctx, req, resp)                             \
	({                                                                     \
		(req)->response = ioctl_ptr_to_u64(resp);                      \
		_execute_write_raw(cmdnum, ctx, get_req_hdr(req), resp);       \
	})

int _execute_write_raw_ex(uint32_t cmdnum, struct ibv_context *ctx,
			  struct _ib_ex_hdr *req, void *resp);

/* For users of DECLARE_LEGACY_UHW_BUFS_EX */
#define execute_write_bufs_ex(cmdnum, ctx, req, resp)                          \
	_execute_write_raw_ex(cmdnum, ctx, get_req_hdr_ex(req), resp)

static inline int _execute_write(uint32_t cmdnum, struct ibv_context *ctx,
				 void *req, size_t req_len, void *resp,
				 size_t resp_len)
{
	struct ib_uverbs_cmd_hdr *hdr = get_req_hdr(req);

	hdr->in_words = req_len / 4;
	hdr->out_words = resp_len / 4;
	return _execute_write_raw(cmdnum, ctx, hdr, resp);
}

/* For users with no possible UHW bufs. */
#define DECLARE_LEGACY_CORE_BUFS(_pattern)                                     \
	DECLARE_LEGACY_REQ_BUF_CORE(__req_onstack, _pattern);                  \
	struct ib_uverbs_##_pattern *const req = &__req_onstack.core_payload;  \
	struct ib_uverbs_##_pattern##_resp resp

/*
 * For users with no UHW bufs. To be used in conjunction with
 * DECLARE_LEGACY_CORE_BUFS. req points to the core payload (with headroom for
 * the header).
 */
#define execute_write(cmdnum, ctx, req, resp)                                  \
	({                                                                     \
		(req)->response = ioctl_ptr_to_u64(resp);                      \
		_execute_write(cmdnum, ctx, req, sizeof(*req), resp,           \
			       sizeof(*resp));                                 \
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
static inline int execute_write_bufs(uint32_t cmdnum,
				     struct ibv_context *ctx, void *req,
				     void *resp)
{
	return ENOSYS;
}

#undef execute_write_bufs_ex
static inline int execute_write_bufs_ex(uint32_t cmdnum,
					struct ibv_context *ctx, void *req,
					void *resp)
{
	return ENOSYS;
}

#undef execute_write
static inline int execute_write(uint32_t cmdnum,
				struct ibv_context *ctx, void *req,
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

#endif
