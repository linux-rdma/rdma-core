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

#include <infiniband/cmd_ioctl.h>
#include <infiniband/cmd_write.h>
#include "ibverbs.h"

#include <util/compiler.h>
#include <ccan/build_assert.h>

#include <unistd.h>
#include <valgrind/memcheck.h>

/*
 * Check if the command buffer provided by the driver includes anything that
 * is not compatible with the legacy interface. If so, then
 * _execute_ioctl_fallback indicates it handled the call and sets the error
 * code
 */
enum write_fallback _check_legacy(struct ibv_command_buffer *cmdb, int *ret)
{
	struct ib_uverbs_attr *cur;
	bool fallback_require_ex = cmdb->fallback_require_ex;
	bool fallback_ioctl_only = cmdb->fallback_ioctl_only;

	for (cmdb = cmdb->next; cmdb; cmdb = cmdb->next) {
		for (cur = cmdb->hdr.attrs; cur != cmdb->next_attr; cur++) {
			if (cur->attr_id != UVERBS_ATTR_UHW_IN &&
			    cur->attr_id != UVERBS_ATTR_UHW_OUT &&
			    cur->flags & UVERBS_ATTR_F_MANDATORY)
				goto not_supp;
		}
		fallback_require_ex |= cmdb->fallback_require_ex;
		fallback_ioctl_only |= cmdb->fallback_ioctl_only;
	}

	if (fallback_ioctl_only)
		goto not_supp;

	if (fallback_require_ex)
		return TRY_WRITE_EX;
	return TRY_WRITE;

not_supp:
	errno = EOPNOTSUPP;
	*ret = EOPNOTSUPP;
	return ERROR;
}

/*
 * Used to support callers that have a fallback to the old write ABI
 * interface.
 */
enum write_fallback _execute_ioctl_fallback(struct ibv_context *ctx,
					    unsigned int cmd_bit,
					    struct ibv_command_buffer *cmdb,
					    int *ret)
{
	struct verbs_ex_private *priv = get_priv(ctx);

	if (bitmap_test_bit(priv->unsupported_ioctls, cmd_bit))
		return _check_legacy(cmdb, ret);

	*ret = execute_ioctl(ctx, cmdb);

	if (likely(*ret == 0))
		return SUCCESS;

	if (*ret == ENOTTY) {
		/* ENOTTY means the ioctl framework is entirely absent */
		bitmap_fill(priv->unsupported_ioctls, VERBS_OPS_NUM);
		return _check_legacy(cmdb, ret);
	}

	if (*ret == EPROTONOSUPPORT) {
		/*
		 * EPROTONOSUPPORT means we have the ioctl framework but this
		 * specific method is not supported
		 */
		bitmap_set_bit(priv->unsupported_ioctls, cmd_bit);
		return _check_legacy(cmdb, ret);
	}

	return ERROR;
}

/*
 * Within the command implementation we get a pointer to the request and
 * response buffers for the legacy interface. This pointer is either allocated
 * on the stack (if the driver didn't provide a UHW) or arranged to be
 * directly before the UHW memory (see _write_set_uhw)
 */
void *_write_get_req(struct ibv_command_buffer *link,
		     struct ib_uverbs_cmd_hdr *onstack, size_t size)
{
	struct ib_uverbs_cmd_hdr *hdr;

	size += sizeof(*hdr);

	if (link->uhw_in_idx != _UHW_NO_INDEX) {
		struct ib_uverbs_attr *uhw = &link->hdr.attrs[link->uhw_in_idx];

		assert(uhw->attr_id == UVERBS_ATTR_UHW_IN);
		assert(link->uhw_in_headroom_dwords * 4 >= size);
		hdr = (void *)((uintptr_t)uhw->data - size);
		hdr->in_words = __check_divide(size + uhw->len, 4);
	} else {
		hdr = onstack;
		hdr->in_words = __check_divide(size, 4);
	}

	return hdr + 1;
}

void *_write_get_req_ex(struct ibv_command_buffer *link, struct ex_hdr *onstack,
			size_t size)
{
	struct ex_hdr *hdr;
	size_t full_size = size + sizeof(*hdr);

	if (link->uhw_in_idx != _UHW_NO_INDEX) {
		struct ib_uverbs_attr *uhw = &link->hdr.attrs[link->uhw_in_idx];

		assert(uhw->attr_id == UVERBS_ATTR_UHW_IN);
		assert(link->uhw_in_headroom_dwords * 4 >= full_size);
		hdr = (void *)((uintptr_t)uhw->data - full_size);
		hdr->ex_hdr.provider_in_words = __check_divide(uhw->len, 8);
	} else {
		hdr = onstack;
		hdr->ex_hdr.provider_in_words = 0;
	}

	return hdr + 1;
}

void *_write_get_resp(struct ibv_command_buffer *link,
		      struct ib_uverbs_cmd_hdr *hdr, void *onstack,
		      size_t resp_size)
{
	void *resp_start;

	if (link->uhw_out_idx != _UHW_NO_INDEX) {
		struct ib_uverbs_attr *uhw =
			&link->hdr.attrs[link->uhw_out_idx];

		assert(uhw->attr_id == UVERBS_ATTR_UHW_OUT);
		assert(link->uhw_out_headroom_dwords * 4 >= resp_size);
		resp_start = (void *)((uintptr_t)uhw->data - resp_size);
		hdr->out_words = __check_divide(resp_size + uhw->len, 4);
	} else {
		resp_start = onstack;
		hdr->out_words = __check_divide(resp_size, 4);
	}

	return resp_start;
}

void *_write_get_resp_ex(struct ibv_command_buffer *link,
			 struct ex_hdr *hdr, void *onstack,
			 size_t resp_size)
{
	void *resp_start;

	if (link->uhw_out_idx != _UHW_NO_INDEX) {
		struct ib_uverbs_attr *uhw =
			&link->hdr.attrs[link->uhw_out_idx];

		assert(uhw->attr_id == UVERBS_ATTR_UHW_OUT);
		assert(link->uhw_out_headroom_dwords * 4 >= resp_size);
		resp_start = (void *)((uintptr_t)uhw->data - resp_size);
		hdr->ex_hdr.provider_out_words = __check_divide(uhw->len, 8);
	} else {
		resp_start = onstack;
		hdr->ex_hdr.provider_out_words = 0;
	}

	return resp_start;
}

static int ioctl_write(struct ibv_context *ctx, unsigned int write_method,
		       const void *req, size_t core_req_size, size_t req_size,
		       void *resp, size_t core_resp_size, size_t resp_size)
{
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_DEVICE,
			       UVERBS_METHOD_INVOKE_WRITE, 5);

	fill_attr_const_in(cmdb, UVERBS_ATTR_WRITE_CMD, write_method);

	if (core_req_size)
		fill_attr_in(cmdb, UVERBS_ATTR_CORE_IN, req, core_req_size);
	if (core_resp_size)
		fill_attr_out(cmdb, UVERBS_ATTR_CORE_OUT, resp, core_resp_size);

	if (req_size - core_req_size)
		fill_attr_in(cmdb, UVERBS_ATTR_UHW_IN, req + core_req_size,
			     req_size - core_req_size);
	if (resp_size - core_resp_size)
		fill_attr_out(cmdb, UVERBS_ATTR_UHW_OUT, resp + core_resp_size,
			     resp_size - core_resp_size);

	return execute_ioctl(ctx, cmdb);
}

int _execute_cmd_write(struct ibv_context *ctx, unsigned int write_method,
		       struct ib_uverbs_cmd_hdr *req, size_t core_req_size,
		       size_t req_size, void *resp, size_t core_resp_size,
		       size_t resp_size)
{
	struct verbs_ex_private *priv = get_priv(ctx);

	if (!VERBS_WRITE_ONLY && (VERBS_IOCTL_ONLY || priv->use_ioctl_write))
		return ioctl_write(ctx, write_method, req + 1,
				   core_req_size - sizeof(*req),
				   req_size - sizeof(*req), resp,
				   core_resp_size, resp_size);

	req->command = write_method;
	req->in_words = __check_divide(req_size, 4);
	req->out_words = __check_divide(resp_size, 4);

	if (write(ctx->cmd_fd, req, req_size) != req_size)
		return errno;

	if (resp)
		VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);
	return 0;
}

/*
 * req_size is the total length of the ex_hdr, core payload and driver data.
 * core_req_size is the total length of the ex_hdr and core_payload.
 */
int _execute_cmd_write_ex(struct ibv_context *ctx, unsigned int write_method,
		       struct ex_hdr *req, size_t core_req_size,
		       size_t req_size, void *resp, size_t core_resp_size,
		       size_t resp_size)
{
	struct verbs_ex_private *priv = get_priv(ctx);

	if (!VERBS_WRITE_ONLY && (VERBS_IOCTL_ONLY || priv->use_ioctl_write))
		return ioctl_write(
			ctx, IB_USER_VERBS_CMD_FLAG_EXTENDED | write_method,
			req + 1, core_req_size - sizeof(*req),
			req_size - sizeof(*req), resp, core_resp_size,
			resp_size);

	req->hdr.command = IB_USER_VERBS_CMD_FLAG_EXTENDED | write_method;
	req->hdr.in_words =
		__check_divide(core_req_size - sizeof(struct ex_hdr), 8);
	req->hdr.out_words = __check_divide(core_resp_size, 8);
	req->ex_hdr.provider_in_words =
		__check_divide(req_size - core_req_size, 8);
	req->ex_hdr.provider_out_words =
		__check_divide(resp_size - core_resp_size, 8);
	req->ex_hdr.response = ioctl_ptr_to_u64(resp);
	req->ex_hdr.cmd_hdr_reserved = 0;

	/*
	 * Users assumes the stack buffer is zeroed before passing to the
	 * kernel for writing. New kernels with the ioctl path do this
	 * automatically for us.
	 */
	if (resp)
		memset(resp, 0, resp_size);

	if (write(ctx->cmd_fd, req, req_size) != req_size)
		return errno;

	if (resp)
		VALGRIND_MAKE_MEM_DEFINED(resp, resp_size);
	return 0;
}
