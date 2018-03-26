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
		return ERROR;

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
void *_write_get_req(struct ibv_command_buffer *link, void *onstack,
		     size_t size)
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

void *_write_get_req_ex(struct ibv_command_buffer *link, void *onstack,
			size_t size)
{
	struct _ib_ex_hdr *hdr;
	size_t full_size = size + sizeof(*hdr);

	if (link->uhw_in_idx != _UHW_NO_INDEX) {
		struct ib_uverbs_attr *uhw = &link->hdr.attrs[link->uhw_in_idx];

		assert(uhw->attr_id == UVERBS_ATTR_UHW_IN);
		assert(link->uhw_in_headroom_dwords * 4 >= full_size);
		hdr = (void *)((uintptr_t)uhw->data - full_size);
		hdr->hdr.in_words = __check_divide(size, 8);
		hdr->ex_hdr.provider_in_words = __check_divide(uhw->len, 8);
	} else {
		hdr = onstack;
		hdr->hdr.in_words = __check_divide(size, 8);
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
			 struct _ib_ex_hdr *hdr, void *onstack,
			 size_t resp_size)
{
	void *resp_start;

	if (link->uhw_out_idx != _UHW_NO_INDEX) {
		struct ib_uverbs_attr *uhw =
			&link->hdr.attrs[link->uhw_out_idx];

		assert(uhw->attr_id == UVERBS_ATTR_UHW_OUT);
		assert(link->uhw_out_headroom_dwords * 4 >= resp_size);
		resp_start = (void *)((uintptr_t)uhw->data - resp_size);
		hdr->hdr.out_words = __check_divide(resp_size, 8);
		hdr->ex_hdr.provider_out_words = __check_divide(uhw->len, 8);
	} else {
		resp_start = onstack;
		hdr->hdr.out_words = __check_divide(resp_size, 8);
		hdr->ex_hdr.provider_out_words = 0;
	}

	return resp_start;
}

int _execute_write_raw(unsigned int cmdnum, struct ibv_context *ctx,
		       struct ib_uverbs_cmd_hdr *hdr, void *resp)
{
	hdr->command = cmdnum;

	/*
	 * Users assumes the stack buffer is zeroed before passing to the
	 * kernel for writing.
	 */
	memset(resp, 0, hdr->out_words * 4);

	if (write(ctx->cmd_fd, hdr, hdr->in_words * 4) != hdr->in_words * 4)
		return errno;

	VALGRIND_MAKE_MEM_DEFINED(resp, hdr->out_words * 4);

	return 0;
}

int _execute_write_raw_ex(uint32_t cmdnum, struct ibv_context *ctx,
			  struct _ib_ex_hdr *hdr, void *resp)
{
	size_t write_bytes =
		sizeof(*hdr) +
		(hdr->hdr.in_words + hdr->ex_hdr.provider_in_words) * 8;
	size_t resp_bytes =
		(hdr->hdr.out_words + hdr->ex_hdr.provider_out_words) * 8;

	hdr->hdr.command = IB_USER_VERBS_CMD_FLAG_EXTENDED | cmdnum;
	hdr->ex_hdr.cmd_hdr_reserved = 0;
	hdr->ex_hdr.response =  ioctl_ptr_to_u64(resp);

	/*
	 * Users assumes the stack buffer is zeroed before passing to the
	 * kernel for writing.
	 */
	memset(resp, 0, resp_bytes);

	if (write(ctx->cmd_fd, hdr, write_bytes) != write_bytes)
		return errno;

	VALGRIND_MAKE_MEM_DEFINED(resp, resp_bytes);

	return 0;
}
