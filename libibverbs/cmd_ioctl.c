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

#include <sys/ioctl.h>
#include <infiniband/driver.h>

#include <rdma/ib_user_ioctl_cmds.h>
#include <valgrind/memcheck.h>

/* Number of attrs in this and all the link'd buffers */
unsigned int __ioctl_final_num_attrs(unsigned int num_attrs,
				     struct ibv_command_buffer *link)
{
	for (; link; link = link->next)
		num_attrs += link->next_attr - link->hdr.attrs;

	return num_attrs;
}

/* Linearize the link'd buffers into this one */
static void prepare_attrs(struct ibv_command_buffer *cmd)
{
	struct ib_uverbs_attr *end = cmd->next_attr;
	struct ibv_command_buffer *link;

	for (link = cmd->next; link; link = link->next) {
		struct ib_uverbs_attr *cur;

		assert(cmd->hdr.object_id == link->hdr.object_id);
		assert(cmd->hdr.method_id == link->hdr.method_id);

		/*
		 * Keep track of where the uhw_in lands in the final array if
		 * we copy it from a link
		 */
		if (!VERBS_IOCTL_ONLY && link->uhw_in_idx != _UHW_NO_INDEX) {
			assert(cmd->uhw_in_idx == _UHW_NO_INDEX);
			cmd->uhw_in_idx =
				link->uhw_in_idx + (end - cmd->hdr.attrs);
		}

		for (cur = link->hdr.attrs; cur != link->next_attr; cur++)
			*end++ = *cur;

		assert(end <= cmd->last_attr);
	}

	cmd->hdr.num_attrs = end - cmd->hdr.attrs;

	/*
	 * We keep the in UHW uninlined until directly before sending to
	 * support the compat path. See _fill_attr_in_uhw
	 */
	if (!VERBS_IOCTL_ONLY && cmd->uhw_in_idx != _UHW_NO_INDEX) {
		struct ib_uverbs_attr *uhw = &cmd->hdr.attrs[cmd->uhw_in_idx];

		assert(uhw->attr_id == UVERBS_ATTR_UHW_IN);

		if (uhw->len <= sizeof(uhw->data))
			memcpy(&uhw->data, (void *)(uintptr_t)uhw->data,
			       uhw->len);
	}
}

static void finalize_attr(struct ib_uverbs_attr *attr)
{
	/* Only matches UVERBS_ATTR_TYPE_PTR_OUT */
	if (attr->flags & UVERBS_ATTR_F_VALID_OUTPUT && attr->len)
		VALGRIND_MAKE_MEM_DEFINED((void *)(uintptr_t)attr->data,
					  attr->len);
}

/*
 * Copy the link'd attrs back to their source and make all output buffers safe
 * for VALGRIND
 */
static void finalize_attrs(struct ibv_command_buffer *cmd)
{
	struct ibv_command_buffer *link;
	struct ib_uverbs_attr *end;

	for (end = cmd->hdr.attrs; end != cmd->next_attr; end++)
		finalize_attr(end);

	for (link = cmd->next; link; link = link->next) {
		struct ib_uverbs_attr *cur;

		for (cur = link->hdr.attrs; cur != link->next_attr; cur++) {
			finalize_attr(end);
			*cur = *end++;
		}
	}
}

int execute_ioctl(struct ibv_context *context, struct ibv_command_buffer *cmd)
{
	struct verbs_context *vctx = verbs_get_ctx(context);

	/*
	 * One of the fill functions was given input that cannot be marshaled
	 */
	if (unlikely(cmd->buffer_error)) {
		errno = EINVAL;
		return errno;
	}

	prepare_attrs(cmd);
	cmd->hdr.length = sizeof(cmd->hdr) +
		sizeof(cmd->hdr.attrs[0]) * cmd->hdr.num_attrs;
	cmd->hdr.reserved1 = 0;
	cmd->hdr.reserved2 = 0;
	cmd->hdr.driver_id = vctx->priv->driver_id;

	if (ioctl(context->cmd_fd, RDMA_VERBS_IOCTL, &cmd->hdr))
		return errno;

	finalize_attrs(cmd);

	return 0;
}

/*
 * The compat scheme for UHW IN requires a pointer in .data, however the
 * kernel protocol requires pointers < 8 to be inlined into .data. We defer
 * that transformation until directly before the ioctl.
 */
static inline struct ib_uverbs_attr *
_fill_attr_in_uhw(struct ibv_command_buffer *cmd, uint16_t attr_id,
		 const void *data, size_t len)
{
	struct ib_uverbs_attr *attr = _ioctl_next_attr(cmd, attr_id);

	if (unlikely(len > UINT16_MAX))
		cmd->buffer_error = 1;

	attr->len = len;
	attr->data = ioctl_ptr_to_u64(data);

	return attr;
}

/*
 * This helper is used in the driver compat wrappers to build the
 * command buffer from the legacy input pointers format.
 */
void _write_set_uhw(struct ibv_command_buffer *cmdb, const void *req,
		    size_t core_req_size, size_t req_size, void *resp,
		    size_t core_resp_size, size_t resp_size)
{
	if (req && core_req_size < req_size) {
		if (VERBS_IOCTL_ONLY)
			cmdb->uhw_in_idx =
				fill_attr_in(cmdb, UVERBS_ATTR_UHW_IN,
					     (uint8_t *)req + core_req_size,
					     req_size - core_req_size) -
				cmdb->hdr.attrs;
		else
			cmdb->uhw_in_idx =
				_fill_attr_in_uhw(cmdb, UVERBS_ATTR_UHW_IN,
						  (uint8_t *)req +
							  core_req_size,
						  req_size - core_req_size) -
				cmdb->hdr.attrs;
		cmdb->uhw_in_headroom_dwords = __check_divide(core_req_size, 4);
	}


	if (resp && core_resp_size < resp_size) {
		cmdb->uhw_out_idx =
			fill_attr_out(cmdb, UVERBS_ATTR_UHW_OUT,
				      (uint8_t *)resp + core_resp_size,
				      resp_size - core_resp_size) -
			cmdb->hdr.attrs;
		cmdb->uhw_out_headroom_dwords =
			__check_divide(core_resp_size, 4);
	}
}
