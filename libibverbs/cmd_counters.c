/*
 * Copyright (c) 2018 Mellanox Technologies, Ltd.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * - Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer.
 *
 * - Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 *   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 *   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *   SOFTWARE.
 */

#include <infiniband/cmd_ioctl.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <infiniband/driver.h>
#include <infiniband/cmd_write.h>

int ibv_cmd_create_counters(struct ibv_context *context,
			    struct ibv_counters_init_attr *init_attr,
			    struct verbs_counters *vcounters,
			    struct ibv_command_buffer *link)
{
	DECLARE_COMMAND_BUFFER_LINK(cmd, UVERBS_OBJECT_COUNTERS,
				    UVERBS_METHOD_COUNTERS_CREATE,
				    1,
				    link);
	struct ib_uverbs_attr *handle =
		fill_attr_out_obj(cmd, UVERBS_ATTR_CREATE_COUNTERS_HANDLE);
	int ret;

	if (!check_comp_mask(init_attr->comp_mask, 0))
		return EOPNOTSUPP;

	ret = execute_ioctl(context, cmd);
	if (ret)
		return ret;

	vcounters->counters.context = context;
	vcounters->handle = read_attr_obj(UVERBS_ATTR_CREATE_COUNTERS_HANDLE, handle);

	return 0;
}

int ibv_cmd_destroy_counters(struct verbs_counters *vcounters)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_COUNTERS,
			       UVERBS_METHOD_COUNTERS_DESTROY,
			       1);
	int ret;

	fill_attr_in_obj(cmd, UVERBS_ATTR_DESTROY_COUNTERS_HANDLE, vcounters->handle);
	ret = execute_ioctl(vcounters->counters.context, cmd);
	if (verbs_is_destroy_err(&ret))
		return ret;

	return 0;
}

int ibv_cmd_read_counters(struct verbs_counters *vcounters,
			  uint64_t *counters_value,
			  uint32_t ncounters,
			  uint32_t flags,
			  struct ibv_command_buffer *link)
{
	DECLARE_COMMAND_BUFFER_LINK(cmd, UVERBS_OBJECT_COUNTERS,
				    UVERBS_METHOD_COUNTERS_READ,
				    3,
				    link);

	fill_attr_in_obj(cmd, UVERBS_ATTR_READ_COUNTERS_HANDLE, vcounters->handle);
	fill_attr_out_ptr_array(cmd, UVERBS_ATTR_READ_COUNTERS_BUFF, counters_value,
				ncounters);
	fill_attr_in_uint32(cmd, UVERBS_ATTR_READ_COUNTERS_FLAGS, flags);

	return execute_ioctl(vcounters->counters.context, cmd);
}
