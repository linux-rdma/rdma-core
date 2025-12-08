// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/*
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <infiniband/cmd_write.h>

int ibv_cmd_export_dmabuf_fd(struct ibv_context *ctx, off_t pg_off)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_DMABUF,
			       UVERBS_METHOD_DMABUF_ALLOC, 2);
	struct ib_uverbs_attr *handle;
	int ret;

	handle = fill_attr_out_fd(cmd, UVERBS_ATTR_ALLOC_DMABUF_HANDLE, 0);
	fill_attr_in_uint64(cmd, UVERBS_ATTR_ALLOC_DMABUF_PGOFF, pg_off);

	ret = execute_ioctl(ctx, cmd);
	if (ret)
		/* errno is set to a postive value internally */
		return -1;

	return read_attr_fd(UVERBS_ATTR_ALLOC_DMABUF_HANDLE, handle);
}
