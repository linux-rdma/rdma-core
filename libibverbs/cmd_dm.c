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

#include <infiniband/cmd_write.h>

int ibv_cmd_alloc_dm(struct ibv_context *ctx,
		     const struct ibv_alloc_dm_attr *dm_attr,
		     struct verbs_dm *dm,
		     struct ibv_command_buffer *link)
{
	DECLARE_COMMAND_BUFFER_LINK(cmdb, UVERBS_OBJECT_DM,
				    UVERBS_METHOD_DM_ALLOC, 3, link);
	struct ib_uverbs_attr *handle;
	int ret;

	handle = fill_attr_out_obj(cmdb, UVERBS_ATTR_ALLOC_DM_HANDLE);
	fill_attr_in_uint64(cmdb, UVERBS_ATTR_ALLOC_DM_LENGTH,
			    dm_attr->length);
	fill_attr_in_uint32(cmdb, UVERBS_ATTR_ALLOC_DM_ALIGNMENT,
			    dm_attr->log_align_req);

	ret = execute_ioctl(ctx, cmdb);
	if (ret)
		return errno;

	dm->handle = read_attr_obj(UVERBS_ATTR_ALLOC_DM_HANDLE, handle);
	dm->dm.context = ctx;

	return 0;
}

int ibv_cmd_free_dm(struct verbs_dm *dm)
{
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_DM, UVERBS_METHOD_DM_FREE,
			       1);
	int ret;

	fill_attr_in_obj(cmdb, UVERBS_ATTR_FREE_DM_HANDLE, dm->handle);

	ret = execute_ioctl(dm->dm.context, cmdb);
	if (verbs_is_destroy_err(&ret))
		return ret;

	return 0;
}

int ibv_cmd_reg_dm_mr(struct ibv_pd *pd, struct verbs_dm *dm,
		      uint64_t offset, size_t length,
		      unsigned int access, struct verbs_mr *vmr,
		      struct ibv_command_buffer *link)
{
	DECLARE_COMMAND_BUFFER_LINK(cmdb, UVERBS_OBJECT_MR, UVERBS_METHOD_DM_MR_REG,
				    8, link);
	struct ib_uverbs_attr *handle;
	uint32_t lkey, rkey;
	int ret;

	/*
	 * DM MRs are always 0 based since the mmap pointer, if it exists, is
	 * hidden from the user.
	 */
	if (!(access & IBV_ACCESS_ZERO_BASED)) {
		errno = EINVAL;
		return errno;
	}

	handle = fill_attr_out_obj(cmdb, UVERBS_ATTR_REG_DM_MR_HANDLE);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_REG_DM_MR_RESP_LKEY, &lkey);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_REG_DM_MR_RESP_RKEY, &rkey);

	fill_attr_in_obj(cmdb, UVERBS_ATTR_REG_DM_MR_PD_HANDLE, pd->handle);
	fill_attr_in_obj(cmdb, UVERBS_ATTR_REG_DM_MR_DM_HANDLE, dm->handle);
	fill_attr_in_uint64(cmdb, UVERBS_ATTR_REG_DM_MR_OFFSET, offset);
	fill_attr_in_uint64(cmdb, UVERBS_ATTR_REG_DM_MR_LENGTH, length);
	fill_attr_in_uint32(cmdb, UVERBS_ATTR_REG_DM_MR_ACCESS_FLAGS, access);

	ret = execute_ioctl(pd->context, cmdb);
	if (ret)
		return errno;

	vmr->ibv_mr.handle =
		read_attr_obj(UVERBS_ATTR_REG_DM_MR_HANDLE, handle);
	vmr->ibv_mr.context = pd->context;
	vmr->ibv_mr.lkey = lkey;
	vmr->ibv_mr.rkey = rkey;
	vmr->ibv_mr.length = length;
	vmr->ibv_mr.pd = pd;
	vmr->ibv_mr.addr = NULL;
	vmr->mr_type  = IBV_MR_TYPE_MR;

	return 0;
}
