/*
 * Copyright (c) 2018 Mellanox Technologies, Ltd.  All rights reserved.
 * Copyright (c) 2020 Intel Corporation.  All rights reserved.
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
#include <rdma/ib_user_ioctl_cmds.h>
#include <infiniband/driver.h>
#include <infiniband/cmd_write.h>

int ibv_cmd_advise_mr(struct ibv_pd *pd,
		      enum ibv_advise_mr_advice advice,
		      uint32_t flags,
		      struct ibv_sge *sg_list,
		      uint32_t num_sge)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_MR,
			       UVERBS_METHOD_ADVISE_MR,
			       4);

	fill_attr_in_obj(cmd, UVERBS_ATTR_ADVISE_MR_PD_HANDLE, pd->handle);
	fill_attr_const_in(cmd, UVERBS_ATTR_ADVISE_MR_ADVICE, advice);
	fill_attr_in_uint32(cmd, UVERBS_ATTR_ADVISE_MR_FLAGS, flags);
	fill_attr_in_ptr_array(cmd, UVERBS_ATTR_ADVISE_MR_SGE_LIST,
			       sg_list, num_sge);

	return execute_ioctl(pd->context, cmd);
}

int ibv_cmd_dereg_mr(struct verbs_mr *vmr)
{
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_MR, UVERBS_METHOD_MR_DESTROY,
			     1, NULL);
	int ret;

	fill_attr_in_obj(cmdb, UVERBS_ATTR_DESTROY_MR_HANDLE,
			 vmr->ibv_mr.handle);

	switch (execute_ioctl_fallback(vmr->ibv_mr.context, dereg_mr, cmdb,
				       &ret)) {
	case TRY_WRITE: {
		struct ibv_dereg_mr req;

		req.core_payload = (struct ib_uverbs_dereg_mr){
			.mr_handle = vmr->ibv_mr.handle,
		};
		ret = execute_cmd_write_req(vmr->ibv_mr.context,
					    IB_USER_VERBS_CMD_DEREG_MR, &req,
					    sizeof(req));
		break;
	}

	default:
		break;
	}

	if (verbs_is_destroy_err(&ret))
		return ret;
	return 0;
}

int ibv_cmd_query_mr(struct ibv_pd *pd, struct verbs_mr *vmr,
		     uint32_t mr_handle)
{
	DECLARE_FBCMD_BUFFER(cmd, UVERBS_OBJECT_MR,
			     UVERBS_METHOD_QUERY_MR,
			     4, NULL);
	struct ibv_mr *mr = &vmr->ibv_mr;
	int ret;

	fill_attr_in_obj(cmd, UVERBS_ATTR_QUERY_MR_HANDLE, mr_handle);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_QUERY_MR_RESP_LKEY,
			  &mr->lkey);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_QUERY_MR_RESP_RKEY,
			  &mr->rkey);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_QUERY_MR_RESP_LENGTH,
			  &mr->length);

	ret = execute_ioctl(pd->context, cmd);
	if (ret)
		return ret;

	mr->handle  = mr_handle;
	mr->context = pd->context;
	mr->pd = pd;
	mr->addr = NULL;

	vmr->mr_type = IBV_MR_TYPE_IMPORTED_MR;
	return 0;
}

int ibv_cmd_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset, size_t length,
			  uint64_t iova, int fd, int access,
			  struct verbs_mr *vmr,
			  struct ibv_command_buffer *driver)
{
	DECLARE_COMMAND_BUFFER_LINK(cmdb, UVERBS_OBJECT_MR,
				    UVERBS_METHOD_REG_DMABUF_MR,
				    9,
				    driver);
	struct ib_uverbs_attr *handle;
	uint32_t lkey, rkey;
	int ret;

	handle = fill_attr_out_obj(cmdb, UVERBS_ATTR_REG_DMABUF_MR_HANDLE);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_REG_DMABUF_MR_RESP_LKEY, &lkey);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_REG_DMABUF_MR_RESP_RKEY, &rkey);

	fill_attr_in_obj(cmdb, UVERBS_ATTR_REG_DMABUF_MR_PD_HANDLE, pd->handle);
	fill_attr_in_uint64(cmdb, UVERBS_ATTR_REG_DMABUF_MR_OFFSET, offset);
	fill_attr_in_uint64(cmdb, UVERBS_ATTR_REG_DMABUF_MR_LENGTH, length);
	fill_attr_in_uint64(cmdb, UVERBS_ATTR_REG_DMABUF_MR_IOVA, iova);
	fill_attr_in_uint32(cmdb, UVERBS_ATTR_REG_DMABUF_MR_FD, fd);
	fill_attr_in_uint32(cmdb, UVERBS_ATTR_REG_DMABUF_MR_ACCESS_FLAGS, access);

	ret = execute_ioctl(pd->context, cmdb);
	if (ret)
		return errno;

	vmr->ibv_mr.handle = read_attr_obj(UVERBS_ATTR_REG_DMABUF_MR_HANDLE,
					   handle);
	vmr->ibv_mr.context = pd->context;
	vmr->ibv_mr.lkey = lkey;
	vmr->ibv_mr.rkey = rkey;
	vmr->ibv_mr.pd = pd;
	vmr->ibv_mr.addr = (void *)(uintptr_t)offset;
	vmr->ibv_mr.length = length;
	vmr->mr_type = IBV_MR_TYPE_DMABUF_MR;
	return 0;
}

int ibv_cmd_reg_mr_ex(struct ibv_pd *pd, struct verbs_mr *vmr,
		      struct ibv_mr_init_attr *mr_init_attr)
{
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_MR,
			       UVERBS_METHOD_REG_MR, 11);
	bool fd_based = (mr_init_attr->comp_mask & IBV_REG_MR_MASK_FD);
	struct ib_uverbs_attr *handle;
	uint64_t length = mr_init_attr->length;
	uint32_t lkey, rkey;
	int ret;

	if (fd_based) {
		if (!(mr_init_attr->comp_mask & IBV_REG_MR_MASK_FD_OFFSET) ||
		    (mr_init_attr->comp_mask & IBV_REG_MR_MASK_ADDR)) {
			errno = EINVAL;
			return EINVAL;
		}
		fill_attr_in_uint64(cmdb, UVERBS_ATTR_REG_MR_FD_OFFSET,
				    mr_init_attr->fd_offset);
		fill_attr_in_fd(cmdb, UVERBS_ATTR_REG_MR_FD,
				mr_init_attr->fd);
	} else {
		if ((mr_init_attr->comp_mask & IBV_REG_MR_MASK_FD_OFFSET) ||
		    !(mr_init_attr->comp_mask & IBV_REG_MR_MASK_ADDR)) {
			errno = EINVAL;
			return EINVAL;
		}

		fill_attr_in_uint64(cmdb, UVERBS_ATTR_REG_MR_ADDR,
				    (uintptr_t) mr_init_attr->addr);
		if (mr_init_attr->access & IBV_ACCESS_ON_DEMAND) {
			if (mr_init_attr->length == SIZE_MAX && mr_init_attr->addr) {
				errno = EINVAL;
				return EINVAL;
			}
			if (mr_init_attr->length == SIZE_MAX)
				length = UINT64_MAX;
		}
	}

	if (mr_init_attr->comp_mask & IBV_REG_MR_MASK_IOVA) {
		fill_attr_in_uint64(cmdb, UVERBS_ATTR_REG_MR_IOVA, mr_init_attr->iova);
	} else {
		if (!fd_based) {
			fill_attr_in_uint64(cmdb, UVERBS_ATTR_REG_MR_IOVA,
					    (uintptr_t) mr_init_attr->addr);
		} else {
			/* iova is a must from kernel point of view */
			errno = EINVAL;
			return EINVAL;
		}
	}

	handle = fill_attr_out_obj(cmdb, UVERBS_ATTR_REG_MR_HANDLE);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_REG_MR_RESP_LKEY, &lkey);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_REG_MR_RESP_RKEY, &rkey);
	fill_attr_in_obj(cmdb, UVERBS_ATTR_REG_MR_PD_HANDLE, pd->handle);
	fill_attr_in_uint64(cmdb, UVERBS_ATTR_REG_MR_LENGTH, length);
	fill_attr_in_uint32(cmdb, UVERBS_ATTR_REG_MR_ACCESS_FLAGS,
			    mr_init_attr->access);

	if (mr_init_attr->comp_mask & IBV_REG_MR_MASK_DMAH)
		fill_attr_in_obj(cmdb, UVERBS_ATTR_REG_MR_DMA_HANDLE,
				 verbs_get_dmah(mr_init_attr->dmah)->handle);

	ret = execute_ioctl(pd->context, cmdb);
	if (ret)
		return errno;

	vmr->ibv_mr.handle = read_attr_obj(UVERBS_ATTR_REG_MR_HANDLE,
					   handle);
	vmr->ibv_mr.context = pd->context;
	vmr->ibv_mr.lkey = lkey;
	vmr->ibv_mr.rkey = rkey;
	if (fd_based)
		vmr->mr_type = IBV_MR_TYPE_DMABUF_MR;
	else
		vmr->mr_type = IBV_MR_TYPE_MR;

	return 0;
}
