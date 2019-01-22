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
