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

int ibv_cmd_destroy_ah(struct ibv_ah *ah)
{
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_AH,
			     UVERBS_METHOD_AH_DESTROY, 1, NULL);
	int ret;

	fill_attr_in_obj(cmdb, UVERBS_ATTR_DESTROY_AH_HANDLE, ah->handle);

	switch (execute_ioctl_fallback(ah->context, destroy_ah, cmdb, &ret)) {
	case TRY_WRITE: {
		struct ibv_destroy_ah req;

		req.core_payload = (struct ib_uverbs_destroy_ah){
			.ah_handle = ah->handle,
		};
		ret = execute_cmd_write_req(ah->context,
					    IB_USER_VERBS_CMD_DESTROY_AH, &req,
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
