/*
 * Copyright (c) 2006 QLogic, Inc. All rights reserved.
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
 *
 * Patent licenses, if any, provided herein do not apply to
 * combinations of this program with other software, or any other
 * product whatsoever.
 */

#ifndef IPATH_ABI_H
#define IPATH_ABI_H

#include <infiniband/kern-abi.h>

struct ipath_get_context_resp {
	struct ib_uverbs_get_context_resp	ibv_resp;
	__u32				version;
};

struct ipath_create_cq_resp {
	struct ib_uverbs_create_cq_resp	ibv_resp;
	__u64				offset;
};

struct ipath_resize_cq_resp {
	struct ib_uverbs_resize_cq_resp	ibv_resp;
	__u64				offset;
};

struct ipath_create_qp_resp {
	struct ib_uverbs_create_qp_resp	ibv_resp;
	__u64				offset;
};

struct ipath_create_srq_resp {
	struct ib_uverbs_create_srq_resp	ibv_resp;
	__u64				offset;
};

struct ipath_modify_srq_cmd {
	struct ibv_modify_srq		ibv_cmd;
	__u64				offset_addr;
};

#endif /* IPATH_ABI_H */
