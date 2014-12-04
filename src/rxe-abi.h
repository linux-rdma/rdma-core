/*
 * Copyright (c) 2009 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2009 System Fabric Works, Inc. All rights reserved.
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

#ifndef RXE_ABI_H
#define RXE_ABI_H

#include <infiniband/kern-abi.h>

#define RXE_USER_SEND_QUEUE		(1)

struct mmap_info {
	__u64 offset;
	__u32 size;
	__u32 pad;
};

struct rxe_get_context_resp {
	struct ibv_get_context_resp ibv_resp;
	__u32 version;
};

struct rxe_create_cq_resp {
	struct ibv_create_cq_resp ibv_resp;
	struct mmap_info mi;
};

struct rxe_resize_cq_resp {
	struct ibv_resize_cq_resp ibv_resp;
	struct mmap_info mi;
};

struct rxe_create_qp_resp {
	struct ibv_create_qp_resp ibv_resp;
	struct mmap_info rq_mi;
#ifdef RXE_USER_SEND_QUEUE
	struct mmap_info sq_mi;
#endif
};

struct rxe_create_srq_resp {
	struct ibv_create_srq_resp ibv_resp;
	struct mmap_info mi;
	__u32 srq_num;
};

struct rxe_modify_srq_cmd {
	struct ibv_modify_srq ibv_cmd;
	__u64 mmap_info_addr;
};

#if 0
struct rxe_create_xrc_srq {
        struct ibv_create_xrc_srq ibv_cmd;
};

struct rxe_open_xrc_domain_resp {
        struct ibv_open_xrc_domain_resp ibv_resp;
};
#endif

#endif /* RXE_ABI_H */
