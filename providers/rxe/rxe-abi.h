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
 */

#ifndef RXE_ABI_H
#define RXE_ABI_H

#include <infiniband/kern-abi.h>
#include <rdma/rdma_user_rxe.h>
#include <kernel-abi/rdma_user_rxe.h>

DECLARE_DRV_CMD(urxe_create_cq, IB_USER_VERBS_CMD_CREATE_CQ,
		empty, rxe_create_cq_resp);
DECLARE_DRV_CMD(urxe_create_qp, IB_USER_VERBS_CMD_CREATE_QP,
		empty, rxe_create_qp_resp);
DECLARE_DRV_CMD(urxe_create_srq, IB_USER_VERBS_CMD_CREATE_SRQ,
		empty, rxe_create_srq_resp);
DECLARE_DRV_CMD(urxe_modify_srq, IB_USER_VERBS_CMD_MODIFY_SRQ,
		rxe_modify_srq_cmd, empty);
DECLARE_DRV_CMD(urxe_resize_cq, IB_USER_VERBS_CMD_RESIZE_CQ,
		empty, rxe_resize_cq_resp);

#endif /* RXE_ABI_H */
