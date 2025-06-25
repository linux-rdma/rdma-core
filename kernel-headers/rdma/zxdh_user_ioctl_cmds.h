/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * Copyright (c) 2024 ZTE Corporation.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef ZXDH_USER_IOCTL_CMDS_H
#define ZXDH_USER_IOCTL_CMDS_H

#include <linux/types.h>
#include <rdma/ib_user_ioctl_cmds.h>

enum zxdh_ib_dev_get_log_trace_attrs {
	ZXDH_IB_ATTR_DEV_GET_LOG_TARCE_SWITCH = (1U << UVERBS_ID_NS_SHIFT),
};

enum zxdh_ib_dev_set_log_trace_attrs {
	ZXDH_IB_ATTR_DEV_SET_LOG_TARCE_SWITCH = (1U << UVERBS_ID_NS_SHIFT),
};

enum zxdh_ib_dev_methods {
	ZXDH_IB_METHOD_DEV_GET_LOG_TRACE = (1U << UVERBS_ID_NS_SHIFT),
	ZXDH_IB_METHOD_DEV_SET_LOG_TRACE,
};

enum zxdh_ib_qp_modify_udp_sport_attrs {
	ZXDH_IB_ATTR_QP_UDP_PORT = (1U << UVERBS_ID_NS_SHIFT),
	ZXDH_IB_ATTR_QP_QPN,
};

enum zxdh_ib_qp_query_qpc_attrs {
	ZXDH_IB_ATTR_QP_QUERY_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	ZXDH_IB_ATTR_QP_QUERY_RESP,
};

enum zxdh_ib_qp_modify_qpc_attrs {
	ZXDH_IB_ATTR_QP_MODIFY_QPC_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	ZXDH_IB_ATTR_QP_MODIFY_QPC_REQ,
	ZXDH_IB_ATTR_QP_MODIFY_QPC_MASK,
};

enum zxdh_ib_qp_reset_qp_attrs {
	ZXDH_IB_ATTR_QP_RESET_QP_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	ZXDH_IB_ATTR_QP_RESET_OP_CODE,
};

enum zxdh_ib_qp_methods {
	ZXDH_IB_METHOD_QP_MODIFY_UDP_SPORT = (1U << UVERBS_ID_NS_SHIFT),
	ZXDH_IB_METHOD_QP_QUERY_QPC,
	ZXDH_IB_METHOD_QP_MODIFY_QPC,
	ZXDH_IB_METHOD_QP_RESET_QP,
};

enum zxdh_ib_objects {
	ZXDH_IB_OBJECT_DEV = (1U << UVERBS_ID_NS_SHIFT),
	ZXDH_IB_OBJECT_QP_OBJ,
	ZXDH_IB_OBJECT_DEVICE_EX,
};

#endif
