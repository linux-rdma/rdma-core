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
#ifndef ZXDH_RDMA_PRIVATE_VERBS_CMD_H
#define ZXDH_RDMA_PRIVATE_VERBS_CMD_H

#include "zxdh_zrdma.h"
#include "zxdh_dv.h"

enum zxdh_rdma_tool_flags {
	ZXDH_QP_EXTEND_OP = 1 << 0,
	ZXDH_CAPTURE = 1 << 1,
	ZXDH_GET_HW_DATA = 1 << 2,
	ZXDH_GET_HW_OBJECT_DATA = 1 << 3,
	ZXDH_CHECK_HW_HEALTH = 1 << 4,
	ZXDH_RDMA_TOOL_CFG_DEV_PARAM = 1 << 5,
	ZXDH_RDMA_TOOL_SHOW_RES_MAP = 1 << 5,
};

struct zxdh_uvcontext_ops {
	int (*modify_qp_udp_sport)(struct ibv_context *ibctx,
				   uint16_t udp_sport, uint32_t qpn);
	int (*set_log_trace_switch)(struct ibv_context *ibctx,
				    uint8_t switch_status);
	int (*get_log_trace_switch)(struct ibv_context *ibctx,
				    uint8_t *switch_status);
	int (*query_qpc)(struct ibv_qp *qp, struct zxdh_rdma_qpc *qpc);
	int (*modify_qpc)(struct ibv_qp *qp, struct zxdh_rdma_qpc *qpc,
			  uint64_t qpc_mask);
	int (*reset_qp)(struct ibv_qp *qp, uint64_t opcode);
};

void add_private_ops(struct zxdh_uvcontext *iwvctx);

#endif
