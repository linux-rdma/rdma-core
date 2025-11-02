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
#ifndef _ZXDH_DV_H_
#define _ZXDH_DV_H_

#include <stdio.h>
#include <stdbool.h>
#include <linux/types.h> /* For the __be64 type */
#include <sys/types.h>
#include <endian.h>
#if defined(__SSE3__)
#include <limits.h>
#include <emmintrin.h>
#include <tmmintrin.h>
#endif /* defined(__SSE3__) */

#include <infiniband/verbs.h>
#include <infiniband/tm_types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum switch_status {
	SWITCH_CLOSE = 0,
	SWITCH_OPEN = 1,
	SWITCH_ERROR,
};

enum zxdh_qp_reset_qp_code {
	ZXDH_RESET_RETRY_TX_ITEM_FLAG = 1,
};

enum zxdh_qp_modify_qpc_mask {
	ZXDH_RETRY_CQE_SQ_OPCODE = 1 << 0,
	ZXDH_ERR_FLAG_SET = 1 << 1,
	ZXDH_PACKAGE_ERR_FLAG = 1 << 2,
	ZXDH_TX_LAST_ACK_PSN = 1 << 3,
	ZXDH_TX_LAST_ACK_WQE_OFFSET_SET = 1 << 4,
	ZXDH_TX_READ_RETRY_FLAG_SET = 1 << 5,
	ZXDH_TX_RDWQE_PYLD_LENGTH = 1 << 6,
	ZXDH_TX_RECV_READ_FLAG_SET = 1 << 7,
	ZXDH_TX_RD_MSG_LOSS_ERR_FLAG_SET = 1 << 8,
};

struct zxdh_rdma_qpc {
	uint8_t retry_flag;
	uint8_t rnr_retry_flag;
	uint8_t read_retry_flag;
	uint8_t cur_retry_count;
	uint8_t retry_cqe_sq_opcode;
	uint8_t err_flag;
	uint8_t ack_err_flag;
	uint8_t package_err_flag;
	uint8_t recv_err_flag;
	uint32_t tx_last_ack_psn;
	uint8_t retry_count;
};

int zxdh_get_log_trace_switch(struct ibv_context *context,
			      enum switch_status *status);
int zxdh_set_log_trace_switch(struct ibv_context *context,
			      enum switch_status status);
int zxdh_modify_qp_udp_sport(struct ibv_context *context, uint16_t udp_sport,
			     uint32_t qpn);
int zxdh_query_qpc(struct ibv_qp *qp, struct zxdh_rdma_qpc *qpc);
int zxdh_modify_qpc(struct ibv_qp *qp, struct zxdh_rdma_qpc *qpc,
		    uint64_t qpc_mask);
int zxdh_reset_qp(struct ibv_qp *qp, uint64_t opcode);
#ifdef __cplusplus
}
#endif

#endif
