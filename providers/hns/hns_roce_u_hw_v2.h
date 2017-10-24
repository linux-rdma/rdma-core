/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
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

#ifndef _HNS_ROCE_U_HW_V2_H
#define _HNS_ROCE_U_HW_V2_H

/* V2 REG DEFINITION */
#define ROCEE_VF_DB_CFG0_OFFSET			0x0230

struct hns_roce_db {
	unsigned int	byte_4;
	unsigned int	parameter;
};
#define DB_BYTE_4_TAG_S 0
#define DB_BYTE_4_TAG_M   (((1UL << 23) - 1) << DB_BYTE_4_TAG_S)

#define DB_BYTE_4_CMD_S 24
#define DB_BYTE_4_CMD_M   (((1UL << 4) - 1) << DB_BYTE_4_CMD_S)

#define DB_PARAM_SQ_PRODUCER_IDX_S 0
#define DB_PARAM_SQ_PRODUCER_IDX_M \
	(((1UL << 16) - 1) << DB_PARAM_SQ_PRODUCER_IDX_S)

#define DB_PARAM_RQ_PRODUCER_IDX_S 0
#define DB_PARAM_RQ_PRODUCER_IDX_M \
	(((1UL << 16) - 1) << DB_PARAM_RQ_PRODUCER_IDX_S)

#define DB_PARAM_SRQ_PRODUCER_COUNTER_S 0
#define DB_PARAM_SRQ_PRODUCER_COUNTER_M \
	(((1UL << 16) - 1) << DB_PARAM_SRQ_PRODUCER_COUNTER_S)

#define DB_PARAM_SL_S 16
#define DB_PARAM_SL_M \
	(((1UL << 3) - 1) << DB_PARAM_SL_S)

struct hns_roce_v2_cq_db {
	unsigned int	byte_4;
	unsigned int	parameter;
};

#define CQ_DB_BYTE_4_TAG_S 0
#define CQ_DB_BYTE_4_TAG_M   (((1UL << 23) - 1) << CQ_DB_BYTE_4_TAG_S)

#define CQ_DB_BYTE_4_CMD_S 24
#define CQ_DB_BYTE_4_CMD_M   (((1UL << 4) - 1) << CQ_DB_BYTE_4_CMD_S)

#define CQ_DB_PARAMETER_CQ_CONSUMER_IDX_S 0
#define CQ_DB_PARAMETER_CQ_CONSUMER_IDX_M \
	(((1UL << 24) - 1) << CQ_DB_PARAMETER_CQ_CONSUMER_IDX_S)

#define CQ_DB_PARAMETER_NOTIFY_S 24

#define CQ_DB_PARAMETER_CMD_SN_S 25
#define CQ_DB_PARAMETER_CMD_SN_M \
	(((1UL << 2) - 1) << CQ_DB_PARAMETER_CMD_SN_S)

struct hns_roce_v2_cqe {
	unsigned int	byte_4;
	unsigned int	rkey_immtdata;
	unsigned int	byte_12;
	unsigned int	byte_16;
	unsigned int	byte_cnt;
	unsigned int	smac;
	unsigned int	byte_28;
	unsigned int	byte_32;
};

#define CQE_BYTE_4_OPCODE_S 0
#define CQE_BYTE_4_OPCODE_M   (((1UL << 5) - 1) << CQE_BYTE_4_OPCODE_S)

#define CQE_BYTE_4_RQ_INLINE_S 5

#define CQE_BYTE_4_S_R_S 6
#define CQE_BYTE_4_OWNER_S 7

#define CQE_BYTE_4_STATUS_S 8
#define CQE_BYTE_4_STATUS_M   (((1UL << 8) - 1) << CQE_BYTE_4_STATUS_S)

#define CQE_BYTE_4_WQE_IDX_S 16
#define CQE_BYTE_4_WQE_IDX_M   (((1UL << 16) - 1) << CQE_BYTE_4_WQE_IDX_S)

#define CQE_BYTE_12_XRC_SRQN_S 0
#define CQE_BYTE_12_XRC_SRQN_M   (((1UL << 24) - 1) << CQE_BYTE_12_XRC_SRQN_S)

#define CQE_BYTE_16_LCL_QPN_S 0
#define CQE_BYTE_16_LCL_QPN_M   (((1UL << 24) - 1) << CQE_BYTE_16_LCL_QPN_S)

#define CQE_BYTE_28_SMAC_S 0
#define CQE_BYTE_28_SMAC_M   (((1UL << 16) - 1) << CQE_BYTE_28_SMAC_S)

#define CQE_BYTE_28_PORT_TYPE_S 16
#define CQE_BYTE_28_PORT_TYPE_M   (((1UL << 2) - 1) << CQE_BYTE_28_PORT_TYPE_S)

#define CQE_BYTE_32_RMT_QPN_S 0
#define CQE_BYTE_32_RMT_QPN_M   (((1UL << 24) - 1) << CQE_BYTE_32_RMT_QPN_S)

#define CQE_BYTE_32_SL_S 24
#define CQE_BYTE_32_SL_M   (((1UL << 3) - 1) << CQE_BYTE_32_SL_S)

#define CQE_BYTE_32_PORTN_S 27
#define CQE_BYTE_32_PORTN_M   (((1UL << 3) - 1) << CQE_BYTE_32_PORTN_S)

#define CQE_BYTE_32_GLH_S 30

#define CQE_BYTE_32_LPK_S 31

#endif /* _HNS_ROCE_U_HW_V2_H */
