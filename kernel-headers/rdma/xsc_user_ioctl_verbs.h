/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_USER_IOCTL_VERBS_H
#define XSC_USER_IOCTL_VERBS_H

#include <linux/types.h>

enum xsc_ib_uapi_flow_action_flags {
	XSC_IB_UAPI_FLOW_ACTION_FLAGS_REQUIRE_METADATA	= 1 << 0,
};

enum xsc_ib_uapi_flow_table_type {
	XSC_IB_UAPI_FLOW_TABLE_TYPE_NIC_RX     = 0x0,
	XSC_IB_UAPI_FLOW_TABLE_TYPE_NIC_TX	= 0x1,
};

enum xsc_ib_uapi_flow_action_packet_reformat_type {
	XSC_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TUNNEL_TO_L2 = 0x0,
	XSC_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L2_TUNNEL = 0x1,
	XSC_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L3_TUNNEL_TO_L2 = 0x2,
	XSC_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L3_TUNNEL = 0x3,
};

#endif

