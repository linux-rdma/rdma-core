/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_API_H
#define XSC_API_H

#include <infiniband/xsc_user_ioctl_verbs.h>

#define xscdv_flow_action_flags			xsc_ib_uapi_flow_action_flags
#define XSCDV_FLOW_ACTION_FLAGS_REQUIRE_METADATA \
	XSC_IB_UAPI_FLOW_ACTION_FLAGS_REQUIRE_METADATA
#define xscdv_flow_table_type				xsc_ib_uapi_flow_table_type
#define XSCDV_FLOW_TABLE_TYPE_NIC_RX			XSC_IB_UAPI_FLOW_TABLE_TYPE_NIC_RX
#define XSCDV_FLOW_TABLE_TYPE_NIC_TX			XSC_IB_UAPI_FLOW_TABLE_TYPE_NIC_TX
#define xscdv_flow_action_packet_reformat_type		xsc_ib_uapi_flow_action_packet_reformat_type
#define XSCDV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TUNNEL_TO_L2 \
	XSC_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TUNNEL_TO_L2
#define XSCDV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L2_TUNNEL \
	XSC_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L2_TUNNEL
#define XSCDV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L3_TUNNEL_TO_L2 \
	XSC_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L3_TUNNEL_TO_L2
#define XSCDV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L3_TUNNEL \
	XSC_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L3_TUNNEL

enum xsc_qp_create_flags {
	XSC_QP_CREATE_RAWPACKET_TSO	= 1 << 0,
	XSC_QP_CREATE_RAWPACKET_SNIFFER	= 1 << 2,
	XSC_QP_CREATE_RAWPACKET_TX	= 1 << 3,
	XSC_QP_CREATE_WORC		= 1 << 4,
};

#endif
