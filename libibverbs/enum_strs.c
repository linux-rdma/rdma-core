/*
 * Copyright (c) 2008 Lawrence Livermore National Laboratory
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

#include <infiniband/verbs.h>

const char *ibv_node_type_str(enum ibv_node_type node_type)
{
	static const char *const node_type_str[] = {
		[IBV_NODE_CA]		= "InfiniBand channel adapter",
		[IBV_NODE_SWITCH]	= "InfiniBand switch",
		[IBV_NODE_ROUTER]	= "InfiniBand router",
		[IBV_NODE_RNIC]		= "iWARP NIC",
		[IBV_NODE_USNIC]	= "usNIC",
		[IBV_NODE_USNIC_UDP]	= "usNIC UDP",
		[IBV_NODE_UNSPECIFIED]	= "unspecified",
	};

	if (node_type < IBV_NODE_CA || node_type > IBV_NODE_UNSPECIFIED)
		return "unknown";

	return node_type_str[node_type];
}

const char *ibv_port_state_str(enum ibv_port_state port_state)
{
	static const char *const port_state_str[] = {
		[IBV_PORT_NOP]		= "no state change (NOP)",
		[IBV_PORT_DOWN]		= "down",
		[IBV_PORT_INIT]		= "init",
		[IBV_PORT_ARMED]	= "armed",
		[IBV_PORT_ACTIVE]	= "active",
		[IBV_PORT_ACTIVE_DEFER]	= "active defer"
	};

	if (port_state < IBV_PORT_NOP || port_state > IBV_PORT_ACTIVE_DEFER)
		return "unknown";

	return port_state_str[port_state];
}

const char *ibv_event_type_str(enum ibv_event_type event)
{
	static const char *const event_type_str[] = {
		[IBV_EVENT_CQ_ERR]		= "CQ error",
		[IBV_EVENT_QP_FATAL]		= "local work queue catastrophic error",
		[IBV_EVENT_QP_REQ_ERR]		= "invalid request local work queue error",
		[IBV_EVENT_QP_ACCESS_ERR]	= "local access violation work queue error",
		[IBV_EVENT_COMM_EST]		= "communication established",
		[IBV_EVENT_SQ_DRAINED]		= "send queue drained",
		[IBV_EVENT_PATH_MIG]		= "path migrated",
		[IBV_EVENT_PATH_MIG_ERR]	= "path migration request error",
		[IBV_EVENT_DEVICE_FATAL]	= "local catastrophic error",
		[IBV_EVENT_PORT_ACTIVE]		= "port active",
		[IBV_EVENT_PORT_ERR]		= "port error",
		[IBV_EVENT_LID_CHANGE]		= "LID change",
		[IBV_EVENT_PKEY_CHANGE]		= "P_Key change",
		[IBV_EVENT_SM_CHANGE]		= "SM change",
		[IBV_EVENT_SRQ_ERR]		= "SRQ catastrophic error",
		[IBV_EVENT_SRQ_LIMIT_REACHED]	= "SRQ limit reached",
		[IBV_EVENT_QP_LAST_WQE_REACHED]	= "last WQE reached",
		[IBV_EVENT_CLIENT_REREGISTER]	= "client reregistration",
		[IBV_EVENT_GID_CHANGE]		= "GID table change",
		[IBV_EVENT_WQ_FATAL]		= "WQ fatal"
	};

	if (event < IBV_EVENT_CQ_ERR || event > IBV_EVENT_WQ_FATAL)
		return "unknown";

	return event_type_str[event];
}

const char *ibv_wc_status_str(enum ibv_wc_status status)
{
	static const char *const wc_status_str[] = {
		[IBV_WC_SUCCESS]		= "success",
		[IBV_WC_LOC_LEN_ERR]		= "local length error",
		[IBV_WC_LOC_QP_OP_ERR]		= "local QP operation error",
		[IBV_WC_LOC_EEC_OP_ERR]		= "local EE context operation error",
		[IBV_WC_LOC_PROT_ERR]		= "local protection error",
		[IBV_WC_WR_FLUSH_ERR]		= "Work Request Flushed Error",
		[IBV_WC_MW_BIND_ERR]		= "memory management operation error",
		[IBV_WC_BAD_RESP_ERR]		= "bad response error",
		[IBV_WC_LOC_ACCESS_ERR]		= "local access error",
		[IBV_WC_REM_INV_REQ_ERR]	= "remote invalid request error",
		[IBV_WC_REM_ACCESS_ERR]		= "remote access error",
		[IBV_WC_REM_OP_ERR]		= "remote operation error",
		[IBV_WC_RETRY_EXC_ERR]		= "transport retry counter exceeded",
		[IBV_WC_RNR_RETRY_EXC_ERR]	= "RNR retry counter exceeded",
		[IBV_WC_LOC_RDD_VIOL_ERR]	= "local RDD violation error",
		[IBV_WC_REM_INV_RD_REQ_ERR]	= "remote invalid RD request",
		[IBV_WC_REM_ABORT_ERR]		= "aborted error",
		[IBV_WC_INV_EECN_ERR]		= "invalid EE context number",
		[IBV_WC_INV_EEC_STATE_ERR]	= "invalid EE context state",
		[IBV_WC_FATAL_ERR]		= "fatal error",
		[IBV_WC_RESP_TIMEOUT_ERR]	= "response timeout error",
		[IBV_WC_GENERAL_ERR]		= "general error",
		[IBV_WC_TM_ERR]			= "TM error",
		[IBV_WC_TM_RNDV_INCOMPLETE]     = "TM software rendezvous",
	};

	if (status < IBV_WC_SUCCESS || status > IBV_WC_TM_RNDV_INCOMPLETE)
		return "unknown";

	return wc_status_str[status];
}

const char *ibv_wr_opcode_str(enum ibv_wr_opcode opcode)
{
	static const char *const wr_opcode_str[] = {
		[IBV_WR_RDMA_WRITE]		= "rdma-write",
		[IBV_WR_RDMA_WRITE_WITH_IMM]	= "rdma-write-with-imm",
		[IBV_WR_SEND]			= "send",
		[IBV_WR_SEND_WITH_IMM]		= "send-with-imm",
		[IBV_WR_RDMA_READ]		= "rdma-read",
		[IBV_WR_ATOMIC_CMP_AND_SWP]	= "atomic-cmp-and-swp",
		[IBV_WR_ATOMIC_FETCH_AND_ADD]	= "atomic-fetch-and-add",
		[IBV_WR_LOCAL_INV]		= "local-inv",
		[IBV_WR_BIND_MW]		= "bind-mw",
		[IBV_WR_SEND_WITH_INV]		= "send-with-inv",
		[IBV_WR_TSO]			= "tso",
		[IBV_WR_DRIVER1]		= "driver1",
		[IBV_WR_FLUSH]			= "flush",
		[IBV_WR_ATOMIC_WRITE]		= "atomic-write"
	};

	if (opcode < IBV_WR_RDMA_WRITE || opcode > IBV_WR_ATOMIC_WRITE)
		return "unknown";

	return wr_opcode_str[opcode];
}
