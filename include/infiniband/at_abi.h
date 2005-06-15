/*
 * Copyright (c) 2005 Voltaire, Inc.  All rights reserved.
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
 * $Id:$
 */

#ifndef AT_ABI_H
#define AT_ABI_H

#include <linux/types.h>
/*
 * This file must be kept in sync with the kernel's version of
 * drivers/infiniband/include/ib_user_at.h
 */

#define IB_USER_AT_ABI_VERSION 1

enum {
	IB_USER_AT_CMD_ROUTE_BY_IP,
	IB_USER_AT_CMD_PATHS_BY_ROUTE,
	IB_USER_AT_CMD_IPS_BY_GID,
	IB_USER_AT_CMD_IPS_BY_SUBNET,
	IB_USER_AT_CMD_INVALIDATE_PATHS,
	IB_USER_AT_CMD_CANCEL,
	IB_USER_AT_CMD_STATUS,

	IB_USER_AT_CMD_EVENT,
};

/*
 * command ABI structures.
 */
struct at_abi_cmd_hdr {
	__u32 cmd;
	__u16 in;
	__u16 out;
};

struct at_abi_completion {
	void (*fn)(__u64 req_id, void *context, int rec_num);
	void *context;
	__u64 req_id;
};

struct at_abi_path_attr {
	__u16 qos_tag;
	__u16 pkey;
	__u8  multi_path_type;
};

struct at_abi_path_rec {
	__u8  dgid[16];
	__u8  sgid[16];
	__u16 dlid;
	__u16 slid;
	__u32 raw_traffic;
	__u32 flow_label;
	__u32 reversible;
	__u32 mtu;
	__u16 pkey;
	__u8  hop_limit;
	__u8  traffic_class;
	__u8  numb_path;
	__u8  sl;
	__u8  mtu_selector;
	__u8  rate_selector;
	__u8  rate;
	__u8  packet_life_time_selector;
	__u8  packet_life_time;
	__u8  preference;
};

struct at_abi_ib_route {
	union ibv_gid sgid;
	union ibv_gid dgid;
	struct ibv_device *out_dev;
	int out_port;
	struct at_abi_path_attr attr;
};

struct at_abi_route_by_ip {
	__u32 dst_ip;
	__u32 src_ip;
	int   tos;
	__u16 flags;
	struct at_abi_ib_route *ib_route;
	struct at_abi_completion *async_comp;
};

struct at_abi_paths_by_route {
	struct at_abi_ib_route *ib_route;
	__u32 mpath_type;
	struct at_abi_path_rec *path_arr;
	int npath;
	struct at_abi_completion *async_comp;
	__u64 response;
};

struct at_abi_paths_by_route_resp {
	__u64 req_id;	
};

struct at_abi_ips_by_gid {
	union ibv_gid *gid;
	__u32 *dst_ips;
	int nips;
	struct at_abi_completion *async_comp;
};

struct at_abi_ips_by_subnet {
	__u32 network;
	__u32 netmask;
	__u32 *dst_ips;
	int nips;
};

struct at_abi_invalidate_paths {
	struct at_abi_ib_route *ib_route;
};

struct at_abi_cancel {
	__u64 req_id;
};

struct at_abi_status {
	__u64 req_id;
};

/*
 * event notification ABI structures.
 */
struct at_abi_event_get {
	__u64 response;
};

struct at_abi_event_resp {
	__u64 callback;
	__u64 context;
	__u64 req_id;
	int   rec_num;
};

#endif /* AT_ABI_H */
