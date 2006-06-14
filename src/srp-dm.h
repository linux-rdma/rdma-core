/*
 * srp-dm - discover SRP targets over IB
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006 Cisco Systems, Inc.  All rights reserved.
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

#ifndef SRP_DM_H
#define SRP_DM_H

#include <stdint.h>

enum {
	SRP_MGMT_CLASS_SM = 1,
	SRP_MGMT_CLASS_SA = 3,
	SRP_MGMT_CLASS_DM = 6
};

enum {
	SRP_ATTR_CLASS_PORT_INFO 	  = 0x01,

	SRP_SA_ATTR_NODE		  = 0x11,
	SRP_SA_ATTR_PORT_INFO		  = 0x12,

	SRP_DM_ATTR_NOTICE          	  = 0x02,
	SRP_DM_ATTR_IO_UNIT_INFO    	  = 0x10,
	SRP_DM_ATTR_IO_CONTROLLER_PROFILE = 0x11,
	SRP_DM_ATTR_SERVICE_ENTRIES       = 0x12
};

enum {
	SRP_DM_METHOD_GET	= 0x01,
	SRP_DM_METHOD_SET	= 0x02,
	SRP_SA_METHOD_GET_TABLE	= 0x12,
};

enum {
	SRP_DM_NO_IOC 	   = 0x0,
	SRP_DM_IOC_PRESENT = 0x1,
	SRP_DM_NO_SLOT 	   = 0xf
};

enum {
	SRP_REV10_IB_IO_CLASS	= 0xff00,
	SRP_REV16A_IB_IO_CLASS	= 0x0100
};

struct srp_dm_mad {
	uint8_t		base_version;
	uint8_t		mgmt_class;
	uint8_t		class_version;
	uint8_t		method;
	uint16_t	status;
	uint16_t	reserved1;
	uint64_t	tid;
	uint16_t	attr_id;
	uint16_t	reserved2;
	uint32_t	attr_mod;
	uint8_t		reserved3[40];
	uint8_t		data[192];
};

struct srp_dm_rmpp_sa_mad {
	uint8_t		base_version;
	uint8_t		mgmt_class;
	uint8_t		class_version;
	uint8_t		method;
	uint16_t	status;
	uint16_t	reserved1;
	uint64_t	tid;
	uint16_t	attr_id;
	uint16_t	reserved2;
	uint32_t	attr_mod;
	uint8_t		rmpp_version;
	uint8_t		rmpp_type;
	uint8_t		rmpp_rtime_flags;
	uint8_t		rmpp_status;
	uint32_t	seg_num;
	uint32_t	paylen_newwin;
	uint64_t	sm_key;
	uint16_t	attr_offset;
	uint16_t	reserved3;
	uint64_t	comp_mask;
	uint8_t		data[200];
} __attribute__((packed));

struct srp_sa_node_rec {
	uint16_t	lid;
	uint16_t	reserved;
	uint8_t		base_version;
	uint8_t		class_version;
	uint8_t		type;
	uint8_t		num_ports;
	uint64_t	sys_guid;
	uint64_t	node_guid;
	uint64_t	port_guid;
	uint16_t	partition_cap;
	uint16_t	device_id;
	uint32_t	revision;
	uint32_t	port_num_vendor_id;
	uint8_t		desc[64];
};

struct srp_sa_port_info_rec {
	uint16_t	endport_lid;
	uint8_t		port_num;
	uint8_t		reserved;
	uint64_t	m_key;
	uint64_t	subnet_prefix;
	uint16_t	base_lid;
	uint16_t	master_sm_base_lid;
	uint32_t	capability_mask;
	uint16_t	diag_code;
	uint16_t	m_key_lease_period;
	uint8_t		local_port_num;
	uint8_t		link_width_enabled;
	uint8_t		link_width_supported;
	uint8_t		link_width_active;
	uint8_t		state_info1;
	uint8_t		state_info2;
	uint8_t		mkey_lmc;
	uint8_t		link_speed;
	uint8_t		mtu_smsl;
	uint8_t		vl_cap;
	uint8_t		vl_high_limit;
	uint8_t		vl_arb_high_cap;
	uint8_t		vl_arb_low_cap;
	uint8_t		mtu_cap;
	uint8_t		vl_stall_life;
	uint8_t		vl_enforce;
	uint16_t	m_key_violations;
	uint16_t	p_key_violations;
	uint16_t	q_key_violations;
	uint8_t		guid_cap;
	uint8_t		subnet_timeout;
	uint8_t		resp_time_value;
	uint8_t		error_threshold;
} __attribute__((packed));

struct srp_sa_guid_info_rec {
	uint16_t	lid;
	uint8_t		block_num;
	uint8_t		reserverd[5];
	uint64_t	guid[8];
};

struct srp_dm_class_port_info {
	uint8_t		base_version;
	uint8_t		class_version;
	uint16_t	cap_mask;
	uint8_t		reserved1[3];
	uint8_t		resp_time;
	uint8_t		redir_gid[16];
	uint32_t	redir_tc_sl_fl;
	uint16_t	redir_lid;
	uint16_t	redir_pkey;
	uint32_t	redir_qpn;
	uint32_t	redir_qkey;
	uint8_t		trap_gid[16];
	uint32_t	trap_tc_sl_fl;
	uint16_t	trap_lid;
	uint16_t	trap_pkey;
	uint32_t	trap_hl_qpn;
	uint32_t	trap_qkey;
};

struct srp_dm_iou_info {
	uint16_t	change_id;
	uint8_t		max_controllers;
	uint8_t		diagid_optionrom;
	uint8_t		controller_list[128];
};

struct srp_dm_ioc_prof {
	uint64_t	guid;
	uint32_t	vendor_id;
	uint32_t	device_id;
	uint16_t	device_version;
	uint16_t	reserved1;
	uint32_t	subsys_vendor_id;
	uint32_t	subsys_device_id;
	uint16_t	io_class;
	uint16_t	io_subclass;
	uint16_t	protocol;
	uint16_t	protocol_version;
	uint32_t	reserved2;
	uint16_t	send_queue_depth;
	uint8_t		reserved3;
	uint8_t		rdma_read_depth;
	uint32_t	send_size;
	uint32_t	rdma_size;
	uint8_t		cap_mask;
	uint8_t		reserved4;
	uint8_t		service_entries;
	uint8_t		reserved5[9];
	char		id[64];
};

struct srp_dm_svc_entries {
	struct {
		char		name[40];
		uint64_t	id;
	}		service[4];
};

#endif /* SRP_DM_H */
