/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Voltaire, Inc. All rights reserved.
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

#ifndef INFINIBAND_SA_H
#define INFINIBAND_SA_H

#include <infiniband/verbs.h>

struct ibv_sa_path_rec {
	/* reserved */
	/* reserved */
	union ibv_gid dgid;
	union ibv_gid sgid;
	uint16_t      dlid;
	uint16_t      slid;
	int           raw_traffic;
	/* reserved */
	uint32_t      flow_label;
	uint8_t       hop_limit;
	uint8_t       traffic_class;
	int           reversible;
	uint8_t       numb_path;
	uint16_t      pkey;
	/* reserved */
	uint8_t       sl;
	uint8_t       mtu_selector;
	uint8_t	      mtu;
	uint8_t       rate_selector;
	uint8_t       rate;
	uint8_t       packet_life_time_selector;
	uint8_t       packet_life_time;
	uint8_t       preference;
};

struct ibv_sa_mcmember_rec {
	union ibv_gid mgid;
	union ibv_gid port_gid;
	uint32_t      qkey;
	uint16_t      mlid;
	uint8_t       mtu_selector;
	uint8_t       mtu;
	uint8_t       traffic_class;
	uint16_t      pkey;
	uint8_t       rate_selector;
	uint8_t       rate;
	uint8_t       packet_life_time_selector;
	uint8_t       packet_life_time;
	uint8_t       sl;
	uint32_t      flow_label;
	uint8_t       hop_limit;
	uint8_t       scope;
	uint8_t       join_state;
	int           proxy_join;
};

struct ibv_sa_service_rec {
	uint64_t      id;
	union ibv_gid gid;
	uint16_t      pkey;
	/* uint16_t  resv;   */
	uint32_t      lease;
	uint8_t       key[16];
	uint8_t       name[64];
	uint8_t       data8[16];
	uint16_t      data16[8];
	uint32_t      data32[4];
	uint64_t      data64[2];
};

#endif /* INFINIBAND_SA_H */
