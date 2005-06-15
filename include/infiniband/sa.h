/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
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
 * $Id$
 */

#ifndef IB_SA_H
#define IB_SA_H

#include <infiniband/verbs.h>

enum ib_sa_rate {
	IB_SA_RATE_2_5_GBPS = 2,
	IB_SA_RATE_5_GBPS   = 5,
	IB_SA_RATE_10_GBPS  = 3,
	IB_SA_RATE_20_GBPS  = 6,
	IB_SA_RATE_30_GBPS  = 4,
	IB_SA_RATE_40_GBPS  = 7,
	IB_SA_RATE_60_GBPS  = 8,
	IB_SA_RATE_80_GBPS  = 9,
	IB_SA_RATE_120_GBPS = 10
};

static inline int ib_sa_rate_enum_to_int(enum ib_sa_rate rate)
{
	switch (rate) {
	case IB_SA_RATE_2_5_GBPS: return  1;
	case IB_SA_RATE_5_GBPS:   return  2;
	case IB_SA_RATE_10_GBPS:  return  4;
	case IB_SA_RATE_20_GBPS:  return  8;
	case IB_SA_RATE_30_GBPS:  return 12;
	case IB_SA_RATE_40_GBPS:  return 16;
	case IB_SA_RATE_60_GBPS:  return 24;
	case IB_SA_RATE_80_GBPS:  return 32;
	case IB_SA_RATE_120_GBPS: return 48;
	default: 	          return -1;
	}
}

struct ib_sa_path_rec {
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
	enum ibv_mtu  mtu;
	uint8_t       rate_selector;
	uint8_t       rate;
	uint8_t       packet_life_time_selector;
	uint8_t       packet_life_time;
	uint8_t       preference;
};

#endif /* IB_SA_H */
