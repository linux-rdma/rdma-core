/*
 * Copyright (c) 2004-2009 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2007 Xsigo Systems Inc.  All rights reserved.
 * Copyright (c) 2009 HNR Consulting.  All rights reserved.
 * Copyright (c) 2011 Mellanox Technologies LTD.  All rights reserved.
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>

#include "ibdiag_common.h"

static struct ibmad_port *srcport;

struct perf_count {
	uint32_t portselect;
	uint32_t counterselect;
	uint32_t symbolerrors;
	uint32_t linkrecovers;
	uint32_t linkdowned;
	uint32_t rcverrors;
	uint32_t rcvremotephyerrors;
	uint32_t rcvswrelayerrors;
	uint32_t xmtdiscards;
	uint32_t xmtconstrainterrors;
	uint32_t rcvconstrainterrors;
	uint32_t linkintegrityerrors;
	uint32_t excbufoverrunerrors;
	uint32_t qp1dropped;
	uint32_t vl15dropped;
	uint32_t xmtdata;
	uint32_t rcvdata;
	uint32_t xmtpkts;
	uint32_t rcvpkts;
	uint32_t xmtwait;
};

struct perf_count_ext {
	uint32_t portselect;
	uint32_t counterselect;
	uint64_t portxmitdata;
	uint64_t portrcvdata;
	uint64_t portxmitpkts;
	uint64_t portrcvpkts;
	uint64_t portunicastxmitpkts;
	uint64_t portunicastrcvpkts;
	uint64_t portmulticastxmitpkits;
	uint64_t portmulticastrcvpkts;

	uint32_t counterSelect2;
	uint64_t symbolErrorCounter;
	uint64_t linkErrorRecoveryCounter;
	uint64_t linkDownedCounter;
	uint64_t portRcvErrors;
	uint64_t portRcvRemotePhysicalErrors;
	uint64_t portRcvSwitchRelayErrors;
	uint64_t portXmitDiscards;
	uint64_t portXmitConstraintErrors;
	uint64_t portRcvConstraintErrors;
	uint64_t localLinkIntegrityErrors;
	uint64_t excessiveBufferOverrunErrors;
	uint64_t VL15Dropped;
	uint64_t portXmitWait;
	uint64_t QP1Dropped;
};

static uint8_t pc[1024];

static struct perf_count perf_count = {};
static struct perf_count_ext perf_count_ext = {};

#define ALL_PORTS 0xFF
#define MAX_PORTS 255

/* Notes: IB semantics is to cap counters if count has exceeded limits.
 * Therefore we must check for overflows and cap the counters if necessary.
 *
 * mad_decode_field and mad_encode_field assume 32 bit integers passed in
 * for fields < 32 bits in length.
 */

static void aggregate_4bit(uint32_t * dest, uint32_t val)
{
	if ((((*dest) + val) < (*dest)) || ((*dest) + val) > 0xf)
		(*dest) = 0xf;
	else
		(*dest) = (*dest) + val;
}

static void aggregate_8bit(uint32_t * dest, uint32_t val)
{
	if ((((*dest) + val) < (*dest))
	    || ((*dest) + val) > 0xff)
		(*dest) = 0xff;
	else
		(*dest) = (*dest) + val;
}

static void aggregate_16bit(uint32_t * dest, uint32_t val)
{
	if ((((*dest) + val) < (*dest))
	    || ((*dest) + val) > 0xffff)
		(*dest) = 0xffff;
	else
		(*dest) = (*dest) + val;
}

static void aggregate_32bit(uint32_t * dest, uint32_t val)
{
	if (((*dest) + val) < (*dest))
		(*dest) = 0xffffffff;
	else
		(*dest) = (*dest) + val;
}

static void aggregate_64bit(uint64_t * dest, uint64_t val)
{
	if (((*dest) + val) < (*dest))
		(*dest) = 0xffffffffffffffffULL;
	else
		(*dest) = (*dest) + val;
}

static void aggregate_perfcounters(void)
{
	uint32_t val;

	mad_decode_field(pc, IB_PC_PORT_SELECT_F, &val);
	perf_count.portselect = val;
	mad_decode_field(pc, IB_PC_COUNTER_SELECT_F, &val);
	perf_count.counterselect = val;
	mad_decode_field(pc, IB_PC_ERR_SYM_F, &val);
	aggregate_16bit(&perf_count.symbolerrors, val);
	mad_decode_field(pc, IB_PC_LINK_RECOVERS_F, &val);
	aggregate_8bit(&perf_count.linkrecovers, val);
	mad_decode_field(pc, IB_PC_LINK_DOWNED_F, &val);
	aggregate_8bit(&perf_count.linkdowned, val);
	mad_decode_field(pc, IB_PC_ERR_RCV_F, &val);
	aggregate_16bit(&perf_count.rcverrors, val);
	mad_decode_field(pc, IB_PC_ERR_PHYSRCV_F, &val);
	aggregate_16bit(&perf_count.rcvremotephyerrors, val);
	mad_decode_field(pc, IB_PC_ERR_SWITCH_REL_F, &val);
	aggregate_16bit(&perf_count.rcvswrelayerrors, val);
	mad_decode_field(pc, IB_PC_XMT_DISCARDS_F, &val);
	aggregate_16bit(&perf_count.xmtdiscards, val);
	mad_decode_field(pc, IB_PC_ERR_XMTCONSTR_F, &val);
	aggregate_8bit(&perf_count.xmtconstrainterrors, val);
	mad_decode_field(pc, IB_PC_ERR_RCVCONSTR_F, &val);
	aggregate_8bit(&perf_count.rcvconstrainterrors, val);
	mad_decode_field(pc, IB_PC_ERR_LOCALINTEG_F, &val);
	aggregate_4bit(&perf_count.linkintegrityerrors, val);
	mad_decode_field(pc, IB_PC_ERR_EXCESS_OVR_F, &val);
	aggregate_4bit(&perf_count.excbufoverrunerrors, val);
	mad_decode_field(pc, IB_PC_QP1_DROP_F, &val);
	aggregate_16bit(&perf_count.qp1dropped, val);
	mad_decode_field(pc, IB_PC_VL15_DROPPED_F, &val);
	aggregate_16bit(&perf_count.vl15dropped, val);
	mad_decode_field(pc, IB_PC_XMT_BYTES_F, &val);
	aggregate_32bit(&perf_count.xmtdata, val);
	mad_decode_field(pc, IB_PC_RCV_BYTES_F, &val);
	aggregate_32bit(&perf_count.rcvdata, val);
	mad_decode_field(pc, IB_PC_XMT_PKTS_F, &val);
	aggregate_32bit(&perf_count.xmtpkts, val);
	mad_decode_field(pc, IB_PC_RCV_PKTS_F, &val);
	aggregate_32bit(&perf_count.rcvpkts, val);
	mad_decode_field(pc, IB_PC_XMT_WAIT_F, &val);
	aggregate_32bit(&perf_count.xmtwait, val);
}

static void output_aggregate_perfcounters(ib_portid_t * portid,
					  __be16 cap_mask)
{
	char buf[1024];
	uint32_t val = ALL_PORTS;

	/* set port_select to 255 to emulate AllPortSelect */
	mad_encode_field(pc, IB_PC_PORT_SELECT_F, &val);
	mad_encode_field(pc, IB_PC_COUNTER_SELECT_F, &perf_count.counterselect);
	mad_encode_field(pc, IB_PC_ERR_SYM_F, &perf_count.symbolerrors);
	mad_encode_field(pc, IB_PC_LINK_RECOVERS_F, &perf_count.linkrecovers);
	mad_encode_field(pc, IB_PC_LINK_DOWNED_F, &perf_count.linkdowned);
	mad_encode_field(pc, IB_PC_ERR_RCV_F, &perf_count.rcverrors);
	mad_encode_field(pc, IB_PC_ERR_PHYSRCV_F,
			 &perf_count.rcvremotephyerrors);
	mad_encode_field(pc, IB_PC_ERR_SWITCH_REL_F,
			 &perf_count.rcvswrelayerrors);
	mad_encode_field(pc, IB_PC_XMT_DISCARDS_F, &perf_count.xmtdiscards);
	mad_encode_field(pc, IB_PC_ERR_XMTCONSTR_F,
			 &perf_count.xmtconstrainterrors);
	mad_encode_field(pc, IB_PC_ERR_RCVCONSTR_F,
			 &perf_count.rcvconstrainterrors);
	mad_encode_field(pc, IB_PC_ERR_LOCALINTEG_F,
			 &perf_count.linkintegrityerrors);
	mad_encode_field(pc, IB_PC_ERR_EXCESS_OVR_F,
			 &perf_count.excbufoverrunerrors);
	mad_encode_field(pc, IB_PC_QP1_DROP_F, &perf_count.qp1dropped);
	mad_encode_field(pc, IB_PC_VL15_DROPPED_F, &perf_count.vl15dropped);
	mad_encode_field(pc, IB_PC_XMT_BYTES_F, &perf_count.xmtdata);
	mad_encode_field(pc, IB_PC_RCV_BYTES_F, &perf_count.rcvdata);
	mad_encode_field(pc, IB_PC_XMT_PKTS_F, &perf_count.xmtpkts);
	mad_encode_field(pc, IB_PC_RCV_PKTS_F, &perf_count.rcvpkts);
	mad_encode_field(pc, IB_PC_XMT_WAIT_F, &perf_count.xmtwait);

	mad_dump_perfcounters(buf, sizeof buf, pc, sizeof pc);

	printf("# Port counters: %s port %d (CapMask: 0x%02X)\n%s",
	       portid2str(portid), ALL_PORTS, ntohs(cap_mask), buf);
}

static void aggregate_perfcounters_ext(__be16 cap_mask, uint32_t cap_mask2)
{
	uint32_t val;
	uint64_t val64;

	mad_decode_field(pc, IB_PC_EXT_PORT_SELECT_F, &val);
	perf_count_ext.portselect = val;
	mad_decode_field(pc, IB_PC_EXT_COUNTER_SELECT_F, &val);
	perf_count_ext.counterselect = val;
	mad_decode_field(pc, IB_PC_EXT_XMT_BYTES_F, &val64);
	aggregate_64bit(&perf_count_ext.portxmitdata, val64);
	mad_decode_field(pc, IB_PC_EXT_RCV_BYTES_F, &val64);
	aggregate_64bit(&perf_count_ext.portrcvdata, val64);
	mad_decode_field(pc, IB_PC_EXT_XMT_PKTS_F, &val64);
	aggregate_64bit(&perf_count_ext.portxmitpkts, val64);
	mad_decode_field(pc, IB_PC_EXT_RCV_PKTS_F, &val64);
	aggregate_64bit(&perf_count_ext.portrcvpkts, val64);

	if (cap_mask & IB_PM_EXT_WIDTH_SUPPORTED) {
		mad_decode_field(pc, IB_PC_EXT_XMT_UPKTS_F, &val64);
		aggregate_64bit(&perf_count_ext.portunicastxmitpkts, val64);
		mad_decode_field(pc, IB_PC_EXT_RCV_UPKTS_F, &val64);
		aggregate_64bit(&perf_count_ext.portunicastrcvpkts, val64);
		mad_decode_field(pc, IB_PC_EXT_XMT_MPKTS_F, &val64);
		aggregate_64bit(&perf_count_ext.portmulticastxmitpkits, val64);
		mad_decode_field(pc, IB_PC_EXT_RCV_MPKTS_F, &val64);
		aggregate_64bit(&perf_count_ext.portmulticastrcvpkts, val64);
	}

	if (htonl(cap_mask2) & IB_PM_IS_ADDL_PORT_CTRS_EXT_SUP) {
		mad_decode_field(pc, IB_PC_EXT_COUNTER_SELECT2_F, &val);
		perf_count_ext.counterSelect2 = val;
		mad_decode_field(pc, IB_PC_EXT_ERR_SYM_F, &val64);
		aggregate_64bit(&perf_count_ext.symbolErrorCounter, val64);
		mad_decode_field(pc, IB_PC_EXT_LINK_RECOVERS_F, &val64);
		aggregate_64bit(&perf_count_ext.linkErrorRecoveryCounter, val64);
		mad_decode_field(pc, IB_PC_EXT_LINK_DOWNED_F, &val64);
		aggregate_64bit(&perf_count_ext.linkDownedCounter, val64);
		mad_decode_field(pc, IB_PC_EXT_ERR_RCV_F, &val64);
		aggregate_64bit(&perf_count_ext.portRcvErrors, val64);
		mad_decode_field(pc, IB_PC_EXT_ERR_PHYSRCV_F, &val64);
		aggregate_64bit(&perf_count_ext.portRcvRemotePhysicalErrors, val64);
		mad_decode_field(pc, IB_PC_EXT_ERR_SWITCH_REL_F, &val64);
		aggregate_64bit(&perf_count_ext.portRcvSwitchRelayErrors, val64);
		mad_decode_field(pc, IB_PC_EXT_XMT_DISCARDS_F, &val64);
		aggregate_64bit(&perf_count_ext.portXmitDiscards, val64);
		mad_decode_field(pc, IB_PC_EXT_ERR_XMTCONSTR_F, &val64);
		aggregate_64bit(&perf_count_ext.portXmitConstraintErrors, val64);
		mad_decode_field(pc, IB_PC_EXT_ERR_RCVCONSTR_F, &val64);
		aggregate_64bit(&perf_count_ext.portRcvConstraintErrors, val64);
		mad_decode_field(pc, IB_PC_EXT_ERR_LOCALINTEG_F, &val64);
		aggregate_64bit(&perf_count_ext.localLinkIntegrityErrors, val64);
		mad_decode_field(pc, IB_PC_EXT_ERR_EXCESS_OVR_F, &val64);
		aggregate_64bit(&perf_count_ext.excessiveBufferOverrunErrors, val64);
		mad_decode_field(pc, IB_PC_EXT_VL15_DROPPED_F, &val64);
		aggregate_64bit(&perf_count_ext.VL15Dropped, val64);
		mad_decode_field(pc, IB_PC_EXT_XMT_WAIT_F, &val64);
		aggregate_64bit(&perf_count_ext.portXmitWait, val64);
		mad_decode_field(pc, IB_PC_EXT_QP1_DROP_F, &val64);
		aggregate_64bit(&perf_count_ext.QP1Dropped, val64);
	}
}

static void dump_perfcounters_ext(char *buf, int size, __be16 cap_mask,
				  uint32_t cap_mask2)
{
	size_t offset, tmp_offset;

	mad_dump_fields(buf, size, pc, sizeof(pc), IB_PC_EXT_FIRST_F,
			IB_PC_EXT_XMT_UPKTS_F);
	offset = strlen(buf);

	if (cap_mask & IB_PM_EXT_WIDTH_SUPPORTED) {
		mad_dump_fields(buf + offset, size - offset, pc, sizeof(pc),
				IB_PC_EXT_XMT_UPKTS_F, IB_PC_EXT_LAST_F);
		tmp_offset = strlen(buf + offset);
		offset += tmp_offset;
	}

	if (htonl(cap_mask2) & IB_PM_IS_ADDL_PORT_CTRS_EXT_SUP) {
		mad_dump_fields(buf + offset, size - offset, pc, sizeof(pc),
				IB_PC_EXT_COUNTER_SELECT2_F,
				IB_PC_EXT_ERR_LAST_F);
	}
}

static void output_aggregate_perfcounters_ext(ib_portid_t * portid,
					      __be16 cap_mask, uint32_t cap_mask2)
{
	char buf[1536];
	uint32_t val = ALL_PORTS;

	memset(buf, 0, sizeof(buf));

	/* set port_select to 255 to emulate AllPortSelect */
	mad_encode_field(pc, IB_PC_EXT_PORT_SELECT_F, &val);
	mad_encode_field(pc, IB_PC_EXT_COUNTER_SELECT_F,
			 &perf_count_ext.counterselect);
	mad_encode_field(pc, IB_PC_EXT_XMT_BYTES_F,
			 &perf_count_ext.portxmitdata);
	mad_encode_field(pc, IB_PC_EXT_RCV_BYTES_F,
			 &perf_count_ext.portrcvdata);
	mad_encode_field(pc, IB_PC_EXT_XMT_PKTS_F,
			 &perf_count_ext.portxmitpkts);
	mad_encode_field(pc, IB_PC_EXT_RCV_PKTS_F, &perf_count_ext.portrcvpkts);

	if (cap_mask & IB_PM_EXT_WIDTH_SUPPORTED) {
		mad_encode_field(pc, IB_PC_EXT_XMT_UPKTS_F,
				 &perf_count_ext.portunicastxmitpkts);
		mad_encode_field(pc, IB_PC_EXT_RCV_UPKTS_F,
				 &perf_count_ext.portunicastrcvpkts);
		mad_encode_field(pc, IB_PC_EXT_XMT_MPKTS_F,
				 &perf_count_ext.portmulticastxmitpkits);
		mad_encode_field(pc, IB_PC_EXT_RCV_MPKTS_F,
				 &perf_count_ext.portmulticastrcvpkts);
	}

	if (htonl(cap_mask2) & IB_PM_IS_ADDL_PORT_CTRS_EXT_SUP) {
		mad_encode_field(pc, IB_PC_EXT_COUNTER_SELECT2_F,
				 &perf_count_ext.counterSelect2);
		mad_encode_field(pc, IB_PC_EXT_ERR_SYM_F,
				 &perf_count_ext.symbolErrorCounter);
		mad_encode_field(pc, IB_PC_EXT_LINK_RECOVERS_F,
				 &perf_count_ext.linkErrorRecoveryCounter);
		mad_encode_field(pc, IB_PC_EXT_LINK_DOWNED_F,
				 &perf_count_ext.linkDownedCounter);
		mad_encode_field(pc, IB_PC_EXT_ERR_RCV_F,
				 &perf_count_ext.portRcvErrors);
		mad_encode_field(pc, IB_PC_EXT_ERR_PHYSRCV_F,
				 &perf_count_ext.portRcvRemotePhysicalErrors);
		mad_encode_field(pc, IB_PC_EXT_ERR_SWITCH_REL_F,
				 &perf_count_ext.portRcvSwitchRelayErrors);
		mad_encode_field(pc, IB_PC_EXT_XMT_DISCARDS_F,
				 &perf_count_ext.portXmitDiscards);
		mad_encode_field(pc, IB_PC_EXT_ERR_XMTCONSTR_F,
				 &perf_count_ext.portXmitConstraintErrors);
		mad_encode_field(pc, IB_PC_EXT_ERR_RCVCONSTR_F,
				 &perf_count_ext.portRcvConstraintErrors);
		mad_encode_field(pc, IB_PC_EXT_ERR_LOCALINTEG_F,
				 &perf_count_ext.localLinkIntegrityErrors);
		mad_encode_field(pc, IB_PC_EXT_ERR_EXCESS_OVR_F,
				 &perf_count_ext.excessiveBufferOverrunErrors);
		mad_encode_field(pc, IB_PC_EXT_VL15_DROPPED_F,
				 &perf_count_ext.VL15Dropped);
		mad_encode_field(pc, IB_PC_EXT_XMT_WAIT_F,
				 &perf_count_ext.portXmitWait);
		mad_encode_field(pc, IB_PC_EXT_QP1_DROP_F,
				 &perf_count_ext.QP1Dropped);
	}

	dump_perfcounters_ext(buf, sizeof(buf), cap_mask, cap_mask2);

	printf("# Port extended counters: %s port %d (CapMask: 0x%02X CapMask2: 0x%07X)\n%s",
	       portid2str(portid), ALL_PORTS, ntohs(cap_mask), cap_mask2, buf);
}

static void dump_perfcounters(int extended, int timeout, __be16 cap_mask,
			      uint32_t cap_mask2, ib_portid_t * portid,
			      int port, int aggregate)
{
	char buf[1536];

	if (extended != 1) {
		memset(pc, 0, sizeof(pc));
		if (!pma_query_via(pc, portid, port, timeout,
				   IB_GSI_PORT_COUNTERS, srcport))
			IBEXIT("perfquery");
		if (!(cap_mask & IB_PM_PC_XMIT_WAIT_SUP)) {
			/* if PortCounters:PortXmitWait not supported clear this counter */
			VERBOSE("PortXmitWait not indicated"
				" so ignore this counter");
			perf_count.xmtwait = 0;
			mad_encode_field(pc, IB_PC_XMT_WAIT_F,
					 &perf_count.xmtwait);
		}
		if (aggregate)
			aggregate_perfcounters();
		else
			mad_dump_perfcounters(buf, sizeof buf, pc, sizeof pc);

	} else {
		/* 1.2 errata: bit 9 is extended counter support
		 * bit 10 is extended counter NoIETF
		 */
		if (!(cap_mask & IB_PM_EXT_WIDTH_SUPPORTED) &&
		    !(cap_mask & IB_PM_EXT_WIDTH_NOIETF_SUP))
			IBWARN
			    ("PerfMgt ClassPortInfo CapMask 0x%02X; No extended counter support indicated\n",
			     ntohs(cap_mask));

		memset(pc, 0, sizeof(pc));
		if (!pma_query_via(pc, portid, port, timeout,
				   IB_GSI_PORT_COUNTERS_EXT, srcport))
			IBEXIT("perfextquery");
		if (aggregate)
			aggregate_perfcounters_ext(cap_mask, cap_mask2);
		else
			dump_perfcounters_ext(buf, sizeof(buf), cap_mask,
					      cap_mask2);
	}

	if (!aggregate) {
		if (extended)
			printf("# Port extended counters: %s port %d "
			       "(CapMask: 0x%02X CapMask2: 0x%07X)\n%s",
			       portid2str(portid), port, ntohs(cap_mask),
			       cap_mask2, buf);
		else
			printf("# Port counters: %s port %d "
			       "(CapMask: 0x%02X)\n%s",
			       portid2str(portid), port, ntohs(cap_mask), buf);
	}
}

static void reset_counters(int extended, int timeout, int mask,
			   ib_portid_t * portid, int port)
{
	memset(pc, 0, sizeof(pc));
	if (extended != 1) {
		if (!performance_reset_via(pc, portid, port, mask, timeout,
					   IB_GSI_PORT_COUNTERS, srcport))
			IBEXIT("perf reset");
	} else {
		if (!performance_reset_via(pc, portid, port, mask, timeout,
					   IB_GSI_PORT_COUNTERS_EXT, srcport))
			IBEXIT("perf ext reset");
	}
}

static struct
{
	int reset, reset_only, all_ports, loop_ports, port, extended, xmt_sl,
		rcv_sl, xmt_disc, rcv_err, extended_speeds, smpl_ctl,
		oprcvcounters, flowctlcounters, vloppackets, vlopdata,
		vlxmitflowctlerrors, vlxmitcounters, swportvlcong, rcvcc,
		slrcvfecn, slrcvbecn, xmitcc, vlxmittimecc;
	int ports[MAX_PORTS];
	int ports_count;
} info;

static void common_func(ib_portid_t * portid, int port_num, int mask,
			unsigned query, unsigned reset,
			const char *name, uint16_t attr,
			void dump_func(char *, int, void *, int))
{
	char buf[1536];

	if (query) {
		memset(pc, 0, sizeof(pc));
		if (!pma_query_via(pc, portid, port_num, ibd_timeout, attr,
				   srcport))
			IBEXIT("cannot query %s", name);

		dump_func(buf, sizeof(buf), pc, sizeof(pc));

		printf("# %s counters: %s port %d\n%s", name,
		       portid2str(portid), port_num, buf);
	}

	memset(pc, 0, sizeof(pc));
	if (reset && !performance_reset_via(pc, portid, info.port, mask,
					    ibd_timeout, attr, srcport))
		IBEXIT("cannot reset %s", name);
}

static void xmt_sl_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "PortXmitDataSL",
		    IB_GSI_PORT_XMIT_DATA_SL, mad_dump_perfcounters_xmt_sl);
}

static void rcv_sl_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "PortRcvDataSL",
		    IB_GSI_PORT_RCV_DATA_SL, mad_dump_perfcounters_rcv_sl);
}

static void xmt_disc_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "PortXmitDiscardDetails",
		    IB_GSI_PORT_XMIT_DISCARD_DETAILS,
		    mad_dump_perfcounters_xmt_disc);
}

static void rcv_err_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "PortRcvErrorDetails",
		    IB_GSI_PORT_RCV_ERROR_DETAILS,
		    mad_dump_perfcounters_rcv_err);
}

static uint8_t *ext_speeds_reset_via(void *rcvbuf, ib_portid_t * dest,
				     int port, uint64_t mask, unsigned timeout)
{
	ib_rpc_t rpc = { 0 };
	int lid = dest->lid;

	DEBUG("lid %u port %d mask 0x%" PRIx64, lid, port, mask);

	if (lid == -1) {
		IBWARN("only lid routed is supported");
		return NULL;
	}

	if (!mask)
		mask = ~0;

	rpc.mgtclass = IB_PERFORMANCE_CLASS;
	rpc.method = IB_MAD_METHOD_SET;
	rpc.attr.id = IB_GSI_PORT_EXT_SPEEDS_COUNTERS;

	memset(rcvbuf, 0, IB_MAD_SIZE);

	mad_set_field(rcvbuf, 0, IB_PESC_PORT_SELECT_F, port);
	mad_set_field64(rcvbuf, 0, IB_PESC_COUNTER_SELECT_F, mask);
	rpc.attr.mod = 0;
	rpc.timeout = timeout;
	rpc.datasz = IB_PC_DATA_SZ;
	rpc.dataoffs = IB_PC_DATA_OFFS;
	if (!dest->qp)
		dest->qp = 1;
	if (!dest->qkey)
		dest->qkey = IB_DEFAULT_QP1_QKEY;

	return mad_rpc(srcport, &rpc, dest, rcvbuf, rcvbuf);
}

static uint8_t is_rsfec_mode_active(ib_portid_t * portid, int port,
				  __be16 cap_mask)
{
	uint8_t data[IB_SMP_DATA_SIZE] = { 0 };
	uint32_t fec_mode_active = 0;
	uint32_t pie_capmask = 0;
	if (cap_mask & IS_PM_RSFEC_COUNTERS_SUP) {
		if (!is_port_info_extended_supported(portid, port, srcport)) {
			IBWARN("Port Info Extended not supported");
			return 0;
		}

		if (!smp_query_via(data, portid, IB_ATTR_PORT_INFO_EXT, port, 0,
				   srcport))
			IBEXIT("smp query portinfo extended failed");

		mad_decode_field(data, IB_PORT_EXT_CAPMASK_F, &pie_capmask);
		mad_decode_field(data, IB_PORT_EXT_FEC_MODE_ACTIVE_F,
				 &fec_mode_active);
		if((pie_capmask &
		    be32toh(IB_PORT_EXT_CAP_IS_FEC_MODE_SUPPORTED)) &&
		   ((be16toh(IB_PORT_EXT_RS_FEC_MODE_ACTIVE) == (fec_mode_active & 0xffff)) ||
                    (be16toh(IB_PORT_EXT_RS_FEC2_MODE_ACTIVE) == (fec_mode_active & 0xffff))))
			return 1;
	}

	return 0;
}

static void extended_speeds_query(ib_portid_t * portid, int port,
				  uint64_t ext_mask, __be16 cap_mask)
{
	int mask = ext_mask;

	if (!info.reset_only) {
		if (is_rsfec_mode_active(portid, port, cap_mask))
			common_func(portid, port, mask, 1, 0,
				    "PortExtendedSpeedsCounters with RS-FEC Active",
				    IB_GSI_PORT_EXT_SPEEDS_COUNTERS,
				    mad_dump_port_ext_speeds_counters_rsfec_active);
		else
			common_func(portid, port, mask, 1, 0,
			    "PortExtendedSpeedsCounters",
			    IB_GSI_PORT_EXT_SPEEDS_COUNTERS,
			    mad_dump_port_ext_speeds_counters);
	}

	if ((info.reset_only || info.reset) &&
	    !ext_speeds_reset_via(pc, portid, port, ext_mask, ibd_timeout))
		IBEXIT("cannot reset PortExtendedSpeedsCounters");
}

static void oprcvcounters_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "PortOpRcvCounters",
		    IB_GSI_PORT_PORT_OP_RCV_COUNTERS,
		    mad_dump_perfcounters_port_op_rcv_counters);
}

static void flowctlcounters_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "PortFlowCtlCounters",
		    IB_GSI_PORT_PORT_FLOW_CTL_COUNTERS,
		    mad_dump_perfcounters_port_flow_ctl_counters);
}

static void vloppackets_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "PortVLOpPackets",
		    IB_GSI_PORT_PORT_VL_OP_PACKETS,
		    mad_dump_perfcounters_port_vl_op_packet);
}

static void vlopdata_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "PortVLOpData",
		    IB_GSI_PORT_PORT_VL_OP_DATA,
		    mad_dump_perfcounters_port_vl_op_data);
}

static void vlxmitflowctlerrors_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset),
		    "PortVLXmitFlowCtlUpdateErrors",
		    IB_GSI_PORT_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS,
		    mad_dump_perfcounters_port_vl_xmit_flow_ctl_update_errors);
}

static void vlxmitcounters_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "PortVLXmitWaitCounters",
		    IB_GSI_PORT_PORT_VL_XMIT_WAIT_COUNTERS,
		    mad_dump_perfcounters_port_vl_xmit_wait_counters);
}

static void swportvlcong_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "SwPortVLCongestion",
		    IB_GSI_SW_PORT_VL_CONGESTION,
		    mad_dump_perfcounters_sw_port_vl_congestion);
}

static void rcvcc_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "PortRcvConCtrl",
		    IB_GSI_PORT_RCV_CON_CTRL,
		    mad_dump_perfcounters_rcv_con_ctrl);
}

static void slrcvfecn_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "PortSLRcvFECN",
		    IB_GSI_PORT_SL_RCV_FECN, mad_dump_perfcounters_sl_rcv_fecn);
}

static void slrcvbecn_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "PortSLRcvBECN",
		    IB_GSI_PORT_SL_RCV_BECN, mad_dump_perfcounters_sl_rcv_becn);
}

static void xmitcc_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "PortXmitConCtrl",
		    IB_GSI_PORT_XMIT_CON_CTRL,
		    mad_dump_perfcounters_xmit_con_ctrl);
}

static void vlxmittimecc_query(ib_portid_t * portid, int port, int mask)
{
	common_func(portid, port, mask, !info.reset_only,
		    (info.reset_only || info.reset), "PortVLXmitTimeCong",
		    IB_GSI_PORT_VL_XMIT_TIME_CONG,
		    mad_dump_perfcounters_vl_xmit_time_cong);
}

static void dump_portsamples_control(ib_portid_t *portid, int port)
{
	char buf[1280];

	memset(pc, 0, sizeof(pc));
	if (!pma_query_via(pc, portid, port, ibd_timeout,
			   IB_GSI_PORT_SAMPLES_CONTROL, srcport))
		IBEXIT("sampctlquery");

	mad_dump_portsamples_control(buf, sizeof buf, pc, sizeof pc);
	printf("# PortSamplesControl: %s port %d\n%s", portid2str(portid),
	       port, buf);
}

static int process_opt(void *context, int ch)
{
	switch (ch) {
	case 'x':
		info.extended = 1;
		break;
	case 'X':
		info.xmt_sl = 1;
		break;
	case 'S':
		info.rcv_sl = 1;
		break;
	case 'D':
		info.xmt_disc = 1;
		break;
	case 'E':
		info.rcv_err = 1;
		break;
	case 'T':
		info.extended_speeds = 1;
		break;
	case 'c':
		info.smpl_ctl = 1;
		break;
	case 1:
		info.oprcvcounters = 1;
		break;
	case 2:
		info.flowctlcounters = 1;
		break;
	case 3:
		info.vloppackets = 1;
		break;
	case 4:
		info.vlopdata = 1;
		break;
	case 5:
		info.vlxmitflowctlerrors = 1;
		break;
	case 6:
		info.vlxmitcounters = 1;
		break;
	case 7:
		info.swportvlcong = 1;
		break;
	case 8:
		info.rcvcc = 1;
		break;
	case 9:
		info.slrcvfecn = 1;
		break;
	case 10:
		info.slrcvbecn = 1;
		break;
	case 11:
		info.xmitcc = 1;
		break;
	case 12:
		info.vlxmittimecc = 1;
		break;
	case 'a':
		info.all_ports++;
		info.port = ALL_PORTS;
		break;
	case 'l':
		info.loop_ports++;
		break;
	case 'r':
		info.reset++;
		break;
	case 'R':
		info.reset_only++;
		break;
	default:
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int mgmt_classes[3] = { IB_SMI_CLASS, IB_SA_CLASS, IB_PERFORMANCE_CLASS };
	ib_portid_t portid = { 0 };
	int mask = 0xffff;
	uint64_t ext_mask = 0xffffffffffffffffULL;
	__be32 cap_mask2_be;
	uint32_t cap_mask2;
	__be16 cap_mask;
	int all_ports_loop = 0;
	int node_type, num_ports = 0;
	uint8_t data[IB_SMP_DATA_SIZE] = { 0 };
	int start_port = 1;
	int enhancedport0;
	char *tmpstr;
	int i;

	const struct ibdiag_opt opts[] = {
		{"extended", 'x', 0, NULL, "show extended port counters"},
		{"xmtsl", 'X', 0, NULL, "show Xmt SL port counters"},
		{"rcvsl", 'S', 0, NULL, "show Rcv SL port counters"},
		{"xmtdisc", 'D', 0, NULL, "show Xmt Discard Details"},
		{"rcverr", 'E', 0, NULL, "show Rcv Error Details"},
		{"extended_speeds", 'T', 0, NULL, "show port extended speeds counters"},
		{"oprcvcounters", 1, 0, NULL, "show Rcv Counters per Op code"},
		{"flowctlcounters", 2, 0, NULL, "show flow control counters"},
		{"vloppackets", 3, 0, NULL, "show packets received per Op code per VL"},
		{"vlopdata", 4, 0, NULL, "show data received per Op code per VL"},
		{"vlxmitflowctlerrors", 5, 0, NULL, "show flow control update errors per VL"},
		{"vlxmitcounters", 6, 0, NULL, "show ticks waiting to transmit counters per VL"},
		{"swportvlcong", 7, 0, NULL, "show sw port VL congestion"},
		{"rcvcc", 8, 0, NULL, "show Rcv congestion control counters"},
		{"slrcvfecn", 9, 0, NULL, "show SL Rcv FECN counters"},
		{"slrcvbecn", 10, 0, NULL, "show SL Rcv BECN counters"},
		{"xmitcc", 11, 0, NULL, "show Xmit congestion control counters"},
		{"vlxmittimecc", 12, 0, NULL, "show VL Xmit Time congestion control counters"},
		{"smplctl", 'c', 0, NULL, "show samples control"},
		{"all_ports", 'a', 0, NULL, "show aggregated counters"},
		{"loop_ports", 'l', 0, NULL, "iterate through each port"},
		{"reset_after_read", 'r', 0, NULL, "reset counters after read"},
		{"Reset_only", 'R', 0, NULL, "only reset counters"},
		{}
	};
	char usage_args[] = " [<lid|guid> [[port(s)] [reset_mask]]]";
	const char *usage_examples[] = {
		"\t\t# read local port's performance counters",
		"32 1\t\t# read performance counters from lid 32, port 1",
		"-x 32 1\t# read extended performance counters from lid 32, port 1",
		"-a 32\t\t# read performance counters from lid 32, all ports",
		"-r 32 1\t# read performance counters and reset",
		"-x -r 32 1\t# read extended performance counters and reset",
		"-R 0x20 1\t# reset performance counters of port 1 only",
		"-x -R 0x20 1\t# reset extended performance counters of port 1 only",
		"-R -a 32\t# reset performance counters of all ports",
		"-R 32 2 0x0fff\t# reset only error counters of port 2",
		"-R 32 2 0xf000\t# reset only non-error counters of port 2",
		"-a 32 1-10\t# read performance counters from lid 32, port 1-10, aggregate output",
		"-l 32 1-10\t# read performance counters from lid 32, port 1-10, output each port",
		"-a 32 1,4,8\t# read performance counters from lid 32, port 1, 4, and 8, aggregate output",
		"-l 32 1,4,8\t# read performance counters from lid 32, port 1, 4, and 8, output each port",
		NULL,
	};

	ibdiag_process_opts(argc, argv, NULL, "DK", opts, process_opt,
			    usage_args, usage_examples);

	argc -= optind;
	argv += optind;

	if (argc > 1) {
		if (strchr(argv[1], ',')) {
			tmpstr = strtok(argv[1], ",");
			while (tmpstr) {
				info.ports[info.ports_count++] =
					strtoul(tmpstr, NULL, 0);
				tmpstr = strtok(NULL, ",");
			}
			info.port = info.ports[0];
		}
		else if ((tmpstr = strchr(argv[1], '-'))) {
			int pmin, pmax;

			*tmpstr = '\0';
			tmpstr++;

			pmin = strtoul(argv[1], NULL, 0);
			pmax = strtoul(tmpstr, NULL, 0);

			if (pmin >= pmax)
				IBEXIT("max port must be greater than min port in range");

			while (pmin <= pmax)
				info.ports[info.ports_count++] = pmin++;

			info.port = info.ports[0];
		}
		else
			info.port = strtoul(argv[1], NULL, 0);
	}
	if (argc > 2) {
		ext_mask = strtoull(argv[2], NULL, 0);
		mask = ext_mask;
	}

	srcport = mad_rpc_open_port(ibd_ca, ibd_ca_port, mgmt_classes, 3);
	if (!srcport)
		IBEXIT("Failed to open '%s' port '%d'", ibd_ca, ibd_ca_port);

	smp_mkey_set(srcport, ibd_mkey);

	if (argc) {
		if (resolve_portid_str(ibd_ca, ibd_ca_port, &portid, argv[0],
				       ibd_dest_type, ibd_sm_id, srcport) < 0)
			IBEXIT("can't resolve destination port %s", argv[0]);
	} else {
		if (resolve_self(ibd_ca, ibd_ca_port, &portid, &info.port, NULL) <
		    0)
			IBEXIT("can't resolve self port %s", argv[0]);
	}

	/* PerfMgt ClassPortInfo is a required attribute */
	memset(pc, 0, sizeof(pc));
	if (!pma_query_via(pc, &portid, info.port, ibd_timeout, CLASS_PORT_INFO,
			   srcport))
		IBEXIT("classportinfo query");
	/* ClassPortInfo should be supported as part of libibmad */
	memcpy(&cap_mask, pc + 2, sizeof(cap_mask));	/* CapabilityMask */
	memcpy(&cap_mask2_be, pc + 4, sizeof(cap_mask2_be));	/* CapabilityMask2 */
	cap_mask2 = ntohl(cap_mask2_be) >> 5;

	if (!(cap_mask & IB_PM_ALL_PORT_SELECT)) {	/* bit 8 is AllPortSelect */
		if (!info.all_ports && info.port == ALL_PORTS)
			IBEXIT("AllPortSelect not supported");
		if (info.all_ports && info.port == ALL_PORTS)
			all_ports_loop = 1;
	}

	if (info.xmt_sl) {
		xmt_sl_query(&portid, info.port, mask);
		goto done;
	}

	if (info.rcv_sl) {
		rcv_sl_query(&portid, info.port, mask);
		goto done;
	}

	if (info.xmt_disc) {
		xmt_disc_query(&portid, info.port, mask);
		goto done;
	}

	if (info.rcv_err) {
		rcv_err_query(&portid, info.port, mask);
		goto done;
	}

	if (info.extended_speeds) {
		extended_speeds_query(&portid, info.port, ext_mask, cap_mask);
		goto done;
	}

	if (info.oprcvcounters) {
		oprcvcounters_query(&portid, info.port, mask);
		goto done;
	}

	if (info.flowctlcounters) {
		flowctlcounters_query(&portid, info.port, mask);
		goto done;
	}

	if (info.vloppackets) {
		vloppackets_query(&portid, info.port, mask);
		goto done;
	}

	if (info.vlopdata) {
		vlopdata_query(&portid, info.port, mask);
		goto done;
	}

	if (info.vlxmitflowctlerrors) {
		vlxmitflowctlerrors_query(&portid, info.port, mask);
		goto done;
	}

	if (info.vlxmitcounters) {
		vlxmitcounters_query(&portid, info.port, mask);
		goto done;
	}

	if (info.swportvlcong) {
		swportvlcong_query(&portid, info.port, mask);
		goto done;
	}

	if (info.rcvcc) {
		rcvcc_query(&portid, info.port, mask);
		goto done;
	}

	if (info.slrcvfecn) {
		slrcvfecn_query(&portid, info.port, mask);
		goto done;
	}

	if (info.slrcvbecn) {
		slrcvbecn_query(&portid, info.port, mask);
		goto done;
	}

	if (info.xmitcc) {
		xmitcc_query(&portid, info.port, mask);
		goto done;
	}

	if (info.vlxmittimecc) {
		vlxmittimecc_query(&portid, info.port, mask);
		goto done;
	}

	if (info.smpl_ctl) {
		dump_portsamples_control(&portid, info.port);
		goto done;
	}

	if (all_ports_loop ||
	    (info.loop_ports && (info.all_ports || info.port == ALL_PORTS))) {
		if (!smp_query_via(data, &portid, IB_ATTR_NODE_INFO, 0, 0,
				   srcport))
			IBEXIT("smp query nodeinfo failed");
		node_type = mad_get_field(data, 0, IB_NODE_TYPE_F);
		mad_decode_field(data, IB_NODE_NPORTS_F, &num_ports);
		if (!num_ports)
			IBEXIT("smp query nodeinfo: num ports invalid");

		if (node_type == IB_NODE_SWITCH) {
			if (!smp_query_via(data, &portid, IB_ATTR_SWITCH_INFO,
					   0, 0, srcport))
				IBEXIT("smp query nodeinfo failed");
			enhancedport0 =
			    mad_get_field(data, 0, IB_SW_ENHANCED_PORT0_F);
			if (enhancedport0)
				start_port = 0;
		}
		if (all_ports_loop && !info.loop_ports)
			IBWARN
			    ("Emulating AllPortSelect by iterating through all ports");
	}

	if (info.reset_only)
		goto do_reset;

	if (all_ports_loop ||
	    (info.loop_ports && (info.all_ports || info.port == ALL_PORTS))) {
		for (i = start_port; i <= num_ports; i++)
			dump_perfcounters(info.extended, ibd_timeout, cap_mask,
					  cap_mask2, &portid, i,
					  (all_ports_loop && !info.loop_ports));
		if (all_ports_loop && !info.loop_ports) {
			if (info.extended != 1)
				output_aggregate_perfcounters(&portid,
							      cap_mask);
			else
				output_aggregate_perfcounters_ext(&portid,
								  cap_mask, cap_mask2);
		}
	} else if (info.ports_count > 1) {
		for (i = 0; i < info.ports_count; i++)
			dump_perfcounters(info.extended, ibd_timeout, cap_mask,
					  cap_mask2, &portid, info.ports[i],
					  (info.all_ports && !info.loop_ports));
		if (info.all_ports && !info.loop_ports) {
			if (info.extended != 1)
				output_aggregate_perfcounters(&portid,
							      cap_mask);
			else
				output_aggregate_perfcounters_ext(&portid,
								  cap_mask, cap_mask2);
		}
	} else
		dump_perfcounters(info.extended, ibd_timeout, cap_mask,
				  cap_mask2, &portid, info.port, 0);

	if (!info.reset)
		goto done;

do_reset:
	if (argc <= 2 && !info.extended) {
		if (cap_mask & IB_PM_PC_XMIT_WAIT_SUP)
			mask |= (1 << 16);	/* reset portxmitwait */
		if (cap_mask & IB_PM_IS_QP1_DROP_SUP)
			mask |= (1 << 17);	/* reset qp1dropped */
	}

	if (info.extended) {
		mask |= 0xfff0000;
		if (cap_mask & IB_PM_PC_XMIT_WAIT_SUP)
			mask |= (1 << 28);
		if (cap_mask & IB_PM_IS_QP1_DROP_SUP)
			mask |= (1 << 29);
	}

	if (all_ports_loop ||
	    (info.loop_ports && (info.all_ports || info.port == ALL_PORTS))) {
		for (i = start_port; i <= num_ports; i++)
			reset_counters(info.extended, ibd_timeout, mask,
				       &portid, i);
	} else if (info.ports_count > 1) {
		for (i = 0; i < info.ports_count; i++)
			reset_counters(info.extended, ibd_timeout, mask,
				       &portid, info.ports[i]);
	} else
		reset_counters(info.extended, ibd_timeout, mask, &portid, info.port);

done:
	mad_rpc_close_port(srcport);
	exit(0);
}
