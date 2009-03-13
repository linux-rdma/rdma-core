/*
 * Copyright (c) 2004-2008 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2007 Xsigo Systems Inc.  All rights reserved.
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/in.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>

#include "ibdiag_common.h"

struct ibmad_port *srcport;

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
};

static uint8_t pc[1024];

struct perf_count perf_count = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
struct perf_count_ext perf_count_ext = {0,0,0,0,0,0,0,0,0,0};

#define ALL_PORTS 0xFF

/* Notes: IB semantics is to cap counters if count has exceeded limits.
 * Therefore we must check for overflows and cap the counters if necessary.
 *
 * mad_decode_field and mad_encode_field assume 32 bit integers passed in
 * for fields < 32 bits in length.
 */

static void aggregate_4bit(uint32_t *dest, uint32_t val)
{
	if ((((*dest) + val) < (*dest))
	    || ((*dest) + val) > 0xf)
		(*dest) = 0xf;
	else
		(*dest) = (*dest) + val;
}

static void aggregate_8bit(uint32_t *dest, uint32_t val)
{
	if ((((*dest) + val) < (*dest))
	    || ((*dest) + val) > 0xff)
		(*dest) = 0xff;
	else
		(*dest) = (*dest) + val;
}

static void aggregate_16bit(uint32_t *dest, uint32_t val)
{
	if ((((*dest) + val) < (*dest))
	    || ((*dest) + val) > 0xffff)
		(*dest) = 0xffff;
	else
		(*dest) = (*dest) + val;
}

static void aggregate_32bit(uint32_t *dest, uint32_t val)
{
	if (((*dest) + val) < (*dest))
		(*dest) = 0xffffffff;
	else
		(*dest) = (*dest) + val;
}

static void aggregate_64bit(uint64_t *dest, uint64_t val)
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

static void output_aggregate_perfcounters(ib_portid_t *portid)
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
	mad_encode_field(pc, IB_PC_ERR_PHYSRCV_F, &perf_count.rcvremotephyerrors);
	mad_encode_field(pc, IB_PC_ERR_SWITCH_REL_F, &perf_count.rcvswrelayerrors);
	mad_encode_field(pc, IB_PC_XMT_DISCARDS_F, &perf_count.xmtdiscards);
	mad_encode_field(pc, IB_PC_ERR_XMTCONSTR_F, &perf_count.xmtconstrainterrors);
	mad_encode_field(pc, IB_PC_ERR_RCVCONSTR_F, &perf_count.rcvconstrainterrors);
	mad_encode_field(pc, IB_PC_ERR_LOCALINTEG_F, &perf_count.linkintegrityerrors);
	mad_encode_field(pc, IB_PC_ERR_EXCESS_OVR_F, &perf_count.excbufoverrunerrors);
	mad_encode_field(pc, IB_PC_VL15_DROPPED_F, &perf_count.vl15dropped);
	mad_encode_field(pc, IB_PC_XMT_BYTES_F, &perf_count.xmtdata);
	mad_encode_field(pc, IB_PC_RCV_BYTES_F, &perf_count.rcvdata);
	mad_encode_field(pc, IB_PC_XMT_PKTS_F, &perf_count.xmtpkts);
	mad_encode_field(pc, IB_PC_RCV_PKTS_F, &perf_count.rcvpkts);
	mad_encode_field(pc, IB_PC_XMT_WAIT_F, &perf_count.xmtwait);

	mad_dump_perfcounters(buf, sizeof buf, pc, sizeof pc);

	printf("# Port counters: %s port %d\n%s", portid2str(portid), ALL_PORTS, buf);
}

static void aggregate_perfcounters_ext(void)
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
	mad_decode_field(pc, IB_PC_EXT_XMT_UPKTS_F, &val64);
	aggregate_64bit(&perf_count_ext.portunicastxmitpkts, val64);
	mad_decode_field(pc, IB_PC_EXT_RCV_UPKTS_F, &val64);
	aggregate_64bit(&perf_count_ext.portunicastrcvpkts, val64);
	mad_decode_field(pc, IB_PC_EXT_XMT_MPKTS_F, &val64);
	aggregate_64bit(&perf_count_ext.portmulticastxmitpkits, val64);
	mad_decode_field(pc, IB_PC_EXT_RCV_MPKTS_F, &val64);
	aggregate_64bit(&perf_count_ext.portmulticastrcvpkts, val64);
}

static void output_aggregate_perfcounters_ext(ib_portid_t *portid)
{
	char buf[1024];
	uint32_t val = ALL_PORTS;

	/* set port_select to 255 to emulate AllPortSelect */
	mad_encode_field(pc, IB_PC_EXT_PORT_SELECT_F, &val);
	mad_encode_field(pc, IB_PC_EXT_COUNTER_SELECT_F, &perf_count_ext.counterselect);
	mad_encode_field(pc, IB_PC_EXT_XMT_BYTES_F, &perf_count_ext.portxmitdata);
	mad_encode_field(pc, IB_PC_EXT_RCV_BYTES_F, &perf_count_ext.portrcvdata);
	mad_encode_field(pc, IB_PC_EXT_XMT_PKTS_F, &perf_count_ext.portxmitpkts);
	mad_encode_field(pc, IB_PC_EXT_RCV_PKTS_F, &perf_count_ext.portrcvpkts);
	mad_encode_field(pc, IB_PC_EXT_XMT_UPKTS_F, &perf_count_ext.portunicastxmitpkts);
	mad_encode_field(pc, IB_PC_EXT_RCV_UPKTS_F, &perf_count_ext.portunicastrcvpkts);
	mad_encode_field(pc, IB_PC_EXT_XMT_MPKTS_F, &perf_count_ext.portmulticastxmitpkits);
	mad_encode_field(pc, IB_PC_EXT_RCV_MPKTS_F, &perf_count_ext.portmulticastrcvpkts);

	mad_dump_perfcounters_ext(buf, sizeof buf, pc, sizeof pc);

	printf("# Port counters: %s port %d\n%s", portid2str(portid), ALL_PORTS, buf);
}

static void dump_perfcounters(int extended, int timeout, uint16_t cap_mask,
			      ib_portid_t *portid, int port, int aggregate)
{
	char buf[1024];

	if (extended != 1) {
		if (!pma_query_via(pc, portid, port, timeout,
				   IB_GSI_PORT_COUNTERS, srcport))
			IBERROR("perfquery");
		if (!(cap_mask & 0x1000)) {
			/* if PortCounters:PortXmitWait not suppported clear this counter */
			perf_count.xmtwait = 0;
			mad_encode_field(pc, IB_PC_XMT_WAIT_F, &perf_count.xmtwait);
		}
		if (aggregate)
			aggregate_perfcounters();
		else
			mad_dump_perfcounters(buf, sizeof buf, pc, sizeof pc);
	} else {
		if (!(cap_mask & 0x200)) /* 1.2 errata: bit 9 is extended counter support */
			IBWARN("PerfMgt ClassPortInfo 0x%x extended counters not indicated\n", cap_mask);

		if (!pma_query_via(pc, portid, port, timeout,
				   IB_GSI_PORT_COUNTERS_EXT, srcport))
			IBERROR("perfextquery");
		if (aggregate)
			aggregate_perfcounters_ext();
		else
			mad_dump_perfcounters_ext(buf, sizeof buf, pc, sizeof pc);
	}

	if (!aggregate)
		printf("# Port counters: %s port %d\n%s", portid2str(portid), port, buf);
}

static void reset_counters(int extended, int timeout, int mask, ib_portid_t *portid, int port)
{
	if (extended != 1) {
		if (!performance_reset_via(pc, portid, port, mask, timeout,
					   IB_GSI_PORT_COUNTERS, srcport))
			IBERROR("perf reset");
	} else {
		if (!performance_reset_via(pc, portid, port, mask, timeout,
					   IB_GSI_PORT_COUNTERS_EXT, srcport))
			IBERROR("perf ext reset");
	}
}

static int reset, reset_only, all_ports, loop_ports, port, extended, xmt_sl, rcv_sl;

void xmt_sl_query(ib_portid_t *portid, int port, int mask)
{
	char buf[1024];

	if (reset_only) {
		if (!performance_reset_via(pc, portid, port, mask, ibd_timeout,
						IB_GSI_PORT_XMIT_DATA_SL, srcport))
			IBERROR("perfslreset");
		return;
	}

	if (!pma_query_via(pc, portid, port, ibd_timeout,
				IB_GSI_PORT_XMIT_DATA_SL, srcport))
		IBERROR("perfslquery");

	mad_dump_perfcounters_xmt_sl(buf, sizeof buf, pc, sizeof pc);
	printf("# PortXmitDataSL counters: %s port %d\n%s", portid2str(portid), port, buf);

	if (reset)
		if (!performance_reset_via(pc, portid, port, mask, ibd_timeout,
						IB_GSI_PORT_XMIT_DATA_SL, srcport))
			IBERROR("perfslreset");
}

void rcv_sl_query(ib_portid_t *portid, int port, int mask)
{
	char buf[1024];

	if (reset_only) {
		if (!performance_reset_via(pc, portid, port, mask, ibd_timeout,
						IB_GSI_PORT_RCV_DATA_SL, srcport))
			IBERROR("perfslreset");
		return;
	}

	if (!pma_query_via(pc, portid, port, ibd_timeout,
				IB_GSI_PORT_RCV_DATA_SL, srcport))
		IBERROR("perfslquery");

	mad_dump_perfcounters_rcv_sl(buf, sizeof buf, pc, sizeof pc);
	printf("# PortRcvDataSL counters: %s port %d\n%s", portid2str(portid), port, buf);

	if (reset)
		if (!performance_reset_via(pc, portid, port, mask, ibd_timeout,
						IB_GSI_PORT_RCV_DATA_SL, srcport))
			IBERROR("perfslreset");
}

static int process_opt(void *context, int ch, char *optarg)
{
	switch (ch) {
	case 'x':
		extended = 1;
		break;
	case 'X':
		xmt_sl = 1;
		break;
	case 'S':
		rcv_sl = 1;
		break;
	case 'a':
		all_ports++;
		port = ALL_PORTS;
		break;
	case 'l':
		loop_ports++;
		break;
	case 'r':
		reset++;
		break;
	case 'R':
		reset_only++;
		break;
	default:
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int mgmt_classes[4] = {IB_SMI_CLASS, IB_SMI_DIRECT_CLASS, IB_SA_CLASS, IB_PERFORMANCE_CLASS};
	ib_portid_t portid = {0};
	int mask = 0xffff;
	uint16_t cap_mask;
	int all_ports_loop = 0;
	int node_type, num_ports = 0;
	uint8_t data[IB_SMP_DATA_SIZE];
	int start_port = 1;
	int enhancedport0;
	int i;

	const struct ibdiag_opt opts[] = {
		{ "extended", 'x', 0, NULL, "show extended port counters" },
		{ "xmtsl", 'X', 0, NULL, "show Xmt SL port counters" },
		{ "rcvsl", 'S', 0, NULL, "show Rcv SL port counters" },
		{ "all_ports", 'a', 0, NULL, "show aggregated counters" },
		{ "loop_ports", 'l', 0, NULL, "iterate through each port" },
		{ "reset_after_read", 'r', 0, NULL, "reset counters after read" },
		{ "Reset_only", 'R', 0, NULL, "only reset counters" },
		{ 0 }
	};
	char usage_args[] = " [<lid|guid> [[port] [reset_mask]]]";
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
		NULL,
	};

	ibdiag_process_opts(argc, argv, NULL, "D", opts, process_opt,
			    usage_args, usage_examples);

	argc -= optind;
	argv += optind;

	if (argc > 1)
		port = strtoul(argv[1], 0, 0);
	if (argc > 2)
		mask = strtoul(argv[2], 0, 0);

	srcport = mad_rpc_open_port(ibd_ca, ibd_ca_port, mgmt_classes, 4);
	if (!srcport)
		IBERROR("Failed to open '%s' port '%d'", ibd_ca, ibd_ca_port);

	if (argc) {
		if (ib_resolve_portid_str_via(&portid, argv[0], ibd_dest_type,
				ibd_sm_id, srcport) < 0)
			IBERROR("can't resolve destination port %s", argv[0]);
	} else {
		if (ib_resolve_self_via(&portid, &port, 0, srcport) < 0)
			IBERROR("can't resolve self port %s", argv[0]);
	}

	/* PerfMgt ClassPortInfo is a required attribute */
	if (!pma_query_via(pc, &portid, port, ibd_timeout, CLASS_PORT_INFO,
			   srcport))
		IBERROR("classportinfo query");
	/* ClassPortInfo should be supported as part of libibmad */
	memcpy(&cap_mask, pc + 2, sizeof(cap_mask));	/* CapabilityMask */
	cap_mask = ntohs(cap_mask);
	if (!(cap_mask & 0x100)) { /* bit 8 is AllPortSelect */
		if (!all_ports && port == ALL_PORTS)
			IBERROR("AllPortSelect not supported");
		if (all_ports)
			all_ports_loop = 1;
	}

	if (xmt_sl) {
		xmt_sl_query(&portid, port, mask);
		goto done;
	}

	if (rcv_sl) {
		rcv_sl_query(&portid, port, mask);
		goto done;
	}

	if (all_ports_loop || (loop_ports && (all_ports || port == ALL_PORTS))) {
		if (smp_query_via(data, &portid, IB_ATTR_NODE_INFO, 0, 0,
				srcport) < 0)
			IBERROR("smp query nodeinfo failed");
		node_type = mad_get_field(data, 0, IB_NODE_TYPE_F);
		mad_decode_field(data, IB_NODE_NPORTS_F, &num_ports);
		if (!num_ports)
			IBERROR("smp query nodeinfo: num ports invalid");

		if (node_type == IB_NODE_SWITCH) {
			if (smp_query_via(data, &portid, IB_ATTR_SWITCH_INFO,
					0, 0, srcport) < 0)
				IBERROR("smp query nodeinfo failed");
			enhancedport0 = mad_get_field(data, 0, IB_SW_ENHANCED_PORT0_F);
			if (enhancedport0)
				start_port = 0;
		}
		if (all_ports_loop && !loop_ports)
			IBWARN("Emulating AllPortSelect by iterating through all ports");
	}

	if (reset_only)
		goto do_reset;

	if (all_ports_loop || (loop_ports && (all_ports || port == ALL_PORTS))) {
		for (i = start_port; i <= num_ports; i++)
			dump_perfcounters(extended, ibd_timeout, cap_mask, &portid, i,
					  (all_ports_loop && !loop_ports));
		if (all_ports_loop && !loop_ports) {
			if (extended != 1)
				output_aggregate_perfcounters(&portid);
			else
				output_aggregate_perfcounters_ext(&portid);
		}
	}
	else
		dump_perfcounters(extended, ibd_timeout, cap_mask, &portid, port, 0);

	if (!reset)
		goto done;

do_reset:

	if (argc <= 2 && !extended && (cap_mask & 0x1000))
		mask |= (1<<16); /* reset portxmitwait */

	if (all_ports_loop || (loop_ports && (all_ports || port == ALL_PORTS))) {
		for (i = start_port; i <= num_ports; i++)
			reset_counters(extended, ibd_timeout, mask, &portid, i);
	}
	else
		reset_counters(extended, ibd_timeout, mask, &portid, port);

done:
	mad_rpc_close_port(srcport);
	exit(0);
}
