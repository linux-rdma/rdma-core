/*
 * Copyright (c) 2004-2007 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2007 Xsigo Systems Inc.  All rights reserved.
 * Copyright (c) 2008 Lawrence Livermore National Lab.  All rights reserved.
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
#endif				/* HAVE_CONFIG_H */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <inttypes.h>

#include <complib/cl_nodenamemap.h>
#include <infiniband/ibnetdisc.h>
#include <infiniband/mad.h>

#include "ibdiag_common.h"

struct ibmad_port *ibmad_port;
static char *node_name_map_file = NULL;
static nn_map_t *node_name_map = NULL;
int data_counters = 0;
int port_config = 0;
uint64_t switch_guid = 0;
char *switch_guid_str = NULL;
int sup_total = 0;
enum MAD_FIELDS *suppressed_fields = NULL;
char *dr_path = NULL;
int all_nodes = 0;

static unsigned int get_max(unsigned int num)
{
	unsigned int v = num;	// 32-bit word to find the log base 2 of
	unsigned r = 0;		// r will be lg(v)

	while (v >>= 1)		// unroll for more speed...
	{
		r++;
	}

	return (1 << r);
}

static void get_msg(char *width_msg, char *speed_msg, int msg_size,
		    ibnd_port_t * port)
{
	char buf[64];
	uint32_t max_speed = 0;

	uint32_t max_width = get_max(mad_get_field(port->info, 0,
						   IB_PORT_LINK_WIDTH_SUPPORTED_F)
				     & mad_get_field(port->remoteport->info, 0,
						     IB_PORT_LINK_WIDTH_SUPPORTED_F));
	if ((max_width & mad_get_field(port->info, 0,
				       IB_PORT_LINK_WIDTH_ACTIVE_F)) == 0) {
		// we are not at the max supported width
		// print what we could be at.
		snprintf(width_msg, msg_size, "Could be %s",
			 mad_dump_val(IB_PORT_LINK_WIDTH_ACTIVE_F,
				      buf, 64, &max_width));
	}

	max_speed = get_max(mad_get_field(port->info, 0,
					  IB_PORT_LINK_SPEED_SUPPORTED_F)
			    & mad_get_field(port->remoteport->info, 0,
					    IB_PORT_LINK_SPEED_SUPPORTED_F));
	if ((max_speed & mad_get_field(port->info, 0,
				       IB_PORT_LINK_SPEED_ACTIVE_F)) == 0) {
		// we are not at the max supported speed
		// print what we could be at.
		snprintf(speed_msg, msg_size, "Could be %s",
			 mad_dump_val(IB_PORT_LINK_SPEED_ACTIVE_F,
				      buf, 64, &max_speed));
	}
}

static void print_port_config(ibnd_node_t * node, int portnum)
{
	char width[64], speed[64], state[64], physstate[64];
	char remote_str[256];
	char link_str[256];
	char width_msg[256];
	char speed_msg[256];
	char ext_port_str[256];
	int iwidth, ispeed, istate, iphystate;

	ibnd_port_t *port = node->ports[portnum];

	if (!port)
		return;

	iwidth = mad_get_field(port->info, 0, IB_PORT_LINK_WIDTH_ACTIVE_F);
	ispeed = mad_get_field(port->info, 0, IB_PORT_LINK_SPEED_ACTIVE_F);
	istate = mad_get_field(port->info, 0, IB_PORT_STATE_F);
	iphystate = mad_get_field(port->info, 0, IB_PORT_PHYS_STATE_F);

	remote_str[0] = '\0';
	link_str[0] = '\0';
	width_msg[0] = '\0';
	speed_msg[0] = '\0';

	snprintf(link_str, 256, "(%3s %s %6s/%8s)",
		 mad_dump_val(IB_PORT_LINK_WIDTH_ACTIVE_F, width, 64, &iwidth),
		 mad_dump_val(IB_PORT_LINK_SPEED_ACTIVE_F, speed, 64, &ispeed),
		 mad_dump_val(IB_PORT_STATE_F, state, 64, &istate),
		 mad_dump_val(IB_PORT_PHYS_STATE_F, physstate, 64, &iphystate));

	if (port->remoteport) {
		char *remap =
		    remap_node_name(node_name_map, port->remoteport->node->guid,
				    port->remoteport->node->nodedesc);

		if (port->remoteport->ext_portnum)
			snprintf(ext_port_str, 256, "%d",
				 port->remoteport->ext_portnum);
		else
			ext_port_str[0] = '\0';

		get_msg(width_msg, speed_msg, 256, port);

		snprintf(remote_str, 256,
			 "0x%016" PRIx64 " %6d %4d[%2s] \"%s\" (%s %s)\n",
			 port->remoteport->node->guid,
			 port->remoteport->base_lid ? port->remoteport->
			 base_lid : port->remoteport->node->smalid,
			 port->remoteport->portnum, ext_port_str, remap,
			 width_msg, speed_msg);
		free(remap);
	} else
		snprintf(remote_str, 256, "           [  ] \"\" ( )\n");

	if (port->ext_portnum)
		snprintf(ext_port_str, 256, "%d", port->ext_portnum);
	else
		ext_port_str[0] = '\0';

	if (node->type == IB_NODE_SWITCH)
		printf("       Link info: %6d", node->smalid);
	else
		printf("       Link info: %6d", port->base_lid);

	printf("%4d[%2s] ==%s==>  %s",
	       port->portnum, ext_port_str, link_str, remote_str);
}

static int suppress(enum MAD_FIELDS field)
{
	int i = 0;
	if (suppressed_fields)
		for (i = 0; i < sup_total; i++) {
			if (field == suppressed_fields[i])
				return (1);
		}
	return (0);
}

static void report_suppressed(void)
{
	int i = 0;
	if (suppressed_fields) {
		printf("Suppressing:");
		for (i = 0; i < sup_total; i++) {
			printf(" %s", mad_field_name(suppressed_fields[i]));
		}
		printf("\n");
	}
}

static void print_results(ibnd_node_t * node, uint8_t * pc, int portnum,
			  int *header_printed)
{
	char buf[1024];
	char *str = buf;
	uint32_t val = 0;
	int n = 0;
	int i = 0;

	for (n = 0, i = IB_PC_ERR_SYM_F; i <= IB_PC_VL15_DROPPED_F; i++) {
		if (suppress(i))
			continue;

		mad_decode_field(pc, i, (void *)&val);
		if (val)
			n += snprintf(str + n, 1024 - n, " [%s == %d]",
				      mad_field_name(i), val);
	}

	if (!suppress(IB_PC_XMT_WAIT_F)) {
		mad_decode_field(pc, IB_PC_XMT_WAIT_F, (void *)&val);
		if (val)
			n += snprintf(str + n, 1024 - n, " [%s == %d]",
				      mad_field_name(i), val);
	}

	/* if we found errors. */
	if (n != 0) {
		if (data_counters)
			for (i = IB_PC_XMT_BYTES_F; i <= IB_PC_RCV_PKTS_F; i++) {
				uint64_t val64 = 0;
				mad_decode_field(pc, i, (void *)&val64);
				if (val64)
					n += snprintf(str + n, 1024 - n,
						      " [%s == %" PRId64 "]",
						      mad_field_name(i), val64);
			}

		if (!*header_printed) {
			char *nodename =
			    remap_node_name(node_name_map, node->guid,
					    node->nodedesc);
			printf("Errors for 0x%" PRIx64 " \"%s\"\n", node->guid,
			       nodename);
			*header_printed = 1;
			free(nodename);
		}

		printf("   GUID 0x%" PRIx64 " port %d:%s\n", node->guid,
		       portnum, str);
		if (port_config)
			print_port_config(node, portnum);
	}
}

static void print_port(ibnd_node_t * node, int portnum, int *header_printed)
{
	uint8_t pc[1024];
	uint16_t cap_mask;
	ib_portid_t portid = { 0 };
	char *nodename =
	    remap_node_name(node_name_map, node->guid, node->nodedesc);

	if (node->type == IB_NODE_SWITCH)
		ib_portid_set(&portid, node->smalid, 0, 0);
	else
		ib_portid_set(&portid, node->ports[portnum]->base_lid, 0, 0);

	/* PerfMgt ClassPortInfo is a required attribute */
	if (!pma_query_via(pc, &portid, portnum, ibd_timeout, CLASS_PORT_INFO,
			   ibmad_port)) {
		IBWARN("classportinfo query failed on %s, %s port %d",
		       nodename, portid2str(&portid), portnum);
		goto cleanup;
	}
	/* ClassPortInfo should be supported as part of libibmad */
	memcpy(&cap_mask, pc + 2, sizeof(cap_mask));	/* CapabilityMask */

	if (!pma_query_via(pc, &portid, portnum, ibd_timeout,
			   IB_GSI_PORT_COUNTERS, ibmad_port)) {
		IBWARN("IB_GSI_PORT_COUNTERS query failed on %s, %s port %d\n",
		       nodename, portid2str(&portid), portnum);
		goto cleanup;
	}
	if (!(cap_mask & 0x1000)) {
		/* if PortCounters:PortXmitWait not suppported clear this counter */
		uint32_t foo = 0;
		mad_encode_field(pc, IB_PC_XMT_WAIT_F, &foo);
	}
	print_results(node, pc, portnum, header_printed);

cleanup:
	free(nodename);
}

void print_node(ibnd_node_t * node, void *user_data)
{
	int header_printed = 0;
	int p = 0;
	int startport = 1;

	if (!all_nodes && node->type != IB_NODE_SWITCH)
		return;

	if (node->type == IB_NODE_SWITCH && node->smaenhsp0)
		startport = 0;

	for (p = startport; p <= node->numports; p++) {
		if (node->ports[p]) {
			print_port(node, p, &header_printed);
		}
	}
}

static void add_suppressed(enum MAD_FIELDS field)
{
	suppressed_fields = realloc(suppressed_fields, sizeof(enum MAD_FIELDS));
	suppressed_fields[sup_total] = field;
	sup_total++;
}

static void calculate_suppressed_fields(char *str)
{
	enum MAD_FIELDS f;
	char *val, *lasts = NULL;
	char *tmp = strdup(str);

	val = strtok_r(tmp, ",", &lasts);
	while (val) {
		for (f = IB_PC_FIRST_F; f <= IB_PC_LAST_F; f++) {
			if (strcmp(val, mad_field_name(f)) == 0) {
				add_suppressed(f);
			}
		}
		val = strtok_r(NULL, ",", &lasts);
	}

	free(tmp);
}

static int process_opt(void *context, int ch, char *optarg)
{
	switch (ch) {
	case 's':
		calculate_suppressed_fields(optarg);
		break;
	case 'c':
		/* Right now this is the only "common" error */
		add_suppressed(IB_PC_ERR_SWITCH_REL_F);
		break;
	case 1:
		node_name_map_file = strdup(optarg);
		break;
	case 2:
		data_counters++;
		break;
	case 3:
		all_nodes++;
		break;
	case 'S':
		switch_guid_str = optarg;
		switch_guid = strtoull(optarg, 0, 0);
		break;
	case 'D':
		dr_path = strdup(optarg);
		break;
	case 'r':
		port_config++;
		break;
	case 'R':		/* nop */
		break;
	default:
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int resolved = -1;
	ib_portid_t portid = { 0 };
	int rc = 0;
	ibnd_fabric_t *fabric = NULL;

	int mgmt_classes[4] = { IB_SMI_CLASS, IB_SMI_DIRECT_CLASS, IB_SA_CLASS,
		IB_PERFORMANCE_CLASS
	};

	const struct ibdiag_opt opts[] = {
		{"suppress", 's', 1, "<err1,err2,...>",
		 "suppress errors listed"},
		{"suppress-common", 'c', 0, NULL,
		 "suppress some of the common counters"},
		{"node-name-map", 1, 1, "<file>", "node name map file"},
		{"switch", 'S', 1, "<switch_guid>",
		 "query only <switch_guid> (hex format)"},
		{"Direct", 'D', 1, "<dr_path>",
		 "query only switch specified by <dr_path>"},
		{"report-port", 'r', 0, NULL,
		 "report port configuration information"},
		{"GNDN", 'R', 0, NULL,
		 "(This option is obsolete and does nothing)"},
		{"data", 2, 0, NULL, "include the data counters in the output"},
		{"all", 3, 0, NULL, "output all nodes (not just switches)"},
		{0}
	};
	char usage_args[] = "";

	ibdiag_process_opts(argc, argv, NULL, "scnSrRDGL", opts, process_opt,
			    usage_args, NULL);

	argc -= optind;
	argv += optind;

	if (ibverbose)
		ibnd_debug(1);

	ibmad_port = mad_rpc_open_port(ibd_ca, ibd_ca_port, mgmt_classes, 4);
	if (!ibmad_port)
		IBERROR("Failed to open port; %s:%d\n", ibd_ca, ibd_ca_port);

	if (ibd_timeout)
		mad_rpc_set_timeout(ibmad_port, ibd_timeout);

	node_name_map = open_node_name_map(node_name_map_file);

	/* limit the scan the fabric around the target */
	if (dr_path) {
		if ((resolved =
		     ib_resolve_portid_str_via(&portid, dr_path, IB_DEST_DRPATH,
					       NULL, ibmad_port)) < 0)
			IBWARN("Failed to resolve %s; attempting full scan\n",
			       dr_path);
	} else if (switch_guid_str) {
		if ((resolved =
		     ib_resolve_portid_str_via(&portid, switch_guid_str,
					       IB_DEST_GUID, ibd_sm_id,
					       ibmad_port)) >= 0)
			IBWARN("Failed to resolve %s; attempting full scan\n",
			       switch_guid_str);
	}

	if (resolved >= 0)
		if ((fabric = ibnd_discover_fabric(ibmad_port, &portid,
						   0)) == NULL)
			IBWARN
			    ("Single node discover failed; attempting full scan\n");

	if (!fabric)		/* do a full scan */
		if ((fabric =
		     ibnd_discover_fabric(ibmad_port, NULL, -1)) == NULL) {
			fprintf(stderr, "discover failed\n");
			rc = 1;
			goto close_port;
		}

	report_suppressed();

	if (switch_guid_str) {
		ibnd_node_t *node = ibnd_find_node_guid(fabric, switch_guid);
		if (node)
			print_node(node, NULL);
		else
			fprintf(stderr, "Failed to find node: %s\n",
				switch_guid_str);
	} else if (dr_path) {
		ibnd_node_t *node = ibnd_find_node_dr(fabric, dr_path);
		uint8_t ni[IB_SMP_DATA_SIZE];

		if (!smp_query_via(ni, &portid, IB_ATTR_NODE_INFO, 0,
				   ibd_timeout, ibmad_port))
			return -1;
		mad_decode_field(ni, IB_NODE_GUID_F, &(switch_guid));

		node = ibnd_find_node_guid(fabric, switch_guid);
		if (node)
			print_node(node, NULL);
		else
			fprintf(stderr, "Failed to find node: %s\n", dr_path);
	} else
		ibnd_iter_nodes(fabric, print_node, NULL);

	ibnd_destroy_fabric(fabric);

close_port:
	mad_rpc_close_port(ibmad_port);
	close_node_name_map(node_name_map);
	exit(rc);
}
