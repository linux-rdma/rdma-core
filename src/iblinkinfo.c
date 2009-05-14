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
#endif /* HAVE_CONFIG_H */

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

char *argv0 = "iblinkinfotest";

static char *node_name_map_file = NULL;
static nn_map_t *node_name_map = NULL;

static int timeout_ms = 500;

static int down_links_only = 0;
static int line_mode = 0;
static int add_sw_settings = 0;
static int print_port_guids = 0;

static unsigned int
get_max(unsigned int num)
{
	unsigned int v = num; // 32-bit word to find the log base 2 of
	unsigned r = 0; // r will be lg(v)

	while (v >>= 1) // unroll for more speed...
	{
		r++;
	}

	return (1 << r);
}

void
get_msg(char *width_msg, char *speed_msg, int msg_size, ibnd_port_t *port)
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

void
print_port(ibnd_node_t *node, ibnd_port_t *port)
{
	char width[64], speed[64], state[64], physstate[64];
	char remote_guid_str[256];
	char remote_str[256];
	char link_str[256];
	char width_msg[256];
	char speed_msg[256];
	char ext_port_str[256];
	int iwidth, ispeed, istate, iphystate;
	int n = 0;

	if (!port)
		return;

	iwidth = mad_get_field(port->info, 0, IB_PORT_LINK_WIDTH_ACTIVE_F);
	ispeed = mad_get_field(port->info, 0, IB_PORT_LINK_SPEED_ACTIVE_F);
	istate = mad_get_field(port->info, 0, IB_PORT_STATE_F);
	iphystate = mad_get_field(port->info, 0, IB_PORT_PHYS_STATE_F);

	remote_guid_str[0] = '\0';
	remote_str[0] = '\0';
	link_str[0] = '\0';
	width_msg[0] = '\0';
	speed_msg[0] = '\0';

	n = snprintf(link_str, 256, "(%3s %s %6s/%8s)",
		mad_dump_val(IB_PORT_LINK_WIDTH_ACTIVE_F, width, 64, &iwidth),
		mad_dump_val(IB_PORT_LINK_SPEED_ACTIVE_F, speed, 64, &ispeed),
		mad_dump_val(IB_PORT_STATE_F, state, 64, &istate),
		mad_dump_val(IB_PORT_PHYS_STATE_F, physstate, 64, &iphystate));

	if (add_sw_settings)
		snprintf(link_str+n, 256-n,
			" (HOQ:%d VL_Stall:%d)",
			mad_get_field(port->info, 0, IB_PORT_HOQ_LIFE_F),
			mad_get_field(port->info, 0, IB_PORT_VL_STALL_COUNT_F));

	if (port->remoteport) {
		char *remap = remap_node_name(node_name_map, port->remoteport->node->guid,
				port->remoteport->node->nodedesc);

		if (port->remoteport->ext_portnum)
			snprintf(ext_port_str, 256, "%d", port->remoteport->ext_portnum);
		else
			ext_port_str[0] = '\0';

		get_msg(width_msg, speed_msg, 256, port);

		if (line_mode) {
			if (print_port_guids)
				snprintf(remote_guid_str, 256, "0x%016"PRIx64" ",
					port->remoteport->guid);
			else
				snprintf(remote_guid_str, 256, "0x%016"PRIx64" ",
					port->remoteport->node->guid);
		}

		snprintf(remote_str, 256,
			"%s%6d %4d[%2s] \"%s\" (%s %s)\n",
			remote_guid_str,
			port->remoteport->base_lid ?  port->remoteport->base_lid :
				port->remoteport->node->smalid,
			port->remoteport->portnum,
			ext_port_str,
			remap,
			width_msg,
			speed_msg);
		free(remap);
	} else
		snprintf(remote_str, 256, "           [  ] \"\" ( )\n");

	if (port->ext_portnum)
		snprintf(ext_port_str, 256, "%d", port->ext_portnum);
	else
		ext_port_str[0] = '\0';

	if (line_mode) {
		char *remap = remap_node_name(node_name_map, node->guid,
					node->nodedesc);
		printf("0x%016"PRIx64" \"%30s\" ", node->guid, remap);
		free(remap);
	} else
		printf("      ");

	printf("%6d %4d[%2s] ==%s==>  %s",
		node->smalid, port->portnum, ext_port_str, link_str, remote_str);
}

void
print_switch(ibnd_node_t *node, void *user_data)
{
	int i = 0;
	int head_print = 0;
	char *remap = remap_node_name(node_name_map, node->guid, node->nodedesc);

	for (i = 1; i <= node->numports; i++) {
		ibnd_port_t *port = node->ports[i];
		if (!port)
			continue;
		if (!down_links_only ||
				mad_get_field(port->info, 0, IB_PORT_STATE_F) == IB_LINK_DOWN) {
			if (!head_print && !line_mode) {
				printf("Switch 0x%016"PRIx64" %s:\n", node->guid, remap);
				head_print = 1;
			}
			print_port(node, port);
		}
	}
	free(remap);
}

void
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-hclp -S <guid> -D <direct route> -C <ca_name> -P <ca_port>]\n"
		"   Report link speed and connection for each port of each switch which is active\n"
		"   -h This help message\n"
		"   -S <guid> output only the node specified by guid\n"
		"   -D <direct route> print only node specified by <direct route>\n"
		"   -f <dr_path> specify node to start \"from\"\n"
		"   -n <hops> Number of hops to include away from specified node\n"
		"   -d print only down links\n"
		"   -l (line mode) print all information for each link on each line\n"
		"   -p print additional switch settings (PktLifeTime,HoqLife,VLStallCount)\n"


		"   -t <timeout_ms> timeout for any single fabric query\n"
		"   -s show progress during scan\n"
		"   --node-name-map <map_file> use specified node name map\n"

		"   -C <ca_name> use selected Channel Adaptor name for queries\n"
		"   -P <ca_port> use selected channel adaptor port for queries\n"
		"   -g print port guids instead of node guids\n"
		"   --debug print debug messages\n"
		"   -R (this option is obsolete and does nothing)\n"
		,
			argv0);
	exit(-1);
}

int
main(int argc, char **argv)
{
	int rc = 0;
	char *ca = 0;
	int ca_port = 0;
	ibnd_fabric_t *fabric = NULL;
	uint64_t guid = 0;
	char *guid_str = NULL;
	char *dr_path = NULL;
	char *from = NULL;
	int hops = 0;
	ib_portid_t port_id = {0};

	struct ibmad_port *ibmad_port;
	int mgmt_classes[3] = {IB_SMI_CLASS, IB_SMI_DIRECT_CLASS, IB_SA_CLASS};

	static char const str_opts[] = "S:D:n:C:P:t:sldgphuf:R";
	static const struct option long_opts[] = {
		{ "S", 1, 0, 'S'},
		{ "D", 1, 0, 'D'},
		{ "num-hops", 1, 0, 'n'},
		{ "down-links-only", 0, 0, 'd'},
		{ "line-mode", 0, 0, 'l'},
		{ "ca-name", 1, 0, 'C'},
		{ "ca-port", 1, 0, 'P'},
		{ "timeout", 1, 0, 't'},
		{ "show", 0, 0, 's'},
		{ "print-port-guids", 0, 0, 'g'},
		{ "print-additional", 0, 0, 'p'},
		{ "help", 0, 0, 'h'},
		{ "usage", 0, 0, 'u'},
		{ "node-name-map", 1, 0, 1},
		{ "debug", 0, 0, 2},
		{ "compat", 0, 0, 3},
		{ "from", 1, 0, 'f'},
		{ "R", 0, 0, 'R'},
		{ 0 }
	};

	argv0 = argv[0];

	while (1) {
		int ch = getopt_long(argc, argv, str_opts, long_opts, NULL);
		if ( ch == -1 )
			break;
		switch(ch) {
		case 1:
			node_name_map_file = strdup(optarg);
			break;
		case 2:
			ibnd_debug(1);
			break;
		case 'f':
			from = strdup(optarg);
			break;
		case 'C':
			ca = strdup(optarg);
			break;
		case 'P':
			ca_port = strtoul(optarg, 0, 0);
			break;
		case 'D':
			dr_path = strdup(optarg);
			break;
		case 'n':
			hops = (int)strtol(optarg, NULL, 0);
			break;
		case 'd':
			down_links_only = 1;
			break;
		case 'l':
			line_mode = 1;
			break;
		case 't':
			timeout_ms = strtoul(optarg, 0, 0);
			break;
		case 's':
			ibnd_show_progress(1);
			break;
		case 'g':
			print_port_guids = 1;
			break;
		case 'S':
			guid_str = optarg;
			guid = (uint64_t)strtoull(guid_str, 0, 0);
			break;
		case 'p':
			add_sw_settings = 1;
			break;
		case 'R':
			/* GNDN */
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	ibmad_port = mad_rpc_open_port(ca, ca_port, mgmt_classes, 3);
	if (!ibmad_port) {
		fprintf(stderr, "Failed to open %s port %d", ca, ca_port);
		exit(1);
	}

	node_name_map = open_node_name_map(node_name_map_file);

	if (from) {
		/* only scan part of the fabric */
		str2drpath(&(port_id.drpath), from, 0, 0);
		if ((fabric = ibnd_discover_fabric(ibmad_port, timeout_ms, &port_id, hops)) == NULL) {
			fprintf(stderr, "discover failed\n");
			rc = 1;
			goto close_port;
		}
		guid = 0;
	} else if (guid_str) {
		if (ib_resolve_portid_str_via(&port_id, guid_str, IB_DEST_GUID,
				NULL, ibmad_port) >= 0) {
			if ((fabric = ibnd_discover_fabric(ibmad_port,
					timeout_ms, &port_id, 1)) == NULL)
				IBWARN("Single node discover failed; attempting full scan\n");
		} else
			IBWARN("Failed to resolve %s; attempting full scan\n",
				guid_str);
	}

	if (!fabric) /* do a full scan */
		if ((fabric = ibnd_discover_fabric(ibmad_port, timeout_ms, NULL, -1)) == NULL) {
			fprintf(stderr, "discover failed\n");
			rc = 1;
			goto close_port;
		}

	if (guid_str) {
		ibnd_node_t *sw = ibnd_find_node_guid(fabric, guid);
		if (sw)
			print_switch(sw, NULL);
		else
			fprintf(stderr, "Failed to find switch: %s\n", guid_str);
	} else if (dr_path) {
		ibnd_node_t *sw = ibnd_find_node_dr(fabric, dr_path);
		if (sw)
			print_switch(sw, NULL);
		else
			fprintf(stderr, "Failed to find switch: %s\n", dr_path);
		print_switch(sw, NULL);
	} else {
		ibnd_iter_nodes_type(fabric, print_switch, IB_NODE_SWITCH, NULL);
	}

	ibnd_destroy_fabric(fabric);

close_port:
	close_node_name_map(node_name_map);
	mad_rpc_close_port(ibmad_port);
	exit(rc);
}
