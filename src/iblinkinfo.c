/*
 * Copyright (c) 2004-2009 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2007 Xsigo Systems Inc.  All rights reserved.
 * Copyright (c) 2008 Lawrence Livermore National Lab.  All rights reserved.
 * Copyright (c) 2010 Mellanox Technologies LTD.  All rights reserved.
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

#include "ibdiag_common.h"

static char *node_name_map_file = NULL;
static nn_map_t *node_name_map = NULL;
static char *load_cache_file = NULL;

static uint64_t guid = 0;
static char *guid_str = NULL;
static char *dr_path = NULL;
static int all = 0;

static int down_links_only = 0;
static int line_mode = 0;
static int add_sw_settings = 0;
static int print_port_guids = 0;

static unsigned int get_max(unsigned int num)
{
	unsigned r = 0;		// r will be lg(num)

	while (num >>= 1)	// unroll for more speed...
		r++;

	return (1 << r);
}

void get_msg(char *width_msg, char *speed_msg, int msg_size, ibnd_port_t * port)
{
	char buf[64];
	uint32_t max_speed = 0;

	uint32_t max_width = get_max(mad_get_field(port->info, 0,
						   IB_PORT_LINK_WIDTH_SUPPORTED_F)
				     & mad_get_field(port->remoteport->info, 0,
						     IB_PORT_LINK_WIDTH_SUPPORTED_F));
	if ((max_width & mad_get_field(port->info, 0,
				       IB_PORT_LINK_WIDTH_ACTIVE_F)) == 0)
		// we are not at the max supported width
		// print what we could be at.
		snprintf(width_msg, msg_size, "Could be %s",
			 mad_dump_val(IB_PORT_LINK_WIDTH_ACTIVE_F,
				      buf, 64, &max_width));

	max_speed = get_max(mad_get_field(port->info, 0,
					  IB_PORT_LINK_SPEED_SUPPORTED_F)
			    & mad_get_field(port->remoteport->info, 0,
					    IB_PORT_LINK_SPEED_SUPPORTED_F));
	if ((max_speed & mad_get_field(port->info, 0,
				       IB_PORT_LINK_SPEED_ACTIVE_F)) == 0)
		// we are not at the max supported speed
		// print what we could be at.
		snprintf(speed_msg, msg_size, "Could be %s",
			 mad_dump_val(IB_PORT_LINK_SPEED_ACTIVE_F,
				      buf, 64, &max_speed));
}

void print_port(ibnd_node_t * node, ibnd_port_t * port)
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

	/* C14-24.2.1 states that a down port allows for invalid data to be
	 * returned for all PortInfo components except PortState and
	 * PortPhysicalState */
	if (istate != IB_LINK_DOWN) {
		n = snprintf(link_str, 256, "(%3s %9s %6s/%8s)",
		     mad_dump_val(IB_PORT_LINK_WIDTH_ACTIVE_F, width, 64,
				  &iwidth),
		     mad_dump_val(IB_PORT_LINK_SPEED_ACTIVE_F, speed, 64,
				  &ispeed),
		     mad_dump_val(IB_PORT_STATE_F, state, 64, &istate),
		     mad_dump_val(IB_PORT_PHYS_STATE_F, physstate, 64,
				  &iphystate));
	} else {
		n = snprintf(link_str, 256, "(              %6s/%8s)",
		     mad_dump_val(IB_PORT_STATE_F, state, 64, &istate),
		     mad_dump_val(IB_PORT_PHYS_STATE_F, physstate, 64,
				  &iphystate));
	}

	/* again default values due to C14-24.2.1 */
	if (add_sw_settings && istate != IB_LINK_DOWN) {
		snprintf(link_str + n, 256 - n,
			" (HOQ:%d VL_Stall:%d)",
			mad_get_field(port->info, 0,
				IB_PORT_HOQ_LIFE_F),
			mad_get_field(port->info, 0,
				IB_PORT_VL_STALL_COUNT_F));
	}

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

		if (line_mode) {
			if (print_port_guids)
				snprintf(remote_guid_str, 256,
					 "0x%016" PRIx64 " ",
					 port->remoteport->guid);
			else
				snprintf(remote_guid_str, 256,
					 "0x%016" PRIx64 " ",
					 port->remoteport->node->guid);
		}

		snprintf(remote_str, 256, "%s%6d %4d[%2s] \"%s\" (%s %s)\n",
			 remote_guid_str, port->remoteport->base_lid ?
			 port->remoteport->base_lid :
			 port->remoteport->node->smalid,
			 port->remoteport->portnum, ext_port_str, remap,
			 width_msg, speed_msg);
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
		printf("0x%016" PRIx64 " \"%30s\" ", node->guid, remap);
		free(remap);
	} else
		printf("      ");

	printf("%6d %4d[%2s] ==%s==>  %s",
	       node->smalid, port->portnum, ext_port_str, link_str, remote_str);
}

void print_switch(ibnd_node_t * node, void *user_data)
{
	int i = 0;
	int head_print = 0;
	char *remap =
	    remap_node_name(node_name_map, node->guid, node->nodedesc);

	for (i = 1; i <= node->numports; i++) {
		ibnd_port_t *port = node->ports[i];
		if (!port)
			continue;
		if (!down_links_only ||
		    mad_get_field(port->info, 0,
				  IB_PORT_STATE_F) == IB_LINK_DOWN) {
			if (!head_print && !line_mode) {
				printf("Switch 0x%016" PRIx64 " %s:\n",
				       node->guid, remap);
				head_print = 1;
			}
			print_port(node, port);
		}
	}
	free(remap);
}

static int process_opt(void *context, int ch, char *optarg)
{
	struct ibnd_config *cfg = context;
	switch (ch) {
	case 1:
		node_name_map_file = strdup(optarg);
		break;
	case 2:
		load_cache_file = strdup(optarg);
		break;
	case 'S':
		guid_str = optarg;
		guid = (uint64_t) strtoull(guid_str, 0, 0);
		break;
	case 'D':
		dr_path = strdup(optarg);
		break;
	case 'a':
		all = 1;
		break;
	case 'n':
		cfg->max_hops = strtoul(optarg, NULL, 0);
		break;
	case 'd':
		down_links_only = 1;
		break;
	case 'l':
		line_mode = 1;
		break;
	case 'p':
		add_sw_settings = 1;
		break;
	case 'g':
		print_port_guids = 1;
		break;
	case 'R':		/* nop */
		break;
	case 'o':
		cfg->max_smps = strtoul(optarg, NULL, 0);
		break;
	default:
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ibnd_config config = { 0 };
	int rc = 0;
	int resolved = -1;
	ibnd_fabric_t *fabric = NULL;
	struct ibmad_port *ibmad_port;
	ib_portid_t port_id = { 0 };
	int mgmt_classes[3] =
	    { IB_SMI_CLASS, IB_SMI_DIRECT_CLASS, IB_SA_CLASS };

	const struct ibdiag_opt opts[] = {
		{"node-name-map", 1, 1, "<file>", "node name map file"},
		{"switch", 'S', 1, "<switch_guid>",
		 "query only <switch_guid> (hex format)"},
		{"Direct", 'D', 1, "<dr_path>",
		 "query only node specified by <dr_path>"},
		{"all", 'a', 0, NULL,
		 "print all switches found in a partial fabric scan"},
		{"hops", 'n', 1, "<hops>",
		 "Number of hops to include away from specified node"},
		{"down", 'd', 0, NULL, "print only down links"},
		{"line", 'l', 0, NULL,
		 "(line mode) print all information for each link on a single line"},
		{"additional", 'p', 0, NULL,
		 "print additional switch settings (PktLifeTime, HoqLife, VLStallCount)"},
		{"portguids", 'g', 0, NULL,
		 "print port guids instead of node guids"},
		{"load-cache", 2, 1, "<file>",
		 "filename of ibnetdiscover cache to load"},
		{"outstanding_smps", 'o', 1, NULL,
		 "specify the number of outstanding SMP's which should be "
		 "issued during the scan"},
		{"GNDN", 'R', 0, NULL,
		 "(This option is obsolete and does nothing)"},
		{0}
	};
	char usage_args[] = "";

	ibdiag_process_opts(argc, argv, &config, "SDandlpgRGL", opts,
			    process_opt, usage_args, NULL);

	argc -= optind;
	argv += optind;

	ibmad_port = mad_rpc_open_port(ibd_ca, ibd_ca_port, mgmt_classes, 3);
	if (!ibmad_port) {
		fprintf(stderr, "Failed to open %s port %d", ibd_ca,
			ibd_ca_port);
		exit(1);
	}

	if (ibd_timeout) {
		mad_rpc_set_timeout(ibmad_port, ibd_timeout);
		config.timeout_ms = ibd_timeout;
	}

	node_name_map = open_node_name_map(node_name_map_file);

	if (dr_path && load_cache_file) {
		fprintf(stderr, "Cannot specify cache and direct route path\n");
		exit(1);
	}

	if (dr_path) {
		/* only scan part of the fabric */
		if ((resolved =
		     ib_resolve_portid_str_via(&port_id, dr_path,
					       IB_DEST_DRPATH, NULL,
					       ibmad_port)) < 0)
			IBWARN("Failed to resolve %s; attempting full scan\n",
			       dr_path);
	} else if (guid_str) {
		if ((resolved =
		     ib_resolve_portid_str_via(&port_id, guid_str, IB_DEST_GUID,
					       NULL, ibmad_port)) < 0)
			IBWARN("Failed to resolve %s; attempting full scan\n",
			       guid_str);
	}

	if (load_cache_file) {
		if ((fabric = ibnd_load_fabric(load_cache_file, 0)) == NULL) {
			fprintf(stderr, "loading cached fabric failed\n");
			exit(1);
		}
	} else {
		if (resolved >= 0) {
			if (!config.max_hops)
				config.max_hops = 1;
			if (!(fabric =
			    ibnd_discover_fabric(ibd_ca, ibd_ca_port, &port_id, &config)))
				IBWARN("Single node discover failed;"
				       " attempting full scan\n");
		}

		if (!fabric &&
		    !(fabric = ibnd_discover_fabric(ibd_ca, ibd_ca_port, NULL, &config))) {
			fprintf(stderr, "discover failed\n");
			rc = 1;
			goto close_port;
		}
	}

	if (!all && guid_str) {
		ibnd_node_t *sw = ibnd_find_node_guid(fabric, guid);
		if (sw && sw->type == IB_NODE_TYPE_SWITCH)
			print_switch(sw, NULL);
		else
			fprintf(stderr, "Failed to find switch: %s\n",
				guid_str);
	} else if (!all && dr_path) {
		ibnd_node_t *sw = NULL;
		uint8_t ni[IB_SMP_DATA_SIZE];

		if (!smp_query_via(ni, &port_id, IB_ATTR_NODE_INFO, 0,
				   ibd_timeout, ibmad_port))
			return -1;
		mad_decode_field(ni, IB_NODE_GUID_F, &(guid));

		sw = ibnd_find_node_guid(fabric, guid);
		if (sw && sw->type == IB_NODE_TYPE_SWITCH)
			print_switch(sw, NULL);
		else
			fprintf(stderr, "Failed to find switch: %s\n", dr_path);
	} else
		ibnd_iter_nodes_type(fabric, print_switch, IB_NODE_SWITCH,
				     NULL);

	ibnd_destroy_fabric(fabric);

close_port:
	close_node_name_map(node_name_map);
	mad_rpc_close_port(ibmad_port);
	exit(rc);
}
