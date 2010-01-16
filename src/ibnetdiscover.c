/*
 * Copyright (c) 2004-2009 Voltaire Inc.  All rights reserved.
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
#include <time.h>
#include <string.h>
#include <getopt.h>
#include <inttypes.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>
#include <complib/cl_nodenamemap.h>
#include <infiniband/ibnetdisc.h>

#include "ibdiag_common.h"

#define LIST_CA_NODE	 (1 << IB_NODE_CA)
#define LIST_SWITCH_NODE (1 << IB_NODE_SWITCH)
#define LIST_ROUTER_NODE (1 << IB_NODE_ROUTER)

struct ibmad_port *srcport;

static FILE *f;

static char *node_name_map_file = NULL;
static nn_map_t *node_name_map = NULL;
static char *cache_file = NULL;
static char *load_cache_file = NULL;

static int report_max_hops = 0;

/**
 * Define our own conversion functions to maintain compatibility with the old
 * ibnetdiscover which did not use the ibmad conversion functions.
 */
char *dump_linkspeed_compat(uint32_t speed)
{
	switch (speed) {
	case 1:
		return ("SDR");
		break;
	case 2:
		return ("DDR");
		break;
	case 4:
		return ("QDR");
		break;
	}
	return ("???");
}

char *dump_linkwidth_compat(uint32_t width)
{
	switch (width) {
	case 1:
		return ("1x");
		break;
	case 2:
		return ("4x");
		break;
	case 4:
		return ("8x");
		break;
	case 8:
		return ("12x");
		break;
	}
	return ("??");
}

static inline const char *ports_nt_str_compat(ibnd_node_t * node)
{
	switch (node->type) {
	case IB_NODE_SWITCH:
		return "SW";
	case IB_NODE_CA:
		return "CA";
	case IB_NODE_ROUTER:
		return "RT";
	}
	return "??";
}

char *node_name(ibnd_node_t * node)
{
	static char buf[256];

	switch (node->type) {
	case IB_NODE_SWITCH:
		sprintf(buf, "\"%s", "S");
		break;
	case IB_NODE_CA:
		sprintf(buf, "\"%s", "H");
		break;
	case IB_NODE_ROUTER:
		sprintf(buf, "\"%s", "R");
		break;
	default:
		sprintf(buf, "\"%s", "?");
		break;
	}
	sprintf(buf + 2, "-%016" PRIx64 "\"", node->guid);

	return buf;
}

void list_node(ibnd_node_t * node, void *user_data)
{
	char *node_type;
	char *nodename = remap_node_name(node_name_map, node->guid,
					 node->nodedesc);

	switch (node->type) {
	case IB_NODE_SWITCH:
		node_type = "Switch";
		break;
	case IB_NODE_CA:
		node_type = "Ca";
		break;
	case IB_NODE_ROUTER:
		node_type = "Router";
		break;
	default:
		node_type = "???";
		break;
	}
	fprintf(f,
		"%s\t : 0x%016" PRIx64
		" ports %d devid 0x%x vendid 0x%x \"%s\"\n", node_type,
		node->guid, node->numports, mad_get_field(node->info, 0,
							  IB_NODE_DEVID_F),
		mad_get_field(node->info, 0, IB_NODE_VENDORID_F), nodename);

	free(nodename);
}

void list_nodes(ibnd_fabric_t * fabric, int list)
{
	if (list & LIST_CA_NODE)
		ibnd_iter_nodes_type(fabric, list_node, IB_NODE_CA, NULL);
	if (list & LIST_SWITCH_NODE)
		ibnd_iter_nodes_type(fabric, list_node, IB_NODE_SWITCH, NULL);
	if (list & LIST_ROUTER_NODE)
		ibnd_iter_nodes_type(fabric, list_node, IB_NODE_ROUTER, NULL);
}

void out_ids(ibnd_node_t * node, int group, char *chname)
{
	uint64_t sysimgguid =
	    mad_get_field64(node->info, 0, IB_NODE_SYSTEM_GUID_F);

	fprintf(f, "\nvendid=0x%x\ndevid=0x%x\n",
		mad_get_field(node->info, 0, IB_NODE_VENDORID_F),
		mad_get_field(node->info, 0, IB_NODE_DEVID_F));
	if (sysimgguid)
		fprintf(f, "sysimgguid=0x%" PRIx64, sysimgguid);
	if (group && node->chassis && node->chassis->chassisnum) {
		fprintf(f, "\t\t# Chassis %d", node->chassis->chassisnum);
		if (chname)
			fprintf(f, " (%s)", clean_nodedesc(chname));
		if (ibnd_is_xsigo_tca(node->guid) && node->ports[1] &&
		    node->ports[1]->remoteport)
			fprintf(f, " slot %d",
				node->ports[1]->remoteport->portnum);
	}
	fprintf(f, "\n");
}

uint64_t out_chassis(ibnd_fabric_t * fabric, unsigned char chassisnum)
{
	uint64_t guid;

	fprintf(f, "\nChassis %u", chassisnum);
	guid = ibnd_get_chassis_guid(fabric, chassisnum);
	if (guid)
		fprintf(f, " (guid 0x%" PRIx64 ")", guid);
	fprintf(f, "\n");
	return guid;
}

void out_switch(ibnd_node_t * node, int group, char *chname)
{
	char *str;
	char str2[256];
	char *nodename = NULL;

	out_ids(node, group, chname);
	fprintf(f, "switchguid=0x%" PRIx64, node->guid);
	fprintf(f, "(%" PRIx64 ")",
		mad_get_field64(node->info, 0, IB_NODE_PORT_GUID_F));
	if (group) {
		fprintf(f, "\t# ");
		str = ibnd_get_chassis_type(node);
		if (str)
			fprintf(f, "%s ", str);
		str = ibnd_get_chassis_slot_str(node, str2, 256);
		if (str)
			fprintf(f, "%s", str);
	}

	nodename = remap_node_name(node_name_map, node->guid, node->nodedesc);

	fprintf(f, "\nSwitch\t%d %s\t\t# \"%s\" %s port 0 lid %d lmc %d\n",
		node->numports, node_name(node), nodename,
		node->smaenhsp0 ? "enhanced" : "base",
		node->smalid, node->smalmc);

	free(nodename);
}

void out_ca(ibnd_node_t * node, int group, char *chname)
{
	char *node_type;
	char *node_type2;

	out_ids(node, group, chname);
	switch (node->type) {
	case IB_NODE_CA:
		node_type = "ca";
		node_type2 = "Ca";
		break;
	case IB_NODE_ROUTER:
		node_type = "rt";
		node_type2 = "Rt";
		break;
	default:
		node_type = "???";
		node_type2 = "???";
		break;
	}

	fprintf(f, "%sguid=0x%" PRIx64 "\n", node_type, node->guid);
	fprintf(f, "%s\t%d %s\t\t# \"%s\"",
		node_type2, node->numports, node_name(node),
		clean_nodedesc(node->nodedesc));
	if (group && ibnd_is_xsigo_hca(node->guid))
		fprintf(f, " (scp)");
	fprintf(f, "\n");
}

#define OUT_BUFFER_SIZE 16
static char *out_ext_port(ibnd_port_t * port, int group)
{
	static char mapping[OUT_BUFFER_SIZE];

	if (group && port->ext_portnum != 0) {
		snprintf(mapping, OUT_BUFFER_SIZE,
			 "[ext %d]", port->ext_portnum);
		return (mapping);
	}

	return (NULL);
}

void out_switch_port(ibnd_port_t * port, int group)
{
	char *ext_port_str = NULL;
	char *rem_nodename = NULL;
	uint32_t iwidth = mad_get_field(port->info, 0,
					IB_PORT_LINK_WIDTH_ACTIVE_F);
	uint32_t ispeed = mad_get_field(port->info, 0,
					IB_PORT_LINK_SPEED_ACTIVE_F);

	DEBUG("port %p:%d remoteport %p\n", port, port->portnum,
	      port->remoteport);
	fprintf(f, "[%d]", port->portnum);

	ext_port_str = out_ext_port(port, group);
	if (ext_port_str)
		fprintf(f, "%s", ext_port_str);

	rem_nodename = remap_node_name(node_name_map,
				       port->remoteport->node->guid,
				       port->remoteport->node->nodedesc);

	ext_port_str = out_ext_port(port->remoteport, group);
	fprintf(f, "\t%s[%d]%s",
		node_name(port->remoteport->node), port->remoteport->portnum,
		ext_port_str ? ext_port_str : "");
	if (port->remoteport->node->type != IB_NODE_SWITCH)
		fprintf(f, "(%" PRIx64 ") ", port->remoteport->guid);
	fprintf(f, "\t\t# \"%s\" lid %d %s%s",
		rem_nodename,
		port->remoteport->node->type == IB_NODE_SWITCH ?
		port->remoteport->node->smalid :
		port->remoteport->base_lid,
		dump_linkwidth_compat(iwidth), dump_linkspeed_compat(ispeed));

	if (ibnd_is_xsigo_tca(port->remoteport->guid))
		fprintf(f, " slot %d", port->portnum);
	else if (ibnd_is_xsigo_hca(port->remoteport->guid))
		fprintf(f, " (scp)");
	fprintf(f, "\n");

	free(rem_nodename);
}

void out_ca_port(ibnd_port_t * port, int group)
{
	char *str = NULL;
	char *rem_nodename = NULL;
	uint32_t iwidth = mad_get_field(port->info, 0,
					IB_PORT_LINK_WIDTH_ACTIVE_F);
	uint32_t ispeed = mad_get_field(port->info, 0,
					IB_PORT_LINK_SPEED_ACTIVE_F);

	fprintf(f, "[%d]", port->portnum);
	if (port->node->type != IB_NODE_SWITCH)
		fprintf(f, "(%" PRIx64 ") ", port->guid);
	fprintf(f, "\t%s[%d]",
		node_name(port->remoteport->node), port->remoteport->portnum);
	str = out_ext_port(port->remoteport, group);
	if (str)
		fprintf(f, "%s", str);
	if (port->remoteport->node->type != IB_NODE_SWITCH)
		fprintf(f, " (%" PRIx64 ") ", port->remoteport->guid);

	rem_nodename = remap_node_name(node_name_map,
				       port->remoteport->node->guid,
				       port->remoteport->node->nodedesc);

	fprintf(f, "\t\t# lid %d lmc %d \"%s\" lid %d %s%s\n",
		port->base_lid, port->lmc, rem_nodename,
		port->remoteport->node->type == IB_NODE_SWITCH ?
		port->remoteport->node->smalid :
		port->remoteport->base_lid,
		dump_linkwidth_compat(iwidth), dump_linkspeed_compat(ispeed));

	free(rem_nodename);
}

struct iter_user_data {
	int group;
	int skip_chassis_nodes;
};

static void switch_iter_func(ibnd_node_t * node, void *iter_user_data)
{
	ibnd_port_t *port;
	int p = 0;
	struct iter_user_data *data = (struct iter_user_data *)iter_user_data;

	DEBUG("SWITCH: node %p\n", node);

	/* skip chassis based switches if flagged */
	if (data->skip_chassis_nodes && node->chassis
	    && node->chassis->chassisnum)
		return;

	out_switch(node, data->group, NULL);
	for (p = 1; p <= node->numports; p++) {
		port = node->ports[p];
		if (port && port->remoteport)
			out_switch_port(port, data->group);
	}
}

static void ca_iter_func(ibnd_node_t * node, void *iter_user_data)
{
	ibnd_port_t *port;
	int p = 0;
	struct iter_user_data *data = (struct iter_user_data *)iter_user_data;

	DEBUG("CA: node %p\n", node);
	/* Now, skip chassis based CAs */
	if (data->group && node->chassis && node->chassis->chassisnum)
		return;
	out_ca(node, data->group, NULL);

	for (p = 1; p <= node->numports; p++) {
		port = node->ports[p];
		if (port && port->remoteport)
			out_ca_port(port, data->group);
	}
}

static void router_iter_func(ibnd_node_t * node, void *iter_user_data)
{
	ibnd_port_t *port;
	int p = 0;
	struct iter_user_data *data = (struct iter_user_data *)iter_user_data;

	DEBUG("RT: node %p\n", node);
	/* Now, skip chassis based RTs */
	if (data->group && node->chassis && node->chassis->chassisnum)
		return;
	out_ca(node, data->group, NULL);
	for (p = 1; p <= node->numports; p++) {
		port = node->ports[p];
		if (port && port->remoteport)
			out_ca_port(port, data->group);
	}
}

int dump_topology(int group, ibnd_fabric_t * fabric)
{
	ibnd_node_t *node;
	ibnd_port_t *port;
	int i = 0, p = 0;
	time_t t = time(0);
	uint64_t chguid;
	char *chname = NULL;
	struct iter_user_data iter_user_data;

	fprintf(f, "#\n# Topology file: generated on %s#\n", ctime(&t));
	if (report_max_hops)
		fprintf(f, "# Reported max hops discovered: %d\n",
			fabric->maxhops_discovered);
	fprintf(f, "# Initiated from node %016" PRIx64 " port %016" PRIx64 "\n",
		fabric->from_node->guid,
		mad_get_field64(fabric->from_node->info, 0,
				IB_NODE_PORT_GUID_F));

	/* Make pass on switches */
	if (group) {
		ibnd_chassis_t *ch = NULL;

		/* Chassis based switches first */
		for (ch = fabric->chassis; ch; ch = ch->next) {
			int n = 0;

			if (!ch->chassisnum)
				continue;
			chguid = out_chassis(fabric, ch->chassisnum);

			chname = NULL;
/**
 * Will this work for Xsigo?
 */
			if (ibnd_is_xsigo_guid(chguid)) {
				for (node = ch->nodes; node;
				     node = node->next_chassis_node) {
					if (ibnd_is_xsigo_hca(node->guid)) {
						chname = node->nodedesc;
						fprintf(f, "Hostname: %s\n",
							clean_nodedesc
							(node->nodedesc));
					}
				}
			}

			fprintf(f, "\n# Spine Nodes");
			for (n = 1; n <= SPINES_MAX_NUM; n++) {
				if (ch->spinenode[n]) {
					out_switch(ch->spinenode[n], group,
						   chname);
					for (p = 1;
					     p <= ch->spinenode[n]->numports;
					     p++) {
						port =
						    ch->spinenode[n]->ports[p];
						if (port && port->remoteport)
							out_switch_port(port,
									group);
					}
				}
			}
			fprintf(f, "\n# Line Nodes");
			for (n = 1; n <= LINES_MAX_NUM; n++) {
				if (ch->linenode[n]) {
					out_switch(ch->linenode[n], group,
						   chname);
					for (p = 1;
					     p <= ch->linenode[n]->numports;
					     p++) {
						port =
						    ch->linenode[n]->ports[p];
						if (port && port->remoteport)
							out_switch_port(port,
									group);
					}
				}
			}

			fprintf(f, "\n# Chassis Switches");
			for (node = ch->nodes; node;
			     node = node->next_chassis_node) {
				if (node->type == IB_NODE_SWITCH) {
					out_switch(node, group, chname);
					for (p = 1; p <= node->numports; p++) {
						port = node->ports[p];
						if (port && port->remoteport)
							out_switch_port(port,
									group);
					}
				}

			}

			fprintf(f, "\n# Chassis CAs");
			for (node = ch->nodes; node;
			     node = node->next_chassis_node) {
				if (node->type == IB_NODE_CA) {
					out_ca(node, group, chname);
					for (p = 1; p <= node->numports; p++) {
						port = node->ports[p];
						if (port && port->remoteport)
							out_ca_port(port,
								    group);
					}
				}
			}

		}

	} else {		/* !group */
		iter_user_data.group = group;
		iter_user_data.skip_chassis_nodes = 0;
		ibnd_iter_nodes_type(fabric, switch_iter_func,
				     IB_NODE_SWITCH, &iter_user_data);
	}

	chname = NULL;
	if (group) {
		iter_user_data.group = group;
		iter_user_data.skip_chassis_nodes = 1;

		fprintf(f, "\nNon-Chassis Nodes\n");

		ibnd_iter_nodes_type(fabric, switch_iter_func,
				     IB_NODE_SWITCH, &iter_user_data);
	}

	iter_user_data.group = group;
	iter_user_data.skip_chassis_nodes = 0;
	/* Make pass on CAs */
	ibnd_iter_nodes_type(fabric, ca_iter_func, IB_NODE_CA, &iter_user_data);

	/* Make pass on routers */
	ibnd_iter_nodes_type(fabric, router_iter_func, IB_NODE_ROUTER,
			     &iter_user_data);

	return i;
}

void dump_ports_report(ibnd_node_t * node, void *user_data)
{
	int p = 0;
	ibnd_port_t *port = NULL;

	/* for each port */
	for (p = node->numports, port = node->ports[p]; p > 0;
	     port = node->ports[--p]) {
		uint32_t iwidth, ispeed;
		if (port == NULL)
			continue;
		iwidth =
		    mad_get_field(port->info, 0, IB_PORT_LINK_WIDTH_ACTIVE_F);
		ispeed =
		    mad_get_field(port->info, 0, IB_PORT_LINK_SPEED_ACTIVE_F);
		fprintf(stdout, "%2s %5d %2d 0x%016" PRIx64 " %s %s",
			ports_nt_str_compat(node),
			node->type ==
			IB_NODE_SWITCH ? node->smalid : port->base_lid,
			port->portnum, port->guid,
			dump_linkwidth_compat(iwidth),
			dump_linkspeed_compat(ispeed));
		if (port->remoteport)
			fprintf(stdout,
				" - %2s %5d %2d 0x%016" PRIx64
				" ( '%s' - '%s' )\n",
				ports_nt_str_compat(port->remoteport->node),
				port->remoteport->node->type == IB_NODE_SWITCH ?
				port->remoteport->node->smalid :
				port->remoteport->base_lid,
				port->remoteport->portnum,
				port->remoteport->guid, port->node->nodedesc,
				port->remoteport->node->nodedesc);
		else
			fprintf(stdout, "%36s'%s'\n", "", port->node->nodedesc);
	}
}

static int list, group, ports_report;

static int process_opt(void *context, int ch, char *optarg)
{
	switch (ch) {
	case 1:
		node_name_map_file = strdup(optarg);
		break;
	case 2:
		cache_file = strdup(optarg);
		break;
	case 3:
		load_cache_file = strdup(optarg);
		break;
	case 's':
		ibnd_show_progress(1);
		break;
	case 'l':
		list = LIST_CA_NODE | LIST_SWITCH_NODE | LIST_ROUTER_NODE;
		break;
	case 'g':
		group = 1;
		break;
	case 'S':
		list = LIST_SWITCH_NODE;
		break;
	case 'H':
		list = LIST_CA_NODE;
		break;
	case 'R':
		list = LIST_ROUTER_NODE;
		break;
	case 'p':
		ports_report = 1;
		break;
	case 'm':
		report_max_hops = 1;
		break;
	default:
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	ibnd_fabric_t *fabric = NULL;

	struct ibmad_port *ibmad_port;
	int mgmt_classes[2] = { IB_SMI_CLASS, IB_SMI_DIRECT_CLASS };

	const struct ibdiag_opt opts[] = {
		{"show", 's', 0, NULL, "show more information"},
		{"list", 'l', 0, NULL, "list of connected nodes"},
		{"grouping", 'g', 0, NULL, "show grouping"},
		{"Hca_list", 'H', 0, NULL, "list of connected CAs"},
		{"Switch_list", 'S', 0, NULL, "list of connected switches"},
		{"Router_list", 'R', 0, NULL, "list of connected routers"},
		{"node-name-map", 1, 1, "<file>", "node name map file"},
		{"cache", 2, 1, "<file>",
		 "filename to cache ibnetdiscover data to"},
		{"load-cache", 3, 1, "<file>",
		 "filename of ibnetdiscover cache to load"},
		{"ports", 'p', 0, NULL, "obtain a ports report"},
		{"max_hops", 'm', 0, NULL,
		 "report max hops discovered by the library"},
		{0}
	};
	char usage_args[] = "[topology-file]";

	ibdiag_process_opts(argc, argv, NULL, "sGDL", opts, process_opt,
			    usage_args, NULL);

	f = stdout;

	argc -= optind;
	argv += optind;

	if (ibverbose)
		ibnd_debug(1);

	ibmad_port = mad_rpc_open_port(ibd_ca, ibd_ca_port, mgmt_classes, 2);
	if (!ibmad_port)
		IBERROR("Failed to open %s port %d", ibd_ca, ibd_ca_port);

	if (ibd_timeout)
		mad_rpc_set_timeout(ibmad_port, ibd_timeout);

	if (argc && !(f = fopen(argv[0], "w")))
		IBERROR("can't open file %s for writing", argv[0]);

	node_name_map = open_node_name_map(node_name_map_file);

	if (load_cache_file) {
		if ((fabric = ibnd_load_fabric(load_cache_file, 0)) == NULL)
			IBERROR("loading cached fabric failed\n");
	} else {
		if ((fabric =
		     ibnd_discover_fabric(ibmad_port, NULL, -1)) == NULL)
			IBERROR("discover failed\n");
	}

	if (ports_report)
		ibnd_iter_nodes(fabric, dump_ports_report, NULL);
	else if (list)
		list_nodes(fabric, list);
	else
		dump_topology(group, fabric);

	if (cache_file)
		if (ibnd_cache_fabric(fabric, cache_file, 0) < 0)
			IBERROR("caching ibnetdiscover data failed\n");

	ibnd_destroy_fabric(fabric);
	close_node_name_map(node_name_map);
	mad_rpc_close_port(ibmad_port);
	exit(0);
}
