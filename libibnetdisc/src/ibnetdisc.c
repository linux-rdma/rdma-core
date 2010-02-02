/*
 * Copyright (c) 2004-2009 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2007 Xsigo Systems Inc.  All rights reserved.
 * Copyright (c) 2008 Lawrence Livermore National Laboratory
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
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>

#include <infiniband/ibnetdisc.h>
#include <complib/cl_nodenamemap.h>

#include "internal.h"
#include "chassis.h"

static int show_progress = 0;
static int max_smps_on_wire = DEFAULT_MAX_SMP_ON_WIRE;
int ibdebug;

/* forward declare */
int query_node_info(smp_engine_t * engine, ib_portid_t * portid,
		    ibnd_node_t * node);


static int recv_switch_info(smp_engine_t *engine, ibnd_smp_t * smp,
			    uint8_t *mad, void *cb_data)
{
	uint8_t *switch_info = mad + IB_SMP_DATA_OFFS;
	ibnd_node_t * node = (ibnd_node_t *)cb_data;
	memcpy(node->switchinfo, switch_info, sizeof(node->switchinfo));
	mad_decode_field(node->switchinfo, IB_SW_ENHANCED_PORT0_F,
			 &node->smaenhsp0);
	return 0;
}
static int query_switch_info(smp_engine_t * engine, ib_portid_t * portid,
		      ibnd_node_t *node)
{
	node->smaenhsp0 = 0;	/* assume base SP0 */
	return (issue_smp(engine, portid, IB_ATTR_SWITCH_INFO, 0, recv_switch_info,
			  (void *)node));
}

static int add_port_to_dpath(ib_dr_path_t * path, int nextport)
{
	if (path->cnt + 2 >= sizeof(path->p)) {
		return -1;
	}
	++path->cnt;
	path->p[path->cnt] = (uint8_t) nextport;
	return path->cnt;
}

#if 0
static void retract_dpath(ib_portid_t * path)
{
	path->drpath.cnt--;	/* restore path */
	if (path->drpath.cnt == 0 && path->lid) {
		/* return to lid based routing on this path */
		path->drpath.drslid = 0;
		path->drpath.drdlid = 0;
	}
}
#endif

static int extend_dpath(smp_engine_t * engine, ib_portid_t * portid, int nextport)
{
	int rc = 0;
	ibnd_scan_t *scan = (ibnd_scan_t *)engine->user_data;
	ibnd_fabric_t *fabric = scan->fabric;

	if (portid->lid) {
		/* If we were LID routed we need to set up the drslid */
		if (!scan->selfportid.lid)
			if (ib_resolve_self_via(&scan->selfportid, NULL, NULL,
						engine->ibmad_port) < 0) {
				IBND_ERROR("Failed to resolve self\n");
				return -1;
			}

		portid->drpath.drslid = (uint16_t) scan->selfportid.lid;
		portid->drpath.drdlid = 0xFFFF;
	}

	rc = add_port_to_dpath(&portid->drpath, nextport);
	if (rc < 0)
		IBND_ERROR("add port %d to DR path failed; %s\n", nextport,
			   portid2str(portid));

	if (rc != -1 && portid->drpath.cnt > fabric->maxhops_discovered)
		fabric->maxhops_discovered = portid->drpath.cnt;
	return rc;
}

static int recv_node_desc(smp_engine_t * engine, ibnd_smp_t * smp,
			  uint8_t *mad, void *cb_data)
{
	uint8_t *node_desc = mad + IB_SMP_DATA_OFFS;
	ibnd_node_t *node = (ibnd_node_t *)cb_data;
	memcpy(node->nodedesc, node_desc, sizeof(node->nodedesc));
	return 0;
}

int query_node_desc(smp_engine_t * engine, ib_portid_t * portid, ibnd_node_t *node)
{
	return (issue_smp(engine, portid, IB_ATTR_NODE_DESC, 0, recv_node_desc,
			  (void *)node));
}

static void debug_port(ib_portid_t *portid, ibnd_port_t * port)
{
	char width[64], speed[64];
	int iwidth;
	int ispeed;

	iwidth = mad_get_field(port->info, 0, IB_PORT_LINK_WIDTH_ACTIVE_F);
	ispeed = mad_get_field(port->info, 0, IB_PORT_LINK_SPEED_ACTIVE_F);
	IBND_DEBUG
	    ("portid %s portnum %d: base lid %d state %d physstate %d %s %s\n",
	     portid2str(portid), port->portnum, port->base_lid,
	     mad_get_field(port->info, 0, IB_PORT_STATE_F),
	     mad_get_field(port->info, 0, IB_PORT_PHYS_STATE_F),
	     mad_dump_val(IB_PORT_LINK_WIDTH_ACTIVE_F, width, 64, &iwidth),
	     mad_dump_val(IB_PORT_LINK_SPEED_ACTIVE_F, speed, 64, &ispeed));
}

static int recv_port_info(smp_engine_t *engine, ibnd_smp_t * smp,
			  uint8_t *mad, void *cb_data)
{
	ibnd_fabric_t *fabric = ((ibnd_scan_t *)engine->user_data)->fabric;
	ibnd_node_t *node = (ibnd_node_t *)cb_data;
	ibnd_port_t *port;
	uint8_t *port_info = mad + IB_SMP_DATA_OFFS;
	uint8_t port_num, local_port;

	port_num = mad_get_field(mad, 0, IB_MAD_ATTRMOD_F);
	local_port = mad_get_field(port_info, 0, IB_PORT_LOCAL_PORT_F);

	/* this may have been created before */
	port = node->ports[port_num];
	if (!port) {
		port = node->ports[port_num] = calloc(1, sizeof(*port));
		if (!port) {
			IBND_ERROR("Failed to allocate port\n");
			return -1;
		}
	}

	memcpy(port->info, port_info, sizeof(port->info));
	port->node = node;
	port->portnum = port_num;
	port->ext_portnum = 0;
	port->base_lid = (uint16_t) mad_get_field(port->info, 0, IB_PORT_LID_F);
	port->lmc = (uint8_t) mad_get_field(port->info, 0, IB_PORT_LMC_F);

	if (port_num == 0) {
		node->smalid = port->base_lid;
		node->smalmc = port->lmc;
	} else if (node->type == IB_NODE_SWITCH) {
		port->base_lid = node->smalid;
		port->lmc = node->smalmc;
	}

	add_to_portguid_hash(port, fabric->portstbl);

	debug_port(&smp->path, port);

	if (port_num &&
	    (mad_get_field(port->info, 0, IB_PORT_PHYS_STATE_F)
	    == IB_PORT_PHYS_STATE_LINKUP)
		&&
	    (node->type == IB_NODE_SWITCH || node == fabric->from_node)) {

		ib_portid_t path = smp->path;
		if (extend_dpath(engine, &path, port_num) != -1)
			query_node_info(engine, &path, node);
	}

	return 0;
}
int query_port_info(smp_engine_t * engine, ib_portid_t * portid,
		    ibnd_node_t *node, int portnum)
{
	IBND_DEBUG("Query Port Info; %s (%lx):%d\n", portid2str(portid),
		   node->guid, portnum);
	return (issue_smp(engine, portid, IB_ATTR_PORT_INFO, portnum, recv_port_info,
			  (void *)node));
}

static ibnd_node_t *create_node(smp_engine_t * engine, ib_portid_t * path,
				uint8_t *node_info)
{
	ibnd_fabric_t *fabric = ((ibnd_scan_t *)engine->user_data)->fabric;
	ibnd_node_t *rc = calloc(1, sizeof(*rc));
	if (!rc) {
		IBND_ERROR("OOM: node creation failed\n");
		return NULL;
	}

	/* decode just a couple of fields for quicker reference. */
	mad_decode_field(node_info, IB_NODE_GUID_F, &(rc->guid));
	mad_decode_field(node_info, IB_NODE_TYPE_F, &(rc->type));
	mad_decode_field(node_info, IB_NODE_NPORTS_F, &(rc->numports));

	rc->ports = calloc(rc->numports + 1, sizeof(*rc->ports));
	if (!rc->ports) {
		free(rc);
		IBND_ERROR("OOM: Failed to allocate the ports array\n");
		return NULL;
	}

	rc->path_portid = *path;
	memcpy(rc->info, node_info, sizeof(rc->info));

	add_to_nodeguid_hash(rc, fabric->nodestbl);

	/* add this to the all nodes list */
	rc->next = fabric->nodes;
	fabric->nodes = rc;

	add_to_type_list(rc, fabric);

	return rc;
}

static int get_last_port(ib_portid_t * path)
{
	return (path->drpath.p[path->drpath.cnt]);
}
static void link_ports(ibnd_node_t * node, ibnd_port_t * port,
		       ibnd_node_t * remotenode, ibnd_port_t * remoteport)
{
	IBND_DEBUG("linking: 0x%" PRIx64 " %p->%p:%u and 0x%" PRIx64
		   " %p->%p:%u\n", node->guid, node, port, port->portnum,
		   remotenode->guid, remotenode, remoteport,
		   remoteport->portnum);
	if (port->remoteport)
		port->remoteport->remoteport = NULL;
	if (remoteport->remoteport)
		remoteport->remoteport->remoteport = NULL;
	port->remoteport = (ibnd_port_t *) remoteport;
	remoteport->remoteport = (ibnd_port_t *) port;
}

static int recv_node_info(smp_engine_t *engine, ibnd_smp_t * smp,
			  uint8_t *mad, void *cb_data)
{
	ibnd_fabric_t *fabric = ((ibnd_scan_t *)engine->user_data)->fabric;
	int i = 0;
	uint8_t *node_info = mad + IB_SMP_DATA_OFFS;
	ibnd_node_t * rem_node = (ibnd_node_t *)cb_data;
	ibnd_node_t *node;
	int node_is_new = 0;
	uint64_t node_guid = mad_get_field64(node_info, 0, IB_NODE_GUID_F);
	uint64_t port_guid = mad_get_field64(node_info, 0, IB_NODE_PORT_GUID_F);
	int port_num = mad_get_field(node_info, 0, IB_NODE_LOCAL_PORT_F);
	ibnd_port_t *port = NULL;

	node = ibnd_find_node_guid(fabric, node_guid);
	if (!node) {
		node = create_node(engine, &smp->path, node_info);
		if (!node)
			return -1;
		node_is_new = 1;
	}
	IBND_DEBUG("Found %s node GUID %lx (%s)\n",
		   (node_is_new) ? "new": "old", node->guid,
		   portid2str(&smp->path));

	port = node->ports[port_num];
	if (!port) {
		/* If we have not see this port before create a shell for it */
		port = node->ports[port_num] = calloc(1, sizeof(*port));
		port->node = node;
		port->portnum = port_num;
	}
	port->guid = port_guid;

	if (rem_node == NULL) /* this is the start node */
		fabric->from_node = node;
	else {
		/* link ports... */
		int rem_port_num = get_last_port(&smp->path);

		if (!rem_node->ports[rem_port_num]) {
			IBND_ERROR("Internal Error; "
				   "Node(%p) %lx Port %d no port created!?!?!?\n\n",
				   rem_node, rem_node->guid, rem_port_num);
			return (-1);
		}

		link_ports(node, port, rem_node, rem_node->ports[rem_port_num]);
	}

	if (!node_is_new)
		return 0;

	query_node_desc(engine, &smp->path, node);

	if (node->type == IB_NODE_SWITCH)
		query_switch_info(engine, &smp->path, node);

	/* process all the ports on this node */
	for (i = (node->type == IB_NODE_SWITCH) ? 0 : 1;
		i <= node->numports; i++) {
			query_port_info(engine, &smp->path, node, i);
	}

	return 0;
}

int query_node_info(smp_engine_t * engine, ib_portid_t * portid,
		    ibnd_node_t * node)
{
	IBND_DEBUG("Query Node Info; %s\n", portid2str(portid));
	return (issue_smp(engine, portid, IB_ATTR_NODE_INFO, 0, recv_node_info,
			  (void *)node));
}

ibnd_node_t *ibnd_find_node_guid(ibnd_fabric_t * fabric, uint64_t guid)
{
	int hash = HASHGUID(guid) % HTSZ;
	ibnd_node_t *node;

	if (!fabric) {
		IBND_DEBUG("fabric parameter NULL\n");
		return NULL;
	}

	for (node = fabric->nodestbl[hash]; node; node = node->htnext)
		if (node->guid == guid)
			return node;

	return NULL;
}

static int _check_ibmad_port(struct ibmad_port *ibmad_port)
{
	if (!ibmad_port) {
		IBND_DEBUG("ibmad_port must be specified\n");
		return -1;
	}
	if (mad_rpc_class_agent(ibmad_port, IB_SMI_CLASS) == -1
	    || mad_rpc_class_agent(ibmad_port, IB_SMI_DIRECT_CLASS) == -1) {
		IBND_DEBUG("ibmad_port must be opened with "
			   "IB_SMI_CLASS && IB_SMI_DIRECT_CLASS\n");
		return -1;
	}
	return 0;
}

ibnd_node_t *ibnd_find_node_dr(ibnd_fabric_t * fabric, char *dr_str)
{
	int i = 0;
	ibnd_node_t *rc;
	ib_dr_path_t path;

	if (!fabric) {
		IBND_DEBUG("fabric parameter NULL\n");
		return NULL;
	}

	rc = fabric->from_node;

	if (str2drpath(&path, dr_str, 0, 0) == -1) {
		return NULL;
	}

	for (i = 0; i <= path.cnt; i++) {
		ibnd_port_t *remote_port = NULL;
		if (path.p[i] == 0)
			continue;
		if (!rc->ports)
			return NULL;

		remote_port = rc->ports[path.p[i]]->remoteport;
		if (!remote_port)
			return NULL;

		rc = remote_port->node;
	}

	return rc;
}

void add_to_nodeguid_hash(ibnd_node_t * node, ibnd_node_t * hash[])
{
	int hash_idx = HASHGUID(node->guid) % HTSZ;

	node->htnext = hash[hash_idx];
	hash[hash_idx] = node;
}

void add_to_portguid_hash(ibnd_port_t * port, ibnd_port_t * hash[])
{
	int hash_idx = HASHGUID(port->guid) % HTSZ;

	port->htnext = hash[hash_idx];
	hash[hash_idx] = port;
}

void add_to_type_list(ibnd_node_t * node, ibnd_fabric_t * fabric)
{
	switch (node->type) {
	case IB_NODE_CA:
		node->type_next = fabric->ch_adapters;
		fabric->ch_adapters = node;
		break;
	case IB_NODE_SWITCH:
		node->type_next = fabric->switches;
		fabric->switches = node;
		break;
	case IB_NODE_ROUTER:
		node->type_next = fabric->routers;
		fabric->routers = node;
		break;
	}
}

int ibnd_set_max_smps_on_wire(int i)
{
	int rc = max_smps_on_wire;
	max_smps_on_wire = i;
	return rc;
}

ibnd_fabric_t *ibnd_discover_fabric(struct ibmad_port *ibmad_port,
				    ib_portid_t * from, int hops)
{
	ibnd_fabric_t *fabric = NULL;
	ib_portid_t my_portid = { 0 };
	int max_hops = MAXHOPS - 1;	/* default find everything */
	smp_engine_t engine;
	ibnd_scan_t scan;

	if (_check_ibmad_port(ibmad_port) < 0)
		return NULL;

	/* if not everything how much? */
	if (hops >= 0) {
		max_hops = hops;
	}

	/* If not specified start from "my" port */
	if (!from)
		from = &my_portid;

	fabric = calloc(1, sizeof(*fabric));
	if (!fabric) {
		IBND_ERROR("OOM: failed to calloc ibnd_fabric_t\n");
		return NULL;
	}

	memset(fabric, 0, sizeof(*fabric));

	memset(&(scan.selfportid), 0, sizeof(scan.selfportid));
	scan.fabric = fabric;

	smp_engine_init(&engine, ibmad_port, &scan, max_smps_on_wire);

	IBND_DEBUG("from %s\n", portid2str(from));

	if (!query_node_info(&engine, from, NULL)) {
		if (process_mads(&engine) != 0)
			goto error;
	}

	if (group_nodes(fabric))
		goto error;

	smp_engine_destroy(&engine);
	return fabric;
error:
	smp_engine_destroy(&engine);
	ibnd_destroy_fabric(fabric);
	return NULL;
}

static void destroy_node(ibnd_node_t * node)
{
	int p = 0;

	if (node->ports) {
		for (p = 0; p <= node->numports; p++)
			free(node->ports[p]);
		free(node->ports);
	}
	free(node);
}

void ibnd_destroy_fabric(ibnd_fabric_t * fabric)
{
	ibnd_node_t *node = NULL;
	ibnd_node_t *next = NULL;
	ibnd_chassis_t *ch, *ch_next;

	if (!fabric)
		return;

	ch = fabric->chassis;
	while (ch) {
		ch_next = ch->next;
		free(ch);
		ch = ch_next;
	}
	node = fabric->nodes;
	while (node) {
		next = node->next;
		destroy_node(node);
		node = next;
	}
	free(fabric);
}

void ibnd_debug(int i)
{
	if (i) {
		ibdebug++;
		madrpc_show_errors(1);
		umad_debug(i);
	} else {
		ibdebug = 0;
		madrpc_show_errors(0);
		umad_debug(0);
	}
}

void ibnd_show_progress(int i)
{
	show_progress = i;
}

void ibnd_iter_nodes(ibnd_fabric_t * fabric, ibnd_iter_node_func_t func,
		     void *user_data)
{
	ibnd_node_t *cur = NULL;

	if (!fabric) {
		IBND_DEBUG("fabric parameter NULL\n");
		return;
	}

	if (!func) {
		IBND_DEBUG("func parameter NULL\n");
		return;
	}

	for (cur = fabric->nodes; cur; cur = cur->next)
		func(cur, user_data);
}

void ibnd_iter_nodes_type(ibnd_fabric_t * fabric, ibnd_iter_node_func_t func,
			  int node_type, void *user_data)
{
	ibnd_node_t *list = NULL;
	ibnd_node_t *cur = NULL;

	if (!fabric) {
		IBND_DEBUG("fabric parameter NULL\n");
		return;
	}

	if (!func) {
		IBND_DEBUG("func parameter NULL\n");
		return;
	}

	switch (node_type) {
	case IB_NODE_SWITCH:
		list = fabric->switches;
		break;
	case IB_NODE_CA:
		list = fabric->ch_adapters;
		break;
	case IB_NODE_ROUTER:
		list = fabric->routers;
		break;
	default:
		IBND_DEBUG("Invalid node_type specified %d\n", node_type);
		break;
	}

	for (cur = list; cur; cur = cur->type_next)
		func(cur, user_data);
}
