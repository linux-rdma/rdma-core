/*
 * Copyright (c) 2004-2007 Voltaire Inc.  All rights reserved.
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
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <inttypes.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>

#include <infiniband/ibnetdisc.h>
#include <complib/cl_nodenamemap.h>

#include "internal.h"
#include "chassis.h"

static int show_progress = 0;
int ibdebug;

void decode_port_info(ibnd_port_t * port)
{
	port->base_lid = (uint16_t) mad_get_field(port->info, 0, IB_PORT_LID_F);
	port->lmc = (uint8_t) mad_get_field(port->info, 0, IB_PORT_LMC_F);
}

static int get_port_info(struct ibmad_port *ibmad_port,
			 struct ibnd_fabric *fabric, struct ibnd_port *port,
			 int portnum, ib_portid_t * portid)
{
	char width[64], speed[64];
	int iwidth;
	int ispeed;

	port->port.portnum = portnum;
	iwidth = mad_get_field(port->port.info, 0, IB_PORT_LINK_WIDTH_ACTIVE_F);
	ispeed = mad_get_field(port->port.info, 0, IB_PORT_LINK_SPEED_ACTIVE_F);

	if (!smp_query_via(port->port.info, portid, IB_ATTR_PORT_INFO,
			   portnum, 0, ibmad_port))
		return -1;

	decode_port_info(&(port->port));

	IBND_DEBUG
	    ("portid %s portnum %d: base lid %d state %d physstate %d %s %s\n",
	     portid2str(portid), portnum, port->port.base_lid,
	     mad_get_field(port->port.info, 0, IB_PORT_STATE_F),
	     mad_get_field(port->port.info, 0, IB_PORT_PHYS_STATE_F),
	     mad_dump_val(IB_PORT_LINK_WIDTH_ACTIVE_F, width, 64, &iwidth),
	     mad_dump_val(IB_PORT_LINK_SPEED_ACTIVE_F, speed, 64, &ispeed));
	return 0;
}

/*
 * Returns -1 if error.
 */
static int query_node_info(struct ibmad_port *ibmad_port,
			   struct ibnd_fabric *fabric, ibnd_node_t * node,
			   ib_portid_t * portid)
{
	if (!smp_query_via(&(node->info), portid, IB_ATTR_NODE_INFO, 0, 0,
			   ibmad_port))
		return -1;

	/* decode just a couple of fields for quicker reference. */
	mad_decode_field(node->info, IB_NODE_GUID_F, &(node->guid));
	mad_decode_field(node->info, IB_NODE_TYPE_F, &(node->type));
	mad_decode_field(node->info, IB_NODE_NPORTS_F, &(node->numports));

	return (0);
}

/*
 * Returns 0 if non switch node is found, 1 if switch is found, -1 if error.
 */
static int query_node(struct ibmad_port *ibmad_port, struct ibnd_fabric *fabric,
		      ibnd_node_t * node, struct ibnd_port *iport,
		      ib_portid_t * portid)
{
	int rc = 0;
	ibnd_port_t *port = &(iport->port);
	void *nd = node->nodedesc;

	if ((rc = query_node_info(ibmad_port, fabric, node, portid)) != 0)
		return rc;

	port->portnum = mad_get_field(node->info, 0, IB_NODE_LOCAL_PORT_F);
	port->guid = mad_get_field64(node->info, 0, IB_NODE_PORT_GUID_F);

	if (!smp_query_via(nd, portid, IB_ATTR_NODE_DESC, 0, 0, ibmad_port))
		return -1;

	if (!smp_query_via(port->info, portid, IB_ATTR_PORT_INFO, 0, 0,
			   ibmad_port))
		return -1;
	decode_port_info(port);

	if (node->type != IB_NODE_SWITCH)
		return 0;

	node->smalid = port->base_lid;
	node->smalmc = port->lmc;

	/* after we have the sma information find out the real PortInfo for this port */
	if (!smp_query_via(port->info, portid, IB_ATTR_PORT_INFO,
			   port->portnum, 0, ibmad_port))
		return -1;
	decode_port_info(port);

	port->base_lid = (uint16_t) node->smalid;	/* LID is still defined by port 0 */
	port->lmc = (uint8_t) node->smalmc;

	if (!smp_query_via(node->switchinfo, portid, IB_ATTR_SWITCH_INFO, 0, 0,
			   ibmad_port))
		node->smaenhsp0 = 0;	/* assume base SP0 */
	else
		mad_decode_field(node->switchinfo, IB_SW_ENHANCED_PORT0_F,
				 &node->smaenhsp0);

	IBND_DEBUG("portid %s: got switch node %" PRIx64 " '%s'\n",
		   portid2str(portid), node->guid, node->nodedesc);
	return 0;
}

static int add_port_to_dpath(ib_dr_path_t * path, int nextport)
{
	if (path->cnt + 2 >= sizeof(path->p)) {
		IBND_ERROR("DR path has grown too long\n");
		return -1;
	}
	++path->cnt;
	path->p[path->cnt] = (uint8_t) nextport;
	return path->cnt;
}

static int extend_dpath(struct ibmad_port *ibmad_port, struct ibnd_fabric *f,
			ib_portid_t * portid, int nextport)
{
	int rc = 0;

	if (portid->lid) {
		/* If we were LID routed we need to set up the drslid */
		if (!f->selfportid.lid)
			if (ib_resolve_self_via(&f->selfportid, NULL, NULL,
						ibmad_port) < 0) {
				IBND_ERROR("Failed to resolve self\n");
				return -1;
			}

		portid->drpath.drslid = (uint16_t) f->selfportid.lid;
		portid->drpath.drdlid = 0xFFFF;
	}

	rc = add_port_to_dpath(&portid->drpath, nextport);

	if ((rc != -1) && (portid->drpath.cnt > f->fabric.maxhops_discovered))
		f->fabric.maxhops_discovered = portid->drpath.cnt;
	return (rc);
}

static void dump_endnode(ib_portid_t * path, char *prompt,
			 ibnd_node_t * node, struct ibnd_port *port)
{
	char type[64];
	if (!show_progress)
		return;

	mad_dump_node_type(type, 64, &(node->type), sizeof(int)),
	    printf("%s -> %s %s {%016" PRIx64
		   "} portnum %d base lid %d-%d\"%s\"\n", portid2str(path),
		   prompt, type, node->guid,
		   node->type == IB_NODE_SWITCH ? 0 : port->port.portnum,
		   port->port.base_lid,
		   port->port.base_lid + (1 << port->port.lmc) - 1,
		   node->nodedesc);
}

static ibnd_node_t *find_existing_node(struct ibnd_fabric *fabric,
				       ibnd_node_t * new)
{
	int hash = HASHGUID(new->guid) % HTSZ;
	ibnd_node_t *node;

	for (node = fabric->nodestbl[hash]; node; node = node->htnext)
		if (node->guid == new->guid)
			return node;

	return NULL;
}

ibnd_node_t *ibnd_find_node_guid(ibnd_fabric_t * fabric, uint64_t guid)
{
	struct ibnd_fabric *f = CONV_FABRIC_INTERNAL(fabric);
	int hash = HASHGUID(guid) % HTSZ;
	ibnd_node_t *node;

	if (!fabric) {
		IBND_DEBUG("fabric parameter NULL\n");
		return (NULL);
	}

	for (node = f->nodestbl[hash]; node; node = node->htnext)
		if (node->guid == guid)
			return (ibnd_node_t *) node;

	return NULL;
}

static int _check_ibmad_port(struct ibmad_port *ibmad_port)
{
	if (!ibmad_port) {
		IBND_DEBUG("ibmad_port must be specified\n");
		return (-1);
	}
	if (mad_rpc_class_agent(ibmad_port, IB_SMI_CLASS) == -1
	    || mad_rpc_class_agent(ibmad_port, IB_SMI_DIRECT_CLASS) == -1) {
		IBND_DEBUG("ibmad_port must be opened with "
			   "IB_SMI_CLASS && IB_SMI_DIRECT_CLASS\n");
		return (-1);
	}
	return (0);
}

ibnd_node_t *ibnd_update_node(struct ibmad_port * ibmad_port,
			      ibnd_fabric_t * fabric, ibnd_node_t * node)
{
	char portinfo_port0[IB_SMP_DATA_SIZE];
	void *nd = node->nodedesc;
	int p = 0;
	struct ibnd_fabric *f = CONV_FABRIC_INTERNAL(fabric);

	if (_check_ibmad_port(ibmad_port) < 0)
		return (NULL);

	if (!fabric) {
		IBND_DEBUG("fabric parameter NULL\n");
		return (NULL);
	}

	if (!node) {
		IBND_DEBUG("node parameter NULL\n");
		return (NULL);
	}

	if (query_node_info(ibmad_port, f, node, &(node->path_portid)))
		return (NULL);

	if (!smp_query_via(nd, &(node->path_portid), IB_ATTR_NODE_DESC, 0, 0,
			   ibmad_port))
		return (NULL);

	/* update all the port info's */
	for (p = 1; p >= node->numports; p++) {
		get_port_info(ibmad_port, f, CONV_PORT_INTERNAL(node->ports[p]),
			      p, &(node->path_portid));
	}

	if (node->type != IB_NODE_SWITCH)
		goto done;

	if (!smp_query_via
	    (portinfo_port0, &(node->path_portid), IB_ATTR_PORT_INFO, 0, 0,
	     ibmad_port))
		return (NULL);

	node->smalid = mad_get_field(portinfo_port0, 0, IB_PORT_LID_F);
	node->smalmc = mad_get_field(portinfo_port0, 0, IB_PORT_LMC_F);

	if (!smp_query_via(node->switchinfo, &(node->path_portid),
			   IB_ATTR_SWITCH_INFO, 0, 0, ibmad_port))
		node->smaenhsp0 = 0;	/* assume base SP0 */
	else
		mad_decode_field(node->switchinfo, IB_SW_ENHANCED_PORT0_F,
				 &node->smaenhsp0);

done:
	return (node);
}

ibnd_node_t *ibnd_find_node_dr(ibnd_fabric_t * fabric, char *dr_str)
{
	struct ibnd_fabric *f = CONV_FABRIC_INTERNAL(fabric);
	int i = 0;
	ibnd_node_t *rc;
	ib_dr_path_t path;

	if (!fabric) {
		IBND_DEBUG("fabric parameter NULL\n");
		return (NULL);
	}

	rc = f->fabric.from_node;

	if (str2drpath(&path, dr_str, 0, 0) == -1) {
		return (NULL);
	}

	for (i = 0; i <= path.cnt; i++) {
		ibnd_port_t *remote_port = NULL;
		if (path.p[i] == 0)
			continue;
		if (!rc->ports)
			return (NULL);

		remote_port = rc->ports[path.p[i]]->remoteport;
		if (!remote_port)
			return (NULL);

		rc = remote_port->node;
	}

	return (rc);
}

static void add_to_nodeguid_hash(ibnd_node_t * node, ibnd_node_t * hash[])
{
	int hash_idx = HASHGUID(node->guid) % HTSZ;

	node->htnext = hash[hash_idx];
	hash[hash_idx] = node;
}

static void add_to_portguid_hash(struct ibnd_port *port,
				 struct ibnd_port *hash[])
{
	int hash_idx = HASHGUID(port->port.guid) % HTSZ;

	port->htnext = hash[hash_idx];
	hash[hash_idx] = port;
}

static void add_to_type_list(ibnd_node_t * node, struct ibnd_fabric *fabric)
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

static void add_to_nodedist(ibnd_node_t * node, struct ibnd_fabric *fabric)
{
	int dist = node->dist;
	if (node->type != IB_NODE_SWITCH)
		dist = MAXHOPS;	/* special Ca list */

	node->dnext = fabric->nodesdist[dist];
	fabric->nodesdist[dist] = node;
}

static ibnd_node_t *create_node(struct ibnd_fabric *fabric,
				ibnd_node_t * temp, ib_portid_t * path,
				int dist)
{
	ibnd_node_t *node;

	node = malloc(sizeof(*node));
	if (!node) {
		IBND_ERROR("OOM: node creation failed\n");
		return (NULL);
	}

	memcpy(node, temp, sizeof(*node));
	node->dist = dist;
	node->path_portid = *path;

	add_to_nodeguid_hash(node, fabric->nodestbl);

	/* add this to the all nodes list */
	node->next = fabric->fabric.nodes;
	fabric->fabric.nodes = (ibnd_node_t *) node;

	add_to_type_list(node, fabric);
	add_to_nodedist(node, fabric);

	return node;
}

static struct ibnd_port *find_existing_port_node(ibnd_node_t * node,
						 struct ibnd_port *port)
{
	if (port->port.portnum > node->numports || node->ports == NULL)
		return (NULL);

	return (CONV_PORT_INTERNAL(node->ports[port->port.portnum]));
}

static struct ibnd_port *add_port_to_node(struct ibnd_fabric *fabric,
					  ibnd_node_t * node,
					  struct ibnd_port *temp)
{
	struct ibnd_port *port;

	if (node->ports == NULL) {
		node->ports = calloc(sizeof(*node->ports), node->numports + 1);
		if (!node->ports) {
			IBND_ERROR("Failed to allocate the ports array\n");
			return (NULL);
		}
	}

	port = malloc(sizeof(*port));
	if (!port) {
		IBND_ERROR("Failed to allocate port\n");
		return NULL;
	}

	memcpy(port, temp, sizeof(*port));
	port->port.node = (ibnd_node_t *) node;
	port->port.ext_portnum = 0;

	node->ports[temp->port.portnum] = (ibnd_port_t *) port;

	add_to_portguid_hash(port, fabric->portstbl);
	return port;
}

static void link_ports(ibnd_node_t * node, struct ibnd_port *port,
		       ibnd_node_t * remotenode, struct ibnd_port *remoteport)
{
	IBND_DEBUG("linking: 0x%" PRIx64 " %p->%p:%u and 0x%" PRIx64
		   " %p->%p:%u\n", node->guid, node, port, port->port.portnum,
		   remotenode->guid, remotenode, remoteport,
		   remoteport->port.portnum);
	if (port->port.remoteport)
		port->port.remoteport->remoteport = NULL;
	if (remoteport->port.remoteport)
		remoteport->port.remoteport->remoteport = NULL;
	port->port.remoteport = (ibnd_port_t *) remoteport;
	remoteport->port.remoteport = (ibnd_port_t *) port;
}

static int get_remote_node(struct ibmad_port *ibmad_port,
			   struct ibnd_fabric *fabric, ibnd_node_t * node,
			   struct ibnd_port *port, ib_portid_t * path,
			   int portnum, int dist)
{
	int rc = 0;
	ibnd_node_t node_buf;
	struct ibnd_port port_buf;
	ibnd_node_t *remotenode, *oldnode;
	struct ibnd_port *remoteport, *oldport;

	memset(&node_buf, 0, sizeof(node_buf));
	memset(&port_buf, 0, sizeof(port_buf));

	IBND_DEBUG("handle node %p port %p:%d dist %d\n", node, port, portnum,
		   dist);

	if (mad_get_field(port->port.info, 0, IB_PORT_PHYS_STATE_F)
	    != IB_PORT_PHYS_STATE_LINKUP)
		return 1;	/* positive == non-fatal error */

	if (extend_dpath(ibmad_port, fabric, path, portnum) < 0)
		return -1;

	if (query_node(ibmad_port, fabric, &node_buf, &port_buf, path)) {
		IBND_ERROR("Query remote node (%s) failed, skipping port\n",
			   portid2str(path));
		path->drpath.cnt--;	/* restore path */
		return 1;	/* positive == non-fatal error */
	}

	oldnode = find_existing_node(fabric, &node_buf);
	if (oldnode)
		remotenode = oldnode;
	else if (!(remotenode = create_node(fabric, &node_buf, path, dist + 1))) {
		rc = -1;
		goto error;
	}

	oldport = find_existing_port_node(remotenode, &port_buf);
	if (oldport) {
		remoteport = oldport;
	} else if (!(remoteport = add_port_to_node(fabric, remotenode,
						   &port_buf))) {
		IBND_ERROR("OOM failed to add port to node\n");
		rc = -1;
		goto error;
	}

	dump_endnode(path, oldnode ? "known remote" : "new remote",
		     remotenode, remoteport);

	link_ports(node, port, remotenode, remoteport);

error:
	path->drpath.cnt--;	/* restore path */
	return (rc);
}

ibnd_fabric_t *ibnd_discover_fabric(struct ibmad_port * ibmad_port,
				    ib_portid_t * from, int hops)
{
	int rc = 0;
	struct ibnd_fabric *fabric = NULL;
	ib_portid_t my_portid = { 0 };
	ibnd_node_t node_buf;
	struct ibnd_port port_buf;
	ibnd_node_t *node;
	struct ibnd_port *port;
	int i;
	int dist = 0;
	ib_portid_t *path;
	int max_hops = MAXHOPS - 1;	/* default find everything */

	if (_check_ibmad_port(ibmad_port) < 0)
		return (NULL);

	/* if not everything how much? */
	if (hops >= 0) {
		max_hops = hops;
	}

	/* If not specified start from "my" port */
	if (!from)
		from = &my_portid;

	fabric = malloc(sizeof(*fabric));

	if (!fabric) {
		IBND_ERROR("OOM: failed to malloc ibnd_fabric_t\n");
		return (NULL);
	}

	memset(fabric, 0, sizeof(*fabric));

	IBND_DEBUG("from %s\n", portid2str(from));

	memset(&node_buf, 0, sizeof(node_buf));
	memset(&port_buf, 0, sizeof(port_buf));

	if (query_node(ibmad_port, fabric, &node_buf, &port_buf, from)) {
		IBND_DEBUG("can't reach node %s\n", portid2str(from));
		goto error;
	}

	node = create_node(fabric, &node_buf, from, 0);
	if (!node)
		goto error;

	fabric->fabric.from_node = (ibnd_node_t *) node;

	port = add_port_to_node(fabric, node, &port_buf);
	if (!port)
		goto error;

	rc = get_remote_node(ibmad_port, fabric, node, port, from,
			     mad_get_field(node->info, 0,
					   IB_NODE_LOCAL_PORT_F), 0);
	if (rc < 0)
		goto error;
	if (rc > 0)		/* non-fatal error, nothing more to be done */
		return ((ibnd_fabric_t *) fabric);

	for (dist = 0; dist <= max_hops; dist++) {

		for (node = fabric->nodesdist[dist]; node; node = node->dnext) {

			path = &node->path_portid;

			IBND_DEBUG("dist %d node %p\n", dist, node);
			dump_endnode(path, "processing", node, port);

			for (i = 1; i <= node->numports; i++) {
				if (i == mad_get_field(node->info, 0,
						       IB_NODE_LOCAL_PORT_F))
					continue;

				if (get_port_info(ibmad_port, fabric,
						  &port_buf, i, path)) {
					IBND_ERROR
					    ("can't reach node %s port %d",
					     portid2str(path), i);
					continue;
				}

				port = find_existing_port_node(node, &port_buf);
				if (port)
					continue;

				port =
				    add_port_to_node(fabric, node, &port_buf);
				if (!port)
					goto error;

				/* If switch, set port GUID to node port GUID */
				if (node->type == IB_NODE_SWITCH) {
					port->port.guid =
					    mad_get_field64(node->info, 0,
							    IB_NODE_PORT_GUID_F);
				}

				if (get_remote_node(ibmad_port, fabric, node,
						    port, path, i, dist) < 0)
					goto error;
			}
		}
	}

	if (group_nodes(fabric))
		goto error;

	return ((ibnd_fabric_t *) fabric);
error:
	ibnd_destroy_fabric((ibnd_fabric_t *) fabric);
	return (NULL);
}

static void destroy_node(ibnd_node_t * node)
{
	int p = 0;

	for (p = 0; p <= node->numports; p++) {
		free(node->ports[p]);
	}
	free(node->ports);
	free(node);
}

void ibnd_destroy_fabric(ibnd_fabric_t * fabric)
{
	struct ibnd_fabric *f = CONV_FABRIC_INTERNAL(fabric);
	int dist = 0;
	ibnd_node_t *node = NULL;
	ibnd_node_t *next = NULL;
	ibnd_chassis_t *ch, *ch_next;

	if (!fabric)
		return;

	ch = f->first_chassis;
	while (ch) {
		ch_next = ch->next;
		free(ch);
		ch = ch_next;
	}
	for (dist = 0; dist <= MAXHOPS; dist++) {
		node = f->nodesdist[dist];
		while (node) {
			next = node->dnext;
			destroy_node(node);
			node = next;
		}
	}
	free(f);
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

	for (cur = fabric->nodes; cur; cur = cur->next) {
		func(cur, user_data);
	}
}

void ibnd_iter_nodes_type(ibnd_fabric_t * fabric, ibnd_iter_node_func_t func,
			  int node_type, void *user_data)
{
	struct ibnd_fabric *f = CONV_FABRIC_INTERNAL(fabric);
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
		list = f->switches;
		break;
	case IB_NODE_CA:
		list = f->ch_adapters;
		break;
	case IB_NODE_ROUTER:
		list = f->routers;
		break;
	default:
		IBND_DEBUG("Invalid node_type specified %d\n", node_type);
		break;
	}

	for (cur = list; cur; cur = cur->type_next) {
		func((ibnd_node_t *) cur, user_data);
	}
}
