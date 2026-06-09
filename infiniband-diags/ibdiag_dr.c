// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

/*
 * Direct route construction.
 *
 * Given a destination LID and a starting portid (LID- or DR-addressed),
 * build the direct route to that LID by following switch Linear Forwarding
 * Tables hop-by-hop via live SMP queries.  This is the single implementation
 * of the unicast route walk, available to all diags via ibdiags_tools.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>
#include <util/node_name_map.h>

#include "ibdiag_common.h"
#include "ibdiag_dr.h"

#define IBDIAG_MAX_HOPS 63

struct dr_node {
	int type;
	int numports;
	uint64_t nodeguid;
	char nodeinfo[64];
	char nodedesc[IB_SMP_DATA_SIZE + 1];
};

struct dr_port {
	uint64_t portguid;
	int portnum;
	int lid;
	int lmc;
	int state;
	char portinfo[64];
};

struct dr_switch {
	int linearcap;
	int linearFDBtop;
	int enhsp0;
	uint8_t fdb[64];
	char switchinfo[64];
};

static int dr_get_node(struct dr_node *node, struct dr_port *port,
		       ib_portid_t *portid, const struct ibmad_port *srcport,
		       int timeout)
{
	void *pi = port->portinfo, *ni = node->nodeinfo, *nd = node->nodedesc;
	char *s, *e;

	memset(ni, 0, sizeof(node->nodeinfo));
	if (!smp_query_via(ni, portid, IB_ATTR_NODE_INFO, 0, timeout, srcport))
		return -1;

	memset(nd, 0, sizeof(node->nodedesc));
	if (!smp_query_via(nd, portid, IB_ATTR_NODE_DESC, 0, timeout, srcport))
		return -1;

	for (s = nd, e = s + 64; s < e; s++) {
		if (!*s)
			break;
		if (!isprint(*s))
			*s = ' ';
	}

	memset(pi, 0, sizeof(port->portinfo));
	if (!smp_query_via(pi, portid, IB_ATTR_PORT_INFO, 0, timeout, srcport))
		return -1;

	mad_decode_field(ni, IB_NODE_GUID_F, &node->nodeguid);
	mad_decode_field(ni, IB_NODE_TYPE_F, &node->type);
	mad_decode_field(ni, IB_NODE_NPORTS_F, &node->numports);

	mad_decode_field(ni, IB_NODE_PORT_GUID_F, &port->portguid);
	mad_decode_field(ni, IB_NODE_LOCAL_PORT_F, &port->portnum);
	mad_decode_field(pi, IB_PORT_LID_F, &port->lid);
	mad_decode_field(pi, IB_PORT_LMC_F, &port->lmc);
	mad_decode_field(pi, IB_PORT_STATE_F, &port->state);

	DEBUG("portid %s: got node 0x%" PRIx64 " '%s'", portid2str(portid),
	      node->nodeguid, node->nodedesc);
	return 0;
}

static int dr_switch_lookup(struct dr_switch *sw, ib_portid_t *portid, int lid,
			    const struct ibmad_port *srcport, int timeout)
{
	void *si = sw->switchinfo, *fdb = sw->fdb;

	memset(si, 0, sizeof(sw->switchinfo));
	if (!smp_query_via(si, portid, IB_ATTR_SWITCH_INFO, 0, timeout,
			   srcport))
		return -1;

	mad_decode_field(si, IB_SW_LINEAR_FDB_CAP_F, &sw->linearcap);
	mad_decode_field(si, IB_SW_LINEAR_FDB_TOP_F, &sw->linearFDBtop);
	mad_decode_field(si, IB_SW_ENHANCED_PORT0_F, &sw->enhsp0);

	/* not supported*/
	if (sw->linearcap == 0)
		return -1;

	/* wrong configuration*/
	if (sw->linearcap < sw->linearFDBtop)
		return -1;

	/* overflow */
	if (lid > sw->linearFDBtop)
		return -1;

	memset(fdb, 0, sizeof(sw->fdb));
	if (!smp_query_via(fdb, portid, IB_ATTR_LINEARFORWTBL, lid / 64,
			   timeout, srcport))
		return -1;

	DEBUG("portid %s: forward lid %d to port %d", portid2str(portid), lid,
	      sw->fdb[lid % 64]);
	return sw->fdb[lid % 64];
}

static bool dr_sameport(struct dr_port *a, struct dr_port *b)
{
	if (a->portguid && b->portguid)
		return a->portguid == b->portguid;

	if (a->lid && b->lid)
		return a->lid == b->lid;

	return false;
}

/*
 * Returns true when the port is not active and false when active.
 * Base switch port 0 is considered always active.
 */
static bool dr_port_inactive(struct dr_node *node, struct dr_port *port)
{
	if (node->type == IB_NODE_SWITCH && port->portnum == 0)
		return false;

	return port->state == IB_LINK_DOWN;
}

static int dr_extend_dpath(ib_portid_t *portid, int nextport)
{
	if (portid->drpath.cnt + 2 >= sizeof(portid->drpath.p))
		return -1;
	++portid->drpath.cnt;
	portid->drpath.p[portid->drpath.cnt] = (uint8_t)nextport;

	return portid->drpath.cnt;
}

int build_dr_path_to_lid(const struct ibmad_port *srcport, int timeout,
			 ib_portid_t *from, uint16_t dest_lid)
{
	struct dr_node fromnode = {};
	struct dr_node nextnode = {};
	struct dr_port fromport = {};
	struct dr_port toport = {};
	struct dr_port nextport = {};
	struct dr_switch sw = {};
	struct dr_node *node;
	struct dr_port *port;
	int maxhops = IBDIAG_MAX_HOPS;
	int portnum, outport = 255, next_sw_outport = 255;

	if (dest_lid == 0) {
		IBWARN("invalid destination LID 0");
		return -1;
	}

	DEBUG("from %s to lid %u", portid2str(from), dest_lid);

	if (dr_get_node(&fromnode, &fromport, from, srcport, timeout) < 0) {
		IBWARN("can't reach from port");
		return -1;
	}

	if (dest_lid > 0)
		toport.lid = dest_lid;

	node = &fromnode;
	port = &fromport;
	portnum = port->portnum;

	if (node->type == IB_NODE_SWITCH) {
		next_sw_outport = dr_switch_lookup(&sw, from, dest_lid, srcport,
						   timeout);
		if (next_sw_outport < 0 || next_sw_outport > node->numports) {
			outport = next_sw_outport;
			goto badtbl;
		}
	}

	while (maxhops--) {
		if (dr_port_inactive(node, port))
			goto badport;

		if (dr_sameport(port, &toport))
			break;	/* found */

		if (node->type == IB_NODE_SWITCH) {
			outport = next_sw_outport;

			if (dr_extend_dpath(from, outport) < 0)
				goto badpath;

			if (dr_get_node(&nextnode, &nextport, from, srcport,
					timeout) < 0) {
				IBWARN("can't reach port at %s",
				       portid2str(from));
				return -1;
			}
			if (outport == 0) {
				if (!dr_sameport(&nextport, &toport))
					goto badtbl;
				else
					break;	/* found SMA port */
			}
		} else if ((node->type == IB_NODE_CA) ||
			   (node->type == IB_NODE_ROUTER)) {
			int ca_src = 0;

			outport = portnum;
			if ((dest_lid & ~((1 << port->lmc) - 1)) == port->lid)
				break;
			if (!dr_sameport(port, &fromport)) {
				IBWARN("can't continue: reached CA or router port 0x%" PRIx64 ", lid %d",
				       port->portguid, port->lid);
				return -1;
			}

			/* we are at CA or router "from" - go one hop back to
			 * (hopefully) a switch
			 */
			if (from->drpath.cnt > 0) {
				from->drpath.cnt--;
			} else {
				ca_src = 1;
				if (portnum &&
				    dr_extend_dpath(from, portnum) < 0)
					goto badpath;
			}
			if (dr_get_node(&nextnode, &nextport, from, srcport,
					timeout) < 0) {
				IBWARN("can't reach port at %s",
				       portid2str(from));
				return -1;
			}
			/* fix port num to be seen from the CA or router side */
			if (!ca_src)
				nextport.portnum =
				    from->drpath.p[from->drpath.cnt + 1];
		}
		/* only if the next node is a switch, get switch info */
		if (nextnode.type == IB_NODE_SWITCH) {
			next_sw_outport = dr_switch_lookup(&sw, from, dest_lid,
							   srcport, timeout);
			if (next_sw_outport < 0 ||
			    next_sw_outport > nextnode.numports) {
				outport = next_sw_outport;
				goto badtbl;
			}
		}

		port = &nextport;
		if (dr_port_inactive(&nextnode, port))
			goto badoutport;
		node = &nextnode;
		portnum = port->portnum;
	}

	if (maxhops <= 0) {
		IBWARN("no route found after %d hops", IBDIAG_MAX_HOPS);
		return -1;
	}

	return 0;

badport:
	IBWARN("Bad port state found: node \"%s\" port %d state %d",
	       clean_nodedesc(node->nodedesc), portnum, port->state);
	return -1;
badoutport:
	IBWARN("Bad out port state found: node \"%s\" outport %d state %d",
	       clean_nodedesc(node->nodedesc), outport, port->state);
	return -1;
badtbl:
	IBWARN("Bad forwarding table entry found at: node \"%s\" lid entry %d is %d (top %d)",
	       clean_nodedesc(node->nodedesc), dest_lid, outport,
	       sw.linearFDBtop);
	return -1;
badpath:
	IBWARN("Direct path too long!");
	return -1;
}
