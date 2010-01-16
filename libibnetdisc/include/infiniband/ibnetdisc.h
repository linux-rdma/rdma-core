/*
 * Copyright (c) 2009 Voltaire, Inc. All rights reserved.
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

#ifndef _IBNETDISC_H_
#define _IBNETDISC_H_

#include <stdio.h>
#include <infiniband/mad.h>
#include <iba/ib_types.h>

struct ibnd_chassis;		/* forward declare */
struct ibnd_port;		/* forward declare */

/** =========================================================================
 * Node
 */
typedef struct ibnd_node {
	struct ibnd_node *next;	/* all node list in fabric */

	ib_portid_t path_portid;	/* path from "from_node" */
	uint16_t smalid;
	uint8_t smalmc;

	/* quick cache of switchinfo below */
	int smaenhsp0;
	/* use libibmad decoder functions for switchinfo */
	uint8_t switchinfo[IB_SMP_DATA_SIZE];

	/* quick cache of info below */
	uint64_t guid;
	int type;
	int numports;
	/* use libibmad decoder functions for info */
	uint8_t info[IB_SMP_DATA_SIZE];

	char nodedesc[IB_SMP_DATA_SIZE];

	struct ibnd_port **ports;	/* array of ports, indexed by port number
					   ports[1] == port 1,
					   ports[2] == port 2,
					   etc...
					   Any port in the array MAY BE NULL!
					   Most notable is non-switches have no
					   port 0 therefore node.ports[0] == NULL
					   for those nodes */

	/* chassis info */
	struct ibnd_node *next_chassis_node;	/* next node in ibnd_chassis_t->nodes */
	struct ibnd_chassis *chassis;	/* if != NULL the chassis this node belongs to */
	unsigned char ch_type;
	unsigned char ch_anafanum;
	unsigned char ch_slotnum;
	unsigned char ch_slot;

	/* internal use only */
	unsigned char ch_found;
	struct ibnd_node *htnext;	/* hash table list */
	struct ibnd_node *type_next;	/* next based on type */
} ibnd_node_t;

/** =========================================================================
 * Port
 */
typedef struct ibnd_port {
	uint64_t guid;
	int portnum;
	int ext_portnum;	/* optional if != 0 external port num */
	ibnd_node_t *node;	/* node this port belongs to */
	struct ibnd_port *remoteport;	/* null if SMA, or does not exist */
	/* quick cache of info below */
	uint16_t base_lid;
	uint8_t lmc;
	/* use libibmad decoder functions for info */
	uint8_t info[IB_SMP_DATA_SIZE];

	/* internal use only */
	struct ibnd_port *htnext;
} ibnd_port_t;

/** =========================================================================
 * Chassis
 */
typedef struct ibnd_chassis {
	struct ibnd_chassis *next;
	uint64_t chassisguid;
	unsigned char chassisnum;

	/* generic grouping by SystemImageGUID */
	unsigned char nodecount;
	ibnd_node_t *nodes;

	/* specific to voltaire type nodes */
#define SPINES_MAX_NUM 12
#define LINES_MAX_NUM 36
	ibnd_node_t *spinenode[SPINES_MAX_NUM + 1];
	ibnd_node_t *linenode[LINES_MAX_NUM + 1];
} ibnd_chassis_t;

#define HTSZ 137

/** =========================================================================
 * Fabric
 * Main fabric object which is returned and represents the data discovered
 */
typedef struct ibnd_fabric {
	/* the node the discover was initiated from
	 * "from" parameter in ibnd_discover_fabric
	 * or by default the node you ar running on
	 */
	ibnd_node_t *from_node;
	/* NULL term list of all nodes in the fabric */
	ibnd_node_t *nodes;
	/* NULL terminated list of all chassis found in the fabric */
	ibnd_chassis_t *chassis;
	int maxhops_discovered;

	/* internal use only */
	ibnd_node_t *nodestbl[HTSZ];
	ibnd_port_t *portstbl[HTSZ];
	ibnd_node_t *switches;
	ibnd_node_t *ch_adapters;
	ibnd_node_t *routers;
} ibnd_fabric_t;

/** =========================================================================
 * Initialization (fabric operations)
 */
MAD_EXPORT void ibnd_debug(int i);
MAD_EXPORT void ibnd_show_progress(int i);

MAD_EXPORT ibnd_fabric_t *ibnd_discover_fabric(struct ibmad_port *ibmad_port,
					       ib_portid_t * from, int hops);
	/**
	 * open: (required) ibmad_port object from libibmad
	 * from: (optional) specify the node to start scanning from.
	 *       If NULL start from the node we are running on.
	 * hops: (optional) Specify how much of the fabric to traverse.
	 *       negative value == scan entire fabric
	 */
MAD_EXPORT void ibnd_destroy_fabric(ibnd_fabric_t * fabric);

MAD_EXPORT ibnd_fabric_t *ibnd_load_fabric(const char *file,
					   unsigned int flags);

MAD_EXPORT int ibnd_cache_fabric(ibnd_fabric_t * fabric, const char *file,
				 unsigned int flags);

/** =========================================================================
 * Node operations
 */
MAD_EXPORT ibnd_node_t *ibnd_find_node_guid(ibnd_fabric_t * fabric,
					    uint64_t guid);
MAD_EXPORT ibnd_node_t *ibnd_find_node_dr(ibnd_fabric_t * fabric, char *dr_str);

typedef void (*ibnd_iter_node_func_t) (ibnd_node_t * node, void *user_data);
MAD_EXPORT void ibnd_iter_nodes(ibnd_fabric_t * fabric,
				ibnd_iter_node_func_t func, void *user_data);
MAD_EXPORT void ibnd_iter_nodes_type(ibnd_fabric_t * fabric,
				     ibnd_iter_node_func_t func,
				     int node_type, void *user_data);

/** =========================================================================
 * Chassis queries
 */
MAD_EXPORT uint64_t ibnd_get_chassis_guid(ibnd_fabric_t * fabric,
					  unsigned char chassisnum);
MAD_EXPORT char *ibnd_get_chassis_type(ibnd_node_t * node);
MAD_EXPORT char *ibnd_get_chassis_slot_str(ibnd_node_t * node,
					   char *str, size_t size);

MAD_EXPORT int ibnd_is_xsigo_guid(uint64_t guid);
MAD_EXPORT int ibnd_is_xsigo_tca(uint64_t guid);
MAD_EXPORT int ibnd_is_xsigo_hca(uint64_t guid);

#endif				/* _IBNETDISC_H_ */
