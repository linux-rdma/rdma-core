/*
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

/** =========================================================================
 * Define the internal data structures.
 */

#ifndef _INTERNAL_H_
#define _INTERNAL_H_

#include <infiniband/ibnetdisc.h>

#define MAXHOPS		63

#define	IBND_DEBUG(fmt, ...) \
	if (ibdebug) { \
		printf("%s:%u; " fmt, __FILE__, __LINE__, ## __VA_ARGS__); \
	}
#define	IBND_ERROR(fmt, ...) \
		fprintf(stderr, "%s:%u; " fmt, __FILE__, __LINE__, ## __VA_ARGS__)

struct ibnd_node {
	/* This member MUST BE FIRST */
	ibnd_node_t node;

	/* internal use only */
	unsigned char ch_found;
	struct ibnd_node *htnext; /* hash table list */
	struct ibnd_node *dnext; /* nodesdist next */
	struct ibnd_node *type_next; /* next based on type */
};
#define CONV_NODE_INTERNAL(node) ((struct ibnd_node *)node)

struct ibnd_port {
	/* This member MUST BE FIRST */
	ibnd_port_t port;

	/* internal use only */
	struct ibnd_port *htnext;
};
#define CONV_PORT_INTERNAL(port) ((struct ibnd_port *)port)

/* HASH table defines */
#define HASHGUID(guid) ((uint32_t)(((uint32_t)(guid) * 101) ^ ((uint32_t)((guid) >> 32) * 103)))
#define HTSZ 137

struct ibnd_fabric {
	/* This member MUST BE FIRST */
	ibnd_fabric_t fabric;

	/* internal use only */
	struct ibnd_node *nodestbl[HTSZ];
	struct ibnd_port *portstbl[HTSZ];
	struct ibnd_node *nodesdist[MAXHOPS+1];
	ibnd_chassis_t *first_chassis;
	ibnd_chassis_t *current_chassis;
	ibnd_chassis_t *last_chassis;
	struct ibnd_node *switches;
	struct ibnd_node *ch_adapters;
	struct ibnd_node *routers;
	ib_portid_t selfportid;
};
#define CONV_FABRIC_INTERNAL(fabric) ((struct ibnd_fabric *)fabric)

#endif /* _INTERNAL_H_ */
