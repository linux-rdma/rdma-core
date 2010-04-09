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
#include <complib/cl_qmap.h>

#define	IBND_DEBUG(fmt, ...) \
	if (ibdebug) { \
		printf("%s:%u; " fmt, __FILE__, __LINE__, ## __VA_ARGS__); \
	}
#define	IBND_ERROR(fmt, ...) \
		fprintf(stderr, "%s:%u; " fmt, __FILE__, __LINE__, ## __VA_ARGS__)

/* HASH table defines */
#define HASHGUID(guid) ((uint32_t)(((uint32_t)(guid) * 101) ^ ((uint32_t)((guid) >> 32) * 103)))

#define MAXHOPS         63

#define DEFAULT_MAX_SMP_ON_WIRE 2

typedef struct ibnd_scan {
	ib_portid_t selfportid;
	ibnd_fabric_t *fabric;
	unsigned max_hops;
} ibnd_scan_t;

typedef struct ibnd_smp ibnd_smp_t;
typedef struct smp_engine smp_engine_t;
typedef int (*smp_comp_cb_t) (smp_engine_t * engine, ibnd_smp_t * smp,
			      uint8_t * mad_resp, void *cb_data);
struct ibnd_smp {
	cl_map_item_t on_wire;
	struct ibnd_smp *qnext;
	smp_comp_cb_t cb;
	void *cb_data;
	ib_portid_t path;
	ib_rpc_t rpc;
};

struct smp_engine {
	struct ibmad_port *ibmad_port;
	ibnd_smp_t *smp_queue_head;
	ibnd_smp_t *smp_queue_tail;
	void *user_data;
	cl_qmap_t smps_on_wire;
	int num_smps_outstanding;
	int max_smps_on_wire;
	unsigned total_smps;
};

void smp_engine_init(smp_engine_t * engine, struct ibmad_port *ibmad_port,
		     void *user_data, int max_smps_on_wire);
int issue_smp(smp_engine_t * engine, ib_portid_t * portid,
	      unsigned attrid, unsigned mod, smp_comp_cb_t cb, void *cb_data);
int process_mads(smp_engine_t * engine);
void smp_engine_destroy(smp_engine_t * engine);

void add_to_nodeguid_hash(ibnd_node_t * node, ibnd_node_t * hash[]);

void add_to_portguid_hash(ibnd_port_t * port, ibnd_port_t * hash[]);

void add_to_type_list(ibnd_node_t * node, ibnd_fabric_t * fabric);

#endif				/* _INTERNAL_H_ */
