/*
 * Copyright (c) 2010 Lawrence Livermore National Laboratory
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

#include <errno.h>
#include <infiniband/ibnetdisc.h>
#include <infiniband/umad.h>
#include "internal.h"

static void queue_smp(smp_engine_t * engine, ibnd_smp_t * smp)
{
	smp->qnext = NULL;
	if (!engine->smp_queue_head) {
		engine->smp_queue_head = smp;
		engine->smp_queue_tail = smp;
	} else {
		engine->smp_queue_tail->qnext = smp;
		engine->smp_queue_tail = smp;
	}
}

static ibnd_smp_t *get_smp(smp_engine_t * engine)
{
	ibnd_smp_t *head = engine->smp_queue_head;
	ibnd_smp_t *tail = engine->smp_queue_tail;
	ibnd_smp_t *rc = head;
	if (head) {
		if (tail == head)
			engine->smp_queue_tail = NULL;
		engine->smp_queue_head = head->qnext;
	}
	return rc;
}

static int send_smp(ibnd_smp_t * smp, struct ibmad_port *srcport)
{
	int rc = 0;
	uint8_t umad[1024];
	ib_rpc_t *rpc = &smp->rpc;

	memset(umad, 0, umad_size() + IB_MAD_SIZE);

	if ((rc = mad_build_pkt(umad, &smp->rpc, &smp->path, NULL, NULL))
	    < 0) {
		IBND_ERROR("mad_build_pkt failed; %d", rc);
		return rc;
	}

	if ((rc = umad_send(mad_rpc_portid(srcport),
			    mad_rpc_class_agent(srcport, rpc->mgtclass),
			    umad, IB_MAD_SIZE,
			    mad_get_timeout(srcport, rpc->timeout),
			    mad_get_retries(srcport))) < 0) {
		IBND_ERROR("send failed; %d", rc);
		return rc;
	}

	return 0;
}

static int process_smp_queue(smp_engine_t * engine)
{
	int rc = 0;
	ibnd_smp_t *smp;
	while (cl_qmap_count(&engine->smps_on_wire) < engine->max_smps_on_wire) {
		smp = get_smp(engine);
		if (!smp)
			return 0;

		cl_qmap_insert(&engine->smps_on_wire, (uint32_t) smp->rpc.trid,
			       (cl_map_item_t *) smp);
		if ((rc = send_smp(smp, engine->ibmad_port)) != 0)
			return rc;
	}
	return 0;
}

int issue_smp(smp_engine_t * engine, ib_portid_t * portid,
	      unsigned attrid, unsigned mod, smp_comp_cb_t cb, void *cb_data)
{
	ibnd_smp_t *smp = calloc(1, sizeof *smp);
	if (!smp) {
		IBND_ERROR("OOM");
		return -ENOMEM;
	}

	smp->cb = cb;
	smp->cb_data = cb_data;
	smp->path = *portid;
	smp->rpc.method = IB_MAD_METHOD_GET;
	smp->rpc.attr.id = attrid;
	smp->rpc.attr.mod = mod;
	smp->rpc.timeout = mad_get_timeout(engine->ibmad_port, 0);
	smp->rpc.datasz = IB_SMP_DATA_SIZE;
	smp->rpc.dataoffs = IB_SMP_DATA_OFFS;
	smp->rpc.trid = mad_trid();

	if (portid->lid <= 0 || portid->drpath.drslid == 0xffff ||
	    portid->drpath.drdlid == 0xffff)
		smp->rpc.mgtclass = IB_SMI_DIRECT_CLASS;	/* direct SMI */
	else
		smp->rpc.mgtclass = IB_SMI_CLASS;	/* Lid routed SMI */

	portid->sl = 0;
	portid->qp = 0;

	engine->total_smps++;
	engine->num_smps_outstanding++;
	queue_smp(engine, smp);
	return process_smp_queue(engine);
}

static int process_one_recv(smp_engine_t * engine)
{
	int rc = 0;
	int status = 0;
	ibnd_smp_t *smp;
	uint8_t *mad;
	uint32_t trid;
	uint8_t umad[umad_size() + IB_MAD_SIZE];
	int length = umad_size() + IB_MAD_SIZE;

	memset(umad, 0, sizeof(umad));

	/* wait for the next message */
	if ((rc = umad_recv(mad_rpc_portid(engine->ibmad_port), umad, &length,
			    0)) < 0) {
		if (rc == -EWOULDBLOCK)
			return 0;
		IBND_ERROR("umad_recv failed: %d\n", rc);
		return -1;
	}

	rc = process_smp_queue(engine);

	mad = umad_get_mad(umad);
	trid = (uint32_t) mad_get_field64(mad, 0, IB_MAD_TRID_F);

	smp = (ibnd_smp_t *) cl_qmap_remove(&engine->smps_on_wire, trid);
	if ((cl_map_item_t *) smp == cl_qmap_end(&engine->smps_on_wire)) {
		IBND_ERROR("Failed to find matching smp for trid (%x)\n", trid);
		return -1;
	}

	if (rc)
		goto error;

	if ((status = umad_status(umad))) {
		IBND_ERROR("umad (%s Attr 0x%x:%u) bad status %d; %s\n",
			   portid2str(&smp->path), smp->rpc.attr.id,
			   smp->rpc.attr.mod, status, strerror(status));
	} else if ((status = mad_get_field(mad, 0, IB_DRSMP_STATUS_F))) {
		IBND_ERROR("mad (%s Attr 0x%x:%u) bad status 0x%x\n",
			   portid2str(&smp->path), smp->rpc.attr.id,
			   smp->rpc.attr.mod, status);
	} else
		rc = smp->cb(engine, smp, mad, smp->cb_data);

error:
	free(smp);
	engine->num_smps_outstanding--;
	return rc;
}

void smp_engine_init(smp_engine_t * engine, struct ibmad_port *ibmad_port,
		     void *user_data, int max_smps_on_wire)
{
	memset(engine, 0, sizeof(*engine));
	engine->ibmad_port = ibmad_port;
	engine->user_data = user_data;
	cl_qmap_init(&engine->smps_on_wire);
	engine->num_smps_outstanding = 0;
	engine->max_smps_on_wire = max_smps_on_wire;
}

void smp_engine_destroy(smp_engine_t * engine)
{
	cl_map_item_t *item;
	ibnd_smp_t *smp;

	/* remove queued smps */
	smp = get_smp(engine);
	if (smp)
		IBND_ERROR("outstanding SMP's\n");
	for ( /* */ ; smp; smp = get_smp(engine))
		free(smp);

	/* remove smps from the wire queue */
	item = cl_qmap_head(&engine->smps_on_wire);
	if (item != cl_qmap_end(&engine->smps_on_wire))
		IBND_ERROR("outstanding SMP's on wire\n");
	for ( /* */ ; item != cl_qmap_end(&engine->smps_on_wire);
	     item = cl_qmap_head(&engine->smps_on_wire)) {
		cl_qmap_remove_item(&engine->smps_on_wire, item);
		free(item);
	}

	engine->num_smps_outstanding = 0;
}

int process_mads(smp_engine_t * engine)
{
	int rc = 0;
	while (engine->num_smps_outstanding > 0) {
		if ((rc = process_smp_queue(engine)) != 0)
			return rc;
		while (!cl_is_qmap_empty(&engine->smps_on_wire))
			if ((rc = process_one_recv(engine)) != 0)
				return rc;
	}
	return 0;
}
