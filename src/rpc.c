/*
 * Copyright (c) 2004,2005 Voltaire Inc.  All rights reserved.
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
 *
 * $Id$
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <string.h>

#include <common.h>
#include <umad.h>
#include "mad.h"


int ibdebug;

static int mad_portid = -1;
static int iberrs;

static int class_agent[256];
static int madrpc_retries = MAD_DEF_RETRIES;
static int def_madrpc_timeout = MAD_DEF_TIMEOUT_MS;
static void *save_mad;
static int save_mad_len = 256;

#undef DEBUG
#define DEBUG	if (ibdebug)	WARN
#define ERRS	if (iberrs || ibdebug)	WARN

#define MAD_TID(mad)	(*((uint64 *)((char *)(mad) + 8)))

void
madrpc_show_errors(int set)
{
	iberrs = set;
}

void
madrpc_save_mad(void *madbuf, int len)
{
	save_mad = madbuf;
	save_mad_len = len;
}

int
madrpc_set_retries(int retries)
{
	if (retries > 0)
		madrpc_retries = retries;
	return madrpc_retries;
}

int
madrpc_set_timeout(int timeout)
{
	def_madrpc_timeout = timeout;
	return 0;
}

static int 
_do_madrpc(void *umad, int agentid, int len, int timeout)
{
	int retries;

	if (!timeout)
		timeout = def_madrpc_timeout;

	if (ibdebug > 1) {
		WARN(">>> sending: len %d", len);
		xdump(stderr, "send buf\n", umad, len);
	}

	for (retries = 0; retries < madrpc_retries; retries++) {
		if (retries)
			ERRS("retry %d (timeout %d ms)", retries+1, timeout);

		if (umad_send(mad_portid, agentid, umad, timeout) < 0) {
			WARN("send failed; %m");
			return -1;
		}

		if (umad_recv(mad_portid, umad, 0) < 0) {
			WARN("recv failed: %m");
			return -1;
		}
		
		if (ibdebug > 1) {
			WARN("rcv buf:");
			xdump(stderr, "rcv buf\n", umad_get_mad(umad), IB_MAD_SIZE);
		}

		if (!umad_status(umad))
			return IB_MAD_SIZE;		/* done */
	}

	ERRS("timeout after %d retries, %d ms", retries, timeout*retries);
	return -1;
}

void *
madrpc(ib_rpc_t *rpc, ib_portid_t *dport, void *payload, void *rcvdata)
{
	int status, len;
	uint8 pktbuf[1024], *mad, *p;
	void *umad = pktbuf;

	memset(pktbuf, 0, umad_size());
#if 0
	uint8 grh[40] = {0};

	if (rpc->grh) {
		av.grh_flag = 1;        /* Send GRH flag             */
		av.traffic_class = 0;   /* TClass 8 bits             */
		av.flow_label = 0;      /* Flow Label 20 bits        */
		av.hop_limit = 0xff;    /* Hop Limit 8 bits          */
		av.sgid_index = 0;      /* SGID index in SGID table  */
		memcpy(av.dgid, rpc->dgid, sizeof(av.dgid)); /* Destination GID */
	}
#endif
	if (dport->lid)
		umad_set_addr(umad, dport->lid, dport->qp, dport->sl, dport->qkey);
	else
		umad_set_addr(umad, 0xffff, 0, 0, 0);

	umad_set_grh(umad, dport->grh ? 0: 0);	/* FIXME: GRH support */

	umad_set_pkey(umad, dport->pkey_idx);

	mad = umad_get_mad(umad);

	p = encode_MAD(mad, rpc, dport->lid ? 0 : &dport->drpath, payload);
	len = p - pktbuf;

	if ((len = _do_madrpc(umad, class_agent[rpc->mgtclass], len, rpc->timeout)) < 0)
		return 0;

	if (save_mad) {
		memcpy(save_mad, mad, save_mad_len < len ? save_mad_len : len);
		save_mad = 0;
	}

	if ((status = mad_get_field(mad, 0, IB_DRSMP_STATUS_F)) != 0) {
		ERRS("SMP ended with error status %x", status);
		return 0;
	}

	if (ibdebug) {
		WARN("data offs %d sz %d", rpc->dataoffs, rpc->datasz);
		xdump(stderr, "mad data\n", mad + rpc->dataoffs, rpc->datasz);
	}

	if (rcvdata)
		memcpy(rcvdata, mad + rpc->dataoffs, rpc->datasz);

	return rcvdata;
}

void *
madrpc_sa(ib_rpc_t *rpc, ib_portid_t *dport, ib_rmpp_hdr_t *rmpp, void *data)
{
	int status, len;
	uint8 pktbuf[1024], *p, *mad;
	void *umad = pktbuf;

	memset(pktbuf, 0, umad_size());

	DEBUG("rmpp %p data %p", rmpp, data);

	umad_set_addr(umad, dport->lid, dport->qp, dport->sl, dport->qkey);
	umad_set_grh(umad, dport->grh ? 0: 0);	/* FIXME: GRH support */
	umad_set_pkey(umad, dport->pkey_idx);

	mad = umad_get_mad(umad);
	p = encode_MAD(mad, rpc, 0, data);
	len = p - pktbuf;

	if (rmpp) {
		mad_set_field(mad, 0, IB_SA_RMPP_VERS_F, 1);
		mad_set_field(mad, 0, IB_SA_RMPP_TYPE_F, rmpp->type);
		mad_set_field(mad, 0, IB_SA_RMPP_RESP_F, 0x3f);
		mad_set_field(mad, 0, IB_SA_RMPP_FLAGS_F, rmpp->flags);
		mad_set_field(mad, 0, IB_SA_RMPP_STATUS_F, rmpp->status);
		mad_set_field(mad, 0, IB_SA_RMPP_D1_F, rmpp->d1.u);
		mad_set_field(mad, 0, IB_SA_RMPP_D2_F, rmpp->d2.u);
	}

	if ((len = _do_madrpc(umad, class_agent[rpc->mgtclass], len, rpc->timeout)) < 0)
		return 0;

	if ((status = mad_get_field(mad, 0, IB_MAD_STATUS_F)) != 0) {
		ERRS("SMP ended with error status %x", status);
		return 0;
	}

	if (ibdebug) {
		WARN("data offs %d sz %d", rpc->dataoffs, rpc->datasz);
		xdump(stderr, "sa mad data\n", mad + rpc->dataoffs, rpc->datasz);
	}

	if (rmpp) {
		rmpp->flags = mad_get_field(mad, 0, IB_SA_RMPP_FLAGS_F);
		if ((rmpp->flags & 0x3) &&
		    mad_get_field(mad, 0, IB_SA_RMPP_VERS_F) != 1) {
			WARN("bad rmpp version");
			return 0;
		}
		rmpp->type = mad_get_field(mad, 0, IB_SA_RMPP_TYPE_F);
		rmpp->status = mad_get_field(mad, 0, IB_SA_RMPP_STATUS_F);
		DEBUG("rmpp type %d status %d", rmpp->type, rmpp->status);
		rmpp->d1.u = mad_get_field(mad, 0, IB_SA_RMPP_D1_F);
		rmpp->d2.u = mad_get_field(mad, 0, IB_SA_RMPP_D2_F);
	}
	if (data)
		memcpy(data, mad + rpc->dataoffs, rpc->datasz);

	rpc->recsz = mad_get_field(mad, 0, IB_SA_ATTROFFS_F);

	return data;
}

static pthread_mutex_t rpclock = PTHREAD_MUTEX_INITIALIZER;

void
madrpc_lock(void)
{
	pthread_mutex_lock(&rpclock);
}

void
madrpc_unlock(void)
{
	pthread_mutex_unlock(&rpclock);
}

static int
mgmt_class_vers(int mgmt_class)
{
	switch(mgmt_class) {
		case IB_SMI_CLASS:
		case IB_SMI_DIRECT_CLASS:
			return 1;
		case IB_SA_CLASS:
			return 2;
		case IB_PERFORMANCE_CLASS:
			return 1;
	}

	return 0;
}

void
madrpc_init(char *dev_name, int dev_port, int *mgmt_classes, int num_classes)
{
	if (umad_init() < 0)
		PANIC("can't init UMAD library");

	if ((mad_portid = umad_open_port(dev_name, dev_port)) < 0)
		PANIC("can't open UMAD port (%s:%d)", dev_name, dev_port);

	while (num_classes--) {
		int vers, mgmt = *mgmt_classes++;

		if ((vers = mgmt_class_vers(mgmt)) <= 0)
			PANIC("Unknown class %d mgmt_class", mgmt);
		if ((class_agent[mgmt] = umad_register(mad_portid, mgmt, vers, 0)) < 0)
			PANIC("Can't register agent for class %d", mgmt);
	}
}
