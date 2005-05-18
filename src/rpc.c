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

#include <umad.h>
#include "mad.h"


int ibdebug;

static int mad_portid = -1;
static int iberrs;

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

int
madrpc_def_timeout(void)
{
	return def_madrpc_timeout;
}

int
madrpc_portid(void)
{
	return mad_portid;
}

static int 
_do_madrpc(void *umad, int agentid, int len, int timeout)
{
	int retries;

	if (!timeout)
		timeout = def_madrpc_timeout;

	if (ibdebug > 1) {
		WARN(">>> sending: len %d pktsz %d", len, umad_size());
		xdump(stderr, "send buf\n", umad, umad_size());
	}

	if (save_mad) {
		memcpy(save_mad, umad_get_mad(umad), save_mad_len < len ? save_mad_len : len);
		save_mad = 0;
	}

	for (retries = 0; retries < madrpc_retries; retries++) {
		if (retries)
			ERRS("retry %d (timeout %d ms)", retries+1, timeout);

		if (umad_send(mad_portid, agentid, umad, timeout) < 0) {
			WARN("send failed; %m");
			return -1;
		}

		if (umad_recv(mad_portid, umad, -1) < 0) {
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

/* change to madrpc_qp0 ??? */
void *
madrpc(ib_rpc_t *rpc, ib_portid_t *dport, void *payload, void *rcvdata)
{
	int status, len;
	uint8_t pktbuf[1024], *mad;
	void *umad = pktbuf;

	memset(pktbuf, 0, umad_size());

	if ((len = mad_build_pkt(umad, rpc, dport, 0, payload)) < 0)
		return 0;

	if ((len = _do_madrpc(umad, mad_class_agent(rpc->mgtclass), len, rpc->timeout)) < 0)
		return 0;

	mad = umad_get_mad(umad);

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

/* change to madrpc_qp1 ??? */
void *
madrpc_rmpp(ib_rpc_t *rpc, ib_portid_t *dport, ib_rmpp_hdr_t *rmpp, void *data)
{
	int status, len;
	uint8_t pktbuf[1024], *mad;
	void *umad = pktbuf;

	memset(pktbuf, 0, umad_size());

	DEBUG("rmpp %p data %p", rmpp, data);

	if ((len = mad_build_pkt(umad, rpc, dport, rmpp, data)) < 0)
		return 0;

	if ((len = _do_madrpc(umad, mad_class_agent(rpc->mgtclass),
			      len, rpc->timeout)) < 0)
		return 0;

	mad = umad_get_mad(umad);

	if ((status = mad_get_field(mad, 0, IB_MAD_STATUS_F)) != 0) {
		ERRS("SMP ended with error status %x", status);
		return 0;
	}

	if (ibdebug) {
		WARN("data offs %d sz %d", rpc->dataoffs, rpc->datasz);
		xdump(stderr, "rmpp mad data\n", mad + rpc->dataoffs,
		      rpc->datasz);
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

void
madrpc_init(char *dev_name, int dev_port, int *mgmt_classes, int num_classes)
{
	if (umad_init() < 0)
		PANIC("can't init UMAD library");

	if ((mad_portid = umad_open_port(dev_name, dev_port)) < 0)
		PANIC("can't open UMAD port (%s:%d)", dev_name, dev_port);

	while (num_classes--) {
		int mgmt = *mgmt_classes++;

		if (mad_register_client(mgmt) < 0)
			PANIC("client_register for mgmt %d failed", mgmt);
	}
}
