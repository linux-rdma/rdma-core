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
#include <mad.h>

#undef DEBUG
#define DEBUG	if (ibdebug)	WARN

int
mad_send(ib_rpc_t *rpc, ib_portid_t *dport, ib_rmpp_hdr_t *rmpp, void *data)
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
	p = mad_encode(mad, rpc, 0, data);
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

	if (ibdebug) {
		WARN("data offs %d sz %d", rpc->dataoffs, rpc->datasz);
		xdump(stderr, "mad send data\n", mad + rpc->dataoffs, rpc->datasz);
	}

	if (umad_send(madrpc_portid(), mad_class_agent(rpc->mgtclass), umad, rpc->timeout) < 0) {
		WARN("send failed; %m");
		return -1;
	}

	return 0;
}

void *
mad_receive(void *umad, int timeout)
{
	void *mad = umad ? umad : umad_alloc(1);
	int agent;

	if ((agent = umad_recv(madrpc_portid(), mad, 0)) < 0) {
		DEBUG("recv failed: %m");
		return 0;
	}

	return mad;
}

void *
mad_alloc(void)
{
	return umad_alloc(1);
}

void
mad_free(void *umad)
{
	umad_free(umad);
}
