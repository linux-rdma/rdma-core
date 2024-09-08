/*
 * Copyright (c) 2004-2009 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>

#include "smi_gsi.h"
#include "mad_internal.h"

#undef DEBUG
#define DEBUG	if (ibdebug)	IBWARN

int mad_send(ib_rpc_t * rpc, ib_portid_t * dport, ib_rmpp_hdr_t * rmpp,
	     void *data)
{
	return mad_send_via(rpc, dport, rmpp, data, ibmp);
}

int mad_send_via(ib_rpc_t * rpc, ib_portid_t * dport, ib_rmpp_hdr_t * rmpp,
		 void *data, struct ibmad_port *srcport)
{
	uint8_t pktbuf[1024];
	void *umad = pktbuf;
	int port_id;

	memset(pktbuf, 0, umad_size() + IB_MAD_SIZE);

	DEBUG("rmpp %p data %p", rmpp, data);

	if (mad_build_pkt(umad, rpc, dport, rmpp, data) < 0)
		return -1;

	if (ibdebug) {
		IBWARN("data offs %d sz %d", rpc->dataoffs, rpc->datasz);
		xdump(stderr, "mad send data\n",
		      (char *)umad_get_mad(umad) + rpc->dataoffs, rpc->datasz);
	}

	port_id = smi_gsi_port_by_class(srcport->port_id,
				mad_get_field(umad_get_mad(umad), 0, IB_MAD_MGMTCLASS_F));


    if (umad_send(port_id, srcport->class_agents[rpc->mgtclass & 0xff],
		      umad, IB_MAD_SIZE, mad_get_timeout(srcport, rpc->timeout),
		      0) < 0) {
		IBWARN("send failed; %s", strerror(errno));
		return -1;
	}

	return 0;
}

int mad_respond(void *umad, ib_portid_t * portid, uint32_t rstatus)
{
	return mad_respond_via(umad, portid, rstatus, ibmp);
}

int mad_respond_via(void *umad, ib_portid_t * portid, uint32_t rstatus,
		    struct ibmad_port *srcport)
{
	uint8_t *mad = umad_get_mad(umad);
	ib_mad_addr_t *mad_addr;
	ib_rpc_t rpc = { 0 };
	ib_portid_t rport;
	int is_smi;

	if (!portid) {
		if (!(mad_addr = umad_get_mad_addr(umad))) {
			errno = EINVAL;
			return -1;
		}

		memset(&rport, 0, sizeof(rport));

		rport.lid = ntohs(mad_addr->lid);
		rport.qp = ntohl(mad_addr->qpn);
		rport.qkey = ntohl(mad_addr->qkey);
		rport.sl = mad_addr->sl;

		portid = &rport;
	}

	DEBUG("dest %s", portid2str(portid));

	rpc.mgtclass = mad_get_field(mad, 0, IB_MAD_MGMTCLASS_F);

	rpc.method = mad_get_field(mad, 0, IB_MAD_METHOD_F);
	if (rpc.method == IB_MAD_METHOD_SET)
		rpc.method = IB_MAD_METHOD_GET;
	if (rpc.method != IB_MAD_METHOD_SEND)
		rpc.method |= IB_MAD_RESPONSE;

	rpc.attr.id = mad_get_field(mad, 0, IB_MAD_ATTRID_F);
	rpc.attr.mod = mad_get_field(mad, 0, IB_MAD_ATTRMOD_F);
	if (rpc.mgtclass == IB_SA_CLASS)
		rpc.recsz = mad_get_field(mad, 0, IB_SA_ATTROFFS_F);
	if (mad_is_vendor_range2(rpc.mgtclass))
		rpc.oui = mad_get_field(mad, 0, IB_VEND2_OUI_F);

	rpc.trid = mad_get_field64(mad, 0, IB_MAD_TRID_F);
	rpc.rstatus = rstatus;

	/* cleared by default: timeout, datasz, dataoffs, mkey, mask */

	is_smi = rpc.mgtclass == IB_SMI_CLASS ||
	    rpc.mgtclass == IB_SMI_DIRECT_CLASS;

	if (is_smi)
		portid->qp = 0;
	else if (!portid->qp)
		portid->qp = 1;

	if (!portid->qkey && portid->qp == 1)
		portid->qkey = IB_DEFAULT_QP1_QKEY;

	DEBUG
	    ("qp 0x%x class 0x%x method %d attr 0x%x mod 0x%x datasz %d off %d qkey %x",
	     portid->qp, rpc.mgtclass, rpc.method, rpc.attr.id, rpc.attr.mod,
	     rpc.datasz, rpc.dataoffs, portid->qkey);

	if (mad_build_pkt(umad, &rpc, portid, NULL, NULL) < 0)
		return -1;

	if (ibdebug > 1)
		xdump(stderr, "mad respond pkt\n", mad, IB_MAD_SIZE);

	if (umad_send
	    (srcport->port_id, srcport->class_agents[rpc.mgtclass], umad,
	     IB_MAD_SIZE, mad_get_timeout(srcport, rpc.timeout), 0) < 0) {
		DEBUG("send failed; %s", strerror(errno));
		return -1;
	}

	return 0;
}

void *mad_receive(void *umad, int timeout)
{
	return mad_receive_via(umad, timeout, ibmp);
}

void *mad_receive_via(void *umad, int timeout, struct ibmad_port *srcport)
{
	void *mad;
	int rc;
	int length = IB_MAD_SIZE;

	struct pollfd fds[2];
	ports_record_t * x = smi_gsi_record_find(srcport->port_id);

	if (!x) {
		IBWARN("Couldn't resolve SMI/GSI_device for %d.", srcport->port_id);
	}

	fds[0].fd = umad_get_fd(x->smi_port_id);
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	fds[1].fd = umad_get_fd(x->gsi_port_id);
	fds[1].events = POLLIN;
	fds[1].revents = 0;

	rc = poll(fds, 2, timeout);

	if (rc < 0) {
		IBWARN("Call poll failed for %d with error: %s",
				srcport->port_id, strerror(errno));
		return NULL;
	}

	mad = umad ? umad : umad_alloc(1, umad_size() + IB_MAD_SIZE);

	if (fds[0].revents & POLLIN) {
		rc = umad_recv(x->smi_port_id, mad, &length, 0);
	} else if (fds[1].revents & POLLIN) {
		rc = umad_recv(x->gsi_port_id, mad, &length, 0);
	} else {
		IBWARN("Call poll failed for %d with error: %s",
				srcport->port_id, strerror(errno));

		rc = -1;
    }

	if (rc < 0) {

		if (!umad)
			umad_free(mad);

		DEBUG("recv failed: %s", strerror(errno));
		return NULL;
	}

	return mad;
}

void *mad_alloc(void)
{
	return umad_alloc(1, umad_size() + IB_MAD_SIZE);
}

void mad_free(void *umad)
{
	umad_free(umad);
}
