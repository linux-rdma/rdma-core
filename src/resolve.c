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
 * $Id$
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <sys/time.h>

#include <common.h>
#include <umad.h>
#include <mad.h>


#undef DEBUG
#define DEBUG 	if (ibdebug)	WARN

int
ib_resolve_smlid(ib_portid_t *sm_id, int timeout)
{
	ib_portid_t self = {0};
	char portinfo[64];
	int lid;

	if (!smp_query(portinfo, &self, IB_ATTR_PORT_INFO, 0, 0))
		return -1;

	mad_decode_field(portinfo, IB_PORT_SMLID_F, &lid);

	return ib_portid_set(sm_id, lid, 0, 0);
}

int
ib_resolve_guid(ib_portid_t *portid, uint64_t *guid, ib_portid_t *sm_id, int timeout)
{
	ib_portid_t sm_portid;
	char buf[IB_SA_DATA_SIZE] = {0};

	if (!sm_id) {
		sm_id = &sm_portid;
		if (ib_resolve_smlid(sm_id, timeout) < 0)
			return -1;
	}
	if (*(uint64*)&portid->gid == 0)
		mad_set_field64(portid->gid, 0, IB_GID_PREFIX_F, IB_DEFAULT_SUBN_PREFIX);
	if (guid)
		mad_set_field64(portid->gid, 0, IB_GID_GUID_F, *guid);

	if ((portid->lid = ib_path_query(portid->gid, portid->gid, sm_id, buf)) < 0)
		return -1;

	return 0;
}
	
int
ib_resolve_portid_str(ib_portid_t *portid, char *addr_str, int dest_type, ib_portid_t *sm_id)
{
	uint64_t guid;
	int lid;

	switch (dest_type) {
	case IB_DEST_LID:
		lid = strtol(addr_str, 0, 0);
		if (!IB_LID_VALID(lid))
			return -1;
		return ib_portid_set(portid, lid, 0, 0);

	case IB_DEST_DRPATH:
		if (str2drpath(&portid->drpath, addr_str, 0, 0) < 0)
			return -1;
		return 0;

	case IB_DEST_GUID:
		if (!(guid = strtoll(addr_str, 0, 0)))
			return -1;

		/* keep guid in portid? */
		return ib_resolve_guid(portid, &guid, sm_id, 0);

	default:
		WARN("bad dest_type %d", dest_type);
	}

	return -1;
}

int
ib_resolve_self(ib_portid_t *portid)
{
	ib_portid_t self = {0};
	char portinfo[64];
	char nodeinfo[64];
	uint64 guid, prefix;
	
	if (!smp_query(nodeinfo, &self, IB_ATTR_NODE_INFO, 0, 0))
		return -1;

	if (!smp_query(portinfo, &self, IB_ATTR_PORT_INFO, 0, 0))
		return -1;

	mad_decode_field(portinfo, IB_PORT_LID_F, &portid->lid);
	mad_decode_field(portinfo, IB_PORT_GID_PREFIX_F, &prefix);
	mad_decode_field(portinfo, IB_NODE_PORT_GUID_F, &guid);

	mad_encode_field(portid->gid, IB_GID_PREFIX_F, &prefix);
	mad_encode_field(portid->gid, IB_GID_GUID_F, &prefix);

	return 0;
}