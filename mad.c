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
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#include <common.h>
#include "mad.h"

#undef DEBUG
#define DEBUG	if (ibdebug)	WARN

void
mad_decode_field(uint8 *buf, int field, void *val)
{
	ib_field_t *f = ib_mad_f + field;

	if (!field) {
		*(int *)val = *(int *)buf;
		return;
	}
	if (f->bitlen <= 32) {
		*(uint32 *)val = _get_field(buf, 0, f);
		return;
	}
	if (f->bitlen == 64) {
		*(uint64 *)val = _get_field64(buf, 0, f);
		return;
	}
	_get_array(buf, 0, f, val);
}

void
mad_encode_field(uint8 *buf, int field, void *val)
{
	ib_field_t *f = ib_mad_f + field;

	if (!field) {
		*(int *)buf = *(int *)val;
		return;
	}
	if (f->bitlen <= 32) {
		_set_field(buf, 0, f, *(uint32 *)val);
		return;
	}
	if (f->bitlen == 32) {
		_set_field64(buf, 0, f, *(uint64 *)val);
		return;
	}
	_set_array(buf, 0, f, val);
}

static uint64 trid = 0x1122334455667788;

uint64
mad_trid(void)
{
	static uint64 base;
	uint64 next;

	if (!base) {
		srandom(time(0)*getpid());
		base = random();
	}
	next = ++trid | (base << 32);
	return htonll(next);
}

void *
encode_MAD(void *buf, ib_rpc_t *rpc, ib_dr_path_t *drpath, void *data)
{
	memset(buf, 0, IB_MAD_SIZE);

	/* first word */
	mad_set_field(buf, 0, IB_MAD_METHOD_F, rpc->method);
	mad_set_field(buf, 0, IB_MAD_RESPONSE_F, 0);
	mad_set_field(buf, 0, IB_MAD_CLASSVER_F, rpc->mgtclass == IB_SA_CLASS ? 2 : 1);
	mad_set_field(buf, 0, IB_MAD_MGMTCLASS_F, rpc->mgtclass);
	mad_set_field(buf, 0, IB_MAD_BASEVER_F, 1);

	/* second word */
	if (rpc->mgtclass == IB_SMI_DIRECT_CLASS) {
		if (!drpath) {
			WARN("encoding dr mad without drpath (null)");
			return 0;
		}
		mad_set_field(buf, 0, IB_DRSMP_HOPCNT_F, drpath->cnt);
		mad_set_field(buf, 0, IB_DRSMP_HOPPTR_F, 0x0);
		mad_set_field(buf, 0, IB_DRSMP_STATUS_F, 0);
		mad_set_field(buf, 0, IB_DRSMP_DIRECTION_F, 0);	/* out */
	} else
		mad_set_field(buf, 0, IB_MAD_STATUS_F, 0);

	/* words 3,4,5,6 */
	if (!rpc->trid)
		rpc->trid = mad_trid();

	mad_encode_field(buf, IB_MAD_TRID_F, &rpc->trid);
	mad_set_field(buf, 0, IB_MAD_ATTRID_F, rpc->attr.id);
	mad_set_field(buf, 0, IB_MAD_ATTRMOD_F, rpc->attr.mod);

	/* words 7,8 */
	mad_set_field(buf, 0, IB_MAD_MKEY_F, rpc->mkey >> 32);
	mad_set_field(buf, 4, IB_MAD_MKEY_F, rpc->mkey & 0xffffffff);

	if (rpc->mgtclass == IB_SMI_DIRECT_CLASS) {
		/* word 9 */
		mad_set_field(buf, 0, IB_DRSMP_DRDLID_F, drpath->drdlid ? drpath->drdlid : 0xffff);
		mad_set_field(buf, 0, IB_DRSMP_DRSLID_F, drpath->drslid ? drpath->drslid : 0xffff);

		/* bytes 128 - 256 */
		mad_set_array(buf, 0, IB_DRSMP_PATH_F, drpath->p);
		// mad_set_array(buf, 0, IB_DRSMP_RPATH_F, 0);	/* should be zero due memset*/
	}

	if (rpc->mgtclass == IB_SA_CLASS)
		mad_set_field64(buf, 0, IB_SA_COMPMASK_F, rpc->mask);

	if (data)
		memcpy((char *)buf + rpc->dataoffs, data, rpc->datasz);

	return (uint8 *)buf + IB_MAD_SIZE;
}
