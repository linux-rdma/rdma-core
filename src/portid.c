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
#include <sys/time.h>
#include <string.h>

#include <mad.h>

#undef DEBUG
#define DEBUG	if (ibdebug)	WARN

int
portid2portnum(ib_portid_t *portid)
{
	if (portid->lid > 0)
		return -1;

	if (portid->drpath.cnt == 0)
		return 0;

	return portid->drpath.p[(portid->drpath.cnt-1)];
}

char *
portid2str(ib_portid_t *portid)
{
	static char buf[1024] = "local";
	char *s = buf;
	int i;

	if (portid->lid > 0) {
		s += sprintf(s, "Lid 0x%x", portid->lid);
		if (portid->grh) {
#if __WORDSIZE == 64
			s += sprintf(s, " Gid %lx%lx",
#else
			s += sprintf(s, " Gid %Lx%Lx",
#endif
					*(uint64_t *)portid->gid,
					*(uint64_t *)(portid->gid+8));
		}
		return buf;
	}
	s += sprintf(s, "DR path ");
	for (i = 0; i < portid->drpath.cnt+1; i++)
		s += sprintf(s, "[%d]", portid->drpath.p[i]);

	return buf;
}

int
str2drpath(ib_dr_path_t *path, char *routepath, int drslid, int drdlid)
{
	char *s, *str = routepath;

	path->cnt = -1;

	DEBUG("DR str: %s", routepath);
	while (str && *str) {
		if ((s = strchr(str, ',')))
			*s = 0;
		path->p[++path->cnt] = atoi(str);
		if (!s)
			break;
		str = s+1;
	}

	path->drdlid = drdlid ? drdlid : 0xffff;
	path->drslid = drslid ? drslid : 0xffff;

	return path->cnt;
}
