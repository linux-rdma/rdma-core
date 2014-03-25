/*
 * Copyright (c) 2009 Intel Corporation. All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
 * below:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <infiniband/verbs.h>
#include "acm_util.h"

extern struct ibv_context **verbs;
extern int dev_cnt;
extern int verbose;

static int
get_devaddr(union ibv_gid *sgid, int *dev_index, uint8_t *port)
{
	struct ibv_device_attr dev_attr;
	struct ibv_port_attr port_attr;
	union ibv_gid gid;
	int ret, i;

	for (*dev_index = 0; *dev_index < dev_cnt; (*dev_index)++) {
		ret = ibv_query_device(verbs[*dev_index], &dev_attr);
		if (ret)
			continue;

		for (*port = 1; *port <= dev_attr.phys_port_cnt; (*port)++) {
			ret = ibv_query_port(verbs[*dev_index], *port, &port_attr);
			if (ret)
				continue;

			for (i = 0; i < port_attr.gid_tbl_len; i++) {
				ret = ibv_query_gid(verbs[*dev_index], *port, i, &gid);
				if (ret || !gid.global.interface_id)
					break;

				if (!memcmp(sgid->raw, gid.raw, sizeof gid))
					return 0;
			}
		}
	}
	return -1;
}

static void iter_cb(char *ifname, union ibv_gid *gid, uint16_t pkey,
		uint8_t addr_type, uint8_t *addr, size_t addr_len,
		char *addr_name, void *ctx)
{
	FILE *f = (FILE *)ctx;
	int ret;
	int dev_index;
	uint8_t port;

	ret = get_devaddr(gid, &dev_index, &port);
	if (ret) {
		printf("Failed to find verbs device for %s\n", ifname);
		return;
	}

	if (verbose)
		printf("%s %s %d 0x%x\n", addr_name, verbs[dev_index]->device->name, port, pkey);
	fprintf(f, "%s %s %d 0x%x\n", addr_name, verbs[dev_index]->device->name, port, pkey);
}

int gen_addr_ip(FILE *f)
{
	return acm_if_iter_sys(iter_cb, (void *)f);
}
