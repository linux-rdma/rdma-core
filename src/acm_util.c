/*
 * Copyright (c) 2014 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the OpenFabrics.org BSD license
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
#include <net/if_arp.h>

#include "acm_util.h"

int acm_if_is_ib(char *ifname)
{
	unsigned type;
	char buf[128];
	FILE *f;
	int ret;

	snprintf(buf, sizeof buf, "//sys//class//net//%s//type", ifname);
	f = fopen(buf, "r");
	if (!f) {
		printf("failed to open %s\n", buf);
		return 0;
	}

	if (fgets(buf, sizeof buf, f)) {
		type = strtol(buf, NULL, 0);
		ret = (type == ARPHRD_INFINIBAND);
	} else {
		ret = 0;
	}

	fclose(f);
	return ret;
}

int acm_if_get_pkey(char *ifname, uint16_t *pkey)
{
	char buf[128], *end;
	FILE *f;
	int ret;

	snprintf(buf, sizeof buf, "//sys//class//net//%s//pkey", ifname);
	f = fopen(buf, "r");
	if (!f) {
		printf("failed to open %s\n", buf);
		return -1;
	}

	if (fgets(buf, sizeof buf, f)) {
		*pkey = strtol(buf, &end, 16);
		ret = 0;
	} else {
		printf("failed to read pkey\n");
		ret = -1;
	}

	fclose(f);
	return ret;
}

int acm_if_get_sgid(char *ifname, union ibv_gid *sgid)
{
	char buf[128], *end;
	FILE *f;
	int i, p, ret;

	snprintf(buf, sizeof buf, "//sys//class//net//%s//address", ifname);
	f = fopen(buf, "r");
	if (!f) {
		printf("failed to open %s\n", buf);
		return -1;
	}

	if (fgets(buf, sizeof buf, f)) {
		for (i = 0, p = 12; i < 16; i++, p += 3) {
			buf[p + 2] = '\0';
			sgid->raw[i] = (uint8_t) strtol(buf + p, &end, 16);
		}
		ret = 0;
	} else {
		printf("failed to read sgid\n");
		ret = -1;
	}

	fclose(f);
	return ret;
}
