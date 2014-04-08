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
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>

#include <infiniband/acm.h>
#include "acm_mad.h"
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
		acm_log(0, "failed to open %s\n", buf);
		return 0;
	}

	if (fgets(buf, sizeof buf, f)) {
		type = strtol(buf, NULL, 0);
		ret = (type == ARPHRD_INFINIBAND);
	} else {
		acm_log(0, "failed to read interface type\n");
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
		acm_log(0, "failed to open %s\n", buf);
		return -1;
	}

	if (fgets(buf, sizeof buf, f)) {
		*pkey = strtol(buf, &end, 16);
		ret = 0;
	} else {
		acm_log(0, "failed to read pkey\n");
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
		acm_log(0, "failed to open %s\n", buf);
		return -1;
	}

	if (fgets(buf, sizeof buf, f)) {
		for (i = 0, p = 12; i < 16; i++, p += 3) {
			buf[p + 2] = '\0';
			sgid->raw[i] = (uint8_t) strtol(buf + p, &end, 16);
		}
		ret = 0;
	} else {
		acm_log(0, "failed to read sgid\n");
		ret = -1;
	}

	fclose(f);
	return ret;
}

int acm_if_iter_sys(acm_if_iter_cb cb, void *ctx)
{
	struct ifconf *ifc;
	struct ifreq *ifr;
	char ip[INET6_ADDRSTRLEN];
	int s, ret, i, len;
	uint16_t pkey;
	union ibv_gid sgid;
	uint8_t addr_type;
	uint8_t addr[ACM_MAX_ADDRESS];
	size_t addr_len;
	char *alias_sep;

	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (!s)
		return -1;

	len = sizeof(*ifc) + sizeof(*ifr) * 64;
	ifc = malloc(len);
	if (!ifc) {
		ret = -1;
		goto out1;
	}

	memset(ifc, 0, len);
	ifc->ifc_len = len;
	ifc->ifc_req = (struct ifreq *) (ifc + 1);

	ret = ioctl(s, SIOCGIFCONF, ifc);
	if (ret < 0) {
		acm_log(0, "ioctl ifconf error %d\n", ret);
		goto out2;
	}

	ifr = ifc->ifc_req;
	for (i = 0; i < ifc->ifc_len / sizeof(struct ifreq); i++) {
		switch (ifr[i].ifr_addr.sa_family) {
		case AF_INET:
			addr_type = ACM_ADDRESS_IP;
			memcpy(&addr, &((struct sockaddr_in *) &ifr[i].ifr_addr)->sin_addr, sizeof addr);
			addr_len = 4;
			inet_ntop(ifr[i].ifr_addr.sa_family,
				&((struct sockaddr_in *) &ifr[i].ifr_addr)->sin_addr, ip, sizeof ip);
			break;
		case AF_INET6:
			addr_type = ACM_ADDRESS_IP6;
			memcpy(&addr, &((struct sockaddr_in6 *) &ifr[i].ifr_addr)->sin6_addr, sizeof addr);
			addr_len = ACM_MAX_ADDRESS;
			inet_ntop(ifr[i].ifr_addr.sa_family,
				&((struct sockaddr_in6 *) &ifr[i].ifr_addr)->sin6_addr, ip, sizeof ip);
			break;
		default:
			continue;
		}

		acm_log(2, "%s\n", ifr[i].ifr_name);

		alias_sep = strchr(ifr[i].ifr_name, ':');
		if (alias_sep)
			*alias_sep = '\0';

		if (!acm_if_is_ib(ifr[i].ifr_name))
			continue;

		ret = acm_if_get_sgid(ifr[i].ifr_name, &sgid);
		if (ret)
			continue;

		ret = acm_if_get_pkey(ifr[i].ifr_name, &pkey);
		if (ret)
			continue;

		cb(ifr[i].ifr_name, &sgid, pkey, addr_type, addr, addr_len, ip, ctx);
	}
	ret = 0;

out2:
	free(ifc);
out1:
	close(s);
	return ret;

}
