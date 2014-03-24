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
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <infiniband/verbs.h>

extern struct ibv_context **verbs;
extern int dev_cnt;
extern int verbose;


static int
get_pkey(char *ifname, uint16_t *pkey)
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

static int
get_sgid(char *ifname, union ibv_gid *sgid)
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

static int
get_devaddr(char *ifname, int *dev_index, uint8_t *port, uint16_t *pkey)
{
	struct ibv_device_attr dev_attr;
	struct ibv_port_attr port_attr;
	union ibv_gid sgid, gid;
	int ret, i;

	ret = get_sgid(ifname, &sgid);
	if (ret) {
		printf("unable to get sgid\n");
		return ret;
	}

	ret = get_pkey(ifname, pkey);
	if (ret) {
		printf("unable to get pkey\n");
		return ret;
	}

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

				if (!memcmp(sgid.raw, gid.raw, sizeof gid))
					return 0;
			}
		}
	}
	return -1;
}

int gen_addr_ip(FILE *f)
{
	struct ifconf *ifc;
	struct ifreq *ifr;
	char ip[INET6_ADDRSTRLEN];
	int s, ret, dev_index, i, len;
	uint16_t pkey;
	uint8_t port;

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
		printf("ioctl ifconf error %d\n", ret);
		goto out2;
	}

	ifr = ifc->ifc_req;
	for (i = 0; i < ifc->ifc_len / sizeof(struct ifreq); i++) {
		switch (ifr[i].ifr_addr.sa_family) {
		case AF_INET:
			inet_ntop(ifr[i].ifr_addr.sa_family,
				&((struct sockaddr_in *) &ifr[i].ifr_addr)->sin_addr, ip, sizeof ip);
			break;
		case AF_INET6:
			inet_ntop(ifr[i].ifr_addr.sa_family,
				&((struct sockaddr_in6 *) &ifr[i].ifr_addr)->sin6_addr, ip, sizeof ip);
			break;
		default:
			continue;
		}

		ret = ioctl(s, SIOCGIFHWADDR, &ifr[i]);
		if (ret) {
			printf("failed to get hw address %d\n", ret);
			continue;
		}

		if (ifr[i].ifr_hwaddr.sa_family != ARPHRD_INFINIBAND)
			continue;

		ret = get_devaddr(ifr[i].ifr_name, &dev_index, &port, &pkey);
		if (ret)
			continue;

		if (verbose)
			printf("%s %s %d 0x%x\n", ip, verbs[dev_index]->device->name, port, pkey);
		fprintf(f, "%s %s %d 0x%x\n", ip, verbs[dev_index]->device->name, port, pkey);
	}
	ret = 0;

out2:
	free(ifc);
out1:
	close(s);
	return ret;
}
