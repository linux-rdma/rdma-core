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
#include <inttypes.h>
#include <net/if_arp.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/socket.h>

#include <infiniband/acm.h>
#include "acm_mad.h"
#include "acm_util.h"

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

static struct nl_sock *sk;
static struct nl_cache *link_cache;
static struct nl_cache *addr_cache;

int acm_init_if_iter_sys(void)
{
	int sts;

	sk = nl_socket_alloc();
	if (!sk) {
		acm_log(0, "nl_socket_alloc");
		return -1;
	}

	sts = nl_connect(sk, NETLINK_ROUTE);
	if (sts) {
		acm_log(0, "nl_connect failed");
		goto out_connect;
	}

	sts = rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache);
	if (sts) {
		acm_log(0, "rtnl_link_alloc_cache failed");
		goto out_connect;
	}

	sts = rtnl_addr_alloc_cache(sk, &addr_cache);
	if (sts) {
		acm_log(0, "rtnl_addr_alloc_cache");
		goto out_addr;
	}

	return 0;

out_addr:
	nl_cache_free(link_cache);

out_connect:
	nl_close(sk);
	return sts;
}

void acm_fini_if_iter_sys(void)
{
	nl_cache_free(link_cache);
	nl_cache_free(addr_cache);
	nl_close(sk);
}

static inline int af2acm_addr_type(int af)
{
	switch (af) {
	case AF_INET:
		return ACM_ADDRESS_IP;

	case AF_INET6:
		return ACM_ADDRESS_IP6;
	}

	acm_log(0, "Unnkown address family\n");
	return ACM_ADDRESS_INVALID;
}

struct ctx_and_cb {
	void *ctx;
	acm_if_iter_cb cb;
};

static void acm_if_iter(struct nl_object *obj, void *_ctx_and_cb)
{
	struct ctx_and_cb *ctx_cb = (struct ctx_and_cb *)_ctx_and_cb;
	struct rtnl_addr *addr = (struct rtnl_addr *)obj;
	struct nl_addr *a = rtnl_addr_get_local(addr);
	uint8_t bin_addr[ACM_MAX_ADDRESS] = {};
	int addr_len = nl_addr_get_len(a);
	char ip_str[INET6_ADDRSTRLEN];
	struct nl_addr *link_addr;
	struct rtnl_link *link;
	char flags_str[128];
	union ibv_gid sgid;
	uint16_t pkey;
	char *label;
	int af;

	link = rtnl_link_get(link_cache, rtnl_addr_get_ifindex(addr));

	if (rtnl_link_get_arptype(link) != ARPHRD_INFINIBAND)
		return;

	if (!a)
		return;

	if (addr_len > ACM_MAX_ADDRESS) {
		acm_log(0, "address too long (%d)\n", addr_len);
		return;
	}

	af = nl_addr_get_family(a);
	if (af != AF_INET && af != AF_INET6)
		return;

	label = rtnl_addr_get_label(addr);

	link_addr = rtnl_link_get_addr(link);
	/* gid has a 4 byte offset into the link address */
	memcpy(sgid.raw, nl_addr_get_binary_addr(link_addr) + 4, sizeof(sgid));

	if (acm_if_get_pkey(rtnl_link_get_name(link), &pkey))
		return;

	acm_log(2, "name: %5s label: %9s index: %2d flags: %s addr: %s pkey: 0x%04x guid: 0x%" PRIx64 "\n",
		rtnl_link_get_name(link), label,
		rtnl_addr_get_ifindex(addr),
		rtnl_link_flags2str(rtnl_link_get_flags(link), flags_str, sizeof(flags_str)),
		nl_addr2str(a, ip_str, sizeof(ip_str)),	pkey,
		be64toh(sgid.global.interface_id));

	memcpy(&bin_addr, nl_addr_get_binary_addr(a), addr_len);
	ctx_cb->cb(label ? label : rtnl_link_get_name(link),
		   &sgid, pkey, af2acm_addr_type(af), bin_addr, ip_str, ctx_cb->ctx);
}


int acm_if_iter_sys(acm_if_iter_cb cb, void *ctx)
{
	struct ctx_and_cb ctx_cb;
	int sts;

	sts = nl_cache_refill(sk, link_cache);
	if (sts) {
		acm_log(0, "nl_cache_refill link_cache");
		return sts;
	}

	sts = nl_cache_refill(sk, addr_cache);
	if (sts) {
		acm_log(0, "nl_cache_refill addr_cache");
		return sts;
	}

	ctx_cb.ctx = ctx;
	ctx_cb.cb = cb;
	nl_cache_foreach(addr_cache, acm_if_iter, (void *)&ctx_cb);

	return 0;
}
