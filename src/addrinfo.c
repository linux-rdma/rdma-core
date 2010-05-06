/*
 * Copyright (c) 2010 Intel Corporation.  All rights reserved.
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
 * $Id: cm.c 3453 2005-09-15 21:43:21Z sean.hefty $
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "cma.h"
#include <rdma/rdma_cma.h>
#include <infiniband/ib.h>

static void ucma_convert_to_ai(struct addrinfo *ai, struct rdma_addrinfo *rai)
{
	memset(ai, 0, sizeof *ai);
	ai->ai_flags = rai->ai_flags;
	ai->ai_family = rai->ai_family;

	switch (rai->ai_qp_type) {
	case IBV_QPT_RC:
		ai->ai_socktype = SOCK_STREAM;
		break;
	case IBV_QPT_UD:
		ai->ai_socktype = SOCK_DGRAM;
		break;
	}

	switch (rai->ai_port_space) {
	case RDMA_PS_TCP:
		ai->ai_protocol = IPPROTO_TCP;
		break;
	case RDMA_PS_IPOIB:
	case RDMA_PS_UDP:
		ai->ai_protocol = IPPROTO_UDP;
		break;
	}

	if (rai->ai_flags & RAI_PASSIVE) {
		ai->ai_addrlen = rai->ai_src_len;
		ai->ai_addr = rai->ai_src_addr;
	} else {
		ai->ai_addrlen = rai->ai_dst_len;
		ai->ai_addr = rai->ai_dst_addr;
	}
	ai->ai_canonname = rai->ai_dst_canonname;
	ai->ai_next = NULL;
}

static int ucma_convert_to_rai(struct rdma_addrinfo *rai, struct addrinfo *ai)
{
	struct sockaddr *addr;
	char *canonname;

	memset(rai, 0, sizeof *rai);
	rai->ai_flags = ai->ai_flags;
	rai->ai_family = ai->ai_family;

	switch (ai->ai_socktype) {
	case SOCK_STREAM:
		rai->ai_qp_type = IBV_QPT_RC;
		break;
	case SOCK_DGRAM:
		rai->ai_qp_type = IBV_QPT_UD;
		break;
	}

	switch (ai->ai_protocol) {
	case IPPROTO_TCP:
		rai->ai_port_space = RDMA_PS_TCP;
		break;
	case IPPROTO_UDP:
		rai->ai_port_space = RDMA_PS_UDP;
		break;
	}

	addr = malloc(ai->ai_addrlen);
	if (!addr)
		return ERR(ENOMEM);

	canonname = ai->ai_canonname ? malloc(strlen(ai->ai_canonname) + 1) : NULL;
	if (canonname)
		strcpy(canonname, ai->ai_canonname);

	memcpy(addr, ai->ai_addr, ai->ai_addrlen);
	if (ai->ai_flags & RAI_PASSIVE) {
		rai->ai_src_addr = addr;
		rai->ai_src_len = ai->ai_addrlen;
		rai->ai_src_canonname = canonname;
	} else {
		rai->ai_dst_addr = addr;
		rai->ai_dst_len = ai->ai_addrlen;
		rai->ai_dst_canonname = canonname;
	}

	return 0;
}

int rdma_getaddrinfo(char *node, char *service,
		     struct rdma_addrinfo *hints,
		     struct rdma_addrinfo **res)
{
	struct rdma_addrinfo *rai;
	struct addrinfo ai_hints;
	struct addrinfo *ai;
	int ret;

	ret = ucma_init();
	if (ret)
		return ret;

	if (hints)
		ucma_convert_to_ai(&ai_hints, hints);

	ret = getaddrinfo(node, service, &ai_hints, &ai);
	if (ret)
		return ret;

	rai = malloc(sizeof(*rai));
	if (!rai) {
		ret = ERR(ENOMEM);
		goto err1;
	}

	ret = ucma_convert_to_rai(rai, ai);
	if (ret)
		goto err2;

	freeaddrinfo(ai);
	*res = rai;
	return 0;

err2:
	rdma_freeaddrinfo(rai);
err1:
	freeaddrinfo(ai);
	return ret;
}

void rdma_freeaddrinfo(struct rdma_addrinfo *res)
{
	struct rdma_addrinfo *rai;

	while (res) {
		rai = res;
		res = res->ai_next;

		if (rai->ai_connect)
			free(rai->ai_connect);

		if (rai->ai_route)
			free(rai->ai_route);

		if (rai->ai_src_canonname)
			free(rai->ai_src_canonname);

		if (rai->ai_dst_canonname)
			free(rai->ai_dst_canonname);

		if (rai->ai_src_addr)
			free(rai->ai_src_addr);

		if (rai->ai_dst_addr)
			free(rai->ai_dst_addr);

		free(rai);
	}
}
