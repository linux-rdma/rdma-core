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
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include "cma.h"
#include <rdma/rdma_cma.h>
#include <infiniband/ib.h>
#include <infiniband/sa.h>

#ifdef USE_IB_ACM
#include <infiniband/acm.h>

static pthread_mutex_t acm_lock = PTHREAD_MUTEX_INITIALIZER;
static int sock;
static short server_port = 6125;

struct ib_connect_hdr {
	uint8_t  cma_version;
	uint8_t  ip_version; /* IP version: 7:4 */
	uint16_t port;
	uint32_t src_addr[4];
	uint32_t dst_addr[4];
#define cma_src_ip4 src_addr[3]
#define cma_src_ip6 src_addr[0]
#define cma_dst_ip4 dst_addr[3]
#define cma_dst_ip6 dst_addr[0]
};

void ucma_ib_init(void)
{
	struct sockaddr_in addr;
	int ret;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
		return;

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(server_port);
	ret = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (ret)
		goto err;

	return;

err:
	close(sock);
	sock = 0;
}

void ucma_ib_cleanup(void)
{
	if (sock > 0) {
		shutdown(sock, SHUT_RDWR);
		close(sock);
	}
}

static void ucma_set_sid(enum rdma_port_space ps, struct sockaddr *addr,
			 struct sockaddr_ib *sib)
{
	uint16_t port;

	if (addr->sa_family == AF_INET)
		port = ((struct sockaddr_in *) addr)->sin_port;
	else
		port = ((struct sockaddr_in6 *) addr)->sin6_port;

	sib->sib_sid = htonll(((uint64_t) ps << 16) + ntohs(port));
	if (port)
		sib->sib_sid_mask = ~0ULL;
	else
		sib->sib_sid_mask = htonll(RDMA_IB_IP_PS_MASK);
}

static int ucma_ib_convert_addr(struct rdma_addrinfo *rai,
				struct ibv_path_record *path)
{
	struct sockaddr_ib *src, *dst;

	if (!path)
		return ERR(ENODATA);

	src = calloc(1, sizeof *src);
	if (!src)
		return ERR(ENOMEM);

	dst = calloc(1, sizeof *dst);
	if (!dst) {
		free(src);
		return ERR(ENOMEM);
	}

	src->sib_family = AF_IB;
	src->sib_pkey = path->pkey;
	src->sib_flowinfo = htonl(ntohl(path->flowlabel_hoplimit) >> 8);
	memcpy(&src->sib_addr, &path->sgid, 16);
	ucma_set_sid(rai->ai_port_space, rai->ai_src_addr, src);

	dst->sib_family = AF_IB;
	dst->sib_pkey = path->pkey;
	dst->sib_flowinfo = htonl(ntohl(path->flowlabel_hoplimit) >> 8);
	memcpy(&dst->sib_addr, &path->dgid, 16);
	ucma_set_sid(rai->ai_port_space, rai->ai_dst_addr, dst);

	free(rai->ai_src_addr);
	rai->ai_src_addr = (struct sockaddr *) src;
	rai->ai_src_len = sizeof(*src);

	free(rai->ai_dst_addr);
	rai->ai_dst_addr = (struct sockaddr *) dst;
	rai->ai_dst_len = sizeof(*dst);

	rai->ai_family = AF_IB;
	rai->ai_port_space = RDMA_PS_IB;
	return 0;
}
				 
static void ucma_ib_format_connect(struct rdma_addrinfo *rai)
{
	struct ib_connect_hdr *hdr;

	hdr = calloc(1, sizeof *hdr);
	if (!hdr)
		return;

	if (rai->ai_family == AF_INET) {
		hdr->ip_version = 4 << 4;
		memcpy(&hdr->cma_src_ip4,
		       &((struct sockaddr_in *) rai->ai_src_addr)->sin_addr, 4);
		memcpy(&hdr->cma_dst_ip4,
		       &((struct sockaddr_in *) rai->ai_dst_addr)->sin_addr, 4);
	} else {
		hdr->ip_version = 6 << 4;
		memcpy(&hdr->cma_src_ip6,
		       &((struct sockaddr_in6 *) rai->ai_src_addr)->sin6_addr, 16);
		memcpy(&hdr->cma_dst_ip6,
		       &((struct sockaddr_in6 *) rai->ai_dst_addr)->sin6_addr, 16);
	}

	rai->ai_connect = hdr;
	rai->ai_connect_len = sizeof(*hdr);
}

static void ucma_ib_save_resp(struct rdma_addrinfo *rai, struct acm_resolve_msg *msg)
{
	struct ibv_path_data *path_data = NULL;
	struct ibv_path_record *pri_path = NULL;
	int i, cnt, path_cnt = 0;

	cnt = (msg->hdr.length - ACM_MSG_HDR_LENGTH) / ACM_MSG_EP_LENGTH;
	for (i = 0; i < cnt; i++) {
		switch (msg->data[i].type) {
		case ACM_EP_INFO_PATH:
			msg->data[i].type = 0;
			if (!path_data)
				path_data = (struct ibv_path_data *) &msg->data[i];
			path_cnt++;
			if (msg->data[i].flags |
			    (IBV_PATH_FLAG_PRIMARY | IBV_PATH_FLAG_OUTBOUND))
				pri_path = &path_data[i].path;
			break;
		case ACM_EP_INFO_ADDRESS_IP:
			if (!(msg->data[i].flags & ACM_EP_FLAG_SOURCE) || rai->ai_src_len)
				break;

			rai->ai_src_addr = calloc(1, sizeof(struct sockaddr_in));
			if (!rai->ai_src_addr)
				break;

			rai->ai_src_len = sizeof(struct sockaddr_in);
			memcpy(&((struct sockaddr_in *) rai->ai_src_addr)->sin_addr,
			       &msg->data[i].info.addr, 4);
			break;
		case ACM_EP_INFO_ADDRESS_IP6:
			if (!(msg->data[i].flags & ACM_EP_FLAG_SOURCE) || rai->ai_src_len)
				break;

			rai->ai_src_addr = calloc(1, sizeof(struct sockaddr_in6));
			if (!rai->ai_src_addr)
				break;

			rai->ai_src_len = sizeof(struct sockaddr_in6);
			memcpy(&((struct sockaddr_in6 *) rai->ai_src_addr)->sin6_addr,
			       &msg->data[i].info.addr, 16);
			break;
		default:
			break;
		}
	}

	rai->ai_route = calloc(path_cnt, sizeof(*path_data));
	if (rai->ai_route) {
		memcpy(rai->ai_route, path_data, path_cnt * sizeof(*path_data));
		rai->ai_route_len = path_cnt * sizeof(*path_data);
	}

	if (af_ib_support && !(rai->ai_flags & RAI_ROUTEONLY)) {
		ucma_ib_format_connect(rai);
		if (ucma_ib_convert_addr(rai, pri_path) &&
		    rai->ai_connect) {
			free(rai->ai_connect);
			rai->ai_connect_len = 0;
		}
	}
}

static void ucma_copy_rai_addr(struct acm_ep_addr_data *data, struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET) {
		data->type = ACM_EP_INFO_ADDRESS_IP;
		memcpy(data->info.addr, &((struct sockaddr_in *) addr)->sin_addr, 4);
	} else {
		data->type = ACM_EP_INFO_ADDRESS_IP6;
		memcpy(data->info.addr, &((struct sockaddr_in6 *) addr)->sin6_addr, 16);
	}
}

void ucma_ib_resolve(struct rdma_addrinfo *rai, struct rdma_addrinfo *hints)
{
	struct acm_msg msg;
	struct acm_resolve_msg *resolve_msg = (struct acm_resolve_msg *) &msg;
	struct acm_ep_addr_data *data;
	int ret;

	if (sock <= 0)
		return;

	memset(&msg, 0, sizeof msg);
	msg.hdr.version = ACM_VERSION;
	msg.hdr.opcode = ACM_OP_RESOLVE;
	msg.hdr.length = ACM_MSG_HDR_LENGTH;

	data = &resolve_msg->data[0];
	if (rai->ai_src_len) {
		data->flags = ACM_EP_FLAG_SOURCE;
		ucma_copy_rai_addr(data, rai->ai_src_addr);
		data++;
		msg.hdr.length += ACM_MSG_EP_LENGTH;
	}

	if (rai->ai_dst_len) {
		data->flags = ACM_EP_FLAG_DEST;
		ucma_copy_rai_addr(data, rai->ai_dst_addr);
		data++;
		msg.hdr.length += ACM_MSG_EP_LENGTH;
	}

	if (hints && hints->ai_route_len) {
		data->type = ACM_EP_INFO_PATH;
		memcpy(&data->info.path, hints->ai_route, hints->ai_route_len);
		data++;
		msg.hdr.length += ACM_MSG_EP_LENGTH;
	}

	pthread_mutex_lock(&acm_lock);
	ret = send(sock, (char *) &msg, msg.hdr.length, 0);
	if (ret != msg.hdr.length) {
		pthread_mutex_unlock(&acm_lock);
		return;
	}

	ret = recv(sock, (char *) &msg, sizeof msg, 0);
	pthread_mutex_unlock(&acm_lock);
	if (ret < ACM_MSG_HDR_LENGTH || ret != msg.hdr.length || msg.hdr.status)
		return;

	ucma_ib_save_resp(rai, resolve_msg);
}

#endif /* USE_IB_ACM */
