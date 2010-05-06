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

static void ucma_ib_save_resp(struct rdma_addrinfo *rai, struct acm_resolve_msg *msg)
{
	struct ibv_path_data *path_data = NULL;
	int i, cnt, path_cnt;

	cnt = (msg->hdr.length - ACM_MSG_HDR_LENGTH) / ACM_MSG_EP_LENGTH;
	for (i = 0; i < cnt; i++) {
		switch (msg->data[i].type) {
		case ACM_EP_INFO_PATH:
			msg->data[i].type = 0;
			if (!path_data)
				path_data = (struct ibv_path_data *) &msg->data[i];
			path_cnt++;
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
}

void ucma_ib_resolve(struct rdma_addrinfo *rai)
{
	struct acm_msg msg;
	struct acm_resolve_msg *resolve_msg = (struct acm_resolve_msg *) &msg;
	struct acm_ep_addr_data *src_data, *dst_data;
	int ret;

	if (sock <= 0)
		return;

	memset(&msg, 0, sizeof msg);
	msg.hdr.version = ACM_VERSION;
	msg.hdr.opcode = ACM_OP_RESOLVE;

	if (rai->ai_src_len) {
		src_data = &resolve_msg->data[0];
		src_data->flags = ACM_EP_FLAG_SOURCE;
		if (rai->ai_family == AF_INET) {
			src_data->type = ACM_EP_INFO_ADDRESS_IP;
			memcpy(src_data->info.addr,
			       &((struct sockaddr_in *) rai->ai_src_addr)->sin_addr, 4);
		} else {
			src_data->type = ACM_EP_INFO_ADDRESS_IP6;
			memcpy(src_data->info.addr,
			       &((struct sockaddr_in6 *) rai->ai_src_addr)->sin6_addr, 16);
		}
		dst_data = &resolve_msg->data[1];
		msg.hdr.length = ACM_MSG_HDR_LENGTH + (2 * ACM_MSG_EP_LENGTH);
	} else {
		dst_data = &resolve_msg->data[0];
		msg.hdr.length = ACM_MSG_HDR_LENGTH + ACM_MSG_EP_LENGTH;
	}

	dst_data->flags = ACM_EP_FLAG_DEST;
	if (rai->ai_family == AF_INET) {
		dst_data->type = ACM_EP_INFO_ADDRESS_IP;
		memcpy(dst_data->info.addr,
		       &((struct sockaddr_in *) rai->ai_dst_addr)->sin_addr, 4);
	} else {
		dst_data->type = ACM_EP_INFO_ADDRESS_IP6;
		memcpy(dst_data->info.addr,
		       &((struct sockaddr_in6 *) rai->ai_dst_addr)->sin6_addr, 16);
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
