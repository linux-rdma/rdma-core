/*
 * Copyright (c) 2009 Intel Corporation.  All rights reserved.
 * Copyright (c) 2013 Mellanox Technologies LTD. All rights reserved.
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

#include <config.h>

#include <osd.h>
#include "libacm.h"
#include <infiniband/acm.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>

static pthread_mutex_t acm_lock = PTHREAD_MUTEX_INITIALIZER;
static int sock = -1;
static short server_port = 6125;

static void acm_set_server_port(void)
{
	FILE *f;

	if ((f = fopen(IBACM_PORT_FILE, "r"))) {
		if (fscanf(f, "%hu", (unsigned short *) &server_port) != 1)
			printf("Failed to read server port\n");
		fclose(f);
	}
}

int ib_acm_connect(char *dest)
{
	struct addrinfo hint, *res;
	int ret;

	acm_set_server_port();
	memset(&hint, 0, sizeof hint);
	hint.ai_family = AF_INET;
	hint.ai_protocol = IPPROTO_TCP;
	ret = getaddrinfo(dest, NULL, &hint, &res);
	if (ret)
		return ret;

	sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock == -1) {
		ret = errno;
		goto err1;
	}

	((struct sockaddr_in *) res->ai_addr)->sin_port = htons(server_port);
	ret = connect(sock, res->ai_addr, res->ai_addrlen);
	if (ret)
		goto err2;

	freeaddrinfo(res);
	return 0;

err2:
	close(sock);
	sock = -1;
err1:
	freeaddrinfo(res);
	return ret;
}

void ib_acm_disconnect(void)
{
	if (sock != -1) {
		shutdown(sock, SHUT_RDWR);
		close(sock);
		sock = -1;
	}
}

static int acm_format_resp(struct acm_msg *msg,
	struct ibv_path_data **paths, int *count, int print)
{
	struct ibv_path_data *path_data;
	char addr[ACM_MAX_ADDRESS];
	int i, addr_cnt;

	*count = 0;
	addr_cnt = (msg->hdr.length - ACM_MSG_HDR_LENGTH) /
		sizeof(struct acm_ep_addr_data);
	path_data = (struct ibv_path_data *)
		calloc(1, addr_cnt * sizeof(struct ibv_path_data));
	if (!path_data)
		return -1;

	for (i = 0; i < addr_cnt; i++) {
		switch (msg->resolve_data[i].type) {
		case ACM_EP_INFO_PATH:
			path_data[i].flags = msg->resolve_data[i].flags;
			path_data[i].path  = msg->resolve_data[i].info.path;
			(*count)++;
			break;
		default:
			if (!(msg->resolve_data[i].flags & ACM_EP_FLAG_SOURCE))
				goto err;

			switch (msg->resolve_data[i].type) {
			case ACM_EP_INFO_ADDRESS_IP:
				inet_ntop(AF_INET, msg->resolve_data[i].info.addr,
					addr, sizeof addr);
				break;
			case ACM_EP_INFO_ADDRESS_IP6:
				inet_ntop(AF_INET6, msg->resolve_data[i].info.addr,
					addr, sizeof addr);
				break;
			case ACM_EP_INFO_NAME:
				memcpy(addr, msg->resolve_data[i].info.name,
					ACM_MAX_ADDRESS);
				break;
			default:
				goto err;
			}
			if (print)
				printf("Source: %s\n", addr);
			break;
		}
	}

	*paths = path_data;
	return 0;
err:
	free(path_data);
	return -1;
}

static int acm_format_ep_addr(struct acm_ep_addr_data *data, uint8_t *addr,
	uint8_t type, uint32_t flags)
{
	data->type   = type;
	data->flags  = flags;

	switch (type) {
	case ACM_EP_INFO_NAME:
		strncpy((char *) data->info.name,  (char *) addr,  ACM_MAX_ADDRESS);
		break;
	case ACM_EP_INFO_ADDRESS_IP:
		memcpy(data->info.addr, &((struct sockaddr_in *) addr)->sin_addr, 4);
		break;
	case ACM_EP_INFO_ADDRESS_IP6:
		memcpy(data->info.addr, &((struct sockaddr_in6 *) addr)->sin6_addr, 16);
		break;
	default:
		return -1;
	}

	return 0;
}

static inline int ERR(int err)
{
	errno = err;
	return -1;
}

static int acm_error(uint8_t status)
{
	switch (status) {
	case ACM_STATUS_SUCCESS:
		return 0;
	case ACM_STATUS_ENOMEM:
		return ERR(ENOMEM);
	case ACM_STATUS_EINVAL:
		return ERR(EINVAL);
	case ACM_STATUS_ENODATA:
		return ERR(ENODATA);
	case ACM_STATUS_ENOTCONN:
		return ERR(ENOTCONN);
	case ACM_STATUS_ETIMEDOUT:
		return ERR(ETIMEDOUT);
	case ACM_STATUS_ESRCADDR:
	case ACM_STATUS_EDESTADDR:
		return ERR(EADDRNOTAVAIL);
	case ACM_STATUS_ESRCTYPE:
	case ACM_STATUS_EDESTTYPE:
	default:
		return ERR(EINVAL);
	}
}

static int acm_resolve(uint8_t *src, uint8_t *dest, uint8_t type,
	struct ibv_path_data **paths, int *count, uint32_t flags, int print)
{
	struct acm_msg msg;
	int ret, cnt = 0;

	pthread_mutex_lock(&acm_lock);
	memset(&msg, 0, sizeof msg);
	msg.hdr.version = ACM_VERSION;
	msg.hdr.opcode = ACM_OP_RESOLVE;

	if (src) {
		ret = acm_format_ep_addr(&msg.resolve_data[cnt++], src, type,
			ACM_EP_FLAG_SOURCE);
		if (ret)
			goto out;
	}

	ret = acm_format_ep_addr(&msg.resolve_data[cnt++], dest, type,
		ACM_EP_FLAG_DEST | flags);
	if (ret)
		goto out;

	msg.hdr.length = ACM_MSG_HDR_LENGTH + (cnt * ACM_MSG_EP_LENGTH);

	ret = send(sock, (char *) &msg, msg.hdr.length, 0);
	if (ret != msg.hdr.length)
		goto out;

	ret = recv(sock, (char *) &msg, sizeof msg, 0);
	if (ret < ACM_MSG_HDR_LENGTH || ret != msg.hdr.length)
		goto out;

	if (msg.hdr.status) {
		ret = acm_error(msg.hdr.status);
		goto out;
	}

	ret = acm_format_resp(&msg, paths, count, print);
out:
	pthread_mutex_unlock(&acm_lock);
	return ret;
}

int ib_acm_resolve_name(char *src, char *dest,
	struct ibv_path_data **paths, int *count, uint32_t flags, int print)
{
	return acm_resolve((uint8_t *) src, (uint8_t *) dest,
		ACM_EP_INFO_NAME, paths, count, flags, print);
}

int ib_acm_resolve_ip(struct sockaddr *src, struct sockaddr *dest,
	struct ibv_path_data **paths, int *count, uint32_t flags, int print)
{
	if (((struct sockaddr *) dest)->sa_family == AF_INET) {
		return acm_resolve((uint8_t *) src, (uint8_t *) dest,
			ACM_EP_INFO_ADDRESS_IP, paths, count, flags, print);
	} else {
		return acm_resolve((uint8_t *) src, (uint8_t *) dest,
			ACM_EP_INFO_ADDRESS_IP6, paths, count, flags, print);
	}
}

int ib_acm_resolve_path(struct ibv_path_record *path, uint32_t flags)
{
	struct acm_msg msg;
	struct acm_ep_addr_data *data;
	int ret;

	pthread_mutex_lock(&acm_lock);
	memset(&msg, 0, sizeof msg);
	msg.hdr.version = ACM_VERSION;
	msg.hdr.opcode = ACM_OP_RESOLVE;
	msg.hdr.length = ACM_MSG_HDR_LENGTH + ACM_MSG_EP_LENGTH;

	data = &msg.resolve_data[0];
	data->flags = flags;
	data->type = ACM_EP_INFO_PATH;
	data->info.path = *path;

	ret = send(sock, (char *) &msg, msg.hdr.length, 0);
	if (ret != msg.hdr.length)
		goto out;

	ret = recv(sock, (char *) &msg, sizeof msg, 0);
	if (ret < ACM_MSG_HDR_LENGTH || ret != msg.hdr.length)
		goto out;

	ret = acm_error(msg.hdr.status);
	if (!ret)
		*path = data->info.path;

out:
	pthread_mutex_unlock(&acm_lock);
	return ret;
}

int ib_acm_query_perf(int index, uint64_t **counters, int *count)
{
	struct acm_msg msg;
	int ret, i;

	pthread_mutex_lock(&acm_lock);
	memset(&msg, 0, sizeof msg);
	msg.hdr.version = ACM_VERSION;
	msg.hdr.opcode = ACM_OP_PERF_QUERY;
	msg.hdr.data[1] = index;
	msg.hdr.length = htons(ACM_MSG_HDR_LENGTH);

	ret = send(sock, (char *) &msg, ACM_MSG_HDR_LENGTH, 0);
	if (ret != ACM_MSG_HDR_LENGTH)
		goto out;

	ret = recv(sock, (char *) &msg, sizeof msg, 0);
	if (ret < ACM_MSG_HDR_LENGTH || ret != ntohs(msg.hdr.length)) {
		ret = ACM_STATUS_EINVAL;
		goto out;
	}

	if (msg.hdr.status) {
		ret = acm_error(msg.hdr.status);
		goto out;
	}

	*counters = malloc(sizeof(uint64_t) * msg.hdr.data[0]);
	if (!*counters) {
		ret = ACM_STATUS_ENOMEM;
		goto out;
	}

	*count = msg.hdr.data[0];
	for (i = 0; i < *count; i++)
		(*counters)[i] = ntohll(msg.perf_data[i]);
	ret = 0;
out:
	pthread_mutex_unlock(&acm_lock);
	return ret;
}

int ib_acm_enum_ep(int index, struct acm_ep_config_data **data)
{
	struct acm_msg msg;
	int ret;
	int len;
	int cnt;
	struct acm_ep_config_data *edata;

	pthread_mutex_lock(&acm_lock);
	memset(&msg, 0, sizeof msg);
	msg.hdr.version = ACM_VERSION;
	msg.hdr.opcode = ACM_OP_EP_QUERY;
	msg.hdr.data[0] = index;
	msg.hdr.length = htons(ACM_MSG_HDR_LENGTH);

	ret = send(sock, (char *) &msg, ACM_MSG_HDR_LENGTH, 0);
	if (ret != ACM_MSG_HDR_LENGTH)
		goto out;

	ret = recv(sock, (char *) &msg, sizeof msg, 0);
	if (ret < ACM_MSG_HDR_LENGTH || ret != ntohs(msg.hdr.length)) {
		ret = ACM_STATUS_EINVAL;
		goto out;
	}

	if (msg.hdr.status) {
		ret = acm_error(msg.hdr.status);
		goto out;
	}

	cnt = ntohs(msg.ep_data[0].addr_cnt);
	len = sizeof(struct acm_ep_config_data) +
		ACM_MAX_ADDRESS * cnt;
	edata = malloc(len);
	if (!edata) {
		ret = ACM_STATUS_ENOMEM;
		goto out;
	}

	memcpy(edata, &msg.ep_data[0], len);
	edata->dev_guid = ntohll(msg.ep_data[0].dev_guid);
	edata->pkey = ntohs(msg.ep_data[0].pkey);
	edata->addr_cnt = cnt;
	*data = edata;
	ret = 0;
out:
	pthread_mutex_unlock(&acm_lock);
	return ret;
}

int ib_acm_query_perf_ep_addr(uint8_t *src, uint8_t type,
			     uint64_t **counters, int *count)
{
	struct acm_msg msg;
	int ret, i, len;

	if (!src)
		return -1;

	pthread_mutex_lock(&acm_lock);
	memset(&msg, 0, sizeof msg);
	msg.hdr.version = ACM_VERSION;
	msg.hdr.opcode = ACM_OP_PERF_QUERY;

	ret = acm_format_ep_addr(&msg.resolve_data[0], src, type,
		ACM_EP_FLAG_SOURCE);
	if (ret)
		goto out;

	len = ACM_MSG_HDR_LENGTH + ACM_MSG_EP_LENGTH;
	msg.hdr.length = htons(len);

	ret = send(sock, (char *) &msg, len, 0);
	if (ret != len)
		goto out;

	ret = recv(sock, (char *) &msg, sizeof msg, 0);
	if (ret < ACM_MSG_HDR_LENGTH || ret != ntohs(msg.hdr.length)) {
		ret = ACM_STATUS_EINVAL;
		goto out;
	}

	if (msg.hdr.status) {
		ret = acm_error(msg.hdr.status);
		goto out;
	}

	*counters = malloc(sizeof(uint64_t) * msg.hdr.data[0]);
	if (!*counters) {
		ret = ACM_STATUS_ENOMEM;
		goto out;
	}

	*count = msg.hdr.data[0];
	for (i = 0; i < *count; i++)
		(*counters)[i] = ntohll(msg.perf_data[i]);

	ret = 0;
out:
	pthread_mutex_unlock(&acm_lock);
	return ret;
}


const char *ib_acm_cntr_name(int index)
{
	static const char *const cntr_name[] = {
		[ACM_CNTR_ERROR]	= "Error Count",
		[ACM_CNTR_RESOLVE]	= "Resolve Count",
		[ACM_CNTR_NODATA]	= "No Data",
		[ACM_CNTR_ADDR_QUERY]	= "Addr Query Count",
		[ACM_CNTR_ADDR_CACHE]	= "Addr Cache Count",
		[ACM_CNTR_ROUTE_QUERY]	= "Route Query Count",
		[ACM_CNTR_ROUTE_CACHE]	= "Route Cache Count",
	};

	if (index < ACM_CNTR_ERROR || index > ACM_MAX_COUNTER)
		return "Unknown";

	return cntr_name[index];
}
