/*
 * Copyright (c) 2009 Intel Corporation.  All rights reserved.
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

#include <osd.h>
#include <infiniband/ib_acm.h>
#include <infiniband/acm.h>
#include <stdio.h>

struct acm_port
{
	uint8_t           port_num;
	uint16_t          lid;
	union ibv_gid     gid;
	int               pkey_cnt;
	uint16_t          pkey[4];
};

struct acm_device
{
	struct ibv_context *verbs;
	uint64_t           guid;
	int                port_cnt;
	struct acm_port    *ports;
};

extern lock_t lock;
static SOCKET sock = INVALID_SOCKET;
static short server_port = 6125;
static int ready;

static int acm_init(void)
{
	struct sockaddr_in addr;
	int ret;

	ret = osd_init();
	if (ret)
		return ret;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		ret = socket_errno();
		goto err1;
	}

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(server_port);
	ret = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (ret)
		goto err2;

	ready = 1;
	return 0;

err2:
	closesocket(sock);
	sock = INVALID_SOCKET;
err1:
	osd_close();
	return ret;
}

void LIB_DESTRUCTOR acm_cleanup(void)
{
	if (sock != INVALID_SOCKET) {
		shutdown(sock, SHUT_RDWR);
		closesocket(sock);
	}
}

static int acm_format_resp(struct acm_resolve_msg *msg,
	struct ib_acm_path_data **paths, int *count, struct ib_acm_cm_data *data)
{
	struct ib_acm_path_data *path_data;
	int i, addr_cnt;

	*count = 0;
	addr_cnt = (msg->hdr.length - ACM_MSG_HDR_LENGTH) /
		sizeof(struct acm_ep_addr_data);
	path_data = (struct ib_acm_path_data *)
		zalloc(addr_cnt * sizeof(struct ib_acm_path_data));
	if (!path_data)
		return -1;

	memset(data, 0, sizeof *data);
	for (i = 0; i < addr_cnt; i++) {
		switch (msg->data[i].type) {
		case ACM_EP_INFO_PATH:
			path_data[i].flags = msg->data[i].flags;
			path_data[i].path  = msg->data[i].info.path;
			(*count)++;
			break;
		case ACM_EP_INFO_CM:
			data->init_depth = msg->data[i].info.cm.init_depth;
			data->resp_resources = msg->data[i].info.cm.resp_resources;
			break;
		default:
			goto err;
		}
	}

	*paths = path_data;
	return 0;
err:
	free(path_data);
	return -1;
}

static int acm_resolve(uint8_t *src, uint8_t *dest, uint8_t type,
	struct ib_acm_path_data **paths, int *count,
	struct ib_acm_cm_data *data)
{
	struct acm_msg msg;
	struct acm_resolve_msg *resolve_msg = (struct acm_resolve_msg *) &msg;
	struct acm_ep_addr_data *src_data, *dest_data;
	int ret;

	lock_acquire(&lock);
	if (!ready && (ret = acm_init()))
		goto out;

	memset(&msg, 0, sizeof msg);
	msg.hdr.version = ACM_VERSION;
	msg.hdr.opcode = ACM_OP_RESOLVE;
	msg.hdr.length = ACM_MSG_HDR_LENGTH + (2 * ACM_MSG_EP_LENGTH);

	src_data  = &resolve_msg->data[0];
	dest_data = &resolve_msg->data[1];

	src_data->type   = type;
	src_data->flags  = IB_ACM_FLAGS_INBOUND;
	dest_data->type  = type;
	dest_data->flags = IB_ACM_FLAGS_OUTBOUND;

	switch (type) {
	case ACM_EP_INFO_NAME:
		strncpy((char *) src_data->info.name,  (char *) src,  ACM_MAX_ADDRESS);
		strncpy((char *) dest_data->info.name, (char *) dest, ACM_MAX_ADDRESS);
		break;
	case ACM_EP_INFO_ADDRESS_IP:
		memcpy(src_data->info.addr,  &((struct sockaddr_in *) src)->sin_addr,  4);
		memcpy(dest_data->info.addr, &((struct sockaddr_in *) dest)->sin_addr, 4);
		break;
	case ACM_EP_INFO_ADDRESS_IP6:
		memcpy(src_data->info.addr,  &((struct sockaddr_in6 *) src)->sin6_addr,  16);
		memcpy(dest_data->info.addr, &((struct sockaddr_in6 *) dest)->sin6_addr, 16);
		break;
	default:
		ret = -1;
		goto out;
	}
	
	ret = send(sock, (char *) &msg, msg.hdr.length, 0);
	if (ret != msg.hdr.length)
		goto out;

	ret = recv(sock, (char *) &msg, sizeof msg, 0);
	if (ret < ACM_MSG_HDR_LENGTH || ret != msg.hdr.length)
		goto out;

	if (msg.hdr.status) {
		ret = msg.hdr.status;
		goto out;
	}

	ret = acm_format_resp(resolve_msg, paths, count, data);
out:
	lock_release(&lock);
	return ret;
}

LIB_EXPORT
int ib_acm_resolve_name(char *src, char *dest,
	struct ib_acm_path_data **paths, int *count,
	struct ib_acm_cm_data *data)
{
	return acm_resolve((uint8_t *) src, (uint8_t *) dest,
		ACM_EP_INFO_NAME, paths, count, data);
}

LIB_EXPORT
int ib_acm_resolve_ip(struct sockaddr *src, struct sockaddr *dest,
	struct ib_acm_path_data **paths, int *count,
	struct ib_acm_cm_data *data)
{
	if (((struct sockaddr *) dest)->sa_family == AF_INET) {
		return acm_resolve((uint8_t *) src, (uint8_t *) dest,
			ACM_EP_INFO_ADDRESS_IP, paths, count, data);
	} else {
		return acm_resolve((uint8_t *) src, (uint8_t *) dest,
			ACM_EP_INFO_ADDRESS_IP6, paths, count, data);
	}
}

LIB_EXPORT
int ib_acm_resolve_path(struct ib_path_record *path, uint32_t flags)
{
	struct acm_msg msg;
	struct acm_ep_addr_data *data;
	int ret;

	lock_acquire(&lock);
	if (!ready && (ret = acm_init()))
		goto out;

	memset(&msg, 0, sizeof msg);
	msg.hdr.version = ACM_VERSION;
	msg.hdr.opcode = ACM_OP_RESOLVE;
	msg.hdr.length = ACM_MSG_HDR_LENGTH + ACM_MSG_EP_LENGTH;

	data = &((struct acm_resolve_msg *) &msg)->data[0];
	data->flags = flags;
	data->type = ACM_EP_INFO_PATH;
	data->info.path = *path;
	
	ret = send(sock, (char *) &msg, msg.hdr.length, 0);
	if (ret != msg.hdr.length)
		goto out;

	ret = recv(sock, (char *) &msg, sizeof msg, 0);
	if (ret < ACM_MSG_HDR_LENGTH || ret != msg.hdr.length)
		goto out;

	ret = msg.hdr.status;
	if (!ret)
		*path = data->info.path;

out:
	lock_release(&lock);
	return ret;
}
