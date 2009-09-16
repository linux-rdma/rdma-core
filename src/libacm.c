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

static int acm_resolve(uint8_t *src, uint8_t *dest, uint8_t type,
	struct ib_acm_dev_addr *dev_addr, struct ibv_ah_attr *ah,
	struct ib_acm_resolve_data *data)
{
	struct acm_resolve_msg msg;
	int ret;

	lock_acquire(&lock);
	if (!ready && (ret = acm_init()))
		goto out;

	memset(&msg, 0, sizeof msg);
	msg.hdr.version = ACM_VERSION;
	msg.hdr.opcode = ACM_OP_RESOLVE;
	msg.hdr.dest_type = type;
	msg.hdr.src_type = type;

	switch (type) {
	case ACM_EP_TYPE_NAME:
		strncpy((char *) msg.src.name, (char *) src, ACM_MAX_ADDRESS);
		strncpy((char *) msg.dest.name, (char *) dest, ACM_MAX_ADDRESS);
		break;
	case ACM_EP_TYPE_ADDRESS_IP:
		memcpy(msg.src.addr, &((struct sockaddr_in *) src)->sin_addr, 4);
		memcpy(msg.dest.addr, &((struct sockaddr_in *) dest)->sin_addr, 4);
		break;
	case ACM_EP_TYPE_ADDRESS_IP6:
		memcpy(msg.src.addr, &((struct sockaddr_in6 *) src)->sin6_addr, 16);
		memcpy(msg.dest.addr, &((struct sockaddr_in *) dest)->sin_addr, 16);
		break;
	case ACM_EP_TYPE_AV:
		memcpy(&msg.src.av, src, sizeof(msg.src.av));
		memcpy(&msg.dest.av, dest, sizeof(msg.dest.av));
		break;
	default:
		ret = -1;
		goto out;
	}
	
	ret = send(sock, (char *) &msg, sizeof msg, 0);
	if (ret != sizeof msg)
		goto out;

	ret = recv(sock, (char *) &msg, sizeof msg, 0);
	if (ret != sizeof msg)
		goto out;

	memcpy(dev_addr, &msg.src.dev, sizeof(*dev_addr));
	*ah = msg.dest.av;
	memcpy(data, &msg.data, sizeof(*data));
	ret = 0;

out:
	lock_release(&lock);
	return ret;
}

LIB_EXPORT
int ib_acm_resolve_name(char *src, char *dest,
	struct ib_acm_dev_addr *dev_addr, struct ibv_ah_attr *ah,
	struct ib_acm_resolve_data *data)
{
	return acm_resolve((uint8_t *) src, (uint8_t *) dest,
		ACM_EP_TYPE_NAME, dev_addr, ah, data);
}

LIB_EXPORT
int ib_acm_resolve_ip(struct sockaddr *src, struct sockaddr *dest,
	struct ib_acm_dev_addr *dev_addr, struct ibv_ah_attr *ah,
	struct ib_acm_resolve_data *data)
{
	if (((struct sockaddr *) dest)->sa_family == AF_INET) {
		return acm_resolve((uint8_t *) src, (uint8_t *) dest,
			ACM_EP_TYPE_ADDRESS_IP, dev_addr, ah, data);
	} else {
		return acm_resolve((uint8_t *) src, (uint8_t *) dest,
			ACM_EP_TYPE_ADDRESS_IP6, dev_addr, ah, data);
	}
}

static int acm_query_path(struct ib_path_record *path, uint8_t query_sa)
{
	struct acm_query_msg msg;
	int ret;

	lock_acquire(&lock);
	if (!ready && (ret = acm_init()))
		goto out;

	memset(&msg, 0, sizeof msg);
	msg.hdr.version = ACM_VERSION;
	msg.hdr.opcode = ACM_OP_QUERY;
	msg.hdr.param = ACM_QUERY_PATH_RECORD | query_sa;

	if (path->dgid.global.interface_id || path->dgid.global.subnet_prefix) {
		msg.hdr.dest_type = ACM_EP_TYPE_GID;
	} else if (path->dlid) {
		msg.hdr.dest_type = ACM_EP_TYPE_LID;
	} else {
		ret = -1;
		goto out;
	}

	if (path->sgid.global.interface_id || path->sgid.global.subnet_prefix) {
		msg.hdr.src_type = ACM_EP_TYPE_GID;
	} else if (path->slid) {
		msg.hdr.src_type = ACM_EP_TYPE_LID;
	} else {
		ret = -1;
		goto out;
	}

	msg.data.path = *path;
	
	ret = send(sock, (char *) &msg, sizeof msg, 0);
	if (ret != sizeof msg)
		goto out;

	ret = recv(sock, (char *) &msg, sizeof msg, 0);
	if (ret != sizeof msg)
		goto out;

	*path = msg.data.path;
	ret = msg.hdr.status;

out:
	lock_release(&lock);
	return ret;
}

LIB_EXPORT
int ib_acm_query_path(struct ib_path_record *path)
{
	return acm_query_path(path, ACM_QUERY_SA);
}

LIB_EXPORT
int ib_acm_resolve_path(struct ib_path_record *path)
{
	return acm_query_path(path, 0);
}

static struct ibv_context *acm_open_device(uint64_t guid)
{
	struct ibv_device **dev_array;
	struct ibv_context *verbs = NULL;
	int i, cnt;

	dev_array = ibv_get_device_list(&cnt);
	if (!dev_array)
		return NULL;

	for (i = 0; i < cnt; i++) {
		if (guid == ibv_get_device_guid(dev_array[i])) {
			verbs = ibv_open_device(dev_array[i]);
			break;
		}
	}

	ibv_free_device_list(dev_array);
	return verbs;
}

LIB_EXPORT
int ib_acm_convert_to_path(struct ib_acm_dev_addr *dev_addr,
	struct ibv_ah_attr *ah, struct ib_acm_resolve_data *data,
	struct ib_path_record *path)
{
	struct ibv_context *verbs;
	struct ibv_port_attr attr;
	int ret;

	verbs = acm_open_device(dev_addr->guid);
	if (!verbs)
		return -1;

	if (ah->is_global) {
		path->dgid = ah->grh.dgid;
		ret = ibv_query_gid(verbs, dev_addr->port_num, ah->grh.sgid_index, &path->sgid);
		if (ret)
			goto out;

		path->flowlabel_hoplimit =
			htonl(ah->grh.flow_label << 8 | (uint32_t) ah->grh.hop_limit);
		path->tclass = ah->grh.traffic_class;
	}

	path->dlid = htons(ah->dlid);
	ret = ibv_query_port(verbs, dev_addr->port_num, &attr);
	if (ret)
		goto out;

	path->slid = htons(attr.lid | ah->src_path_bits);
	path->reversible_numpath = IB_PATH_RECORD_REVERSIBLE | 1;
	ret = ibv_query_pkey(verbs, dev_addr->port_num, dev_addr->pkey_index, &path->pkey);
	if (ret)
		goto out;

	path->pkey = htons(path->pkey);
	path->qosclass_sl = htons((uint16_t) ah->sl);
	path->mtu = (2 << 6) | data->mtu;
	path->rate = (2 << 6) | ah->static_rate;
	path->packetlifetime = (2 << 6) | data->packet_lifetime;

out:
	ibv_close_device(verbs);
	return ret;
}
