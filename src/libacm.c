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

static struct acm_device *dev_array;
static int dev_cnt;


static int acm_init_port(struct acm_device *dev, int index)
{
	struct acm_port *port;
	struct ibv_port_attr attr;
	int ret;

	port = &dev->ports[index];
	port->port_num = index + 1;
	ret = ibv_query_gid(dev->verbs, port->port_num, 0, &port->gid);
	if (ret)
		return -1;

	ret = ibv_query_port(dev->verbs, port->port_num, &attr);
	if (ret)
		return -1;

	port->lid = attr.lid;
	for (port->pkey_cnt = 0; !ret && port->pkey_cnt < 4; port->pkey_cnt++) {
		ret = ibv_query_pkey(dev->verbs, port->port_num,
			port->pkey_cnt, &port->pkey[port->pkey_cnt]);
	}

	return port->pkey_cnt ? 0 : ret;
}

static int acm_open_devices(void)
{
	struct ibv_device **dev_list;
	struct acm_device *dev;
	struct ibv_device_attr attr;
	int i, p, cnt, ret;

	dev_list = ibv_get_device_list(&cnt);
	if (!dev_list)
		return -1;

	dev_array = (struct acm_device *) zalloc(sizeof(struct acm_device) * cnt);
	if (!dev_array)
		goto err1;

	for (i = 0; dev_list[i];) {
		dev = &dev_array[i];

		dev->guid = ibv_get_device_guid(dev_list[i]);
		dev->verbs = ibv_open_device(dev_list[i]);
		if (dev->verbs == NULL)
			goto err2;

		++i;
		ret = ibv_query_device(dev->verbs, &attr);
		if (ret)
			goto err2;

		dev->port_cnt = attr.phys_port_cnt;
		dev->ports = zalloc(sizeof(struct acm_port) * dev->port_cnt);
		if (!dev->ports)
			goto err2;

		for (p = 0; p < dev->port_cnt; p++) {
			ret = acm_init_port(dev, p);
			if (ret)
				goto err2;
		}
	}

	ibv_free_device_list(dev_list);
	dev_cnt = cnt;
	return 0;

err2:
	while (i--) {
		ibv_close_device(dev_array[i].verbs);
		if (dev_array[i].ports)
			free(dev_array[i].ports);
	}
	free(dev_array);
err1:
	ibv_free_device_list(dev_list);
	return -1;
}

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

	ret = acm_open_devices();
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

static struct acm_device *acm_get_device(uint64_t guid)
{
	int i;

	for (i = 0; i < dev_cnt; i++) {
		if (dev_array[i].guid == guid)
			return &dev_array[i];
	}

	return NULL;
}

LIB_EXPORT
int ib_acm_convert_to_path(struct ib_acm_dev_addr *dev_addr,
	struct ibv_ah_attr *ah, struct ib_acm_resolve_data *data,
	struct ib_path_record *path)
{
	struct acm_device *dev;
	int p = dev_addr->port_num - 1;

	dev = acm_get_device(dev_addr->guid);
	if (!dev)
		return -1;

	if (ah->grh.sgid_index || dev_addr->pkey_index > 4)
		return -1;

	if (ah->is_global) {
		path->dgid = ah->grh.dgid;
		path->sgid = dev->ports[p].gid;
		path->flowlabel_hoplimit =
			htonl(ah->grh.flow_label << 8 | (uint32_t) ah->grh.hop_limit);
		path->tclass = ah->grh.traffic_class;
	}

	path->dlid = htons(ah->dlid);
	path->slid = htons(dev->ports[p].lid | ah->src_path_bits);
	path->reversible_numpath = IB_PATH_RECORD_REVERSIBLE | 1;
	path->pkey = htons(dev->ports[p].pkey[dev_addr->pkey_index]);
	path->qosclass_sl = htons((uint16_t) ah->sl);
	path->mtu = (2 << 6) | data->mtu;
	path->rate = (2 << 6) | ah->static_rate;
	path->packetlifetime = (2 << 6) | data->packet_lifetime;

	return 0;
}
