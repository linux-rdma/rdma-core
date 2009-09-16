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
#include <stdarg.h>
#include <string.h>
#include <osd.h>
#include <arpa/inet.h>
#include <infiniband/acm.h>
#include <infiniband/umad.h>
#include <dlist.h>
#include <search.h>
#include "acm_mad.h"

#define MAX_EP_ADDR 4
#define MAX_EP_MC   2

struct acm_dest
{
	uint8_t            address[ACM_MAX_ADDRESS]; /* keep first */
	struct ibv_ah      *ah;
	struct ibv_ah_attr av;
	union ibv_gid      mgid;
	DLIST_ENTRY        req_queue;
	uint32_t           remote_qpn;
	uint8_t            init_depth;
	uint8_t            resp_resources;
	uint8_t            mtu;
	uint8_t            packet_lifetime;
};

struct acm_port
{
	struct acm_device   *dev;
	DLIST_ENTRY         ep_list;
	int                 mad_portid;
	int                 mad_agentid;
	struct acm_dest     sa_dest;
	enum ibv_port_state state;
	enum ibv_mtu        mtu;
	enum ibv_rate       rate;
	int                 subnet_timeout;
	int                 gid_cnt;
	uint16_t            pkey_cnt;
	uint16_t            lid;
	uint8_t             lmc;
	uint8_t             port_num;
};

struct acm_device
{
	struct ibv_context      *verbs;
	struct ibv_comp_channel *channel;
	struct ibv_pd           *pd;
	uint64_t                guid;
	DLIST_ENTRY             entry;
	uint8_t                 active;
	uint8_t                 init_depth;
	uint8_t                 resp_resources;
	int                     port_cnt;
	struct acm_port         port[0];
};

struct acm_ep
{
	struct acm_port    *port;
	struct ibv_cq      *cq;
	struct ibv_qp      *qp;
	struct ibv_mr      *mr;
	uint8_t            *recv_bufs;
	DLIST_ENTRY        entry;
	union acm_ep_addr  addr[MAX_EP_ADDR];
	uint8_t            addr_type[MAX_EP_ADDR];
	void               *dest_map[ACM_ADDRESS_RESERVED - 1];
	struct acm_dest    mc_dest[MAX_EP_MC];
	int                mc_cnt;
	uint16_t           pkey_index;
	uint16_t           pkey;
	lock_t             lock;
	int                available_sends;
	DLIST_ENTRY        pending_queue;
	DLIST_ENTRY        active_queue;
	DLIST_ENTRY        wait_queue;
};

struct acm_send_msg
{
	DLIST_ENTRY        entry;
	struct acm_ep      *ep;
	struct ibv_mr      *mr;
	struct ibv_send_wr wr;
	struct ibv_sge     sge;
	uint64_t           expires;
	int                tries;
	uint8_t            data[ACM_SEND_SIZE];
};

struct acm_client
{
	lock_t   lock;   /* acquire ep lock first */
	SOCKET   sock;
	int      index;
	atomic_t refcnt;
};

struct acm_request
{
	struct acm_client *client;
	DLIST_ENTRY       entry;
	struct acm_msg    msg;
};

static DLIST_ENTRY dev_list;

static atomic_t tid;
static DLIST_ENTRY timeout_list;
static event_t timeout_event;
static atomic_t wait_cnt;

static SOCKET listen_socket;
static struct acm_client client[FD_SETSIZE - 1];

static FILE *flog;
static lock_t log_lock;

static char log_file[128] = "stdout";
static int log_level = 0;
static short server_port = 6125;
static int timeout = 2000;
static int retries = 15;
static int send_depth = 64;
static int recv_depth = 1024;
static uint8_t min_mtu = IBV_MTU_2048;
static uint8_t min_rate = IBV_RATE_10_GBPS;

#define acm_log(level, format, ...) \
	acm_write(level, "%s: "format, __func__, ## __VA_ARGS__)

static void acm_write(int level, const char *format, ...)
{
	va_list args;

	if (level > log_level)
		return;

	va_start(args, format);
	lock_acquire(&log_lock);
	vfprintf(flog, format, args);
	lock_release(&log_lock);
	va_end(args);
}

static void acm_log_ep_addr(int level, const char *msg,
	union acm_ep_addr *addr, uint8_t ep_type)
{
	char ip_addr[ACM_MAX_ADDRESS];

	if (level > log_level)
		return;

	lock_acquire(&log_lock);
	fprintf(flog, msg);
	switch (ep_type) {
	case ACM_EP_TYPE_NAME:
		fprintf(flog, "%s\n", addr->name);
		break;
	case ACM_EP_TYPE_ADDRESS_IP:
		inet_ntop(AF_INET, addr->addr, ip_addr, ACM_MAX_ADDRESS);
		fprintf(flog, "%s\n", ip_addr);
		break;
	case ACM_EP_TYPE_ADDRESS_IP6:
		inet_ntop(AF_INET6, addr->addr, ip_addr, ACM_MAX_ADDRESS);
		fprintf(flog, "%s\n", ip_addr);
		break;
	case ACM_EP_TYPE_DEVICE:
		fprintf(flog, "device guid 0x%llx, pkey index %d, port %d\n",
			addr->dev.guid, addr->dev.pkey_index, addr->dev.port_num);
		break;
	case ACM_EP_TYPE_AV:
		fprintf(flog, "endpoint specified using address vector\n");
		break;
	default:
		fprintf(flog, "unknown endpoint address 0x%x\n", ep_type);
	}
	lock_release(&log_lock);
}

static void *zalloc(size_t size)
{
	void *buf;

	buf = malloc(size);
	if (buf)
		memset(buf, 0, size);
	return buf;
}

static struct acm_send_msg *
acm_alloc_send(struct acm_ep *ep, struct acm_dest *dest, size_t size)
{
	struct acm_send_msg *msg;

	msg = (struct acm_send_msg *) zalloc(sizeof *msg);
	if (!msg) {
		acm_log(0, "ERROR - unable to allocate send buffer\n");
		return NULL;
	}

	msg->ep = ep;
	msg->mr = ibv_reg_mr(ep->port->dev->pd, msg->data, size, 0);
	if (!msg->mr) {
		acm_log(0, "ERROR - failed to register send buffer\n");
		goto err;
	}

	msg->wr.next = NULL;
	msg->wr.sg_list = &msg->sge;
	msg->wr.num_sge = 1;
	msg->wr.opcode = IBV_WR_SEND;
	msg->wr.send_flags = IBV_SEND_SIGNALED;
	msg->wr.wr_id = (uintptr_t) msg;

	msg->wr.wr.ud.ah = dest->ah;
	msg->wr.wr.ud.remote_qpn = dest->remote_qpn;
	msg->wr.wr.ud.remote_qkey = ACM_QKEY;

	msg->sge.length = size;
	msg->sge.lkey = msg->mr->lkey;
	msg->sge.addr = (uintptr_t) msg->data;
	return msg;
err:
	free(msg);
	return NULL;
}

static void acm_free_send(struct acm_send_msg *msg)
{
	ibv_dereg_mr(msg->mr);
	free(msg);
}

static void acm_post_send(struct acm_send_msg *msg)
{
	struct acm_ep *ep = msg->ep;
	struct ibv_send_wr *bad_wr;

	if (ep->available_sends) {
		acm_log(2, "posting send to QP\n");
		ep->available_sends--;
		DListInsertTail(&msg->entry, &ep->active_queue);
		ibv_post_send(ep->qp, &msg->wr, &bad_wr);
	} else {
		acm_log(2, "no sends available, queuing message\n");
		DListInsertTail(&msg->entry, &ep->pending_queue);
	}
}

static void acm_post_recv(struct acm_ep *ep, uint64_t address)
{
	struct ibv_recv_wr wr, *bad_wr;
	struct ibv_sge sge;

	wr.next = NULL;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr_id = address;

	sge.length = ACM_RECV_SIZE;
	sge.lkey = ep->mr->lkey;
	sge.addr = address;

	ibv_post_recv(ep->qp, &wr, &bad_wr);
}

static void acm_send_available(struct acm_ep *ep)
{
	struct acm_send_msg *msg;
	struct ibv_send_wr *bad_wr;
	DLIST_ENTRY *entry;

	if (DListEmpty(&ep->pending_queue)) {
		ep->available_sends++;
	} else {
		acm_log(2, "posting queued send message\n");
		entry = ep->pending_queue.Next;
		DListRemove(entry);
		msg = container_of(entry, struct acm_send_msg, entry);
		DListInsertTail(&msg->entry, &ep->active_queue);
		ibv_post_send(ep->qp, &msg->wr, &bad_wr);
	}
}

static void acm_complete_send(struct acm_send_msg *msg)
{
	struct acm_ep *ep = msg->ep;

	lock_acquire(&ep->lock);
	DListRemove(&msg->entry);
	if (msg->tries) {
		acm_log(2, "waiting for response\n");
		msg->expires = time_stamp_ms() + ep->port->subnet_timeout + timeout;
		DListInsertTail(&msg->entry, &ep->wait_queue);
		if (atomic_inc(&wait_cnt) == 1)
			event_signal(&timeout_event);
	} else {
		acm_log(2, "freeing\n");
		acm_send_available(ep);
		acm_free_send(msg);
	}
	lock_release(&ep->lock);
}

static struct acm_send_msg *acm_get_request(struct acm_ep *ep, uint64_t tid, int *free)
{
	struct acm_send_msg *msg, *req = NULL;
	struct acm_mad *mad;
	DLIST_ENTRY *entry, *next;

	acm_log(2, "\n");
	lock_acquire(&ep->lock);
	for (entry = ep->wait_queue.Next; entry != &ep->wait_queue; entry = next) {
		next = entry->Next;
		msg = container_of(entry, struct acm_send_msg, entry);
		mad = (struct acm_mad *) msg->data;
		if (mad->tid == tid) {
			acm_log(2, "match found in wait queue\n");
			req = msg;
			DListRemove(entry);
			(void) atomic_dec(&wait_cnt);
			acm_send_available(ep);
			*free = 1;
			goto unlock;
		}
	}

	for (entry = ep->active_queue.Next; entry != &ep->active_queue; entry = entry->Next) {
		msg = container_of(entry, struct acm_send_msg, entry);
		mad = (struct acm_mad *) msg->data;
		if (mad->tid == tid && msg->tries) {
			acm_log(2, "match found in active queue\n");
			req = msg;
			req->tries = 0;
			*free = 0;
			break;
		}
	}
unlock:
	lock_release(&ep->lock);
	return req;
}

static uint8_t acm_gid_index(struct acm_port *port, union ibv_gid *gid)
{
	union ibv_gid cmp_gid;
	uint8_t i;

	for (i = 0; i < port->gid_cnt; i++) {
		ibv_query_gid(port->dev->verbs, port->port_num, i, &cmp_gid);
		if (!memcmp(&cmp_gid, gid, sizeof cmp_gid))
			break;
	}
	return i;
}

static int acm_mc_index(struct acm_ep *ep, union ibv_gid *gid)
{
	int i;

	for (i = 0; i < ep->mc_cnt; i++) {
		if (!memcmp(&ep->mc_dest[i].address, gid, sizeof(*gid)))
			return i;
	}
	return -1;
}

static void
acm_init_mc_av(struct acm_port *port, struct ib_mc_member_rec *mc_rec,
	struct ibv_ah_attr *av)
{
	uint32_t sl_flow_hop;

	sl_flow_hop = ntohl(mc_rec->sl_flow_hop);

	av->dlid = ntohs(mc_rec->mlid);
	av->sl = (uint8_t) (sl_flow_hop >> 28);
	av->src_path_bits = port->sa_dest.av.src_path_bits;
	av->static_rate = mc_rec->rate & 0x3F;
	av->port_num = port->port_num;

	av->is_global = 1;
	av->grh.dgid = mc_rec->mgid;
	av->grh.flow_label = (sl_flow_hop >> 8) & 0xFFFFF;
	av->grh.sgid_index = acm_gid_index(port, &mc_rec->port_gid);
	av->grh.hop_limit = (uint8_t) sl_flow_hop;
	av->grh.traffic_class = mc_rec->tclass;
}

static void acm_process_join_resp(struct acm_ep *ep, struct ib_user_mad *umad)
{
	struct acm_dest *dest;
	struct ib_mc_member_rec *mc_rec;
	struct ib_sa_mad *mad;
	int index, ret;

	mad = (struct ib_sa_mad *) umad->data;
	acm_log(1, "response status: 0x%x, mad status: 0x%x\n",
		umad->status, mad->status);
	if (umad->status) {
		acm_log(0, "ERROR - send join failed 0x%x\n", umad->status);
		return;
	}
	if (mad->status) {
		acm_log(0, "ERROR - join response status 0x%x\n", mad->status);
		return;
	}

	mc_rec = (struct ib_mc_member_rec *) mad->data;
	lock_acquire(&ep->lock);
	index = acm_mc_index(ep, &mc_rec->mgid);
	if (index >= 0) {
		dest = &ep->mc_dest[index];
		dest->remote_qpn = IB_MC_QPN;
		dest->mgid = mc_rec->mgid;
		acm_init_mc_av(ep->port, mc_rec, &dest->av);
		dest->mtu = mc_rec->mtu & 0x3F;
		dest->packet_lifetime = mc_rec->packet_lifetime & 0x3F;
		dest->ah = ibv_create_ah(ep->port->dev->pd, &dest->av);
		ret = ibv_attach_mcast(ep->qp, &mc_rec->mgid, mc_rec->mlid);
		if (ret) {
			acm_log(0, "ERROR - unable to attach QP to multicast group\n");
		}
		acm_log(1, "join successful\n");
	} else {
		acm_log(0, "ERROR - MGID in join response not found\n");
	}
	lock_release(&ep->lock);
}

static int acm_compare_dest(const void *dest1, const void *dest2)
{
	return memcmp(dest1, dest2, ACM_MAX_ADDRESS);
}

static int acm_addr_index(struct acm_ep *ep, uint8_t *addr, uint8_t addr_type)
{
	int i;

	for (i = 0; i < MAX_EP_ADDR; i++) {
		if (ep->addr_type[i] != addr_type)
			continue;

		if ((addr_type == ACM_ADDRESS_NAME &&
			!strnicmp((char *) ep->addr[i].name, (char *) addr, ACM_MAX_ADDRESS)) ||
			!memcmp(ep->addr[i].addr, addr, ACM_MAX_ADDRESS))
			return i;
	}
	return -1;
}

/*
 * Multicast groups are ordered lowest to highest preference.
 */
static int
acm_record_av(struct acm_dest *dest, struct acm_ep *ep,
	struct ibv_wc *wc, struct acm_resolve_rec *rec)
{
	int i, index;

	acm_log(2, "\n");
	for (i = min(rec->gid_cnt, ACM_MAX_GID_COUNT) - 1; i >= 0; i--) {
		index = acm_mc_index(ep, &rec->gid[i]);
		if (index >= 0) {
			acm_log(2, "selecting MC group at index %d\n", index);
			dest->av = ep->mc_dest[index].av;
			dest->av.dlid = wc->slid;
			dest->av.src_path_bits = wc->dlid_path_bits;
			dest->av.grh.dgid = ((struct ibv_grh *) (uintptr_t) wc->wr_id)->sgid;
			
			dest->mgid = ep->mc_dest[index].mgid;
			dest->mtu = ep->mc_dest[index].mtu;
			dest->packet_lifetime = ep->mc_dest[index].packet_lifetime;
			return ACM_STATUS_SUCCESS;
		}
	}

	return ACM_STATUS_ENODATA;
}

/* 
 * Record the source of a resolve request.  Use the source QPN to see if
 * the remote service has relocated and we need to update our cache.
 */
static struct acm_dest *
acm_record_src(struct acm_ep *ep, struct ibv_wc *wc, struct acm_resolve_rec *rec)
{
	struct acm_dest *dest, **tdest;
	int ret;

	acm_log(2, "\n");
	lock_acquire(&ep->lock);
	tdest = tfind(rec->src, &ep->dest_map[rec->src_type - 1], acm_compare_dest);
	if (!tdest) {
		acm_log(2, "creating new dest\n");
		dest = zalloc(sizeof *dest);
		if (!dest) {
			acm_log(0, "ERROR - unable to allocate dest\n");
			goto unlock;
		}

		memcpy(dest->address, rec->src, ACM_MAX_ADDRESS);
		DListInit(&dest->req_queue);
		tsearch(dest, &ep->dest_map[rec->src_type - 1], acm_compare_dest);
	} else {
		dest = *tdest;
	}

	if (dest->ah) {
		if (dest->remote_qpn == wc->src_qp)
			goto unlock;

		ibv_destroy_ah(dest->ah); // TODO: ah could be in use
		dest->ah = NULL;
	}

	acm_log(2, "creating address handle\n");
	ret = acm_record_av(dest, ep, wc, rec);
	if (ret) {
		acm_log(0, "ERROR - failed to record av\n");
		goto err;
	}

	dest->ah = ibv_create_ah(ep->port->dev->pd, &dest->av);
	if (!dest->ah) {
		acm_log(0, "ERROR - failed to create ah\n");
		goto err;
	}

	dest->remote_qpn = wc->src_qp;
	dest->init_depth = rec->init_depth;
	dest->resp_resources = rec->resp_resources;

unlock:
	lock_release(&ep->lock);
	return dest;

err:
	if (!tdest) {
		tdelete(dest->address, &ep->dest_map[rec->src_type - 1], acm_compare_dest);
		free(dest);
	}
	lock_release(&ep->lock);
	return NULL;
}

static void acm_init_resp_mad(struct acm_mad *resp, struct acm_mad *req)
{
	resp->base_version = req->base_version;
	resp->mgmt_class = req->mgmt_class;
	resp->class_version = req->class_version;
	resp->method = req->method | IB_METHOD_RESP;
	resp->status = ACM_STATUS_SUCCESS;
	resp->control = req->control;
	resp->tid = req->tid;
}

static int acm_validate_resolve_req(struct acm_mad *mad)
{
	struct acm_resolve_rec *rec;

	if (mad->method != IB_METHOD_GET) {
		acm_log(0, "ERROR - invalid method 0x%x\n", mad->method);
		return ACM_STATUS_EINVAL;
	}

	rec = (struct acm_resolve_rec *) mad->data;
	if (!rec->src_type || rec->src_type >= ACM_ADDRESS_RESERVED) {
		acm_log(0, "ERROR - unknown src type 0x%x\n", rec->src_type);
		return ACM_STATUS_EINVAL;
	}

	return 0;
}

static void
acm_process_resolve_req(struct acm_ep *ep, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_resolve_rec *rec, *resp_rec;
	struct acm_dest *dest;
	struct acm_send_msg *msg;
	struct acm_mad *resp_mad;

	acm_log(2, "\n");
	if (acm_validate_resolve_req(mad)) {
		acm_log(0, "ERROR - invalid request\n");
		return;
	}

	rec = (struct acm_resolve_rec *) mad->data;
	dest = acm_record_src(ep, wc, rec);
	if (!dest) {
		acm_log(0, "ERROR - failed to record source\n");
		return;
	}

	if (acm_addr_index(ep, rec->dest, rec->dest_type) < 0) {
		acm_log(2, "no matching address - discarding\n");
		return;
	}

	msg = acm_alloc_send(ep, dest, sizeof (*resp_mad));
	if (!msg) {
		acm_log(0, "ERROR - failed to allocate message\n");
		return;
	}

	resp_mad = (struct acm_mad *) msg->data;
	resp_rec = (struct acm_resolve_rec *) resp_mad->data;
	acm_init_resp_mad(resp_mad, mad);
	resp_rec->dest_type = rec->src_type;
	resp_rec->dest_length = rec->src_length;
	resp_rec->src_type = rec->dest_type;
	resp_rec->src_length = rec->dest_length;
	resp_rec->gid_cnt = 1;
	resp_rec->resp_resources = ep->port->dev->resp_resources;
	resp_rec->init_depth = ep->port->dev->init_depth;
	memcpy(resp_rec->dest, rec->src, ACM_MAX_ADDRESS);
	memcpy(resp_rec->src, rec->dest, ACM_MAX_ADDRESS);
	memcpy(resp_rec->gid, dest->mgid.raw, sizeof(union ibv_gid));

	acm_log(2, "sending resolve response\n");
	lock_acquire(&ep->lock);
	acm_post_send(msg);
	lock_release(&ep->lock);
}

static int
acm_client_resolve_resp(struct acm_ep *ep, struct acm_client *client,
	struct acm_resolve_msg *msg, struct acm_dest *dest, uint8_t status)
{
	int ret;

	acm_log(1, "status 0x%x\n", status);
	lock_acquire(&client->lock);
	if (client->sock == INVALID_SOCKET) {
		acm_log(0, "ERROR - connection lost\n");
		ret = ACM_STATUS_ENOTCONN;
		goto release;
	}

	msg->hdr.opcode |= ACM_OP_ACK;
	msg->hdr.status = status;
	msg->hdr.param = 0;

	if (!status) {
		msg->hdr.src_type = ACM_EP_TYPE_DEVICE;
		msg->src.dev.guid = ep->port->dev->guid;
		msg->src.dev.pkey_index = ep->pkey_index;
		msg->src.dev.port_num = ep->port->port_num;

		if (dest) {
			acm_log(2, "destination found\n");
			msg->hdr.dest_type = ACM_EP_TYPE_AV;
			msg->dest.av = dest->av;
			msg->data.init_depth = min(ep->port->dev->init_depth, dest->resp_resources);
			msg->data.resp_resources = min(ep->port->dev->resp_resources, dest->init_depth);
			msg->data.packet_lifetime = dest->packet_lifetime;
			msg->data.mtu = dest->mtu;
		}
	}

	ret = send(client->sock, (char *) msg, sizeof *msg, 0);
	if (ret != sizeof(*msg))
		acm_log(0, "failed to send response\n");
	else
		ret = 0;

release:
	lock_release(&client->lock);
	(void) atomic_dec(&client->refcnt);
	return ret;
}

static struct acm_dest *
acm_record_dest(struct acm_ep *ep, struct ibv_wc *wc,
	struct acm_resolve_rec *req_rec, struct acm_resolve_rec *resp_rec)
{
	struct acm_dest *dest, **tdest;
	int ret;

	acm_log(2, "\n");
	lock_acquire(&ep->lock);
	tdest = tfind(req_rec->dest, &ep->dest_map[req_rec->dest_type - 1], acm_compare_dest);
	if (!tdest) {
		dest = NULL;
		goto unlock;
	}

	dest = *tdest;
	if (dest->ah)
		goto unlock;

	acm_log(2, "creating address handle\n");
	ret = acm_record_av(dest, ep, wc, resp_rec);
	if (ret) {
		acm_log(0, "ERROR - failed to record av\n");
		goto unlock;
	}

	dest->ah = ibv_create_ah(ep->port->dev->pd, &dest->av);
	if (!dest->ah) {
		acm_log(0, "ERROR - failed to create ah\n");
		goto unlock;
	}

	dest->remote_qpn = wc->src_qp;
	dest->init_depth = resp_rec->init_depth;
	dest->resp_resources = resp_rec->resp_resources;

unlock:
	lock_release(&ep->lock);
	return dest;
}

static void
acm_process_resolve_resp(struct acm_ep *ep, struct ibv_wc *wc,
	struct acm_send_msg *msg, struct acm_mad *mad)
{
	struct acm_resolve_rec *req_rec, *resp_rec;
	struct acm_dest *dest;
	struct acm_request *client_req;
	DLIST_ENTRY *entry;
	uint8_t status;

	status = acm_class_status(mad->status);
	acm_log(2, "resp status 0x%x\n", status);
	req_rec = (struct acm_resolve_rec *) ((struct acm_mad *) msg->data)->data;
	resp_rec = (struct acm_resolve_rec *) mad->data;

	dest = acm_record_dest(ep, wc, req_rec, resp_rec);
	if (!dest) {
		acm_log(0, "ERROR - cannot record dest\n");
		return;
	}

	if (!status && !dest->ah)
		status = ACM_STATUS_EINVAL;

	lock_acquire(&ep->lock);
	while (!DListEmpty(&dest->req_queue)) {
		entry = dest->req_queue.Next;
		DListRemove(entry);
		client_req = container_of(entry, struct acm_request, entry);
		lock_release(&ep->lock);
		acm_log(2, "completing queued client request\n");
		acm_client_resolve_resp(ep, client_req->client,
			(struct acm_resolve_msg *) &client_req->msg, dest, status);
		lock_acquire(&ep->lock);
	}
	if (status) {
		acm_log(0, "resp failed 0x%x\n", status);
		tdelete(dest->address, &ep->dest_map[req_rec->dest_type - 1], acm_compare_dest);
	}
	lock_release(&ep->lock);
}

static int acm_validate_recv(struct acm_mad *mad)
{
	if (mad->base_version != 1 || mad->class_version != 1) {
		acm_log(0, "ERROR - invalid version %d %d\n",
			mad->base_version, mad->class_version);
		return ACM_STATUS_EINVAL;
	}
	
	if (mad->mgmt_class != ACM_MGMT_CLASS) {
		acm_log(0, "ERROR - invalid mgmt class 0x%x\n", mad->mgmt_class);
		return ACM_STATUS_EINVAL;
	}

	if (mad->control != ACM_CTRL_RESOLVE) {
		acm_log(0, "ERROR - invalid control 0x%x\n", mad->control);
		return ACM_STATUS_EINVAL;
	}

	return 0;
}

static void acm_process_recv(struct acm_ep *ep, struct ibv_wc *wc)
{
	struct acm_mad *mad;
	struct acm_send_msg *req;
	int free;

	acm_log(2, "\n");
	mad = (struct acm_mad *) (uintptr_t) (wc->wr_id + sizeof(struct ibv_grh));
	if (acm_validate_recv(mad)) {
		acm_log(0, "ERROR - discarding message\n");
		goto out;
	}

	if (mad->method & IB_METHOD_RESP) {
		acm_log(2, "received response\n");
		req = acm_get_request(ep, mad->tid, &free);
		if (!req) {
			acm_log(0, "response did not match active request\n");
			goto out;
		}
		acm_log(2, "found matching request\n");
		acm_process_resolve_resp(ep, wc, req, mad);
		if (free)
			acm_free_send(req);
	} else {
		acm_log(2, "unsolicited request\n");
		acm_process_resolve_req(ep, wc, mad);
		free = 0;
	}

out:
	acm_post_recv(ep, wc->wr_id);
}

static void acm_process_comp(struct acm_ep *ep, struct ibv_wc *wc)
{
	if (wc->status) {
		acm_log(0, "ERROR - work completion error\n"
			"\topcode %d, completion status %d\n",
			wc->opcode, wc->status);
		return;
	}

	if (wc->opcode & IBV_WC_RECV)
		acm_process_recv(ep, wc);
	else
		acm_complete_send((struct acm_send_msg *) (uintptr_t) wc->wr_id);
}

static void CDECL_FUNC acm_comp_handler(void *context)
{
	struct acm_device *dev = (struct acm_device *) context;
	struct acm_ep *ep;
	struct ibv_cq *cq;
	struct ibv_wc wc;
	int cnt;

	acm_log(1, "started\n");
	while (1) {
		ibv_get_cq_event(dev->channel, &cq, (void *) &ep);

		cnt = 0;
		while (ibv_poll_cq(cq, 1, &wc) > 0) {
			cnt++;
			acm_process_comp(ep, &wc);
		}

		ibv_req_notify_cq(cq, 0);
		while (ibv_poll_cq(cq, 1, &wc) > 0) {
			cnt++;
			acm_process_comp(ep, &wc);
		}

		ibv_ack_cq_events(cq, cnt);
	}
}

static void acm_format_mgid(union ibv_gid *mgid, uint16_t pkey, uint8_t tos,
	uint8_t rate, uint8_t mtu)
{
	mgid->raw[0] = 0xFF;
	mgid->raw[1] = 0x10 | 0x05;
	mgid->raw[2] = 0x40;
	mgid->raw[3] = 0x01;
	mgid->raw[4] = (uint8_t) (pkey >> 8);
	mgid->raw[5] = (uint8_t) pkey;
	mgid->raw[6] = tos;
	mgid->raw[7] = rate;
	mgid->raw[8] = mtu;
	mgid->raw[9] = 0;
	mgid->raw[10] = 0;
	mgid->raw[11] = 0;
	mgid->raw[12] = 0;
	mgid->raw[13] = 0;
	mgid->raw[14] = 0;
	mgid->raw[15] = 0;
}

static void acm_init_path_query(struct ib_sa_mad *mad, struct ib_path_record *path)
{
	uint32_t fl_hop;
	uint16_t qos_sl;

	acm_log(2, "\n");
	mad->base_version = 1;
	mad->mgmt_class = IB_MGMT_CLASS_SA;
	mad->class_version = 2;
	mad->method = IB_METHOD_GET;
	mad->tid = (uint64_t) atomic_inc(&tid);
	mad->attr_id = IB_SA_ATTR_PATH_REC;

	memcpy(mad->data, path, sizeof(*path));
	if (path->service_id)
		mad->comp_mask |= IB_COMP_MASK_PR_SERVICE_ID;
	if (path->dgid.global.interface_id || path->dgid.global.subnet_prefix)
		mad->comp_mask |= IB_COMP_MASK_PR_DGID;
	if (path->sgid.global.interface_id || path->sgid.global.subnet_prefix)
		mad->comp_mask |= IB_COMP_MASK_PR_SGID;
	if (path->dlid)
		mad->comp_mask |= IB_COMP_MASK_PR_DLID;
	if (path->slid)
		mad->comp_mask |= IB_COMP_MASK_PR_SLID;

	fl_hop = ntohl(path->flowlabel_hoplimit);
	if (fl_hop >> 8)
		mad->comp_mask |= IB_COMP_MASK_PR_FLOW_LABEL;
	if (fl_hop & 0xFF)
		mad->comp_mask |= IB_COMP_MASK_PR_HOP_LIMIT;

	if (path->tclass)
		mad->comp_mask |= IB_COMP_MASK_PR_TCLASS;
	if (path->reversible_numpath & 0x80)
		mad->comp_mask |= IB_COMP_MASK_PR_REVERSIBLE;
	if (path->pkey)
		mad->comp_mask |= IB_COMP_MASK_PR_PKEY;

	qos_sl = ntohs(path->qosclass_sl);
	if (qos_sl >> 4)
		mad->comp_mask |= IB_COMP_MASK_PR_QOS_CLASS;
	if (qos_sl & 0xF)
		mad->comp_mask |= IB_COMP_MASK_PR_SL;

	if (path->mtu & 0xC0)
		mad->comp_mask |= IB_COMP_MASK_PR_MTU_SELECTOR;
	if (path->mtu & 0x3F)
		mad->comp_mask |= IB_COMP_MASK_PR_MTU;
	if (path->rate & 0xC0)
		mad->comp_mask |= IB_COMP_MASK_PR_RATE_SELECTOR;
	if (path->rate & 0x3F)
		mad->comp_mask |= IB_COMP_MASK_PR_RATE;
	if (path->packetlifetime & 0xC0)
		mad->comp_mask |= IB_COMP_MASK_PR_PACKET_LIFETIME_SELECTOR;
	if (path->packetlifetime & 0x3F)
		mad->comp_mask |= IB_COMP_MASK_PR_PACKET_LIFETIME;
}

static void acm_init_join(struct ib_sa_mad *mad, union ibv_gid *port_gid,
	uint16_t pkey, uint8_t tos, uint8_t tclass, uint8_t sl, uint8_t rate, uint8_t mtu)
{
	struct ib_mc_member_rec *mc_rec;

	acm_log(2, "\n");
	mad->base_version = 1;
	mad->mgmt_class = IB_MGMT_CLASS_SA;
	mad->class_version = 2;
	mad->method = IB_METHOD_SET;
	mad->tid = (uint64_t) atomic_inc(&tid);
	mad->attr_id = IB_SA_ATTR_MC_MEMBER_REC;
	mad->comp_mask =
		IB_COMP_MASK_MC_MGID | IB_COMP_MASK_MC_PORT_GID |
		IB_COMP_MASK_MC_QKEY | IB_COMP_MASK_MC_MTU_SEL| IB_COMP_MASK_MC_MTU |
		IB_COMP_MASK_MC_TCLASS | IB_COMP_MASK_MC_PKEY | IB_COMP_MASK_MC_RATE_SEL |
		IB_COMP_MASK_MC_RATE | IB_COMP_MASK_MC_SL | IB_COMP_MASK_MC_FLOW |
		IB_COMP_MASK_MC_SCOPE | IB_COMP_MASK_MC_JOIN_STATE;

	mc_rec = (struct ib_mc_member_rec *) mad->data;
	acm_format_mgid(&mc_rec->mgid, pkey, tos, rate, mtu);
	mc_rec->port_gid = *port_gid;
	mc_rec->qkey = ACM_QKEY;
	mc_rec->mtu = 0x80 | mtu;
	mc_rec->tclass = tclass;
	mc_rec->pkey = htons(pkey);
	mc_rec->rate = 0x80 | rate;
	mc_rec->sl_flow_hop = htonl(((uint32_t) sl) << 28);
	mc_rec->scope_state = 0x51;
}

static void acm_join_group(struct acm_ep *ep, union ibv_gid *port_gid,
	uint8_t tos, uint8_t tclass, uint8_t sl, uint8_t rate, uint8_t mtu)
{
	struct acm_port *port;
	struct ib_sa_mad *mad;
	struct ib_user_mad *umad;
	struct ib_mc_member_rec *mc_rec;
	int ret, len;

	acm_log(2, "\n");
	len = sizeof(*umad) + sizeof(*mad);
	umad = (struct ib_user_mad *) zalloc(len);
	if (!umad) {
		acm_log(0, "ERROR - unable to allocate MAD for join\n");
		return;
	}

	port = ep->port;
	umad->addr.qpn = htonl(port->sa_dest.remote_qpn);
	umad->addr.qkey = htonl(ACM_QKEY);
	umad->addr.pkey_index = ep->pkey_index;
	umad->addr.lid = htons(port->sa_dest.av.dlid);
	umad->addr.sl = port->sa_dest.av.sl;
	umad->addr.path_bits = port->sa_dest.av.src_path_bits;

	acm_log(0, "%s %d pkey 0x%x, sl 0x%x, rate 0x%x, mtu 0x%x\n",
		ep->port->dev->verbs->device->name, ep->port->port_num,
		ep->pkey, sl, rate, mtu);
	mad = (struct ib_sa_mad *) umad->data;
	acm_init_join(mad, port_gid, ep->pkey, tos, tclass, sl, rate, mtu);
	mc_rec = (struct ib_mc_member_rec *) mad->data;
	memcpy(&ep->mc_dest[ep->mc_cnt++], &mc_rec->mgid, sizeof(mc_rec->mgid));

	ret = umad_send(port->mad_portid, port->mad_agentid, (void *) umad,
		sizeof(*mad), timeout, retries);
	if (ret) {
		acm_log(0, "ERROR - failed to send multicast join request %d\n", ret);
		goto out;
	}

	acm_log(1, "waiting for response from SA to join request\n");
	ret = umad_recv(port->mad_portid, (void *) umad, &len, -1);
	if (ret < 0) {
		acm_log(0, "ERROR - recv error for multicast join response %d\n", ret);
		goto out;
	}

	acm_process_join_resp(ep, umad);
out:
	free(umad);
}

static void acm_port_join(void *context)
{
	struct acm_device *dev;
	struct acm_port *port = (struct acm_port *) context;
	struct acm_ep *ep;
	union ibv_gid port_gid;
	DLIST_ENTRY *ep_entry;
	int ret;

	dev = port->dev;
	acm_log(1, "device %s port %d\n", dev->verbs->device->name,
		port->port_num);

	ret = ibv_query_gid(dev->verbs, port->port_num, 0, &port_gid);
	if (ret) {
		acm_log(0, "ERROR - ibv_query_gid %d device %s port %d\n",
			ret, dev->verbs->device->name, port->port_num);
		return;
	}

	for (ep_entry = port->ep_list.Next; ep_entry != &port->ep_list;
		 ep_entry = ep_entry->Next) {

		ep = container_of(ep_entry, struct acm_ep, entry);
		acm_join_group(ep, &port_gid, 0, 0, 0, min_rate, min_mtu);
		if (port->rate != min_rate || port->mtu != min_mtu)
			acm_join_group(ep, &port_gid, 0, 0, 0, port->rate, port->mtu);
	}
	acm_log(1, "joins for device %s port %d complete\n", dev->verbs->device->name,
		port->port_num);
}

static void acm_join_groups(void)
{
	struct acm_device *dev;
	struct acm_port *port;
	DLIST_ENTRY *dev_entry;
	int i;

	acm_log(1, "initiating multicast joins for all ports\n");
	for (dev_entry = dev_list.Next; dev_entry != &dev_list;
		 dev_entry = dev_entry->Next) {

		dev = container_of(dev_entry, struct acm_device, entry);

		for (i = 0; i < dev->port_cnt; i++) {
			port = &dev->port[i];
			if (port->state != IBV_PORT_ACTIVE)
				continue;

			acm_log(1, "starting join for device %s, port %d\n",
				dev->verbs->device->name, port->port_num);
			// TODO: handle dynamic changes
			//beginthread(acm_port_join, port);
			acm_port_join(port);
		}
	}
}

static void acm_process_timeouts(void)
{
	DLIST_ENTRY *entry;
	struct acm_send_msg *msg;
	struct acm_mad *mad;
	struct acm_resolve_rec *rec;
	struct acm_dest *dest, **tdest;
	struct acm_request *req;
	struct acm_ep *ep;
	
	while (!DListEmpty(&timeout_list)) {
		entry = timeout_list.Next;
		DListRemove(entry);

		msg = container_of(entry, struct acm_send_msg, entry);
		mad = (struct acm_mad *) msg->data;

		rec = (struct acm_resolve_rec *) mad->data;
		ep = msg->ep;

		acm_log_ep_addr(0, "acm_process_timeouts: dest ",
			(union acm_ep_addr *) &rec->dest, rec->dest_type);
		lock_acquire(&ep->lock);
		tdest = tfind(rec->dest, &ep->dest_map[rec->dest_type - 1], acm_compare_dest);
		if (!tdest) {
			acm_log(0, "destination already removed\n");
			lock_release(&ep->lock);
			continue;
		} else {
			dest = *tdest;
		}

		acm_log(2, "failing pending client requests\n");
		while (!DListEmpty(&dest->req_queue)) {
			entry = dest->req_queue.Next;
			DListRemove(entry);
		
			req = container_of(entry, struct acm_request, entry);
			lock_release(&ep->lock);
			acm_client_resolve_resp(ep, req->client,
				(struct acm_resolve_msg *) &req->msg, dest,
				ACM_STATUS_ETIMEDOUT);
			lock_acquire(&ep->lock);
		}

		acm_log(2, "resolve timed out, releasing destination\n");
		tdelete(dest->address, &ep->dest_map[rec->dest_type - 1], acm_compare_dest);
		lock_release(&ep->lock);
	}
}

static void acm_process_wait_queue(struct acm_ep *ep, uint64_t *next_expire)
{
	struct acm_send_msg *msg;
	DLIST_ENTRY *entry, *next;
	struct ibv_send_wr *bad_wr;

	for (entry = ep->wait_queue.Next; entry != &ep->wait_queue; entry = next) {
		next = entry->Next;
		msg = container_of(entry, struct acm_send_msg, entry);
		if (msg->expires < time_stamp_ms()) {
			DListRemove(entry);
			(void) atomic_dec(&wait_cnt);
			if (--msg->tries) {
				acm_log(2, "retrying request\n");
				DListInsertTail(&msg->entry, &ep->active_queue);
				ibv_post_send(ep->qp, &msg->wr, &bad_wr);
			} else {
				acm_log(0, "failing request\n");
				acm_send_available(ep);
				DListInsertTail(&msg->entry, &timeout_list);
			}
		} else {
			*next_expire = min(*next_expire, msg->expires);
			break;
		}
	}
}

static void CDECL_FUNC acm_retry_handler(void *context)
{
	struct acm_device *dev;
	struct acm_port *port;
	struct acm_ep *ep;
	DLIST_ENTRY *dev_entry, *ep_entry;
	uint64_t next_expire;
	int i, wait;

	acm_log(0, "started\n");
	while (1) {
		while (!atomic_get(&wait_cnt))
			event_wait(&timeout_event, -1);

		next_expire = -1;
		for (dev_entry = dev_list.Next; dev_entry != &dev_list;
			 dev_entry = dev_entry->Next) {

			dev = container_of(dev_entry, struct acm_device, entry);

			for (i = 0; i < dev->port_cnt; i++) {
				port = &dev->port[i];

				for (ep_entry = port->ep_list.Next;
					 ep_entry != &port->ep_list;
					 ep_entry = ep_entry->Next) {

					ep = container_of(ep_entry, struct acm_ep, entry);
					lock_acquire(&ep->lock);
					if (!DListEmpty(&ep->wait_queue))
						acm_process_wait_queue(ep, &next_expire);
					lock_release(&ep->lock);
				}
			}
		}

		acm_process_timeouts();
		wait = (int) (next_expire - time_stamp_ms());
		if (wait > 0 && atomic_get(&wait_cnt))
			event_wait(&timeout_event, wait);
	}
}

static void acm_init_server(void)
{
	int i;

	for (i = 0; i < FD_SETSIZE - 1; i++) {
		lock_init(&client[i].lock);
		client[i].index = i;
		client[i].sock = INVALID_SOCKET;
	}
}

static int acm_listen(void)
{
	struct sockaddr_in addr;
	int ret;

	acm_log(2, "\n");
	listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listen_socket == INVALID_SOCKET) {
		acm_log(0, "ERROR - unable to allocate listen socket\n");
		return socket_errno();
	}

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);
	ret = bind(listen_socket, (struct sockaddr *) &addr, sizeof addr);
	if (ret == SOCKET_ERROR) {
		acm_log(0, "ERROR - unable to bind listen socket\n");
		return socket_errno();
	}
	
	ret = listen(listen_socket, 0);
	if (ret == SOCKET_ERROR) {
		acm_log(0, "ERROR - unable to start listen\n");
		return socket_errno();
	}

	acm_log(2, "listen active\n");
	return 0;
}

static void acm_release_client(struct acm_client *client)
{
	lock_acquire(&client->lock);
	shutdown(client->sock, SHUT_RDWR);
	closesocket(client->sock);
	client->sock = INVALID_SOCKET;
	lock_release(&client->lock);
	(void) atomic_dec(&client->refcnt);
}

static void acm_svr_accept(void)
{
	SOCKET s;
	int i;

	acm_log(2, "\n");
	s = accept(listen_socket, NULL, NULL);
	if (s == INVALID_SOCKET) {
		acm_log(0, "ERROR - failed to accept connection\n");
		return;
	}

	for (i = 0; i < FD_SETSIZE - 1; i++) {
		if (!atomic_get(&client[i].refcnt))
			break;
	}

	if (i == FD_SETSIZE - 1) {
		acm_log(0, "all connections busy - rejecting\n");
		closesocket(s);
		return;
	}

	client[i].sock = s;
	atomic_set(&client[i].refcnt, 1);
	acm_log(2, "assigned client id %d\n", i);
}

static uint8_t acm_get_addr_type(uint8_t ep_type)
{
	if (ep_type >= ACM_ADDRESS_RESERVED) {
		acm_log(0, "ERROR - invalid ep type %d\n", ep_type);
		return ACM_ADDRESS_INVALID;
	}
	return ep_type;
}

static int
acm_client_query_resp(struct acm_ep *ep, struct acm_client *client,
	struct acm_query_msg *msg, uint8_t status)
{
	int ret;

	acm_log(1, "status 0x%x\n", status);
	lock_acquire(&client->lock);
	if (client->sock == INVALID_SOCKET) {
		acm_log(0, "ERROR - connection lost\n");
		ret = ACM_STATUS_ENOTCONN;
		goto release;
	}

	msg->hdr.opcode |= ACM_OP_ACK;
	msg->hdr.status = status;

	ret = send(client->sock, (char *) msg, sizeof *msg, 0);
	if (ret != sizeof(*msg))
		acm_log(0, "failed to send response\n");
	else
		ret = 0;

release:
	lock_release(&client->lock);
	(void) atomic_dec(&client->refcnt);
	return ret;
}

static struct acm_ep *
acm_get_ep_by_path(struct ib_path_record *path)
{
	struct acm_device *dev;
	struct acm_port *port;
	struct acm_ep *ep;
	DLIST_ENTRY *dev_entry, *ep_entry;
	int i;

	for (dev_entry = dev_list.Next; dev_entry != &dev_list;
		 dev_entry = dev_entry->Next) {

		dev = container_of(dev_entry, struct acm_device, entry);
		for (i = 0; i < dev->port_cnt; i++) {
			port = &dev->port[i];

			// requires slid
			if (port->lid != ntohs(path->slid))
				continue;

			for (ep_entry = port->ep_list.Next; ep_entry != &port->ep_list;
				 ep_entry = ep_entry->Next) {

				// ignores pkey
				ep = container_of(ep_entry, struct acm_ep, entry);
				return ep;
			}
		}
	}

	acm_log(0, "could not find endpoint\n");
	return NULL;
}

// TODO: process send/recv asynchronously
static uint8_t acm_query_sa(struct acm_ep *ep, uint8_t query, union acm_query_data *data)
{
	struct acm_port *port;
	struct ib_sa_mad *mad;
	struct ib_user_mad *umad;
	int ret, len;
	size_t size;

	acm_log(2, "\n");
	len = sizeof(*umad) + sizeof(*mad);
	umad = (struct ib_user_mad *) zalloc(len);
	if (!umad) {
		acm_log(0, "ERROR - unable to allocate MAD\n");
		return ACM_STATUS_ENOMEM;
	}

	port = ep->port;
	umad->addr.qpn = htonl(port->sa_dest.remote_qpn);
	umad->addr.qkey = htonl(ACM_QKEY);
	umad->addr.pkey_index = ep->pkey_index;
	umad->addr.lid = htons(port->sa_dest.av.dlid);
	umad->addr.sl = port->sa_dest.av.sl;
	umad->addr.path_bits = port->sa_dest.av.src_path_bits;

	mad = (struct ib_sa_mad *) umad->data;
	switch (query) {
	case ACM_QUERY_PATH_RECORD:
		acm_init_path_query(mad, &data->path);
		size = sizeof(data->path);
		break;
	default:
		acm_log(0, "ERROR - unknown attribute id\n");
		ret = ACM_STATUS_EINVAL;
		goto out;
	}

	ret = umad_send(port->mad_portid, port->mad_agentid, (void *) umad,
		sizeof(*mad), timeout, retries);
	if (ret) {
		acm_log(0, "ERROR - umad_send %d\n", ret);
		goto out;
	}

	acm_log(2, "waiting to receive SA response\n");
	ret = umad_recv(port->mad_portid, (void *) umad, &len, -1);
	if (ret < 0) {
		acm_log(0, "ERROR - umad_recv %d\n", ret);
		goto out;
	}

	memcpy(data, mad->data, size);
	ret = umad->status ? umad->status : mad->status;
	if (ret) {
		acm_log(0, "SA query response error: 0x%x\n", ret);
		ret = ((uint8_t) ret) ? ret : -1;
	}
out:
	free(umad);
	return (uint8_t) ret;
}

static int
acm_svr_query(struct acm_client *client, struct acm_query_msg *msg)
{
	struct acm_ep *ep;
	uint8_t status;

	acm_log(2, "processing client query\n");
	ep = acm_get_ep_by_path(&msg->data.path);
	if (!ep) {
		acm_log(0, "could not find local end point\n");
		status = ACM_STATUS_ESRCADDR;
		goto resp;
	}

	(void) atomic_inc(&client->refcnt);
	lock_acquire(&ep->lock);
	status = acm_query_sa(ep, msg->hdr.param & ~ACM_QUERY_SA, &msg->data);
	lock_release(&ep->lock);

resp:
	return acm_client_query_resp(ep, client, msg, status);
}

static uint8_t
acm_send_resolve(struct acm_ep *ep, union acm_ep_addr *src, uint8_t src_type,
	struct acm_dest *dest, uint8_t dest_type)
{
	struct acm_send_msg *msg;
	struct acm_mad *mad;
	struct acm_resolve_rec *rec;
	int i;

	acm_log(2, "\n");
	if (!ep->mc_dest[0].ah) {
		acm_log(0, "ERROR - multicast group not ready\n");
		return ACM_STATUS_ENOTCONN;
	}

	msg = acm_alloc_send(ep, &ep->mc_dest[0], sizeof(struct acm_mad));
	if (!msg) {
		acm_log(0, "ERROR - cannot allocate send msg\n");
		return ACM_STATUS_ENOMEM;
	}

	msg->tries = retries + 1;
	mad = (struct acm_mad *) msg->data;
	mad->base_version = 1;
	mad->mgmt_class = ACM_MGMT_CLASS;
	mad->class_version = 1;
	mad->method = IB_METHOD_GET;
	mad->control = ACM_CTRL_RESOLVE;
	mad->tid = (uint64_t) atomic_inc(&tid);

	rec = (struct acm_resolve_rec *) mad->data;
	rec->src_type = src_type;
	rec->src_length = ACM_MAX_ADDRESS;
	memcpy(rec->src, src->addr, ACM_MAX_ADDRESS);
	rec->dest_type = dest_type;
	rec->dest_length = ACM_MAX_ADDRESS;
	memcpy(rec->dest, dest->address, ACM_MAX_ADDRESS);
	rec->resp_resources = ep->port->dev->resp_resources;
	rec->init_depth = ep->port->dev->init_depth;

	rec->gid_cnt = (uint8_t) ep->mc_cnt;
	for (i = 0; i < ep->mc_cnt; i++)
		memcpy(&rec->gid[i], ep->mc_dest[i].address, 16);
	
	acm_post_send(msg);
	return 0;
}

static struct acm_ep *
acm_get_ep_by_addr(union acm_ep_addr *addr, uint8_t src_type)
{
	struct acm_device *dev;
	struct acm_port *port;
	struct acm_ep *ep;
	DLIST_ENTRY *dev_entry, *ep_entry;
	int i;

	acm_log_ep_addr(2, "acm_get_ep_by_addr: ", addr, src_type);
	for (dev_entry = dev_list.Next; dev_entry != &dev_list;
		 dev_entry = dev_entry->Next) {

		dev = container_of(dev_entry, struct acm_device, entry);
		for (i = 0; i < dev->port_cnt; i++) {
			port = &dev->port[i];

			for (ep_entry = port->ep_list.Next; ep_entry != &port->ep_list;
				 ep_entry = ep_entry->Next) {

				ep = container_of(ep_entry, struct acm_ep, entry);
				if (acm_addr_index(ep, addr->addr, src_type) >= 0)
					return ep;
			}
		}
	}

	acm_log_ep_addr(0, "acm_get_ep_by_addr: could not find ", addr, src_type);
	return NULL;
}

static int
acm_svr_resolve(struct acm_client *client, struct acm_resolve_msg *msg)
{
	struct acm_ep *ep;
	struct acm_dest *dest, **tdest;
	struct acm_request *req;
	uint8_t dest_type, src_type;
	uint8_t status;

	acm_log_ep_addr(2, "acm_svr_resolve: source ", &msg->src, msg->hdr.src_type);
	ep = acm_get_ep_by_addr(&msg->src, msg->hdr.src_type);
	if (!ep) {
		acm_log(0, "unknown local end point\n");
		status = ACM_STATUS_ESRCADDR;
		goto resp;
	}

	dest_type = acm_get_addr_type(msg->hdr.dest_type);
	if (dest_type == ACM_ADDRESS_INVALID) {
		acm_log(0, "ERROR - unknown destination type\n");
		status = ACM_STATUS_EDESTTYPE;
		goto resp;
	}

	acm_log_ep_addr(2, "acm_svr_resolve: dest ", &msg->dest, msg->hdr.dest_type);
	(void) atomic_inc(&client->refcnt);
	lock_acquire(&ep->lock);
	tdest = tfind(msg->dest.addr, &ep->dest_map[dest_type - 1], acm_compare_dest);
	dest = tdest ? *tdest : NULL;
	if (dest && dest->ah) {
		acm_log(2, "request satisfied from local cache\n");
		status = ACM_STATUS_SUCCESS;
		goto release;
	}

	req = zalloc(sizeof *req);
	if (!req) {
		acm_log(0, "ERROR - unable to allocate memory to queue client request\n");
		status = ACM_STATUS_ENOMEM;
		goto release;
	}

	if (!dest) {
		acm_log(2, "adding new destination\n");
		dest = zalloc(sizeof *dest);
		if (!dest) {
			acm_log(0, "ERROR - unable to allocate destination in client request\n");
			status = ACM_STATUS_ENOMEM;
			goto free_req;
		}

		memcpy(dest->address, msg->dest.addr, ACM_MAX_ADDRESS);
		src_type = acm_get_addr_type(msg->hdr.src_type);
		acm_log(2, "sending resolve msg to dest\n");
		status = acm_send_resolve(ep, &msg->src, src_type, dest, dest_type);
		if (status) {
			acm_log(0, "ERROR - failure sending resolve request 0x%x\n", status);
			goto free_dest;
		}

		DListInit(&dest->req_queue);
		tsearch(dest, &ep->dest_map[dest_type - 1], acm_compare_dest);
	}

	acm_log(2, "queuing client request\n");
	req->client = client;
	memcpy(&req->msg, msg, sizeof(req->msg));
	DListInsertTail(&req->entry, &dest->req_queue);
	lock_release(&ep->lock);
	return 0;

free_dest:
	free(dest);
	dest = NULL;
free_req:
	free(req);
release:
	lock_release(&ep->lock);
resp:
	return acm_client_resolve_resp(ep, client, msg, dest, status);
}

static void acm_svr_receive(struct acm_client *client)
{
	struct acm_msg msg;
	int ret;

	acm_log(2, "\n");
	ret = recv(client->sock, (char *) &msg, sizeof msg, 0);
	if (ret != sizeof msg) {
		acm_log(2, "client disconnected\n");
		ret = ACM_STATUS_ENOTCONN;
		goto out;
	}

	if (msg.hdr.version != ACM_VERSION) {
		acm_log(0, "ERROR - unsupported version %d\n", msg.hdr.version);
		goto out;
	}

	switch (msg.hdr.opcode & ACM_OP_MASK) {
	case ACM_OP_RESOLVE:
		ret = acm_svr_resolve(client, (struct acm_resolve_msg *) &msg);
		break;
	case ACM_OP_QUERY:
		ret = acm_svr_query(client, (struct acm_query_msg *) &msg);
		break;
	default:
		acm_log(0, "ERROR - unknown opcode 0x%x\n", msg.hdr.opcode);
		ret = -1;
		break;
	}

out:
	if (ret)
		acm_release_client(client);
}

static void acm_server(void)
{
	fd_set readfds;
	int i, n, ret;

	acm_log(0, "started\n");
	acm_init_server();
	ret = acm_listen();
	if (ret) {
		acm_log(0, "ERROR - server listen failed\n");
		return;
	}

	while (1) {
		n = (int) listen_socket;
		FD_ZERO(&readfds);
		FD_SET(listen_socket, &readfds);

		for (i = 0; i < FD_SETSIZE - 1; i++) {
			if (client[i].sock != INVALID_SOCKET) {
				FD_SET(client[i].sock, &readfds);
				n = max(n, (int) client[i].sock);
			}
		}

		ret = select(n + 1, &readfds, NULL, NULL, NULL);
		if (ret == SOCKET_ERROR) {
			acm_log(0, "ERROR - server select error\n");
			continue;
		}

		if (FD_ISSET(listen_socket, &readfds))
			acm_svr_accept();

		for (i = 0; i < FD_SETSIZE - 1; i++) {
			if (client[i].sock != INVALID_SOCKET &&
				FD_ISSET(client[i].sock, &readfds)) {
				acm_log(2, "receiving from client %d\n", i);
				acm_svr_receive(&client[i]);
			}
		}
	}
}

static enum ibv_rate acm_get_rate(uint8_t width, uint8_t speed)
{
	switch (width) {
	case 1:
		switch (speed) {
		case 1: return IBV_RATE_2_5_GBPS;
		case 2: return IBV_RATE_5_GBPS;
		case 4: return IBV_RATE_10_GBPS;
		default: return IBV_RATE_MAX;
		}
	case 2:
		switch (speed) {
		case 1: return IBV_RATE_10_GBPS;
		case 2: return IBV_RATE_20_GBPS;
		case 4: return IBV_RATE_40_GBPS;
		default: return IBV_RATE_MAX;
		}
	case 4:
		switch (speed) {
		case 1: return IBV_RATE_20_GBPS;
		case 2: return IBV_RATE_40_GBPS;
		case 4: return IBV_RATE_80_GBPS;
		default: return IBV_RATE_MAX;
		}
	case 8:
		switch (speed) {
		case 1: return IBV_RATE_30_GBPS;
		case 2: return IBV_RATE_60_GBPS;
		case 4: return IBV_RATE_120_GBPS;
		default: return IBV_RATE_MAX;
		}
	default:
		acm_log(0, "ERROR - unknown link width 0x%x\n", width);
		return IBV_RATE_MAX;
	}
}

static enum ibv_mtu acm_convert_mtu(int mtu)
{
	switch (mtu) {
	case 256:  return IBV_MTU_256;
	case 512:  return IBV_MTU_512;
	case 1024: return IBV_MTU_1024;
	case 2048: return IBV_MTU_2048;
	case 4096: return IBV_MTU_4096;
	default:   return IBV_MTU_2048;
	}
}

static enum ibv_rate acm_convert_rate(int rate)
{
	switch (rate) {
	case 2:   return IBV_RATE_2_5_GBPS;
	case 5:   return IBV_RATE_5_GBPS;
	case 10:  return IBV_RATE_10_GBPS;
	case 20:  return IBV_RATE_20_GBPS;
	case 30:  return IBV_RATE_30_GBPS;
	case 40:  return IBV_RATE_40_GBPS;
	case 60:  return IBV_RATE_60_GBPS;
	case 80:  return IBV_RATE_80_GBPS;
	case 120: return IBV_RATE_120_GBPS;
	default:  return IBV_RATE_10_GBPS;
	}
}

static int acm_post_recvs(struct acm_ep *ep)
{
	int i, size;

	size = recv_depth * ACM_RECV_SIZE;
	ep->recv_bufs = malloc(size);
	if (!ep->recv_bufs) {
		acm_log(0, "ERROR - unable to allocate receive buffer\n");
		return ACM_STATUS_ENOMEM;
	}

	ep->mr = ibv_reg_mr(ep->port->dev->pd, ep->recv_bufs, size,
		IBV_ACCESS_LOCAL_WRITE);
	if (!ep->mr) {
		acm_log(0, "ERROR - unable to register receive buffer\n");
		goto err;
	}

	for (i = 0; i < recv_depth; i++) {
		acm_post_recv(ep, (uintptr_t) (ep->recv_bufs + ACM_RECV_SIZE * i));
	}
	return 0;

err:
	free(ep->recv_bufs);
	return -1;
}

static int acm_assign_ep_names(struct acm_ep *ep)
{
	char *dev_name;
	FILE *f;
	char s[120];
	char dev[32], addr[32], pkey_str[8];
	uint16_t pkey;
	uint8_t type;
	int port, index = 0;
	struct in6_addr ip_addr;

	dev_name = ep->port->dev->verbs->device->name;
	acm_log(1, "device %s, port %d, pkey 0x%x\n",
		dev_name, ep->port->port_num, ep->pkey);

	if (!(f = fopen("acm_addr.cfg", "r"))) {
		acm_log(0, "ERROR - unable to open acm_addr.cfg file\n");
		return ACM_STATUS_ENODATA;
	}

	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;

		if (sscanf(s, "%32s%32s%d%8s", addr, dev, &port, pkey_str) != 4)
			continue;

		acm_log(2, "%s", s);
		if (inet_pton(AF_INET, addr, &ip_addr) > 0)
			type = ACM_ADDRESS_IP;
		else if (inet_pton(AF_INET6, addr, &ip_addr) > 0)
			type = ACM_ADDRESS_IP6;
		else
			type = ACM_ADDRESS_NAME;

		if (stricmp(pkey_str, "default")) {
			if (sscanf(pkey_str, "%hx", &pkey) != 1) {
				acm_log(0, "ERROR - bad pkey format %s\n", pkey_str);
				continue;
			}
		} else {
			pkey = 0xFFFF;
		}

		if (!stricmp(dev_name, dev) && (ep->port->port_num == (uint8_t) port) &&
			(ep->pkey == pkey)) {

			ep->addr_type[index] = type;
			acm_log(1, "assigning %s\n", addr);
			if (type == ACM_ADDRESS_IP)
				memcpy(ep->addr[index].addr, &ip_addr, 4);
			else if (type == ACM_ADDRESS_IP6)
				memcpy(ep->addr[index].addr, &ip_addr, sizeof ip_addr);
			else
				strncpy((char *) ep->addr[index].addr, addr, ACM_MAX_ADDRESS);

			if (++index == MAX_EP_ADDR) {
				acm_log(1, "maximum number of names assigned to EP\n");
				break;
			}
		}
	}

	fclose(f);
	return !index;
}

static int acm_activate_ep(struct acm_port *port, struct acm_ep *ep, uint16_t pkey_index)
{
	struct ibv_qp_init_attr init_attr;
	struct ibv_qp_attr attr;
	int ret;

	acm_log(1, "\n");
	ep->port = port;
	ep->pkey_index = pkey_index;
	ep->available_sends = send_depth;
	DListInit(&ep->pending_queue);
	DListInit(&ep->active_queue);
	DListInit(&ep->wait_queue);
	lock_init(&ep->lock);

	ret = ibv_query_pkey(port->dev->verbs, port->port_num, pkey_index, &ep->pkey);
	if (ret)
		return ACM_STATUS_EINVAL;

	ret = acm_assign_ep_names(ep);
	if (ret) {
		acm_log(0, "ERROR - unable to assign EP name\n");
		return ret;
	}

	ep->cq = ibv_create_cq(port->dev->verbs, send_depth + recv_depth, ep,
		port->dev->channel, 0);
	if (!ep->cq) {
		acm_log(0, "ERROR - failed to create CQ\n");
		return -1;
	}

	ret = ibv_req_notify_cq(ep->cq, 0);
	if (ret) {
		acm_log(0, "ERROR - failed to arm CQ\n");
		goto err1;
	}

	memset(&init_attr, 0, sizeof init_attr);
	init_attr.cap.max_send_wr = send_depth;
	init_attr.cap.max_recv_wr = recv_depth;
	init_attr.cap.max_send_sge = 1;
	init_attr.cap.max_recv_sge = 1;
	init_attr.qp_context = ep;
	init_attr.sq_sig_all = 1;
	init_attr.qp_type = IBV_QPT_UD;
	init_attr.send_cq = ep->cq;
	init_attr.recv_cq = ep->cq;
	ep->qp = ibv_create_qp(ep->port->dev->pd, &init_attr);
	if (!ep->qp) {
		acm_log(0, "ERROR - failed to create QP\n");
		goto err1;
	}

	attr.qp_state = IBV_QPS_INIT;
	attr.port_num = port->port_num;
	attr.pkey_index = pkey_index;
	attr.qkey = ACM_QKEY;
	ret = ibv_modify_qp(ep->qp, &attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX |
		IBV_QP_PORT | IBV_QP_QKEY);
	if (ret) {
		acm_log(0, "ERROR - failed to modify QP to init\n");
		goto err2;
	}

	attr.qp_state = IBV_QPS_RTR;
	ret = ibv_modify_qp(ep->qp, &attr, IBV_QP_STATE);
	if (ret) {
		acm_log(0, "ERROR - failed to modify QP to rtr\n");
		goto err2;
	}

	attr.qp_state = IBV_QPS_RTS;
	attr.sq_psn = 0;
	ret = ibv_modify_qp(ep->qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN);
	if (ret) {
		acm_log(0, "ERROR - failed to modify QP to rts\n");
		goto err2;
	}

	ret = acm_post_recvs(ep);
	if (ret)
		goto err2;

	return 0;

err2:
	ibv_destroy_qp(ep->qp);
err1:
	ibv_destroy_cq(ep->cq);
	return -1;
}

static void acm_activate_port(struct acm_port *port)
{
	struct acm_ep *ep;
	int i, ret;

	acm_log(1, "%s %d\n", port->dev->verbs->device->name,
		port->port_num);

	for (i = 0; i < port->pkey_cnt; i++) {
		ep = zalloc(sizeof *ep);
		if (!ep)
			break;

		ret = acm_activate_ep(port, ep, (uint16_t) i);
		if (!ret) {
			DListInsertHead(&ep->entry, &port->ep_list);
		} else {
			acm_log(0, "ERROR - failed to activate EP\n");
			free(ep);
		}
	}

	if (DListEmpty(&port->ep_list))
		goto err1;

	port->mad_portid = umad_open_port(port->dev->verbs->device->name, port->port_num);
	if (port->mad_portid < 0) {
		acm_log(0, "ERROR - unable to open MAD port\n");
		goto err2;
	}

	port->mad_agentid = umad_register(port->mad_portid,
		IB_MGMT_CLASS_SA, 1, 1, NULL);
	if (port->mad_agentid < 0) {
		acm_log(0, "ERROR - unable to register MAD client\n");
		goto err3;
	}

	return;

err3:
	umad_close_port(port->mad_portid);
err2:
	/* TODO: cleanup ep list */
err1:
	port->state = IBV_PORT_NOP;
	port->dev->active--;
}

static int acm_activate_dev(struct acm_device *dev)
{
	int i;

	acm_log(1, "%s\n", dev->verbs->device->name);
	dev->pd = ibv_alloc_pd(dev->verbs);
	if (!dev->pd)
		return ACM_STATUS_ENOMEM;

	dev->channel = ibv_create_comp_channel(dev->verbs);
	if (!dev->channel) {
		acm_log(0, "ERROR - unable to create comp channel\n");
		goto err1;
	}

	for (i = 0; i < dev->port_cnt; i++) {
		acm_log(2, "checking port %d\n", dev->port[i].port_num);
		if (dev->port[i].state == IBV_PORT_ACTIVE)
			acm_activate_port(&dev->port[i]);
	}

	if (!dev->active)
		goto err2;

	acm_log(1, "starting completion thread\n");
	beginthread(acm_comp_handler, dev);
	return 0;

err2:
	ibv_destroy_comp_channel(dev->channel);
err1:
	ibv_dealloc_pd(dev->pd);
	return -1;
}

static void acm_init_port(struct acm_port *port)
{
	struct ibv_port_attr attr;
	union ibv_gid gid;
	uint16_t pkey;
	int ret;

	acm_log(1, "%s %d\n", port->dev->verbs->device->name, port->port_num);
	DListInit(&port->ep_list);
	ret = ibv_query_port(port->dev->verbs, port->port_num, &attr);
	if (ret)
		return;

	port->state = attr.state;
	port->mtu = attr.active_mtu;
	port->rate = acm_get_rate(attr.active_width, attr.active_speed);
	port->subnet_timeout = 1 << (attr.subnet_timeout - 8);
	for (;; port->gid_cnt++) {
		ret = ibv_query_gid(port->dev->verbs, port->port_num, port->gid_cnt, &gid);
		if (ret || !gid.global.interface_id)
			break;
	}

	for (;; port->pkey_cnt++) {
		ret = ibv_query_pkey(port->dev->verbs, port->port_num, port->pkey_cnt, &pkey);
		if (ret || !pkey)
			break;
	}
	port->lid = attr.lid;
	port->lmc = attr.lmc;

	port->sa_dest.av.dlid = attr.sm_lid;
	port->sa_dest.av.sl = attr.sm_sl;
	port->sa_dest.av.port_num = port->port_num;
	port->sa_dest.remote_qpn = 1;

	if (port->state == IBV_PORT_ACTIVE)
		port->dev->active++;
}

static void acm_open_dev(struct ibv_device *ibdev)
{
	struct acm_device *dev;
	struct ibv_device_attr attr;
	struct ibv_context *verbs;
	size_t size;
	int i, ret;

	acm_log(1, "%s\n", ibdev->name);
	verbs = ibv_open_device(ibdev);
	if (verbs == NULL) {
		acm_log(0, "ERROR - opening device %s\n", ibdev->name);
		return;
	}

	ret = ibv_query_device(verbs, &attr);
	if (ret) {
		acm_log(0, "ERROR - ibv_query_device (%s) %d\n", ret, ibdev->name);
		goto err1;
	}

	size = sizeof(*dev) + sizeof(struct acm_port) * attr.phys_port_cnt;
	dev = (struct acm_device *) zalloc(size);
	if (!dev)
		goto err1;

	dev->verbs = verbs;
	dev->guid = ibv_get_device_guid(ibdev);
	dev->port_cnt = attr.phys_port_cnt;
	dev->init_depth = (uint8_t) attr.max_qp_init_rd_atom;
	dev->resp_resources = (uint8_t) attr.max_qp_rd_atom;

	for (i = 0; i < dev->port_cnt; i++) {
		dev->port[i].dev = dev;
		dev->port[i].port_num = i + 1;
		acm_init_port(&dev->port[i]);
	}

	if (!dev->active || acm_activate_dev(dev))
		goto err2;

	acm_log(1, "%s now active\n", ibdev->name);
	DListInsertHead(&dev->entry, &dev_list);
	return;

err2:
	free(dev);
err1:
	ibv_close_device(verbs);
}

static void acm_set_options(void)
{
	FILE *f;
	char s[120];
	char opt[32], value[32];

	if (!(f = fopen("acm_opts.cfg", "r")))
		return;

	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;

		if (sscanf(s, "%32s%32s", opt, value) != 2)
			continue;

		if (!stricmp("log_file", opt))
			strcpy(log_file, value);
		else if (!stricmp("log_level", opt))
			log_level = atoi(value);
		else if (!stricmp("server_port", opt))
			server_port = (short) atoi(value);
		else if (!stricmp("timeout", opt))
			timeout = atoi(value);
		else if (!stricmp("retries", opt))
			retries = atoi(value);
		else if (!stricmp("send_depth", opt))
			send_depth = atoi(value);
		else if (!stricmp("recv_depth", opt))
			recv_depth = atoi(value);
		else if (!stricmp("min_mtu", opt))
			min_mtu = acm_convert_mtu(atoi(value));
		else if (!stricmp("min_rate", opt))
			min_rate = acm_convert_rate(atoi(value));
	}

	fclose(f);
}

static void acm_log_options(void)
{
	acm_log(0, "log level %d\n", log_level);
	acm_log(0, "server_port %d\n", server_port);
	acm_log(0, "timeout %d ms\n", timeout);
	acm_log(0, "retries %d\n", retries);
	acm_log(0, "send depth %d\n", send_depth);
	acm_log(0, "receive depth %d\n", recv_depth);
	acm_log(0, "minimum mtu %d\n", min_mtu);
	acm_log(0, "minimum rate %d\n", min_rate);
}

static FILE *acm_open_log(void)
{
	FILE *f;
	int n;

	if (!stricmp(log_file, "stdout"))
		return stdout;

	if (!stricmp(log_file, "stderr"))
		return stderr;

	n = strlen(log_file);
	sprintf(&log_file[n], "%5u.log", getpid());
	if (!(f = fopen(log_file, "w")))
		f = stdout;

	return f;
}

int CDECL_FUNC main(int argc, char **argv)
{
	struct ibv_device **ibdev;
	int dev_cnt;
	int i;

	if (osd_init())
		return -1;

	acm_set_options();

	lock_init(&log_lock);
	flog = acm_open_log();

	acm_log(0, "Assistant to the InfiniBand Communication Manager\n");
	acm_log_options();

	DListInit(&dev_list);
	DListInit(&timeout_list);
	event_init(&timeout_event);

	umad_init();
	ibdev = ibv_get_device_list(&dev_cnt);
	if (!ibdev) {
		acm_log(0, "ERROR - unable to get device list\n");
		return -1;
	}

	acm_log(1, "opening devices\n");
	for (i = 0; i < dev_cnt; i++)
		acm_open_dev(ibdev[i]);

	ibv_free_device_list(ibdev);

	acm_log(1, "initiating multicast joins\n");
	acm_join_groups();
	acm_log(1, "multicast joins done\n");
	acm_log(1, "starting timeout/retry thread\n");
	beginthread(acm_retry_handler, NULL);
	acm_log(1, "starting server\n");
	acm_server();

	acm_log(0, "shutting down\n");
	fclose(flog);
	return 0;
}
