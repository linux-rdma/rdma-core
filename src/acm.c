/*
 * Copyright (c) 2009-2010 Intel Corporation. All rights reserved.
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
#include <infiniband/verbs.h>
#include <dlist.h>
#include <search.h>
#include "acm_mad.h"

#define src_out     reserved[0]

#define MAX_EP_ADDR 4
#define MAX_EP_MC   2

enum acm_state {
	ACM_INIT,
	ACM_QUERY_ADDR,
	ACM_ADDR_RESOLVED,
	ACM_QUERY_ROUTE,
	ACM_PROCESS_REQUEST,
	ACM_READY
};

enum acm_addr_prot
{
	ACM_ADDR_PROT_ACM
};

enum acm_route_prot
{
	ACM_ROUTE_PROT_ACM,
	ACM_ROUTE_PROT_SA
};

/*
 * Nested locking order: dest -> ep, dest -> port
 */
struct acm_dest
{
	uint8_t                address[ACM_MAX_ADDRESS]; /* keep first */
	struct ibv_ah          *ah;
	struct ibv_ah_attr     av;
	struct ibv_path_record path;
	union ibv_gid          mgid;
	uint64_t               req_id;
	DLIST_ENTRY            req_queue;
	uint32_t               remote_qpn;
	lock_t                 lock;
	enum acm_state         state;
	atomic_t               refcnt;
	uint8_t                addr_type;
};

struct acm_port
{
	struct acm_device   *dev;
	DLIST_ENTRY         ep_list;
	lock_t              lock;
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
	int                     port_cnt;
	struct acm_port         port[0];
};

/* Maintain separate virtual send queues to avoid deadlock */
struct acm_send_queue
{
	int                   credits;
	DLIST_ENTRY           pending;
};

struct acm_ep
{
	struct acm_port       *port;
	struct ibv_cq         *cq;
	struct ibv_qp         *qp;
	struct ibv_mr         *mr;
	uint8_t               *recv_bufs;
	DLIST_ENTRY           entry;
	union acm_ep_info     addr[MAX_EP_ADDR];
	uint8_t               addr_type[MAX_EP_ADDR];
	void                  *dest_map[ACM_ADDRESS_RESERVED - 1];
	struct acm_dest       mc_dest[MAX_EP_MC];
	int                   mc_cnt;
	uint16_t              pkey_index;
	uint16_t              pkey;
	lock_t                lock;
	struct acm_send_queue resolve_queue;
	struct acm_send_queue sa_queue;
	struct acm_send_queue resp_queue;
	DLIST_ENTRY           active_queue;
	DLIST_ENTRY           wait_queue;
	enum acm_state        state;
};

struct acm_send_msg
{
	DLIST_ENTRY          entry;
	struct acm_ep        *ep;
	struct acm_dest      *dest;
	void                 *context;
	void                 (*resp_handler)(struct acm_send_msg *req,
	                                     struct ibv_wc *wc, struct acm_mad *resp);
	struct acm_send_queue *req_queue;
	struct ibv_mr        *mr;
	struct ibv_send_wr   wr;
	struct ibv_sge       sge;
	uint64_t             expires;
	int                  tries;
	uint8_t              data[ACM_SEND_SIZE];
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
static enum acm_addr_prot addr_prot = ACM_ADDR_PROT_ACM;
static enum acm_route_prot route_prot = ACM_ROUTE_PROT_ACM;
static short server_port = 6125;
static int timeout = 2000;
static int retries = 15;
static int resolve_depth = 1;
static int sa_depth = 1;
static int send_depth = 1;
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
	fflush(flog);
	lock_release(&log_lock);
	va_end(args);
}

static void acm_log_addr(int level, const char *msg, uint16_t addr_type, uint8_t *addr)
{
	struct ibv_path_record *path;
	char ip_addr[ACM_MAX_ADDRESS];

	if (level > log_level)
		return;

	lock_acquire(&log_lock);
	fprintf(flog, msg);
	switch (addr_type) {
	case ACM_EP_INFO_NAME:
		fprintf(flog, "%s\n", addr);
		break;
	case ACM_EP_INFO_ADDRESS_IP:
		inet_ntop(AF_INET, addr, ip_addr, ACM_MAX_ADDRESS);
		fprintf(flog, "%s\n", ip_addr);
		break;
	case ACM_EP_INFO_ADDRESS_IP6:
		inet_ntop(AF_INET6, addr, ip_addr, ACM_MAX_ADDRESS);
		fprintf(flog, "%s\n", ip_addr);
		break;
	case ACM_EP_INFO_PATH:
		path = (struct ibv_path_record *) addr;
		fprintf(flog, "path record, SLID 0x%x, DLID 0x%x\n",
			ntohs(path->slid), ntohs(path->dlid));
		break;
	default:
		fprintf(flog, "unknown address 0x%x\n", addr_type);
	}
	lock_release(&log_lock);
}

static int acm_compare_dest(const void *dest1, const void *dest2)
{
	return memcmp(dest1, dest2, ACM_MAX_ADDRESS);
}

static void
acm_init_dest(struct acm_dest *dest, uint8_t addr_type, uint8_t *addr, size_t size)
{
	memcpy(dest->address, addr, size);
	dest->addr_type = addr_type;
	DListInit(&dest->req_queue);
	atomic_set(&dest->refcnt, 1);
	lock_init(&dest->lock);
}

static struct acm_dest *
acm_alloc_dest(uint8_t addr_type, uint8_t *addr)
{
	struct acm_dest *dest;

	dest = calloc(1, sizeof *dest);
	if (!dest) {
		acm_log(0, "ERROR - unable to allocate dest\n");
		return NULL;
	}

	acm_init_dest(dest, addr_type, addr, ACM_MAX_ADDRESS);
	acm_log(1, "%p\n", dest);
	return dest;
}

/* Caller must hold ep lock. */
static struct acm_dest *
acm_get_dest(struct acm_ep *ep, uint8_t addr_type, uint8_t *addr)
{
	struct acm_dest *dest, **tdest;

	tdest = tfind(addr, &ep->dest_map[addr_type - 1], acm_compare_dest);
	if (tdest) {
		dest = *tdest;
		(void) atomic_inc(&dest->refcnt);
	} else {
		dest = NULL;
	}
	acm_log(2, "%p\n", dest);
	return dest;
}

static void
acm_put_dest(struct acm_dest *dest)
{
	acm_log(2, "%p\n", dest);
	if (atomic_dec(&dest->refcnt) == 0) {
		free(dest);
	}
}

static struct acm_dest *
acm_acquire_dest(struct acm_ep *ep, uint8_t addr_type, uint8_t *addr)
{
	struct acm_dest *dest;

	acm_log_addr(2, "acm_acquire_dest: ", addr_type, addr);
	lock_acquire(&ep->lock);
	dest = acm_get_dest(ep, addr_type, addr);
	if (!dest) {
		dest = acm_alloc_dest(addr_type, addr);
		if (dest) {
			tsearch(dest, &ep->dest_map[addr_type - 1], acm_compare_dest);
			(void) atomic_inc(&dest->refcnt);
		}
	}
	lock_release(&ep->lock);
	return dest;
}

/* Caller must hold ep lock. */
//static void
//acm_remove_dest(struct acm_ep *ep, struct acm_dest *dest)
//{
//	acm_log_addr(2, "acm_remove_dest: ", dest->addr_type, dest->addr);
//	tdelete(dest->address, &ep->dest_map[dest->addr_type - 1], acm_compare_dest);
//	acm_put_dest(dest);
//}

static struct acm_request *
acm_alloc_req(struct acm_client *client, struct acm_resolve_msg *msg)
{
	struct acm_request *req;

	req = calloc(1, sizeof *req);
	if (!req) {
		acm_log(0, "ERROR - unable to alloc client request\n");
		return NULL;
	}

	(void) atomic_inc(&client->refcnt);
	req->client = client;
	memcpy(&req->msg, msg, sizeof(req->msg));
	acm_log(2, "%p\n", req);
	return req;
}

static void
acm_free_req(struct acm_request *req)
{
	acm_log(2, "%p\n", req);
	(void) atomic_dec(&client->refcnt);
	free(req);
}

static struct acm_send_msg *
acm_alloc_send(struct acm_ep *ep, struct acm_dest *dest, size_t size)
{
	struct acm_send_msg *msg;

	msg = (struct acm_send_msg *) calloc(1, sizeof *msg);
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

	(void) atomic_inc(&dest->refcnt);
	msg->dest = dest;
	msg->wr.wr.ud.ah = dest->ah;
	msg->wr.wr.ud.remote_qpn = dest->remote_qpn;
	msg->wr.wr.ud.remote_qkey = ACM_QKEY;

	msg->sge.length = size;
	msg->sge.lkey = msg->mr->lkey;
	msg->sge.addr = (uintptr_t) msg->data;
	acm_log(2, "%p\n", msg);
	return msg;
err:
	free(msg);
	return NULL;
}

static void
acm_init_send_req(struct acm_send_msg *msg, void *context, 
	void (*resp_handler)(struct acm_send_msg *req,
		struct ibv_wc *wc, struct acm_mad *resp))
{
	acm_log(2, "%p\n", msg);
	msg->tries = retries + 1;
	msg->context = context;
	msg->resp_handler = resp_handler;
}

static void acm_free_send(struct acm_send_msg *msg)
{
	acm_log(2, "%p\n", msg);
	ibv_dereg_mr(msg->mr);
	acm_put_dest(msg->dest);
	free(msg);
}

static void acm_post_send(struct acm_send_queue *queue, struct acm_send_msg *msg)
{
	struct acm_ep *ep = msg->ep;
	struct ibv_send_wr *bad_wr;

	msg->req_queue = queue;
	lock_acquire(&ep->lock);
	if (queue->credits) {
		acm_log(2, "posting send to QP\n");
		queue->credits--;
		DListInsertTail(&msg->entry, &ep->active_queue);
		ibv_post_send(ep->qp, &msg->wr, &bad_wr);
	} else {
		acm_log(2, "no sends available, queuing message\n");
		DListInsertTail(&msg->entry, &queue->pending);
	}
	lock_release(&ep->lock);
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

/* Caller must hold ep lock */
static void acm_send_available(struct acm_ep *ep, struct acm_send_queue *queue)
{
	struct acm_send_msg *msg;
	struct ibv_send_wr *bad_wr;
	DLIST_ENTRY *entry;

	if (DListEmpty(&queue->pending)) {
		queue->credits++;
	} else {
		acm_log(2, "posting queued send message\n");
		entry = queue->pending.Next;
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
		acm_send_available(ep, msg->req_queue);
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
			acm_send_available(ep, msg->req_queue);
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

/* Multicast groups are ordered lowest to highest preference. */
static int acm_best_mc_index(struct acm_ep *ep, struct acm_resolve_rec *rec)
{
	int i, index;

	for (i = min(rec->gid_cnt, ACM_MAX_GID_COUNT) - 1; i >= 0; i--) {
		index = acm_mc_index(ep, &rec->gid[i]);
		if (index >= 0) {
			return index;
		}
	}
	return -1;
}

static void
acm_record_mc_av(struct acm_port *port, struct ib_mc_member_rec *mc_rec,
	struct acm_dest *dest)
{
	uint32_t sl_flow_hop;

	sl_flow_hop = ntohl(mc_rec->sl_flow_hop);

	dest->av.dlid = ntohs(mc_rec->mlid);
	dest->av.sl = (uint8_t) (sl_flow_hop >> 28);
	dest->av.src_path_bits = port->sa_dest.av.src_path_bits;
	dest->av.static_rate = mc_rec->rate & 0x3F;
	dest->av.port_num = port->port_num;

	dest->av.is_global = 1;
	dest->av.grh.dgid = mc_rec->mgid;
	dest->av.grh.flow_label = (sl_flow_hop >> 8) & 0xFFFFF;
	dest->av.grh.sgid_index = acm_gid_index(port, &mc_rec->port_gid);
	dest->av.grh.hop_limit = (uint8_t) sl_flow_hop;
	dest->av.grh.traffic_class = mc_rec->tclass;

	dest->path.dgid = mc_rec->mgid;
	dest->path.sgid = mc_rec->port_gid;
	dest->path.dlid = mc_rec->mlid;
	dest->path.slid = htons(port->lid) | port->sa_dest.av.src_path_bits;
	dest->path.flowlabel_hoplimit = htonl(sl_flow_hop & 0xFFFFFFF);
	dest->path.tclass = mc_rec->tclass;
	dest->path.reversible_numpath = IBV_PATH_RECORD_REVERSIBLE | 1;
	dest->path.pkey = mc_rec->pkey;
	dest->path.qosclass_sl = htons((uint16_t) (sl_flow_hop >> 28));
	dest->path.mtu = mc_rec->mtu;
	dest->path.rate = mc_rec->rate;
	dest->path.packetlifetime = mc_rec->packet_lifetime;
}

/* Always send the GRH to transfer GID data to remote side */
static void
acm_init_path_av(struct acm_port *port, struct acm_dest *dest)
{
	uint32_t flow_hop;

	dest->av.dlid = ntohs(dest->path.dlid);
	dest->av.sl = ntohs(dest->path.qosclass_sl) & 0xF;
	dest->av.src_path_bits = dest->path.slid & 0x7F;
	dest->av.static_rate = dest->path.rate & 0x3F;
	dest->av.port_num = port->port_num;

	flow_hop = ntohl(dest->path.flowlabel_hoplimit);
	dest->av.is_global = 1;
	dest->av.grh.flow_label = (flow_hop >> 8) & 0xFFFFF;
	dest->av.grh.sgid_index = acm_gid_index(port, &dest->path.sgid);
	dest->av.grh.hop_limit = (uint8_t) flow_hop;
	dest->av.grh.traffic_class = dest->path.tclass;
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
		acm_record_mc_av(ep->port, mc_rec, dest);
		dest->ah = ibv_create_ah(ep->port->dev->pd, &dest->av);
		ret = ibv_attach_mcast(ep->qp, &mc_rec->mgid, mc_rec->mlid);
		if (ret) {
			acm_log(0, "ERROR - unable to attach QP to multicast group\n");
		} else {
			dest->state = ACM_READY;
			acm_log(1, "join successful\n");
		}
	} else {
		acm_log(0, "ERROR - MGID in join response not found\n");
	}
	lock_release(&ep->lock);
}

static int acm_addr_index(struct acm_ep *ep, uint8_t *addr, uint8_t addr_type)
{
	int i;

	for (i = 0; i < MAX_EP_ADDR; i++) {
		if (ep->addr_type[i] != addr_type)
			continue;

		if ((addr_type == ACM_ADDRESS_NAME &&
			!strnicmp((char *) ep->addr[i].name,
				(char *) addr, ACM_MAX_ADDRESS)) ||
			!memcmp(ep->addr[i].addr, addr, ACM_MAX_ADDRESS))
			return i;
	}
	return -1;
}

static uint8_t
acm_record_acm_route(struct acm_ep *ep, struct acm_dest *dest)
{
	uint8_t status;

	acm_log(2, "\n");
	dest->ah = ibv_create_ah(ep->port->dev->pd, &dest->av);
	if (!dest->ah) {
		acm_log(0, "ERROR - failed to create ah\n");
		dest->state = ACM_INIT;
		status = ACM_STATUS_ENOMEM;
	} else {
		dest->state = ACM_READY;
		status = ACM_STATUS_SUCCESS;
	}
	
	return status;
}

static void acm_init_path_query(struct ib_sa_mad *mad)
{
	acm_log(2, "\n");
	mad->base_version = 1;
	mad->mgmt_class = IB_MGMT_CLASS_SA;
	mad->class_version = 2;
	mad->method = IB_METHOD_GET;
	mad->tid = (uint64_t) atomic_inc(&tid);
	mad->attr_id = IB_SA_ATTR_PATH_REC;
}

/* Caller must hold dest lock */
static uint8_t acm_resolve_path(struct acm_ep *ep, struct acm_dest *dest,
	void (*resp_handler)(struct acm_send_msg *req,
		struct ibv_wc *wc, struct acm_mad *resp))
{
	struct acm_send_msg *msg;
	struct ib_sa_mad *mad;

	acm_log(2, "\n");
	msg = acm_alloc_send(ep, &ep->port->sa_dest, sizeof(*mad));
	if (!msg) {
		acm_log(0, "ERROR - cannot allocate send msg\n");
		dest->state = ACM_INIT;
		return ACM_STATUS_ENOMEM;
	}

	acm_init_send_req(msg, (void *) dest, resp_handler);
	mad = (struct ib_sa_mad *) msg->data;
	acm_init_path_query(mad);

	memcpy(mad->data, &dest->path, sizeof(dest->path));
	mad->comp_mask = IB_COMP_MASK_PR_DGID | IB_COMP_MASK_PR_SGID |
		IB_COMP_MASK_PR_TCLASS | IB_COMP_MASK_PR_PKEY;

	dest->state = ACM_QUERY_ROUTE;
	acm_post_send(&ep->sa_queue, msg);
	return ACM_STATUS_SUCCESS;
}

static uint8_t
acm_record_acm_addr(struct acm_ep *ep, struct acm_dest *dest, struct ibv_wc *wc,
	struct acm_resolve_rec *rec)
{
	int index;

	acm_log(2, "\n");
	index = acm_best_mc_index(ep, rec);
	if (index < 0) {
		acm_log(0, "ERROR - no shared multicast groups\n");
		dest->state = ACM_INIT;
		return ACM_STATUS_ENODATA;
	}

	acm_log(2, "selecting MC group at index %d\n", index);
	dest->av = ep->mc_dest[index].av;
	dest->av.dlid = wc->slid;
	dest->av.src_path_bits = wc->dlid_path_bits;
	dest->av.grh.dgid = ((struct ibv_grh *) (uintptr_t) wc->wr_id)->sgid;
	
	dest->mgid = ep->mc_dest[index].mgid;

	dest->path = ep->mc_dest[index].path;
	dest->path.dgid = dest->av.grh.dgid;
	dest->path.dlid = htons(dest->av.dlid);
	dest->remote_qpn = wc->src_qp;

	dest->state = ACM_ADDR_RESOLVED;
	return ACM_STATUS_SUCCESS;
}

static uint8_t acm_validate_addr_req(struct acm_mad *mad)
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

	return ACM_STATUS_SUCCESS;
}

static void
acm_send_addr_resp(struct acm_ep *ep, struct acm_dest *dest)
{
	struct acm_resolve_rec *rec;
	struct acm_send_msg *msg;
	struct acm_mad *mad;

	acm_log(2, "\n");
	msg = acm_alloc_send(ep, dest, sizeof (*mad));
	if (!msg) {
		acm_log(0, "ERROR - failed to allocate message\n");
		return;
	}

	mad = (struct acm_mad *) msg->data;
	rec = (struct acm_resolve_rec *) mad->data;

	mad->base_version = 1;
	mad->mgmt_class = ACM_MGMT_CLASS;
	mad->class_version = 1;
	mad->method = IB_METHOD_GET | IB_METHOD_RESP;
	mad->status = ACM_STATUS_SUCCESS;
	mad->control = ACM_CTRL_RESOLVE;
	mad->tid = dest->req_id;
	rec->gid_cnt = 1;
	memcpy(rec->gid, dest->mgid.raw, sizeof(union ibv_gid));

	acm_post_send(&ep->resp_queue, msg);
}

static int
acm_client_resolve_resp(struct acm_client *client, struct acm_resolve_msg *req_msg,
	struct acm_dest *dest, uint8_t status)
{
	struct acm_msg msg;
	struct acm_resolve_msg *resp_msg = (struct acm_resolve_msg *) &msg;
	int ret;

	acm_log(1, "status 0x%x\n", status);
	memset(&msg, 0, sizeof msg);

	lock_acquire(&client->lock);
	if (client->sock == INVALID_SOCKET) {
		acm_log(0, "ERROR - connection lost\n");
		ret = ACM_STATUS_ENOTCONN;
		goto release;
	}

	resp_msg->hdr = req_msg->hdr;
	resp_msg->hdr.opcode |= ACM_OP_ACK;
	resp_msg->hdr.status = status;
	resp_msg->hdr.length = ACM_MSG_HDR_LENGTH;
	memset(resp_msg->hdr.reserved, 0, sizeof(resp_msg->hdr.reserved));

	if (status == ACM_STATUS_SUCCESS) {
		resp_msg->hdr.length += ACM_MSG_EP_LENGTH;
		resp_msg->data[0].flags = IBV_PATH_FLAG_GMP |
			IBV_PATH_FLAG_PRIMARY | IBV_PATH_FLAG_BIDIRECTIONAL;
		resp_msg->data[0].type = ACM_EP_INFO_PATH;
		resp_msg->data[0].info.path = dest->path;

		if (req_msg->hdr.src_out) {
			resp_msg->hdr.length += ACM_MSG_EP_LENGTH;
			memcpy(&resp_msg->data[1], &req_msg->data[req_msg->hdr.src_out],
				ACM_MSG_EP_LENGTH);
		}
	}

	ret = send(client->sock, (char *) resp_msg, resp_msg->hdr.length, 0);
	if (ret != resp_msg->hdr.length)
		acm_log(0, "failed to send response\n");
	else
		ret = 0;

release:
	lock_release(&client->lock);
	return ret;
}

static void
acm_complete_queued_req(struct acm_dest *dest, uint8_t status)
{
	struct acm_request *req;
	DLIST_ENTRY *entry;

	acm_log(2, "status %d\n", status);
	lock_acquire(&dest->lock);
	while (!DListEmpty(&dest->req_queue)) {
		entry = dest->req_queue.Next;
		DListRemove(entry);
		req = container_of(entry, struct acm_request, entry);
		lock_release(&dest->lock);

		acm_log(2, "completing client request\n");
		acm_client_resolve_resp(req->client,
			(struct acm_resolve_msg *) &req->msg, dest, status);
		acm_free_req(req);

		lock_acquire(&dest->lock);
	}
	lock_release(&dest->lock);
}

static void
acm_dest_sa_resp(struct acm_send_msg *msg, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_dest *dest = (struct acm_dest *) msg->context;
	struct ib_sa_mad *sa_mad = (struct ib_sa_mad *) mad;
	uint8_t status;

	if (mad) {
		status = (uint8_t) (ntohs(mad->status) >> 8);
	} else {
		status = ACM_STATUS_ETIMEDOUT;
	}
	acm_log(2, "resp status 0x%x\n", status);

	lock_acquire(&dest->lock);
	if (dest->state != ACM_QUERY_ROUTE) {
		lock_release(&dest->lock);
		return;
	}

	if (!status) {
		memcpy(&dest->path, sa_mad->data, sizeof(dest->path));
		acm_init_path_av(msg->ep->port, dest);
		dest->ah = ibv_create_ah(msg->ep->port->dev->pd, &dest->av);
		if (!dest->ah) {
			acm_log(0, "ERROR - failed to create ah\n");
			status = ACM_STATUS_ENOMEM;
		}
	}
	if (!status) {
		dest->state = ACM_READY;
	} else {
		dest->state = ACM_INIT;
	}
	lock_release(&dest->lock);

	acm_complete_queued_req(dest, status);
}

static void
acm_resolve_sa_resp(struct acm_send_msg *msg, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_dest *dest = (struct acm_dest *) msg->context;
	int send_resp;

	acm_log(2, "\n");
	acm_dest_sa_resp(msg, wc, mad);

	lock_acquire(&dest->lock);
	send_resp = (dest->state == ACM_READY);
	lock_release(&dest->lock);

	if (send_resp)
		acm_send_addr_resp(msg->ep, dest);
}

static void
acm_process_addr_req(struct acm_ep *ep, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_resolve_rec *rec;
	struct acm_dest *dest;
	uint8_t status;
	int addr_index;

	acm_log(2, "\n");
	if ((status = acm_validate_addr_req(mad))) {
		acm_log(0, "ERROR - invalid request\n");
		return;
	}

	rec = (struct acm_resolve_rec *) mad->data;
	dest = acm_acquire_dest(ep, rec->src_type, rec->src);
	if (!dest) {
		acm_log(0, "ERROR - unable to add source\n");
		return;
	}
	
	addr_index = acm_addr_index(ep, rec->dest, rec->dest_type);
	if (addr_index >= 0)
		dest->req_id = mad->tid;

	lock_acquire(&dest->lock);
	switch (dest->state) {
	case ACM_READY:
		if (dest->remote_qpn == wc->src_qp)
			break;

		ibv_destroy_ah(dest->ah); // TODO: ah could be in use
		/* fall through */
	default:
		status = acm_record_acm_addr(ep, dest, wc, rec);
		if (status)
			break;

		if (route_prot == ACM_ROUTE_PROT_ACM) {
			status = acm_record_acm_route(ep, dest);
		} else if (addr_index >= 0) {
			status = acm_resolve_path(ep, dest, acm_resolve_sa_resp);
			if (!status) {
				lock_release(&dest->lock);
				return;
			}
		}
	}
	lock_release(&dest->lock);
	acm_complete_queued_req(dest, status);

	if (addr_index >= 0 && !status) {
		acm_send_addr_resp(ep, dest);
	}
	acm_put_dest(dest);
}

static void
acm_process_addr_resp(struct acm_send_msg *msg, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_resolve_rec *resp_rec;
	struct acm_dest *dest = (struct acm_dest *) msg->context;
	uint8_t status;

	if (mad) {
		status = acm_class_status(mad->status);
		resp_rec = (struct acm_resolve_rec *) mad->data;
	} else {
		status = ACM_STATUS_ETIMEDOUT;
		resp_rec = NULL;
	}
	acm_log(2, "resp status 0x%x\n", status);

	lock_acquire(&dest->lock);
	if (dest->state != ACM_QUERY_ADDR) {
		lock_release(&dest->lock);
		acm_put_dest(dest);
		return;
	}

	if (!status) {
		status = acm_record_acm_addr(msg->ep, dest, wc, resp_rec);
		if (!status) {
			if (route_prot == ACM_ROUTE_PROT_ACM) {
				status = acm_record_acm_route(msg->ep, dest);
			} else {
				status = acm_resolve_path(msg->ep, dest, acm_dest_sa_resp);
				if (!status) {
					lock_release(&dest->lock);
					return;
				}
			}
		}
	} else {
		dest->state = ACM_INIT;
	}
	lock_release(&dest->lock);

	acm_complete_queued_req(dest, status);
	acm_put_dest(dest);
}

static void acm_process_acm_recv(struct acm_ep *ep, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_send_msg *req;
	int free;

	acm_log(2, "\n");
	if (mad->base_version != 1 || mad->class_version != 1) {
		acm_log(0, "ERROR - invalid version %d %d\n",
			mad->base_version, mad->class_version);
		return;
	}
	
	if (mad->control != ACM_CTRL_RESOLVE) {
		acm_log(0, "ERROR - invalid control 0x%x\n", mad->control);
		return;
	}

	if (mad->method & IB_METHOD_RESP) {
		acm_log(2, "received response\n");
		req = acm_get_request(ep, mad->tid, &free);
		if (!req) {
			acm_log(0, "response did not match active request\n");
			return;
		}
		acm_log(2, "found matching request\n");
		req->resp_handler(req, wc, mad);
		if (free)
			acm_free_send(req);
	} else {
		acm_log(2, "unsolicited request\n");
		acm_process_addr_req(ep, wc, mad);
	}
}

static int
acm_client_query_resp(struct acm_client *client,
	struct acm_resolve_msg *msg, uint8_t status)
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

	ret = send(client->sock, (char *) msg, msg->hdr.length, 0);
	if (ret != msg->hdr.length)
		acm_log(0, "failed to send response\n");
	else
		ret = 0;

release:
	lock_release(&client->lock);
	return ret;
}

static void
acm_client_sa_resp(struct acm_send_msg *msg, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_request *req = (struct acm_request *) msg->context;
	struct acm_resolve_msg *client_req = (struct acm_resolve_msg *) &req->msg;
	struct ib_sa_mad *sa_mad = (struct ib_sa_mad *) mad;
	uint8_t status;

	if (mad) {
		status = (uint8_t) (ntohs(sa_mad->status) >> 8);
		memcpy(&client_req->data[0].info.path, sa_mad->data,
			sizeof(struct ibv_path_record));
	} else {
		status = ACM_STATUS_ETIMEDOUT;
	}
	acm_log(2, "status 0x%x\n", status);

	acm_client_query_resp(req->client, client_req, status);
	acm_free_req(req);
}

static void acm_process_sa_recv(struct acm_ep *ep, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct ib_sa_mad *sa_mad = (struct ib_sa_mad *) mad;
	struct acm_send_msg *req;
	int free;

	acm_log(2, "\n");
	if (mad->base_version != 1 || mad->class_version != 2 ||
	    !(mad->method & IB_METHOD_RESP) || sa_mad->attr_id != IB_SA_ATTR_PATH_REC) {
		acm_log(0, "ERROR - unexpected SA MAD %d %d\n",
			mad->base_version, mad->class_version);
		return;
	}
	
	req = acm_get_request(ep, mad->tid, &free);
	if (!req) {
		acm_log(0, "response did not match active request\n");
		return;
	}
	acm_log(2, "found matching request\n");
	req->resp_handler(req, wc, mad);
	if (free)
		acm_free_send(req);
}

static void acm_process_recv(struct acm_ep *ep, struct ibv_wc *wc)
{
	struct acm_mad *mad;

	acm_log(2, "\n");
	mad = (struct acm_mad *) (uintptr_t) (wc->wr_id + sizeof(struct ibv_grh));
	switch (mad->mgmt_class) {
	case IB_MGMT_CLASS_SA:
		acm_process_sa_recv(ep, wc, mad);
		break;
	case ACM_MGMT_CLASS:
		acm_process_acm_recv(ep, wc, mad);
		break;
	default:
		acm_log(0, "ERROR - invalid mgmt class 0x%x\n", mad->mgmt_class);
		break;
	}

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

static uint64_t acm_path_comp_mask(struct ibv_path_record *path)
{
	uint32_t fl_hop;
	uint16_t qos_sl;
	uint64_t comp_mask = 0;

	acm_log(2, "\n");
	if (path->service_id)
		comp_mask |= IB_COMP_MASK_PR_SERVICE_ID;
	if (path->dgid.global.interface_id || path->dgid.global.subnet_prefix)
		comp_mask |= IB_COMP_MASK_PR_DGID;
	if (path->sgid.global.interface_id || path->sgid.global.subnet_prefix)
		comp_mask |= IB_COMP_MASK_PR_SGID;
	if (path->dlid)
		comp_mask |= IB_COMP_MASK_PR_DLID;
	if (path->slid)
		comp_mask |= IB_COMP_MASK_PR_SLID;

	fl_hop = ntohl(path->flowlabel_hoplimit);
	if (fl_hop >> 8)
		comp_mask |= IB_COMP_MASK_PR_FLOW_LABEL;
	if (fl_hop & 0xFF)
		comp_mask |= IB_COMP_MASK_PR_HOP_LIMIT;

	if (path->tclass)
		comp_mask |= IB_COMP_MASK_PR_TCLASS;
	if (path->reversible_numpath & 0x80)
		comp_mask |= IB_COMP_MASK_PR_REVERSIBLE;
	if (path->pkey)
		comp_mask |= IB_COMP_MASK_PR_PKEY;

	qos_sl = ntohs(path->qosclass_sl);
	if (qos_sl >> 4)
		comp_mask |= IB_COMP_MASK_PR_QOS_CLASS;
	if (qos_sl & 0xF)
		comp_mask |= IB_COMP_MASK_PR_SL;

	if (path->mtu & 0xC0)
		comp_mask |= IB_COMP_MASK_PR_MTU_SELECTOR;
	if (path->mtu & 0x3F)
		comp_mask |= IB_COMP_MASK_PR_MTU;
	if (path->rate & 0xC0)
		comp_mask |= IB_COMP_MASK_PR_RATE_SELECTOR;
	if (path->rate & 0x3F)
		comp_mask |= IB_COMP_MASK_PR_RATE;
	if (path->packetlifetime & 0xC0)
		comp_mask |= IB_COMP_MASK_PR_PACKET_LIFETIME_SELECTOR;
	if (path->packetlifetime & 0x3F)
		comp_mask |= IB_COMP_MASK_PR_PACKET_LIFETIME;

	return comp_mask;
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
	umad = (struct ib_user_mad *) calloc(1, len);
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
	acm_init_dest(&ep->mc_dest[ep->mc_cnt++], ACM_ADDRESS_GID,
		mc_rec->mgid.raw, sizeof(mc_rec->mgid));

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

		if ((ep->state = ep->mc_dest[0].state) != ACM_READY)
			continue;

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
	struct acm_resolve_rec *rec;
	
	while (!DListEmpty(&timeout_list)) {
		entry = timeout_list.Next;
		DListRemove(entry);

		msg = container_of(entry, struct acm_send_msg, entry);
		rec = (struct acm_resolve_rec *) ((struct acm_mad *) msg->data)->data;

		acm_log_addr(0, "acm_process_timeouts: dest ", rec->dest_type, rec->dest);
		msg->resp_handler(msg, NULL, NULL);
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
				acm_send_available(ep, msg->req_queue);
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

static void acm_disconnect_client(struct acm_client *client)
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

static uint8_t acm_svr_query_sa(struct acm_ep *ep, struct acm_request *req)
{
	struct acm_resolve_msg *client_req = (struct acm_resolve_msg *) &req->msg;
	struct acm_send_msg *msg;
	struct ib_sa_mad *mad;

	acm_log(2, "\n");
	msg = acm_alloc_send(ep, &ep->port->sa_dest, sizeof(*mad));
	if (!msg) {
		acm_log(0, "ERROR - cannot allocate send msg\n");
		return ACM_STATUS_ENOMEM;
	}

	acm_init_send_req(msg, (void *) req, acm_client_sa_resp);
	mad = (struct ib_sa_mad *) msg->data;
	acm_init_path_query(mad);

	memcpy(mad->data, &client_req->data[0].info.path, sizeof(struct ibv_path_record));
	mad->comp_mask = acm_path_comp_mask(&client_req->data[0].info.path);

	acm_post_send(&ep->sa_queue, msg);
	return ACM_STATUS_SUCCESS;
}

static struct acm_ep *
acm_get_ep(struct acm_ep_addr_data *data)
{
	struct acm_device *dev;
	struct acm_port *port;
	struct acm_ep *ep;
	DLIST_ENTRY *dev_entry, *ep_entry;
	int i;

	acm_log_addr(2, "acm_get_ep: ", data->type, data->info.addr);
	for (dev_entry = dev_list.Next; dev_entry != &dev_list;
		 dev_entry = dev_entry->Next) {

		dev = container_of(dev_entry, struct acm_device, entry);
		for (i = 0; i < dev->port_cnt; i++) {
			port = &dev->port[i];

			if (data->type == ACM_EP_INFO_PATH &&
			    port->lid != ntohs(data->info.path.slid))
				continue;

			for (ep_entry = port->ep_list.Next; ep_entry != &port->ep_list;
				 ep_entry = ep_entry->Next) {

				ep = container_of(ep_entry, struct acm_ep, entry);
				if (ep->state != ACM_READY)
					continue;

				if (data->type == ACM_EP_INFO_PATH)
					return ep; // TODO: check pkey

				if (acm_addr_index(ep, data->info.addr,
				    (uint8_t) data->type) >= 0)
					return ep;
			}
		}
	}

	acm_log_addr(0, "acm_get_ep: could not find ", data->type, data->info.addr);
	return NULL;
}

static int
acm_svr_query(struct acm_client *client, struct acm_resolve_msg *msg)
{
	struct acm_request *req;
	struct acm_ep *ep;
	uint8_t status;

	acm_log(2, "processing client query\n");
	if (msg->hdr.length != ACM_MSG_HDR_LENGTH + ACM_MSG_EP_LENGTH) {
		acm_log(0, "ERROR - invalid length: 0x%x\n", msg->hdr.length);
		status = ACM_STATUS_EINVAL;
		goto resp;
	}

	if (msg->data[0].type != ACM_EP_INFO_PATH) {
		acm_log(0, "ERROR - unsupported type: 0x%x\n", msg->data[0].type);
		status = ACM_STATUS_EINVAL;
		goto resp;
	}

	ep = acm_get_ep(&msg->data[0]);
	if (!ep) {
		acm_log(0, "could not find local end point\n");
		status = ACM_STATUS_ESRCADDR;
		goto resp;
	}

	req = acm_alloc_req(client, msg);
	if (!req) {
		status = ACM_STATUS_ENOMEM;
		goto resp;
	}

	status = acm_svr_query_sa(ep, req);
	if (!status)
		return status;

	acm_free_req(req);
resp:
	return acm_client_query_resp(client, msg, status);
}

static uint8_t
acm_send_resolve(struct acm_ep *ep, struct acm_dest *dest,
	struct acm_ep_addr_data *saddr)
{
	struct acm_send_msg *msg;
	struct acm_mad *mad;
	struct acm_resolve_rec *rec;
	int i;

	acm_log(2, "\n");
	msg = acm_alloc_send(ep, &ep->mc_dest[0], sizeof(*mad));
	if (!msg) {
		acm_log(0, "ERROR - cannot allocate send msg\n");
		return ACM_STATUS_ENOMEM;
	}

	acm_init_send_req(msg, (void *) dest, acm_process_addr_resp);
	(void) atomic_inc(&dest->refcnt);

	mad = (struct acm_mad *) msg->data;
	mad->base_version = 1;
	mad->mgmt_class = ACM_MGMT_CLASS;
	mad->class_version = 1;
	mad->method = IB_METHOD_GET;
	mad->control = ACM_CTRL_RESOLVE;
	mad->tid = (uint64_t) atomic_inc(&tid);

	rec = (struct acm_resolve_rec *) mad->data;
	rec->src_type = (uint8_t) saddr->type;
	rec->src_length = ACM_MAX_ADDRESS;
	memcpy(rec->src, saddr->info.addr, ACM_MAX_ADDRESS);
	rec->dest_type = dest->addr_type;
	rec->dest_length = ACM_MAX_ADDRESS;
	memcpy(rec->dest, dest->address, ACM_MAX_ADDRESS);

	rec->gid_cnt = (uint8_t) ep->mc_cnt;
	for (i = 0; i < ep->mc_cnt; i++)
		memcpy(&rec->gid[i], ep->mc_dest[i].address, 16);
	
	acm_post_send(&ep->resolve_queue, msg);
	return 0;
}

static int acm_svr_select_src(struct acm_ep_addr_data *src, struct acm_ep_addr_data *dst)
{
	struct sockaddr_in6 addr;
	socklen_t len;
	int ret;
	SOCKET s;

	if (src->type)
		return 0;

	acm_log(2, "selecting source address\n");
	memset(&addr, 0, sizeof addr);
	if (dst->type == ACM_EP_INFO_ADDRESS_IP) {
		((struct sockaddr_in *) &addr)->sin_family = AF_INET;
		memcpy(&((struct sockaddr_in *) &addr)->sin_addr, dst->info.addr, 4);
		len = sizeof(struct sockaddr_in);
	} else {
		addr.sin6_family = AF_INET6;
		memcpy(&addr.sin6_addr, dst->info.addr, 16);
		len = sizeof(struct sockaddr_in6);
	}

	s = socket(addr.sin6_family, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET) {
		acm_log(0, "ERROR - unable to allocate socket\n");
		return socket_errno();
	}

	ret = connect(s, &addr, len);
	if (ret) {
		acm_log(0, "ERROR - unable to connect socket\n");
		ret = socket_errno();
		goto out;
	}

	ret = getsockname(s, &addr, &len);
	if (ret) {
		acm_log(0, "ERROR - failed to get socket address\n");
		ret = socket_errno();
		goto out;
	}

	src->type = dst->type;
	src->flags = ACM_EP_FLAG_SOURCE;
	if (dst->type == ACM_EP_INFO_ADDRESS_IP) {
		memcpy(&src->info.addr, &((struct sockaddr_in *) &addr)->sin_addr, 4);
	} else {
		memcpy(&src->info.addr, &((struct sockaddr_in6 *) &addr)->sin6_addr, 16);
	}
out:
	close(s);
	return ret;
}

/*
 * Verify the resolve message from the client and return
 * references to the source and destination addresses.
 * The message buffer contains extra address data buffers.  If a
 * source address is not given, reference an empty address buffer,
 * and we'll resolve a source address later.
 */
static uint8_t
acm_svr_verify_resolve(struct acm_resolve_msg *msg,
	struct acm_ep_addr_data **saddr, struct acm_ep_addr_data **daddr)
{
	struct acm_ep_addr_data *src = NULL, *dst = NULL;
	int i, cnt;

	if (msg->hdr.length < ACM_MSG_HDR_LENGTH) {
		acm_log(0, "ERROR - invalid msg hdr length %d\n", msg->hdr.length);
		return ACM_STATUS_EINVAL;
	}

	cnt = (msg->hdr.length - ACM_MSG_HDR_LENGTH) / ACM_MSG_EP_LENGTH;
	for (i = 0; i < cnt; i++) {
		switch (msg->data[i].flags) {
		case ACM_EP_FLAG_SOURCE:
			if (src) {
				acm_log(0, "ERROR - multiple sources specified\n");
				return ACM_STATUS_ESRCADDR;
			}
			if (!msg->data[i].type || (msg->data[i].type >= ACM_ADDRESS_RESERVED)) {
				acm_log(0, "ERROR - unsupported source address type\n");
				return ACM_STATUS_ESRCTYPE;
			}
			src = &msg->data[i];
			break;
		case ACM_EP_FLAG_DEST:
			if (dst) {
				acm_log(0, "ERROR - multiple destinations specified\n");
				return ACM_STATUS_EDESTADDR;
			}
			if (!msg->data[i].type || (msg->data[i].type >= ACM_ADDRESS_RESERVED)) {
				acm_log(0, "ERROR - unsupported destination address type\n");
				return ACM_STATUS_EDESTTYPE;
			}
			dst = &msg->data[i];
			break;
		default:
			acm_log(0, "ERROR - unexpected endpoint flags 0x%x\n",
				msg->data[i].flags);
			return ACM_STATUS_EINVAL;
		}
	}

	if (!dst) {
		acm_log(0, "ERROR - destination address required\n");
		return ACM_STATUS_EDESTTYPE;
	}

	if (!src) {
		msg->hdr.src_out = i;
		src = &msg->data[i];
		memset(src, 0, sizeof *src);
	}
	*saddr = src;
	*daddr = dst;
	return ACM_STATUS_SUCCESS;
}

/* Caller must hold dest lock */
static uint8_t
acm_svr_queue_req(struct acm_dest *dest, struct acm_client *client,
	struct acm_resolve_msg *msg)
{
	struct acm_request *req;

	acm_log(2, "\n");
	req = acm_alloc_req(client, msg);
	if (!req) {
		return ACM_STATUS_ENOMEM;
	}

	DListInsertTail(&req->entry, &dest->req_queue);
	return ACM_STATUS_SUCCESS;
}

static int
acm_svr_resolve(struct acm_client *client, struct acm_resolve_msg *msg)
{
	struct acm_ep *ep;
	struct acm_dest *dest;
	struct acm_ep_addr_data *saddr, *daddr;
	uint8_t status;
	int ret;

	status = acm_svr_verify_resolve(msg, &saddr, &daddr);
	if (status) {
		acm_log(0, "misformatted or unsupported request\n");
		return acm_client_resolve_resp(client, msg, NULL, status);
	}

	status = acm_svr_select_src(saddr, daddr);
	if (status) {
		acm_log(0, "unable to select suitable source address\n");
		return acm_client_resolve_resp(client, msg, NULL, status);
	}

	acm_log_addr(2, "acm_svr_resolve: source ", saddr->type, saddr->info.addr);
	ep = acm_get_ep(saddr);
	if (!ep) {
		acm_log(0, "unknown local end point\n");
		return acm_client_resolve_resp(client, msg, NULL, ACM_STATUS_ESRCADDR);
	}

	acm_log_addr(2, "acm_svr_resolve: dest ", daddr->type, daddr->info.addr);

	dest = acm_acquire_dest(ep, daddr->type, daddr->info.addr);
	if (!dest) {
		acm_log(0, "ERROR - unable to allocate destination in client request\n");
		return acm_client_resolve_resp(client, msg, NULL, ACM_STATUS_ENOMEM);
	}

	lock_acquire(&dest->lock);
	switch (dest->state) {
	case ACM_READY:
		acm_log(2, "request satisfied from local cache\n");
		status = ACM_STATUS_SUCCESS;
		break;
	case ACM_ADDR_RESOLVED:
		acm_log(2, "have address, resolving route\n");
		status = acm_resolve_path(ep, dest, acm_dest_sa_resp);
		if (status) {
			break;
		}
		ret = 0;
		lock_release(&dest->lock);
		goto put;
	case ACM_INIT:
		acm_log(2, "sending resolve msg to dest\n");
		status = acm_send_resolve(ep, dest, saddr);
		if (status) {
			break;
		}
		dest->state = ACM_QUERY_ADDR;
		/* fall through */
	default:
		status = acm_svr_queue_req(dest, client, msg);
		if (status) {
			break;
		}
		ret = 0;
		lock_release(&dest->lock);
		goto put;
	}
	lock_release(&dest->lock);
	ret = acm_client_resolve_resp(client, msg, dest, status);
put:
	acm_put_dest(dest);
	return ret;
}

static void acm_svr_receive(struct acm_client *client)
{
	struct acm_msg msg;
	struct acm_resolve_msg *resolve_msg = (struct acm_resolve_msg *) &msg;
	int ret;

	acm_log(2, "\n");
	ret = recv(client->sock, (char *) &msg, sizeof msg, 0);
	if (ret <= 0 || ret != msg.hdr.length) {
		acm_log(2, "client disconnected\n");
		ret = ACM_STATUS_ENOTCONN;
		goto out;
	}

	if (msg.hdr.version != ACM_VERSION) {
		acm_log(0, "ERROR - unsupported version %d\n", msg.hdr.version);
		goto out;
	}

	if ((msg.hdr.opcode & ACM_OP_MASK) != ACM_OP_RESOLVE) {
		acm_log(0, "ERROR - unknown opcode 0x%x\n", msg.hdr.opcode);
		goto out;
	}

	if (resolve_msg->data[0].type == ACM_EP_INFO_PATH) {
		ret = acm_svr_query(client, resolve_msg);
	} else {
		ret = acm_svr_resolve(client, resolve_msg);
	}

out:
	if (ret)
		acm_disconnect_client(client);
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

static enum acm_addr_prot acm_convert_addr_prot(char *param)
{
	if (!stricmp("acm", param))
		return ACM_ADDR_PROT_ACM;

	return addr_prot;
}

static enum acm_route_prot acm_convert_route_prot(char *param)
{
	if (!stricmp("acm", param))
		return ACM_ROUTE_PROT_ACM;
	else if (!stricmp("sa", param))
		return ACM_ROUTE_PROT_SA;

	return route_prot;
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
	int ret, sq_size;

	acm_log(1, "\n");
	ep->port = port;
	ep->pkey_index = pkey_index;
	ep->resolve_queue.credits = resolve_depth;
	ep->sa_queue.credits = sa_depth;
	ep->resp_queue.credits = send_depth;
	DListInit(&ep->resolve_queue.pending);
	DListInit(&ep->sa_queue.pending);
	DListInit(&ep->resp_queue.pending);
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

	sq_size = resolve_depth + sa_depth + send_depth;
	ep->cq = ibv_create_cq(port->dev->verbs, sq_size + recv_depth,
		ep, port->dev->channel, 0);
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
	init_attr.cap.max_send_wr = sq_size;
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

	port->sa_dest.ah = ibv_create_ah(port->dev->pd, &port->sa_dest.av);
	if (!port->sa_dest.ah)
		goto err1;

	for (i = 0; i < port->pkey_cnt; i++) {
		ep = calloc(1, sizeof *ep);
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
		goto err2;

	port->mad_portid = umad_open_port(port->dev->verbs->device->name, port->port_num);
	if (port->mad_portid < 0) {
		acm_log(0, "ERROR - unable to open MAD port\n");
		goto err3;
	}

	port->mad_agentid = umad_register(port->mad_portid,
		IB_MGMT_CLASS_SA, 1, 1, NULL);
	if (port->mad_agentid < 0) {
		acm_log(0, "ERROR - unable to register MAD client\n");
		goto err4;
	}

	return;

err4:
	umad_close_port(port->mad_portid);
err3:
	/* TODO: cleanup ep list */
err2:
	ibv_destroy_ah(port->sa_dest.ah);
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
	lock_init(&port->lock);
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

	acm_init_dest(&port->sa_dest, ACM_ADDRESS_LID,
		(uint8_t *) &attr.sm_lid, sizeof(attr.sm_lid));
	port->sa_dest.av.src_path_bits = attr.lid & attr.lmc;
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
	dev = (struct acm_device *) calloc(1, size);
	if (!dev)
		goto err1;

	dev->verbs = verbs;
	dev->guid = ibv_get_device_guid(ibdev);
	dev->port_cnt = attr.phys_port_cnt;

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
		else if (!stricmp("addr_prot", opt))
			addr_prot = acm_convert_addr_prot(value);
		else if (!stricmp("route_prot", opt))
			route_prot = acm_convert_route_prot(value);
		else if (!stricmp("server_port", opt))
			server_port = (short) atoi(value);
		else if (!stricmp("timeout", opt))
			timeout = atoi(value);
		else if (!stricmp("retries", opt))
			retries = atoi(value);
		else if (!stricmp("resolve_depth", opt))
			resolve_depth = atoi(value);
		else if (!stricmp("sa_depth", opt))
			sa_depth = atoi(value);
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
	acm_log(0, "address resolution %d\n", addr_prot);
	acm_log(0, "route resolution %d\n", route_prot);
	acm_log(0, "server_port %d\n", server_port);
	acm_log(0, "timeout %d ms\n", timeout);
	acm_log(0, "retries %d\n", retries);
	acm_log(0, "resolve depth %d\n", resolve_depth);
	acm_log(0, "sa depth %d\n", sa_depth);
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
	sprintf(&log_file[n], "%05u.log", getpid());
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
