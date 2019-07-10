/*
 * Copyright (c) 2009-2014 Intel Corporation. All rights reserved.
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

#include <endian.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <osd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <dirent.h>
#include <infiniband/acm.h>
#include <infiniband/acm_prov.h>
#include <infiniband/umad.h>
#include <infiniband/verbs.h>
#include <infiniband/umad_sa.h>
#include <infiniband/umad_sa_mcm.h>
#include <ifaddrs.h>
#include <dlfcn.h>
#include <search.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <inttypes.h>
#include <ccan/list.h>
#include "acm_util.h"
#include "acm_mad.h"

#define IB_LID_MCAST_START 0xc000

#define MAX_EP_ADDR 4
#define MAX_EP_MC   2

enum acmp_state {
	ACMP_INIT,
	ACMP_QUERY_ADDR,
	ACMP_ADDR_RESOLVED,
	ACMP_QUERY_ROUTE,
	ACMP_READY
};

enum acmp_addr_prot {
	ACMP_ADDR_PROT_ACM
};

enum acmp_route_prot {
	ACMP_ROUTE_PROT_ACM,
	ACMP_ROUTE_PROT_SA
};

enum acmp_loopback_prot {
	ACMP_LOOPBACK_PROT_NONE,
	ACMP_LOOPBACK_PROT_LOCAL
};

enum acmp_route_preload {
	ACMP_ROUTE_PRELOAD_NONE,
	ACMP_ROUTE_PRELOAD_OSM_FULL_V1
};

enum acmp_addr_preload {
	ACMP_ADDR_PRELOAD_NONE,
	ACMP_ADDR_PRELOAD_HOSTS
};

/*
 * Nested locking order: dest -> ep, dest -> port
 */
struct acmp_ep;

struct acmp_dest {
	uint8_t                address[ACM_MAX_ADDRESS]; /* keep first */
	char                   name[ACM_MAX_ADDRESS];
	struct ibv_ah          *ah;
	struct ibv_ah_attr     av;
	struct ibv_path_record path;
	union ibv_gid          mgid;
	__be64                 req_id;
	struct list_head       req_queue;
	uint32_t               remote_qpn;
	pthread_mutex_t        lock;
	enum acmp_state        state;
	atomic_t               refcnt;
	uint64_t	       addr_timeout;
	uint64_t	       route_timeout;
	uint8_t                addr_type;
	struct acmp_ep         *ep;
};

struct acmp_device;

struct acmp_port {
	struct acmp_device  *dev;
	const struct acm_port *port;
	struct list_head    ep_list;
	pthread_mutex_t     lock;
	struct acmp_dest    sa_dest;
	enum ibv_port_state state;
	enum ibv_mtu        mtu;
	enum ibv_rate       rate;
	int                 subnet_timeout;
	uint16_t            default_pkey_ix;
	uint16_t            lid;
	uint16_t            lid_mask;
	uint8_t             port_num;
};

struct acmp_device {
	struct ibv_context      *verbs;
	const struct acm_device *device;
	struct ibv_comp_channel *channel;
	struct ibv_pd           *pd;
	__be64                  guid;
	struct list_node        entry;
	pthread_t               comp_thread_id;
	int                     port_cnt;
	struct acmp_port        port[0];
};

/* Maintain separate virtual send queues to avoid deadlock */
struct acmp_send_queue {
	int                   credits;
	struct list_head      pending;
};

struct acmp_addr {
	uint16_t              type;
	union acm_ep_info     info;
	struct acm_address    *addr;
	struct acmp_ep        *ep;
};

struct acmp_ep {
	struct acmp_port      *port;
	struct ibv_cq         *cq;
	struct ibv_qp         *qp;
	struct ibv_mr         *mr;
	uint8_t               *recv_bufs;
	struct list_node      entry;
	char		      id_string[IBV_SYSFS_NAME_MAX + 11];
	void                  *dest_map[ACM_ADDRESS_RESERVED - 1];
	struct acmp_dest      mc_dest[MAX_EP_MC];
	int                   mc_cnt;
	uint16_t              pkey_index;
	uint16_t	      pkey;
	const struct acm_endpoint *endpoint;
	pthread_mutex_t       lock;
	struct acmp_send_queue resolve_queue;
	struct acmp_send_queue resp_queue;
	struct list_head      active_queue;
	struct list_head      wait_queue;
	enum acmp_state       state;
	struct acmp_addr      addr_info[MAX_EP_ADDR];
	atomic_t              counters[ACM_MAX_COUNTER];
};

struct acmp_send_msg {
	struct list_node     entry;
	struct acmp_ep       *ep;
	struct acmp_dest     *dest;
	struct ibv_ah        *ah;
	void                 *context;
	void                 (*resp_handler)(struct acmp_send_msg *req,
	                                     struct ibv_wc *wc, struct acm_mad *resp);
	struct acmp_send_queue *req_queue;
	struct ibv_mr        *mr;
	struct ibv_send_wr   wr;
	struct ibv_sge       sge;
	uint64_t             expires;
	int                  tries;
	uint8_t              data[ACM_SEND_SIZE];
};

struct acmp_request {
	uint64_t	id;
	struct list_node entry;
	struct acm_msg	msg;
	struct acmp_ep	*ep;
};

static int acmp_open_dev(const struct acm_device *device, void **dev_context);
static void acmp_close_dev(void *dev_context);
static int acmp_open_port(const struct acm_port *port, void *dev_context,
			  void **port_context);
static void acmp_close_port(void *port_context);
static int acmp_open_endpoint(const struct acm_endpoint *endpoint,
			      void *port_context, void **ep_context);
static void acmp_close_endpoint(void *ep_context);
static int acmp_add_addr(const struct acm_address *addr, void *ep_context,
			 void **addr_context);
static void acmp_remove_addr(void *addr_context);
static int acmp_resolve(void *addr_context, struct acm_msg *msg, uint64_t id);
static int acmp_query(void *addr_context, struct acm_msg *msg, uint64_t id);
static int acmp_handle_event(void *port_context, enum ibv_event_type type);
static void acmp_query_perf(void *ep_context, uint64_t *values, uint8_t *cnt);

static struct acm_provider def_prov = {
	.size = sizeof(struct acm_provider),
	.version = ACM_PROV_VERSION,
	.name = "ibacmp",
	.open_device = acmp_open_dev,
	.close_device = acmp_close_dev,
	.open_port = acmp_open_port,
	.close_port = acmp_close_port,
	.open_endpoint = acmp_open_endpoint,
	.close_endpoint = acmp_close_endpoint,
	.add_address = acmp_add_addr,
	.remove_address = acmp_remove_addr,
	.resolve = acmp_resolve,
	.query = acmp_query,
	.handle_event = acmp_handle_event,
	.query_perf = acmp_query_perf,
};

static LIST_HEAD(acmp_dev_list);
static pthread_mutex_t acmp_dev_lock;

static atomic_t g_tid;
static LIST_HEAD(timeout_list);
static event_t timeout_event;
static atomic_t wait_cnt;
static pthread_t retry_thread_id;
static int retry_thread_started = 0;

static __thread char log_data[ACM_MAX_ADDRESS];

/*
 * Service options - may be set through ibacm_opts.cfg file.
 */
static char route_data_file[128] = ACM_CONF_DIR "/ibacm_route.data";
static char addr_data_file[128] = ACM_CONF_DIR "/ibacm_hosts.data";
static enum acmp_addr_prot addr_prot = ACMP_ADDR_PROT_ACM;
static int addr_timeout = 1440;
static enum acmp_route_prot route_prot = ACMP_ROUTE_PROT_SA;
static int route_timeout = -1;
static enum acmp_loopback_prot loopback_prot = ACMP_LOOPBACK_PROT_LOCAL;
static int timeout = 2000;
static int retries = 2;
static int resolve_depth = 1;
static int send_depth = 1;
static int recv_depth = 1024;
static uint8_t min_mtu = IBV_MTU_2048;
static uint8_t min_rate = IBV_RATE_10_GBPS;
static enum acmp_route_preload route_preload;
static enum acmp_addr_preload addr_preload;

static int acmp_initialized = 0;

static int acmp_compare_dest(const void *dest1, const void *dest2)
{
	return memcmp(dest1, dest2, ACM_MAX_ADDRESS);
}

static void
acmp_set_dest_addr(struct acmp_dest *dest, uint8_t addr_type,
		   const uint8_t *addr, size_t size)
{
	memcpy(dest->address, addr, size);
	dest->addr_type = addr_type;
	acm_format_name(0, dest->name, sizeof dest->name, addr_type, addr, size);
}

static void
acmp_init_dest(struct acmp_dest *dest, uint8_t addr_type,
	       const uint8_t *addr, size_t size)
{
	list_head_init(&dest->req_queue);
	atomic_init(&dest->refcnt);
	atomic_set(&dest->refcnt, 1);
	pthread_mutex_init(&dest->lock, NULL);
	if (size)
		acmp_set_dest_addr(dest, addr_type, addr, size);
	dest->state = ACMP_INIT;
}

static struct acmp_dest *
acmp_alloc_dest(uint8_t addr_type, const uint8_t *addr)
{
	struct acmp_dest *dest;

	dest = calloc(1, sizeof *dest);
	if (!dest) {
		acm_log(0, "ERROR - unable to allocate dest\n");
		return NULL;
	}

	acmp_init_dest(dest, addr_type, addr, ACM_MAX_ADDRESS);
	acm_log(1, "%s\n", dest->name);
	return dest;
}

/* Caller must hold ep lock. */
static struct acmp_dest *
acmp_get_dest(struct acmp_ep *ep, uint8_t addr_type, const uint8_t *addr)
{
	struct acmp_dest *dest, **tdest;

	tdest = tfind(addr, &ep->dest_map[addr_type - 1], acmp_compare_dest);
	if (tdest) {
		dest = *tdest;
		(void) atomic_inc(&dest->refcnt);
		acm_log(2, "%s\n", dest->name);
	} else {
		dest = NULL;
		acm_format_name(2, log_data, sizeof log_data,
				addr_type, addr, ACM_MAX_ADDRESS);
		acm_log(2, "%s not found\n", log_data);
	}
	return dest;
}

static void
acmp_put_dest(struct acmp_dest *dest)
{
	acm_log(2, "%s\n", dest->name);
	if (atomic_dec(&dest->refcnt) == 0) {
		free(dest);
	}
}

/* Caller must hold ep lock. */
static void
acmp_remove_dest(struct acmp_ep *ep, struct acmp_dest *dest)
{
	acm_log(2, "%s\n", dest->name);
	if (!tdelete(dest->address, &ep->dest_map[dest->addr_type - 1],
		     acmp_compare_dest))
		acm_log(0, "ERROR: %s not found!!\n", dest->name);

	acmp_put_dest(dest);
}

static struct acmp_dest *
acmp_acquire_dest(struct acmp_ep *ep, uint8_t addr_type, const uint8_t *addr)
{
	struct acmp_dest *dest;
	int64_t rec_expr_minutes;

	acm_format_name(2, log_data, sizeof log_data,
			addr_type, addr, ACM_MAX_ADDRESS);
	acm_log(2, "%s\n", log_data);
	pthread_mutex_lock(&ep->lock);
	dest = acmp_get_dest(ep, addr_type, addr);
	if (dest && dest->state == ACMP_READY &&
	    dest->addr_timeout != (uint64_t)~0ULL) {
		rec_expr_minutes = dest->addr_timeout - time_stamp_min();
		if (rec_expr_minutes <= 0) {
			acm_log(2, "Record expired\n");
			acmp_remove_dest(ep, dest);
			dest = NULL;
		} else {
			acm_log(2, "Record valid for the next %" PRId64 " minute(s)\n",
				rec_expr_minutes);
		}
	}
	if (!dest) {
		dest = acmp_alloc_dest(addr_type, addr);
		if (dest) {
			dest->ep = ep;
			tsearch(dest, &ep->dest_map[addr_type - 1], acmp_compare_dest);
			(void) atomic_inc(&dest->refcnt);
		}
	}
	pthread_mutex_unlock(&ep->lock);
	return dest;
}

static struct acmp_request *acmp_alloc_req(uint64_t id, struct acm_msg *msg)
{
	struct acmp_request *req;

	req = calloc(1, sizeof *req);
	if (!req) {
		acm_log(0, "ERROR - unable to alloc client request\n");
		return NULL;
	}

	req->id = id;
	memcpy(&req->msg, msg, sizeof(req->msg));
	acm_log(2, "id %" PRIu64 ", req %p\n", id, req);
	return req;
}

static void acmp_free_req(struct acmp_request *req)
{
	acm_log(2, "%p\n", req);
	free(req);
}

static struct acmp_send_msg *
acmp_alloc_send(struct acmp_ep *ep, struct acmp_dest *dest, size_t size)
{
	struct acmp_send_msg *msg;

	msg = (struct acmp_send_msg *) calloc(1, sizeof *msg);
	if (!msg) {
		acm_log(0, "ERROR - unable to allocate send buffer\n");
		return NULL;
	}

	msg->ep = ep;
	msg->mr = ibv_reg_mr(ep->port->dev->pd, msg->data, size, 0);
	if (!msg->mr) {
		acm_log(0, "ERROR - failed to register send buffer\n");
		goto err1;
	}

	if (!dest->ah) {
		msg->ah = ibv_create_ah(ep->port->dev->pd, &dest->av);
		if (!msg->ah) {
			acm_log(0, "ERROR - unable to create ah\n");
			goto err2;
		}
		msg->wr.wr.ud.ah = msg->ah;
	} else {
		msg->wr.wr.ud.ah = dest->ah;
	}

	acm_log(2, "get dest %s\n", dest->name);
	(void) atomic_inc(&dest->refcnt);
	msg->dest = dest;

	msg->wr.next = NULL;
	msg->wr.sg_list = &msg->sge;
	msg->wr.num_sge = 1;
	msg->wr.opcode = IBV_WR_SEND;
	msg->wr.send_flags = IBV_SEND_SIGNALED;
	msg->wr.wr_id = (uintptr_t) msg;
	msg->wr.wr.ud.remote_qpn = dest->remote_qpn;
	msg->wr.wr.ud.remote_qkey = ACM_QKEY;

	msg->sge.length = size;
	msg->sge.lkey = msg->mr->lkey;
	msg->sge.addr = (uintptr_t) msg->data;
	acm_log(2, "%p\n", msg);
	return msg;

err2:
	ibv_dereg_mr(msg->mr);
err1:
	free(msg);
	return NULL;
}

static void
acmp_init_send_req(struct acmp_send_msg *msg, void *context,
	void (*resp_handler)(struct acmp_send_msg *req,
		struct ibv_wc *wc, struct acm_mad *resp))
{
	acm_log(2, "%p\n", msg);
	msg->tries = retries + 1;
	msg->context = context;
	msg->resp_handler = resp_handler;
}

static void acmp_free_send(struct acmp_send_msg *msg)
{
	acm_log(2, "%p\n", msg);
	if (msg->ah)
		ibv_destroy_ah(msg->ah);
	ibv_dereg_mr(msg->mr);
	acmp_put_dest(msg->dest);
	free(msg);
}

static void acmp_post_send(struct acmp_send_queue *queue, struct acmp_send_msg *msg)
{
	struct acmp_ep *ep = msg->ep;
	struct ibv_send_wr *bad_wr;

	msg->req_queue = queue;
	pthread_mutex_lock(&ep->lock);
	if (queue->credits) {
		acm_log(2, "posting send to QP\n");
		queue->credits--;
		list_add_tail(&ep->active_queue, &msg->entry);
		ibv_post_send(ep->qp, &msg->wr, &bad_wr);
	} else {
		acm_log(2, "no sends available, queuing message\n");
		list_add_tail(&queue->pending, &msg->entry);
	}
	pthread_mutex_unlock(&ep->lock);
}

static void acmp_post_recv(struct acmp_ep *ep, uint64_t address)
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
static void acmp_send_available(struct acmp_ep *ep, struct acmp_send_queue *queue)
{
	struct acmp_send_msg *msg;
	struct ibv_send_wr *bad_wr;

	msg = list_pop(&queue->pending, struct acmp_send_msg, entry);
	if (msg) {
		acm_log(2, "posting queued send message\n");
		list_add_tail(&ep->active_queue, &msg->entry);
		ibv_post_send(ep->qp, &msg->wr, &bad_wr);
	} else {
		queue->credits++;
	}
}

static void acmp_complete_send(struct acmp_send_msg *msg)
{
	struct acmp_ep *ep = msg->ep;

	pthread_mutex_lock(&ep->lock);
	list_del(&msg->entry);
	if (msg->tries) {
		acm_log(2, "waiting for response\n");
		msg->expires = time_stamp_ms() + ep->port->subnet_timeout + timeout;
		list_add_tail(&ep->wait_queue, &msg->entry);
		if (atomic_inc(&wait_cnt) == 1)
			event_signal(&timeout_event);
	} else {
		acm_log(2, "freeing\n");
		acmp_send_available(ep, msg->req_queue);
		acmp_free_send(msg);
	}
	pthread_mutex_unlock(&ep->lock);
}

static struct acmp_send_msg *acmp_get_request(struct acmp_ep *ep, __be64 tid, int *free)
{
	struct acmp_send_msg *msg, *next, *req = NULL;
	struct acm_mad *mad;

	acm_log(2, "\n");
	pthread_mutex_lock(&ep->lock);
	list_for_each_safe(&ep->wait_queue, msg, next, entry) {
		mad = (struct acm_mad *) msg->data;
		if (mad->tid == tid) {
			acm_log(2, "match found in wait queue\n");
			req = msg;
			list_del(&msg->entry);
			(void) atomic_dec(&wait_cnt);
			acmp_send_available(ep, msg->req_queue);
			*free = 1;
			goto unlock;
		}
	}

	list_for_each(&ep->active_queue, msg, entry) {
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
	pthread_mutex_unlock(&ep->lock);
	return req;
}

static int acmp_mc_index(struct acmp_ep *ep, union ibv_gid *gid)
{
	int i;

	for (i = 0; i < ep->mc_cnt; i++) {
		if (!memcmp(&ep->mc_dest[i].address, gid, sizeof(*gid)))
			return i;
	}
	return -1;
}

/* Multicast groups are ordered lowest to highest preference. */
static int acmp_best_mc_index(struct acmp_ep *ep, struct acm_resolve_rec *rec)
{
	int i, index;

	for (i = min_t(int, rec->gid_cnt, ACM_MAX_GID_COUNT) - 1; i >= 0; i--) {
		index = acmp_mc_index(ep, &rec->gid[i]);
		if (index >= 0) {
			return index;
		}
	}
	return -1;
}

static void
acmp_record_mc_av(struct acmp_port *port, struct ib_mc_member_rec *mc_rec,
	struct acmp_dest *dest)
{
	uint32_t sl_flow_hop;

	sl_flow_hop = be32toh(mc_rec->sl_flow_hop);

	dest->av.dlid = be16toh(mc_rec->mlid);
	dest->av.sl = (uint8_t) (sl_flow_hop >> 28);
	dest->av.src_path_bits = port->sa_dest.av.src_path_bits;
	dest->av.static_rate = mc_rec->rate & 0x3F;
	dest->av.port_num = port->port_num;

	dest->av.is_global = 1;
	dest->av.grh.dgid = mc_rec->mgid;
	dest->av.grh.flow_label = (sl_flow_hop >> 8) & 0xFFFFF;
	dest->av.grh.sgid_index = acm_gid_index((struct acm_port *) port->port,
						&mc_rec->port_gid);
	dest->av.grh.hop_limit = (uint8_t) sl_flow_hop;
	dest->av.grh.traffic_class = mc_rec->tclass;

	dest->path.dgid = mc_rec->mgid;
	dest->path.sgid = mc_rec->port_gid;
	dest->path.dlid = mc_rec->mlid;
	dest->path.slid = htobe16(port->lid | port->sa_dest.av.src_path_bits);
	dest->path.flowlabel_hoplimit = htobe32(sl_flow_hop & 0xFFFFFFF);
	dest->path.tclass = mc_rec->tclass;
	dest->path.reversible_numpath = IBV_PATH_RECORD_REVERSIBLE | 1;
	dest->path.pkey = mc_rec->pkey;
	dest->path.qosclass_sl = htobe16((uint16_t) (sl_flow_hop >> 28));
	dest->path.mtu = mc_rec->mtu;
	dest->path.rate = mc_rec->rate;
	dest->path.packetlifetime = mc_rec->packet_lifetime;
}

/* Always send the GRH to transfer GID data to remote side */
static void
acmp_init_path_av(struct acmp_port *port, struct acmp_dest *dest)
{
	uint32_t flow_hop;

	dest->av.dlid = be16toh(dest->path.dlid);
	dest->av.sl = be16toh(dest->path.qosclass_sl) & 0xF;
	dest->av.src_path_bits = be16toh(dest->path.slid) & 0x7F;
	dest->av.static_rate = dest->path.rate & 0x3F;
	dest->av.port_num = port->port_num;

	flow_hop = be32toh(dest->path.flowlabel_hoplimit);
	dest->av.is_global = 1;
	dest->av.grh.flow_label = (flow_hop >> 8) & 0xFFFFF;
	pthread_mutex_lock(&port->lock);
	if (port->port)
		dest->av.grh.sgid_index = acm_gid_index(
		   (struct acm_port *) port->port, &dest->path.sgid);
	else
		dest->av.grh.sgid_index = 0;
	pthread_mutex_unlock(&port->lock);
	dest->av.grh.hop_limit = (uint8_t) flow_hop;
	dest->av.grh.traffic_class = dest->path.tclass;
}

static void acmp_process_join_resp(struct acm_sa_mad *sa_mad)
{
	struct acmp_dest *dest;
	struct ib_mc_member_rec *mc_rec;
	struct ib_sa_mad *mad;
	int index, ret;
	struct acmp_ep *ep = sa_mad->context;

	mad = (struct ib_sa_mad *) &sa_mad->sa_mad;
	acm_log(1, "response status: 0x%x, mad status: 0x%x\n",
		sa_mad->umad.status, mad->status);
	pthread_mutex_lock(&ep->lock);
	if (sa_mad->umad.status) {
		acm_log(0, "ERROR - send join failed 0x%x\n", sa_mad->umad.status);
		goto out;
	}
	if (mad->status) {
		acm_log(0, "ERROR - join response status 0x%x\n", mad->status);
		goto out;
	}

	mc_rec = (struct ib_mc_member_rec *) mad->data;
	index = acmp_mc_index(ep, &mc_rec->mgid);
	if (index < 0) {
		acm_log(0, "ERROR - MGID in join response not found\n");
		goto out;
	}

	dest = &ep->mc_dest[index];
	dest->remote_qpn = IB_MC_QPN;
	dest->mgid = mc_rec->mgid;
	acmp_record_mc_av(ep->port, mc_rec, dest);

	if (index == 0) {
		dest->ah = ibv_create_ah(ep->port->dev->pd, &dest->av);
		if (!dest->ah) {
			acm_log(0, "ERROR - unable to create ah\n");
			goto out;
		}
		ret = ibv_attach_mcast(ep->qp, &dest->mgid, dest->av.dlid);
		if (ret) {
			acm_log(0, "ERROR - unable to attach QP to multicast group\n");
			ibv_destroy_ah(dest->ah);
			dest->ah = NULL;
			goto out;
		}
		ep->state = ACMP_READY;
	}

	atomic_set(&dest->refcnt, 1);
	dest->state = ACMP_READY;
	acm_log(1, "join successful\n");
out:
	acm_free_sa_mad(sa_mad);
	pthread_mutex_unlock(&ep->lock);
}

static uint8_t
acmp_record_acm_route(struct acmp_ep *ep, struct acmp_dest *dest)
{
	int i;

	acm_log(2, "\n");
	for (i = 0; i < MAX_EP_MC; i++) {
		if (!memcmp(&dest->mgid, &ep->mc_dest[i].mgid, sizeof dest->mgid))
			break;
	}
	if (i == MAX_EP_MC) {
		acm_log(0, "ERROR - cannot match mgid\n");
		return ACM_STATUS_EINVAL;
	}

	dest->path = ep->mc_dest[i].path;
	dest->path.dgid = dest->av.grh.dgid;
	dest->path.dlid = htobe16(dest->av.dlid);
	dest->addr_timeout = time_stamp_min() + (unsigned) addr_timeout;
	dest->route_timeout = time_stamp_min() + (unsigned) route_timeout;
	dest->state = ACMP_READY;
	return ACM_STATUS_SUCCESS;
}

static void acmp_init_path_query(struct ib_sa_mad *mad)
{
	acm_log(2, "\n");
	mad->base_version = 1;
	mad->mgmt_class = IB_MGMT_CLASS_SA;
	mad->class_version = 2;
	mad->method = IB_METHOD_GET;
	mad->tid = htobe64((uint64_t) atomic_inc(&g_tid));
	mad->attr_id = IB_SA_ATTR_PATH_REC;
}

/* Caller must hold dest lock */
static uint8_t acmp_resolve_path_sa(struct acmp_ep *ep, struct acmp_dest *dest,
				    void (*handler)(struct acm_sa_mad *))
{
	struct ib_sa_mad *mad;
	uint8_t ret;
	struct acm_sa_mad *sa_mad;

	acm_log(2, "%s\n", dest->name);

	sa_mad = acm_alloc_sa_mad(ep->endpoint, dest, handler);
	if (!sa_mad) {
		acm_log(0, "Error - failed to allocate sa_mad\n");
		ret = ACM_STATUS_ENOMEM;
		goto err;
	}

	mad = (struct ib_sa_mad *) &sa_mad->sa_mad;
	acmp_init_path_query(mad);

	memcpy(mad->data, &dest->path, sizeof(dest->path));
	mad->comp_mask = acm_path_comp_mask(&dest->path);

	acm_increment_counter(ACM_CNTR_ROUTE_QUERY);
	atomic_inc(&ep->counters[ACM_CNTR_ROUTE_QUERY]);
	dest->state = ACMP_QUERY_ROUTE;
	if (acm_send_sa_mad(sa_mad)) {
		acm_log(0, "Error - Failed to send sa mad\n");
		ret = ACM_STATUS_ENODATA;
		goto free_mad;
	}
	return ACM_STATUS_SUCCESS;
free_mad:
	acm_free_sa_mad(sa_mad);
err:
	dest->state = ACMP_INIT;
	return ret;
}

static uint8_t
acmp_record_acm_addr(struct acmp_ep *ep, struct acmp_dest *dest, struct ibv_wc *wc,
	struct acm_resolve_rec *rec)
{
	int index;

	acm_log(2, "%s\n", dest->name);
	index = acmp_best_mc_index(ep, rec);
	if (index < 0) {
		acm_log(0, "ERROR - no shared multicast groups\n");
		dest->state = ACMP_INIT;
		return ACM_STATUS_ENODATA;
	}

	acm_log(2, "selecting MC group at index %d\n", index);
	dest->av = ep->mc_dest[index].av;
	dest->av.dlid = wc->slid;
	dest->av.src_path_bits = wc->dlid_path_bits;
	dest->av.grh.dgid = ((struct ibv_grh *) (uintptr_t) wc->wr_id)->sgid;

	dest->mgid = ep->mc_dest[index].mgid;
	dest->path.sgid = ep->mc_dest[index].path.sgid;
	dest->path.dgid = dest->av.grh.dgid;
	dest->path.tclass = ep->mc_dest[index].path.tclass;
	dest->path.pkey = ep->mc_dest[index].path.pkey;
	dest->remote_qpn = wc->src_qp;

	dest->state = ACMP_ADDR_RESOLVED;
	return ACM_STATUS_SUCCESS;
}

static void
acmp_record_path_addr(struct acmp_ep *ep, struct acmp_dest *dest,
	struct ibv_path_record *path)
{
	acm_log(2, "%s\n", dest->name);
	dest->path.pkey = htobe16(ep->pkey);
	dest->path.dgid = path->dgid;
	if (path->slid) {
		dest->path.slid = path->slid;
	} else {
		dest->path.slid = htobe16(ep->port->lid);
	}
	if (!ib_any_gid(&path->sgid)) {
		dest->path.sgid = path->sgid;
	} else {
		dest->path.sgid = ep->mc_dest[0].path.sgid;
	}
	dest->path.dlid = path->dlid;
	dest->state = ACMP_ADDR_RESOLVED;
}

static uint8_t acmp_validate_addr_req(struct acm_mad *mad)
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
acmp_send_addr_resp(struct acmp_ep *ep, struct acmp_dest *dest)
{
	struct acm_resolve_rec *rec;
	struct acmp_send_msg *msg;
	struct acm_mad *mad;

	acm_log(2, "%s\n", dest->name);
	msg = acmp_alloc_send(ep, dest, sizeof (*mad));
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

	acmp_post_send(&ep->resp_queue, msg);
}

static int
acmp_resolve_response(uint64_t id, struct acm_msg *req_msg,
		      struct acmp_dest *dest, uint8_t status)
{
	struct acm_msg msg;

	acm_log(2, "client %" PRIu64 ", status 0x%x\n", id, status);
	memset(&msg, 0, sizeof msg);

	if (dest) {
		if (status == ACM_STATUS_ENODATA)
			atomic_inc(&dest->ep->counters[ACM_CNTR_NODATA]);
		else if (status)
			atomic_inc(&dest->ep->counters[ACM_CNTR_ERROR]);
	}
	msg.hdr = req_msg->hdr;
	msg.hdr.status = status;
	msg.hdr.length = ACM_MSG_HDR_LENGTH;
	memset(msg.hdr.data, 0, sizeof(msg.hdr.data));

	if (status == ACM_STATUS_SUCCESS) {
		msg.hdr.length += ACM_MSG_EP_LENGTH;
		msg.resolve_data[0].flags = IBV_PATH_FLAG_GMP |
			IBV_PATH_FLAG_PRIMARY | IBV_PATH_FLAG_BIDIRECTIONAL;
		msg.resolve_data[0].type = ACM_EP_INFO_PATH;
		msg.resolve_data[0].info.path = dest->path;

		if (req_msg->hdr.src_out) {
			msg.hdr.length += ACM_MSG_EP_LENGTH;
			memcpy(&msg.resolve_data[1],
				&req_msg->resolve_data[req_msg->hdr.src_index],
				ACM_MSG_EP_LENGTH);
		}
	}

	return acm_resolve_response(id, &msg);
}

static void
acmp_complete_queued_req(struct acmp_dest *dest, uint8_t status)
{
	struct acmp_request *req;

	acm_log(2, "status %d\n", status);
	pthread_mutex_lock(&dest->lock);
	while ((req = list_pop(&dest->req_queue, struct acmp_request, entry))) {
		pthread_mutex_unlock(&dest->lock);

		acm_log(2, "completing request, client %" PRIu64 "\n", req->id);
		acmp_resolve_response(req->id, &req->msg, dest, status);
		acmp_free_req(req);

		pthread_mutex_lock(&dest->lock);
	}
	pthread_mutex_unlock(&dest->lock);
}

static void
acmp_dest_sa_resp(struct acm_sa_mad *mad)
{
	struct acmp_dest *dest = (struct acmp_dest *) mad->context;
	struct ib_sa_mad *sa_mad = (struct ib_sa_mad *) &mad->sa_mad;
	uint8_t status;

	if (!mad->umad.status) {
		status = (uint8_t) (be16toh(sa_mad->status) >> 8);
	} else {
		status = ACM_STATUS_ETIMEDOUT;
	}
	acm_log(2, "%s status=0x%x\n", dest->name, status);

	pthread_mutex_lock(&dest->lock);
	if (dest->state != ACMP_QUERY_ROUTE) {
		acm_log(1, "notice - discarding SA response\n");
		pthread_mutex_unlock(&dest->lock);
		goto out;
	}

	if (!status) {
		memcpy(&dest->path, sa_mad->data, sizeof(dest->path));
		acmp_init_path_av(dest->ep->port, dest);
		dest->addr_timeout = time_stamp_min() + (unsigned) addr_timeout;
		dest->route_timeout = time_stamp_min() + (unsigned) route_timeout;
		acm_log(2, "timeout addr %" PRIu64 " route %" PRIu64 "\n",
			dest->addr_timeout, dest->route_timeout);
		dest->state = ACMP_READY;
	} else {
		dest->state = ACMP_INIT;
	}
	pthread_mutex_unlock(&dest->lock);

	acmp_complete_queued_req(dest, status);
out:
	acm_free_sa_mad(mad);
}

static void
acmp_resolve_sa_resp(struct acm_sa_mad *mad)
{
	struct acmp_dest *dest = (struct acmp_dest *) mad->context;
	int send_resp;

	acm_log(2, "\n");
	acmp_dest_sa_resp(mad);

	pthread_mutex_lock(&dest->lock);
	send_resp = (dest->state == ACMP_READY);
	pthread_mutex_unlock(&dest->lock);

	if (send_resp)
		acmp_send_addr_resp(dest->ep, dest);
}

static struct acmp_addr *
acmp_addr_lookup(struct acmp_ep *ep, uint8_t *addr, uint16_t type)
{
	int i;

	for (i = 0; i < MAX_EP_ADDR; i++) {
		if (ep->addr_info[i].type != type)
			continue;

		if ((type == ACM_ADDRESS_NAME &&
		    !strncasecmp((char *) ep->addr_info[i].info.name,
			      (char *) addr, ACM_MAX_ADDRESS)) ||
		    !memcmp(ep->addr_info[i].info.addr, addr,
			    ACM_MAX_ADDRESS)) {
			return &ep->addr_info[i];
		}
	}

	return NULL;
}

static void
acmp_process_addr_req(struct acmp_ep *ep, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_resolve_rec *rec;
	struct acmp_dest *dest;
	uint8_t status;
	struct acmp_addr *addr;

	acm_log(2, "\n");
	if ((status = acmp_validate_addr_req(mad))) {
		acm_log(0, "ERROR - invalid request\n");
		return;
	}

	rec = (struct acm_resolve_rec *) mad->data;
	dest = acmp_acquire_dest(ep, rec->src_type, rec->src);
	if (!dest) {
		acm_log(0, "ERROR - unable to add source\n");
		return;
	}

	addr = acmp_addr_lookup(ep, rec->dest, rec->dest_type);
	if (addr)
		dest->req_id = mad->tid;

	pthread_mutex_lock(&dest->lock);
	acm_log(2, "dest state %d\n", dest->state);
	switch (dest->state) {
	case ACMP_READY:
		if (dest->remote_qpn == wc->src_qp)
			break;

		acm_log(2, "src service has new qp, resetting\n");
		/* fall through */
	case ACMP_INIT:
	case ACMP_QUERY_ADDR:
		status = acmp_record_acm_addr(ep, dest, wc, rec);
		if (status)
			break;
		/* fall through */
	case ACMP_ADDR_RESOLVED:
		if (route_prot == ACMP_ROUTE_PROT_ACM) {
			status = acmp_record_acm_route(ep, dest);
			break;
		}
		if (addr || !list_empty(&dest->req_queue)) {
			status = acmp_resolve_path_sa(ep, dest, acmp_resolve_sa_resp);
			if (status)
				break;
		}
		/* fall through */
	default:
		pthread_mutex_unlock(&dest->lock);
		acmp_put_dest(dest);
		return;
	}
	pthread_mutex_unlock(&dest->lock);
	acmp_complete_queued_req(dest, status);

	if (addr && !status) {
		acmp_send_addr_resp(ep, dest);
	}
	acmp_put_dest(dest);
}

static void
acmp_process_addr_resp(struct acmp_send_msg *msg, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acm_resolve_rec *resp_rec;
	struct acmp_dest *dest = (struct acmp_dest *) msg->context;
	uint8_t status;

	if (mad) {
		status = acm_class_status(mad->status);
		resp_rec = (struct acm_resolve_rec *) mad->data;
	} else {
		status = ACM_STATUS_ETIMEDOUT;
		resp_rec = NULL;
	}
	acm_log(2, "resp status 0x%x\n", status);

	pthread_mutex_lock(&dest->lock);
	if (dest->state != ACMP_QUERY_ADDR) {
		pthread_mutex_unlock(&dest->lock);
		goto put;
	}

	if (!status) {
		status = acmp_record_acm_addr(msg->ep, dest, wc, resp_rec);
		if (!status) {
			if (route_prot == ACMP_ROUTE_PROT_ACM) {
				status = acmp_record_acm_route(msg->ep, dest);
			} else {
				status = acmp_resolve_path_sa(msg->ep, dest, acmp_dest_sa_resp);
				if (!status) {
					pthread_mutex_unlock(&dest->lock);
					goto put;
				}
			}
		}
	} else {
		dest->state = ACMP_INIT;
	}
	pthread_mutex_unlock(&dest->lock);

	acmp_complete_queued_req(dest, status);
put:
	acmp_put_dest(dest);
}

static void acmp_process_acm_recv(struct acmp_ep *ep, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct acmp_send_msg *req;
	struct acm_resolve_rec *rec;
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

	rec = (struct acm_resolve_rec *) mad->data;
	acm_format_name(2, log_data, sizeof log_data,
			rec->src_type, rec->src, sizeof rec->src);
	acm_log(2, "src  %s\n", log_data);
	acm_format_name(2, log_data, sizeof log_data,
			rec->dest_type, rec->dest, sizeof rec->dest);
	acm_log(2, "dest %s\n", log_data);
	if (mad->method & IB_METHOD_RESP) {
		acm_log(2, "received response\n");
		req = acmp_get_request(ep, mad->tid, &free);
		if (!req) {
			acm_log(1, "notice - response did not match active request\n");
			return;
		}
		acm_log(2, "found matching request\n");
		req->resp_handler(req, wc, mad);
		if (free)
			acmp_free_send(req);
	} else {
		acm_log(2, "unsolicited request\n");
		acmp_process_addr_req(ep, wc, mad);
	}
}

static void
acmp_sa_resp(struct acm_sa_mad *mad)
{
	struct acmp_request *req = (struct acmp_request *) mad->context;
	struct ib_sa_mad *sa_mad = (struct ib_sa_mad *) &mad->sa_mad;

	req->msg.hdr.opcode |= ACM_OP_ACK;
	if (!mad->umad.status) {
		req->msg.hdr.status = (uint8_t) (be16toh(sa_mad->status) >> 8);
		memcpy(&req->msg.resolve_data[0].info.path, sa_mad->data,
		       sizeof(struct ibv_path_record));
	} else {
		req->msg.hdr.status = ACM_STATUS_ETIMEDOUT;
	}
	acm_log(2, "status 0x%x\n", req->msg.hdr.status);

	if (req->msg.hdr.status)
		atomic_inc(&req->ep->counters[ACM_CNTR_ERROR]);
	acm_query_response(req->id, &req->msg);
	acm_free_sa_mad(mad);
	acmp_free_req(req);
}

static void acmp_process_sa_recv(struct acmp_ep *ep, struct ibv_wc *wc, struct acm_mad *mad)
{
	struct ib_sa_mad *sa_mad = (struct ib_sa_mad *) mad;
	struct acmp_send_msg *req;
	int free;

	acm_log(2, "\n");
	if (mad->base_version != 1 || mad->class_version != 2 ||
	    !(mad->method & IB_METHOD_RESP) || sa_mad->attr_id != IB_SA_ATTR_PATH_REC) {
		acm_log(0, "ERROR - unexpected SA MAD %d %d\n",
			mad->base_version, mad->class_version);
		return;
	}

	req = acmp_get_request(ep, mad->tid, &free);
	if (!req) {
		acm_log(1, "notice - response did not match active request\n");
		return;
	}
	acm_log(2, "found matching request\n");
	req->resp_handler(req, wc, mad);
	if (free)
		acmp_free_send(req);
}

static void acmp_process_recv(struct acmp_ep *ep, struct ibv_wc *wc)
{
	struct acm_mad *mad;

	acm_log(2, "base endpoint name %s\n", ep->id_string);
	mad = (struct acm_mad *) (uintptr_t) (wc->wr_id + sizeof(struct ibv_grh));
	switch (mad->mgmt_class) {
	case IB_MGMT_CLASS_SA:
		acmp_process_sa_recv(ep, wc, mad);
		break;
	case ACM_MGMT_CLASS:
		acmp_process_acm_recv(ep, wc, mad);
		break;
	default:
		acm_log(0, "ERROR - invalid mgmt class 0x%x\n", mad->mgmt_class);
		break;
	}

	acmp_post_recv(ep, wc->wr_id);
}

static void acmp_process_comp(struct acmp_ep *ep, struct ibv_wc *wc)
{
	if (wc->status) {
		acm_log(0, "ERROR - work completion error\n"
			"\topcode %d, completion status %d\n",
			wc->opcode, wc->status);
		return;
	}

	if (wc->opcode & IBV_WC_RECV)
		acmp_process_recv(ep, wc);
	else
		acmp_complete_send((struct acmp_send_msg *) (uintptr_t) wc->wr_id);
}

static void *acmp_comp_handler(void *context)
{
	struct acmp_device *dev = (struct acmp_device *) context;
	struct acmp_ep *ep;
	struct ibv_cq *cq;
	struct ibv_wc wc;
	int cnt;

	acm_log(1, "started\n");

	if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL)) {
		acm_log(0, "Error: failed to set cancel type for dev %s\n",
			dev->verbs->device->name);
		pthread_exit(NULL);
	}

	if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) {
		acm_log(0, "Error: failed to set cancel state for dev %s\n",
			dev->verbs->device->name);
		pthread_exit(NULL);
	}
	while (1) {
		pthread_testcancel();
		ibv_get_cq_event(dev->channel, &cq, (void *) &ep);

		cnt = 0;
		while (ibv_poll_cq(cq, 1, &wc) > 0) {
			cnt++;
			acmp_process_comp(ep, &wc);
		}

		ibv_req_notify_cq(cq, 0);
		while (ibv_poll_cq(cq, 1, &wc) > 0) {
			cnt++;
			acmp_process_comp(ep, &wc);
		}

		ibv_ack_cq_events(cq, cnt);
	}

	return NULL;
}

static void acmp_format_mgid(union ibv_gid *mgid, uint16_t pkey, uint8_t tos,
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

static void acmp_init_join(struct ib_sa_mad *mad, union ibv_gid *port_gid,
	uint16_t pkey, uint8_t tos, uint8_t tclass, uint8_t sl, uint8_t rate, uint8_t mtu)
{
	struct ib_mc_member_rec *mc_rec;

	acm_log(2, "\n");
	mad->base_version = 1;
	mad->mgmt_class = IB_MGMT_CLASS_SA;
	mad->class_version = 2;
	mad->method = IB_METHOD_SET;
	mad->tid = htobe64((uint64_t) atomic_inc(&g_tid));
	mad->attr_id = IB_SA_ATTR_MC_MEMBER_REC;
	mad->comp_mask =
		IB_COMP_MASK_MC_MGID | IB_COMP_MASK_MC_PORT_GID |
		IB_COMP_MASK_MC_QKEY | IB_COMP_MASK_MC_MTU_SEL| IB_COMP_MASK_MC_MTU |
		IB_COMP_MASK_MC_TCLASS | IB_COMP_MASK_MC_PKEY | IB_COMP_MASK_MC_RATE_SEL |
		IB_COMP_MASK_MC_RATE | IB_COMP_MASK_MC_SL | IB_COMP_MASK_MC_FLOW |
		IB_COMP_MASK_MC_SCOPE | IB_COMP_MASK_MC_JOIN_STATE;

	mc_rec = (struct ib_mc_member_rec *) mad->data;
	acmp_format_mgid(&mc_rec->mgid, pkey | IB_PKEY_FULL_MEMBER, tos, rate, mtu);
	mc_rec->port_gid = *port_gid;
	mc_rec->qkey = htobe32(ACM_QKEY);
	mc_rec->mtu = umad_sa_set_rate_mtu_or_life(UMAD_SA_SELECTOR_EXACTLY, mtu);
	mc_rec->tclass = tclass;
	mc_rec->pkey = htobe16(pkey);
	mc_rec->rate = umad_sa_set_rate_mtu_or_life(UMAD_SA_SELECTOR_EXACTLY, rate);
	mc_rec->sl_flow_hop = umad_sa_mcm_set_sl_flow_hop(sl, 0, 0);
	mc_rec->scope_state = umad_sa_mcm_set_scope_state(UMAD_SA_MCM_ADDR_SCOPE_SITE_LOCAL,
							  UMAD_SA_MCM_JOIN_STATE_FULL_MEMBER);
}

static void acmp_join_group(struct acmp_ep *ep, union ibv_gid *port_gid,
	uint8_t tos, uint8_t tclass, uint8_t sl, uint8_t rate, uint8_t mtu)
{
	struct ib_sa_mad *mad;
	struct ib_mc_member_rec *mc_rec;
	struct acm_sa_mad *sa_mad;

	acm_log(2, "\n");
	sa_mad = acm_alloc_sa_mad(ep->endpoint, ep, acmp_process_join_resp);
	if (!sa_mad) {
		acm_log(0, "Error - failed to allocate sa_mad\n");
		return;
	}

	acm_log(0, "%s %d pkey 0x%x, sl 0x%x, rate 0x%x, mtu 0x%x\n",
		ep->port->dev->verbs->device->name,
		ep->port->port_num, ep->pkey, sl, rate, mtu);
	mad = (struct ib_sa_mad *) &sa_mad->sa_mad;
	acmp_init_join(mad, port_gid, ep->pkey, tos, tclass, sl, rate, mtu);
	mc_rec = (struct ib_mc_member_rec *) mad->data;
	acmp_set_dest_addr(&ep->mc_dest[ep->mc_cnt++], ACM_ADDRESS_GID,
		mc_rec->mgid.raw, sizeof(mc_rec->mgid));
	ep->mc_dest[ep->mc_cnt - 1].state = ACMP_INIT;

	if (acm_send_sa_mad(sa_mad)) {
		acm_log(0, "Error - Failed to send sa mad\n");
		acm_free_sa_mad(sa_mad);
	}
}

static void acmp_ep_join(struct acmp_ep *ep)
{
	struct acmp_port *port;
	union ibv_gid gid;

	port = ep->port;
	acm_log(1, "%s\n", ep->id_string);

	if (ep->mc_dest[0].state == ACMP_READY && ep->mc_dest[0].ah) {
		ibv_detach_mcast(ep->qp, &ep->mc_dest[0].mgid,
				 ep->mc_dest[0].av.dlid);
		ibv_destroy_ah(ep->mc_dest[0].ah);
		ep->mc_dest[0].ah = NULL;
	}
	ep->mc_cnt = 0;
	ep->state = ACMP_INIT;
	acm_get_gid((struct acm_port *)ep->port->port, 0, &gid);
	acmp_join_group(ep, &gid, 0, 0, 0, min_rate, min_mtu);

	if ((route_prot == ACMP_ROUTE_PROT_ACM) &&
	    (port->rate != min_rate || port->mtu != min_mtu))
		acmp_join_group(ep, &gid, 0, 0, 0, port->rate, port->mtu);

	acm_log(1, "join for %s complete\n", ep->id_string);
}

static int acmp_port_join(void *port_context)
{
	struct acmp_ep *ep;
	struct acmp_port *port = port_context;

	acm_log(1, "device %s port %d\n", port->dev->verbs->device->name,
		port->port_num);

	list_for_each(&port->ep_list, ep, entry) {
		if (!ep->endpoint) {
			/* Stale endpoint */
			continue;
		}
		acmp_ep_join(ep);
	}
	acm_log(1, "joins for device %s port %d complete\n",
		port->dev->verbs->device->name, port->port_num);

	return 0;
}

static int acmp_handle_event(void *port_context, enum ibv_event_type type)
{
	int ret = 0;

	acm_log(2, "event %s\n", ibv_event_type_str(type));

	switch (type) {
	case IBV_EVENT_CLIENT_REREGISTER:
		ret = acmp_port_join(port_context);
		break;
	default:
		break;
	}
	return ret;
}

static void acmp_process_timeouts(void)
{
	struct acmp_send_msg *msg;
	struct acm_resolve_rec *rec;
	struct acm_mad *mad;

	while ((msg = list_pop(&timeout_list, struct acmp_send_msg, entry))) {
		mad = (struct acm_mad *) &msg->data[0];
		rec = (struct acm_resolve_rec *) mad->data;

		acm_format_name(0, log_data, sizeof log_data,
				rec->dest_type, rec->dest, sizeof rec->dest);
		acm_log(0, "notice - dest %s\n", log_data);

		msg->resp_handler(msg, NULL, NULL);
		acmp_free_send(msg);
	}
}

static void acmp_process_wait_queue(struct acmp_ep *ep, uint64_t *next_expire)
{
	struct acmp_send_msg *msg, *next;
	struct ibv_send_wr *bad_wr;

	list_for_each_safe(&ep->wait_queue, msg, next, entry) {
		if (msg->expires <= time_stamp_ms()) {
			list_del(&msg->entry);
			(void) atomic_dec(&wait_cnt);
			if (--msg->tries) {
				acm_log(1, "notice - retrying request\n");
				list_add_tail(&ep->active_queue, &msg->entry);
				ibv_post_send(ep->qp, &msg->wr, &bad_wr);
			} else {
				acm_log(0, "notice - failing request\n");
				acmp_send_available(ep, msg->req_queue);
				list_add_tail(&timeout_list, &msg->entry);
			}
		} else {
			*next_expire = min(*next_expire, msg->expires);
			break;
		}
	}
}

/* While the device/port/ep will not be freed, we need to be careful of
 * their addition while walking the link lists. Therefore, we need to acquire
 * the appropriate locks.
 */
static void *acmp_retry_handler(void *context)
{
	struct acmp_device *dev;
	struct acmp_port *port;
	struct acmp_ep *ep;
	uint64_t next_expire;
	int i, wait;

	acm_log(0, "started\n");
	if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL)) {
		acm_log(0, "Error: failed to set cancel type \n");
		pthread_exit(NULL);
	}
	if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) {
		acm_log(0, "Error: failed to set cancel state\n");
		pthread_exit(NULL);
	}
	retry_thread_started = 1;

	while (1) {
		while (!atomic_get(&wait_cnt)) {
			pthread_testcancel();
			event_wait(&timeout_event, -1);
		}

		next_expire = -1;
		pthread_mutex_lock(&acmp_dev_lock);
		list_for_each(&acmp_dev_list, dev, entry) {
			pthread_mutex_unlock(&acmp_dev_lock);

			for (i = 0; i < dev->port_cnt; i++) {
				port = &dev->port[i];

				pthread_mutex_lock(&port->lock);
				list_for_each(&port->ep_list, ep, entry) {
					pthread_mutex_unlock(&port->lock);
					pthread_mutex_lock(&ep->lock);
					if (!list_empty(&ep->wait_queue))
						acmp_process_wait_queue(ep, &next_expire);
					pthread_mutex_unlock(&ep->lock);
					pthread_mutex_lock(&port->lock);
				}
				pthread_mutex_unlock(&port->lock);
			}
			pthread_mutex_lock(&acmp_dev_lock);
		}
		pthread_mutex_unlock(&acmp_dev_lock);

		acmp_process_timeouts();
		if (next_expire != -1) {
			wait = (int) (next_expire - time_stamp_ms());
			if (wait > 0 && atomic_get(&wait_cnt)) {
				pthread_testcancel();
				event_wait(&timeout_event, wait);
			}
		}
	}

	retry_thread_started = 0;
	return NULL;
}

static int
acmp_query(void *addr_context, struct acm_msg *msg, uint64_t id)
{
	struct acmp_request *req;
	struct ib_sa_mad *mad;
	struct acmp_addr *address = addr_context;
	struct acmp_ep *ep = address->ep;
	uint8_t status;
	struct acm_sa_mad *sa_mad;

	if (ep->state != ACMP_READY) {
		status = ACM_STATUS_ENODATA;
		goto resp;
	}

	req = acmp_alloc_req(id, msg);
	if (!req) {
		status = ACM_STATUS_ENOMEM;
		goto resp;
	}
	req->ep = ep;

	sa_mad = acm_alloc_sa_mad(ep->endpoint, req, acmp_sa_resp);
	if (!sa_mad) {
		acm_log(0, "Error - failed to allocate sa_mad\n");
		status = ACM_STATUS_ENOMEM;
		goto free_req;
	}

	mad = (struct ib_sa_mad *) &sa_mad->sa_mad;
	acmp_init_path_query(mad);

	memcpy(mad->data, &msg->resolve_data[0].info.path,
		sizeof(struct ibv_path_record));
	mad->comp_mask = acm_path_comp_mask(&msg->resolve_data[0].info.path);

	acm_increment_counter(ACM_CNTR_ROUTE_QUERY);
	atomic_inc(&ep->counters[ACM_CNTR_ROUTE_QUERY]);
	if (acm_send_sa_mad(sa_mad)) {
		acm_log(0, "Error - Failed to send sa mad\n");
		status = ACM_STATUS_ENODATA;
		goto free_mad;
	}
	return ACM_STATUS_SUCCESS;

free_mad:
	acm_free_sa_mad(sa_mad);
free_req:
	acmp_free_req(req);
resp:
	msg->hdr.opcode |= ACM_OP_ACK;
	msg->hdr.status = status;
	if (status == ACM_STATUS_ENODATA)
		atomic_inc(&ep->counters[ACM_CNTR_NODATA]);
	else
		atomic_inc(&ep->counters[ACM_CNTR_ERROR]);
	return acm_query_response(id, msg);
}

static uint8_t
acmp_send_resolve(struct acmp_ep *ep, struct acmp_dest *dest,
	struct acm_ep_addr_data *saddr)
{
	struct acmp_send_msg *msg;
	struct acm_mad *mad;
	struct acm_resolve_rec *rec;
	int i;

	acm_log(2, "\n");
	msg = acmp_alloc_send(ep, &ep->mc_dest[0], sizeof(*mad));
	if (!msg) {
		acm_log(0, "ERROR - cannot allocate send msg\n");
		return ACM_STATUS_ENOMEM;
	}

	acmp_init_send_req(msg, (void *) dest, acmp_process_addr_resp);
	(void) atomic_inc(&dest->refcnt);

	mad = (struct acm_mad *) msg->data;
	mad->base_version = 1;
	mad->mgmt_class = ACM_MGMT_CLASS;
	mad->class_version = 1;
	mad->method = IB_METHOD_GET;
	mad->control = ACM_CTRL_RESOLVE;
	mad->tid = htobe64((uint64_t) atomic_inc(&g_tid));

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

	acm_increment_counter(ACM_CNTR_ADDR_QUERY);
	atomic_inc(&ep->counters[ACM_CNTR_ADDR_QUERY]);
	acmp_post_send(&ep->resolve_queue, msg);
	return 0;
}

/* Caller must hold dest lock */
static uint8_t acmp_queue_req(struct acmp_dest *dest, uint64_t id, struct acm_msg *msg)
{
	struct acmp_request *req;

	acm_log(2, "id %" PRIu64 "\n", id);
	req = acmp_alloc_req(id, msg);
	if (!req) {
		return ACM_STATUS_ENOMEM;
	}
	req->ep = dest->ep;

	list_add_tail(&dest->req_queue, &req->entry);
	return ACM_STATUS_SUCCESS;
}

static int acmp_dest_timeout(struct acmp_dest *dest)
{
	uint64_t timestamp = time_stamp_min();

	if (timestamp > dest->addr_timeout) {
		acm_log(2, "%s address timed out\n", dest->name);
		dest->state = ACMP_INIT;
		return 1;
	} else if (timestamp > dest->route_timeout) {
		acm_log(2, "%s route timed out\n", dest->name);
		dest->state = ACMP_ADDR_RESOLVED;
		return 1;
	}
	return 0;
}

static int
acmp_check_addr_match(struct ifaddrs *iap, struct acm_ep_addr_data *saddr,
		      unsigned int d_family)
{
	char sip[INET6_ADDRSTRLEN] = {0};
	char dip[INET6_ADDRSTRLEN] = {0};
	const char *tmp;
	size_t sock_size;
	unsigned int s_family;
	int ret;

	s_family = iap->ifa_addr->sa_family;

	if (!iap->ifa_addr ||
	    !(iap->ifa_flags & IFF_UP) ||
	    (s_family != d_family))
		return -1;

	sock_size = (s_family == AF_INET) ? sizeof(struct sockaddr_in) :
		sizeof(struct sockaddr_in6);

	ret = getnameinfo(iap->ifa_addr, sock_size,
			  sip, sizeof(sip),
			  NULL, 0, NI_NUMERICHOST);

	if (ret)
		return ret;

	tmp = inet_ntop(d_family, (void *)saddr->info.addr, dip,
			sizeof(dip));
	if (!tmp)
		return -1;
	ret = memcmp(sip, dip, strlen(dip));
	return ret;
}

static void
acmp_acquire_sgid(struct acm_ep_addr_data *saddr,
		  struct acmp_dest *dest)
{
	struct ifaddrs *addrs, *iap;
	unsigned int d_family;
	int ret;

	if (!ib_any_gid(&dest->path.sgid))
		return;

	if (dest->addr_type != ACM_ADDRESS_IP6 &&
	    dest->addr_type != ACM_ADDRESS_IP)
		return;

	if (getifaddrs(&addrs))
		return;

	d_family = (dest->addr_type == ACM_ADDRESS_IP) ? AF_INET : AF_INET6;

	for (iap = addrs; iap != NULL; iap = iap->ifa_next) {
		ret = acmp_check_addr_match(iap, saddr, d_family);
		if (!ret) {
			ret = acm_if_get_sgid(iap->ifa_name,
					      &dest->path.sgid);
			if (!ret)
				break;
		}
	}
	freeifaddrs(addrs);
}

static int
acmp_resolve_dest(struct acmp_ep *ep, struct acm_msg *msg, uint64_t id)
{
	struct acmp_dest *dest;
	struct acm_ep_addr_data *saddr, *daddr;
	uint8_t status;
	int ret;

	saddr = &msg->resolve_data[msg->hdr.src_index];
	daddr = &msg->resolve_data[msg->hdr.dst_index];
	acm_format_name(2, log_data, sizeof log_data,
			daddr->type, daddr->info.addr, sizeof daddr->info.addr);
	acm_log(2, "dest %s\n", log_data);

	dest = acmp_acquire_dest(ep, daddr->type, daddr->info.addr);
	if (!dest) {
		acm_log(0, "ERROR - unable to allocate destination in request\n");
		atomic_inc(&ep->counters[ACM_CNTR_ERROR]);
		return acmp_resolve_response(id, msg, NULL, ACM_STATUS_ENOMEM);
	}

	pthread_mutex_lock(&dest->lock);
test:
	switch (dest->state) {
	case ACMP_READY:
		if (acmp_dest_timeout(dest))
			goto test;
		acm_log(2, "request satisfied from local cache\n");
		acm_increment_counter(ACM_CNTR_ROUTE_CACHE);
		atomic_inc(&ep->counters[ACM_CNTR_ROUTE_CACHE]);
		status = ACM_STATUS_SUCCESS;
		break;
	case ACMP_ADDR_RESOLVED:
		acm_log(2, "have address, resolving route\n");
		acm_increment_counter(ACM_CNTR_ADDR_CACHE);
		atomic_inc(&ep->counters[ACM_CNTR_ADDR_CACHE]);
		acmp_acquire_sgid(saddr, dest);
		status = acmp_resolve_path_sa(ep, dest, acmp_dest_sa_resp);
		if (status) {
			break;
		}
		goto queue;
	case ACMP_INIT:
		acm_log(2, "sending resolve msg to dest\n");
		status = acmp_send_resolve(ep, dest, saddr);
		if (status) {
			break;
		}
		dest->state = ACMP_QUERY_ADDR;
		/* fall through */
	default:
queue:
		if (daddr->flags & ACM_FLAGS_NODELAY) {
			acm_log(2, "lookup initiated, but client wants no delay\n");
			status = ACM_STATUS_ENODATA;
			break;
		}
		status = acmp_queue_req(dest, id, msg);
		if (status) {
			break;
		}
		ret = 0;
		pthread_mutex_unlock(&dest->lock);
		goto put;
	}
	pthread_mutex_unlock(&dest->lock);
	ret = acmp_resolve_response(id, msg, dest, status);
put:
	acmp_put_dest(dest);
	return ret;
}

static int
acmp_resolve_path(struct acmp_ep *ep, struct acm_msg *msg, uint64_t id)
{
	struct acmp_dest *dest;
	struct ibv_path_record *path;
	uint8_t *addr;
	uint8_t status;
	int ret;

	path = &msg->resolve_data[0].info.path;
	addr = msg->resolve_data[1].info.addr;
	memset(addr, 0, ACM_MAX_ADDRESS);
	if (path->dlid) {
		* ((__be16 *) addr) = path->dlid;
		dest = acmp_acquire_dest(ep, ACM_ADDRESS_LID, addr);
	} else {
		memcpy(addr, &path->dgid, sizeof path->dgid);
		dest = acmp_acquire_dest(ep, ACM_ADDRESS_GID, addr);
	}
	if (!dest) {
		acm_log(0, "ERROR - unable to allocate destination in request\n");
		atomic_inc(&ep->counters[ACM_CNTR_ERROR]);
		return acmp_resolve_response(id, msg, NULL, ACM_STATUS_ENOMEM);
	}

	pthread_mutex_lock(&dest->lock);
test:
	switch (dest->state) {
	case ACMP_READY:
		if (acmp_dest_timeout(dest))
			goto test;
		acm_log(2, "request satisfied from local cache\n");
		acm_increment_counter(ACM_CNTR_ROUTE_CACHE);
		atomic_inc(&ep->counters[ACM_CNTR_ROUTE_CACHE]);
		status = ACM_STATUS_SUCCESS;
		break;
	case ACMP_INIT:
		acm_log(2, "have path, bypassing address resolution\n");
		acmp_record_path_addr(ep, dest, path);
		/* fall through */
	case ACMP_ADDR_RESOLVED:
		acm_log(2, "have address, resolving route\n");
		status = acmp_resolve_path_sa(ep, dest, acmp_dest_sa_resp);
		if (status) {
			break;
		}
		/* fall through */
	default:
		if (msg->resolve_data[0].flags & ACM_FLAGS_NODELAY) {
			acm_log(2, "lookup initiated, but client wants no delay\n");
			status = ACM_STATUS_ENODATA;
			break;
		}
		status = acmp_queue_req(dest, id, msg);
		if (status) {
			break;
		}
		ret = 0;
		pthread_mutex_unlock(&dest->lock);
		goto put;
	}
	pthread_mutex_unlock(&dest->lock);
	ret = acmp_resolve_response(id, msg, dest, status);
put:
	acmp_put_dest(dest);
	return ret;
}

static int
acmp_resolve(void *addr_context, struct acm_msg *msg, uint64_t id)
{
	struct acmp_addr *address = addr_context;
	struct acmp_ep *ep = address->ep;

	if (ep->state != ACMP_READY) {
		atomic_inc(&ep->counters[ACM_CNTR_NODATA]);
		return acmp_resolve_response(id, msg, NULL, ACM_STATUS_ENODATA);
	}

	atomic_inc(&ep->counters[ACM_CNTR_RESOLVE]);
	if (msg->resolve_data[0].type == ACM_EP_INFO_PATH)
		return acmp_resolve_path(ep, msg, id);
	else
		return acmp_resolve_dest(ep, msg, id);
}

static void acmp_query_perf(void *ep_context, uint64_t *values, uint8_t *cnt)
{
	struct acmp_ep *ep = ep_context;
	int i;

	for (i = 0; i < ACM_MAX_COUNTER; i++)
		values[i] = htobe64((uint64_t) atomic_get(&ep->counters[i]));
	*cnt = ACM_MAX_COUNTER;
}

static enum acmp_addr_prot acmp_convert_addr_prot(char *param)
{
	if (!strcasecmp("acm", param))
		return ACMP_ADDR_PROT_ACM;

	return addr_prot;
}

static enum acmp_route_prot acmp_convert_route_prot(char *param)
{
	if (!strcasecmp("acm", param))
		return ACMP_ROUTE_PROT_ACM;
	else if (!strcasecmp("sa", param))
		return ACMP_ROUTE_PROT_SA;

	return route_prot;
}

static enum acmp_loopback_prot acmp_convert_loopback_prot(char *param)
{
	if (!strcasecmp("none", param))
		return ACMP_LOOPBACK_PROT_NONE;
	else if (!strcasecmp("local", param))
		return ACMP_LOOPBACK_PROT_LOCAL;

	return loopback_prot;
}

static enum acmp_route_preload acmp_convert_route_preload(char *param)
{
	if (!strcasecmp("none", param) || !strcasecmp("no", param))
		return ACMP_ROUTE_PRELOAD_NONE;
	else if (!strcasecmp("opensm_full_v1", param))
		return ACMP_ROUTE_PRELOAD_OSM_FULL_V1;

	return route_preload;
}

static enum acmp_addr_preload acmp_convert_addr_preload(char *param)
{
	if (!strcasecmp("none", param) || !strcasecmp("no", param))
		return ACMP_ADDR_PRELOAD_NONE;
	else if (!strcasecmp("acm_hosts", param))
		return ACMP_ADDR_PRELOAD_HOSTS;

	return addr_preload;
}

static int acmp_post_recvs(struct acmp_ep *ep)
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
		acmp_post_recv(ep, (uintptr_t) (ep->recv_bufs + ACM_RECV_SIZE * i));
	}
	return 0;

err:
	free(ep->recv_bufs);
	return -1;
}

/* Parse "opensm full v1" file to build LID to GUID table */
static void acmp_parse_osm_fullv1_lid2guid(FILE *f, __be64 *lid2guid)
{
	char s[128];
	char *p, *ptr, *p_guid, *p_lid;
	uint64_t guid;
	uint16_t lid;

	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;
		if (!(p = strtok_r(s, " \n", &ptr)))
			continue;	/* ignore blank lines */

		if (strncmp(p, "Switch", sizeof("Switch") - 1) &&
		    strncmp(p, "Channel", sizeof("Channel") - 1) &&
		    strncmp(p, "Router", sizeof("Router") - 1))
			continue;

		if (!strncmp(p, "Channel", sizeof("Channel") - 1)) {
			p = strtok_r(NULL, " ", &ptr); /* skip 'Adapter' */
			if (!p)
				continue;
		}

		p_guid = strtok_r(NULL, ",", &ptr);
		if (!p_guid)
			continue;

		guid = (uint64_t) strtoull(p_guid, NULL, 16);

		ptr = strstr(ptr, "base LID");
		if (!ptr)
			continue;
		ptr += sizeof("base LID");
		p_lid = strtok_r(NULL, ",", &ptr);
		if (!p_lid)
			continue;

		lid = (uint16_t) strtoul(p_lid, NULL, 0);
		if (lid >= IB_LID_MCAST_START)
			continue;
		if (lid2guid[lid])
			acm_log(0, "ERROR - duplicate lid %u\n", lid);
		else
			lid2guid[lid] = htobe64(guid);
	}
}

/* Parse 'opensm full v1' file to populate PR cache */
static int acmp_parse_osm_fullv1_paths(FILE *f, __be64 *lid2guid, struct acmp_ep *ep)
{
	union ibv_gid sgid, dgid;
	struct ibv_port_attr attr = {};
	struct acmp_dest *dest;
	char s[128];
	char *p, *ptr, *p_guid, *p_lid;
	uint64_t guid;
	uint16_t lid, dlid;
	__be16 net_dlid;
	int sl, mtu, rate;
	int ret = 1, i;
	uint8_t addr[ACM_MAX_ADDRESS];
	uint8_t addr_type;

	acm_get_gid((struct acm_port *)ep->port->port, 0, &sgid);

	/* Search for endpoint's SLID */
	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;
		if (!(p = strtok_r(s, " \n", &ptr)))
			continue;	/* ignore blank lines */

		if (strncmp(p, "Switch", sizeof("Switch") - 1) &&
		    strncmp(p, "Channel", sizeof("Channel") - 1) &&
		    strncmp(p, "Router", sizeof("Router") - 1))
			continue;

		if (!strncmp(p, "Channel", sizeof("Channel") - 1)) {
			p = strtok_r(NULL, " ", &ptr); /* skip 'Adapter' */
			if (!p)
				continue;
		}

		p_guid = strtok_r(NULL, ",", &ptr);
		if (!p_guid)
			continue;

		guid = (uint64_t) strtoull(p_guid, NULL, 16);
		if (guid != be64toh(sgid.global.interface_id))
			continue;

		ptr = strstr(ptr, "base LID");
		if (!ptr)
			continue;
		ptr += sizeof("base LID");
		p_lid = strtok_r(NULL, ",", &ptr);
		if (!p_lid)
			continue;

		lid = (uint16_t) strtoul(p_lid, NULL, 0);
		if (lid != ep->port->lid)
			continue;

		ibv_query_port(ep->port->dev->verbs, ep->port->port_num, &attr);
		ret = 0;
		break;
	}

	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;
		if (!(p = strtok_r(s, " \n", &ptr)))
			continue;	/* ignore blank lines */

		if (!strncmp(p, "Switch", sizeof("Switch") - 1) ||
		    !strncmp(p, "Channel", sizeof("Channel") - 1) ||
		    !strncmp(p, "Router", sizeof("Router") - 1))
			break;

		dlid = strtoul(p, NULL, 0);
		net_dlid = htobe16(dlid);

		p = strtok_r(NULL, ":", &ptr);
		if (!p)
			continue;
		if (strcmp(p, "UNREACHABLE") == 0)
			continue;
		sl = atoi(p);

		p = strtok_r(NULL, ":", &ptr);
		if (!p)
			continue;
		mtu = atoi(p);

		p = strtok_r(NULL, ":", &ptr);
		if (!p)
			continue;
		rate = atoi(p);

		if (!lid2guid[dlid]) {
			acm_log(0, "ERROR - dlid %u not found in lid2guid table\n", dlid);
			continue;
		}

		dgid.global.subnet_prefix = sgid.global.subnet_prefix;
		dgid.global.interface_id = lid2guid[dlid];

		for (i = 0; i < 2; i++) {
			memset(addr, 0, ACM_MAX_ADDRESS);
			if (i == 0) {
				addr_type = ACM_ADDRESS_LID;
				memcpy(addr, &net_dlid, sizeof net_dlid);
			} else {
				addr_type = ACM_ADDRESS_GID;
				memcpy(addr, &dgid, sizeof(dgid));
			}
			dest = acmp_acquire_dest(ep, addr_type, addr);
			if (!dest) {
				acm_log(0, "ERROR - unable to create dest\n");
				break;
			}

			dest->path.sgid = sgid;
			dest->path.slid = htobe16(ep->port->lid);
			dest->path.dgid = dgid;
			dest->path.dlid = net_dlid;
			dest->path.reversible_numpath = IBV_PATH_RECORD_REVERSIBLE;
			dest->path.pkey = htobe16(ep->pkey);
			dest->path.mtu = (uint8_t) mtu;
			dest->path.rate = (uint8_t) rate;
			dest->path.qosclass_sl = htobe16((uint16_t) sl & 0xF);
			if (dlid == ep->port->lid) {
				dest->path.packetlifetime = 0;
				dest->addr_timeout = (uint64_t)~0ULL;
				dest->route_timeout = (uint64_t)~0ULL;
			} else {
				dest->path.packetlifetime = attr.subnet_timeout;
				dest->addr_timeout = time_stamp_min() + (unsigned) addr_timeout;
				dest->route_timeout = time_stamp_min() + (unsigned) route_timeout;
			}
			dest->remote_qpn = 1;
			dest->state = ACMP_READY;
			acmp_put_dest(dest);
			acm_log(1, "added cached dest %s\n", dest->name);
		}
	}
	return ret;
}

static int acmp_parse_osm_fullv1(struct acmp_ep *ep)
{
	FILE *f;
	__be64 *lid2guid;
	int ret = 1;

	if (!(f = fopen(route_data_file, "r"))) {
		acm_log(0, "ERROR - couldn't open %s\n", route_data_file);
		return ret;
	}

	lid2guid = calloc(IB_LID_MCAST_START, sizeof(*lid2guid));
	if (!lid2guid) {
		acm_log(0, "ERROR - no memory for path record parsing\n");
		goto err;
	}

	acmp_parse_osm_fullv1_lid2guid(f, lid2guid);
	rewind(f);
	ret = acmp_parse_osm_fullv1_paths(f, lid2guid, ep);
	free(lid2guid);
err:
	fclose(f);
	return ret;
}

static void acmp_parse_hosts_file(struct acmp_ep *ep)
{
	FILE *f;
	char s[120];
	char addr[INET6_ADDRSTRLEN], gid[INET6_ADDRSTRLEN];
	uint8_t name[ACM_MAX_ADDRESS];
	struct in6_addr ip_addr, ib_addr;
	struct acmp_dest *dest, *gid_dest;
	uint8_t addr_type;

	if (!(f = fopen(addr_data_file, "r"))) {
		acm_log(0, "ERROR - couldn't open %s\n", addr_data_file);
		return;
        }

	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;

		if (sscanf(s, "%46s%46s", addr, gid) != 2)
			continue;

		acm_log(2, "%s", s);
		if (inet_pton(AF_INET6, gid, &ib_addr) <= 0) {
			acm_log(0, "ERROR - %s is not IB GID\n", gid);
			continue;
		}
		memset(name, 0, ACM_MAX_ADDRESS);
		if (inet_pton(AF_INET, addr, &ip_addr) > 0) {
			addr_type = ACM_ADDRESS_IP;
			memcpy(name, &ip_addr, 4);
		} else if (inet_pton(AF_INET6, addr, &ip_addr) > 0) {
			addr_type = ACM_ADDRESS_IP6;
			memcpy(name, &ip_addr, sizeof(ip_addr));
		} else {
			addr_type = ACM_ADDRESS_NAME;
			strncpy((char *)name, addr, ACM_MAX_ADDRESS);
		}

		dest = acmp_acquire_dest(ep, addr_type, name);
		if (!dest) {
			acm_log(0, "ERROR - unable to create dest %s\n", addr);
			continue;
		}

		memset(name, 0, ACM_MAX_ADDRESS);
		memcpy(name, &ib_addr, sizeof(ib_addr));
		gid_dest = acmp_get_dest(ep, ACM_ADDRESS_GID, name);
		if (gid_dest) {
			dest->path = gid_dest->path;
			dest->state = ACMP_READY;
			acmp_put_dest(gid_dest);
		} else {
			memcpy(&dest->path.dgid, &ib_addr, 16);
			//ibv_query_gid(ep->port->dev->verbs, ep->port->port_num,
			//		0, &dest->path.sgid);
			dest->path.slid = htobe16(ep->port->lid);
			dest->path.reversible_numpath = IBV_PATH_RECORD_REVERSIBLE;
			dest->path.pkey = htobe16(ep->pkey);
			dest->state = ACMP_ADDR_RESOLVED;
		}

		dest->remote_qpn = 1;
		dest->addr_timeout = time_stamp_min() + (unsigned) addr_timeout;
		dest->route_timeout = time_stamp_min() + (unsigned) route_timeout;
		acmp_put_dest(dest);
		acm_log(1, "added host %s address type %d IB GID %s\n",
			addr, addr_type, gid);
	}

	fclose(f);
}

/*
 * We currently require that the routing data be preloaded in order to
 * load the address data.  This is backwards from normal operation, which
 * usually resolves the address before the route.
 */
static void acmp_ep_preload(struct acmp_ep *ep)
{
	switch (route_preload) {
	case ACMP_ROUTE_PRELOAD_OSM_FULL_V1:
		if (acmp_parse_osm_fullv1(ep))
			acm_log(0, "ERROR - failed to preload EP\n");
		break;
	default:
		break;
	}

	switch (addr_preload) {
	case ACMP_ADDR_PRELOAD_HOSTS:
		acmp_parse_hosts_file(ep);
		break;
	default:
		break;
	}
}

static int acmp_add_addr(const struct acm_address *addr, void *ep_context,
			 void **addr_context)
{
	struct acmp_ep *ep = ep_context;
	struct acmp_dest *dest;
	int i;

	acm_log(2, "\n");

	for (i = 0; (i < MAX_EP_ADDR) &&
	     (ep->addr_info[i].type != ACM_ADDRESS_INVALID); i++)
		;

	if (i == MAX_EP_ADDR) {
		acm_log(0, "ERROR - no more space for local address\n");
		return -1;
	}
	ep->addr_info[i].type = addr->type;
	memcpy(&ep->addr_info[i].info, &addr->info, sizeof(addr->info));
	ep->addr_info[i].addr = (struct acm_address *) addr;
	ep->addr_info[i].ep = ep;

	if (loopback_prot != ACMP_LOOPBACK_PROT_LOCAL) {
		*addr_context = &ep->addr_info[i];
		return 0;
	}

	dest = acmp_acquire_dest(ep, addr->type, (uint8_t *) addr->info.addr);
	if (!dest) {
		acm_log(0, "ERROR - unable to create loopback dest %s\n",
			addr->id_string);
		memset(&ep->addr_info[i], 0, sizeof(ep->addr_info[i]));
		return -1;
	}

	acm_get_gid((struct acm_port *) ep->port->port, 0, &dest->path.sgid);
	dest->path.dgid = dest->path.sgid;
	dest->path.dlid = dest->path.slid = htobe16(ep->port->lid);
	dest->path.reversible_numpath = IBV_PATH_RECORD_REVERSIBLE;
	dest->path.pkey = htobe16(ep->pkey);
	dest->path.mtu = (uint8_t) ep->port->mtu;
	dest->path.rate = (uint8_t) ep->port->rate;

	dest->remote_qpn = ep->qp->qp_num;
	dest->addr_timeout = (uint64_t) ~0ULL;
	dest->route_timeout = (uint64_t) ~0ULL;
	dest->state = ACMP_READY;
	acmp_put_dest(dest);
	*addr_context = &ep->addr_info[i];
	acm_log(1, "added loopback dest %s\n", dest->name);

	return 0;
}

static void acmp_remove_addr(void *addr_context)
{
	struct acmp_addr *address = addr_context;
	struct acmp_device *dev;
	struct acmp_dest *dest;
	struct acmp_ep *ep;
	int i;

	acm_log(2, "\n");

	/*
	 * The address may be a local destination address. If so,
	 * delete it from the cache.
	 */

	pthread_mutex_lock(&acmp_dev_lock);
	list_for_each(&acmp_dev_list, dev, entry) {
		pthread_mutex_unlock(&acmp_dev_lock);

		for (i = 0; i < dev->port_cnt; i++) {
			struct acmp_port *port = &dev->port[i];

			pthread_mutex_lock(&port->lock);
			list_for_each(&port->ep_list, ep, entry) {
				pthread_mutex_unlock(&port->lock);
				dest = acmp_get_dest(ep, address->type, address->addr->info.addr);
				if (dest) {
					acm_log(2, "Found a dest addr, deleting it\n");
					pthread_mutex_lock(&ep->lock);
					acmp_remove_dest(ep, dest);
					pthread_mutex_unlock(&ep->lock);
				}
				pthread_mutex_lock(&port->lock);
			}
			pthread_mutex_unlock(&port->lock);
		}
		pthread_mutex_lock(&acmp_dev_lock);
	}
	pthread_mutex_unlock(&acmp_dev_lock);

	memset(address, 0, sizeof(*address));
}

static struct acmp_port *acmp_get_port(struct acm_endpoint *endpoint)
{
	struct acmp_device *dev;

	acm_log(1, "dev 0x%" PRIx64 " port %d pkey 0x%x\n",
		be64toh(endpoint->port->dev->dev_guid),
		endpoint->port->port_num, endpoint->pkey);

	list_for_each(&acmp_dev_list, dev, entry) {
		if (dev->guid == endpoint->port->dev->dev_guid)
			return &dev->port[endpoint->port->port_num - 1];
	}

	return NULL;
}

static struct acmp_ep *
acmp_get_ep(struct acmp_port *port, struct acm_endpoint *endpoint)
{
	struct acmp_ep *ep;

	acm_log(1, "dev 0x%" PRIx64 " port %d pkey 0x%x\n",
		be64toh(endpoint->port->dev->dev_guid),
		endpoint->port->port_num, endpoint->pkey);

	list_for_each(&port->ep_list, ep, entry) {
		if (ep->pkey == endpoint->pkey)
			return ep;
	}

	return NULL;
}

static uint16_t acmp_get_pkey_index(struct acm_endpoint *endpoint)
{
	struct acmp_port *port;
	int i;

	port = acmp_get_port(endpoint);
	if (!port)
		return 0;
	i = ibv_get_pkey_index(port->dev->verbs, port->port_num,
			       htobe16(endpoint->pkey));
	if (i < 0)
		return 0;
	return i;
}

static void acmp_close_endpoint(void *ep_context)
{

	struct acmp_ep *ep = ep_context;

	acm_log(1, "%s %d pkey 0x%04x\n",
		ep->port->dev->verbs->device->name,
		ep->port->port_num, ep->pkey);

	ep->endpoint = NULL;
}

static struct acmp_ep *
acmp_alloc_ep(struct acmp_port *port, struct acm_endpoint *endpoint)
{
	struct acmp_ep *ep;
	int i;

	acm_log(1, "\n");
	ep = calloc(1, sizeof *ep);
	if (!ep)
		return NULL;

	ep->port = port;
	ep->endpoint = endpoint;
	ep->pkey = endpoint->pkey;
	ep->resolve_queue.credits = resolve_depth;
	ep->resp_queue.credits = send_depth;
	list_head_init(&ep->resolve_queue.pending);
	list_head_init(&ep->resp_queue.pending);
	list_head_init(&ep->active_queue);
	list_head_init(&ep->wait_queue);
	pthread_mutex_init(&ep->lock, NULL);
	sprintf(ep->id_string, "%s-%d-0x%x", port->dev->verbs->device->name,
		port->port_num, endpoint->pkey);
	for (i = 0; i < ACM_MAX_COUNTER; i++)
		atomic_init(&ep->counters[i]);

	return ep;
}

static int acmp_open_endpoint(const struct acm_endpoint *endpoint,
			      void *port_context, void **ep_context)
{
	struct acmp_port *port = port_context;
	struct acmp_ep *ep;
	struct ibv_qp_init_attr init_attr;
	struct ibv_qp_attr attr;
	int ret, sq_size;

	ep = acmp_get_ep(port,  (struct acm_endpoint *) endpoint);
	if (ep) {
		acm_log(2, "endpoint for pkey 0x%x already exists\n", endpoint->pkey);
		pthread_mutex_lock(&ep->lock);
		ep->endpoint =  (struct acm_endpoint *) endpoint;
		pthread_mutex_unlock(&ep->lock);
		*ep_context = (void *) ep;
		return 0;
	}

	acm_log(2, "creating endpoint for pkey 0x%x\n", endpoint->pkey);
	ep = acmp_alloc_ep(port, (struct acm_endpoint *) endpoint);
	if (!ep)
		return -1;

	sprintf(ep->id_string, "%s-%d-0x%x",
		port->dev->verbs->device->name,
		port->port_num, endpoint->pkey);

	sq_size = resolve_depth + send_depth;
	ep->cq = ibv_create_cq(port->dev->verbs, sq_size + recv_depth,
		ep, port->dev->channel, 0);
	if (!ep->cq) {
		acm_log(0, "ERROR - failed to create CQ\n");
		goto err0;
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
	attr.pkey_index = acmp_get_pkey_index((struct acm_endpoint *) endpoint);
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

	ret = acmp_post_recvs(ep);
	if (ret)
		goto err2;

	pthread_mutex_lock(&port->lock);
	list_add(&port->ep_list, &ep->entry);
	pthread_mutex_unlock(&port->lock);
	acmp_ep_preload(ep);
	acmp_ep_join(ep);
	*ep_context = (void *) ep;
	return 0;

err2:
	ibv_destroy_qp(ep->qp);
err1:
	ibv_destroy_cq(ep->cq);
err0:
	free(ep);
	return -1;
}

static void acmp_port_up(struct acmp_port *port)
{
	struct ibv_port_attr attr;
	uint16_t pkey;
	__be16 pkey_be;
	__be16 sm_lid;
	int i, ret;
	int instance;

	acm_log(1, "%s %d\n", port->dev->verbs->device->name, port->port_num);
	ret = ibv_query_port(port->dev->verbs, port->port_num, &attr);
	if (ret) {
		acm_log(0, "ERROR - unable to get port attribute\n");
		return;
	}

	port->mtu = attr.active_mtu;
	port->rate = acm_get_rate(attr.active_width, attr.active_speed);
	if (attr.subnet_timeout >= 8)
		port->subnet_timeout = 1 << (attr.subnet_timeout - 8);

	port->lid = attr.lid;
	port->lid_mask = 0xffff - ((1 << attr.lmc) - 1);

	port->sa_dest.av.src_path_bits = 0;
	port->sa_dest.av.dlid = attr.sm_lid;
	port->sa_dest.av.sl = attr.sm_sl;
	port->sa_dest.av.port_num = port->port_num;
	port->sa_dest.remote_qpn = 1;
	sm_lid = htobe16(attr.sm_lid);
	acmp_set_dest_addr(&port->sa_dest, ACM_ADDRESS_LID,
			   (uint8_t *) &sm_lid, sizeof(sm_lid));

	instance = atomic_inc(&port->sa_dest.refcnt) - 1;
	port->sa_dest.state = ACMP_READY;
	for (i = 0; i < attr.pkey_tbl_len; i++) {
		ret = ibv_query_pkey(port->dev->verbs, port->port_num, i, &pkey_be);
		if (ret)
			continue;
		pkey = be16toh(pkey_be);
		if (!(pkey & 0x7fff))
			continue;

		/* Determine pkey index for default partition with preference
		 * for full membership
		 */
		if ((pkey & 0x7fff) == 0x7fff) {
			port->default_pkey_ix = i;
			break;
		}
	}

	port->state = IBV_PORT_ACTIVE;
	acm_log(1, "%s %d %d is up\n", port->dev->verbs->device->name, port->port_num, instance);
}

static void acmp_port_down(struct acmp_port *port)
{
	int instance;

	acm_log(1, "%s %d\n", port->dev->verbs->device->name, port->port_num);
	pthread_mutex_lock(&port->lock);
	port->state = IBV_PORT_DOWN;
	pthread_mutex_unlock(&port->lock);

	/*
	 * We wait for the SA destination to be released.  We could use an
	 * event instead of a sleep loop, but it's not worth it given how
	 * infrequently we should be processing a port down event in practice.
	 */
	instance = atomic_dec(&port->sa_dest.refcnt);
	if (instance == 1) {
		pthread_mutex_lock(&port->sa_dest.lock);
		port->sa_dest.state = ACMP_INIT;
		pthread_mutex_unlock(&port->sa_dest.lock);
	}
	acm_log(1, "%s %d %d is down\n", port->dev->verbs->device->name, port->port_num, instance);
}

static int acmp_open_port(const struct acm_port *cport, void *dev_context,
			  void **port_context)
{
	struct acmp_device *dev = dev_context;
	struct acmp_port *port;

	if (cport->port_num < 1 || cport->port_num > dev->port_cnt) {
		acm_log(0, "Error: port_num %d is out of range (max %d)\n",
			cport->port_num, dev->port_cnt);
		return -1;
	}

	port = &dev->port[cport->port_num - 1];
	pthread_mutex_lock(&port->lock);
	port->port = cport;
	port->state = IBV_PORT_DOWN;
	pthread_mutex_unlock(&port->lock);
	acmp_port_up(port);
	*port_context = port;
	return 0;
}

static void acmp_close_port(void *port_context)
{
	struct acmp_port *port = port_context;

	acmp_port_down(port);
	pthread_mutex_lock(&port->lock);
	port->port = NULL;
	pthread_mutex_unlock(&port->lock);
}

static void acmp_init_port(struct acmp_port *port, struct acmp_device *dev,
			   uint8_t port_num)
{
	acm_log(1, "%s %d\n", dev->verbs->device->name, port_num);
	port->dev = dev;
	port->port_num = port_num;
	pthread_mutex_init(&port->lock, NULL);
	list_head_init(&port->ep_list);
	acmp_init_dest(&port->sa_dest, ACM_ADDRESS_LID, NULL, 0);
	port->state = IBV_PORT_DOWN;
}

static int acmp_open_dev(const struct acm_device *device, void **dev_context)
{
	struct acmp_device *dev;
	size_t size;
	struct ibv_device_attr attr;
	int i, ret;
	struct ibv_context *verbs;

	acm_log(1, "dev_guid 0x%" PRIx64 " %s\n", be64toh(device->dev_guid),
		device->verbs->device->name);

	list_for_each(&acmp_dev_list, dev, entry) {
		if (dev->guid == device->dev_guid) {
			acm_log(2, "dev_guid 0x%" PRIx64 " already exits\n",
				be64toh(device->dev_guid));
			*dev_context = dev;
			dev->device = device;
			return 0;
		}
	}

	/* We need to release the core device structure when device close is
	 * called.  But this provider does not support dynamic add/removal of
	 * devices/ports/endpoints.  To avoid use-after-free issues, we open
	 * our own verbs context, rather than using the one in the core
	 * device structure.
	 */
	verbs = ibv_open_device(device->verbs->device);
	if (!verbs) {
		acm_log(0, "ERROR - opening device %s\n",
			device->verbs->device->name);
		goto err;
	}

	ret = ibv_query_device(verbs, &attr);
	if (ret) {
		acm_log(0, "ERROR - ibv_query_device (%s) %d\n",
			verbs->device->name, ret);
		goto err;
	}

	size = sizeof(*dev) + sizeof(struct acmp_port) * attr.phys_port_cnt;
	dev = (struct acmp_device *) calloc(1, size);
	if (!dev)
		goto err;

	dev->verbs = verbs;
	dev->device = device;
	dev->port_cnt = attr.phys_port_cnt;

	dev->pd = ibv_alloc_pd(dev->verbs);
	if (!dev->pd) {
		acm_log(0, "ERROR - unable to allocate PD\n");
		goto err1;
	}

	dev->channel = ibv_create_comp_channel(dev->verbs);
	if (!dev->channel) {
		acm_log(0, "ERROR - unable to create comp channel\n");
		goto err2;
	}

	for (i = 0; i < dev->port_cnt; i++) {
		acmp_init_port(&dev->port[i], dev, i + 1);
	}

	if (pthread_create(&dev->comp_thread_id, NULL, acmp_comp_handler, dev)) {
		acm_log(0, "Error -- failed to create the comp thread for dev %s",
			dev->verbs->device->name);
		goto err3;
	}

	pthread_mutex_lock(&acmp_dev_lock);
	list_add(&acmp_dev_list, &dev->entry);
	pthread_mutex_unlock(&acmp_dev_lock);
	dev->guid = device->dev_guid;
	*dev_context = dev;

	acm_log(1, "%s opened\n", dev->verbs->device->name);
	return 0;

err3:
	ibv_destroy_comp_channel(dev->channel);
err2:
	ibv_dealloc_pd(dev->pd);
err1:
	free(dev);
err:
	return -1;
}

static void acmp_close_dev(void *dev_context)
{
	struct acmp_device *dev = dev_context;

	acm_log(1, "dev_guid 0x%" PRIx64 "\n", be64toh(dev->device->dev_guid));
	dev->device = NULL;
}

static void acmp_set_options(void)
{
	FILE *f;
	char s[120];
	char opt[32], value[256];
	const char *opts_file = acm_get_opts_file();

	if (!(f = fopen(opts_file, "r")))
		return;

	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;

		if (sscanf(s, "%31s%255s", opt, value) != 2)
			continue;

		if (!strcasecmp("addr_prot", opt))
			addr_prot = acmp_convert_addr_prot(value);
		else if (!strcasecmp("addr_timeout", opt))
			addr_timeout = atoi(value);
		else if (!strcasecmp("route_prot", opt))
			route_prot = acmp_convert_route_prot(value);
		else if (!strcmp("route_timeout", opt))
			route_timeout = atoi(value);
		else if (!strcasecmp("loopback_prot", opt))
			loopback_prot = acmp_convert_loopback_prot(value);
		else if (!strcasecmp("timeout", opt))
			timeout = atoi(value);
		else if (!strcasecmp("retries", opt))
			retries = atoi(value);
		else if (!strcasecmp("resolve_depth", opt))
			resolve_depth = atoi(value);
		else if (!strcasecmp("send_depth", opt))
			send_depth = atoi(value);
		else if (!strcasecmp("recv_depth", opt))
			recv_depth = atoi(value);
		else if (!strcasecmp("min_mtu", opt))
			min_mtu = acm_convert_mtu(atoi(value));
		else if (!strcasecmp("min_rate", opt))
			min_rate = acm_convert_rate(atoi(value));
		else if (!strcasecmp("route_preload", opt))
			route_preload = acmp_convert_route_preload(value);
		else if (!strcasecmp("route_data_file", opt))
			strcpy(route_data_file, value);
		else if (!strcasecmp("addr_preload", opt))
			addr_preload = acmp_convert_addr_preload(value);
		else if (!strcasecmp("addr_data_file", opt))
			strcpy(addr_data_file, value);
	}

	fclose(f);
}

static void acmp_log_options(void)
{
	acm_log(0, "address resolution %d\n", addr_prot);
	acm_log(0, "address timeout %d\n", addr_timeout);
	acm_log(0, "route resolution %d\n", route_prot);
	acm_log(0, "route timeout %d\n", route_timeout);
	acm_log(0, "loopback resolution %d\n", loopback_prot);
	acm_log(0, "timeout %d ms\n", timeout);
	acm_log(0, "retries %d\n", retries);
	acm_log(0, "resolve depth %d\n", resolve_depth);
	acm_log(0, "send depth %d\n", send_depth);
	acm_log(0, "receive depth %d\n", recv_depth);
	acm_log(0, "minimum mtu %d\n", min_mtu);
	acm_log(0, "minimum rate %d\n", min_rate);
	acm_log(0, "route preload %d\n", route_preload);
	acm_log(0, "route data file %s\n", route_data_file);
	acm_log(0, "address preload %d\n", addr_preload);
	acm_log(0, "address data file %s\n", addr_data_file);
}

static void __attribute__((constructor)) acmp_init(void)
{
	acmp_set_options();

	acmp_log_options();

	atomic_init(&g_tid);
	atomic_init(&wait_cnt);
	pthread_mutex_init(&acmp_dev_lock, NULL);
	event_init(&timeout_event);

	umad_init();

	acm_log(1, "starting timeout/retry thread\n");
	if (pthread_create(&retry_thread_id, NULL, acmp_retry_handler, NULL)) {
		acm_log(0, "Error: failed to create the retry thread");
		retry_thread_started = 0;
		return;
	}

	acmp_initialized = 1;
}

int provider_query(struct acm_provider **provider, uint32_t *version)
{
	acm_log(1, "\n");

	if (!acmp_initialized)
		return -1;

	if (provider)
		*provider = &def_prov;
	if (version)
		*version = ACM_PROV_VERSION;

	return 0;
}

