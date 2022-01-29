/*
 * RDMA Infiniband to ROCE Bridge or Gateway
 *
 * (C) 2021-2022 Christoph Lameter <cl@linux.com>
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
 * $Author: Christoph Lameter [cl@linux.com]$
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <rdma/rdma_cma.h>
#include <infiniband/ib.h>
#include <infiniband/verbs.h>
#include <poll.h>

#include <linux/rtnetlink.h>

#include "errno.c"

#define VERSION "2022.0125"

#define MIN(a,b) (((a)<(b))?(a):(b))

/* Globals */

static unsigned default_port = 4711;		/* Port to use to bind to devices and for MC groups that do not have a port (if a port is required) */
static bool debug = false;			/* Stay in foreground, print more details */
static bool terminated = false;		/* Daemon received a signal to terminate */
static bool update_requested = false;	/* Received SIGUSR1. Dump all MC data details */
static bool beacon = false;		/* Announce our presence (and possibly coordinate between multiple instances in the future */
static bool bridging = true;		/* Allow briding */
static bool unicast = false;		/* Bridge unicast packets */

/*
 * Handling of special Multicast Group MGID encodings on Infiniband
 */
#define nr_mgid_signatures 4

struct mgid_signature {		/* Manage different MGID formats used */
	unsigned short signature;
	const char *id;
	bool port;		/* Port field is used in MGID */
	bool full_ipv4;	/* Full IP address */
	bool pkey;		/* Pkey in MGID */
} mgid_signatures[nr_mgid_signatures] = {
	{	0x401B,	"IPv4",	false, false, true },
	{	0x601B,	"IPv6",	false, false, true },
	{	0xA01B,	"CLLM", true, true, false },
	{	0x4001, "IB",	false, false, false }
};

struct mgid_signature *mgid_mode;

/*
 * Basic RDMA interface management
 */

#define MAX_GID 20
#define MAX_INLINE_DATA 64

static char *ib_name, *roce_name;

enum interfaces { INFINIBAND, ROCE, NR_INTERFACES };

static const char *interfaces_text[NR_INTERFACES] = { "Infiniband", "ROCE" };

enum stats { packets_received, packets_sent, packets_bridged,
		join_requests, join_failure, join_success,
	        leave_requests,
		nr_stats
};

static const char *stats_text[nr_stats] = {
	"PacketsReceived", "PacketsSent", "PacketsBridged",
	"JoinRequests", "JoinFailures", "JoinSuccess",
	"LeaveRequests"
};

static int cq_high = 0;	/* Largest batch of CQs encountered */

struct rdma_channel {
	struct i2r_interface *i;
	struct ibv_cq *cq;
	struct ibv_pd *pd;
	struct ibv_mr *mr;
	unsigned int active_receive_buffers;
	unsigned int nr_cq;
	unsigned long stats[nr_stats];
	bool rdmacm;
	char *text;
	union {
		struct { /* RDMACM status */
			struct rdma_cm_id *id;
			struct sockaddr_in bindaddr;
		};
		struct { /* Basic RDMA channel without RDMACM */
			struct ibv_qp *qp;
			struct ibv_qp_attr attr;
		};
	};
};

static struct i2r_interface {
	struct ibv_context *context;
	struct rdma_event_channel *rdma_events;
	struct ibv_comp_channel *comp_events;
	struct rdma_channel *multicast;
	struct rdma_channel *raw;
	unsigned port;
	unsigned mtu;
	unsigned maclen;
	char if_name[IFNAMSIZ];
	struct sockaddr_in if_addr;
	struct sockaddr_in if_netmask;
	unsigned ifindex;
	unsigned gid_index;
	union ibv_gid gid;
	struct ibv_device_attr device_attr;
	struct ibv_port_attr port_attr;
	int iges;
	struct ibv_gid_entry ige[MAX_GID];
} i2r[NR_INTERFACES];

static inline void st(struct rdma_channel *c, enum stats s)
{
	c->stats[s]++;
}

static inline struct rdma_cm_id *id(enum interfaces i)
{
	return i2r[i].multicast->id;
}

/* Check the RDMA device if it fits what was specified on the command line and store it if it matches */
static int check_rdma_device(enum interfaces i, int port, char *name,
	       struct ibv_context *c, struct ibv_port_attr *a, struct ibv_device_attr *d)
{
	char *s;
	int p = 1;

	if (i2r[i].context)
		/* Already found a match */
		return 0;

	if (!name)
		/* No command line option, take the first port/device */
		goto success;

	/* Port / device specified */
	s = strchrnul(name,':');
	if (*s)
		/* Portnumber follows device name */
		p = atoi(s + 1);

	if (strncmp(name, ibv_get_device_name(c->device), s - name))
		return 0;

	if (port != p)
		return 0;

success:
	if (a->active_mtu == IBV_MTU_4096)
		i2r[i].mtu = 4096;
	else if (a->active_mtu == IBV_MTU_2048)
		i2r[i].mtu = 2048;
	else
		/* Other MTUs are not supported */
		return 0;

	i2r[i].context = c;
	i2r[i].port = port;
	i2r[i].port_attr = *a;
	i2r[i].device_attr = *d;
	return 1;
}

/* Scan through available RDMA devices in order to locate the devices for bridging */
static int find_rdma_devices(void)
{
	int nr;
	int i;
	struct ibv_device **list;

	list = ibv_get_device_list(&nr);

	if (nr <= 0) {
		syslog(LOG_CRIT, "No RDMA devices present.\n");
		return 1;
	}

	for (i = 0; i < nr; i++) {
		struct ibv_device *d = list[i];
		struct ibv_context *c;
		struct ibv_device_attr dattr;
		int found = 0;
		int port;

		if (d->node_type != IBV_NODE_CA)
			continue;

		if (d->transport_type != IBV_TRANSPORT_IB)
			continue;

		c = ibv_open_device(d);
		if (!c) {
			syslog(LOG_CRIT, "Cannot open device %s\n", ibv_get_device_name(d));
			return 1;
		}

		if (ibv_query_device(c, &dattr)) {
			syslog(LOG_CRIT, "Cannot query device %s\n", ibv_get_device_name(d));
			return 1;
		}

		for (port = 1; port <= dattr.phys_port_cnt; port++) {
			struct ibv_port_attr attr;

			if (ibv_query_port(c, port, &attr)) {
				syslog(LOG_CRIT, "Cannot query port %s:%d\n", ibv_get_device_name(d), port);
				return 1;
			}

			if (attr.link_layer == IBV_LINK_LAYER_INFINIBAND) {
				if (check_rdma_device(INFINIBAND, port, ib_name, c, &attr, &dattr) &&
					(!i2r[ROCE].mtu || i2r[ROCE].mtu == i2r[INFINIBAND].mtu))
					found = 1;

			} else if (attr.link_layer == IBV_LINK_LAYER_ETHERNET) {
				if (check_rdma_device(ROCE, port, roce_name, c, &attr, &dattr) &&
					(!i2r[INFINIBAND].mtu || i2r[ROCE].mtu == i2r[INFINIBAND].mtu))
					found = 1;
			}
		}

		if (!found)
			ibv_close_device(c);
	}


	ibv_free_device_list(list);


	if (!i2r[ROCE].context) {

		if (roce_name[0] == '-')
			bridging = false;
		else {
			if (roce_name)
				syslog(LOG_CRIT, "ROCE device %s not found\n", roce_name);
			else
				syslog(LOG_CRIT,  "No ROCE device available.\n");

			return 1;
		}
	}

	if (!i2r[INFINIBAND].context) {

		if (ib_name[0] == '-' && i2r[ROCE].context)
			bridging = false;
		else {
			if (ib_name)
				syslog(LOG_CRIT, "Infiniband device %s not found.\n", ib_name);
			else
				syslog(LOG_CRIT, "No Infiniband device available.\n");

			return 1;
		}
	}
	return 0;
}

/*
 * Multicast Handling
 */
#define MAX_MC 500

static unsigned nr_mc;
static unsigned active_mc;	/* MC groups actively briding */

struct ah_info {
	struct ibv_ah *ah;
	unsigned remote_qpn;
	unsigned remote_qkey;
};

enum mc_status { MC_OFF, MC_JOINING, MC_JOINED, MC_ERROR, NR_MC_STATUS };

const char *mc_text[NR_MC_STATUS] = { "Inactive", "Joining", "Joined", "Error" };

static struct mc {
	struct in_addr addr;
	enum mc_status status[2];
	bool sendonly[2];
	bool beacon;
	struct ah_info ai[2];
	struct mc *next;	/* For the hash */
	struct sockaddr *sa[2];
	struct mgid_signature *mgid_mode;
	const char *text;
} mcs[MAX_MC];

/*
 * Lookup of IP / Port via Hashes based on the IPv4 Multicast address.
 * Only 24 bits distinguish the Multicast address so ignore the
 * highest 8 bits
 */
static struct mc *mc_hash[0x100];

static unsigned ip_hash(unsigned a)
{
	unsigned low = a & 0xff;
	unsigned middle = (a & 0xff00) >> 8;
	unsigned high = (a & 0xff0000) >> 16;

	return (low + middle + high) & 0xff;
}

static struct mc *__hash_lookup_mc(struct in_addr addr, unsigned index)
{
	struct mc *p = mc_hash[index];

	while (p && (addr.s_addr != p->addr.s_addr))
		p = p->next;

	return p;
}

static struct mc *hash_lookup_mc(struct in_addr addr)
{
	unsigned a = ntohl(addr.s_addr) | 0xe0000000; /* Infiniband may strip top 4 bits so provide them */
	struct in_addr x = {
		.s_addr = htonl(a)
	};
	unsigned index = ip_hash(a);

	return __hash_lookup_mc(x, index);
}

static int hash_add_mc(struct mc *m)
{
	unsigned a = htonl(m->addr.s_addr);
	unsigned index = ip_hash(a);

	if (__hash_lookup_mc(m->addr, index))
		return -EEXIST;

	m->next = mc_hash[index];
	mc_hash[index] = m;
	return 0;
}

static struct mgid_signature *find_mgid_mode(char *p)
{
	struct mgid_signature *g;

	for(g = mgid_signatures; g < mgid_signatures + nr_mgid_signatures; g++)
		if (strcasecmp(p, g->id) == 0)
			break;

	if (g >= mgid_signatures + nr_mgid_signatures) {
		fprintf(stderr, "Not a valid mgid mode %s\n", p);
		return NULL;
	}
	return g;
}

/* Multicast group specifications on the command line */
static int new_mc_addr(char *arg,
	bool sendonly_infiniband,
	bool sendonly_roce)
{
	struct addrinfo *res;
	char *service;
	const struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP
	};
	struct sockaddr_in *si;
	struct mc *m = mcs + nr_mc;
	char *p;
	int ret;

	if (nr_mc == MAX_MC) {
		fprintf(stderr, "Too many multicast groups\n");
		return 1;
	}

	m->sendonly[INFINIBAND] = sendonly_infiniband;
	m->sendonly[ROCE] = sendonly_roce;
	m->text = strdup(arg);

	service = strchr(arg, ':');

	if (service) {

		*service++ = 0;
		p = service;

	} else {
		char *s = alloca(10);

		snprintf(s, 10, "%d", default_port);
		service = s;
		p = arg;
	}

	p = strchr(p, '/');
	if (p) {
		*p++ = 0;
		m->mgid_mode = find_mgid_mode(p);

		if (!m->mgid_mode)
			return -EINVAL;
	} else
		m->mgid_mode = mgid_mode;

	ret = getaddrinfo(arg, service, &hints, &res);
	if (ret) {
		fprintf(stderr, "getaddrinfo() failed (%s) - invalid IP address.\n", gai_strerror(ret));
		return ret;
	}

	ret = 1;

	si = (struct sockaddr_in *)res->ai_addr;

	m->addr = si->sin_addr;
	if (!IN_MULTICAST(ntohl(m->addr.s_addr))) {
		fprintf(stderr, "Not a multicast address (%s)\n", arg);
		goto out;
	}

	ret = hash_add_mc(m);
	if (ret) {
		fprintf(stderr, "Duplicate multicast address (%s)\n", arg);
		goto out;
	}

	m->sa[ROCE] = malloc(sizeof(struct sockaddr_in));
	memcpy(m->sa[ROCE], si, sizeof(struct sockaddr_in));
	m->sa[INFINIBAND] = m->sa[ROCE];

	if (m->mgid_mode) {
		/*
		 * MGID is build according to according to RFC 4391 Section 4
		 * by taking 28 bits and putting them into the mgid
		 *
		 * But then CLLM and others include the full 32 bit...
		 * Deal with this crappy situation.
		 */
		struct sockaddr_ib *saib	= calloc(1, sizeof(struct sockaddr_ib));
		unsigned short *mgid_header	= (unsigned short *)saib->sib_addr.sib_raw;
		unsigned short *mgid_signature	= (unsigned short *)(saib->sib_addr.sib_raw + 2);
		unsigned short *mgid_pkey	= (unsigned short *)(saib->sib_addr.sib_raw + 4);
		unsigned short *mgid_port	= (unsigned short *)(saib->sib_addr.sib_raw + 10);
		unsigned int *mgid_ipv4		= (unsigned int *)(saib->sib_addr.sib_raw + 12);
		unsigned int multicast = ntohl(m->addr.s_addr);
		struct mgid_signature *mg = m->mgid_mode;

		saib->sib_family = AF_IB,
		saib->sib_sid = si->sin_port;

		*mgid_header = htons(0xff15);
		*mgid_signature = htons(mg->signature);

		if (mg->pkey)
			*mgid_pkey = id(INFINIBAND)->route.addr.addr.ibaddr.pkey;

		if (mg->port)
			*mgid_port = si->sin_port;

		if (!mg->full_ipv4)
			/* Strip to 28 bits according to RFC */
			multicast &= 0x0fffffff;

		*mgid_ipv4 = htonl(multicast);

		m->sa[INFINIBAND] = (struct sockaddr *)saib;
	}


	nr_mc++;
	ret = 0;

out:

	freeaddrinfo(res);
	return ret;
}

static int _join_mc(struct in_addr addr, struct sockaddr *sa,
				unsigned port,enum interfaces i,
				bool sendonly, void *private)
{
	struct rdma_cm_join_mc_attr_ex mc_attr = {
		.comp_mask = RDMA_CM_JOIN_MC_ATTR_ADDRESS | RDMA_CM_JOIN_MC_ATTR_JOIN_FLAGS,
		.join_flags = sendonly ? RDMA_MC_JOIN_FLAG_SENDONLY_FULLMEMBER
                                       : RDMA_MC_JOIN_FLAG_FULLMEMBER,
		.addr = sa
	};
	int ret;

	ret = rdma_join_multicast_ex(id(i), &mc_attr, private);

	if (ret) {
		syslog(LOG_ERR, "Failed to create join request %s:%d on %s. Error %s\n",
			inet_ntoa(addr), port,
			interfaces_text[i],
			errname());
		return 1;
	}
	syslog(LOG_NOTICE, "Join Request %sMC group %s:%d on %s .\n",
		sendonly ? "Sendonly " : "",
		inet_ntoa(addr), port,
		interfaces_text[i]);
	st(i2r[i].multicast, join_requests);
	return 0;
}

static int _leave_mc(struct in_addr addr,struct sockaddr *si, enum interfaces i)
{
	int ret;

	ret = rdma_leave_multicast(id(i), si);
	if (ret) {
		perror("Failure to leave");
		return 1;
	}
	syslog(LOG_NOTICE, "Leaving MC group %s on %s .\n",
		inet_ntoa(addr),
		interfaces_text[i]);
	st(i2r[i].multicast, leave_requests);
	return 0;
}

static int leave_mc(enum interfaces i)
{
	int j;
	int ret;

	for (j = 0; j < nr_mc; j++) {
		struct mc *m = mcs + j;

		ret = _leave_mc(m->addr, m->sa[i], i);
		if (ret)
			return 1;
	}
	return 0;
}

/*
 * Manage freelist using simple single linked list with the pointer
 * to the next free element at the beginning of the free buffer
 */

// static const unsigned buf_size = 4096;
// static const unsigned nr_buffers = 20000;

#define buf_size 4096
#define nr_buffers 20000

struct buf {
	struct buf *next;	/* Next buffer */
	bool free;
	/* Add more metadata here */
	struct ibv_grh grh;	/* GRH header as included in UD connections */
	uint8_t payload[buf_size];	/* I wish this was page aligned at some point */
};

static void beacon_received(struct buf *buf);

static struct buf buffers[nr_buffers];

static struct buf *nextbuffer;	/* Pointer to next available RDMA buffer */

static void free_buffer(struct buf *buf)
{
	buf->free = true;
	buf->next = nextbuffer;
	nextbuffer = buf;
}

static void init_buf(void)
{
	int i;

	/*
	 * Free in reverse so that we have a linked list
	 * starting at the first element which points to
	 * the second and so on.
	 */
	for (i = nr_buffers; i > 0; i--)
		free_buffer(&buffers[i-1]);
}

static struct buf *alloc_buffer(void)
{
	struct buf *buf = nextbuffer;

	if (buf) {
		nextbuffer = buf->next;
		buf->free = false;
	}

	return buf;
}


/*
 * Handling of RDMA work requests
 */
static int post_receive(struct rdma_channel *c, int limit)
{
	struct ibv_recv_wr recv_wr, *recv_failure;
	struct ibv_sge sge;
	int ret = 0;

	if (!nextbuffer || c->active_receive_buffers >= limit)
		return -EAGAIN;

	recv_wr.next = NULL;
	recv_wr.sg_list = &sge;
	recv_wr.num_sge = 1;

	sge.length = c->i->mtu + sizeof(struct ibv_grh);
	sge.lkey = c->mr->lkey;

	while (c->active_receive_buffers < limit) {

		struct buf *buf = alloc_buffer();


		if (!buf) {
			syslog(LOG_NOTICE, "No free buffers left\n");
			ret = -ENOMEM;
			break;
		}

		/* Use the buffer address for the completion handler */
		recv_wr.wr_id = (uint64_t)buf;
		sge.addr = (uint64_t)&buf->grh;
		ret = ibv_post_recv(c->qp, &recv_wr, &recv_failure);
		if (ret) {
			free_buffer(buf);
			syslog(LOG_WARNING, "ibv_post_recv failed: %d\n", ret);
			break;
                }
		c->active_receive_buffers++;
	}
	return ret;
}

static int post_receive_buffers(struct i2r_interface *i)
{
	int ret = 0;

	if (!nextbuffer)
		return -EAGAIN;

	ret = post_receive(i->multicast, i->multicast->nr_cq / 2);
	if (i->raw && !ret)
		ret = post_receive(i->raw, 100);

	return ret;
}


static void channel_destroy(struct rdma_channel *c)
{
	if (!c)
		return;

	if (c->rdmacm) {

		if (c->qp)
			rdma_destroy_qp(c->id);

		if (c->cq)
			ibv_destroy_cq(c->cq);

		ibv_dereg_mr(c->mr);
		if (c->pd)
			ibv_dealloc_pd(c->pd);

		rdma_destroy_id(c->id);
	} else {
		ibv_destroy_qp(c->qp);

		if (c->cq)
			ibv_destroy_cq(c->cq);
	
		ibv_dereg_mr(c->mr);
		if (c->pd)
			ibv_dealloc_pd(c->pd);

	}
	free(c);
}

static void qp_destroy(struct i2r_interface *i)
{
	channel_destroy(i->multicast);
	i->multicast = NULL;
	channel_destroy(i->raw);
	i->raw = NULL;

}

/* Retrieve Kernel Stack info about the interface */
static void get_if_info(struct i2r_interface *i)
{
	int fh = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	struct ifreq ifr;

	if (fh < 0)
		goto err;

	/*
	 * Work around the quirk of ifindex always being zero for
	 * INFINIBAND interfaces. Just assume its ib0.
	 */
	if (!i->ifindex && i - i2r == INFINIBAND) {

		syslog(LOG_WARNING, "Assuming ib0 is the IP device name for %s\n",
		     ibv_get_device_name(i->context->device));
		strcpy(i->if_name, "ib0");

		memcpy(ifr.ifr_name, i->if_name, IFNAMSIZ);

		/* Find if_index */
		if (ioctl(fh, SIOCGIFINDEX, &ifr) < 0)
			goto err;

		i->ifindex = ifr.ifr_ifindex;

	} else {

		ifr.ifr_ifindex = i->ifindex;

		if (ioctl(fh, SIOCGIFNAME, &ifr) < 0)
			goto err;

		memcpy(i->if_name, ifr.ifr_name, IFNAMSIZ);
	}

	if (ioctl(fh, SIOCGIFADDR, &ifr) < 0)
		goto err;

	memcpy(&i->if_addr, &ifr.ifr_addr, sizeof(struct sockaddr_in));

	ioctl(fh, SIOCGIFNETMASK, &ifr);
	memcpy(&i->if_netmask, &ifr.ifr_netmask, sizeof(struct sockaddr_in));
	goto out;

err:
	syslog(LOG_CRIT, "Cannot determine IP interface setup for %s",
		     ibv_get_device_name(i->context->device));

	abort();

out:
	close(fh);
}

static void start_channel(struct rdma_channel *c)
{
	if (c->rdmacm) {
		/* kick off if necessary */
	} else {
		int ret;

		c->attr.qp_state = IBV_QPS_RTR;
		ret = ibv_modify_qp(c->qp, &c->attr, IBV_QP_STATE);
		if (ret) {
			errno = -ret;
			syslog(LOG_CRIT, "ibv_modify_qp: Error when moving to RTR state. %s", errname());
		}

		c->attr.qp_state = IBV_QPS_RTS;
		ret = ibv_modify_qp(c->qp, &c->attr, IBV_QP_STATE);
		if (ret) {
			errno = -ret;
			syslog(LOG_CRIT, "ibv_modify_qp: Error when moving to RTS state. %s", errname());
		}
	}
}

static struct rdma_channel *setup_channel(struct i2r_interface *i, const char *text, int rdmacm,
		struct in_addr addr, unsigned port, unsigned qp_type, unsigned nr_cq, unsigned create_flags)
{
	struct rdma_channel *c = calloc(1, sizeof(struct rdma_channel));
	enum interfaces in = i - i2r;
	struct ibv_qp_init_attr_ex init_qp_attr_ex;
	int ret;
	struct ibv_context *context = i->context;

	c->i = i;
	c->rdmacm = rdmacm;
	asprintf(&c->text, "%s-%s", interfaces_text[in], text);

	if (rdmacm) {
		c->bindaddr.sin_family = AF_INET;
		c->bindaddr.sin_addr = addr;
		c->bindaddr.sin_port = htons(port);

		ret = rdma_create_id(i->rdma_events, &c->id, c, RDMA_PS_UDP);
		if (ret) {
			syslog(LOG_CRIT, "Failed to allocate RDMA CM ID for %s failed (%s).\n",
				interfaces_text[in], errname());
			return NULL;
		}

		ret = rdma_bind_addr(c->id, (struct sockaddr *)&c->bindaddr);
		if (ret) {
			syslog(LOG_CRIT, "Failed to bind %s interface. Error %s\n",
				interfaces_text[in], errname());
			return NULL;
		}
		context = c->id->verbs;
	}

	/*
	 * Must alloc pd for each rdma_cm_id due to limitation in rdma_create_qp
	 * There a multiple struct ibv_context *s around . Need to use the right one
	 * since rdma_create_qp validates the alloc pd ibv_context pointer.
	 */
	c->pd = ibv_alloc_pd(context);
	if (!c->pd) {
		syslog(LOG_CRIT, "ibv_alloc_pd failed for %s.\n",
			interfaces_text[in]);
		return NULL;
	}

	c->nr_cq = nr_cq;
	c->cq = ibv_create_cq(context, nr_cq, i, i->comp_events, 0);
	if (!c->cq) {
		syslog(LOG_CRIT, "ibv_create_cq failed for %s.\n",
			interfaces_text[in]);
		return NULL;
	}

	memset(&init_qp_attr_ex, 0, sizeof(init_qp_attr_ex));
	init_qp_attr_ex.cap.max_send_wr = nr_cq;
	init_qp_attr_ex.cap.max_recv_wr = nr_cq;
	init_qp_attr_ex.cap.max_send_sge = 1;	/* Highly sensitive settings that can cause -EINVAL if too large (10 f.e.) */
	init_qp_attr_ex.cap.max_recv_sge = 1;
	init_qp_attr_ex.cap.max_inline_data = MAX_INLINE_DATA;
	init_qp_attr_ex.qp_context = c;
	init_qp_attr_ex.sq_sig_all = 0;
	init_qp_attr_ex.qp_type = qp_type;
	init_qp_attr_ex.send_cq = c->cq;
	init_qp_attr_ex.recv_cq = c->cq;

	init_qp_attr_ex.comp_mask = IBV_QP_INIT_ATTR_CREATE_FLAGS|IBV_QP_INIT_ATTR_PD;
	init_qp_attr_ex.pd = c->pd;
	init_qp_attr_ex.create_flags = create_flags;

	if (rdmacm) {
		ret = rdma_create_qp_ex(c->id, &init_qp_attr_ex);
		if (ret) {
			syslog(LOG_CRIT, "rdma_create_qp_ex failed for %s. Error %s. IP=%s Port=%d QP_TYPE=%d CREATE_FLAGS=%x #CQ=%d\n",
					c->text, errname(), inet_ntoa(addr), port,
					qp_type, create_flags, nr_cq);
			return NULL;
		}

		/* Copy to convenient location that is shared by both types of channels */
		c->qp = c->id->qp;
	} else {
		c->qp = ibv_create_qp_ex(context, &init_qp_attr_ex);
		if (!c->qp)
			syslog(LOG_CRIT, "ibv_create_qp_ex failed for %s. Error %s. Port=%d QP_TYPE=%d CREATE_FLAGS=%x #CQ=%d\n",
					c->text, errname(), port,
					qp_type, create_flags, nr_cq);
			return NULL;

		c->attr.port_num = port;
		c->attr.qp_state = IBV_QPS_INIT;
		ret = ibv_modify_qp(c->qp, &c->attr, IBV_QP_STATE | IBV_QP_PORT);
		if (ret < 0) {
			syslog(LOG_CRIT, "ibv_modify_qp: Error when moving to Init state. %s", errname());
			return NULL;
		}
	}

	c->mr = ibv_reg_mr(c->pd, buffers, nr_buffers * sizeof(struct buf), IBV_ACCESS_LOCAL_WRITE);
	if (!c->mr) {
		syslog(LOG_CRIT, "ibv_reg_mr failed for %s.\n", c->text);
		return NULL;
	}
	return c;
}

static void setup_interface(enum interfaces in)
{
	struct i2r_interface *i = i2r + in;
	struct ibv_gid_entry *e;
	char buf[INET6_ADDRSTRLEN];

	if (in == INFINIBAND) {
		i->maclen = 20;
	} else {
		i->maclen = 6;
	}

	if (!i->context)
		return;

	/* Determine the GID */
	i->iges = ibv_query_gid_table(i->context, i->ige, MAX_GID, 0);

	if (!i->iges) {
		syslog(LOG_CRIT, "Failed to obtain GID table for %s\n",
			interfaces_text[in]);
		abort();
	}

	/* Find the correct gid entry */
	for (e = i->ige; e < i->ige + i->iges; e++) {

		if (e->port_num != i->port)
			continue;

		if (e->gid_type == IBV_GID_TYPE_IB && in == INFINIBAND)
			break;

		if (e->gid_type == IBV_GID_TYPE_ROCE_V2 && in == ROCE)
			break;
	}

	if (e >= i->ige + i->iges) {
		syslog(LOG_CRIT, "Failed to find GIDs in GID table for %s\n",
			interfaces_text[in]);
		abort();
	}

	/* Copy our connection info from GID table */
	i->gid = e->gid;
	i->gid_index = e->gid_index;
	i->ifindex = e->ndev_ifindex;

	/* Get more info about the IP network attached to the RDMA device */
	get_if_info(i);

	/* Create RDMA interface setup */
	i->rdma_events = rdma_create_event_channel();
	if (!i->rdma_events) {
		syslog(LOG_CRIT, "rdma_create_event_channel() for %s failed (%s).\n",
			interfaces_text[in], errname());
		abort();
	}

	i->comp_events = ibv_create_comp_channel(i->context);
	if (!i->comp_events) {
		syslog(LOG_CRIT, "ibv_create_comp_channel failed for %s.\n",
			interfaces_text[in]);
		abort();
	}

	i->multicast = setup_channel(i, "multicast", true, i->if_addr.sin_addr, default_port, IBV_QPT_UD,
				MIN(i->device_attr.max_cqe, nr_buffers / 2),
				IBV_QP_CREATE_BLOCK_SELF_MCAST_LB);

	if (!i->multicast)
		abort();

	i->raw = setup_channel(i, "raw", false, i->if_addr.sin_addr, i->port, IBV_QPT_RAW_PACKET, 100, 0);

	syslog(LOG_NOTICE, "%s interface %s/%s(%d) port %d GID=%s/%d IPv4=%s CQs=%u MTU=%u ready.\n",
		interfaces_text[in],
		ibv_get_device_name(i->context->device),
		i->if_name, i->ifindex,
		i->port,
		inet_ntop(AF_INET6, e->gid.raw, buf, INET6_ADDRSTRLEN),i->gid_index,
		inet_ntoa(i->if_addr.sin_addr),
		i->multicast->nr_cq,
		i->mtu
	);
}

static void shutdown_ib(void)
{
	if (!i2r[INFINIBAND].context)
		return;

	leave_mc(INFINIBAND);

	/* Shutdown Interface */
	qp_destroy(i2r + INFINIBAND);
}

static void shutdown_roce(void)
{
	if (!i2r[ROCE].context)
		return;

	leave_mc(ROCE);

	/* Shutdown Interface */
	qp_destroy(i2r + ROCE);
}

/*
 * Join MC groups. This is called from the event loop every second
 * as long as there are unjoined groups
 */
static void join_processing(void)
{
	int i;
	enum interfaces in;
	int mcs_per_call = 0;

	for (i = 0; i < nr_mc; i++) {
		struct mc *m = mcs + i;
		unsigned port = ntohs(((struct sockaddr_in *)(m->sa[ROCE]))->sin_port);

		if (m->status[ROCE] == MC_JOINED && m->status[INFINIBAND] == MC_JOINED)
			continue;

		for(in = 0; in < 2; in++)
			switch(m->status[in]) {

			case MC_OFF:
				if (_join_mc(m->addr, m->sa[in], port, in, m->sendonly[in], m) == 0)
					m->status[in] = MC_JOINING;
				break;

			case MC_ERROR:

				_leave_mc(m->addr, m->sa[in], in);
				m->status[in] = MC_OFF;
				syslog(LOG_WARNING, "Left Multicast group %s on %s due to MC_ERROR\n",
						m->text, interfaces_text[in]);
				break;

			case MC_JOINED:
				break;

			default:
				syslog(LOG_ERR, "Bad MC status %d MC %s on %s\n",
					       m->status[in], m->text, interfaces_text[in]);
				break;
		}

		mcs_per_call++;

		if (mcs_per_call > 10)
			break;

	}
}

static void handle_rdma_event(enum interfaces in)
{
	struct rdma_cm_event *event;
	int ret;
	struct i2r_interface *i = i2r + in;

	ret = rdma_get_cm_event(i->rdma_events, &event);
	if (ret) {
		syslog(LOG_WARNING, "rdma_get_cm_event()_ failed. Error = %s\n", errname());
		return;
	}

	switch(event->event) {
		/* Connection events */
		case RDMA_CM_EVENT_MULTICAST_JOIN:
			{
				struct rdma_ud_param *param = &event->param.ud;
				struct mc *m = (struct mc *)param->private_data;
				struct ah_info *a = m->ai + in;
				char buf[40];

				a->remote_qpn = param->qp_num;
				a->remote_qkey = param->qkey;
				a->ah = ibv_create_ah(i->multicast->pd, &param->ah_attr);
				if (!a->ah) {
					syslog(LOG_ERR, "Failed to create AH for Multicast group %s on %s \n",
						m->text, interfaces_text[in]);
					m->status[in] = MC_ERROR;
					break;
				}
				m->status[in] = MC_JOINED;

				/* Things actually work if both multicast groups are joined */
				if (!bridging || m->status[in ^ 1] == MC_JOINED)
					active_mc++;

				syslog(LOG_NOTICE, "Joined %s MLID 0x%x sl %u on %s\n",
					inet_ntop(AF_INET6, param->ah_attr.grh.dgid.raw, buf, 40),
					param->ah_attr.dlid,
					param->ah_attr.sl,
					interfaces_text[in]);
				st(i->multicast, join_success);
			}
			break;

		case RDMA_CM_EVENT_MULTICAST_ERROR:
			{
				struct rdma_ud_param *param = &event->param.ud;
				struct mc *m = (struct mc *)param->private_data;

				syslog(LOG_ERR, "Multicast Error. Group %s on %s\n",
					m->text, interfaces_text[in]);

				/* If already joined then the bridging may no longer work */
				if (!bridging || (m->status[in] == MC_JOINED && m->status[in ^ 1] == MC_JOINED))
				       active_mc--;

				m->status[in] = MC_ERROR;
				st(i->multicast, join_failure);
			}
			break;

		case RDMA_CM_EVENT_ADDR_RESOLVED:
			syslog(LOG_ERR, "Unexpected event ADDR_RESOLVED\n");
			break;

		/* Disconnection events */
		case RDMA_CM_EVENT_ADDR_ERROR:
		case RDMA_CM_EVENT_ROUTE_ERROR:
		case RDMA_CM_EVENT_ADDR_CHANGE:
			syslog(LOG_ERR, "RDMA Event handler:%s status: %d\n",
				rdma_event_str(event->event), event->status);
			break;
		default:
			syslog(LOG_NOTICE, "RDMA Event handler:%s status: %d\n",
				rdma_event_str(event->event), event->status);
			break;
	}

	rdma_ack_cm_event(event);
}

/*
 * Do not use a buffer but simply include data directly into WR.
 * Advantage: No buffer used and therefore faster since no memory
 * fetch has to be done by the RDMA subsystem and no completion
 * event has to be handled.
 *
 * Space in the WR is limited, so it only works for very small packets.
 */
static int send_inline(struct rdma_channel *c, void *buf, unsigned len, struct ah_info *ai, int port)
{
	struct ibv_sge sge = {
		.length = len,
		.addr = (uint64_t)buf
	};
	struct ibv_send_wr wr = {
		.sg_list = &sge,
		.num_sge = 1,
		.opcode = IBV_WR_SEND_WITH_IMM,
		.send_flags = IBV_SEND_INLINE,
		.imm_data = htobe32(c->qp->qp_num),
		.wr = {
			/* Get addr info  */
			.ud = {
				.ah = ai->ah,
				.remote_qpn = ai->remote_qpn,
				.remote_qkey = ai->remote_qkey
			}
		}

	};
	struct ibv_send_wr *bad_send_wr;
	int ret;

	if (len > MAX_INLINE_DATA)
		return -E2BIG;

	ret = ibv_post_send(c->qp, &wr, &bad_send_wr);
	if (ret) {
		errno = -ret;
		syslog(LOG_WARNING, "Failed to post inline send: %s on %s\n", errname(), c->text);
	}

	return ret;
}

static int send_buf(struct rdma_channel *c, struct buf *buf, unsigned len, struct ah_info *ai, int port)
{
	struct ibv_send_wr wr, *bad_send_wr;
	struct ibv_sge sge;
	int ret;

	memset(&wr, 0, sizeof(wr));
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.opcode = IBV_WR_SEND_WITH_IMM;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.wr_id = (uint64_t)buf;
	wr.imm_data = htobe32(c->qp->qp_num);

	/* Get addr info  */
	wr.wr.ud.ah = ai->ah;
	wr.wr.ud.remote_qpn = ai->remote_qpn;
	wr.wr.ud.remote_qkey = ai->remote_qkey;

	sge.length = len;
	sge.lkey = c->mr->lkey;
	sge.addr = (uint64_t)buf->payload;

	ret = ibv_post_send(c->qp, &wr, &bad_send_wr);
	if (ret) {
		errno = - ret;
		syslog(LOG_WARNING, "Failed to post send: %s on %s\n", errname(), c->text);
	}

	return ret;
}

#define ROCE_PORT 4791

#if 0
static int sysfs_read_int(const char *s)
{
	int fh = open(s, O_RDONLY);
	static char b[10];
	if (fh < 2)
		return -1;

	if (read(fh, b, 10) < 1) {
		close(fh);
		return -1;
	}

	close(fh);

	return atoi(b);
}
#endif

/* Unicast handling */
#define MAX_MACLEN 20

struct rdma_ah {
	struct i2r_interface *i;
	char mac[MAX_MACLEN];
	struct in_addr addr;
	short state;
	short flags;
	struct ibv_ah *ah;
	struct rdma_ah *next_addr;	/* Hash Collision addr hash */
	struct rdma_ah *next_mac;	/* Hash Collision mac hash */
};

struct rdma_ah *hash_addr[0x100];
struct rdma_ah *hash_mac[0x100];

static int nr_rdma_ah = 0;

static unsigned mac_hash(int maclen, char *mac)
{
	int z = 0;
	unsigned hash = mac[z++];

	while (z < maclen)
		hash += mac[z++];

	return hash & 0xff;
}


static struct rdma_ah *hash_addr_lookup(struct in_addr addr, unsigned addr_hash)
{
	struct rdma_ah *ra = hash_addr[addr_hash];

	while (ra && ra->addr.s_addr != addr.s_addr)
		ra = ra->next_addr;

	return ra;
}

static struct rdma_ah *hash_mac_lookup(int maclen, char *mac, unsigned mac_hash)
{
	struct rdma_ah *ra = hash_mac[mac_hash];

	while (ra && memcmp(mac, ra->mac, maclen) != 0)
		ra = ra->next_mac;

	return ra;
}

static char hexbyte(unsigned x)
{
	if (x < 10)
		return '0' + x;

	return x - 10 + 'a';
}

static char *hexbytes(char *x, unsigned len)
{
	uint8_t *q = (uint8_t *)x;
	static char b[100];
	unsigned i;
	char *p = b;

	for(i =0; i < len; i++) {
		unsigned n = *q++;
		*p++ = hexbyte( n >> 4 );
		*p++ = hexbyte( n & 0xf);
		*p++ = ':';
	}
	p--;
	*p = 0;
	return b;
}

static long lookup_ip_from_gid(struct rdma_channel *c, union ibv_gid *v)
{
	struct rdma_ah *ah;

	unsigned hash;
	struct rdma_ah *ra;
	char mac[20];
	char buf[100];

	/* compose macfrom GID etc. Depends on LLM GID use. Not sure how to do it */
	memcpy(mac + 4, &v, 16);

	hash = mac_hash(c->i->maclen, mac);
	ra = hash_mac_lookup(c->i->maclen, mac, hash);
	if (ah)
		return ah->addr.s_addr;

	/*
	 * Could do ARP for GID -> IP resolution but the GID
	 * should be already be in the ARP cache
	 */
	syslog(LOG_ERR, "Could not find AH for %s on %s\n",
		inet_ntop(AF_INET6, v->raw, buf, INET6_ADDRSTRLEN), c->text);

	return 0;
}

/*
 * Netlink interface
 */

enum netlink_channel { nl_monitor, nl_command, nr_netlink_channels };

static struct sockaddr_nl nladdr[nr_netlink_channels];
static int sock_nl[nr_netlink_channels];

struct neigh {
	struct nlmsghdr nlh;
	struct ndmsg nd;
	char	attrbuf[512];
};

static void handle_neigh_event(struct neigh *n)
{
	struct i2r_interface *i;
	int len = n->nlh.nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));
	unsigned maclen = 0;
	struct rtattr *rta;
	bool have_dst = false;
	bool have_lladdr = false;
	struct rdma_ah *ra = calloc(1, sizeof(struct rdma_ah));
	struct rdma_ah *r;
	unsigned ha, hm;
	const char *action = "New";


	for(i = i2r;  i < i2r + NR_INTERFACES; i++)
		if (i->ifindex == n->nd.ndm_ifindex)
			break;

	for(rta = (struct rtattr *)n->attrbuf; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		switch (rta->rta_type) {

			case NDA_DST:
				memcpy(&ra->addr, RTA_DATA(rta), RTA_PAYLOAD(rta));
				have_dst = true;
				break;

			case NDA_LLADDR:
				have_lladdr = true;
				maclen = RTA_PAYLOAD(rta);
				memcpy(&ra->mac, RTA_DATA(rta), maclen);
				break;

			case NDA_CACHEINFO:
			case NDA_PROBES:
				break;

			default:
				syslog(LOG_NOTICE, "Netlink; unrecognized RTA type=%d\n", rta->rta_type);
				break;

		}
	};

	if (i >= i2r + NR_INTERFACES) {
		i = NULL;
		goto err;
	}

	if (!have_dst) {
		syslog(LOG_ERR, "netlink message without DST\n");
		goto err;
	}

	if (!have_lladdr) {
		syslog(LOG_ERR, "netlink message without LLADDR\n");
		goto err;
	}

	if (i->maclen != maclen) {
		syslog(LOG_ERR, "netlink message mac length does not match. Expected %d got %d\n",
				i->maclen, maclen);
		goto err;
	}

	ha = ip_hash(ntohl(ra->addr.s_addr));
	hm = mac_hash(maclen, ra->mac);

	r = hash_mac_lookup(maclen, ra->mac, hm);
	if (r) {
		/* Update existing */
		free(ra);
		ra = r;
		action = "Update";
	}

	ra->flags = n->nd.ndm_flags;
	ra->state = n->nd.ndm_state;

	r = hash_addr_lookup(ra->addr, ha);

	if (r) {
	       if (r != ra)
			syslog(LOG_WARNING, "Duplicate IP address Interface=%s addr=%s\n",
				i->if_name, inet_ntoa(ra->addr));

	}

	ra->next_addr = hash_addr[ha];
	ra->next_mac = hash_mac[hm];

	hash_addr[ha] = ra;
	hash_mac[hm] = ra;
	nr_rdma_ah++;

	syslog(LOG_NOTICE, "%s ARP entry via netlink for %s: IP=%s MAC=%s Flags=%x State=%x\n",
		action,
		i->if_name,
		inet_ntoa(ra->addr),
		hexbytes(ra->mac, maclen),
		ra->flags, ra->state);

	return;

err:
	syslog(LOG_NOTICE, "Neigh Event interface=%s type %u Len=%u NL flags=%x ND flags=%x state=%x IP=%s MAC=%s ifindex=%d\n",
				i ? i->if_name: "N/A",
			       	n->nlh.nlmsg_type,  n->nlh.nlmsg_len, n->nlh.nlmsg_flags,
				n->nd.ndm_flags, n->nd.ndm_state,
				inet_ntoa(ra->addr), hexbytes(ra->mac, maclen),
				n->nd.ndm_ifindex);

	free(ra);
}

static void handle_netlink_event(enum netlink_channel c)
{
	char buf[8192];
	struct nlmsghdr *h = (void *)buf;
	struct sockaddr_nl addr;
	struct iovec iov = { buf, sizeof(buf) };
	struct msghdr msg = { (void *)&addr, sizeof(struct sockaddr_nl), &iov, 1 };
	int len;

	len = recvmsg(sock_nl[c], &msg, 0);
	if (len < 0) {
		syslog(LOG_CRIT, "Netlink recvmsg error. Errno %s\n", errname());
		return;
	}

	for( ; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
		switch(h->nlmsg_type) {
			case RTM_NEWNEIGH:
			case RTM_GETNEIGH:
			case RTM_DELNEIGH:
			    handle_neigh_event((struct neigh *)h);
			    break;

			default:
			    syslog(LOG_NOTICE, "Unhandled Netlink Message type %u Len=%u flag=%x seq=%x PID=%d\n",
					  h->nlmsg_type,  h->nlmsg_len, h->nlmsg_flags, h->nlmsg_seq, h->nlmsg_pid);
			    break;
		}
	}

}

static void send_netlink_message(enum netlink_channel c, struct nlmsghdr *nlh)
{
	struct iovec iov = { (void *)nlh, nlh->nlmsg_len};
	struct msghdr msg = { (void *)&nladdr, sizeof(struct sockaddr_nl), &iov, 1 };
	int ret;

	ret = sendmsg(sock_nl[c], &msg, 0);
	if (ret < 0)
		syslog(LOG_ERR, "Netlink Send error %s\n", errname());
}

static void setup_netlink(enum netlink_channel c)
{
	static struct sockaddr_nl sal = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_NEIGH | RTMGRP_NOTIFY	/* Subscribe to changes to the ARP cache */
	};
	struct {
		struct nlmsghdr nlh;
		struct ndmsg nd;
	} nlr = { {
			.nlmsg_type = RTM_GETNEIGH,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
			.nlmsg_len = sizeof(nlr),
			.nlmsg_seq = time(NULL)
		}, {
			.ndm_family = AF_INET,
			.ndm_state = NUD_REACHABLE
		} };
	
	sock_nl[c] = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (sock_nl[c] < 0) {
		syslog(LOG_CRIT, "Failed to open netlink socket %s.\n", errname());
		abort();
	}

	sal.nl_pid = getpid() + c;
	if (c != nl_monitor)
		sal.nl_groups = 0;

	if (bind(sock_nl[c], (struct sockaddr *)&sal, sizeof(sal)) < 0) {
		syslog(LOG_CRIT, "Failed to bind to netlink socket %s\n", errname());
		abort();
	};

	memcpy(&nladdr[c], &sal, sizeof(struct sockaddr_nl));

	if (c != nl_monitor)
		send_netlink_message(c, &nlr.nlh);
}

static void setup_flow(enum interfaces in)
{
	struct i2r_interface *i = i2r + in;
	struct i2r_interface *di = i2r + (in ^ 1);
	struct ibv_flow *f;
	unsigned netmask = di->if_netmask.sin_addr.s_addr;
	struct {
		struct ibv_flow_attr attr;
		struct ibv_flow_spec_ipv4 ipv4;
		struct ibv_flow_spec_tcp_udp udp;
	} flattr = {
		{
			0, IBV_FLOW_ATTR_ALL_DEFAULT, sizeof(struct ibv_flow_spec),
			1, 2, i->port, 0
		},
		{
			IBV_FLOW_SPEC_IPV4, sizeof(struct ibv_flow_spec_ipv4),
			{ 0, di->if_addr.sin_addr.s_addr & netmask },
			{ 0, netmask }
		},
		{
			IBV_FLOW_SPEC_UDP, sizeof(struct ibv_flow_spec_tcp_udp),
			{ ROCE_PORT, ROCE_PORT},
			{ 0xffff, 0xffff}
		}
	};

	if (!i->raw) {
		syslog(LOG_ERR, "Cannot create flow due to failure to setup RAW QP on %s\n",
				interfaces_text[in]);
		return;
	}

	f = ibv_create_flow(i->raw->id->qp, &flattr.attr);
	if (!f)
		syslog(LOG_ERR, "Failure to create flow on %s. Errno %s\n", interfaces_text[in], errname());
}

static int unicast_packet(struct rdma_channel *c, struct buf *buf, struct in_addr source_addr, struct in_addr dest_addr)
{
	char xbuf[INET6_ADDRSTRLEN];
	char xbuf2[INET6_ADDRSTRLEN];
	enum interfaces in = c->i - i2r;
	unsigned port = 0; /* How do I get that??? Is it needed? */

	if (in == ROCE) {

		unsigned int iaddr = ntohl(i2r[INFINIBAND].if_addr.sin_addr.s_addr);
		unsigned int netmask = ntohl(i2r[INFINIBAND].if_netmask.sin_addr.s_addr);
		unsigned int daddr = ntohl(dest_addr.s_addr);

		if ((daddr & netmask) == (iaddr & netmask)) {
			/* Unicast ROCE packet destined for Infiniband */
			syslog(LOG_NOTICE, "Packet destination Infiniband from %s to %s port %d\n",
				inet_ntop(AF_INET6, &buf->grh.sgid, xbuf2, INET6_ADDRSTRLEN),
				inet_ntop(AF_INET6, &buf->grh.dgid, xbuf, INET6_ADDRSTRLEN),
				port);
		}

	} else {

		unsigned int iaddr = ntohl(i2r[ROCE].if_addr.sin_addr.s_addr);
		unsigned int netmask = ntohl(i2r[ROCE].if_netmask.sin_addr.s_addr);
		unsigned int daddr = ntohl(lookup_ip_from_gid(c, &buf->grh.dgid));

		if ((daddr & netmask) == (iaddr & netmask)) {
			/* Unicast Infiniband packet destined for ROCE */
			syslog(LOG_NOTICE, "Packet destination Roce from %s to %s port %d\n",
				inet_ntop(AF_INET6, &buf->grh.sgid, xbuf2, INET6_ADDRSTRLEN),
				inet_ntop(AF_INET6, &buf->grh.dgid, xbuf, INET6_ADDRSTRLEN),
				port);
		}
	}

	/* Dump GRH and the beginning of the packet */
	syslog(LOG_NOTICE, "Unicast GRH flow=%ux Len=%u next_hdr=%u hop_limit=%u SGID=%s DGID:%s Packet="
	       	"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
		"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
		"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			ntohl(buf->grh.version_tclass_flow), ntohs(buf->grh.paylen), buf->grh.next_hdr, buf->grh.hop_limit,
			inet_ntop(AF_INET6, &buf->grh.sgid, xbuf2, INET6_ADDRSTRLEN),
			inet_ntop(AF_INET6, &buf->grh.dgid, xbuf, INET6_ADDRSTRLEN),
			buf->payload[0], buf->payload[1], buf->payload[2], buf->payload[3],
		        buf->payload[4], buf->payload[5], buf->payload[6], buf->payload[7],
			buf->payload[8], buf->payload[9], buf->payload[10], buf->payload[11],
			buf->payload[12], buf->payload[13], buf->payload[14], buf->payload[15],
			buf->payload[16], buf->payload[17], buf->payload[18], buf->payload[19],
			buf->payload[20], buf->payload[21], buf->payload[22], buf->payload[23],
			buf->payload[24], buf->payload[25], buf->payload[26], buf->payload[27],
			buf->payload[28], buf->payload[29], buf->payload[30], buf->payload[31],
			buf->payload[32], buf->payload[33], buf->payload[34], buf->payload[35],
			buf->payload[36], buf->payload[37], buf->payload[38], buf->payload[39],
			buf->payload[40], buf->payload[41], buf->payload[42], buf->payload[43],
			buf->payload[44], buf->payload[45], buf->payload[46], buf->payload[47]);

	return 1;
}


static int recv_buf(struct rdma_channel *c, struct buf *buf, struct ibv_wc *w)
{
	struct mc *m;
	enum interfaces in = c->i - i2r;
	unsigned len;
	struct ib_addr *sgid = (struct ib_addr *)&buf->grh.sgid.raw;
	struct ib_addr *dgid = (struct ib_addr *)&buf->grh.dgid.raw;
	struct in_addr source_addr;
	struct in_addr dest_addr;
	unsigned port = 0;
	char xbuf[INET6_ADDRSTRLEN];

	source_addr.s_addr = sgid->sib_addr32[3];
	dest_addr.s_addr = dgid->sib_addr32[3];

	if (!(w->wc_flags & IBV_WC_GRH)) {
		syslog(LOG_WARNING, "Discard Packet: No GRH provided %s/%s\n",
			inet_ntoa(dest_addr), c->text);
		return -EINVAL;
	}

	if (unicast && buf->grh.dgid.raw[0] != 0xff)
		return unicast_packet(c, buf, source_addr, dest_addr);

	m = hash_lookup_mc(dest_addr);

	if (!m) {
		syslog(LOG_WARNING, "Discard Packet: Multicast group %s not found\n",
			inet_ntoa(dest_addr));
		return -ENODATA;
	}

	if (m->sendonly[in]) {

		syslog(LOG_WARNING, "Discard Packet: Received data from Sendonly MC group %s from %s\n",
			m->text, c->text);
		return -EPERM;
	}

	if (in == INFINIBAND) {
		unsigned char *mgid = buf->grh.dgid.raw;
		unsigned short signature = ntohs(*(unsigned short*)(mgid + 2));

		if (mgid[0] != 0xff) {
			syslog(LOG_WARNING, "Discard Packet: Not multicast. MGID=%s/%s\n",
				inet_ntop(AF_INET6, mgid, xbuf, INET6_ADDRSTRLEN), c->text);
			return -EINVAL;
		}

		if (memcmp(&buf->grh.sgid, &c->i->gid, sizeof(union ibv_gid)) == 0) {
			syslog(LOG_WARNING, "Discard Packet: Loopback from this host. MGID=%s/%s\n",
				inet_ntop(AF_INET6, mgid, xbuf, INET6_ADDRSTRLEN), c->text);
			return -EINVAL;
		}

		if (m->mgid_mode) {
			if (signature == m->mgid_mode->signature) {
				if (m->mgid_mode->port)
					port = ntohs(*((unsigned short *)(mgid + 10)));
			} else {
				syslog(LOG_WARNING, "Discard Packet: MGID multicast signature(%x)  mismatch. MGID=%s\n",
						signature,
						inet_ntop(AF_INET6, mgid, xbuf, INET6_ADDRSTRLEN));
				return -EINVAL;
			}
		}

	} else { /* ROCE */
		struct in_addr local_addr = c->bindaddr.sin_addr;

		if (source_addr.s_addr == local_addr.s_addr) {
			syslog(LOG_WARNING, "Discard Packet: Loopback from this host. %s/%s\n",
				inet_ntoa(source_addr), c->text);
			return -EINVAL;
		}
	}

	if (m->beacon)	{
		beacon_received(buf);
		return 1;
	}

	if (!bridging)
		return -ENOSYS;

	len = w->byte_len - sizeof(struct ibv_grh);
	return send_buf(i2r[in ^ 1].multicast, buf, len, m->ai + (in ^ 1), port);
}

static void handle_comp_event(enum interfaces in)
{
	struct i2r_interface *i = i2r + in;
	struct ibv_cq *cq;
	struct rdma_channel *c;
	int cqs;
	struct ibv_wc wc[100];
	int j;

	ibv_get_cq_event(i->comp_events, &cq, (void **)&c);
	if (cq != c->cq) {
		syslog(LOG_CRIT, "ibv_get_cq_event: CQ mismatch\n");
		abort();
	}

	ibv_ack_cq_events(cq, 1);
	if (ibv_req_notify_cq(cq, 0)) {
		syslog(LOG_CRIT, "ibv_req_notify_cq: Failed\n");
		abort();
	}

redo:
	/* Retrieve completion events and process incoming data */
	cqs = ibv_poll_cq(cq, 100, wc);
	if (cqs < 0) {
		syslog(LOG_WARNING, "CQ polling failed with: %s on %s\n",
			errname(), interfaces_text[i - i2r]);
		goto exit;
	}

	if (cqs == 0)
		goto exit;

	if (cqs > cq_high)
		cq_high = cqs;

	for (j = 0; j < cqs; j++) {
		struct ibv_wc *w = wc + j;
		struct buf *buf = (struct buf *)w->wr_id;

		if (w->status == IBV_WC_SUCCESS && w->opcode == IBV_WC_RECV) {

			c->active_receive_buffers--;
			st(c, packets_received);

			if (recv_buf(c, buf, w))
				free_buffer(buf);
			else
				st(c, packets_bridged);

		} else {
			if (w->status == IBV_WC_SUCCESS && w->opcode == IBV_WC_SEND)
				st(c, packets_sent);
			else
				syslog(LOG_NOTICE, "Strange CQ Entry %d/%d: Status:%x Opcode:%x Len:%u QP=%u SRC_QP=%u Flags=%x\n",
					j, cqs, w->status, w->opcode, w->byte_len, w->qp_num, w->src_qp, w->wc_flags);

			free_buffer(buf);
		}
	}
	goto redo;

exit:

	/* Since we freed some buffers up we may be able to post more of them */
	post_receive_buffers(i);
}

static void handle_async_event(enum interfaces in)
{
//	struct i2r_interface *i = i2r + in;
	struct ibv_async_event event;

	if (!ibv_get_async_event(i2r[in].context, &event))
		syslog(LOG_ALERT, "Async event retrieval failed.\n");
	else
		syslog(LOG_ALERT, "Async RDMA EVENT %d\n", event.event_type);

	/*
	 * Regardless of what the cause is the first approach here
	 * is to simply terminate the program.
	 * We can make exceptions later.
	 */

	terminated = true;

        ibv_ack_async_event(&event);
}

static int status_fd;

static int channel_stats(char *b, struct rdma_channel *c, const char *interface, const char *type)
{
	int n = 0;
	int j;

	n += sprintf(b + n, "\nPacket Statistics for %s(%s):\n", interface, type);

	for(j =0; j < nr_stats; j++)
		if (c->stats[j]) {
			n += sprintf(b + n, "%s=%lu\n", stats_text[j], c->stats[j]);
	}
	return n;
}


static void status_write(void)
{
	static char b[10000];
	struct i2r_interface *i;
	int n = 0;
	int free = 0;
	struct buf *buf;
	int fd = status_fd;
	struct mc *m;

	if (update_requested) {

		char name[40];
		time_t t = time(NULL);
		struct tm tm;

		localtime(&t);

		snprintf(name, 40, "ib2roce-%d%02d%02dT%02d%02d%02d",
				tm.tm_year + 1900, tm.tm_mon +1, tm.tm_mday,
				tm.tm_hour, tm.tm_min, tm.tm_sec);
		fd = open(name, O_CREAT | O_RDWR,  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	} else
		lseek(fd, SEEK_SET, 0);

	for(buf = buffers; buf < buffers + nr_buffers; buf++)
		if (buf->free)
		       free++;

	n+= sprintf(b + n, "Multicast: Active=%u NR=%u Max=%u\nBuffers: Active=%u Total=%u CQ#High=%u\n\n",
		active_mc, nr_mc, MAX_MC, nr_buffers-free , nr_buffers, cq_high);

	for(m = mcs; m < mcs + nr_mc; m++)

		n += sprintf(n + b, "%s INFINIBAND: %s%s%s ROCE: %s%s\n",
			inet_ntoa(m->addr),
			mc_text[m->status[INFINIBAND]],
			m->sendonly[INFINIBAND] ? "Sendonly " : "",
			m->mgid_mode ? m->mgid_mode->id : "",
			mc_text[m->status[ROCE]],
			m->sendonly[ROCE] ? "Sendonly" : "");

	for(i = i2r; i < i2r + NR_INTERFACES; i++) {

		if (i->multicast)
			n += channel_stats(b + n, i->multicast, interfaces_text[i - i2r], "Multicast");
		if (i->raw)
			n += channel_stats(b + n, i->raw, interfaces_text[i - i2r], "Raw");

	}
	n += sprintf(n + b, "\n\n\n\n\n\n\n\n");
	write(fd, b, n);

	if (update_requested) {
		close(fd);
		update_requested = false;
	}
}

/*
 * Beacon processing
 */
struct beacon_info {
	char version[10];
	struct in_addr infiniband;
	struct in_addr roce;
	unsigned nr_mc;
};

struct mc *beacon_mc;

static void beacon_received(struct buf *buf)
{
	struct beacon_info *b = (struct beacon_info *)buf;
	char ib[40];

	strcpy(ib, inet_ntoa(b->infiniband));
	syslog(LOG_NOTICE, "Received Beacon on %s Version %s IB=%s, ROCE=%s MC groups=%u\n",
		beacon_mc->text, b->version, ib, inet_ntoa(b->roce), b->nr_mc);
}

static void beacon_send(void)
{
	struct beacon_info b;
	struct buf *buf;
	int i;

	memcpy(b.version, VERSION, 10);
	b.infiniband = i2r[INFINIBAND].if_addr.sin_addr;
	b.roce = i2r[ROCE].if_addr.sin_addr;
	b.nr_mc = nr_mc;

	for(i = 0; i < NR_INTERFACES; i++)
	if (i2r[i].context && beacon_mc->status[i] == MC_JOINED) {
		if (sizeof(b) > MAX_INLINE_DATA) {
			buf = alloc_buffer();
			memcpy(buf->payload, &b, sizeof(b));
			send_buf(i2r[i].multicast, buf, sizeof(b), beacon_mc->ai + i, 999);
		} else
			send_inline(i2r[i].multicast, &b, sizeof(b), beacon_mc->ai + i, 999);
	}
}

static void beacon_setup(void)
{
	struct mc *m = mcs + nr_mc++;
	struct sockaddr_in *sin;

	sin = calloc(1, sizeof(struct sockaddr_in));

	sin->sin_family = AF_INET,
	sin->sin_port = htons(999);
	sin->sin_addr.s_addr = inet_addr("239.1.2.3");

	memset(m, 0, sizeof(*m));
	m->beacon = true;
	m->text = "239.1.2.3:999";
	m->addr = sin->sin_addr;
	m->sa[INFINIBAND] = m->sa[ROCE] = (struct sockaddr *)sin;
	if (hash_add_mc(m)) {
		syslog(LOG_ERR, "Beacon MC already in use.\n");
		beacon = false;
		free(sin);
	} else
		beacon_mc = m;
}

#define NR_EVENT_TYPES 4

static void (*event_callvec[NR_EVENT_TYPES])(unsigned) = {
		handle_rdma_event,
		handle_comp_event,
		handle_async_event,
		handle_netlink_event
};

static int event_loop(void)
{
	unsigned timeout = 1000;
	struct pollfd pfd[ 2* NR_EVENT_TYPES] = {
		{ i2r[INFINIBAND].rdma_events->fd, POLLIN, 0},
		{ i2r[ROCE].rdma_events->fd, POLLIN, 0},
		{ i2r[INFINIBAND].comp_events->fd, POLLIN, 0},
		{ i2r[ROCE].comp_events->fd, POLLIN,0},
		{ i2r[INFINIBAND].context->async_fd, POLLIN, 0},
		{ i2r[ROCE].context->async_fd, POLLIN, 0},
		{ sock_nl[nl_monitor], POLLIN, 0},
		{ sock_nl[nl_command], POLLIN, 0}
	};
	unsigned nr_types = NR_EVENT_TYPES;
	int events;
	struct i2r_interface *i;
	int t;

	if (!unicast)
		/* No netlink events */
		nr_types--;

	for(i = i2r; i < i2r + NR_INTERFACES; i++) {
		/* Receive Buffers */
		post_receive_buffers(i);
		/* And request notifications if something happens */
		if (i->multicast)
			ibv_req_notify_cq(i->multicast->cq, 0);
		if (i->raw) {
			start_channel(i->raw);
			ibv_req_notify_cq(i->raw->cq, 0);
		}
	}

loop:
	events = poll(pfd, 2 * nr_types, timeout);

	if (terminated)
		goto out;

	if (events < 0) {
		syslog(LOG_WARNING, "Poll failed with error=%s\n", errname());
		goto out;
	}

	if (events == 0) {

		/* Maintenance tasks */
		if (nr_mc > active_mc) {
			join_processing();
			timeout = 1000;
		} else {
			/*
			 * Gradually increase timeout
			 * if nothing is really going
			 * on
			*/
			if (!beacon && timeout < 60*60*100)
				timeout *= 2;
		}

		status_write();

		syslog(LOG_NOTICE, "ib2roce: %d/%d MC Active. Next Wakeup in %u ms.\n",
			active_mc, nr_mc, timeout);

		if (beacon)
			beacon_send();

		goto loop;
	}

	if (timeout > 5000)
		timeout = 5000;

	for(t = 0; t < nr_types; t++) {
		int j;

		for(j = 0; j < NR_INTERFACES; j++) 
			if (pfd[t * 2 + j].revents & POLLIN)
				event_callvec[t](j);
	}

	goto loop;
out:
	return 0;
}

/*
 * Daemon Management functions
 */

static void terminate(int x)
{
	terminated = true;
}


static void update_status(int x)
{
	update_requested = true;
}

static void daemonize(void)
{
	pid_t pid;

	if (debug) {
		chdir("/var/lib/ib2roce");
		openlog("ib2roce", LOG_PERROR, LOG_USER);
		return;
	}

	pid = fork();

	if (pid < 0)
		exit(EXIT_FAILURE);

	if (pid > 0)
		exit(EXIT_SUCCESS);

	if (setsid() < 0)
	        exit(EXIT_FAILURE);

	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	pid = fork();

	if (pid < 0)
		exit(EXIT_FAILURE);

	/* Terminate parent */
	if (pid > 0)
		exit(EXIT_SUCCESS);

	/* Set new file permissions */
	umask(0);

	if (chdir("/var/lib/ib2roce")) {
		perror("chdir");
		exit(EXIT_FAILURE);
	}

	/* Close all open file descriptors */
	int x;
	for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
		close (x);

	openlog ("ib2roce", LOG_PID, LOG_DAEMON);

	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGHUP, terminate);	/* Future: Reload a potential config file */
	signal(SIGUSR1, update_status);
}

static int pid_fd;

static void pid_open(void)
{
	struct flock fl = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};
	int n;
	char buf[10];

	pid_fd = open("ib2roce.pid", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

	if (pid_fd < 0) {
		syslog(LOG_CRIT, "Cannot open pidfile. Error %s\n", errname());
		abort();
	}

	if (fcntl(pid_fd, F_SETLK, &fl) < 0) {
		syslog(LOG_CRIT, "ib2roce already running.\n");
		abort();
	}

	if (ftruncate(pid_fd, 0) < 0) {
		syslog(LOG_CRIT, "Cannot truncate pidfile. Error %s\n", errname());
		abort();
	}

	n = snprintf(buf, sizeof(buf), "%ld", (long) getpid());

	if (write(pid_fd, buf, n) != n) {
		syslog(LOG_CRIT, "Cannot write pidfile. Error %s\n", errname());
		abort();
	}
}

static void pid_close(void)
{
	unlink("ib2roce.pid");
	close(pid_fd);
}

struct option opts[] = {
	{ "device", required_argument, NULL, 'd' },
	{ "roce", required_argument, NULL, 'r' },
	{ "multicast", required_argument, NULL, 'm' },
	{ "inbound", required_argument, NULL, 'i' },
	{ "mgid", optional_argument, NULL, 'l' },
	{ "beacon", no_argument, NULL, 'b' },
	{ "debug", no_argument, NULL, 'x' },
	{ "nobridge", no_argument, NULL, 'n' },
	{ "port", required_argument, NULL, 'p' },
	{ "unicast", no_argument, NULL, 'u' },
	{ NULL, 0, NULL, 0 }
};

int main(int argc, char **argv)
{
	int op, ret = 0;
	int n;

	while ((op = getopt_long(argc, argv, "unbxl::i:r:m:o:d:p:",
					opts, NULL)) != -1) {
                switch (op) {
		case 'd':
			ib_name = optarg;
			break;

		case 'r':
			roce_name = optarg;
			break;

		case 'm':
			ret = new_mc_addr(optarg, false, false);
			break;

		case 'i':
			ret = new_mc_addr(optarg, false, true);
			break;

		case 'o':
			ret =  new_mc_addr(optarg, true, false);
			break;

		case 'l':
			if (optarg) {
				mgid_mode = find_mgid_mode(optarg);
				if (mgid_mode)
					break;
			}
			printf("List of supported MGID formats via -l<id>\n");
			printf("=================================\n");
			printf(" ID    | Signature | Port in MGID\n");
			printf("-------+-----------+-------------\n");
			for (n = 0; n < nr_mgid_signatures; n++) {
				struct mgid_signature *m = mgid_signatures + n;

				printf("%7s|    0x%x | %s\n",
					m->id, m->signature, m->port ? "true" : "false");
			}
			exit(1);
			break;

		case 'x':
			debug = true;
			break;

		case 'b':
			beacon = true;
			break;

		case 'n':
			bridging = false;
			break;

		case 'p':
			default_port = atoi(optarg);
			break;

		case 'u':
			unicast = true;
			break;

		default:
			printf("%s " VERSION " Jan19,2021 (C) 2022 Christoph Lameter <cl@linux.com>\n", argv[0]);
			printf("Usage: ib2roce [<option>] ...\n");
                        printf("-d|--device <if[:portnumber]>		Infiniband interface\n");
                        printf("-r|--roce <if[:portnumber]>		ROCE interface\n");
                        printf("-m|--multicast <multicast address>[:port][/mgidformat] (bidirectional)\n");
                        printf("-i|--inbound <multicast address>	Incoming multicast only (ib traffic in, roce traffic out)\n");
                        printf("-o|--outbound <multicast address>	Outgoing multicast only / sendonly (ib trafic out, roce traffic in)\n");
			printf("-l|--mgid				List availabe MGID formats for Infiniband\n");
			printf("-l|--mgid <format>			Set default MGID format\n");
			printf("-x|--debug				Do not daemonize, enter debug mode\n");
			printf("-p|--port >number>			Set default port number\n");
			printf("-b|--beacon				Send beacon every second\n");
			printf("-n|--nobridge				Do everything but do not bridge packets\n");
			printf("-u|--unicast		*experimental*	Forward unicast packages via proxyarp\n");
			exit(1);
		}
	}

	init_buf();

	daemonize();
	pid_open();

	ret = find_rdma_devices();
	if (ret)
		return ret;

	syslog (LOG_NOTICE, "ib2roce: Infiniband device = %s:%d, ROCE device = %s:%d. Multicast Groups=%d MGIDs=%s Buffers=%u\n",
			i2r[INFINIBAND].context ? ibv_get_device_name(i2r[INFINIBAND].context->device) : "-",
			i2r[INFINIBAND].port,
			i2r[ROCE].context ? ibv_get_device_name(i2r[ROCE].context->device) : "-",
			i2r[ROCE].port,
			nr_mc,
			mgid_mode ? mgid_mode->id : "Default",
			nr_buffers);

	setup_interface(INFINIBAND);
	setup_interface(ROCE);

	status_fd = open("ib2roce-status", O_CREAT | O_RDWR,  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (beacon)
		beacon_setup();

	if (unicast) {
		enum interfaces j;

		for(j = 0; j < NR_INTERFACES; j++) {
			setup_flow(j);
			setup_netlink(j);
		}
	}

	event_loop();

	close(status_fd);

	shutdown_roce();
	shutdown_ib();

	pid_close();
	syslog (LOG_NOTICE, "ib2roce terminated.");
	closelog();

	return EXIT_SUCCESS;
}
