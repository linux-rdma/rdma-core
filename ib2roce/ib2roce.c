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

static struct i2r_interface {
	struct rdma_cm_id *id;
	struct rdma_event_channel *rdma_events;
	struct ibv_context *context;
	struct ibv_comp_channel *comp_events;
	struct ibv_pd *pd;
	struct ibv_cq *cq;
	struct ibv_mr *mr;
	unsigned int active_receive_buffers;
	unsigned int nr_cq;
	unsigned port;
	unsigned mtu;
	unsigned macoffset;
	unsigned maclen;
	char if_name[IFNAMSIZ];
	struct sockaddr_in if_addr;
	struct sockaddr_in if_netmask;
	struct sockaddr *bindaddr;
	struct sockaddr_nl nladdr;
	int sock_nl;
	unsigned ifindex;
	unsigned gid_index;
	union ibv_gid gid;
	unsigned long stats[nr_stats];
	struct ibv_device_attr device_attr;
	struct ibv_port_attr port_attr;
	int iges;
	struct ibv_gid_entry ige[MAX_GID];
} i2r[NR_INTERFACES];

static inline void st(struct i2r_interface *i, enum stats s)
{
	i->stats[s]++;
}

static inline struct rdma_cm_id *id(enum interfaces i)
{
	return i2r[i].id;
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
		syslog(LOG_ERR, "Failed to create join request %s:%d on %s. Error %d\n",
			inet_ntoa(addr), port,
			interfaces_text[i],
			errno);
		return 1;
	}
	syslog(LOG_NOTICE, "Join Request %sMC group %s:%d on %s .\n",
		sendonly ? "Sendonly " : "",
		inet_ntoa(addr), port,
		interfaces_text[i]);
	st(i2r + i, join_requests);
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
	st(i2r + i, leave_requests);
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

static int post_receive_buffers(struct i2r_interface *i)
{
	struct ibv_recv_wr recv_wr, *recv_failure;
	struct ibv_sge sge;
	int ret = 0;

	if (!nextbuffer || i->active_receive_buffers >= i->nr_cq / 2 )
		return -EAGAIN;

	recv_wr.next = NULL;
	recv_wr.sg_list = &sge;
	recv_wr.num_sge = 1;

	sge.length = i->mtu + sizeof(struct ibv_grh);
	sge.lkey = i->mr->lkey;

	while (i->active_receive_buffers < i->nr_cq / 2) {

		struct buf *buf = alloc_buffer();


		if (!buf) {
			syslog(LOG_NOTICE, "No free buffers left\n");
			ret = -ENOMEM;
			break;
		}

		/* Use the buffer address for the completion handler */
		recv_wr.wr_id = (uint64_t)buf;
		sge.addr = (uint64_t)&buf->grh;
		ret = ibv_post_recv(i->id->qp, &recv_wr, &recv_failure);
		if (ret) {
			free_buffer(buf);
			syslog(LOG_WARNING, "ibv_post_recv failed: %d\n", ret);
			break;
                }
		i->active_receive_buffers++;
	}
	return ret;
}


static int qp_destroy(struct i2r_interface *i)
{
	if (i->id->qp)
		rdma_destroy_qp(i->id);

	if (i->cq)
		ibv_destroy_cq(i->cq);

	ibv_dereg_mr(i->mr);

	if (i->pd)
		ibv_dealloc_pd(i->pd);

	return 0;
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

static void setup_interface(enum interfaces in)
{
	struct i2r_interface *i = i2r + in;
	struct ibv_gid_entry *e;
	struct ibv_qp_init_attr_ex init_qp_attr_ex;
	char buf[INET6_ADDRSTRLEN];
	struct sockaddr_in *sin;
	int ret;

	if (in == INFINIBAND) {
		i->macoffset = 4;
		i->maclen = 16;
	} else {
		i->macoffset = 0;
		i->maclen = 6;
	}

	if (!i->context)
		return;

	i->rdma_events = rdma_create_event_channel();
	if (!i->rdma_events) {
		syslog(LOG_CRIT, "rdma_create_event_channel() for %s failed (%d).\n",
			interfaces_text[in], errno);
		abort();
	}

	ret = rdma_create_id(i->rdma_events, &i->id, i, RDMA_PS_UDP);
	if (ret) {
		syslog(LOG_CRIT, "Failed to allocate RDMA CM ID for %s failed (%d).\n",
			interfaces_text[in], errno);
		abort();
	}

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

	get_if_info(i);

	sin = calloc(1, sizeof(struct sockaddr_in));
	sin->sin_family = AF_INET;
	*sin = i->if_addr;
	sin->sin_port = htons(default_port);
	i->bindaddr = (struct sockaddr *)sin;

	ret = rdma_bind_addr(i->id, i->bindaddr);
	if (ret) {
		syslog(LOG_CRIT, "Failed to bind %s interface. Error %d\n",
			interfaces_text[in], errno);
		abort();
	}

	i->pd = ibv_alloc_pd(i->id->verbs);
	if (!i->pd) {
		syslog(LOG_CRIT, "ibv_alloc_pd failed for %s.\n",
			interfaces_text[in]);
		abort();
	}

	i->comp_events = ibv_create_comp_channel(i->context);
	if (!i->comp_events) {
		syslog(LOG_CRIT, "ibv_create_comp_channel failed for %s.\n",
			interfaces_text[in]);
		abort();
	}

	i->nr_cq = MIN(i->device_attr.max_cqe, nr_buffers / 2);
	i->cq = ibv_create_cq(i->id->verbs, i->nr_cq, i, i->comp_events, 0);
	if (!i->cq) {
		syslog(LOG_CRIT, "ibv_create_cq failed for %s.\n",
			interfaces_text[in]);
		abort();
	}

	memset(&init_qp_attr_ex, 0, sizeof(init_qp_attr_ex));
	init_qp_attr_ex.cap.max_send_wr = i->nr_cq;
	init_qp_attr_ex.cap.max_recv_wr = i->nr_cq;
	init_qp_attr_ex.cap.max_send_sge = 1;
	init_qp_attr_ex.cap.max_recv_sge = 1;
	init_qp_attr_ex.cap.max_inline_data = MAX_INLINE_DATA;
	init_qp_attr_ex.qp_context = i;
	init_qp_attr_ex.sq_sig_all = 0;
	init_qp_attr_ex.qp_type = IBV_QPT_UD;
	init_qp_attr_ex.send_cq = i->cq;
	init_qp_attr_ex.recv_cq = i->cq;

	init_qp_attr_ex.comp_mask = IBV_QP_INIT_ATTR_CREATE_FLAGS|IBV_QP_INIT_ATTR_PD;
	init_qp_attr_ex.pd = i->pd;
	init_qp_attr_ex.create_flags = IBV_QP_CREATE_BLOCK_SELF_MCAST_LB;

	ret = rdma_create_qp_ex(i->id, &init_qp_attr_ex);
	if (ret) {
		syslog(LOG_CRIT, "rdma_create_qp_ex failed for %s. Error %d.\n",
			interfaces_text[in], errno);
		abort();
	}

	i->mr = ibv_reg_mr(i->pd, buffers, nr_buffers * sizeof(struct buf), IBV_ACCESS_LOCAL_WRITE);
	if (!i->mr) {
		syslog(LOG_CRIT, "ibv_reg_mr failed for %s.\n",
			interfaces_text[in]);
		abort();
	}

	syslog(LOG_NOTICE, "%s interface %s/%s port %d GID=%s/%d IPv4=%s CQs=%u MTU=%u ready.\n",
		interfaces_text[in],
		ibv_get_device_name(i->context->device),
		i->if_name,
		i->port,
		inet_ntop(AF_INET6, e->gid.raw, buf, INET6_ADDRSTRLEN),i->gid_index,
		inet_ntoa(i->if_addr.sin_addr),
		i->nr_cq,
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
	rdma_destroy_id(id(INFINIBAND));
}

static void shutdown_roce(void)
{
	if (!i2r[ROCE].context)
		return;

	leave_mc(ROCE);

	/* Shutdown Interface */
	qp_destroy(i2r + ROCE);
	rdma_destroy_id(id(ROCE));
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
		syslog(LOG_WARNING, "rdma_get_cm_event()_ failed. Error = %d\n", errno);
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
				a->ah = ibv_create_ah(i->pd, &param->ah_attr);
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
				st(i, join_success);
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
				st(i, join_failure);
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
static int send_inline(struct i2r_interface *i, void *buf, unsigned len, struct ah_info *ai)
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
		.imm_data = htobe32(i->id->qp->qp_num),
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

	ret = ibv_post_send(i->id->qp, &wr, &bad_send_wr);
	if (ret)
		syslog(LOG_WARNING, "Failed to post inline send: %d\n", ret);

	return ret;
}

static int send_buf(struct i2r_interface *i, struct buf *buf, unsigned len, struct ah_info *ai)
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
	wr.imm_data = htobe32(i->id->qp->qp_num);

	/* Get addr info  */
	wr.wr.ud.ah = ai->ah;
	wr.wr.ud.remote_qpn = ai->remote_qpn;
	wr.wr.ud.remote_qkey = ai->remote_qkey;

	sge.length = len;
	sge.lkey = i->mr->lkey;
	sge.addr = (uint64_t)buf->payload;

	ret = ibv_post_send(i->id->qp, &wr, &bad_send_wr);
	if (ret)
		syslog(LOG_WARNING, "Failed to post send: %d\n", ret);

	return ret;
}

static unsigned int lookup_ip_from_gid(union ibv_gid *v)
{
	/* This is something like a mac address lookup ?? */
	return 0;
}

#define ROCE_PORT 4791

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

/* Unicast handling */

struct rdma_ah {
	struct i2r_interface *i;
	char mac[16];
	struct in_addr addr;
	struct rdma_ah *next_addr;	/* Hash Collision addr hash */
	struct rdma_ah *next_mac;	/* Hash Collision mac hash */
};

struct rdma_ah *hash_addr[0xff];
struct rdma_ah *hash_mac[0xff];

static int nr_rdma_ah = 0;

static unsigned mac_hash(struct i2r_interface *i, char *mac)
{
	int z = i->macoffset;
	unsigned hash = mac[z++];

	while (z < i->maclen)
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

static struct rdma_ah *hash_mac_lookup(struct i2r_interface *i, char *mac, unsigned mac_hash)
{
	struct rdma_ah *ra = hash_mac[mac_hash];

	while (ra && memcmp(mac + i->macoffset, ra->mac, i->maclen) != 0)
		ra = ra->next_mac;

	return ra;
}

static char hexbyte(unsigned x)
{
	if (x < 10)
		return '0' + x;

	return x - 10 + 'a';
}

static char *hexbytes(unsigned char *x, unsigned len)
{
	static char b[100];
	unsigned i;
	char *p = b;

	for(i =0; i < len; i++) {
		unsigned n = *x++;
		*p++ = hexbyte( n >> 4 );
		*p++ = hexbyte( n & 0xf);
		*p++ = ':';
	}
	p--;
	*p = 0;
	return b;
}


static void hash_add_unicast_rdma_ah(struct i2r_interface *i, struct rdma_ah *ra)
{
	unsigned ha = ip_hash(ntohl(ra->addr.s_addr));
	unsigned hm = mac_hash(i, ra->mac);

	if (hash_addr_lookup(ra->addr, ha)) {
		syslog(LOG_CRIT, "Duplicate IP address in Hash Interface=%s addr=%s\n",
				i->if_name, inet_ntoa(ra->addr));
		abort();
	}

	if (hash_mac_lookup(i, ra->mac, hm)) {
		syslog(LOG_CRIT, "Duplicate MAC Address in Hash Interface=%s mac=%s\n",
				i->if_name, hexbytes(ra->mac+ i->macoffset, i->maclen));
		abort();
	}

	ra->next_addr = hash_addr[ha];
	ra->next_mac = hash_mac[hm];

	hash_addr[ha] = ra;
	hash_mac[hm] = ra;
	nr_rdma_ah++;
}

struct neigh {
	struct nlmsghdr nlh;
	struct ndmsg nd;
	char	attrbuf[512];
};

static void handle_neigh_event(struct i2r_interface *i, struct neigh *n)
{
	int len = n->nlh.nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));
	unsigned maclen = 0;
	struct rtattr *rta;
	struct rdma_ah *ra = calloc(1, sizeof(struct rdma_ah));


	for(rta = (struct rtattr *)n->attrbuf; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		switch (rta->rta_type) {
			case NDA_DST:
				memcpy(&ra->addr, RTA_DATA(rta), RTA_PAYLOAD(rta));
				break;
			case NDA_LLADDR:
				maclen = RTA_PAYLOAD(rta);
				memcpy(&ra->mac, RTA_DATA(rta), RTA_PAYLOAD(rta));
				break;
			default:
				syslog(LOG_NOTICE, "Netlink; invalid RTA type=%d\n", rta->rta_type);
				break;
		}
	};

	/* Code to check for removal and changes omitted for now */
	hash_add_unicast_rdma_ah(i, ra);

	syslog(LOG_NOTICE, "Neigh Even type %u Len=%u flag=%x seq=%x PID=%d\n",
				  n->nlh.nlmsg_type,  n->nlh.nlmsg_len, n->nlh.nlmsg_flags, n->nlh.nlmsg_seq, n->nlh.nlmsg_pid);

}

static void handle_netlink_event(enum interfaces in)
{
	struct i2r_interface *i = i2r + in;
	char buf[1000];
	struct nlmsghdr *h = (void *)buf;
	struct sockaddr_nl nladdr;
	struct iovec iov = { buf, sizeof(buf) };
	struct msghdr msg = { (void *)&nladdr, sizeof(struct sockaddr_nl), &iov, 1 };
	int ret;

	ret = recvmsg(i->sock_nl, &msg, 0);
	if (ret < 9) {
		perror("Netlink recvmsg");
		return;
	}

	switch(h->nlmsg_type) {
		case RTM_NEWNEIGH:
		case RTM_DELNEIGH:
		    handle_neigh_event(i, (struct neigh *)h);
		    break;

		default:
		    syslog(LOG_NOTICE, "Unhandled Netlink Message type %u Len=%u flag=%x seq=%x PID=%d\n",
				  h->nlmsg_type,  h->nlmsg_len, h->nlmsg_flags, h->nlmsg_seq, h->nlmsg_pid);
		    break;
	}

}

static int send_netlink_message(struct i2r_interface *i, struct nlmsghdr *nlh)
{
	struct iovec iov = { (void *)nlh, nlh->nlmsg_len};
	struct msghdr msg = { (void *)&i->nladdr, sizeof(struct sockaddr_nl), &iov, 1 };
	int ret;

	ret = sendmsg(i->sock_nl, &msg, 0);
	return ret;
}

static int netlink_setup(struct i2r_interface *i)
{
	static struct sockaddr_nl sal = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_NEIGH	/* Subscribe to changes to the ARP cache */
	};
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg r;
	} nlr = { {
			.nlmsg_type = RTM_GETNEIGH,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
			.nlmsg_len = sizeof(nlr),
			.nlmsg_seq = time(NULL)
		}, {
			.rtgen_family = AF_INET,
		} };
	
	i->sock_nl = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (i->sock_nl < 0) {
		syslog(LOG_CRIT, "Failed to open netlink socket %d.\n", errno);
		abort();
	}

	sal.nl_pid = getpid();
	if (bind(i->sock_nl, (struct sockaddr *)&sal, sizeof(sal)) < 0) {
		syslog(LOG_CRIT, "Failed to bind to netlink socket %d\n", errno);
		abort();
	};

	send_netlink_message(i, &nlr.nlh);
}

static void setup_flow(enum interfaces in)
{
	struct i2r_interface *i = i2r + in;
	struct i2r_interface *di = i2r + (in ^ 1);
	enum interfaces j;
	struct ibv_flow *f;
	bool err = false;
	char name[100];
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

	if (!bridging)
		return;

	/* Check system config for unicast setup */
	if (sysfs_read_int("/proc/sys/net/ipv4/ip_forward") != 1) {
		err = true;
		syslog(LOG_CRIT, "unicast mode requires ip_forwarding to be active\n");
	}

	for (j = 0; j < NR_INTERFACES; j++) {
		const char *interface = i2r[j].if_name;

		snprintf(name, 100, "/proc/sys/net/ipv4/conf/%s/proxy_arp", interface);
		if (sysfs_read_int(name) != 1) {
			err = true;
			syslog(LOG_CRIT,"unicast mode requires a proxyarp setup on interface %s",
				interface);
		}
	}

	f = ibv_create_flow(i->id->qp, &flattr.attr);
	if (!f) {
		err = true;
		syslog(LOG_ERR, "unicast mode: Cannot create required flow on %s. Errno %d\n", interfaces_text[in], errno);
	}

	if (err)
		abort();
}

static int unicast_packet(struct i2r_interface *i, struct buf *buf, struct in_addr source_addr, struct in_addr dest_addr)
{
	char xbuf[INET6_ADDRSTRLEN];
	char xbuf2[INET6_ADDRSTRLEN];
	enum interfaces in = i - i2r;
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
		unsigned int daddr = ntohl(lookup_ip_from_gid(&buf->grh.dgid));

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


static int recv_buf(struct i2r_interface *i,
			struct buf *buf, struct ibv_wc *w)
{
	struct mc *m;
	enum interfaces in = i - i2r;
	unsigned len;
	struct in_addr source_addr = *(struct in_addr *)(buf->grh.sgid.raw + 12);
	struct in_addr dest_addr = *(struct in_addr *)(buf->grh.dgid.raw + 12);
	unsigned port = 0;
	char xbuf[INET6_ADDRSTRLEN];

	if (!(w->wc_flags & IBV_WC_GRH)) {
		syslog(LOG_WARNING, "Discard Packet: No GRH provided %s/%s\n",
			inet_ntoa(dest_addr), interfaces_text[in]);
		return -EINVAL;
	}

	if (unicast && buf->grh.dgid.raw[0] != 0xff)
		return unicast_packet(i, buf, source_addr, dest_addr);

	m = hash_lookup_mc(dest_addr);

	if (!m) {
		syslog(LOG_WARNING, "Discard Packet: Multicast group %s not found\n",
			inet_ntoa(dest_addr));
		return -ENODATA;
	}

	if (m->sendonly[in]) {

		syslog(LOG_WARNING, "Discard Packet: Received data from Sendonly MC group %s from %s\n",
			m->text, interfaces_text[in]);
		return -EPERM;
	}

	if (in == INFINIBAND) {
		unsigned char *mgid = buf->grh.dgid.raw;
		unsigned short signature = ntohs(*(unsigned short*)(mgid + 2));

		if (mgid[0] != 0xff) {
			syslog(LOG_WARNING, "Discard Packet: Not multicast. MGID=%s/%s\n",
				inet_ntop(AF_INET6, mgid, xbuf, INET6_ADDRSTRLEN), interfaces_text[in]);
			return -EINVAL;
		}

		if (memcmp(&buf->grh.sgid, &i->gid, sizeof(union ibv_gid)) == 0) {
			syslog(LOG_WARNING, "Discard Packet: Loopback from this host. MGID=%s/%s\n",
				inet_ntop(AF_INET6, mgid, xbuf, INET6_ADDRSTRLEN), interfaces_text[in]);
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
		struct in_addr local_addr = ((struct sockaddr_in *)i->bindaddr)->sin_addr;

		if (source_addr.s_addr == local_addr.s_addr) {
			syslog(LOG_WARNING, "Discard Packet: Loopback from this host. %s/%s\n",
				inet_ntoa(source_addr), interfaces_text[in]);
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
	return send_buf(i2r + (in ^ 1), buf, len, m->ai + (in ^ 1));
}

static void handle_comp_event(enum interfaces in)
{
	struct i2r_interface *i = i2r + in;
	struct ibv_cq *cq;
	void *private;
	int cqs;
	struct ibv_wc wc[100];
	int j;

	ibv_get_cq_event(i->comp_events, &cq, &private);
	if (cq != i->cq) {
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
		syslog(LOG_WARNING, "CQ polling failed with: %d on %s\n",
			errno, interfaces_text[i - i2r]);
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

			i->active_receive_buffers--;
			st(i, packets_received);

			if (recv_buf(i, buf, w))
				free_buffer(buf);
			else
				st(i, packets_bridged);

		} else {
			if (w->status == IBV_WC_SUCCESS && w->opcode == IBV_WC_SEND)
				st(i, packets_sent);
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
	struct i2r_interface *i = i2r + in;
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

static void status_write(void)
{
	static char b[10000];
	int i,j;
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

	for(i = 0; i < 2; i++) {
		n += sprintf(b + n, "\nPacket Statistics for %s:\n", interfaces_text[i]);

		for(j =0; j < nr_stats; j++) {
			n += sprintf(b + n, "%s=%lu\n", stats_text[j], i2r[i].stats[j]);
		}
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
			send_buf(i2r + i, buf, sizeof(b), beacon_mc->ai + i);
		} else
			send_inline(i2r + i, &b, sizeof(b), beacon_mc->ai + i);
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


static int event_loop(void)
{
	unsigned timeout = 1000;
	struct pollfd pfd[8] = {
		{ i2r[INFINIBAND].rdma_events->fd, POLLIN|POLLOUT, 0},
		{ i2r[ROCE].rdma_events->fd, POLLIN|POLLOUT, 0},
		{ i2r[INFINIBAND].comp_events->fd, POLLIN|POLLOUT, 0},
		{ i2r[ROCE].comp_events->fd, POLLIN|POLLOUT,0},
		{ i2r[INFINIBAND].context->async_fd, POLLIN|POLLOUT, 0},
		{ i2r[ROCE].context->async_fd, POLLIN|POLLOUT, 0},
		{ i2r[INFINIBAND].sock_nl, POLLIN|POLLOUT, 0},
		{ i2r[ROCE].sock_nl, POLLIN|POLLOUT, 0}
	};
	int events;
	int i;

	for(i = 0; i < NR_INTERFACES; i++) {
		/* Receive Buffers */
		post_receive_buffers(i2r + i);
		/* And request notifications if something happens */
		ibv_req_notify_cq(i2r[i].cq, 0);
	}

loop:
	events = poll(pfd, 8, timeout);

	if (terminated)
		goto out;

	if (events < 0) {
		syslog(LOG_WARNING, "Poll failed with error=%d\n", errno);
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

	if (pfd[0].revents & (POLLIN|POLLOUT))
		handle_rdma_event(INFINIBAND);

	if (pfd[1].revents & (POLLIN|POLLOUT))
		handle_rdma_event(ROCE);

	if (pfd[2].revents & (POLLIN|POLLOUT))
		handle_comp_event(INFINIBAND);

	if (pfd[3].revents & (POLLIN|POLLOUT))
		handle_comp_event(ROCE);

	if (pfd[4].revents & (POLLIN|POLLOUT))
		handle_async_event(INFINIBAND);

	if (pfd[5].revents & (POLLIN|POLLOUT))
		handle_async_event(ROCE);

	if (pfd[6].revents & (POLLIN|POLLOUT))
		handle_netlink_event(INFINIBAND);

	if (pfd[7].revents & (POLLIN|POLLOUT))
		handle_netlink_event(ROCE);

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
		syslog(LOG_CRIT, "Cannot open pidfile. Error %d\n", errno);
		abort();
	}

	if (fcntl(pid_fd, F_SETLK, &fl) < 0) {
		syslog(LOG_CRIT, "ib2roce already running.\n");
		abort();
	}

	if (ftruncate(pid_fd, 0) < 0) {
		syslog(LOG_CRIT, "Cannot truncate pidfile. Error %d\n", errno);
		abort();
	}

	n = snprintf(buf, sizeof(buf), "%ld", (long) getpid());

	if (write(pid_fd, buf, n) != n) {
		syslog(LOG_CRIT, "Cannot write pidfile. Error %d\n", errno);
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
		setup_flow(ROCE);
		setup_flow(INFINIBAND);
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