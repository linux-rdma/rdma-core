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
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <fcntl.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <rdma/rdma_cma.h>
#include <infiniband/ib.h>
#include <infiniband/verbs.h>
#include <poll.h>
#include <sys/mman.h>

#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_arp.h>

#include <infiniband/umad_cm.h>
#include <infiniband/umad_str.h>
#include "packet.h"
#include "errno.h"
#include "bth_hdr.h"
#include "ib_hdrs.h"
#include "fifo.h"
#include "hash.h"
#include "ibraw.h"

#define VERSION "2022.0220"

#define MIN(a,b) (((a)<(b))?(a):(b))

#define ROCE_PORT 4791
#define ETHERTYPE_ROCE 0x8915

#define BEACON_SIGNATURE 0xD3ADB33F

// #define NETLINK_SUPPORT
// #define LEARN
// #define HAVE_MSTFLINT
// #define DEBUG

/* Globals */

static unsigned default_port = 0;	/* Port to use to bind to devices and for MC groups that do not have a port (if a port is required) */
static bool debug = false;		/* Stay in foreground, print more details */
static bool background = false;		/* Are we actually running in the background ? */
static bool terminated = false;		/* Daemon received a signal to terminate */
static bool update_requested = false;	/* Received SIGUSR1. Dump all MC data details */
static bool beacon = false;		/* Announce our presence (and possibly coordinate between multiple instances in the future */
static bool bridging = true;		/* Allow briding */
static bool unicast = false;		/* Bridge unicast packets */
static bool flow_steering = false;	/* Use flow steering to filter packets */
static int log_packets = 0;		/* Show details on discarded packets */
static int testing = false;		/* Run some tests on startup */


/* Timestamp in milliseconds */
static unsigned long timestamp(void)
{
	struct timespec t;

	clock_gettime(CLOCK_REALTIME, &t);
	return t.tv_sec * 1000 + (t.tv_nsec + 500000) / 1000000;
}

__attribute__ ((format (printf, 2, 3)))
static void logg(int prio, const char *fmt, ...)
{
	va_list valist;

	va_start(valist, fmt);

	if (background)
		vsyslog(prio, fmt, valist);
	else
		vprintf(fmt, valist);
}

/*
 * Handling of special Multicast Group MGID encodings on Infiniband
 */
#define nr_mgid_signatures 5

struct mgid_signature {		/* Manage different MGID formats used */
	unsigned short signature;
	const char *id;
	bool port;		/* Port field is used in MGID */
	bool full_ipv4;		/* Full IP address */
	bool pkey;		/* Pkey in MGID */
} mgid_signatures[nr_mgid_signatures] = {
	{	0x0000, "RDMA", false, false, true },
	{	0x401B,	"IPv4",	false, false, true },
	{	0x601B,	"IPv6",	false, false, true },
	{	0xA01B,	"CLLM", true, true, false },
	{	0x4001, "IB",	false, false, false }
};

struct mgid_signature *mgid_mode = mgid_signatures + 3;		/* CLLM is the default */

/*
 * Basic RDMA interface management
 */

#define MAX_GID 20
#define MAX_INLINE_DATA 64

static char *ib_name, *roce_name;

enum interfaces { INFINIBAND, ROCE, NR_INTERFACES };

static const char *interfaces_text[NR_INTERFACES] = { "Infiniband", "ROCE" };

enum stats { packets_received, packets_sent, packets_bridged_mc, packets_bridged_uc, packets_invalid,
		join_requests, join_failure, join_success,
		leave_requests,
		nr_stats
};

static const char *stats_text[nr_stats] = {
	"PacketsReceived", "PacketsSent", "PacketsBridgedMC", "PacketsBridgedUC", "PacketsInvalid",
	"JoinRequests", "JoinFailures", "JoinSuccess",
	"LeaveRequests"
};

static int cq_high = 0;	/* Largest batch of CQs encountered */

struct rdma_channel {
	struct i2r_interface *i;	/* The network interface of this channel */
	struct ibv_qp *qp;		/* Points to QP regardless of method used */
	struct ibv_flow *flow;
	unsigned int active_receive_buffers;
	unsigned int nr_cq;
	unsigned long stats[nr_stats];
	bool rdmacm;		/* Channel uses RDMACM calls */
	bool listening;		/* Channel is listening for connections */
	const char *text;
	struct rdma_unicast *ru;
	union {
		struct { /* RDMACM status */
			struct ibv_comp_channel *comp_events;
			struct ibv_pd *pd;
			struct rdma_cm_id *id;
			struct sockaddr *bindaddr;
			struct ibv_cq *cq;
			struct ibv_mr *mr;
		};
		/* Basic RDMA channel without RDMACM */
		struct ibv_qp_attr attr;
	};
};

/* 
 * Structure for looking up endpoint information.
 * This allows IP addresses to be translated into GIDs and LIDs
 */
struct endpoint_info {
	struct in_addr addr;
	union ibv_gid gid;
	unsigned short lid;
};

/* Object to describe a connection between two hosts */
struct connection {
	struct endpoint_info *e[2];
	unsigned long qp[2];			/* QP Numbers on thoses endpoints */
};

static struct i2r_interface {
	struct ibv_context *context;		/* Not for RDMA CM use */
	struct rdma_event_channel *rdma_events;
	struct rdma_channel *multicast;
	struct rdma_channel *ud;
	struct rdma_channel *raw;
	struct ibv_comp_channel *comp_events;
	struct ibv_cq *cq;
	struct ibv_pd *pd;
	struct ibv_mr *mr;
	unsigned port;
	unsigned mtu;
	unsigned maclen;
	const char *text;
	char if_name[IFNAMSIZ];
	uint8_t if_mac[ETH_ALEN];
	struct sockaddr_in if_addr;
	struct sockaddr_in if_netmask;
	unsigned ifindex;
	unsigned gid_index;
	union ibv_gid gid;
	struct ibv_device_attr device_attr;
	struct ibv_port_attr port_attr;
	int iges;
	struct ibv_gid_entry ige[MAX_GID];
	struct fifo resolve_queue;		/* List of send buffers with unresolved addresses */
	struct hash *ep;			/* Hash of all endpoints */
} i2r[NR_INTERFACES];

enum hashes { hash_ip, hash_mac, hash_gid, hash_lid, nr_hashes };

static unsigned keylength[nr_hashes] = { 4, 6, 16, 2 };

struct rdma_unicast *hash_table[nr_hashes][0x100];

static int nr_rdma_unicast = 0;

/* Enough to fit a GID */
#define hash_max_keylen 16

struct hash_item {
	struct rdma_unicast *next;	/* Linked list to avoid collisions */
	unsigned hash;
	bool member;
	uint8_t key[hash_max_keylen];
};

/*
 * Information provided by RDMA subsystem for how
 * to send a stream to an endpoint that
 * maybe multicast or unicast.
 */
struct ah_info {
	struct ibv_ah *ah;	/* Endpoint Identification */
	unsigned remote_qpn;	/* Address on the Endpoint */
	unsigned remote_qkey;
};

/*
 * A Unicastconnection to a certain port and host with
 * a list of pending I/O items and an rdma channel
 */

enum uc_state { UC_NONE, UC_ADDR_REQ, UC_ROUTE_REQ, UC_CONN_REQ, UC_CONNECTED, UC_ERROR };

struct rdma_unicast {
	struct i2r_interface *i;
	enum uc_state state;
	struct sockaddr_in *sin;	/* Target address */
	struct rdma_channel *c;		/* Channel for resolution and I/O */
	struct fifo pending;		/* Buffers waiting on resolution to complete */
	struct ah_info ai;		/* If ai.ah != NULL then the address info is valid */
	struct hash_item hash[nr_hashes];
#ifdef NETLINK_SUPPORT
	short state;		/* Last netlink state */
	short flags;		/* Last netlink flags */
#endif
};

static inline void st(struct rdma_channel *c, enum stats s)
{
	c->stats[s]++;
}

/* Forwards */
static void add_event(unsigned long time_in_ms, void (*callback));
static struct rdma_unicast *new_rdma_unicast(struct i2r_interface *i, struct sockaddr_in *sin);

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
		logg(LOG_CRIT, "No RDMA devices present.\n");
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
			logg(LOG_CRIT, "Cannot open device %s\n", ibv_get_device_name(d));
			return 1;
		}

		if (ibv_query_device(c, &dattr)) {
			logg(LOG_CRIT, "Cannot query device %s\n", ibv_get_device_name(d));
			return 1;
		}

		for (port = 1; port <= dattr.phys_port_cnt; port++) {
			struct ibv_port_attr attr;

			if (ibv_query_port(c, port, &attr)) {
				logg(LOG_CRIT, "Cannot query port %s:%d\n", ibv_get_device_name(d), port);
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

		if (roce_name && roce_name[0] == '-')
			/* Disabled on the command line */
			bridging = false;
		else {
			if (roce_name) {
				logg(LOG_CRIT, "ROCE device %s not found\n", roce_name);
				return 1;
			}
			/* There is no ROCE device so we cannot bridge */
			bridging = false;
		}
	}

	if (!i2r[INFINIBAND].context) {

		if ((ib_name && ib_name[0] == '-') && bridging)
			/* Disabled on the command line */
			bridging = false;
		else {
			if (ib_name)
				/* User specd IB device */
				logg(LOG_CRIT, "Infiniband device %s not found.\n", ib_name);
			else {
				if (!bridging) {
					logg(LOG_CRIT, "No RDMA Devices available.\n");
					return 1;
				}
				/* We only have a ROCE device but we cannot bridge */
				bridging = false;
			}
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

enum mc_status { MC_OFF, MC_JOINING, MC_JOINED, MC_ERROR, NR_MC_STATUS };

const char *mc_text[NR_MC_STATUS] = { "Inactive", "Joining", "Joined", "Error" };

/* A multicast group.
 * ah_info points to multicast address and QP number in use
 * for the stream. There are no "ports" unless they are
 * embedded in the GID (like done by CLLM).
 */
static struct mc {
	struct in_addr addr;
	enum mc_status status[2];
	bool sendonly[2];
	bool beacon;
	struct ah_info ai[2];
	struct sockaddr *sa[2];
	struct mgid_signature *mgid_mode;
	const char *text;
} mcs[MAX_MC];

struct hash *mc_hash;

static struct mc *hash_lookup_mc(struct in_addr addr)
{
	unsigned a = ntohl(addr.s_addr) | 0xe0000000; /* Infiniband may strip top 4 bits so provide them */
	struct in_addr x = {
		.s_addr = htonl(a)
	};

	return hash_find(mc_hash, &x);
}

static int hash_add_mc(struct mc *m)
{
	if (hash_find(mc_hash, &m->addr))
		return -EEXIST;

	hash_add(mc_hash, m);
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

/*
 * Parse an address with port number [:xxx] and/or mgid format [/YYYY]
 */
static struct sockaddr_in *parse_addr(const char *arg, int port,
	struct mgid_signature **p_mgid_mode, bool mc_only)
{
	struct addrinfo *res;
	char *service;
	const struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP
	};
	struct sockaddr_in *si;
	char *p;
	int ret;
	struct mgid_signature *mgid;
	struct in_addr addr;
	char *a = strdupa(arg);

	service = strchr(a, ':');

	if (service) {

		*service++ = 0;
		p = service;

	} else {
		char *s = alloca(10);

		snprintf(s, 10, "%d", port);
		service = s;
		p = a;
	}

	p = strchr(p, '/');
	if (p) {
		*p++ = 0;
		mgid = find_mgid_mode(p);

		if (!mgid)
			return NULL;
	} else
		mgid = mgid_mode;

	ret = getaddrinfo(a, service, &hints, &res);
	if (ret) {
		fprintf(stderr, "getaddrinfo() failed (%s) - invalid IP address.\n", gai_strerror(ret));
		return NULL;
	}

	si = malloc(sizeof(struct sockaddr_in));
	memcpy(si, res->ai_addr, sizeof(struct sockaddr_in));
	freeaddrinfo(res);

	addr = si->sin_addr;
	if (mc_only && !IN_MULTICAST(ntohl(addr.s_addr))) {
		fprintf(stderr, "Not a multicast address (%s)\n", arg);
		return NULL;
	}

	*p_mgid_mode = mgid;
	return si;
}

/* Setup the addreses for ROCE and INFINIBAND based on a ipaddr:port spec */
static void setup_mc_addrs(struct mc *m, struct sockaddr_in *si)
{
	m->sa[ROCE] = (struct sockaddr  *)si;
	m->sa[INFINIBAND] = m->sa[ROCE];

	if (m->mgid_mode->signature) {
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
			/* WTF? */
			*mgid_pkey = id(INFINIBAND)->route.addr.addr.ibaddr.pkey;

		if (mg->port)
			*mgid_port = si->sin_port;

		if (!mg->full_ipv4)
			/* Strip to 28 bits according to RFC */
			multicast &= 0x0fffffff;

		*mgid_ipv4 = htonl(multicast);

		m->sa[INFINIBAND] = (struct sockaddr *)saib;
	}
}

/* Multicast group specifications on the command line */
static int new_mc_addr(char *arg,
	bool sendonly_infiniband,
	bool sendonly_roce)
{
	struct sockaddr_in *si;
	struct mc *m = mcs + nr_mc;
	int ret;

	if (nr_mc == MAX_MC) {
		fprintf(stderr, "Too many multicast groups\n");
		return 1;
	}

	m->sendonly[INFINIBAND] = sendonly_infiniband;
	m->sendonly[ROCE] = sendonly_roce;
	m->text = strdup(arg);

	si = parse_addr(arg, default_port, &m->mgid_mode, true);
	if (!si)
		return 1;

	m->addr = si->sin_addr;
	ret = hash_add_mc(m);
	if (ret) {
		fprintf(stderr, "Duplicate multicast address (%s)\n", arg);
		goto out;
	}

	setup_mc_addrs(m, si);
	nr_mc++;
	ret = 0;

out:
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
		logg(LOG_ERR, "Failed to create join request %s:%d on %s. Error %s\n",
			inet_ntoa(addr), port,
			interfaces_text[i],
			errname());
		return 1;
	}
	logg(LOG_NOTICE, "Join Request %sMC group %s:%d on %s.\n",
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
	logg(LOG_NOTICE, "Leaving MC group %s on %s .\n",
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

static unsigned nr_buffers = 100000;
static bool huge = false;

#define BUFFER_SIZE 8192
#define META_SIZE 1024
#define DATA_SIZE (BUFFER_SIZE - META_SIZE)
/*
 * Buf is page aligned and contains 2 pages. The layout attempts to put critical components
 * at page boundaries
 */
struct buf {
	uint8_t raw[DATA_SIZE];		/* Raw Frame */
	union {
		struct {
			struct buf *next;	/* Next free buffer */
			bool free;
			struct rdma_channel *c;	/* Which Channels does this buffer belong to */

			bool ether_valid;	/* Ethernet header valid */
			bool ip_valid;		/* IP header valid */
			bool udp_valid;		/* Valid UDP header */
			bool bth_valid;		/* Valid BTH header */
			bool grh_valid;		/* Valid GRH header */
			bool imm_valid;		/* unsigned imm is valid */
			bool ip_csum_ok;	/* Hardware check if IP CSUM was ok */

			uint8_t *cur;		/* Current position in the buffer */
			uint8_t *end;		/* Pointer to the last byte in the packet + 1 */
			unsigned imm;		/* Immediate data from the WC */

			unsigned ethertype;	/* Frame type */

			/* Structs pulled out of the frame */
			struct immdt immdt;	/* BTH subheader */
			struct ibv_grh grh;
			struct ether_header e;
			struct iphdr ip;
			struct udphdr udp;
			struct bth bth;
			struct deth deth;	/* BTH subheader */
			struct pgm_header pgm;	/* RFC3208 header */
			struct umad_hdr umad;
		};
		uint8_t meta[META_SIZE];
	};
};

static void pull(struct buf *buf, void *dest, unsigned length)
{
	memcpy(dest, buf->cur, length);
	buf->cur += length;
}

#define PULL(__BUF, __VAR) pull(__BUF, &(__VAR), sizeof(__VAR))

static void beacon_received(struct buf *buf);

static int send_buf(struct buf *buf, struct rdma_unicast *ra);

static struct buf *buffers;

static struct buf *nextbuffer;	/* Pointer to next available RDMA buffer */

static void free_buffer(struct buf *buf)
{
#ifdef DEBUG
	memset(buf->raw, 0, DATA_SIZE);
#endif
	buf->free = true;
	buf->next = nextbuffer;
	nextbuffer = buf;
}

/* Remove all buffers related to a channel */
static void clear_channel_bufs(struct rdma_channel *c)
{
	struct buf *buf;

	for (buf = buffers; buf < buffers + nr_buffers; buf++) {

		if (!buf->free && buf->c == c)
			free_buffer(buf);
	}
}

static void init_buf(void)
{
	int i;
	unsigned flags;

	if (sizeof(struct buf) != BUFFER_SIZE) {
		logg(LOG_CRIT, "struct buf is not 8k as required\n");
		abort();
	}

	flags = MAP_PRIVATE | MAP_ANONYMOUS;
	if (huge)
		flags |= MAP_HUGETLB;

	buffers = mmap(0, nr_buffers * BUFFER_SIZE, PROT_READ|PROT_WRITE, flags, -1, 0);
	if (!buffers) {
		logg(LOG_CRIT, "Cannot allocate %d KB of memory required for %d buffers. Error %s\n",
				nr_buffers * (BUFFER_SIZE / 1024), nr_buffers, errname());
		abort();
	}

	/*
	 * Free in reverse so that we have a linked list
	 * starting at the first element which points to
	 * the second and so on.
	 */
	for (i = nr_buffers; i > 0; i--)
		free_buffer(&buffers[i-1]);
}

static struct buf *alloc_buffer(struct rdma_channel *c)
{
	struct buf *buf = nextbuffer;

	if (buf) {
		nextbuffer = buf->next;
		buf->free = false;
	}
	buf->c = c;

#ifdef DEBUG
	buf->next = NULL;

	for(uint8_t *q = buf->raw; q < buf->raw + DATA_SIZE; q++)
		if (*q)
			abort();
#endif
	return buf;
}

static char hexbyte(unsigned x)
{
	if (x < 10)
		return '0' + x;

	return x - 10 + 'a';
}

static char *__hexbytes(char *b, uint8_t *q, unsigned len, char separator)
{
	unsigned i;
	char *p = b;

	for(i = 0; i < len; i++) {
		unsigned n = *q++;
		*p++ = hexbyte( n >> 4 );
		*p++ = hexbyte( n & 0xf);
		if (i < len - 1)
			*p++ = separator;
		else
			*p++ = 0;
	}
	return b;
}

static char *_hexbytes(uint8_t *q, unsigned len)
{
	static char b[150];

	return __hexbytes(b, q, len, ' ');
}

static char *payload_dump(uint8_t *p)
{
	static char buf[150];

	__hexbytes(buf, p, 48, ' ');
	return buf;
}

/* Dump GRH and the beginning of the packet */
static void dump_buf_grh(struct buf *buf)
{
	char xbuf[INET6_ADDRSTRLEN];
	char xbuf2[INET6_ADDRSTRLEN];

	logg(LOG_NOTICE, "Unicast GRH flow=%ux Len=%u next_hdr=%u hop_limit=%u SGID=%s DGID:%s Packet=%s\n",
			ntohl(buf->grh.version_tclass_flow), ntohs(buf->grh.paylen), buf->grh.next_hdr, buf->grh.hop_limit,
			inet_ntop(AF_INET6, &buf->grh.sgid, xbuf2, INET6_ADDRSTRLEN),
			inet_ntop(AF_INET6, &buf->grh.dgid, xbuf, INET6_ADDRSTRLEN),
			payload_dump(buf->cur));
}

static char *pgm_dump(struct pgm_header *p)
{
	static char buf[250];

	snprintf(buf, sizeof(buf), "PGM SPORT=%d DPORT=%d PGM-Type=%x Opt=%x Checksum=%x GSI=%s TSDU=%d\n",
			p->pgm_sport, p->pgm_dport, p->pgm_type, p->pgm_options, p->pgm_checksum,
			_hexbytes(p->pgm_gsi, 6), p->pgm_tsdu_length);
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

	sge.length = DATA_SIZE;
	sge.lkey = c->mr->lkey;

	while (c->active_receive_buffers < limit) {

		struct buf *buf = alloc_buffer(c);


		if (!buf) {
			logg(LOG_NOTICE, "No free buffers left\n");
			ret = -ENOMEM;
			break;
		}

		/* Use the buffer address for the completion handler */
		recv_wr.wr_id = (uint64_t)buf;
		sge.addr = (uint64_t)buf->raw;
		ret = ibv_post_recv(c->qp, &recv_wr, &recv_failure);
		if (ret) {
			free_buffer(buf);
			logg(LOG_WARNING, "ibv_post_recv failed: %d\n", ret);
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
	clear_channel_bufs(c);
	free(c);
}

static void qp_destroy(struct i2r_interface *i)
{
	channel_destroy(i->multicast);
	i->multicast = NULL;

#ifdef HAVE_MSTFLINT
	if (i == i2r + INFINIBAND) {
		if (clear_ib_sniffer(i->port, i->raw->qp))
			logg(LOG_ERR, "Failed to switch off sniffer mode on %s\n", i->raw->text);
	}
#endif

	channel_destroy(i->raw);
	i->raw = NULL;

}

/* Retrieve Kernel Stack info about the interface */
static void get_if_info(struct i2r_interface *i)
{
	int fh = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	struct ifreq ifr;
	const char *reason = "socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)";

	if (fh < 0)
		goto err;

	/*
	 * Work around the quirk of ifindex always being zero for
	 * INFINIBAND interfaces. Just assume its ib0.
	 */
	if (!i->ifindex && i - i2r == INFINIBAND) {

		logg(LOG_WARNING, "Assuming ib0 is the IP device name for %s\n",
		     ibv_get_device_name(i->context->device));
		strcpy(i->if_name, "ib0");

		memcpy(ifr.ifr_name, i->if_name, IFNAMSIZ);

		/* Find if_index */
		reason = "ioctl SIOCGIFINDEX";
		if (ioctl(fh, SIOCGIFINDEX, &ifr) < 0)
			goto err;

		i->ifindex = ifr.ifr_ifindex;

	} else {

		ifr.ifr_ifindex = i->ifindex;

		reason= "ioctl SIOGCIFNAME";
		if (ioctl(fh, SIOCGIFNAME, &ifr) < 0)
			goto err;

		memcpy(i->if_name, ifr.ifr_name, IFNAMSIZ);
	}

	reason="ioctl SIOCGIFADDR";
	if (ioctl(fh, SIOCGIFADDR, &ifr) < 0)
		goto err;

	memcpy(&i->if_addr, &ifr.ifr_addr, sizeof(struct sockaddr_in));

	ioctl(fh, SIOCGIFNETMASK, &ifr);
	memcpy(&i->if_netmask, &ifr.ifr_netmask, sizeof(struct sockaddr_in));
	ioctl(fh, SIOCGIFHWADDR, &ifr);
	memcpy(&i->if_mac, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	goto out;

err:
	logg(LOG_CRIT, "Cannot determine IP interface setup for %s %s : %s\n",
		     ibv_get_device_name(i->context->device), reason, errname());

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
		bool send = c->i == i2r + ROCE;

		c->attr.qp_state = IBV_QPS_RTR;
		/* Only Ethernet can send on a raw socket */
		ret = ibv_modify_qp(c->qp, &c->attr, IBV_QP_STATE);
		if (ret)
			logg(LOG_CRIT, "ibv_modify_qp: Error when moving %s to RTR state. %s\n", c->text, errname());

		if (send) {
			c->attr.qp_state = IBV_QPS_RTS;
			ret = ibv_modify_qp(c->qp, &c->attr, IBV_QP_STATE);
			if (ret)
				logg(LOG_CRIT, "ibv_modify_qp: Error when moving %s to RTS state. %s\n", c->text, errname());
		}
		logg(LOG_NOTICE, "QP %s moved to state %s\n", c->text,  send ? "RTS/RTR" : "RTR" );
	}
}

static struct rdma_channel *new_rdma_channel(struct i2r_interface *i)
{
	struct rdma_channel *c = calloc(1, sizeof(struct rdma_channel));

	c->i = i;
	c->rdmacm = true;

	return c;
}

static const char *make_ifname(struct i2r_interface *i, const char *x)
{
	char *p;

	p = malloc(strlen(i->text) + strlen(x) + 1);
	strcpy(p, i->text);
	strcat(p, x);
	return p;
}


static struct rdma_channel *create_rdma_id(struct i2r_interface *i, struct sockaddr *sa)
{
	struct rdma_channel *c = new_rdma_channel(i);
	int ret;


	c->text = make_ifname(i, "-multicast");

	c->bindaddr = sa;
	ret = rdma_create_id(i->rdma_events, &c->id, c, RDMA_PS_UDP);
	if (ret) {
		logg(LOG_CRIT, "Failed to allocate RDMA CM ID for %s failed (%s).\n",
			c->text, errname());
		return NULL;
	}

	ret = rdma_bind_addr(c->id, c->bindaddr);
	if (ret) {
		logg(LOG_CRIT, "Failed to bind %s interface. Error %s\n",
			c->text, errname());
		return NULL;
	}
	return c;
}

static int allocate_rdmacm_qp(struct rdma_channel *c, unsigned nr_cq, bool multicast)
{
	struct ibv_qp_init_attr_ex init_qp_attr_ex;
	int ret;

	/*
	 * Must alloc pd for each rdma_cm_id due to limitation in rdma_create_qp
	 * There a multiple struct ibv_context *s around . Need to use the right one
	 * since rdma_create_qp validates the alloc pd ibv_context pointer.
	 */
	c->pd = ibv_alloc_pd(c->id->verbs);
	if (!c->pd) {
		logg(LOG_CRIT, "ibv_alloc_pd failed for %s.\n",
			c->text);
		return 1;
	}

	/*
	 * Must alloate comp_events channel using the context created by rdmacm
	 * otherwise ibv_create_cq will fail.
	 */
	c->comp_events = ibv_create_comp_channel(c->id->verbs);
	if (!c->comp_events) {
		logg(LOG_CRIT, "ibv_create_comp_channel failed for %s : %s.\n",
			c->text, errname());
		abort();
	}

	c->nr_cq = nr_cq;
	c->cq = ibv_create_cq(c->id->verbs, nr_cq, c, c->comp_events, 0);
	if (!c->cq) {
		logg(LOG_CRIT, "ibv_create_cq failed for %s : %s nr_cq=%d.\n",
			c->text, errname(), nr_cq);
		return 1;
	}

	memset(&init_qp_attr_ex, 0, sizeof(init_qp_attr_ex));
	init_qp_attr_ex.cap.max_send_wr = nr_cq;
	init_qp_attr_ex.cap.max_recv_wr = nr_cq;
	init_qp_attr_ex.cap.max_send_sge = 1;	/* Highly sensitive settings that can cause -EINVAL if too large (10 f.e.) */
	init_qp_attr_ex.cap.max_recv_sge = 1;
	init_qp_attr_ex.cap.max_inline_data = MAX_INLINE_DATA;
	init_qp_attr_ex.qp_context = c;
	init_qp_attr_ex.sq_sig_all = 0;
	init_qp_attr_ex.qp_type = IBV_QPT_UD;
	init_qp_attr_ex.send_cq = c->cq;
	init_qp_attr_ex.recv_cq = c->cq;

	init_qp_attr_ex.comp_mask = IBV_QP_INIT_ATTR_CREATE_FLAGS|IBV_QP_INIT_ATTR_PD;
	init_qp_attr_ex.pd = c->pd;

	if (multicast)
		init_qp_attr_ex.create_flags = IBV_QP_CREATE_BLOCK_SELF_MCAST_LB;

	ret = rdma_create_qp_ex(c->id, &init_qp_attr_ex);
	if (ret) {
		logg(LOG_CRIT, "rdma_create_qp_ex failed for %s. Error %s. #CQ=%d\n",
				c->text, errname(), nr_cq);
		return 1;
	}

	/* Copy QP to convenient location that is shared by all types of channels */
	c->qp = c->id->qp;
	c->mr = ibv_reg_mr(c->pd, buffers, nr_buffers * sizeof(struct buf), IBV_ACCESS_LOCAL_WRITE);
	if (!c->mr) {
		logg(LOG_CRIT, "ibv_reg_mr failed for %s:%s.\n", c->text, errname());
		return 1;
	}
	return 0;
}

/* Not using rdmacm so this is easier on the callbacks */
static struct rdma_channel *create_channel(struct i2r_interface *i, int port, unsigned nr_cq, const char *text, int qp_type)
{
	struct rdma_channel *c = new_rdma_channel(i);
	int ret;
	struct ibv_qp_init_attr_ex init_qp_attr_ex;

	c->i = i;
	c->rdmacm = false;

	c->text = make_ifname(i, text);

	c->nr_cq = nr_cq;
	c->cq = ibv_create_cq(i->context, nr_cq, c, i->comp_events, 0);
	if (!c->cq) {
		logg(LOG_CRIT, "ibv_create_cq failed for %s.\n",
			c->text);
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
	init_qp_attr_ex.qp_type = qp_type,
	init_qp_attr_ex.send_cq = c->cq;
	init_qp_attr_ex.recv_cq = c->cq;

	init_qp_attr_ex.comp_mask = IBV_QP_INIT_ATTR_CREATE_FLAGS|IBV_QP_INIT_ATTR_PD;
	init_qp_attr_ex.pd = c->pd;
	init_qp_attr_ex.create_flags = 0;

	c->qp = ibv_create_qp_ex(i->context, &init_qp_attr_ex);
	if (!c->qp) {
		logg(LOG_CRIT, "ibv_create_qp_ex failed for %s. Error %s. Port=%d #CQ=%d\n",
				c->text, errname(), port, nr_cq);
		return NULL;
	}

	c->attr.port_num = port;
	c->attr.qp_state = IBV_QPS_INIT;
	c->attr.pkey_index = 0;
	c->attr.qkey = RDMA_UDP_QKEY;

//	c->attr.qkey = 0x12345;		/* Default QKEY from ibdump source code */

	ret = ibv_modify_qp(c->qp, &c->attr,
		       (i == i2r + ROCE) ?
				(IBV_QP_STATE | IBV_QP_PORT) :
				( IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_QKEY)
	);

	if (ret) {
		logg(LOG_CRIT, "ibv_modify_qp: Error when moving to Init state. %s", errname());
		return NULL;
	}

	return c;
}

static struct rdma_channel *create_ud_channel(struct i2r_interface *i, int port, unsigned nr_cq)
{
	return create_channel(i, port, nr_cq, "-ud", IBV_QPT_UD);
}

static struct rdma_channel *create_raw_channel(struct i2r_interface *i, int port, unsigned nr_cq)
{
	return create_channel(i, port, nr_cq, "-raw", i == i2r + ROCE  ? IBV_QPT_RAW_PACKET : IBV_QPT_UD);
}


static void setup_interface(enum interfaces in)
{
	struct i2r_interface *i = i2r + in;
	struct ibv_gid_entry *e;
	char buf[INET6_ADDRSTRLEN];
	struct sockaddr_in *sin;

	if (in == INFINIBAND)
		i->maclen = 20;
	else
		i->maclen = 6;

	if (!i->context)
		return;

	i->text = interfaces_text[in];

	/* Determine the GID */
	i->iges = ibv_query_gid_table(i->context, i->ige, MAX_GID, 0);

	if (i->iges <= 0) {
		logg(LOG_CRIT, "Error %s. Failed to obtain GID table for %s\n",
			errname(), i->text);
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
		logg(LOG_CRIT, "Failed to find GIDs in GID table for %s\n",
			i->text);
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
		logg(LOG_CRIT, "rdma_create_event_channel() for %s failed (%s).\n",
			i->text, errname());
		abort();
	}

	sin = calloc(1, sizeof(struct sockaddr_in));
	sin->sin_family = AF_INET;
	sin->sin_addr = i->if_addr.sin_addr;
	sin->sin_port = htons(default_port);

	i->multicast = create_rdma_id(i, (struct sockaddr *)sin);

	if (!i->multicast)
		abort();

	if (allocate_rdmacm_qp(i->multicast, 1000, true))
		abort();

	i->pd = ibv_alloc_pd(i->context);
	if (!i->pd) {
		logg(LOG_CRIT, "ibv_alloc_pd failed for %s.\n", i->text);
		abort();
	}

	i->comp_events = ibv_create_comp_channel(i->context);
	if (!i->comp_events) {
		logg(LOG_CRIT, "ibv_create_comp_channel failed for %s : %s.\n",
					i->text, errname());
		abort();
	}

	i->mr = ibv_reg_mr(i->pd, buffers, nr_buffers * sizeof(struct buf), IBV_ACCESS_LOCAL_WRITE);
	if (!i->mr) {
		logg(LOG_CRIT, "ibv_reg_mr failed for %s.\n", i->text);
		abort();
	}

	if (unicast) {
		i->ud = create_ud_channel(i, i->port, 100);
		i->raw = create_raw_channel(i, i->port, 100);
	}

	logg(LOG_NOTICE, "%s interface %s/%s(%d) port %d GID=%s/%d IPv4=%s:%d CQs=%u/%u/%u MTU=%u.\n",
		i->text,
		ibv_get_device_name(i->context->device),
		i->if_name, i->ifindex,
		i->port,
		inet_ntop(AF_INET6, e->gid.raw, buf, INET6_ADDRSTRLEN),i->gid_index,
		inet_ntoa(i->if_addr.sin_addr), default_port,
		i->multicast ? i->multicast->nr_cq: 0,
		i->ud ? i->ud->nr_cq : 0,
		i->raw ? i->raw->nr_cq : 0,
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
			if (i2r[in].context) {
				switch(m->status[in]) {

				case MC_OFF:
					if (_join_mc(m->addr, m->sa[in], port, in, m->sendonly[in], m) == 0)
						m->status[in] = MC_JOINING;
					break;

				case MC_ERROR:

					_leave_mc(m->addr, m->sa[in], in);
					m->status[in] = MC_OFF;
					logg(LOG_WARNING, "Left Multicast group %s on %s due to MC_ERROR\n",
						m->text, interfaces_text[in]);
					break;

				case MC_JOINED:
					break;

				default:
					logg(LOG_ERR, "Bad MC status %d MC %s on %s\n",
					       m->status[in], m->text, interfaces_text[in]);
					break;
			}
		}

		mcs_per_call++;

		if (mcs_per_call > 10)
			break;

	}
}

static void resolve_start(struct rdma_unicast *);

static void zap_channel(struct rdma_unicast *ru)
{
	struct buf *buf;

	while ((buf = fifo_get(&ru->pending)))		/* Drop pending I/O */
		free_buffer(buf);

	channel_destroy(ru->c);
	if (ru->sin) {
		ru->c = NULL;
		ru->state = UC_NONE;
	} else {
		/* Temporary struct that can go away now */
		free(ru);
		nr_rdma_unicast--;
	}
}

/* Drop the first entry from the list of items to resolve */
static void resolve_end(struct rdma_unicast *ru)
{
	struct i2r_interface *i = ru->i;

	if (ru != fifo_get(&i->resolve_queue))
		abort();

	if (ru->state == UC_CONNECTED) {
		struct buf *buf;

		while ((buf = fifo_get(&ru->pending)))		/* Send pending I/O */
			send_buf(buf, ru);
	} else
		zap_channel(ru);

	/* Resolve the next address */
	ru = fifo_first(&i->resolve_queue);
	if (ru)
		resolve_start(ru);
}

static void resolve_start(struct rdma_unicast *ru)
{
	struct i2r_interface *i = ru->i;

	if (!ru->c) {
		struct sockaddr_in *sin;

		sin = calloc(1, sizeof(struct sockaddr_in));
		sin->sin_family = AF_INET;
		sin->sin_addr = i->if_addr.sin_addr;
		sin->sin_port = 0;
		ru->c = create_rdma_id(i, (struct sockaddr *)sin);
		ru->c->ru = ru;
	}

	if (rdma_resolve_addr(ru->c->id, NULL, (struct sockaddr *)ru->sin, 2000) == 0) {
		ru->state = UC_ADDR_REQ;
		return;
	}

	logg(LOG_ERR, "rdma_resolve_addr error %s on %s for %s:%d\n",
		errname(), ru->c->text, inet_ntoa(ru->sin->sin_addr), ntohs(ru->sin->sin_port));

	resolve_end(ru);
}

/* Resolve Address and send buffer when done */
static void resolve(struct rdma_unicast *ru)
{
	struct i2r_interface *i = ru->i;

	if (fifo_put(&i->resolve_queue, ru))
		resolve_start(ru);
}

static void handle_rdma_event(void *private)
{
	struct i2r_interface *i = private;
	struct rdma_cm_event *event;
	int ret;
	enum interfaces in = i - i2r;
	struct rdma_unicast *ru = fifo_first(&i->resolve_queue);

	ret = rdma_get_cm_event(i->rdma_events, &event);
	if (ret) {
		logg(LOG_WARNING, "rdma_get_cm_event()_ failed. Error = %s\n", errname());
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
					logg(LOG_ERR, "Failed to create AH for Multicast group %s on %s \n",
						m->text, i->text);
					m->status[in] = MC_ERROR;
					break;
				}
				m->status[in] = MC_JOINED;

				/* Things actually work if both multicast groups are joined */
				if (!bridging || m->status[in ^ 1] == MC_JOINED)
					active_mc++;

				logg(LOG_NOTICE, "Joined %s QP=%x QKEY=%x MLID 0x%x sl %u on %s\n",
					inet_ntop(AF_INET6, param->ah_attr.grh.dgid.raw, buf, 40),
					param->qp_num,
					param->qkey,
					param->ah_attr.dlid,
					param->ah_attr.sl,
					i->text);
				st(i->multicast, join_success);
			}
			break;

		case RDMA_CM_EVENT_MULTICAST_ERROR:
			{
				struct rdma_ud_param *param = &event->param.ud;
				struct mc *m = (struct mc *)param->private_data;

				logg(LOG_ERR, "Multicast Error. Group %s on %s\n",
					m->text, i->text);

				/* If already joined then the bridging may no longer work */
				if (!bridging || (m->status[in] == MC_JOINED && m->status[in ^ 1] == MC_JOINED))
				       active_mc--;

				m->status[in] = MC_ERROR;
				st(i->multicast, join_failure);
			}
			break;

		case RDMA_CM_EVENT_ADDR_RESOLVED:
			logg(LOG_NOTICE, "RDMA_CM_EVENT_ADDR_RESOLVED for %s:%d\n",
				inet_ntoa(ru->sin->sin_addr), ntohs(ru->sin->sin_port));

			if (rdma_resolve_route(ru->c->id, 2000) < 0) {

				logg(LOG_ERR, "rdma_resolve_route error %s on %s  %s:%d. Packet dropped.\n",
					errname(), ru->c->text,
					inet_ntoa(ru->sin->sin_addr),
					ntohs(ru->sin->sin_port));
					goto err;
			}
			ru->state = UC_ROUTE_REQ;
			break;

		case RDMA_CM_EVENT_ADDR_ERROR:
			logg(LOG_ERR, "Address resolution error %d on %s  %s:%d. Packet dropped.\n",
				event->status, ru->c->text,
				inet_ntoa(ru->sin->sin_addr),
				ntohs(ru->sin->sin_port));

			goto err;
			break;

		case RDMA_CM_EVENT_ROUTE_RESOLVED:
			{
				struct rdma_conn_param rcp = { };

				logg(LOG_NOTICE, "RDMA_CM_EVENT_ROUTE_RESOLVED for %s:%d\n",
					inet_ntoa(ru->sin->sin_addr), ntohs(ru->sin->sin_port));

				allocate_rdmacm_qp(ru->c, 100, false);

				post_receive(ru->c, 50);
				ibv_req_notify_cq(ru->c->cq, 0);

				if (rdma_connect(ru->c->id, &rcp) < 0) {
					logg(LOG_ERR, "rdma_connecte error %s on %s  %s:%d. Packet dropped.\n",
						errname(), ru->c->text,
						inet_ntoa(ru->sin->sin_addr),
						ntohs(ru->sin->sin_port));

					goto err;
				}
				ru->state = UC_CONN_REQ;
			}
			break;

		case RDMA_CM_EVENT_ROUTE_ERROR:
			logg(LOG_ERR, "Route resolution error %d on %s  %s:%d. Packet dropped.\n",
				event->status, ru->c->text,
				inet_ntoa(ru->sin->sin_addr),
				ntohs(ru->sin->sin_port));

			goto err;
			break;

		case RDMA_CM_EVENT_CONNECT_REQUEST:
			{
				struct rdma_conn_param rcp = { };
				struct rdma_channel *c = new_rdma_channel(i);

				logg(LOG_NOTICE, "RDMA_CM_CONNECT_REQUEST id=%p listen_id=%p\n",
					event->id, event->listen_id);

				c->id->context = c;
				c->text = "incoming-ud-qp";

				if (allocate_rdmacm_qp(c, 100, false))
					goto err;

				if (post_receive(c, 50))
					goto err;

				ibv_req_notify_cq(c->cq, 0);

				rcp.qp_num = c->id->qp->qp_num;
				if (rdma_accept(c->id, &rcp)) {
					logg(LOG_ERR, " rdma_accept error %s\n", errname());
					channel_destroy(c);
				}
				/* Create a structure just for tracking buffers */
				c->ru = new_rdma_unicast(i, NULL);
				c->ru->c = c;
				c->ru->state = UC_CONNECTED;

			}
			break;

		case RDMA_CM_EVENT_DISCONNECTED:
			{
				struct rdma_channel *c = event->id->context;

				logg(LOG_NOTICE, "RDMA_CM_EVENT_DISCONNECTED id=%p %s\n",
					event->id, c->text);

				if (c->ru)
					zap_channel(c->ru);
				else
					channel_destroy(c);
			}
			break;

		case RDMA_CM_EVENT_ESTABLISHED:
			{
				struct ah_info *ai = &ru->ai;

				logg(LOG_NOTICE, "RDMA_CM_EVENT_ESTABLISHED for %s:%d\n",
					inet_ntoa(ru->sin->sin_addr), ntohs(ru->sin->sin_port));

				ai->ah = ibv_create_ah(ru->c->pd, &event->param.ud.ah_attr);
				ai->remote_qpn = event->param.ud.qp_num;
				ai->remote_qkey = event->param.ud.qkey;

				rdma_ack_cm_event(event);
				ru->state = UC_CONNECTED;
				resolve_end(ru);
				return;
			}
			break;

		case RDMA_CM_EVENT_UNREACHABLE:
			logg(LOG_ERR, "Unreachable Port error %d on %s  %s:%d. Packet dropped.\n",
				event->status, ru->c->text,
				inet_ntoa(ru->sin->sin_addr),
				ntohs(ru->sin->sin_port));

			goto err;
			break;

		default:
			logg(LOG_NOTICE, "RDMA Event handler:%s status: %d\n",
				rdma_event_str(event->event), event->status);
			break;
	}

	rdma_ack_cm_event(event);
	return;

err:
	rdma_ack_cm_event(event);
	ru->state = UC_ERROR;
	resolve_end(ru);
}

/*
 * Do not use a buffer but simply include data directly into WR.
 * Advantage: No buffer used and therefore faster since no memory
 * fetch has to be done by the RDMA subsystem and no completion
 * event has to be handled.
 *
 * Space in the WR is limited, so it only works for very small packets.
 */
static int send_inline(struct rdma_channel *c, void *addr, unsigned len, struct ah_info *ai, bool imm_used, unsigned imm)
{
	struct ibv_sge sge = {
		.length = len,
		.addr = (uint64_t)addr
	};
	struct ibv_send_wr wr = {
		.sg_list = &sge,
		.num_sge = 1,
		.opcode = imm_used ? IBV_WR_SEND_WITH_IMM : IBV_WR_SEND,
		.send_flags = IBV_SEND_INLINE,
		.imm_data = imm,
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
		logg(LOG_WARNING, "Failed to post inline send: %s on %s\n", errname(), c->text);
	} else
		if (log_packets > 1)
			logg(LOG_NOTICE, "Inline Send to QPN=%x QKEY=%x %d bytes\n",
				wr.wr.ud.remote_qpn, wr.wr.ud.remote_qkey, len);

	return ret;
}

/*
 * Send data to a target. No metadata is used in struct buf. However, the buffer must be passed to the wc in order
 * to be able to free up resources when done.
 */
static int send_to(struct rdma_channel *c,
	void *addr, unsigned len, struct ah_info *ai,
	bool imm_used, unsigned imm,
	struct buf *buf)
{
	struct ibv_send_wr wr, *bad_send_wr;
	struct ibv_sge sge;
	int ret;

	if (!ai->ah)
		abort();	/* Send without a route */

	buf->c = c;	/* Change ownership to sending channel */

	memset(&wr, 0, sizeof(wr));
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.opcode = imm_used ? IBV_WR_SEND_WITH_IMM: IBV_WR_SEND;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.wr_id = (uint64_t)buf;
	wr.imm_data = imm;

	/* Get addr info  */
	wr.wr.ud.ah = ai->ah;
	wr.wr.ud.remote_qpn = ai->remote_qpn;
	wr.wr.ud.remote_qkey = ai->remote_qkey;

	sge.length = len;
	sge.lkey = c->mr->lkey;
	sge.addr = (uint64_t)addr;

	ret = ibv_post_send(c->qp, &wr, &bad_send_wr);
	if (ret) {
		errno = - ret;
		logg(LOG_WARNING, "Failed to post send: %s on %s\n", errname(), c->text);
	} else
		if (log_packets > 1)
			logg(LOG_NOTICE, "RDMA Send to QPN=%x QKEY=%x %d bytes\n",
				wr.wr.ud.remote_qpn, wr.wr.ud.remote_qkey, len);

	return ret;
}

/* Send buffer based on state in struct buf. Unicast only */
static int send_buf(struct buf *buf, struct rdma_unicast *ra)
{
	unsigned len = buf->end - buf->cur;
	int ret;

	if (len < MAX_INLINE_DATA) {
		ret = send_inline(ra->c, buf->cur, len, &ra->ai, buf->imm_valid, buf->imm);
		if (ret == 0)
			free_buffer(buf);
	} else
		ret = send_to(ra->c, buf->cur, len, &ra->ai, buf->imm_valid, buf->imm, buf);

	return ret;
}

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

static unsigned generate_hash_key(enum hashes type, uint8_t *key, void *p)
{
	int i;
	unsigned sum = 0;

	memcpy(key, p, keylength[type]);

	for (i = 0; i < keylength[type]; i++)
		sum += key[i];

	return sum & 0xff;
}

static struct rdma_unicast *find_key_in_chain(enum hashes type,
	struct rdma_unicast *next, uint8_t *key)
{
	for ( ; next != NULL; next = next->hash[type].next)
		if (memcmp(key, next->hash[type].key, keylength[type]) == 0)
			break;

	return next;
}

static void add_to_hash(struct rdma_unicast *ra, enum hashes type, void *p)
{
	struct hash_item *h = &ra->hash[type];

	if (h->member)
		abort();	/* Already a member of the hash */

	h->hash = generate_hash_key(type, h->key, p);

	/* Duplicate key ? */
	if (find_key_in_chain(type, hash_table[type][h->hash], h->key))
		abort();

	h->next = hash_table[type][h->hash];
	hash_table[type][h->hash] = ra;

	h->member = true;
}

#if 0
static void remove_from_hash(struct rdma_unicast *ra, enum hashes type)
{
	struct hash_item *h = &ra->hash[type];
	unsigned hash = h->hash;
	struct rdma_unicast *next = hash_table[type][hash];
	struct rdma_unicast *prior = NULL;

	for( ; next; next = next->hash[hash].next) {

		if (next == ra)
			break;

		prior = next;

	}

	if (!next)
		abort();	/* Not a in the chain */

	if (!prior) {
		/* This is the only item in the chain */
		hash_table[type][hash] = NULL;
		return;
	}

	prior->hash[type].next = h->next;
	h->member = false;
}
#endif

static struct rdma_unicast *find_in_hash(enum hashes type, void *p)
{
	uint8_t key[hash_max_keylen];
	unsigned hash;

	hash = generate_hash_key(type, key, p);

	return find_key_in_chain(type, hash_table[type][hash], key);
}

static struct rdma_unicast *new_rdma_unicast(struct i2r_interface *i, struct sockaddr_in *sin)
{
	struct rdma_unicast *ra = calloc(1, sizeof(struct rdma_unicast));

	nr_rdma_unicast++;
	ra->i = i;
	ra->sin = sin;
	fifo_init(&ra->pending);
	return ra;
}

static long lookup_ip_from_gid(struct rdma_channel *c, union ibv_gid *v)
{
	struct rdma_unicast *ra;
	char buf[100];

	ra = find_in_hash(hash_gid, v);

	if (ra && ra->hash[hash_ip].member) {
		struct in_addr *in = (struct in_addr *)ra->hash[hash_ip].key;

		return ntohl(in->s_addr);
	}

	/*
	 * Could do ARP for GID -> IP resolution but the GID
	 * should be already be in the ARP cache
	 */
	logg(LOG_ERR, "Could not find AH for %s on %s\n",
		inet_ntop(AF_INET6, v->raw, buf, INET6_ADDRSTRLEN), c->text);

	return 0;
}

#ifdef NETLINK_SUPPORT
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
	char mac[20];
	struct in_addr addr;
	struct rtattr *rta;
	bool have_dst = false;
	bool have_lladdr = false;
	struct rdma_ah *ra;
	const char *action;
	enum hashes mac_hash;
	unsigned offset;


	for(i = i2r;  i < i2r + NR_INTERFACES; i++)
		if (i->ifindex == n->nd.ndm_ifindex)
			break;

	if (i == i2r + INFINIBAND) {
		mac_hash = hash_gid;
		offset = 6;
	} else {
		mac_hash = hash_mac;
		offset = 0;
	}

	for(rta = (struct rtattr *)n->attrbuf; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		switch (rta->rta_type) {

			case NDA_DST:
				memcpy(&addr, RTA_DATA(rta), RTA_PAYLOAD(rta));
				have_dst = true;
				break;

			case NDA_LLADDR:
				have_lladdr = true;
				maclen = RTA_PAYLOAD(rta);
				memcpy(mac, RTA_DATA(rta), maclen);
				break;

			case NDA_CACHEINFO:
			case NDA_PROBES:
				break;

			default:
				logg(LOG_NOTICE, "Netlink; unrecognized RTA type=%d\n", rta->rta_type);
				break;

		}
	};

	if (i >= i2r + NR_INTERFACES) {
		i = NULL;
		goto err;
	}

	if (!have_dst) {
		logg(LOG_ERR, "netlink message without DST\n");
		goto err;
	}

	if (!have_lladdr) {
		logg(LOG_ERR, "netlink message without LLADDR\n");
		goto err;
	}

	if (i->maclen != maclen) {
		logg(LOG_ERR, "netlink message mac length does not match. Expected %d got %d\n",
				i->maclen, maclen);
		goto err;
	}

	ra = find_in_hash(hash_ip, &addr);
	if (ra) {
		/* Already existing entry retrieved by IP address  */
		action = "Update";

	} else {
		ra = find_in_hash(mac_hash, mac + offset);
		if (ra) {
			/* Update existing entry retrieved by MAC address */
			action = "Update";

		} else {
			/* We truly have a new entry */
			ra = new_rdma_ah(i);

			action = "New";
		}
	}

	ra->flags = n->nd.ndm_flags;
	ra->state = n->nd.ndm_state;

	if (!ra->hash[mac_hash].member)
		add_to_hash(ra, mac_hash, mac + offset);

	if (!ra->hash[hash_ip].member)
		add_to_hash(ra, hash_ip, &addr);

	logg(LOG_NOTICE, "%s ARP entry via netlink for %s: IP=%s MAC=%s Flags=%x State=%x\n",
		action,
		i->if_name,
		inet_ntoa(addr),
		hexbytes(mac, maclen),
		ra->flags, ra->state);

	return;

err:
	if (log_packets > 1)
		logg(LOG_NOTICE, "Neigh Event interface=%s type %u Len=%u NL flags=%x ND flags=%x state=%x IP=%s MAC=%s ifindex=%d\n",
				i ? i->if_name: "N/A",
			       	n->nlh.nlmsg_type,  n->nlh.nlmsg_len, n->nlh.nlmsg_flags,
				n->nd.ndm_flags, n->nd.ndm_state,
				inet_ntoa(addr), hexbytes(mac, maclen),
				n->nd.ndm_ifindex);

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
		logg(LOG_CRIT, "Netlink recvmsg error. Errno %s\n", errname());
		return;
	}

	for( ; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
		switch(h->nlmsg_type) {
			case RTM_NEWNEIGH:
			case RTM_GETNEIGH:
			case RTM_DELNEIGH:
				if (!(h->nlmsg_flags & NLM_F_REQUEST)) {
					handle_neigh_event((struct neigh *)h);
				}
				break;
				/* Fall through */

			default:
				if (log_packets > 1)
					logg(LOG_NOTICE, "Unhandled Netlink Message type %u Len=%u flag=%x seq=%x PID=%d\n",
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
		logg(LOG_ERR, "Netlink Send error %s\n", errname());
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
		logg(LOG_CRIT, "Failed to open netlink socket %s.\n", errname());
		abort();
	}

	sal.nl_pid = getpid() + c;
	if (c != nl_monitor)
		sal.nl_groups = 0;

	if (bind(sock_nl[c], (struct sockaddr *)&sal, sizeof(sal)) < 0) {
		logg(LOG_CRIT, "Failed to bind to netlink socket %s\n", errname());
		abort();
	};

	memcpy(&nladdr[c], &sal, sizeof(struct sockaddr_nl));

	if (c != nl_monitor)
		send_netlink_message(c, &nlr.nlh);
}
#else
#endif


static void setup_flow(struct rdma_channel *c)
{
	if (!c)
		return;
#ifdef HAVE_MSTFLINT
	if (c->i == i2r + INFINIBAND) {
		if (set_ib_sniffer(ibv_get_device_name(c->i->context->device), c->i->port, c->qp))
			logg(LOG_ERR, "Failure to set sniffer mode on %s\n", c->text);
		return;
	}
#endif

	if (flow_steering) {
			struct i2r_interface *i = c->i;
			enum interfaces in = i - i2r;
			struct i2r_interface *di = i2r + (in ^ 1);
			unsigned netmask = di->if_netmask.sin_addr.s_addr;
			struct {
				struct ibv_flow_attr attr;
				struct ibv_flow_spec_ipv4 ipv4;
				struct ibv_flow_spec_tcp_udp udp;
			} flattr = {
				{
					0, IBV_FLOW_ATTR_SNIFFER, sizeof(flattr),
					0, 2, i->port, 0
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

			c->flow = ibv_create_flow(c->qp, &flattr.attr);

	} else {

		struct ibv_flow_attr flattr = {
				0, IBV_FLOW_ATTR_SNIFFER, sizeof(struct ibv_flow_spec),
				0, 0, c->i->port, 0
		};

		c->flow = ibv_create_flow(c->qp, &flattr);
	}

	if (!c->flow)
		logg(LOG_ERR, "Failure to create flow on %s. Errno %s\n", c->text, errname());
}

static void unicast_packet(struct rdma_channel *c, struct buf *buf, struct in_addr dest_addr)
{
	char xbuf[INET6_ADDRSTRLEN];
	char xbuf2[INET6_ADDRSTRLEN];
	enum interfaces in = c->i - i2r;
	unsigned port = 0; /* How do I get that??? Is it needed? */
	unsigned long l;

	memcpy(&l, buf->cur, sizeof(long));
	if (l == BEACON_SIGNATURE) {
		beacon_received(buf);
		return;
	}

	if (in == ROCE) {

		unsigned int iaddr = ntohl(i2r[INFINIBAND].if_addr.sin_addr.s_addr);
		unsigned int netmask = ntohl(i2r[INFINIBAND].if_netmask.sin_addr.s_addr);
		unsigned int daddr = ntohl(dest_addr.s_addr);

		if ((daddr & netmask) == (iaddr & netmask)) {
			/* Unicast ROCE packet destined for Infiniband */
			logg(LOG_NOTICE, "Packet destination Infiniband from %s to %s port %d\n",
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
			logg(LOG_NOTICE, "Packet destination Roce from %s to %s port %d\n",
				inet_ntop(AF_INET6, &buf->grh.sgid, xbuf2, INET6_ADDRSTRLEN),
				inet_ntop(AF_INET6, &buf->grh.dgid, xbuf, INET6_ADDRSTRLEN),
				port);
		}
	}
	dump_buf_grh(buf);
}

static void send_buf_to(struct i2r_interface *i, struct buf *buf, struct sockaddr_in *sin);

#ifdef LEARN
/*
 * Populate address cache to avoid expensive lookups.
 *
 * This is also used on the senders to multicast groups because the recover channels
 * for multicast connections will connect later and then we already have the
 * addresses cached
 */
static void learn_source_address(struct rdma_channel *c, struct buf *buf, struct ibv_wc *w)
{
	struct rdma_ah *ra;

	if (c->i == i2r + INFINIBAND) {
		/* Infiniband. Thus able to lean LID, GID and potentially IP */

		ra = find_in_hash(hash_lid, &w->slid);
		if (!ra) {
			if (buf->grh_valid) {
				/* Lookup entry through SGID */
				ra = find_in_hash(hash_gid, &buf->grh.sgid);

				if (ra)	/* LID must be invalid */
					remove_from_hash(ra, hash_lid);
			}
		}

		if (!ra) {
			/* Ok new Infiniband endpoint */
			ra = new_rdma_ah(c->i);
		}

		if (!ra->hash[hash_gid].member && buf->grh_valid)
			add_to_hash(ra, hash_gid, &buf->grh.sgid);

		if (!ra->hash[hash_lid].member)
			add_to_hash(ra, hash_lid, &w->slid);


	} else { /* ROCE so a MAC and IP address */

		ra = find_in_hash(hash_mac, buf->e.ether_shost);

		if (!ra) {
			ra = find_in_hash(hash_ip, &buf->ip.saddr);

			if (ra) /* MAC was invalid */
				remove_from_hash(ra, hash_mac);
		}

		if  (!ra) {
			/* New ROCE endpoint */
			ra = new_rdma_ah(c->i);
		}

		if (!ra->hash[hash_mac].member)
			add_to_hash(ra, hash_mac, &buf->e.ether_shost);

		if (!ra->hash[hash_ip].member)
			add_to_hash(ra, hash_ip, &buf->ip.saddr);

	}

	/* Construct handle that is used by the RDMA subsystem to send datagrams to the endpoint */
	ra->ai.ah = ibv_create_ah_from_wc(c->pd, w, &buf->grh, c->i->port);
	ra->ai.remote_qpn = w->src_qp;
	ra->ai.remote_qkey = RDMA_UDP_QKEY;
}
#endif

/*
 * We have an GRH header so the packet has been processed by the RDMA
 * Subsystem and we can take care of it using the RDMA calls
 */
static void recv_buf_grh(struct rdma_channel *c, struct buf *buf)
{
	struct mc *m;
	enum interfaces in = c->i - i2r;
	struct ib_addr *sgid = (struct ib_addr *)&buf->grh.sgid.raw;
	struct ib_addr *dgid = (struct ib_addr *)&buf->grh.dgid.raw;
	char xbuf[INET6_ADDRSTRLEN];
	struct in_addr dest_addr;
	int ret;
	struct pgm_header pgm;

	if (unicast &&
		((in == INFINIBAND && buf->grh.dgid.raw[0] != 0xff) ||
		((in == ROCE && (buf->grh.dgid.raw[13] & 0x1))))) {

		unicast_packet(c, buf, dest_addr);
		return;
	}

	dest_addr.s_addr = dgid->sib_addr32[3];
	m = hash_lookup_mc(dest_addr);

	if (log_packets > 1) {
		memcpy(&pgm, buf->cur, sizeof(struct pgm_header));
		logg(LOG_NOTICE, "From %s: MC=%s %s\n", c->text, inet_ntoa(dest_addr), pgm_dump(&pgm));
	}

	if (!m) {
		if (log_packets) {
			logg(LOG_WARNING, "Discard Packet: Multicast group %s not found\n",
				inet_ntoa(dest_addr));
			dump_buf_grh(buf);
		}
		goto invalid_packet;
	}

	if (m->sendonly[in]) {

		if (log_packets) {
			logg(LOG_WARNING, "Discard Packet: Received data from Sendonly MC group %s from %s\n",
				m->text, c->text);
			dump_buf_grh(buf);
		}
		goto invalid_packet;
	}

	if (in == INFINIBAND) {
		unsigned char *mgid = buf->grh.dgid.raw;
		unsigned short signature = ntohs(*(unsigned short*)(mgid + 2));

		if (mgid[0] != 0xff) {
			if (log_packets) {
				logg(LOG_WARNING, "Discard Packet: Not multicast. MGID=%s/%s\n",
					inet_ntop(AF_INET6, mgid, xbuf, INET6_ADDRSTRLEN), c->text);
				dump_buf_grh(buf);
			}
			goto invalid_packet;
		}

		if (memcmp(&buf->grh.sgid, &c->i->gid, sizeof(union ibv_gid)) == 0) {

			if (log_packets)
				logg(LOG_WARNING, "Discard Packet: Loopback from this host. MGID=%s/%s\n",
					inet_ntop(AF_INET6, mgid, xbuf, INET6_ADDRSTRLEN), c->text);

			goto invalid_packet;
		}

		if (m->mgid_mode->signature) {
			if (signature == m->mgid_mode->signature) {
//				if (m->mgid_mode->port)
//					port = ntohs(*((unsigned short *)(mgid + 10)));
			} else {
				if (log_packets) {
					logg(LOG_WARNING, "Discard Packet: MGID multicast signature(%x)  mismatch. MGID=%s\n",
							signature,
							inet_ntop(AF_INET6, mgid, xbuf, INET6_ADDRSTRLEN));
					dump_buf_grh(buf);
				}
				goto invalid_packet;
			}
		}

	} else { /* ROCE */
		struct in_addr source_addr;
		struct in_addr local_addr;

		local_addr = c->i->if_addr.sin_addr;

		source_addr.s_addr = sgid->sib_addr32[3];

		if (source_addr.s_addr == local_addr.s_addr) {
			if (log_packets)
				logg(LOG_WARNING, "Discard Packet: Loopback from this host. %s/%s\n",
					inet_ntoa(source_addr), c->text);
			goto invalid_packet;
		}
	}

	if (m->beacon) {
		beacon_received(buf);
		goto free_out;
	}

	if (!bridging)
		goto free_out;

	ret = send_to(i2r[in ^ 1].multicast, buf->cur, buf->end - buf->cur, m->ai + (in ^ 1), false, 0, buf);

	if (ret)
		goto free_out;

	st(c, packets_bridged_mc);
	return;

invalid_packet:
	st(c, packets_invalid);
free_out:
	free_buffer(buf);
}

/* SIDR handshake with gateway involved
 *
 * SIDR REQ from IP to IP sent form QP1 to QP1
 *
 * SIDR REQ SIP(1):DIP(1) -> GW -> SIDR REQ SIP(GW-QP):DIP(1)
 *
 * SIDR RESP DIP(1):SIP(GW-QP) -> GW- > SIDR RESP DIP(GW-QP):SIP(1)
 *
 * Data
 *
 * DATA SIP(SQP) -> DIP(GW-QP) -> GW -> DATA SIP(GW_QP) -> DIP(DQP)
 *
 * State needed by GW
 *
 * 1. Resolution from IP -> ibv_ah and GID->LID to ibv_ah
 *
 * 2. Map from IP/QPN ib <-> IP/QPN roce
 *
 * SIP:DIP SQP:DQP SQP:DQP
 *
 * On the IB side we need to ID the sender by LID also but generally prefer GIDs
 *
 * Need the SM to do routing paths and GID->LID etc conversions. 
 */

/* Could not find a struct anywhere so this may do the trick */
struct sidr_req {
	uint32_t	request_id;
	uint16_t	pkey;
	uint16_t	reserved;
	uint64_t	service_id;
	char private[100];
} __packed;

static bool scan_private(char *s, struct in_addr *from, struct in_addr *to)
{
	struct {
		struct in_addr x;
		char ip[4];
	} addr;
	unsigned short port;
	int r;
	char *p = s;
	char type[2];
	
	while (*p) {
		/* Find the beginning of the rmmXXX */
		while (*p != 'r')
			p++;

		if (!*p)
			return false;

		r = sscanf(p, "rmm%cx at %hhu.%hhu.%hhu.%hhu|%hu", type, addr.ip, addr.ip + 1, addr.ip + 2, addr.ip + 3, &port);

		logg(LOG_NOTICE, "Scan result = %d Type=%s IP=%s port=%d offset=%ld\n", r, type, inet_ntoa(addr.x), port, p - s);

		if (r != 5)
			return false;

		if (*type == 'R')
			*to = addr.x;
		else if (*type == 'T')
			*from = addr.x;
		else
			return false;
		p += 10;
	}
	return true;
}

static void sidr_req(struct buf *buf, char *header)
{
	char *payload = alloca(1500);
	struct sidr_req sr;
//	struct endpoint *ep = buf->source_ep;
	struct in_addr source, dest;

	PULL(buf, sr);

	buf->cur = buf->raw;
	__hexbytes(payload, buf->cur, buf->end - buf->cur, ' ');

	if (!scan_private(sr.private + 36, &source, &dest)) {
		logg(LOG_ERR, "Dest and Source IP not determined\n");
		free_buffer(buf);
		return;
	}

#if 0
	if (ep->addr.s_addr == 0) {
		ep->addr = source;
		hash_add(ep->c->i->ep, ep);
		logg(LOG_NOTICE, "Supplied IP address %s to Endpoint at LID %d\n",
				inet_ntoa(source), ep->lid);
	}
#endif

	logg(LOG_NOTICE, "SIDR_REQ: %s APSN=%x method=%s status=%s attr_id=%s attr_mod=%x SID=%lx RID=%x pkey=%x %s\n",
		header, buf->bth.apsn, umad_method_str(buf->umad.mgmt_class, buf->umad.method),
	       	umad_common_mad_status_str(buf->umad.status),
	       	umad_attribute_str(buf->umad.mgmt_class, buf->umad.attr_id), ntohl(buf->umad.attr_mod),
		be64toh(sr.service_id), ntohl(sr.request_id), ntohs(sr.pkey),
		payload);

	if (false && bridging) {
		struct sockaddr_in sin;

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr = dest;
		sin.sin_port = htons(ROCE_PORT);

		send_buf_to(i2r + INFINIBAND, buf, &sin);
	} else
			free_buffer(buf);
}

struct sidr_rep {
	uint32_t request_id;
	uint8_t	status;
	uint8_t ail;
	uint16_t vendorid1;
	uint32_t qpn;
	uint64_t service_id;
	uint32_t q_key;
	char add_info[72];
	char private[100];
} __packed;

static void sidr_rep(struct buf *buf, char *header)
{
	char *payload = alloca(1500);
	struct sidr_rep sr;

	PULL(buf, sr);

	buf->cur = buf->raw;
	__hexbytes(payload, buf->cur, buf->end - buf->cur, ' ');

	logg(LOG_NOTICE, "SIDR_REP: %s APSN=%x method=%s status=%s attr_id=%s attr_mod=%x SID=%x RID=%x Q_KEY=%x QPN=%x Status=%x %s\n",
		header, buf->bth.apsn, umad_method_str(buf->umad.mgmt_class, buf->umad.method),
	       	umad_common_mad_status_str(buf->umad.status),
	       	umad_attribute_str(buf->umad.mgmt_class, buf->umad.attr_id), ntohl(buf->umad.attr_mod),
		ntohl(sr.service_id), ntohl(sr.request_id), ntohs(sr.q_key), ntohl(sr.qpn), sr.status,
		payload);

	free_buffer(buf);
}

/* Figure out what to do with the packet we got */
static void recv_buf(struct rdma_channel *c, struct buf *buf)
{
	const char *reason;
	int len = 0;
	char header[100];

	if (buf->grh_valid) {
		recv_buf_grh(c, buf);
		return;
	}

	if (c->rdmacm) {
		/* No GRH but using RDMACM channel. This is not supported for now */
		if (log_packets)
			logg(LOG_WARNING, "No GRH on %s. Packet discarded: %s.\n", c->text, payload_dump(buf->cur));

		st(c, packets_invalid);
		free_buffer(buf);
		return;
	}

	/* So the packet came in on a raw channel. We need to parse the headers */

	if (c->i == i2r + INFINIBAND) {
		unsigned short dlid;
		__be16 lrh[4];
		struct ib_header *ih = (void *)&lrh;

		PULL(buf, lrh);

		len = ntohs(lrh[2]) *4;

		dlid = ib_get_dlid(ih);

		snprintf(header, sizeof(header), "SLID=%x DLID=%x SL=%d LVer=%d",
			ib_get_slid(ih), ib_get_dlid(ih), ib_get_sl(ih), ib_get_lver(ih));
	
		if (ib_get_lnh(ih) < 2) {
			reason = "IP v4/v6 packet";
			goto discard;
		}

		if (ib_get_lnh(ih) == 3) {
			char *xbuf = alloca(40);
			char *xbuf2 = alloca(40);

			PULL(buf, buf->grh);
			buf->grh_valid = true;

			snprintf(header + strlen(header), 100-strlen(header), " SGID=%s DGID=%s", 
				inet_ntop(AF_INET6, &buf->grh.sgid, xbuf2, INET6_ADDRSTRLEN),
				inet_ntop(AF_INET6, &buf->grh.dgid, xbuf, INET6_ADDRSTRLEN));

		}

		if ((dlid & 0xf000) == 0xc000) {
			reason = "Multicast";
			goto discard;
		}

		if (dlid == 0xffff) {
			reason = "Permissive Broadcast";
			goto discard;
		}

	} else { /* Ethernet. We expect a ROCE packet */

		pull(buf, &buf->e, sizeof(struct ether_header));
		buf->ethertype = ntohs(buf->e.ether_type);
		buf->ether_valid = true;

		if (memcmp(c->i->if_mac, buf->e.ether_shost, ETH_ALEN) == 0) {

			reason = "Loopback";
			goto discard;
		}

		if (buf->e.ether_dhost[0] & 0x1) {
			reason = "Multicast on RAW channel";
			goto discard;
		}

		buf->end -= 4;		/* Remove Ethernet FCS */

		/* buf->cur .. buf->end is the ethernet payload */
		if (buf->ethertype == ETHERTYPE_ROCE) {

			reason = "Roce V1 not supported";
			goto discard2;

		} else if (buf->ethertype == ETHERTYPE_IP) {

			char source_str[30];
			char dest_str[30];
			struct in_addr source, dest;

			pull(buf, &buf->ip, sizeof(struct iphdr));
			buf->ip_valid = true;
			len = ntohs(buf->ip.tot_len);

			source.s_addr = buf->ip.saddr;
			dest.s_addr = buf->ip.daddr;
			strcpy(source_str, inet_ntoa(source));
			strcpy(dest_str, inet_ntoa(dest));
			snprintf(header, sizeof(header), "%s -> %s", source_str, dest_str);

			if (buf->ip.protocol != IPPROTO_UDP) {

				reason = "Only UDP packets";
				goto discard;

			}

			if (!buf->ip_csum_ok)
				logg(LOG_NOTICE, "TCP/UDP CSUM not valid on raw RDMA channel %s\n", c->text);

			pull(buf, &buf->udp, sizeof(struct udphdr));
			buf->udp_valid = true;

			if (ntohs(buf->udp.dest) != ROCE_PORT) {

				reason = "Not the ROCE UDP port";
				goto discard2;

			}
		}
	}

	PULL(buf, buf->bth);
	buf->bth_valid = true;
//	buf->end -= ICRC_SIZE;
	
	if (ntohl(buf->bth.qpn) != 1) {
		reason = "Packet forwarding for QPN != 1 not implemented yet";
		goto discard2;
	}

	if (buf->bth.opcode != IB_OPCODE_UD_SEND_ONLY &&
 		buf->bth.opcode !=  IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE) {
 			reason = "Only UD Sends are supported";
                        goto discard2;
        }

	PULL(buf, buf->deth);

	if (buf->bth.opcode == IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE) {
		PULL(buf, buf->immdt);
 		buf->imm_valid = true;
		buf->imm = buf->immdt.imm;
 	}

	buf->cur += __bth_pad(&buf->bth);

	/* Start MAD payload */
	PULL(buf, buf->umad);

	if (buf->umad.mgmt_class != UMAD_CLASS_CM) {
		reason = "Only CM Class MADs are supported";
		goto discard2;
	}

	if (ntohs(buf->umad.attr_id) == UMAD_CM_ATTR_SIDR_REQ) {
		sidr_req(buf, header);
		return;
	} else if (ntohs(buf->umad.attr_id) == UMAD_CM_ATTR_SIDR_REP) {
		sidr_rep(buf, header);
		return;
	}
	
	reason = "Only SIDR_REQ and SIDR_REP supported\n";
	goto discard2;

discard:
	if (log_packets < 2)
		goto silent_discard;

discard2:
	logg(LOG_NOTICE, "Discard %s %s: %s QPN=%x APSN=%x LEN=%d\n", c->text, reason, header,
		ntohl(buf->bth.qpn), buf->bth.apsn, len);

silent_discard:
	st(c, packets_invalid);

	free_buffer(buf);
}

static void reset_flags(struct buf *buf)
{
	memset(&buf->ether_valid, 0, (void *)&buf->ip_csum_ok - (void *)&buf->ether_valid);
}

static void handle_comp_event(void *private)
{
	struct rdma_channel *c = private;
	struct i2r_interface *i = c->i;
	struct ibv_cq *cq;
	int cqs;
	struct ibv_wc wc[100];
	int j;
	struct rdma_channel *c2;

	ibv_get_cq_event(c->comp_events, &cq, (void **)&c2);
	if (cq != c->cq || c2 != c) {
		logg(LOG_CRIT, "ibv_get_cq_event on %s: CQ mismatch C=%px CQ=%px\n",
				c->text, cq, c);
		abort();
	}

	ibv_ack_cq_events(cq, 1);
	if (ibv_req_notify_cq(cq, 0)) {
		logg(LOG_CRIT, "ibv_req_notify_cq: Failed\n");
		abort();
	}

	/* Retrieve completion events and process incoming data */
	cqs = ibv_poll_cq(cq, 100, wc);
	if (cqs < 0) {
		logg(LOG_WARNING, "CQ polling failed with: %s on %s\n",
			errname(), c->text);
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

			buf->cur = buf->raw;
			buf->end = buf->raw + w->byte_len;
			reset_flags(buf);
			if (w->wc_flags & IBV_WC_WITH_IMM) {

				buf->imm = w->imm_data;
				buf->imm_valid = true;

			} else {
				buf->imm = 0;
				buf->imm_valid = false;
			}

			if (w->wc_flags & IBV_WC_GRH) {
				PULL(buf, buf->grh);
				buf->grh_valid = true;
			} else
				buf->grh_valid = false;

			buf->ip_csum_ok = (w->wc_flags & IBV_WC_IP_CSUM_OK) != 0;

			recv_buf(c, buf);

		} else {
			if (w->status == IBV_WC_SUCCESS && w->opcode == IBV_WC_SEND) {
				/* Completion entry */
				st(c, packets_sent);
				free_buffer(buf);
			} else
				logg(LOG_NOTICE, "Strange CQ Entry %d/%d: Status:%x Opcode:%x Len:%u QP=%x SRC_QP=%x Flags=%x\n",
					j, cqs, w->status, w->opcode, w->byte_len, w->qp_num, w->src_qp, w->wc_flags);

		}
	}

exit:
	/* Since we freed some buffers up we may be able to post more of them */
	post_receive_buffers(i);
}

static void handle_async_event(void *private)
{
	struct i2r_interface *i = private;
	struct ibv_async_event event;

	if (!ibv_get_async_event(i->context, &event))
		logg(LOG_ALERT, "Async event retrieval failed on %s.\n", i->text);
	else
		logg(LOG_ALERT, "Async RDMA EVENT %d on %s\n", event.event_type, i->text);

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
		struct tm *tm;

		tm = localtime(&t);

		snprintf(name, 40, "ib2roce-%d%02d%02dT%02d%02d%02d",
				tm->tm_year + 1900, tm->tm_mon +1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec);
		fd = open(name, O_CREAT | O_RDWR,  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	} else
		lseek(fd, SEEK_SET, 0);

	for(buf = buffers; buf < buffers + nr_buffers; buf++)
		if (buf->free)
		       free++;

	n+= sprintf(b + n, "Multicast: Active=%u NR=%u Max=%u\nBuffers: Active=%u Total=%u CQ#High=%u\n\n",
		active_mc, nr_mc, MAX_MC, nr_buffers-free , nr_buffers, cq_high);

	for(m = mcs; m < mcs + nr_mc; m++)

		n += sprintf(n + b, "%s INFINIBAND: %s %s%s ROCE: %s %s\n",
			inet_ntoa(m->addr),
			mc_text[m->status[INFINIBAND]],
			m->sendonly[INFINIBAND] ? "Sendonly " : "",
			m->mgid_mode->id,
			mc_text[m->status[ROCE]],
			m->sendonly[ROCE] ? "Sendonly" : "");

	for(i = i2r; i < i2r + NR_INTERFACES; i++) {

		if (i->multicast)
			n += channel_stats(b + n, i->multicast, i->text, "Multicast");
		if (i->raw)
			n += channel_stats(b + n, i->raw, i->text, "Raw");

	}
	n += sprintf(n + b, "\n\n\n\n\n\n\n\n");
	write(fd, b, n);

	if (update_requested) {
		close(fd);
		update_requested = false;
	}
	add_event(timestamp() + 60000, status_write);
}

/*
 * Beacon processing
 */
struct beacon_info {
	unsigned long signature;
	char version[10];
	struct in_addr destination;
	struct in_addr infiniband;
	struct in_addr roce;
	unsigned port;
	unsigned nr_mc;
	struct timespec t;
};

struct mc *beacon_mc;		/* == NULL if unicast */
struct sockaddr_in *beacon_sin;

static void timespec_diff(struct timespec *start, struct timespec *stop,
                   struct timespec *result)
{
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        result->tv_sec = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        result->tv_sec = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }

    return;
}

static void beacon_received(struct buf *buf)
{
	struct beacon_info *b = (struct beacon_info *)buf->cur;
	char ib[40];
	struct timespec diff;
	struct timespec now;

	if (b->signature != BEACON_SIGNATURE) {
		logg(LOG_ERR, "Received non beacon traffic on beacon MC group %s\n", beacon_mc->text);
		return;
	}

	clock_gettime(CLOCK_REALTIME, &now);
	strcpy(ib, inet_ntoa(b->infiniband));
	timespec_diff(&b->t, &now, &diff);

	logg(LOG_NOTICE, "Received Beacon on %s Port %d Version %s IB=%s, ROCE=%s MC groups=%u. Latency %ld ns\n",
		beacon_mc->text, ntohs(b->port), b->version, ib, inet_ntoa(b->roce), b->nr_mc, diff.tv_sec * 1000000000 + diff.tv_nsec);
	free_buffer(buf);
}

/* A mini router follows */
static struct i2r_interface *find_interface(struct sockaddr_in *sin)
{
	struct i2r_interface *i;

	for(i = i2r; i < i2r + NR_INTERFACES; i++)
	    if (i->context) {
		unsigned netmask = i->if_netmask.sin_addr.s_addr;

		if ((sin->sin_addr.s_addr & netmask) ==  (i->if_addr.sin_addr.s_addr & netmask))
			return i;
	}

	return NULL;
}

/* Ship a unicast datagram to an IP address .... */
static void send_buf_to(struct i2r_interface *i, struct buf *buf, struct sockaddr_in *sin)
{
	struct rdma_unicast *ra;
	int ret;

	/* Find address */
	ra = find_in_hash(hash_ip, &sin->sin_addr);
	if (!ra) {
		ra = new_rdma_unicast(i, sin);
		add_to_hash(ra, hash_ip, &sin->sin_addr);
	}

	switch (ra->state) {
		case UC_NONE:	/* We need to resolve the address. Queue up the buffer and initiate */
			fifo_put(&ra->pending, buf);
			resolve(ra);
			return;

		case UC_CONNECTED: /* Channel is open. We can send now */
			ret = send_buf(buf, ra);
			if (!ret)
				logg(LOG_ERR, "Failed to send to %s:%d\n",
					inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
			return;

		default:		/* Resolution is in progress. Just queue it up on the address */
			fifo_put(&ra->pending, buf);
			return;

	}
}

static void beacon_send(void)
{
	struct beacon_info b;
	struct buf *buf;

	b.signature = BEACON_SIGNATURE;
	memcpy(b.version, VERSION, 10);
	b.destination = beacon_sin->sin_addr;
	b.port = beacon_sin->sin_port;
	b.infiniband = i2r[INFINIBAND].if_addr.sin_addr;
	b.roce = i2r[ROCE].if_addr.sin_addr;
	b.nr_mc = nr_mc;
	clock_gettime(CLOCK_REALTIME, &b.t);

	if (beacon_mc) {
		int in;

		for(in = 0; in < NR_INTERFACES; in++) {
			struct i2r_interface *i = i2r + in;

			if (i->context && beacon_mc->status[in] == MC_JOINED) {
				if (sizeof(b) > MAX_INLINE_DATA) {
					buf = alloc_buffer(i->multicast);
					memcpy(buf->raw, &b, sizeof(b));
					send_to(i->multicast, buf, sizeof(b), beacon_mc->ai + in, false, 0, buf);
				} else
					send_inline(i->multicast, &b, sizeof(b), beacon_mc->ai + in, false, 0);
			}
		}

	} else {
		struct i2r_interface *i = find_interface(beacon_sin);

		if (!i) {
			logg(LOG_ERR, "Beacon IP %s unreachable\n", inet_ntoa(beacon_sin->sin_addr));
			beacon = false;
			return;
		}
		buf = alloc_buffer(i->multicast);
		memcpy(buf->raw, &b, sizeof(b));

		reset_flags(buf);
		buf->cur = buf->raw;
		buf->end = buf->cur + sizeof(b);

		send_buf_to(i, buf, beacon_sin);

	}
	add_event(timestamp() + 10000, beacon_send);
}

static void beacon_setup(const char *opt_arg)
{
	struct mgid_signature *mgid;
	struct in_addr addr;

	if (!opt_arg)
		opt_arg = "239.1.2.3";

	beacon_mc = NULL;
	beacon_sin = parse_addr(opt_arg, default_port, &mgid, false);
	addr = beacon_sin->sin_addr;
	if (IN_MULTICAST(ntohl(addr.s_addr))) {
		struct mc *m = mcs + nr_mc++;

		memset(m, 0, sizeof(*m));
		m->beacon = true;
		m->text = strdup(opt_arg);
		m->mgid_mode = mgid;
		m->addr = addr;

		setup_mc_addrs(m, beacon_sin);

		if (hash_add_mc(m)) {
			logg(LOG_ERR, "Beacon MC already in use.\n");
			beacon = false;
			free(beacon_sin);
			beacon_sin = NULL;
		} else
			beacon_mc = m;
	}
	add_event(timestamp() + 1000, beacon_send);
}

/* Events are timed according to milliseconds in the current epoch */
struct timed_event {
	unsigned long time;		/* When should it occur */
	void (*callback)(void);		/* function to run */
	struct timed_event *next;	/* The following event */
};

static struct timed_event *next_event;

static void add_event(unsigned long time, void (*callback))
{
	struct timed_event *t;
	struct timed_event *prior = NULL;
	struct timed_event *new_event;

	new_event = calloc(1, sizeof(struct timed_event));
	new_event->time = time;
	new_event->callback = callback;

	for(t = next_event; t && time > t->time; t = t->next)
		prior = t;

	new_event->next = t;

	if (prior)
		prior->next = new_event;
	else
		next_event = new_event;
}

static void check_joins(void)
{
	struct i2r_interface *i;

	/* Maintenance tasks */
	if (nr_mc > active_mc) {
		join_processing();
		add_event(timestamp() + 1000, check_joins);
	} else {
		/*
		 * All active so start listening. This means we no longer
		 * are able to subscribe to Multicast groups
		 */
		for(i = i2r; i < i2r + NR_INTERFACES; i++)
	       	   if (i->context)	{
			struct rdma_channel *c = i->multicast;

			if (rdma_listen(c->id, 50))
				logg(LOG_ERR, "rdma_listen on %s error %s\n", c->text, errname());

			c->listening = true;
		}
	}
}

static void logging(void)
{
	char buf[100];
	char buf2[150];
	unsigned n = 0;
	unsigned interval = 5000;
	const char *events;

	for(struct timed_event *z = next_event; z; z = z->next)
		n += sprintf(buf + n, "%ldms,", z->time - timestamp());

	if (n > 0)
		buf[n -1] = 0;
	else
		buf[0] = 0;

	if (n == 0) {
		events = "No upcoming events";
		interval = 60000;
	} else {
		snprintf(buf2, sizeof(buf2), "Events in %s", buf);
		events = buf2;
	}

	logg(LOG_NOTICE, "%d/%d MC Active. %s.\n", active_mc, nr_mc, events);
	add_event(timestamp() + interval, logging);
}

/*
 * Logic to support building a pollfd table for the event loop
 */
#define MAX_POLL_ITEMS 20

unsigned poll_items = 0;

struct pollfd pfd[MAX_POLL_ITEMS];
static void (*poll_callback[MAX_POLL_ITEMS])(void *);
void *poll_private[MAX_POLL_ITEMS];

static void register_callback(void (*callback)(void *), int fd, void *private)
{
	struct pollfd e = { fd, POLLIN, 0};

	if (poll_items == MAX_POLL_ITEMS)
		abort();

	poll_callback[poll_items] = callback;
	pfd[poll_items] = e;
	poll_private[poll_items] = private;
	poll_items++;
}

static void register_poll_events(void)
{
	struct i2r_interface *i;

	for(i = i2r; i < i2r + NR_INTERFACES; i++)
	   if (i->context) {

		register_callback(handle_rdma_event, i->rdma_events->fd, i);
		register_callback(handle_comp_event, i->multicast->comp_events->fd, i->multicast);
		register_callback(handle_async_event, i->context->async_fd, i);

		if (i->raw)
			register_callback(handle_comp_event, i->raw->comp_events->fd, i->raw);

	}

#ifdef NETLINK_SUPPORT
	if (unicast) {
		register_callback(handle_netlink_event, sock_nl[nl_monitor], nl_monitor);
		register_callback(handle_netlink_event, sock_nl[nl_command], nl_command);
	}
#endif
}

static void setup_timed_events(void)
{
	unsigned long t;

	t = timestamp();

	if (background)
		add_event(t + 30000, status_write);

	add_event(t + 1000, logging);
	add_event(t + 100, check_joins);
}

static void arm_channels(void)
{
	struct i2r_interface *i;

	for(i = i2r; i < i2r + NR_INTERFACES; i++)
       	   if (i->context) {
		/* Receive Buffers */
		post_receive_buffers(i);
		/* And request notifications if something happens */
		if (i->multicast) {
			ibv_req_notify_cq(i->multicast->cq, 0);
		}
		if (i->raw) {
			start_channel(i->raw);
			ibv_req_notify_cq(i->raw->cq, 0);

			setup_flow(i->raw);
		}
	}

}


static int event_loop(void)
{
	unsigned timeout;
	int events = 0;
	int waitms;
	unsigned long t;

	arm_channels();
	setup_timed_events();
loop:
	timeout = 10000;

	if (next_event) {
		/* Time till next event */
		waitms = next_event->time - timestamp();

		/*
		 * If we come from processing poll events then
		 * give priority to more poll event processing
		 */
		if ((waitms <= 0 && events == 0) || waitms < -10) {
			/* Time is up for an event */
			struct timed_event *te;

			te = next_event;
			next_event = next_event->next;
			te->callback();
			free(te);
			goto loop;
		}
		if (waitms < 1)
			/* There is a pending event but we are processing
			 * poll events.
			 * Make sure we check for more and come back soon
			 * after processing additional poll actions
			*/
			timeout = 3;
		else
			/* Maximum timeout is 10 seconds */
			if (waitms < 10000)
				timeout = waitms;
	}

	events = poll(pfd, poll_items, timeout);

	if (terminated)
		goto out;

	if (events < 0) {
		logg(LOG_WARNING, "Poll failed with error=%s\n", errname());
		goto out;
	}

	if (events == 0)
       		goto loop;

	for(t = 0; t < poll_items; t++)
		if (pfd[t].revents & POLLIN)
			poll_callback[t](poll_private[t]);

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

static void setup_termination_signals(void)
{
	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGHUP, terminate);	/* Future: Reload a potential config file */
}

static void daemonize(void)
{
	pid_t pid;

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
		logg(LOG_CRIT, "Cannot open pidfile. Error %s\n", errname());
		abort();
	}

	if (fcntl(pid_fd, F_SETLK, &fl) < 0) {
		logg(LOG_CRIT, "ib2roce already running.\n");
		abort();
	}

	if (ftruncate(pid_fd, 0) < 0) {
		logg(LOG_CRIT, "Cannot truncate pidfile. Error %s\n", errname());
		abort();
	}

	n = snprintf(buf, sizeof(buf), "%ld", (long) getpid());

	if (write(pid_fd, buf, n) != n) {
		logg(LOG_CRIT, "Cannot write pidfile. Error %s\n", errname());
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
	{ "beacon", optional_argument, NULL, 'b' },
	{ "debug", no_argument, NULL, 'x' },
	{ "nobridge", no_argument, NULL, 'n' },
	{ "port", required_argument, NULL, 'p' },
	{ "flow", no_argument, NULL, 'f' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "test", no_argument, NULL, 't' },
	{ "unicast", no_argument, NULL, 'u' },
	{ "config", required_argument, NULL, 'c' },
	{ NULL, 0, NULL, 0 }
};
	
char *beacon_arg = NULL;

static void exec_opt(int op, char *optarg);

static void readconfig(char *file)
{
	char *line = NULL;
	size_t chars = 0;
	FILE *f = fopen(file, "r");

	if (!f) {
		fprintf(stderr, "Config file %s not found:%s\n", file, errname());
		return;
	}

	while (getline(&line, &chars, f) > 0) {
		char *p = line;
		char *q, *optarg;
		struct option *o;

		while (isspace(*p))
			p++;

		if (!isalpha(*p))
			goto skip;

		q = p;
		while (isalpha(*p))
			p++;

		*p++ = 0;

		optarg = p;
		while (!isspace(*p))
			p++;

		*p = 0;

		for(o = opts; o->name; o++)
			if (strcasecmp(o->name, q) == 0) {
				exec_opt(o->val, optarg);
				goto skip;
			}

		fprintf(stderr, "Unknown option: %s %s\n", q, optarg);
		exit(1);
skip:
		free(line);
		line = NULL;
		chars = 0;
	}
	fclose(f);
}

static void exec_opt(int op, char *optarg)
{
	int ret = 0;
	int n;

	switch (op) {
		case 'c':
			readconfig(optarg);
			break;

		case 'd':
			ib_name = optarg;
			break;

		case 'r':
			roce_name = optarg;
			break;

		case 'm':
			ret = new_mc_addr(optarg, false, false);
			if (ret)
				exit(1);
			break;

		case 'i':
			ret = new_mc_addr(optarg, false, true);
			if (ret)
				exit(1);
			break;

		case 'o':
			ret =  new_mc_addr(optarg, true, false);
			if (ret)
				exit(1);
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

				printf("%7s|    0x%04x | %s\n",
					m->id, m->signature, m->port ? "true" : "false");
			}
			exit(1);
			break;

		case 'x':
			debug = true;
			break;

		case 'b':
			beacon = true;
			beacon_arg = optarg;
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

		case 'f':
			flow_steering = true;
			break;

		case 'v':
			log_packets++;
			break;

		case 't':
			fifo_test();
			hash_test();
			testing = true;	
			break;

		default:
			printf("ib2roce " VERSION " Mar 3,2022 (C) 2022 Christoph Lameter <cl@linux.com>\n");
			printf("Usage: ib2roce [<option>] ...\n");
                        printf("-d|--device <if[:portnumber]>		Infiniband interface\n");
                        printf("-r|--roce <if[:portnumber]>		ROCE interface\n");
                        printf("-m|--multicast <multicast address>[:port][/mgidformat] (bidirectional)\n");
                        printf("-i|--inbound <multicast address>	Incoming multicast only (ib traffic in, roce traffic out)\n");
                        printf("-o|--outbound <multicast address>	Outgoing multicast only / sendonly /(ib trafic out, roce traffic in)\n");
			printf("-l|--mgid				List availabe MGID formats for Infiniband\n");
			printf("-l|--mgid <format>			Set default MGID format\n");
			printf("-x|--debug				Do not daemonize, enter debug mode\n");
			printf("-p|--port >number>			Set default port number\n");
			printf("-b|--beacon <multicast address>		Send beacon every second\n");
			printf("-n|--nobridge				Do everything but do not bridge packets\n");
			printf("-u|--unicast		*experimental*	Unicast forwarding support\n");
			printf("-f|--flow		*experimental*	Enable flow steering to do hardware filtering of packets\n");
			printf("-v|--log-packets			Show detailed information about discarded packets\n");
			printf("-c|--config <file>			Read config from file\n");
			exit(1);
	}
}


int main(int argc, char **argv)
{
	int op, ret = 0;

	mc_hash = hash_create(offsetof(struct mc, addr), sizeof(struct in_addr));

	while ((op = getopt_long(argc, argv, "vtfunb::xl::i:r:m:o:d:p:c:",
					opts, NULL)) != -1)
       		exec_opt(op, optarg);

	init_buf();

	if (debug || !bridging)
		openlog("ib2roce", LOG_PERROR, LOG_USER);
	else {
		background = true;
		daemonize();
		pid_open();
	}

	setup_termination_signals();

	ret = find_rdma_devices();
	if (ret && !testing)
		return ret;

	syslog (LOG_NOTICE, "Infiniband device = %s:%d, ROCE device = %s:%d. Multicast Groups=%d MGIDs=%s Buffers=%u\n",
			i2r[INFINIBAND].context ? ibv_get_device_name(i2r[INFINIBAND].context->device) : "<disabled>",
			i2r[INFINIBAND].port,
			i2r[ROCE].context ? ibv_get_device_name(i2r[ROCE].context->device) : "<disabled>",
			i2r[ROCE].port,
			nr_mc,
			mgid_mode->id,
			nr_buffers);

	setup_interface(INFINIBAND);
	setup_interface(ROCE);

	if (background)
		status_fd = open("ib2roce-status", O_CREAT | O_RDWR | O_TRUNC,  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (beacon)
		beacon_setup(beacon_arg);

#ifdef NETLINK_SUPPORT
	if (unicast) {
		setup_netlink(nl_monitor);
		setup_netlink(nl_command);
	}
#endif

	register_poll_events();

	event_loop();

	if (background)
		close(status_fd);

	shutdown_roce();
	shutdown_ib();

	if (background)
		pid_close();

	syslog (LOG_NOTICE, "Shutdown complete.\n");
	closelog();

	return EXIT_SUCCESS;
}
