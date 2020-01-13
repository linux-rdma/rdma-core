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

#define _GNU_SOURCE

#include <config.h>

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
#include <infiniband/umad_types.h>
#include <infiniband/umad_sa.h>
#include <dlfcn.h>
#include <search.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <rdma/rdma_netlink.h>
#include <rdma/ib_user_sa.h>
#include <poll.h>
#include <inttypes.h>
#include <getopt.h>
#include <systemd/sd-daemon.h>
#include <ccan/list.h>
#include <util/util.h>
#include "acm_mad.h"
#include "acm_util.h"

#define MAX_EP_ADDR 4
#define NL_MSG_BUF_SIZE 4096
#define ACM_PROV_NAME_SIZE 64
#define NL_CLIENT_INDEX 0

struct acmc_subnet {
	struct list_node       entry;
	__be64                 subnet_prefix;
};

struct acmc_prov {
	struct acm_provider    *prov;
	void                   *handle;
	struct list_node       entry;
	struct list_head       subnet_list;
};

struct acmc_prov_context {
	struct list_node        entry;
	atomic_t                refcnt;
	struct acm_provider     *prov;
	void                    *context;
};

struct acmc_device;

struct acmc_port {
	struct acmc_device  *dev;
	struct acm_port     port;
	struct acm_provider *prov; /* limit to 1 provider per port for now */
	void                *prov_port_context;
	int		    mad_portid;
	int		    mad_agentid;
	struct ib_mad_addr  sa_addr;
	struct list_head    sa_pending;
	struct list_head    sa_wait;
	int		    sa_credits;
	pthread_mutex_t     lock;
	struct list_head    ep_list;
	enum ibv_port_state state;
	int                 gid_cnt;
	union ibv_gid       *gid_tbl;
	uint16_t            lid;
	uint16_t            lid_mask;
	int                 sa_pkey_index;
	bool		    pending_rereg;
	uint16_t            def_acm_pkey;
};

struct acmc_device {
	struct acm_device       device;
	struct list_node        entry;
	struct list_head        prov_dev_context_list;
	int                     port_cnt;
	struct acmc_port        port[0];
};

struct acmc_addr {
	struct acm_address    addr;
	void                  *prov_addr_context;
	char		      string_buf[ACM_MAX_ADDRESS];
};

struct acmc_ep {
	struct acmc_port      *port;
	struct acm_endpoint   endpoint;
	void                  *prov_ep_context;
	struct acmc_addr      addr_info[MAX_EP_ADDR];
	struct list_node      entry;
};

struct acmc_client {
	pthread_mutex_t lock;   /* acquire ep lock first */
	int      sock;
	int      index;
	atomic_t refcnt;
};

union socket_addr {
	struct sockaddr     sa;
	struct sockaddr_in  sin;
	struct sockaddr_in6 sin6;
};

struct acmc_sa_req {
	struct list_node	entry;
	struct acmc_ep		*ep;
	void			(*resp_handler)(struct acm_sa_mad *);
	struct acm_sa_mad	mad;
};

struct acm_nl_path {
	struct nlattr			attr_hdr;
	struct ib_path_rec_data		rec;
};

struct acm_nl_msg {
	struct nlmsghdr				nlmsg_header;
	union {
		uint8_t				data[ACM_MSG_DATA_LENGTH];
		struct rdma_ls_resolve_header	resolve_header;
		struct nlattr			attr[0];
		struct acm_nl_path		path[0];
	};
};

static char def_prov_name[ACM_PROV_NAME_SIZE] = "ibacmp";
static LIST_HEAD(provider_list);
static struct acmc_prov *def_provider = NULL;

static LIST_HEAD(dev_list);

static int listen_socket;
static int ip_mon_socket;
static struct acmc_client client_array[FD_SETSIZE - 1];

static FILE *flog;
static pthread_mutex_t log_lock;
static __thread char log_data[ACM_MAX_ADDRESS];
static atomic_t counter[ACM_MAX_COUNTER];

static struct acmc_device *
acm_get_device_from_gid(union ibv_gid *sgid, uint8_t *port);
static struct acmc_ep *acm_find_ep(struct acmc_port *port, uint16_t pkey);
static int acm_ep_insert_addr(struct acmc_ep *ep, const char *name, uint8_t *addr,
			      uint8_t addr_type);
static void acm_event_handler(struct acmc_device *dev);
static int acm_nl_send(int sock, struct acm_msg *msg);

static struct sa_data {
	int		timeout;
	int		retries;
	int		depth;
	pthread_t	thread_id;
	struct pollfd	*fds;
	struct acmc_port **ports;
	int		nfds;
} sa = { 2000, 2, 1, 0, NULL, NULL, 0};

/*
 * Service options - may be set through ibacm_opts.cfg file.
 */
static const char *acme = IBACM_BIN_PATH "/ib_acme -A";
static const char *opts_file = ACM_CONF_DIR "/" ACM_OPTS_FILE;
static const char *addr_file = ACM_CONF_DIR "/" ACM_ADDR_FILE;
static char log_file[128] = IBACM_LOG_FILE;
static int log_level = 0;
static char lock_file[128] = IBACM_PID_FILE;
static short server_port = 6125;
static int server_mode = IBACM_SERVER_MODE_DEFAULT;
static int acme_plus_kernel_only = IBACM_ACME_PLUS_KERNEL_ONLY_DEFAULT;
static int support_ips_in_addr_cfg = 0;
static char prov_lib_path[256] = IBACM_LIB_PATH;

void acm_write(int level, const char *format, ...)
{
	va_list args;
	struct timeval tv;
	struct tm tmtime;
	char buffer[20];

	if (level > log_level)
		return;

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tmtime);
	strftime(buffer, 20, "%Y-%m-%dT%H:%M:%S", &tmtime);
	va_start(args, format);
	pthread_mutex_lock(&log_lock);
	fprintf(flog, "%s.%03u: ", buffer, (unsigned) (tv.tv_usec / 1000));
	vfprintf(flog, format, args);
	fflush(flog);
	pthread_mutex_unlock(&log_lock);
	va_end(args);
}

void acm_format_name(int level, char *name, size_t name_size,
		     uint8_t addr_type, const uint8_t *addr, size_t addr_size)
{
	struct ibv_path_record *path;

	if (level > log_level)
		return;

	switch (addr_type) {
	case ACM_EP_INFO_NAME:
		memcpy(name, addr, addr_size);
		break;
	case ACM_EP_INFO_ADDRESS_IP:
		inet_ntop(AF_INET, addr, name, name_size);
		break;
	case ACM_EP_INFO_ADDRESS_IP6:
	case ACM_ADDRESS_GID:
		inet_ntop(AF_INET6, addr, name, name_size);
		break;
	case ACM_EP_INFO_PATH:
		path = (struct ibv_path_record *) addr;
		if (path->dlid) {
			snprintf(name, name_size, "SLID(%u) DLID(%u)",
				be16toh(path->slid), be16toh(path->dlid));
		} else {
			acm_format_name(level, name, name_size, ACM_ADDRESS_GID,
					path->dgid.raw, sizeof path->dgid);
		}
		break;
	case ACM_ADDRESS_LID:
		snprintf(name, name_size, "LID(%u)", be16toh(*((__be16 *) addr)));
		break;
	default:
		strcpy(name, "Unknown");
		break;
	}
}

int ib_any_gid(union ibv_gid *gid)
{
	return ((gid->global.subnet_prefix | gid->global.interface_id) == 0);
}

const char *acm_get_opts_file(void)
{
	return opts_file;
}

void acm_increment_counter(int type)
{
	if (type >= 0 && type < ACM_MAX_COUNTER)
		atomic_inc(&counter[type]);
}

static struct acmc_prov_context *
acm_alloc_prov_context(struct acm_provider *prov)
{
	struct acmc_prov_context *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		acm_log(0, "Error: failed to allocate prov context\n");
		return NULL;
	}
	atomic_set(&ctx->refcnt, 1);
	ctx->prov = prov;
	return ctx;
}

static struct acmc_prov_context *
acm_get_prov_context(struct list_head *list, struct acm_provider *prov)
{
	struct acmc_prov_context *ctx;

	list_for_each(list, ctx, entry) {
		if (ctx->prov == prov) {
			return ctx;
		}
	}

	return NULL;
}

static struct acmc_prov_context *
acm_acquire_prov_context(struct list_head *list, struct acm_provider *prov)
{
	struct acmc_prov_context *ctx;

	ctx = acm_get_prov_context(list, prov);
	if (!ctx) {
		ctx = acm_alloc_prov_context(prov);
		if (!ctx) {
			acm_log(0, "Error -- failed to allocate provider context\n");
			return NULL;
		}
		list_add_tail(list, &ctx->entry);
	} else {
		atomic_inc(&ctx->refcnt);
	}

	return ctx;
}

static void
acm_release_prov_context(struct acmc_prov_context *ctx)
{
	if (atomic_dec(&ctx->refcnt) <= 0) {
		list_del(&ctx->entry);
		free(ctx);
	}
}

uint8_t acm_gid_index(struct acm_port *port, union ibv_gid *gid)
{
	uint8_t i;
	struct acmc_port *cport;

	cport = container_of(port, struct acmc_port, port);
	for (i = 0; i < cport->gid_cnt; i++) {
		if (!memcmp(&cport->gid_tbl[i], gid, sizeof (*gid)))
			break;
	}
	return i;
}

int acm_get_gid(struct acm_port *port, int index, union ibv_gid *gid)
{
	struct acmc_port *cport;

	cport = container_of(port, struct acmc_port, port);
	if (index >= 0 && index < cport->gid_cnt) {
		*gid = cport->gid_tbl[index];
		return 0;
	} else {
		return -1;
	}
}

static size_t acm_addr_len(uint8_t addr_type)
{
	switch (addr_type) {
	case ACM_ADDRESS_NAME:
		return ACM_MAX_ADDRESS;
	case ACM_ADDRESS_IP:
		return sizeof(struct in_addr);
	case ACM_ADDRESS_IP6:
		return sizeof(struct in6_addr);
	case ACM_ADDRESS_GID:
		return sizeof(union ibv_gid);
	case ACM_ADDRESS_LID:
		return sizeof(uint16_t);
	default:
		acm_log(2, "illegal address type %d\n", addr_type);
	}
	return 0;
}

static int acm_addr_cmp(struct acm_address *acm_addr, uint8_t *addr, uint8_t addr_type)
{
	if (acm_addr->type != addr_type)
		return -2;

	if (acm_addr->type == ACM_ADDRESS_NAME)
		return strncasecmp((char *) acm_addr->info.name,
				   (char *) addr, acm_addr_len(acm_addr->type));
	return memcmp(acm_addr->info.addr, addr, acm_addr_len(acm_addr->type));
}

static void acm_mark_addr_invalid(struct acmc_ep *ep,
				  struct acm_ep_addr_data *data)
{
	int i;

	for (i = 0; i < MAX_EP_ADDR; i++) {
		if (!acm_addr_cmp(&ep->addr_info[i].addr, data->info.addr, data->type)) {
			ep->addr_info[i].addr.type = ACM_ADDRESS_INVALID;
			ep->port->prov->remove_address(ep->addr_info[i].prov_addr_context);
			break;
		}
	}
}

static struct acm_address *
acm_addr_lookup(const struct acm_endpoint *endpoint, uint8_t *addr, uint8_t addr_type)
{
	struct acmc_ep *ep;
	int i;

	ep = container_of(endpoint, struct acmc_ep, endpoint);
	for (i = 0; i < MAX_EP_ADDR; i++)
		if (!acm_addr_cmp(&ep->addr_info[i].addr, addr, addr_type))
			return &ep->addr_info[i].addr;

	return NULL;
}

__be64 acm_path_comp_mask(struct ibv_path_record *path)
{
	uint32_t fl_hop;
	uint16_t qos_sl;
	__be64 comp_mask = 0;

	acm_log(2, "\n");
	if (path->service_id)
		comp_mask |= IB_COMP_MASK_PR_SERVICE_ID;
	if (!ib_any_gid(&path->dgid))
		comp_mask |= IB_COMP_MASK_PR_DGID;
	if (!ib_any_gid(&path->sgid))
		comp_mask |= IB_COMP_MASK_PR_SGID;
	if (path->dlid)
		comp_mask |= IB_COMP_MASK_PR_DLID;
	if (path->slid)
		comp_mask |= IB_COMP_MASK_PR_SLID;

	fl_hop = be32toh(path->flowlabel_hoplimit);
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

	qos_sl = be16toh(path->qosclass_sl);
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

int acm_resolve_response(uint64_t id, struct acm_msg *msg)
{
	struct acmc_client *client = &client_array[id];
	int ret;

	acm_log(2, "client %d, status 0x%x\n", client->index, msg->hdr.status);

	if (msg->hdr.status == ACM_STATUS_ENODATA)
		atomic_inc(&counter[ACM_CNTR_NODATA]);
	else if (msg->hdr.status)
		atomic_inc(&counter[ACM_CNTR_ERROR]);

	pthread_mutex_lock(&client->lock);
	if (client->sock == -1) {
		acm_log(0, "ERROR - connection lost\n");
		ret = ACM_STATUS_ENOTCONN;
		goto release;
	}

	if (id == NL_CLIENT_INDEX)
		ret = acm_nl_send(client->sock, msg);
	else
		ret = send(client->sock, (char *) msg, msg->hdr.length, 0);

	if (ret != msg->hdr.length)
		acm_log(0, "ERROR - failed to send response\n");
	else
		ret = 0;

release:
	pthread_mutex_unlock(&client->lock);
	(void) atomic_dec(&client->refcnt);
	return ret;
}

static int
acmc_resolve_response(uint64_t id, struct acm_msg *req_msg, uint8_t status)
{
	req_msg->hdr.opcode |= ACM_OP_ACK;
	req_msg->hdr.status = status;
	if (status != ACM_STATUS_SUCCESS)
		req_msg->hdr.length = ACM_MSG_HDR_LENGTH;
	memset(req_msg->hdr.data, 0, sizeof(req_msg->hdr.data));

	return acm_resolve_response(id, req_msg);
}

int acm_query_response(uint64_t id, struct acm_msg *msg)
{
	struct acmc_client *client = &client_array[id];
	int ret;

	acm_log(2, "status 0x%x\n", msg->hdr.status);
	pthread_mutex_lock(&client->lock);
	if (client->sock == -1) {
		acm_log(0, "ERROR - connection lost\n");
		ret = ACM_STATUS_ENOTCONN;
		goto release;
	}

	ret = send(client->sock, (char *) msg, msg->hdr.length, 0);
	if (ret != msg->hdr.length)
		acm_log(0, "ERROR - failed to send response\n");
	else
		ret = 0;

release:
	pthread_mutex_unlock(&client->lock);
	(void) atomic_dec(&client->refcnt);
	return ret;
}

static int acmc_query_response(uint64_t id, struct acm_msg *msg, uint8_t status)
{
	acm_log(2, "status 0x%x\n", status);
	msg->hdr.opcode |= ACM_OP_ACK;
	msg->hdr.status = status;
	return acm_query_response(id, msg);
}

static void acm_init_server(void)
{
	FILE *f;
	int i;

	for (i = 0; i < FD_SETSIZE - 1; i++) {
		pthread_mutex_init(&client_array[i].lock, NULL);
		client_array[i].index = i;
		client_array[i].sock = -1;
		atomic_init(&client_array[i].refcnt);
	}

	if (server_mode != IBACM_SERVER_MODE_UNIX) {
		f = fopen(IBACM_IBACME_PORT_FILE, "w");
		if (f) {
			fprintf(f, "%hu\n", server_port);
			fclose(f);
		} else
			acm_log(0,
				"notice - cannot publish ibacm port number\n");

		unlink(IBACM_PORT_FILE);
		if (!acme_plus_kernel_only) {
			if (symlink(IBACM_PORT_BASE, IBACM_PORT_FILE) != 0)
				acm_log(0,
					"notice - can't create port symlink\n");
		}
	} else {
		unlink(IBACM_IBACME_PORT_FILE);
		unlink(IBACM_PORT_FILE);
	}
}

static int acm_listen(void)
{
	union {
		struct sockaddr any;
		struct sockaddr_in inet;
		struct sockaddr_un unx;
	} addr;
	mode_t saved_mask;
	int ret, saved_errno;

	acm_log(2, "\n");

	memset(&addr, 0, sizeof(addr));

	if (server_mode == IBACM_SERVER_MODE_UNIX) {
		addr.any.sa_family = AF_UNIX;
		BUILD_ASSERT(sizeof(IBACM_IBACME_SERVER_PATH) <=
			     sizeof(addr.unx.sun_path));
		strcpy(addr.unx.sun_path, IBACM_IBACME_SERVER_PATH);

		listen_socket = socket(AF_UNIX, SOCK_STREAM, 0);
		if (listen_socket < 0) {
			acm_log(0,
				"ERROR - unable to allocate unix socket\n");
			return errno;
		}

		unlink(addr.unx.sun_path);
		saved_mask = umask(0);
		ret = bind(listen_socket, &addr.any, sizeof(addr.unx));
		saved_errno = errno;
		umask(saved_mask);

		if (ret) {
			acm_log(0,
				"ERROR - unable to bind listen socket '%s'\n",
				addr.unx.sun_path);
			return saved_errno;
		}

		unlink(IBACM_SERVER_PATH);
		if (!acme_plus_kernel_only) {
			if (symlink(IBACM_SERVER_BASE,
				    IBACM_SERVER_PATH) != 0) {
				saved_errno = errno;
				acm_log(0,
					"notice - can't create symlink\n");
				return saved_errno;
			}
		}
	} else {
		unlink(IBACM_IBACME_SERVER_PATH);
		unlink(IBACM_SERVER_PATH);

		listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listen_socket == -1) {
			acm_log(0,
				"ERROR - unable to allocate TCP socket\n");
			return errno;
		}

		addr.any.sa_family = AF_INET;
		addr.inet.sin_port = htobe16(server_port);
		if (server_mode == IBACM_SERVER_MODE_LOOP)
			addr.inet.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		ret = bind(listen_socket, &addr.any, sizeof(addr.inet));
		if (ret == -1) {
			acm_log(0, "ERROR - unable to bind listen socket\n");
			return errno;
		}
	}

	ret = listen(listen_socket, 0);
	if (ret == -1) {
		acm_log(0, "ERROR - unable to start listen\n");
		return errno;
	}

	acm_log(2, "listen active\n");
	return 0;
}

/* Retrieve the listening socket from systemd. */
static int acm_listen_systemd(void)
{
	int fd;

	int rc = sd_listen_fds(1);
	if (rc == -1) {
		fprintf(stderr, "sd_listen_fds failed %d\n", rc);
		return rc;
	}

	if (rc > 2) {
		fprintf(stderr,
			"sd_listen_fds returned %d fds, expected <= 2\n", rc);
		return -1;
	}

	for (fd = SD_LISTEN_FDS_START; fd != SD_LISTEN_FDS_START + rc; fd++) {
		if (sd_is_socket(fd, AF_NETLINK, SOCK_RAW, 0)) {
			/* ListenNetlink for RDMA_NL_GROUP_LS multicast
			 * messages from the kernel
			 */
			if (client_array[NL_CLIENT_INDEX].sock != -1) {
				fprintf(stderr,
					"sd_listen_fds returned more than one netlink socket\n");
				return -1;
			}
			client_array[NL_CLIENT_INDEX].sock = fd;

			/* systemd sets NONBLOCK on the netlink socket, while
			 * we want blocking send to the kernel.
			 */
			if (set_fd_nonblock(fd, false)) {
				fprintf(stderr,
					"Unable to drop O_NOBLOCK on netlink socket");
				return -1;
			}
		} else if (sd_is_socket(SD_LISTEN_FDS_START, AF_UNSPEC,
					SOCK_STREAM, 1)) {
			/* Socket for user space client communication */
			if (listen_socket != -1) {
				fprintf(stderr,
					"sd_listen_fds returned more than one listening socket\n");
				return -1;
			}
			listen_socket = fd;
		} else {
			fprintf(stderr,
				"sd_listen_fds socket is not a SOCK_STREAM/SOCK_NETLINK listening socket\n");
			return -1;
		}
	}

	return 0;
}

static void acm_disconnect_client(struct acmc_client *client)
{
	pthread_mutex_lock(&client->lock);
	shutdown(client->sock, SHUT_RDWR);
	close(client->sock);
	client->sock = -1;
	pthread_mutex_unlock(&client->lock);
	(void) atomic_dec(&client->refcnt);
}

static void acm_svr_accept(void)
{
	int s;
	int i;

	acm_log(2, "\n");
	s = accept(listen_socket, NULL, NULL);
	if (s == -1) {
		acm_log(0, "ERROR - failed to accept connection\n");
		return;
	}

	for (i = 0; i < FD_SETSIZE - 1; i++) {
		if (i == NL_CLIENT_INDEX)
			continue;
		if (!atomic_get(&client_array[i].refcnt))
			break;
	}

	if (i == FD_SETSIZE - 1) {
		acm_log(0, "ERROR - all connections busy - rejecting\n");
		close(s);
		return;
	}

	client_array[i].sock = s;
	atomic_set(&client_array[i].refcnt, 1);
	acm_log(2, "assigned client %d\n", i);
}

static int
acm_is_path_from_port(struct acmc_port *port, struct ibv_path_record *path)
{
	uint8_t i;

	if (!ib_any_gid(&path->sgid)) {
		return (acm_gid_index(&port->port, &path->sgid) <
			port->gid_cnt);
	}

	if (path->slid) {
		return (port->lid == (be16toh(path->slid) & port->lid_mask));
	}

	if (ib_any_gid(&path->dgid)) {
		return 1;
	}

	if (acm_gid_index(&port->port, &path->dgid) < port->gid_cnt) {
		return 1;
	}

	for (i = 0; i < port->gid_cnt; i++) {
		if (port->gid_tbl[i].global.subnet_prefix ==
		    path->dgid.global.subnet_prefix) {
			return 1;
		}
	}

	return 0;
}

static bool acm_same_partition(uint16_t pkey_a, uint16_t pkey_b)
{

	acm_log(2, "pkey_a: 0x%04x pkey_b: 0x%04x\n", pkey_a, pkey_b);

	return ((pkey_a | IB_PKEY_FULL_MEMBER) == (pkey_b | IB_PKEY_FULL_MEMBER));
}

static struct acmc_addr *
acm_get_port_ep_address(struct acmc_port *port, struct acm_ep_addr_data *data)
{
	struct acmc_ep *ep;
	struct acm_address *addr;
	int i;

	if (port->state != IBV_PORT_ACTIVE)
		return NULL;

	if (data->type == ACM_EP_INFO_PATH &&
	    !acm_is_path_from_port(port, &data->info.path))
		return NULL;

	list_for_each(&port->ep_list, ep, entry) {
		if ((data->type == ACM_EP_INFO_PATH) &&
		    (!data->info.path.pkey ||
		     acm_same_partition(be16toh(data->info.path.pkey), ep->endpoint.pkey))) {
			for (i = 0; i < MAX_EP_ADDR; i++) {
				if (ep->addr_info[i].addr.type)
					return &ep->addr_info[i];
			}
			return NULL;
		}

		if ((addr = acm_addr_lookup(&ep->endpoint, data->info.addr,
					    (uint8_t) data->type)))
			return container_of(addr, struct acmc_addr, addr);
	}

	return NULL;
}

static struct acmc_addr *acm_get_ep_address(struct acm_ep_addr_data *data)
{
	struct acmc_device *dev;
	struct acmc_addr *addr;
	int i;

	acm_format_name(2, log_data, sizeof log_data,
			data->type, data->info.addr, sizeof data->info.addr);
	acm_log(2, "%s\n", log_data);
	list_for_each(&dev_list, dev, entry) {
		for (i = 0; i < dev->port_cnt; i++) {
			addr = acm_get_port_ep_address(&dev->port[i], data);
			if (addr)
				return addr;
		}
	}

	acm_format_name(0, log_data, sizeof log_data,
			data->type, data->info.addr, sizeof data->info.addr);
	acm_log(1, "notice - could not find %s\n", log_data);
	return NULL;
}

/* If port_num is zero, iterate through all ports, otherwise consider
 * only the specific port_num */
static struct acmc_ep *acm_get_ep(int index, uint8_t port_num)
{
	struct acmc_device *dev;
	struct acmc_ep *ep;
	int i, inx = 0;

	acm_log(2, "ep index %d\n", index);
	list_for_each(&dev_list, dev, entry) {
		for (i = 0; i < dev->port_cnt; i++) {
			if (port_num && port_num != (i + 1))
				continue;
			if (dev->port[i].state != IBV_PORT_ACTIVE)
				continue;
			list_for_each(&dev->port[i].ep_list, ep, entry) {
				if (index == inx)
					return ep;
			}
		}
	}

	acm_log(1, "notice - could not find ep %d\n", index);
	return NULL;
}

static int
acm_svr_query_path(struct acmc_client *client, struct acm_msg *msg)
{
	struct acmc_addr *addr;
	struct acmc_ep *ep;

	acm_log(2, "client %d\n", client->index);
	if (msg->hdr.length != ACM_MSG_HDR_LENGTH + ACM_MSG_EP_LENGTH) {
		acm_log(0, "ERROR - invalid length: 0x%x\n", msg->hdr.length);
		return acmc_query_response(client->index, msg, ACM_STATUS_EINVAL);
	}

	addr = acm_get_ep_address(&msg->resolve_data[0]);
	if (!addr) {
		acm_log(1, "notice - could not find local end point address\n");
		return acmc_query_response(client->index, msg, ACM_STATUS_ESRCADDR);
	}

	ep = container_of(addr->addr.endpoint, struct acmc_ep, endpoint);
	return ep->port->prov->query(addr->prov_addr_context, msg, client->index);
}

static int acm_svr_select_src(struct acm_ep_addr_data *src, struct acm_ep_addr_data *dst)
{
	union socket_addr addr;
	socklen_t len;
	int ret;
	int s;

	acm_log(2, "selecting source address\n");
	memset(&addr, 0, sizeof addr);
	switch (dst->type) {
	case ACM_EP_INFO_ADDRESS_IP:
		addr.sin.sin_family = AF_INET;
		memcpy(&addr.sin.sin_addr, dst->info.addr, 4);
		len = sizeof(struct sockaddr_in);
		break;
	case ACM_EP_INFO_ADDRESS_IP6:
		addr.sin6.sin6_family = AF_INET6;
		memcpy(&addr.sin6.sin6_addr, dst->info.addr, 16);
		len = sizeof(struct sockaddr_in6);
		break;
	default:
		acm_log(1, "notice - bad destination type, cannot lookup source\n");
		return ACM_STATUS_EDESTTYPE;
	}

	s = socket(addr.sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (s == -1) {
		acm_log(0, "ERROR - unable to allocate socket\n");
		return errno;
	}

	ret = connect(s, &addr.sa, len);
	if (ret) {
		acm_log(0, "ERROR - unable to connect socket\n");
		ret = errno;
		goto out;
	}

	ret = getsockname(s, &addr.sa, &len);
	if (ret) {
		acm_log(0, "ERROR - failed to get socket address\n");
		ret = errno;
		goto out;
	}

	src->type = dst->type;
	src->flags = ACM_EP_FLAG_SOURCE;
	if (dst->type == ACM_EP_INFO_ADDRESS_IP) {
		memcpy(&src->info.addr, &addr.sin.sin_addr, 4);
	} else {
		memcpy(&src->info.addr, &addr.sin6.sin6_addr, 16);
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
 * and we'll resolve a source address later.  Record the location of
 * the source and destination addresses in the message header data
 * to avoid further searches.
 */
static uint8_t acm_svr_verify_resolve(struct acm_msg *msg)
{
	int i, cnt, have_dst = 0;

	if (msg->hdr.length < ACM_MSG_HDR_LENGTH) {
		acm_log(0, "ERROR - invalid msg hdr length %d\n", msg->hdr.length);
		return ACM_STATUS_EINVAL;
	}

	msg->hdr.src_out = 1;
	cnt = (msg->hdr.length - ACM_MSG_HDR_LENGTH) / ACM_MSG_EP_LENGTH;
	for (i = 0; i < cnt; i++) {
		if (msg->resolve_data[i].flags & ACM_EP_FLAG_SOURCE) {
			if (!msg->hdr.src_out) {
				acm_log(0, "ERROR - multiple sources specified\n");
				return ACM_STATUS_ESRCADDR;
			}
			if (!msg->resolve_data[i].type ||
			    (msg->resolve_data[i].type >= ACM_ADDRESS_RESERVED)) {
				acm_log(0, "ERROR - unsupported source address type\n");
				return ACM_STATUS_ESRCTYPE;
			}
			msg->hdr.src_out = 0;
			msg->hdr.src_index = i;
		}
		if (msg->resolve_data[i].flags & ACM_EP_FLAG_DEST) {
			if (have_dst) {
				acm_log(0, "ERROR - multiple destinations specified\n");
				return ACM_STATUS_EDESTADDR;
			}
			if (!msg->resolve_data[i].type ||
			    (msg->resolve_data[i].type >= ACM_ADDRESS_RESERVED)) {
				acm_log(0, "ERROR - unsupported destination address type\n");
				return ACM_STATUS_EDESTTYPE;
			}
			have_dst = 1;
			msg->hdr.dst_index = i;
		}
	}

	if (!have_dst) {
		acm_log(0, "ERROR - destination address required\n");
		return ACM_STATUS_EDESTTYPE;
	}

	if (msg->hdr.src_out) {
		msg->hdr.src_index = i;
		memset(&msg->resolve_data[i], 0, sizeof(struct acm_ep_addr_data));
	}
	return ACM_STATUS_SUCCESS;
}

static int
acm_svr_resolve_dest(struct acmc_client *client, struct acm_msg *msg)
{
	struct acmc_addr *addr;
	struct acmc_ep *ep;
	struct acm_ep_addr_data *saddr, *daddr;
	uint8_t status;

	acm_log(2, "client %d\n", client->index);
	status = acm_svr_verify_resolve(msg);
	if (status) {
		acm_log(0, "notice - misformatted or unsupported request\n");
		return acmc_resolve_response(client->index, msg, status);
	}

	saddr = &msg->resolve_data[msg->hdr.src_index];
	daddr = &msg->resolve_data[msg->hdr.dst_index];
	if (msg->hdr.src_out) {
		status = acm_svr_select_src(saddr, daddr);
		if (status) {
			acm_log(0, "notice - unable to select suitable source address\n");
			return acmc_resolve_response(client->index, msg, status);
		}
	}

	acm_format_name(2, log_data, sizeof log_data,
			saddr->type, saddr->info.addr, sizeof saddr->info.addr);
	acm_log(2, "src  %s\n", log_data);
	addr = acm_get_ep_address(saddr);
	if (!addr) {
		acm_log(0, "notice - unknown local end point address\n");
		return acmc_resolve_response(client->index, msg, ACM_STATUS_ESRCADDR);
	}

	ep = container_of(addr->addr.endpoint, struct acmc_ep, endpoint);
	return ep->port->prov->resolve(addr->prov_addr_context, msg, client->index);
}

/*
 * The message buffer contains extra address data buffers.  We extract the
 * destination address from the path record into an extra buffer, so we can
 * lookup the destination by either LID or GID.
 */
static int
acm_svr_resolve_path(struct acmc_client *client, struct acm_msg *msg)
{
	struct acmc_addr *addr;
	struct acmc_ep *ep;
	struct ibv_path_record *path;

	acm_log(2, "client %d\n", client->index);
	if (msg->hdr.length < (ACM_MSG_HDR_LENGTH + ACM_MSG_EP_LENGTH)) {
		acm_log(0, "notice - invalid msg hdr length %d\n", msg->hdr.length);
		return acmc_resolve_response(client->index, msg, ACM_STATUS_EINVAL);
	}

	path = &msg->resolve_data[0].info.path;
	if (!path->dlid && ib_any_gid(&path->dgid)) {
		acm_log(0, "notice - no destination specified\n");
		return acmc_resolve_response(client->index, msg,
					     ACM_STATUS_EDESTADDR);
	}

	acm_format_name(2, log_data, sizeof log_data, ACM_EP_INFO_PATH,
		msg->resolve_data[0].info.addr, sizeof *path);
	acm_log(2, "path %s\n", log_data);
	addr = acm_get_ep_address(&msg->resolve_data[0]);
	if (!addr) {
		acm_log(0, "notice - unknown local end point address\n");
		return acmc_resolve_response(client->index, msg,
					     ACM_STATUS_ESRCADDR);
	}

	ep = container_of(addr->addr.endpoint, struct acmc_ep, endpoint);
	return ep->port->prov->resolve(addr->prov_addr_context, msg,
				       client->index);
}

static int acm_svr_resolve(struct acmc_client *client, struct acm_msg *msg)
{
	(void) atomic_inc(&client->refcnt);

	if (msg->resolve_data[0].type == ACM_EP_INFO_PATH) {
		if (msg->resolve_data[0].flags & ACM_FLAGS_QUERY_SA) {
			return acm_svr_query_path(client, msg);
		} else {
			return acm_svr_resolve_path(client, msg);
		}
	} else {
		return acm_svr_resolve_dest(client, msg);
	}
}

static int acm_svr_perf_query(struct acmc_client *client, struct acm_msg *msg)
{
	int ret, i;
	uint16_t len;
	struct acmc_addr *addr;
	struct acmc_ep *ep = NULL;
	int index;

	acm_log(2, "client %d\n", client->index);
	index = msg->hdr.src_index;
	msg->hdr.opcode |= ACM_OP_ACK;
	msg->hdr.status = ACM_STATUS_SUCCESS;
	msg->hdr.dst_index = 0;

	if ((be16toh(msg->hdr.length) < (ACM_MSG_HDR_LENGTH + ACM_MSG_EP_LENGTH)
	    && index < 1) ||
	    ((be16toh(msg->hdr.length) >= (ACM_MSG_HDR_LENGTH + ACM_MSG_EP_LENGTH)
	    && !(msg->resolve_data[0].flags & ACM_EP_FLAG_SOURCE)))) {
		for (i = 0; i < ACM_MAX_COUNTER; i++)
			msg->perf_data[i] = htobe64((uint64_t) atomic_get(&counter[i]));

		msg->hdr.src_out = ACM_MAX_COUNTER;
		len = ACM_MSG_HDR_LENGTH + (ACM_MAX_COUNTER * sizeof(uint64_t));
	} else {
		if (index >= 1) {
			ep = acm_get_ep(index - 1, msg->hdr.src_index);
		} else {
			addr = acm_get_ep_address(&msg->resolve_data[0]);
			if (addr)
				ep = container_of(addr->addr.endpoint,
						  struct acmc_ep, endpoint);
		}

		if (ep) {
			ep->port->prov->query_perf(ep->prov_ep_context,
						   msg->perf_data, &msg->hdr.src_out);
			len = ACM_MSG_HDR_LENGTH + (msg->hdr.src_out * sizeof(uint64_t));
		} else {
			msg->hdr.status = ACM_STATUS_ESRCADDR;
			len = ACM_MSG_HDR_LENGTH;
		}
	}
	msg->hdr.length = htobe16(len);

	ret = send(client->sock, (char *) msg, len, 0);
	if (ret != len)
		acm_log(0, "ERROR - failed to send response\n");
	else
		ret = 0;

	return ret;
}

static int acm_svr_ep_query(struct acmc_client *client, struct acm_msg *msg)
{
	int ret, i;
	uint16_t len;
	struct acmc_ep *ep;
	int index, cnt = 0;

	acm_log(2, "client %d\n", client->index);
	index = msg->hdr.src_out;
	ep = acm_get_ep(index - 1, msg->hdr.src_index);
	if (ep) {
		msg->hdr.status = ACM_STATUS_SUCCESS;
		msg->ep_data[0].dev_guid = ep->port->dev->device.dev_guid;
		msg->ep_data[0].port_num = ep->port->port.port_num;
		msg->ep_data[0].phys_port_cnt = ep->port->dev->port_cnt;
		msg->ep_data[0].pkey = htobe16(ep->endpoint.pkey);
		strncpy((char *)msg->ep_data[0].prov_name, ep->port->prov->name,
			ACM_MAX_PROV_NAME - 1);
		msg->ep_data[0].prov_name[ACM_MAX_PROV_NAME - 1] = '\0';
		len = ACM_MSG_HDR_LENGTH + sizeof(struct acm_ep_config_data);
		for (i = 0; i < MAX_EP_ADDR; i++) {
			if (ep->addr_info[i].addr.type != ACM_ADDRESS_INVALID) {
				memcpy(msg->ep_data[0].addrs[cnt++].name,
				       ep->addr_info[i].string_buf,
				       ACM_MAX_ADDRESS);
			}
		}
		msg->ep_data[0].addr_cnt = htobe16(cnt);
		len += cnt * ACM_MAX_ADDRESS;
	} else {
		msg->hdr.status = ACM_STATUS_EINVAL;
		len = ACM_MSG_HDR_LENGTH;
	}
	msg->hdr.opcode |= ACM_OP_ACK;
	msg->hdr.src_index = 0;
	msg->hdr.dst_index = 0;
	msg->hdr.length = htobe16(len);

	ret = send(client->sock, (char *) msg, len, 0);
	if (ret != len)
		acm_log(0, "ERROR - failed to send response\n");
	else
		ret = 0;

	return ret;
}

static int acm_msg_length(struct acm_msg *msg)
{
	return (msg->hdr.opcode == ACM_OP_RESOLVE) ?
		msg->hdr.length : be16toh(msg->hdr.length);
}

static void acm_svr_receive(struct acmc_client *client)
{
	struct acm_msg msg;
	int ret;

	acm_log(2, "client %d\n", client->index);
	ret = recv(client->sock, (char *) &msg, sizeof msg, 0);
	if (ret <= 0 || ret != acm_msg_length(&msg)) {
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
		atomic_inc(&counter[ACM_CNTR_RESOLVE]);
		ret = acm_svr_resolve(client, &msg);
		break;
	case ACM_OP_PERF_QUERY:
		ret = acm_svr_perf_query(client, &msg);
		break;
	case ACM_OP_EP_QUERY:
		ret = acm_svr_ep_query(client, &msg);
		break;
	default:
		acm_log(0, "ERROR - unknown opcode 0x%x\n", msg.hdr.opcode);
		break;
	}

out:
	if (ret)
		acm_disconnect_client(client);
}

static int acm_nl_to_addr_data(struct acm_ep_addr_data *ad,
				  int af_family, uint8_t *addr, size_t addr_len)
{
	if (addr_len > ACM_MAX_ADDRESS)
		return EINVAL;

	/* find the ep associated with this address "if any" */
	switch (af_family) {
	case AF_INET:
		ad->type = ACM_ADDRESS_IP;
		break;
	case AF_INET6:
		ad->type = ACM_ADDRESS_IP6;
		break;
	default:
		return EINVAL;
	}
	memcpy(&ad->info.addr, addr, addr_len);
	return 0;
}

static void acm_add_ep_ip(char *ifname, struct acm_ep_addr_data *data, char *ip_str)
{
	struct acmc_ep *ep;
	struct acmc_device *dev;
	uint8_t port_num;
	uint16_t pkey;
	union ibv_gid sgid;
	struct acmc_addr *addr;

	addr = acm_get_ep_address(data);
	if (addr) {
		acm_log(1, "Address '%s' already available\n", ip_str);
		return;
	}

	if (acm_if_get_sgid(ifname, &sgid))
		return;

	dev = acm_get_device_from_gid(&sgid, &port_num);
	if (!dev)
		return;

	if (acm_if_get_pkey(ifname, &pkey))
		return;

	acm_log(0, " %s\n", ip_str);

	ep = acm_find_ep(&dev->port[port_num - 1], pkey);
	if (ep) {
		if (acm_ep_insert_addr(ep, ip_str, data->info.addr,
				       data->type))
			acm_log(0, "Failed to add '%s' to EP\n", ip_str);
	} else {
		acm_log(0, "Failed to add '%s' no EP for pkey\n", ip_str);
	}
}

static void acm_rm_ep_ip(struct acm_ep_addr_data *data)
{
	struct acmc_ep *ep;
	struct acmc_addr *addr;

	addr = acm_get_ep_address(data);
	if (addr) {
		ep = container_of(addr->addr.endpoint, struct acmc_ep, endpoint);
		acm_format_name(0, log_data, sizeof log_data,
				data->type, data->info.addr, sizeof data->info.addr);
		acm_log(0, " %s\n", log_data);
		acm_mark_addr_invalid(ep, data);
	}
}

static int acm_ipnl_create(void)
{
	struct sockaddr_nl addr;

	if ((ip_mon_socket = socket(PF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE)) == -1) {
		acm_log(0, "Failed to open NETLINK_ROUTE socket");
		return EIO;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;

	if (bind(ip_mon_socket, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		acm_log(0, "Failed to bind NETLINK_ROUTE socket");
		return EIO;
	}

	return 0;
}

static void acm_ip_iter_cb(char *ifname, union ibv_gid *gid, uint16_t pkey,
		uint8_t addr_type, uint8_t *addr,
		char *ip_str, void *ctx)
{
	int ret = EINVAL;
	struct acmc_device *dev;
	struct acmc_ep *ep;
	uint8_t port_num;
	char gid_str[INET6_ADDRSTRLEN];

	dev = acm_get_device_from_gid(gid, &port_num);
	if (dev) {
		ep = acm_find_ep(&dev->port[port_num - 1], pkey);
		if (ep)
			ret = acm_ep_insert_addr(ep, ip_str, addr, addr_type);
	}

	if (ret) {
		inet_ntop(AF_INET6, gid->raw, gid_str, sizeof(gid_str));
		acm_log(0, "Failed to add '%s' (gid %s; pkey 0x%x)\n",
			ip_str, gid_str, pkey);
	}
}

/* Netlink updates have indicated a failure which means we are no longer in
 * sync.  This should be a rare condition so we handle this with a "big
 * hammer" by clearing and re-reading all the system IP's.
 */
static int resync_system_ips(void)
{
	struct acmc_device *dev;
	struct acmc_port *port;
	struct acmc_ep *ep;
	int i, cnt;

	acm_log(0, "Resyncing all IP's\n");

	/* mark all IP's invalid */
	list_for_each(&dev_list, dev, entry) {
		for (cnt = 0; cnt < dev->port_cnt; cnt++) {
			port = &dev->port[cnt];

			list_for_each(&port->ep_list, ep, entry) {
				for (i = 0; i < MAX_EP_ADDR; i++) {
					if (ep->addr_info[i].addr.type == ACM_ADDRESS_IP ||
					    ep->addr_info[i].addr.type == ACM_ADDRESS_IP6)
						ep->addr_info[i].addr.type = ACM_ADDRESS_INVALID;
				}
			}
		}
	}

	return acm_if_iter_sys(acm_ip_iter_cb, NULL);
}

static void acm_ipnl_handler(void)
{
	int len;
	char buffer[NL_MSG_BUF_SIZE];
	struct nlmsghdr *nlh;
	char ifname[IFNAMSIZ];
	char ip_str[INET6_ADDRSTRLEN];
	struct acm_ep_addr_data ad;

	while ((len = recv(ip_mon_socket, buffer, NL_MSG_BUF_SIZE, 0)) > 0) {
		nlh = (struct nlmsghdr *)buffer;
		while ((NLMSG_OK(nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE)) {
			struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nlh);
			struct ifinfomsg *ifi = (struct ifinfomsg *) NLMSG_DATA(nlh);
			struct rtattr *rth = IFA_RTA(ifa);
			int rtl = IFA_PAYLOAD(nlh);

			switch (nlh->nlmsg_type) {
			case RTM_NEWADDR:
				if_indextoname(ifa->ifa_index, ifname);
				while (rtl && RTA_OK(rth, rtl)) {
					if (rth->rta_type == IFA_LOCAL) {
						acm_log(1, "New system address available %s : %s\n",
						        ifname, inet_ntop(ifa->ifa_family, RTA_DATA(rth),
							ip_str, sizeof(ip_str)));
						if (!acm_nl_to_addr_data(&ad, ifa->ifa_family,
								      RTA_DATA(rth),
								      RTA_PAYLOAD(rth))) {
							acm_add_ep_ip(ifname, &ad, ip_str);
						}
					}
					rth = RTA_NEXT(rth, rtl);
				}
				break;
			case RTM_DELADDR:
				if_indextoname(ifa->ifa_index, ifname);
				while (rtl && RTA_OK(rth, rtl)) {
					if (rth->rta_type == IFA_LOCAL) {
						acm_log(1, "System address removed %s : %s\n",
						        ifname, inet_ntop(ifa->ifa_family, RTA_DATA(rth),
							ip_str, sizeof(ip_str)));
						if (!acm_nl_to_addr_data(&ad, ifa->ifa_family,
								      RTA_DATA(rth),
								      RTA_PAYLOAD(rth))) {
							acm_rm_ep_ip(&ad);
						}
					}
					rth = RTA_NEXT(rth, rtl);
				}
				break;
			case RTM_NEWLINK:
				acm_log(2, "Link added : %s\n",
					if_indextoname(ifi->ifi_index, ifname));
				break;
			case RTM_DELLINK:
				acm_log(2, "Link removed : %s\n",
					if_indextoname(ifi->ifi_index, ifname));
				break;
			default:
				acm_log(2, "unknown netlink message\n");
				break;
			}
			nlh = NLMSG_NEXT(nlh, len);
		}
	}

	if (len < 0 && errno == ENOBUFS) {
		acm_log(0, "ENOBUFS returned from netlink...\n");
		resync_system_ips();
	}
}

static int acm_nl_send(int sock, struct acm_msg *msg)
{
	struct sockaddr_nl dst_addr;
	struct acm_nl_msg acmnlmsg;
	struct acm_nl_msg *orig;
	int ret;
	int datalen;

	orig = (struct acm_nl_msg *)(uintptr_t)msg->hdr.tid;

	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.nl_family = AF_NETLINK;
	dst_addr.nl_groups = (1 << (RDMA_NL_GROUP_LS - 1));

	memset(&acmnlmsg, 0, sizeof(acmnlmsg));
	acmnlmsg.nlmsg_header.nlmsg_len = NLMSG_HDRLEN;
	acmnlmsg.nlmsg_header.nlmsg_pid = getpid();
	acmnlmsg.nlmsg_header.nlmsg_type = orig->nlmsg_header.nlmsg_type;
	acmnlmsg.nlmsg_header.nlmsg_seq = orig->nlmsg_header.nlmsg_seq;

	if (msg->hdr.status != ACM_STATUS_SUCCESS) {
		acm_log(2, "acm status no success = %d\n", msg->hdr.status);
		acmnlmsg.nlmsg_header.nlmsg_flags |= RDMA_NL_LS_F_ERR;
	} else {
		acm_log(2, "acm status success\n");
		acmnlmsg.nlmsg_header.nlmsg_len +=
			NLA_ALIGN(sizeof(struct acm_nl_path));
		acmnlmsg.path[0].attr_hdr.nla_type = LS_NLA_TYPE_PATH_RECORD;
		acmnlmsg.path[0].attr_hdr.nla_len = sizeof(struct acm_nl_path);
		if (orig->resolve_header.path_use ==
		    LS_RESOLVE_PATH_USE_UNIDIRECTIONAL)
			acmnlmsg.path[0].rec.flags = IB_PATH_PRIMARY |
				IB_PATH_OUTBOUND;
		else
			acmnlmsg.path[0].rec.flags = IB_PATH_PRIMARY |
				IB_PATH_GMP | IB_PATH_BIDIRECTIONAL;
		memcpy(acmnlmsg.path[0].rec.path_rec,
		       &msg->resolve_data[0].info.path,
		       sizeof(struct ibv_path_record));
	}

	datalen = NLMSG_ALIGN(acmnlmsg.nlmsg_header.nlmsg_len);
	ret = sendto(sock, &acmnlmsg, datalen, 0,
		     (const struct sockaddr *)&dst_addr,
		     (socklen_t)sizeof(dst_addr));
	if (ret != datalen) {
		acm_log(0, "ERROR - sendto = %d errno = %d\n", ret, errno);
		ret = -1;
	} else {
		ret = msg->hdr.length;
	}

	free(orig);

	return ret;
}

#define NLA_LEN(nla)	((nla)->nla_len - NLA_HDRLEN)
#define NLA_DATA(nla)	((char *)(nla) + NLA_HDRLEN)

static int acm_nl_parse_path_attr(struct nlattr *attr,
				   struct acm_ep_addr_data *data)
{
	struct ibv_path_record *path;
	uint64_t  *sid;
	struct rdma_nla_ls_gid *gid;
	uint8_t *tcl;
	uint16_t *pkey;
	uint16_t *qos;
	uint16_t val;
	int ret = 0;

#define IBV_PATH_RECORD_QOS_MASK 0xfff0

	path = &data->info.path;
	switch (attr->nla_type & RDMA_NLA_TYPE_MASK) {
	case LS_NLA_TYPE_SERVICE_ID:
		sid = (uint64_t *) NLA_DATA(attr);
		if (NLA_LEN(attr) == sizeof(*sid)) {
			acm_log(2, "service_id 0x%" PRIx64 "\n", *sid);
			path->service_id = htobe64(*sid);
		} else {
			ret = -1;
		}
		break;

	case LS_NLA_TYPE_DGID:
		gid = (struct rdma_nla_ls_gid *) NLA_DATA(attr);
		if (NLA_LEN(attr) == sizeof(gid->gid)) {
			acm_format_name(2, log_data, sizeof(log_data),
					ACM_ADDRESS_GID, gid->gid,
					sizeof(union ibv_gid));
			acm_log(2, "path dgid %s\n", log_data);
			memcpy(path->dgid.raw, gid->gid, sizeof(path->dgid));
			data->flags |= ACM_EP_FLAG_DEST;
		} else {
			ret = -1;
		}
		break;

	case LS_NLA_TYPE_SGID:
		gid = (struct rdma_nla_ls_gid *) NLA_DATA(attr);
		if (NLA_LEN(attr) == sizeof(gid->gid)) {
			acm_format_name(2, log_data, sizeof(log_data),
					ACM_ADDRESS_GID, gid->gid,
					sizeof(union ibv_gid));
			acm_log(2, "path sgid %s\n", log_data);
			memcpy(path->sgid.raw, gid->gid, sizeof(path->sgid));
			data->flags |= ACM_EP_FLAG_SOURCE;
		} else {
			ret = -1;
		}
		break;

	case LS_NLA_TYPE_TCLASS:
		tcl = (uint8_t *) NLA_DATA(attr);
		if (NLA_LEN(attr) == sizeof(*tcl)) {
			acm_log(2, "tclass 0x%x\n", *tcl);
			path->tclass = *tcl;
		} else {
			ret = -1;
		}
		break;

	case LS_NLA_TYPE_PKEY:
		pkey = (uint16_t *) NLA_DATA(attr);
		if (NLA_LEN(attr) == sizeof(*pkey)) {
			acm_log(2, "pkey 0x%x\n", *pkey);
			path->pkey = htobe16(*pkey);
		} else {
			ret = -1;
		}
		break;

	case LS_NLA_TYPE_QOS_CLASS:
		qos = (uint16_t *) NLA_DATA(attr);
		if (NLA_LEN(attr) == sizeof(*qos)) {
			acm_log(2, "qos_class 0x%x\n", *qos);
			val = be16toh(path->qosclass_sl);
			val &= ~IBV_PATH_RECORD_QOS_MASK;
			val |= (*qos & IBV_PATH_RECORD_QOS_MASK);
			path->qosclass_sl = htobe16(val);
		} else {
			ret = -1;
		}
		break;

	default:
		acm_log(1, "WARN: unknown attr %x\n", attr->nla_type);
		/* We can not ignore a mandatory attribute */
		if (attr->nla_type & RDMA_NLA_F_MANDATORY)
			ret = -1;
		break;
	}

	return ret;
}

static void acm_nl_process_invalid_request(struct acmc_client *client,
					   struct acm_nl_msg *acmnlmsg)
{
	struct acm_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.opcode = ACM_OP_RESOLVE;
	msg.hdr.version = ACM_VERSION;
	msg.hdr.length = ACM_MSG_HDR_LENGTH;
	msg.hdr.status = ACM_STATUS_EINVAL;
	msg.hdr.tid = (uintptr_t) acmnlmsg;

	acm_nl_send(client->sock, &msg);
}

static void acm_nl_process_resolve(struct acmc_client *client,
				   struct acm_nl_msg *acmnlmsg)
{
	struct acm_msg msg;
	struct nlattr *attr;
	int payload_len;
	int resolve_hdr_len;
	int rem;
	int total_attr_len;
	int status;
	unsigned char *data;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.opcode = ACM_OP_RESOLVE;
	msg.hdr.version = ACM_VERSION;
	msg.hdr.length = ACM_MSG_HDR_LENGTH + ACM_MSG_EP_LENGTH;
	msg.hdr.status = ACM_STATUS_SUCCESS;
	msg.hdr.tid = (uintptr_t) acmnlmsg;
	msg.resolve_data[0].type = ACM_EP_INFO_PATH;

	/* We support only one pathrecord */
	acm_log(2, "path use 0x%x\n", acmnlmsg->resolve_header.path_use);
	if (acmnlmsg->resolve_header.path_use ==
	    LS_RESOLVE_PATH_USE_UNIDIRECTIONAL)
		msg.resolve_data[0].info.path.reversible_numpath = 1;
	else
		msg.resolve_data[0].info.path.reversible_numpath =
			IBV_PATH_RECORD_REVERSIBLE | 1;

	data = (unsigned char *) &acmnlmsg->nlmsg_header + NLMSG_HDRLEN;
	resolve_hdr_len = NLMSG_ALIGN(sizeof(struct rdma_ls_resolve_header));
	attr = (struct nlattr *) (data + resolve_hdr_len);
	payload_len = acmnlmsg->nlmsg_header.nlmsg_len - NLMSG_HDRLEN -
		resolve_hdr_len;
	rem = payload_len;
	while (1) {
		if (rem < (int) sizeof(*attr) ||
		    attr->nla_len < sizeof(*attr) ||
		    attr->nla_len > rem)
			break;

		status = acm_nl_parse_path_attr(attr, &msg.resolve_data[0]);
		if (status) {
			acm_nl_process_invalid_request(client, acmnlmsg);
			return;
		}

		/* Next attribute */
		total_attr_len = NLA_ALIGN(attr->nla_len);
		rem -= total_attr_len;
		attr = (struct nlattr *) ((char *) attr + total_attr_len);
	}

	atomic_inc(&counter[ACM_CNTR_RESOLVE]);
	acm_svr_resolve(client, &msg);
}

static int acm_nl_is_valid_resolve_request(struct acm_nl_msg *acmnlmsg)
{
	int payload_len;

	payload_len = acmnlmsg->nlmsg_header.nlmsg_len - NLMSG_HDRLEN;
	if (payload_len < (sizeof(struct rdma_ls_resolve_header) +
			   sizeof(struct nlattr)))
		return 0;

	return 1;
}

static void acm_nl_receive(struct acmc_client *client)
{
	struct acm_nl_msg *acmnlmsg;
	int datalen = sizeof(*acmnlmsg);
	int ret;
	uint16_t client_inx, op;

	acmnlmsg = calloc(1, sizeof(*acmnlmsg));
	if (!acmnlmsg) {
		acm_log(0, "Out of memory for recving nl msg.\n");
		return;
	}
	ret = recv(client->sock, acmnlmsg, datalen, 0);
	if (!NLMSG_OK(&acmnlmsg->nlmsg_header, ret)) {
		acm_log(0, "Netlink receive error: %d.\n", ret);
		goto rcv_cleanup;
	}

	acm_log(2, "nlmsg: len %d type 0x%x flags 0x%x seq %d pid %d\n",
		acmnlmsg->nlmsg_header.nlmsg_len,
		acmnlmsg->nlmsg_header.nlmsg_type,
		acmnlmsg->nlmsg_header.nlmsg_flags,
		acmnlmsg->nlmsg_header.nlmsg_seq,
		acmnlmsg->nlmsg_header.nlmsg_pid);

	/* Currently we handle only request from the local service client */
	client_inx = RDMA_NL_GET_CLIENT(acmnlmsg->nlmsg_header.nlmsg_type);
	op = RDMA_NL_GET_OP(acmnlmsg->nlmsg_header.nlmsg_type);
	if (client_inx != RDMA_NL_LS) {
		acm_log_once(0, "ERROR - Unknown NL client ID (%d)\n", client_inx);
		goto rcv_cleanup;
	}

	switch (op) {
	case RDMA_NL_LS_OP_RESOLVE:
		if (acm_nl_is_valid_resolve_request(acmnlmsg))
			acm_nl_process_resolve(client, acmnlmsg);
		else
			acm_nl_process_invalid_request(client, acmnlmsg);
		break;
	default:
		/* Not supported*/
		acm_log_once(0, "WARN - invalid opcode %x\n", op);
		acm_nl_process_invalid_request(client, acmnlmsg);
		break;
	}

	return;
rcv_cleanup:
	free(acmnlmsg);
}

static int acm_init_nl(void)
{
	struct sockaddr_nl src_addr;
	int ret;
	int nl_rcv_socket;

	nl_rcv_socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_RDMA);
	if (nl_rcv_socket == -1) {
		acm_log(0, "ERROR - unable to allocate netlink recv socket\n");
		return errno;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = (1 << (RDMA_NL_GROUP_LS - 1));

	ret = bind(nl_rcv_socket, (struct sockaddr *)&src_addr,
		   sizeof(src_addr));
	if (ret == -1) {
		acm_log(0, "ERROR - unable to bind netlink socket\n");
		close(nl_rcv_socket);
		return errno;
	}

	/* init nl client structure */
	client_array[NL_CLIENT_INDEX].sock = nl_rcv_socket;
	return 0;
}

static void acm_server(bool systemd)
{
	fd_set readfds;
	int i, n, ret;
	struct acmc_device *dev;

	acm_log(0, "started\n");
	acm_init_server();

	client_array[NL_CLIENT_INDEX].sock = -1;
	listen_socket = -1;
	if (systemd) {
		ret = acm_listen_systemd();
		if (ret) {
			acm_log(0, "ERROR - systemd server listen failed\n");
			return;
		}
	}

	if (listen_socket == -1) {
		ret = acm_listen();
		if (ret) {
			acm_log(0, "ERROR - server listen failed\n");
			return;
		}
	}

	if (client_array[NL_CLIENT_INDEX].sock == -1) {
		ret = acm_init_nl();
		if (ret)
			acm_log(1, "Warn - Netlink init failed\n");
	}

	if (systemd)
		sd_notify(0, "READY=1");

	while (1) {
		n = (int) listen_socket;
		FD_ZERO(&readfds);
		FD_SET(listen_socket, &readfds);
		n = max(n, (int) ip_mon_socket);
		FD_SET(ip_mon_socket, &readfds);

		for (i = 0; i < FD_SETSIZE - 1; i++) {
			if (client_array[i].sock != -1) {
				FD_SET(client_array[i].sock, &readfds);
				n = max(n, (int) client_array[i].sock);
			}
		}

		list_for_each(&dev_list, dev, entry) {
			FD_SET(dev->device.verbs->async_fd, &readfds);
			n = max(n, (int) dev->device.verbs->async_fd);
		}

		ret = select(n + 1, &readfds, NULL, NULL, NULL);
		if (ret == -1) {
			acm_log(0, "ERROR - server select error\n");
			continue;
		}

		if (FD_ISSET(listen_socket, &readfds))
			acm_svr_accept();

		if (FD_ISSET(ip_mon_socket, &readfds))
			acm_ipnl_handler();

		for (i = 0; i < FD_SETSIZE - 1; i++) {
			if (client_array[i].sock != -1 &&
				FD_ISSET(client_array[i].sock, &readfds)) {
				acm_log(2, "receiving from client %d\n", i);
				if (i == NL_CLIENT_INDEX)
					acm_nl_receive(&client_array[i]);
				else
					acm_svr_receive(&client_array[i]);
			}
		}

		list_for_each(&dev_list, dev, entry) {
			if (FD_ISSET(dev->device.verbs->async_fd, &readfds)) {
				acm_log(2, "handling event from %s\n",
					dev->device.verbs->device->name);
				acm_event_handler(dev);
			}
		}
	}
}

enum ibv_rate acm_get_rate(uint8_t width, uint8_t speed)
{
	switch (width) {
	case 1: /* 1x */
		switch (speed) {
		case 1: return IBV_RATE_2_5_GBPS;
		case 2: return IBV_RATE_5_GBPS;
		case 4: /* fall through */
		case 8: return IBV_RATE_10_GBPS;
		case 16: return IBV_RATE_14_GBPS;
		case 32: return IBV_RATE_25_GBPS;
		default: return IBV_RATE_MAX;
		}
	case 2: /* 4x */
		switch (speed) {
		case 1: return IBV_RATE_10_GBPS;
		case 2: return IBV_RATE_20_GBPS;
		case 4: /* fall through */
		case 8: return IBV_RATE_40_GBPS;
		case 16: return IBV_RATE_56_GBPS;
		case 32: return IBV_RATE_100_GBPS;
		default: return IBV_RATE_MAX;
		}
	case 4: /* 8x */
		switch (speed) {
		case 1: return IBV_RATE_20_GBPS;
		case 2: return IBV_RATE_40_GBPS;
		case 4: /* fall through */
		case 8: return IBV_RATE_80_GBPS;
		case 16: return IBV_RATE_112_GBPS;
		case 32: return IBV_RATE_200_GBPS;
		default: return IBV_RATE_MAX;
		}
	case 8: /* 12x */
		switch (speed) {
		case 1: return IBV_RATE_30_GBPS;
		case 2: return IBV_RATE_60_GBPS;
		case 4: /* fall through */
		case 8: return IBV_RATE_120_GBPS;
		case 16: return IBV_RATE_168_GBPS;
		case 32: return IBV_RATE_300_GBPS;
		default: return IBV_RATE_MAX;
		}
	default:
		acm_log(0, "ERROR - unknown link width 0x%x\n", width);
		return IBV_RATE_MAX;
	}
}

enum ibv_mtu acm_convert_mtu(int mtu)
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

enum ibv_rate acm_convert_rate(int rate)
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
	case 14:  return IBV_RATE_14_GBPS;
	case 56:  return IBV_RATE_56_GBPS;
	case 112: return IBV_RATE_112_GBPS;
	case 168: return IBV_RATE_168_GBPS;
	case 25:  return IBV_RATE_25_GBPS;
	case 100: return IBV_RATE_100_GBPS;
	case 200: return IBV_RATE_200_GBPS;
	case 300: return IBV_RATE_300_GBPS;
	default:  return IBV_RATE_10_GBPS;
	}
}

static FILE *acm_open_addr_file(void)
{
	FILE *f;

	if ((f = fopen(addr_file, "r")))
		return f;

	acm_log(0, "notice - generating %s file\n", addr_file);
	if (!(f = popen(acme, "r"))) {
		acm_log(0, "ERROR - cannot generate %s\n", addr_file);
		return NULL;
	}
	pclose(f);
	return fopen(addr_file, "r");
}

static int
acm_ep_insert_addr(struct acmc_ep *ep, const char *name, uint8_t *addr,
		   uint8_t addr_type)
{
	int i, ret = -1;
	uint8_t tmp[ACM_MAX_ADDRESS];

	memset(tmp, 0, sizeof tmp);
	memcpy(tmp, addr, acm_addr_len(addr_type));

	if (!acm_addr_lookup(&ep->endpoint, addr, addr_type)) {
		for (i = 0; (i < MAX_EP_ADDR) &&
			    (ep->addr_info[i].addr.type != ACM_ADDRESS_INVALID); i++)
			;
		if (i == MAX_EP_ADDR) {
			ret = ENOMEM;
			goto out;
		}

		/* Open the provider endpoint only if at least a name or
		   address is found */
		if (!ep->prov_ep_context) {
			ret = ep->port->prov->open_endpoint(&ep->endpoint,
				ep->port->prov_port_context,
				&ep->prov_ep_context);
			if (ret) {
				acm_log(0, "Error: failed to open prov ep\n");
				goto out;
			}
		}
		ep->addr_info[i].addr.type = addr_type;
		strncpy(ep->addr_info[i].string_buf, name, ACM_MAX_ADDRESS);
		memcpy(ep->addr_info[i].addr.info.addr, tmp, ACM_MAX_ADDRESS);
		ret = ep->port->prov->add_address(&ep->addr_info[i].addr,
						  ep->prov_ep_context,
						  &ep->addr_info[i].prov_addr_context);
		if (ret) {
			acm_log(0, "Error: failed to add addr to provider\n");
			ep->addr_info[i].addr.type = ACM_ADDRESS_INVALID;
			goto out;
		}
	}
	ret = 0;
out:
	return ret;
}

static struct acmc_device *
acm_get_device_from_gid(union ibv_gid *sgid, uint8_t *port)
{
	struct acmc_device *dev;
	int i;

	list_for_each(&dev_list, dev, entry) {
		for (*port = 1; *port <= dev->port_cnt; (*port)++) {

			for (i = 0; i < dev->port[*port - 1].gid_cnt; i++) {

				if (!memcmp(sgid->raw,
					    dev->port[*port - 1].gid_tbl[i].raw,
					    sizeof(*sgid)))
					return dev;
			}
		}
	}
	return NULL;
}

static void acm_ep_ip_iter_cb(char *ifname, union ibv_gid *gid, uint16_t pkey,
		uint8_t addr_type, uint8_t *addr,
		char *ip_str, void *ctx)
{
	uint8_t port_num;
	struct acmc_device *dev;
	struct acmc_ep *ep = ctx;

	dev = acm_get_device_from_gid(gid, &port_num);
	if (dev && ep->port->dev == dev
	    && ep->port->port.port_num == port_num &&
		/* pkey retrieved from ipoib has always full mmbr bit set */
		(ep->endpoint.pkey | IB_PKEY_FULL_MEMBER) == pkey) {
		if (!acm_ep_insert_addr(ep, ip_str, addr, addr_type)) {
			acm_log(0, "Added %s %s %d 0x%x from %s\n", ip_str,
				dev->device.verbs->device->name, port_num, ep->endpoint.pkey,
				ifname);
		}
	}
}

static int acm_get_system_ips(struct acmc_ep *ep)
{
	return acm_if_iter_sys(acm_ep_ip_iter_cb, ep);
}

static int acm_assign_ep_names(struct acmc_ep *ep)
{
	FILE *faddr;
	char *dev_name;
	char s[120];
	char dev[32], name[ACM_MAX_ADDRESS], pkey_str[8];
	uint16_t pkey;
	uint8_t addr[ACM_MAX_ADDRESS], type;
	int port;

	dev_name = ep->port->dev->device.verbs->device->name;
	acm_log(1, "device %s, port %d, pkey 0x%x\n",
		dev_name, ep->port->port.port_num, ep->endpoint.pkey);

	acm_get_system_ips(ep);

	if (!(faddr = acm_open_addr_file())) {
		acm_log(0, "ERROR - address file not found\n");
		goto out;
	}

	while (fgets(s, sizeof s, faddr)) {
		if (s[0] == '#')
			continue;

		if (sscanf(s, "%46s%31s%d%7s", name, dev, &port, pkey_str) != 4)
			continue;

		acm_log(2, "%s", s);
		if (inet_pton(AF_INET, name, addr) > 0) {
			if (!support_ips_in_addr_cfg) {
				acm_log(0, "ERROR - IP's are not configured to be read from ibacm_addr.cfg\n");
				continue;
			}
			type = ACM_ADDRESS_IP;
		} else if (inet_pton(AF_INET6, name, addr) > 0) {
			if (!support_ips_in_addr_cfg) {
				acm_log(0, "ERROR - IP's are not configured to be read from ibacm_addr.cfg\n");
				continue;
			}
			type = ACM_ADDRESS_IP6;
		} else {
			type = ACM_ADDRESS_NAME;
			strncpy((char *)addr, name, sizeof(addr));
		}

		if (strcasecmp(pkey_str, "default")) {
			if (sscanf(pkey_str, "%hx", &pkey) != 1) {
				acm_log(0, "ERROR - bad pkey format %s\n", pkey_str);
				continue;
			}
		} else {
			pkey = ep->port->def_acm_pkey;
		}

		if (!strcasecmp(dev_name, dev) &&
		    (ep->port->port.port_num == (uint8_t) port) &&
		    acm_same_partition(ep->endpoint.pkey, pkey)) {
			acm_log(1, "assigning %s\n", name);
			if (acm_ep_insert_addr(ep, name, addr, type)) {
				acm_log(1, "maximum number of names assigned to EP\n");
				break;
			}
		}
	}
	fclose(faddr);

out:
	return (ep->addr_info[0].addr.type == ACM_ADDRESS_INVALID);
}

static struct acmc_ep *acm_find_ep(struct acmc_port *port, uint16_t pkey)
{
	struct acmc_ep *ep, *res = NULL;

	acm_log(2, "pkey 0x%x\n", pkey);

	list_for_each(&port->ep_list, ep, entry) {
		if (acm_same_partition(ep->endpoint.pkey, pkey)) {
			res = ep;
			break;
		}
	}
	return res;
}

static void acm_ep_down(struct acmc_ep *ep)
{
	int i;

	acm_log(1, "%s %d pkey 0x%04x\n",
		ep->port->dev->device.verbs->device->name,
		ep->port->port.port_num, ep->endpoint.pkey);
	for (i = 0; i < MAX_EP_ADDR; i++) {
		if (ep->addr_info[i].addr.type &&
		    ep->addr_info[i].prov_addr_context)
			ep->port->prov->remove_address(ep->addr_info[i].
						       prov_addr_context);
	}

	if (ep->prov_ep_context)
		ep->port->prov->close_endpoint(ep->prov_ep_context);

	free(ep);
}

static struct acmc_ep *
acm_alloc_ep(struct acmc_port *port, uint16_t pkey)
{
	struct acmc_ep *ep;
	int i;

	acm_log(1, "\n");
	ep = calloc(1, sizeof *ep);
	if (!ep)
		return NULL;

	ep->port = port;
	ep->endpoint.port = &port->port;
	ep->endpoint.pkey = pkey;

	for (i = 0; i < MAX_EP_ADDR; i++) {
		ep->addr_info[i].addr.endpoint = &ep->endpoint;
		ep->addr_info[i].addr.id_string = ep->addr_info[i].string_buf;
	}

	return ep;
}

static void acm_ep_up(struct acmc_port *port, uint16_t pkey)
{
	struct acmc_ep *ep;
	int ret;

	acm_log(1, "\n");
	if (acm_find_ep(port, pkey)) {
		acm_log(2, "endpoint for pkey 0x%x already exists\n", pkey);
		return;
	}

	acm_log(2, "creating endpoint for pkey 0x%x\n", pkey);
	ep = acm_alloc_ep(port, pkey);
	if (!ep)
		return;

	ret = acm_assign_ep_names(ep);
	if (ret) {
		acm_log(1, "unable to assign EP name for pkey 0x%x\n", pkey);
		goto ep_close;
	}

	list_add(&port->ep_list, &ep->entry);
	return;

ep_close:
	if (ep->prov_ep_context)
		port->prov->close_endpoint(ep->prov_ep_context);

	free(ep);
}

static void acm_assign_provider(struct acmc_port *port)
{
	struct acmc_prov *prov;
	struct acmc_subnet *subnet;

	acm_log(2, "port %s/%d\n", port->port.dev->verbs->device->name,
		port->port.port_num);
	list_for_each(&provider_list, prov, entry) {
		list_for_each(&prov->subnet_list, subnet, entry) {
			if (subnet->subnet_prefix ==
			    port->gid_tbl[0].global.subnet_prefix) {
				acm_log(2, "Found provider %s for port %s/%d\n",
					prov->prov->name,
					port->port.dev->verbs->device->name,
					port->port.port_num);
				port->prov = prov->prov;
				return;
			}
		}
	}

	/* If no provider is found, assign the default provider*/
	if (!port->prov) {
		acm_log(2, "No prov found, assign default prov %s to %s/%d\n",
			def_provider ? def_provider->prov->name: "NULL",
			port->port.dev->verbs->device->name,
			port->port.port_num);
		port->prov = def_provider ? def_provider->prov : NULL;
	}
}

static void acm_port_get_gid_tbl(struct acmc_port *port)
{
	union ibv_gid gid;
	int i, j, ret;

	for (i = 0;; i++) {
		ret = ibv_query_gid(port->port.dev->verbs, port->port.port_num,
				    i, &gid);
		if (ret || !gid.global.interface_id)
			break;
	}

	if (i > 0) {
		port->gid_tbl = calloc(i, sizeof(union ibv_gid));
		if (!port->gid_tbl) {
			acm_log(0, "Error: failed to allocate gid table\n");
			port->gid_cnt = 0;
			return;
		}

		for (j = 0; j < i; j++) {
			ret = ibv_query_gid(port->port.dev->verbs,
					    port->port.port_num, j,
					    &port->gid_tbl[j]);
			if (ret || !port->gid_tbl[j].global.interface_id)
				break;
			acm_log(2, "guid %d: 0x%" PRIx64 " %" PRIx64 "\n", j,
				be64toh(port->gid_tbl[j].global.subnet_prefix),
				be64toh(port->gid_tbl[j].global.interface_id));
		}
		port->gid_cnt = j;
	}
	acm_log(2, "port %d gid_cnt %d\n", port->port.port_num,
		port->gid_cnt);
}

static void acm_port_up(struct acmc_port *port)
{
	struct ibv_port_attr attr;
	uint16_t pkey;
	__be16 pkey_be;
	int i, ret;
	struct acmc_prov_context *dev_ctx;
	int index = -1;
	uint16_t first_pkey = 0;

	acm_log(1, "%s %d\n", port->dev->device.verbs->device->name,
		port->port.port_num);
	ret = ibv_query_port(port->dev->device.verbs, port->port.port_num,
			     &attr);
	if (ret) {
		acm_log(0, "ERROR - unable to get port state\n");
		return;
	}
	if (attr.state != IBV_PORT_ACTIVE) {
		acm_log(1, "port not active\n");
		return;
	}

	acm_port_get_gid_tbl(port);
	port->lid = attr.lid;
	port->lid_mask = 0xffff - ((1 << attr.lmc) - 1);
	port->sa_addr.lid = htobe16(attr.sm_lid);
	port->sa_addr.sl = attr.sm_sl;
	port->state = IBV_PORT_ACTIVE;
	acm_assign_provider(port);
	if (!port->prov) {
		acm_log(1, "no provider assigned to port\n");
		return;
	}
	dev_ctx = acm_acquire_prov_context(&port->dev->prov_dev_context_list,
					   port->prov);
	if (!dev_ctx) {
		acm_log(0, "Error -- failed to acquire dev context\n");
		return;
	}

	if (atomic_get(&dev_ctx->refcnt) == 1) {
		if (port->prov->open_device(&port->dev->device, &dev_ctx->context)) {
			acm_log(0, "Error -- failed to open the prov device\n");
			goto err1;
		}
	}

	if (port->prov->open_port(&port->port, dev_ctx->context,
				  &port->prov_port_context)) {
		acm_log(0, "Error -- failed to open the prov port\n");
		goto err1;
	}

	/* Determine the default pkey for SA access first.
	 *     Order of preference: 0xffff, 0x7fff
	 * Use the first pkey as the default pkey for parsing address file.
	 */
	for (i = 0; i < attr.pkey_tbl_len; i++) {
		ret = ibv_query_pkey(port->dev->device.verbs,
				     port->port.port_num, i, &pkey_be);
		if (ret)
			continue;
		pkey = be16toh(pkey_be);
		if (i == 0)
			first_pkey = pkey;
		if (pkey == 0xffff) {
			index = i;
			break;
		}
		else if (pkey == 0x7fff) {
			index = i;
		}
	}
	port->sa_pkey_index = index < 0 ? 0 : index;
	port->def_acm_pkey = first_pkey;

	for (i = 0; i < attr.pkey_tbl_len; i++) {
		ret = ibv_query_pkey(port->dev->device.verbs,
				     port->port.port_num, i, &pkey_be);
		if (ret)
			continue;
		pkey = be16toh(pkey_be);
		if (!(pkey & 0x7fff))
			continue;

		acm_ep_up(port, pkey);
	}
	return;
err1:
	acm_release_prov_context(dev_ctx);
}

static void acm_shutdown_port(struct acmc_port *port)
{
	struct acmc_ep *ep;
	struct acmc_prov_context *dev_ctx;

	while ((ep = list_pop(&port->ep_list, struct acmc_ep, entry)))
		acm_ep_down(ep);

	if (port->prov_port_context) {
		port->prov->close_port(port->prov_port_context);
		port->prov_port_context = NULL;
		dev_ctx = acm_get_prov_context(&port->dev->prov_dev_context_list,
					       port->prov);
		if (dev_ctx) {
			if (atomic_get(&dev_ctx->refcnt) == 1)
				port->prov->close_device(dev_ctx->context);
			acm_release_prov_context(dev_ctx);
		}
	}
	port->prov = NULL;
	if (port->gid_tbl) {
		free(port->gid_tbl);
		port->gid_tbl = NULL;
	}
	port->gid_cnt = 0;
}

static void acm_port_down(struct acmc_port *port)
{
	struct ibv_port_attr attr;
	int ret;

	acm_log(1, "%s %d\n", port->port.dev->verbs->device->name, port->port.port_num);
	ret = ibv_query_port(port->port.dev->verbs, port->port.port_num, &attr);
	if (!ret && attr.state == IBV_PORT_ACTIVE) {
		acm_log(1, "port active\n");
		return;
	}

	port->state = attr.state;
	acm_shutdown_port(port);

	acm_log(1, "%s %d is down\n", port->dev->device.verbs->device->name,
		port->port.port_num);
}

static void acm_port_change(struct acmc_port *port)
{
	struct ibv_port_attr attr;
	int ret;

	acm_log(1, "%s %d\n", port->port.dev->verbs->device->name, port->port.port_num);
	ret = ibv_query_port(port->port.dev->verbs, port->port.port_num, &attr);
	if (ret || attr.state != IBV_PORT_ACTIVE) {
		acm_log(1, "port not active: don't care\n");
		return;
	}

	port->state = attr.state;
	acm_shutdown_port(port);
	acm_port_up(port);
}

static void acm_event_handler(struct acmc_device *dev)
{
	struct ibv_async_event event;
	int i, ret;

	ret = ibv_get_async_event(dev->device.verbs, &event);
	if (ret)
		return;

	acm_log(2, "processing async event %s for %s\n",
		ibv_event_type_str(event.event_type),
		dev->device.verbs->device->name);
	i = event.element.port_num - 1;

	switch (event.event_type) {
	case IBV_EVENT_PORT_ACTIVE:
		if (dev->port[i].state != IBV_PORT_ACTIVE)
			acm_port_up(&dev->port[i]);
		if (dev->port[i].pending_rereg && dev->port[i].prov_port_context) {
			dev->port[i].prov->handle_event(dev->port[i].prov_port_context,
							IBV_EVENT_CLIENT_REREGISTER);
			dev->port[i].pending_rereg = false;
			acm_log(1, "%s %d delayed reregistration\n",
				dev->device.verbs->device->name, i + 1);
		}

		break;
	case IBV_EVENT_PORT_ERR:
		if (dev->port[i].state == IBV_PORT_ACTIVE)
			acm_port_down(&dev->port[i]);
		break;
	case IBV_EVENT_CLIENT_REREGISTER:
		if ((dev->port[i].state == IBV_PORT_ACTIVE) &&
		    dev->port[i].prov_port_context) {
			dev->port[i].prov->handle_event(dev->port[i].prov_port_context,
							event.event_type);
			acm_log(1, "%s %d has reregistered\n",
				dev->device.verbs->device->name, i + 1);
		} else {
			acm_log(2, "%s %d rereg on inactive port, postpone handling\n",
				dev->device.verbs->device->name, i + 1);
			dev->port[i].pending_rereg = true;
		}

		break;
	case IBV_EVENT_LID_CHANGE:
	case IBV_EVENT_GID_CHANGE:
	case IBV_EVENT_PKEY_CHANGE:
		acm_port_change(&dev->port[i]);
		break;
	default:
		break;
	}

	ibv_ack_async_event(&event);
}

static void acm_activate_devices(void)
{
	struct acmc_device *dev;
	int i;

	acm_log(1, "\n");
	list_for_each(&dev_list, dev, entry) {
		for (i = 0; i < dev->port_cnt; i++) {
			acm_port_up(&dev->port[i]);
		}
	}
}

static void
acm_open_port(struct acmc_port *port, struct acmc_device *dev, uint8_t port_num)
{
	acm_log(1, "%s %d\n", dev->device.verbs->device->name, port_num);
	port->dev = dev;
	port->port.dev = &dev->device;
	port->port.port_num = port_num;
	pthread_mutex_init(&port->lock, NULL);
	list_head_init(&port->ep_list);
	list_head_init(&port->sa_pending);
	list_head_init(&port->sa_wait);
	port->sa_credits = sa.depth;
	port->sa_addr.qpn = htobe32(1);
	port->sa_addr.qkey = htobe32(ACM_QKEY);

	port->mad_portid = umad_open_port(dev->device.verbs->device->name, port_num);
	if (port->mad_portid < 0)
		acm_log(0, "ERROR - unable to open MAD port\n");

	port->mad_agentid = umad_register(port->mad_portid,
					  IB_MGMT_CLASS_SA, 1, 1, NULL);
	if (port->mad_agentid < 0) {
		umad_close_port(port->mad_portid);
		acm_log(0, "ERROR - unable to register MAD client\n");
	}

	port->prov = NULL;
	port->state = IBV_PORT_DOWN;
}

static void acm_open_dev(struct ibv_device *ibdev)
{
	struct acmc_device *dev;
	struct ibv_device_attr attr;
	struct ibv_port_attr port_attr;
	struct ibv_context *verbs;
	size_t size;
	int i, ret;
	unsigned int opened_ib_port_cnt = 0;

	acm_log(1, "%s\n", ibdev->name);
	verbs = ibv_open_device(ibdev);
	if (verbs == NULL) {
		acm_log(0, "ERROR - opening device %s\n", ibdev->name);
		return;
	}

	ret = ibv_query_device(verbs, &attr);
	if (ret) {
		acm_log(0, "ERROR - ibv_query_device (%d) %s\n", ret, ibdev->name);
		goto err1;
	}

	size = sizeof(*dev) + sizeof(struct acmc_port) * attr.phys_port_cnt;
	dev = (struct acmc_device *) calloc(1, size);
	if (!dev)
		goto err1;

	dev->device.verbs = verbs;
	dev->device.dev_guid = ibv_get_device_guid(ibdev);
	dev->port_cnt = attr.phys_port_cnt;
	list_head_init(&dev->prov_dev_context_list);

	for (i = 0; i < dev->port_cnt; i++) {
		acm_log(1, "%s port %d\n", ibdev->name, i + 1);
		ret = ibv_query_port(dev->device.verbs, i + 1, &port_attr);
		if (ret) {
			acm_log(0, "ERROR - ibv_query_port (%d)\n", ret);
			continue;
		}
		if (port_attr.link_layer != IBV_LINK_LAYER_INFINIBAND) {
			acm_log(1, "not an InfiniBand port\n");
			continue;
		}

		acm_open_port(&dev->port[i], dev, i + 1);
		opened_ib_port_cnt++;
	}

	if (opened_ib_port_cnt) {
		list_add(&dev_list, &dev->entry);
		acm_log(1, "%d InfiniBand %s opened for %s\n",
				opened_ib_port_cnt,
				opened_ib_port_cnt == 1 ? "port" : "ports",
				ibdev->name);
		return;
	}

	free(dev);

err1:
	ibv_close_device(verbs);
}

static int acm_open_devices(void)
{
	struct ibv_device **ibdev;
	int dev_cnt;
	int i;

	acm_log(1, "\n");
	ibdev = ibv_get_device_list(&dev_cnt);
	if (!ibdev) {
		acm_log(0, "ERROR - unable to get device list\n");
		return -1;
	}

	for (i = 0; i < dev_cnt; i++)
		acm_open_dev(ibdev[i]);

	ibv_free_device_list(ibdev);
	if (list_empty(&dev_list)) {
		acm_log(0, "ERROR - no devices\n");
		return -1;
	}

	return 0;
}

static void acm_load_prov_config(void)
{
	FILE *fd;
	char s[128];
	char *p, *ptr;
	char prov_name[ACM_PROV_NAME_SIZE];
	uint64_t prefix;
	struct acmc_prov *prov;
	struct acmc_subnet *subnet;

	if (!(fd = fopen(opts_file, "r")))
		return;

	while (fgets(s, sizeof s, fd)) {
		if (s[0] == '#')
			continue;

		/* Ignore blank lines */
		if (!(p = strtok_r(s, " \n", &ptr)))
			continue;

		if (strncasecmp(p, "provider", sizeof("provider") - 1))
			continue;

		p = strtok_r(NULL, " ", &ptr);
		if (!p)
			continue;

		strncpy(prov_name, p, sizeof(prov_name));
		prov_name[sizeof(prov_name) -1] = '\0';

		p = strtok_r(NULL, " ", &ptr);
		if (!p)
			continue;
		if (!strncasecmp(p, "default", sizeof("default") - 1)) {
			strncpy(def_prov_name, prov_name, sizeof(def_prov_name));
			def_prov_name[sizeof(def_prov_name) -1] = '\0';
			acm_log(2, "default provider: %s\n", def_prov_name);
			continue;
		}
		prefix = strtoull(p, NULL, 0);
		acm_log(2, "provider %s subnet_prefix 0x%" PRIx64 "\n",
			prov_name, prefix);

		list_for_each(&provider_list, prov, entry) {
			if (!strcasecmp(prov->prov->name, prov_name)) {
				subnet = calloc(1, sizeof (*subnet));
				if (!subnet) {
					acm_log(0, "Error: out of memory\n");
					fclose(fd);
					return;
				}
				subnet->subnet_prefix = htobe64(prefix);
				list_add_tail(&prov->subnet_list,
					      &subnet->entry);
			}
		}
	}

	fclose(fd);

	list_for_each(&provider_list, prov, entry) {
		if (!strcasecmp(prov->prov->name, def_prov_name)) {
			def_provider = prov;
			break;
		}
	}
}

static int acm_open_providers(void)
{
	DIR *shlib_dir;
	struct dirent *dent;
	char file_name[256];
	struct stat buf;
	void *handle;
	struct acmc_prov *prov;
	struct acm_provider *provider;
	uint32_t version;
	char *err_str;
	int (*query)(struct acm_provider **, uint32_t *);

	acm_log(1, "\n");
	shlib_dir = opendir(prov_lib_path);
	if (!shlib_dir) {
		acm_log(0, "ERROR - could not open provider lib dir: %s\n",
			prov_lib_path);
		return -1;
	}

	while ((dent = readdir(shlib_dir))) {
		if (!strstr(dent->d_name, ".so"))
			continue;

		if (!check_snprintf(file_name, sizeof(file_name), "%s/%s",
				    prov_lib_path, dent->d_name))
			continue;

		if (lstat(file_name, &buf)) {
			acm_log(0, "Error - could not stat: %s\n", file_name);
			continue;
		}
		if (!S_ISREG(buf.st_mode))
			continue;

		acm_log(2, "Loading provider %s...\n", file_name);
		if (!(handle = dlopen(file_name, RTLD_LAZY))) {
			acm_log(0, "Error - could not load provider %s (%s)\n",
				file_name, dlerror());
			continue;
		}

		query = dlsym(handle, "provider_query");
		if ((err_str = dlerror()) != NULL) {
			acm_log(0, "Error - provider_query not found in %s (%s)\n",
				file_name, err_str);
			dlclose(handle);
			continue;
		}

		if (query(&provider, &version)) {
			acm_log(0, "Error - provider_query failed to %s\n", file_name);
			dlclose(handle);
			continue;
		}

		if (version != ACM_PROV_VERSION ||
		    provider->size != sizeof(struct acm_provider)) {
			acm_log(0, "Error -unmatched provider version 0x%08x (size %zd)"
				" core 0x%08x (size %zd)\n", version, provider->size,
				ACM_PROV_VERSION, sizeof(struct acm_provider));
			dlclose(handle);
			continue;
		}

		acm_log(1, "Provider %s (%s) loaded\n", provider->name, file_name);

		prov = calloc(1, sizeof(*prov));
		if (!prov) {
			acm_log(0, "Error -failed to allocate provider %s\n", file_name);
			dlclose(handle);
			continue;
		}

		prov->prov = provider;
		prov->handle = handle;
		list_head_init(&prov->subnet_list);
		list_add_tail(&provider_list, &prov->entry);
		if (!strcasecmp(provider->name, def_prov_name))
			def_provider = prov;
	}

	closedir(shlib_dir);
	acm_load_prov_config();
	return 0;
}

static void acm_close_providers(void)
{
	struct acmc_prov *prov;
	struct acmc_subnet *subnet;

	acm_log(1, "\n");
	def_provider = NULL;

	while ((prov = list_pop(&provider_list, struct acmc_prov, entry))) {
		while ((subnet = list_pop(&prov->subnet_list,
				struct acmc_subnet, entry)))
			free(subnet);
		dlclose(prov->handle);
		free(prov);
	}
}

static int acmc_init_sa_fds(void)
{
	struct acmc_device *dev;
	int ret, p, i = 0;

	list_for_each(&dev_list, dev, entry)
		sa.nfds += dev->port_cnt;

	sa.fds = calloc(sa.nfds, sizeof(*sa.fds));
	sa.ports = calloc(sa.nfds, sizeof(*sa.ports));
	if (!sa.fds || !sa.ports)
		return -ENOMEM;

	list_for_each(&dev_list, dev, entry) {
		for (p = 0; p < dev->port_cnt; p++) {
			sa.fds[i].fd = umad_get_fd(dev->port[p].mad_portid);
			sa.fds[i].events = POLLIN;
			ret = set_fd_nonblock(sa.fds[i].fd, true);
			if (ret)
				acm_log(0, "WARNING - umad fd is blocking\n");

			sa.ports[i++] = &dev->port[p];
		}
	}

	return 0;
}

struct acm_sa_mad *
acm_alloc_sa_mad(const struct acm_endpoint *endpoint, void *context,
		 void (*handler)(struct acm_sa_mad *))
{
	struct acmc_sa_req *req;

	if (!endpoint) {
		acm_log(0, "Error: NULL endpoint\n");
		return NULL;
	}
	req = calloc(1, sizeof (*req));
	if (!req) {
		acm_log(0, "Error: failed to allocate sa request\n");
		return NULL;
	}

	req->ep = container_of(endpoint, struct acmc_ep, endpoint);
	req->mad.context = context;
	req->resp_handler = handler;

	acm_log(2, "%p\n", req);
	return &req->mad;
}

void acm_free_sa_mad(struct acm_sa_mad *mad)
{
	struct acmc_sa_req *req;
	req = container_of(mad, struct acmc_sa_req, mad);
	acm_log(2, "%p\n", req);
	free(req);
}

int acm_send_sa_mad(struct acm_sa_mad *mad)
{
	struct acmc_port *port;
	struct acmc_sa_req *req;
	int ret;

	req = container_of(mad, struct acmc_sa_req, mad);
	acm_log(2, "%p from %s\n", req, req->ep->addr_info[0].addr.id_string);

	port = req->ep->port;
	mad->umad.addr.qpn = port->sa_addr.qpn;
	mad->umad.addr.qkey = port->sa_addr.qkey;
	mad->umad.addr.lid = port->sa_addr.lid;
	mad->umad.addr.sl = port->sa_addr.sl;
	mad->umad.addr.pkey_index = req->ep->port->sa_pkey_index;

	pthread_mutex_lock(&port->lock);
	if (port->sa_credits && list_empty(&port->sa_wait)) {
		ret = umad_send(port->mad_portid, port->mad_agentid, &mad->umad,
				sizeof mad->sa_mad, sa.timeout, sa.retries);
		if (!ret) {
			port->sa_credits--;
			list_add_tail(&port->sa_pending, &req->entry);
		}
	} else {
		ret = 0;
		list_add_tail(&port->sa_wait, &req->entry);
	}
	pthread_mutex_unlock(&port->lock);
	return ret;
}

static void acmc_send_queued_req(struct acmc_port *port)
{
	struct acmc_sa_req *req;
	int ret;

	pthread_mutex_lock(&port->lock);
	if (list_empty(&port->sa_wait) || !port->sa_credits) {
		pthread_mutex_unlock(&port->lock);
		return;
	}

	req = list_pop(&port->sa_wait, struct acmc_sa_req, entry);

	ret = umad_send(port->mad_portid, port->mad_agentid, &req->mad.umad,
			sizeof req->mad.sa_mad, sa.timeout, sa.retries);
	if (!ret) {
		port->sa_credits--;
		list_add_tail(&port->sa_pending, &req->entry);
	}
	pthread_mutex_unlock(&port->lock);

	if (ret) {
		req->mad.umad.status = -ret;
		req->resp_handler(&req->mad);
	}
}

static void acmc_recv_mad(struct acmc_port *port)
{
	struct acmc_sa_req *req;
	struct acm_sa_mad resp;
	int ret, len, found;
	struct umad_hdr *hdr;

	if (!port->prov) {
		acm_log(1, "no provider assigned to port\n");
		return;
	}

	acm_log(2, "\n");
	len = sizeof(resp.sa_mad);
	ret = umad_recv(port->mad_portid, &resp.umad, &len, 0);
	if (ret < 0) {
		acm_log(1, "umad_recv error %d\n", ret);
		return;
	}

	hdr = &resp.sa_mad.mad_hdr;
	acm_log(2, "bv %x cls %x cv %x mtd %x st %d tid %" PRIx64 "x at %x atm %x\n",
		hdr->base_version, hdr->mgmt_class, hdr->class_version,
		hdr->method, hdr->status, be64toh(hdr->tid), hdr->attr_id, hdr->attr_mod);
	found = 0;
	pthread_mutex_lock(&port->lock);
	list_for_each(&port->sa_pending, req, entry) {
		/* The upper 32-bit of the tid is used for agentid in umad */
		if (req->mad.sa_mad.mad_hdr.tid == (hdr->tid & htobe64(0xFFFFFFFF))) {
			found = 1;
			list_del(&req->entry);
			port->sa_credits++;
			break;
		}
	}
	pthread_mutex_unlock(&port->lock);

	if (found) {
		memcpy(&req->mad.umad, &resp.umad, sizeof(resp.umad) + len);
		req->resp_handler(&req->mad);
	}
}

static void *acm_sa_handler(void *context)
{
	int i, ret;

	acm_log(0, "started\n");
	ret = acmc_init_sa_fds();
	if (ret) {
		acm_log(0, "ERROR - failed to init fds\n");
		return NULL;
	}

	if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL)) {
		acm_log(0, "Error: failed to set cancel type \n");
		return NULL;
	}

	if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) {
		acm_log(0, "Error: failed to set cancel state\n");
		return NULL;
	}

	for (;;) {
		pthread_testcancel();
		ret = poll(sa.fds, sa.nfds, -1);
		if (ret < 0) {
			acm_log(0, "ERROR - sa poll error: %d\n", errno);
			continue;
		}

		for (i = 0; i < sa.nfds; i++) {
			if (!sa.fds[i].revents)
				continue;

			if (sa.fds[i].revents & POLLIN) {
				acmc_recv_mad(sa.ports[i]);
				acmc_send_queued_req(sa.ports[i]);
			}
			sa.fds[i].revents = 0;
		}
	}
	return NULL;
}

static void acm_stop_sa_handler(void)
{
	if (pthread_cancel(sa.thread_id)) {
		acm_log(0, "Error: failed to cancel sa resp thread \n");
		return;
	}

	if (pthread_join(sa.thread_id, NULL)) {
		acm_log(0, "Error: failed to join sa resp thread\n");
		return;
	}
}

static void acm_set_options(void)
{
	FILE *f;
	char s[120];
	char opt[32], value[256];

	if (!(f = fopen(opts_file, "r")))
		return;

	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;

		if (sscanf(s, "%31s%255s", opt, value) != 2)
			continue;

		if (!strcasecmp("log_file", opt))
			strcpy(log_file, value);
		else if (!strcasecmp("log_level", opt))
			log_level = atoi(value);
		else if (!strcasecmp("lock_file", opt))
			strcpy(lock_file, value);
		else if (!strcasecmp("server_port", opt))
			server_port = (short) atoi(value);
		else if (!strcasecmp("server_mode", opt)) {
			if (!strcasecmp(value, "open"))
				server_mode = IBACM_SERVER_MODE_OPEN;
			else if (!strcasecmp(value, "loop"))
				server_mode = IBACM_SERVER_MODE_LOOP;
			else
				server_mode = IBACM_SERVER_MODE_UNIX;
		} else if (!strcasecmp("acme_plus_kernel_only", opt))
			acme_plus_kernel_only =
				!strcasecmp(value, "true") ||
				!strcasecmp(value, "yes") ||
				strtol(value, NULL, 0);
		else if (!strcasecmp("provider_lib_path", opt))
			strcpy(prov_lib_path, value);
		else if (!strcasecmp("support_ips_in_addr_cfg", opt))
			support_ips_in_addr_cfg = atoi(value);
		else if (!strcasecmp("timeout", opt))
			sa.timeout = atoi(value);
		else if (!strcasecmp("retries", opt))
			sa.retries = atoi(value);
		else if (!strcasecmp("sa_depth", opt))
			sa.depth = atoi(value);
	}

	fclose(f);
}

static void acm_log_options(void)
{
	static const char * const server_mode_names[] = {
		[IBACM_SERVER_MODE_UNIX] = "unix",
		[IBACM_SERVER_MODE_LOOP] = "loop",
		[IBACM_SERVER_MODE_OPEN] = "open",
	};

	acm_log(0, "log file %s\n", log_file);
	acm_log(0, "log level %d\n", log_level);
	acm_log(0, "lock file %s\n", lock_file);
	acm_log(0, "server_port %d\n", server_port);
	acm_log(0, "server_mode %s\n", server_mode_names[server_mode]);
	acm_log(0, "acme_plus_kernel_only %s\n",
		acme_plus_kernel_only ? "yes" : "no");
	acm_log(0, "timeout %d ms\n", sa.timeout);
	acm_log(0, "retries %d\n", sa.retries);
	acm_log(0, "sa depth %d\n", sa.depth);
	acm_log(0, "options file %s\n", opts_file);
	acm_log(0, "addr file %s\n", addr_file);
	acm_log(0, "provider lib path %s\n", prov_lib_path);
	acm_log(0, "support IP's in ibacm_addr.cfg %d\n", support_ips_in_addr_cfg);
}

static FILE *acm_open_log(void)
{
	FILE *f;

	if (!strcasecmp(log_file, "stdout"))
		return stdout;

	if (!strcasecmp(log_file, "stderr"))
		return stderr;

	if (!(f = fopen(log_file, "w")))
		f = stdout;

	return f;
}

static int acm_open_lock_file(void)
{
	int lock_fd;
	char pid[16];

	lock_fd = open(lock_file, O_RDWR | O_CREAT, 0640);
	if (lock_fd < 0)
		return lock_fd;

	if (lockf(lock_fd, F_TLOCK, 0)) {
		close(lock_fd);
		return -1;
	}

	snprintf(pid, sizeof pid, "%d\n", getpid());
	if (write(lock_fd, pid, strlen(pid)) != strlen(pid)){
		close(lock_fd);
		return -1;
	}
	return 0;
}

static void show_usage(char *program)
{
	printf("usage: %s\n", program);
	printf("   [-D]             - run as a daemon (default)\n");
	printf("   [-P]             - run as a standard process\n");
	printf("   [-A addr_file]   - address configuration file\n");
	printf("                      (default %s/%s)\n", ACM_CONF_DIR, ACM_ADDR_FILE);
	printf("   [-O option_file] - option configuration file\n");
	printf("                      (default %s/%s)\n", ACM_CONF_DIR, ACM_OPTS_FILE);
}

int main(int argc, char **argv)
{
	int i, op, as_daemon = 1;
	bool systemd = false;

	static const struct option long_opts[] = {
		{"systemd", 0, NULL, 's'},
		{}
	};

	while ((op = getopt_long(argc, argv, "DPA:O:", long_opts, NULL)) !=
	       -1) {
		switch (op) {
		case 'D':
			/* option no longer required */
			break;
		case 'P':
			as_daemon = 0;
			break;
		case 'A':
			addr_file = optarg;
			break;
		case 'O':
			opts_file = optarg;
			break;
		case 's':
			systemd = true;
			break;
		default:
			show_usage(argv[0]);
			exit(1);
		}
	}

	if (as_daemon && !systemd) {
		if (daemon(0, 0))
			return EXIT_FAILURE;
	}

	acm_set_options();

	/* usage of systemd implies unix-domain communication */
	if (systemd)
		server_mode = IBACM_SERVER_MODE_UNIX;

	if (acm_open_lock_file())
		return -1;

	pthread_mutex_init(&log_lock, NULL);
	flog = acm_open_log();

	acm_log(0, "Assistant to the InfiniBand Communication Manager\n");
	acm_log_options();

	for (i = 0; i < ACM_MAX_COUNTER; i++)
		atomic_init(&counter[i]);

	if (umad_init() != 0) {
		acm_log(0, "ERROR - fail to initialize umad\n");
		return -1;
	}

	if (acm_open_providers()) {
		acm_log(0, "ERROR - unable to open any providers\n");
		return -1;
	}

	if (acm_open_devices()) {
		acm_log(0, "ERROR - unable to open any devices\n");
		return -1;
	}

	acm_log(1, "creating IP Netlink socket\n");
	acm_ipnl_create();

	acm_log(1, "starting sa response receiving thread\n");
	if (pthread_create(&sa.thread_id, NULL, acm_sa_handler, NULL)) {
		acm_log(0, "Error: failed to create sa resp rcving thread");
		return -1;
	}

	if (acm_init_if_iter_sys()) {
		acm_log(0, "Error: unable to initialize acm_if_iter_sys");
		return -1;
	}

	acm_activate_devices();
	acm_log(1, "starting server\n");
	acm_server(systemd);

	acm_log(0, "shutting down\n");
	if (client_array[NL_CLIENT_INDEX].sock != -1)
		close(client_array[NL_CLIENT_INDEX].sock);
	acm_close_providers();
	acm_stop_sa_handler();
	umad_done();
	acm_fini_if_iter_sys();
	fclose(flog);
	return 0;
}
