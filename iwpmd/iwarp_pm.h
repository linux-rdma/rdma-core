/*
 * Copyright (c) 2013 Intel Corporation.  All rights reserved.
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
 */

#ifndef IWARP_PM_H
#define IWARP_PM_H

#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <netlink/attr.h>
#include <signal.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <syslog.h>
#include <netlink/msg.h>
#include <ccan/list.h>
#include <rdma/rdma_netlink.h>
#include <stdatomic.h>

#define IWARP_PM_PORT          3935
#define IWARP_PM_VER_SHIFT     6
#define IWARP_PM_VER_MASK      0xc0
#define IWARP_PM_MT_SHIFT      4
#define IWARP_PM_MT_MASK       0x30
#define IWARP_PM_IPVER_SHIFT   0
#define IWARP_PM_IPVER_MASK    0x0F
#define IWARP_PM_MESSAGE_SIZE  48 /* bytes */
#define IWARP_PM_ASSOC_OFFSET  0x10 /* different assochandles for passive/active side map requests */
#define IWARP_PM_IPV4_ADDR     4

#define IWARP_PM_MT_REQ 0
#define IWARP_PM_MT_ACC 1
#define IWARP_PM_MT_ACK 2
#define IWARP_PM_MT_REJ 3

#define IWARP_PM_REQ_QUERY  1
#define IWARP_PM_REQ_ACCEPT 2
#define IWARP_PM_REQ_ACK    4

#define IWARP_PM_RECV_PAYLOAD 4096
#define IWARP_PM_MAX_CLIENTS  64
#define IWPM_MAP_REQ_TIMEOUT  10 /* sec */
#define IWPM_SEND_MSG_RETRIES 3

#define IWPM_ULIB_NAME  "iWarpPortMapperUser"
#define IWPM_ULIBNAME_SIZE 32
#define IWPM_DEVNAME_SIZE  32
#define IWPM_IFNAME_SIZE   16
#define IWPM_IPADDR_SIZE   16

#define IWPM_PARAM_NUM 1
#define IWPM_PARAM_NAME_LEN 64

#define IWARP_PM_NETLINK_DBG  0x01
#define IWARP_PM_WIRE_DBG     0x02
#define IWARP_PM_RETRY_DBG    0x04
#define IWARP_PM_ALL_DBG      0x07
#define IWARP_PM_DEBUG        0x08

#define iwpm_debug(dbg_level, str, args...) \
	do { if (dbg_level &  IWARP_PM_DEBUG) { \
 		syslog(LOG_WARNING, str, ##args); } \
	} while (0)

/* Port Mapper errors */
enum {
        IWPM_INVALID_NLMSG_ERR = 10,
        IWPM_CREATE_MAPPING_ERR,
        IWPM_DUPLICATE_MAPPING_ERR,
        IWPM_UNKNOWN_MAPPING_ERR,
        IWPM_CLIENT_DEV_INFO_ERR,
        IWPM_USER_LIB_INFO_ERR,
        IWPM_REMOTE_QUERY_REJECT,
        IWPM_VERSION_MISMATCH_ERR,
};

/* iwpm param indexes */
enum {
	NL_SOCK_RBUF_SIZE
};

typedef struct iwpm_client {
	char	ifname[IWPM_IFNAME_SIZE];       /* netdev interface name */
	char	ibdevname[IWPM_DEVNAME_SIZE];   /* OFED device name */
	char	ulibname[IWPM_ULIBNAME_SIZE];	/* library name of the userpace PM agent provider */
	__u32	nl_seq;
	char	valid;
} iwpm_client;

typedef union sockaddr_union {
	struct sockaddr_storage s_sockaddr;
	struct sockaddr sock_addr;
	struct sockaddr_in v4_sockaddr;
	struct sockaddr_in6 v6_sockaddr;
	struct sockaddr_nl nl_sockaddr;
} sockaddr_union;

typedef struct iwpm_mapped_port {
	struct list_node	    entry;
	int			    owner_client;
	int			    sd;
	struct sockaddr_storage	    local_addr;
	struct sockaddr_storage	    mapped_addr;
	int			    wcard;
	_Atomic(int)		    ref_cnt; /* the number of owners */
} iwpm_mapped_port;

typedef struct iwpm_wire_msg {
	__u8	magic;
	__u8	pmtime;
	__be16	reserved;
	__be16	apport;
	__be16	cpport;
	__be64	assochandle;
	/* big endian IP addresses and ports */
	__u8	cpipaddr[IWPM_IPADDR_SIZE];
	__u8	apipaddr[IWPM_IPADDR_SIZE];
	__u8	mapped_cpipaddr[IWPM_IPADDR_SIZE];
} iwpm_wire_msg;

typedef struct iwpm_send_msg {
	int			pm_sock;
	struct sockaddr_storage dest_addr;
	iwpm_wire_msg    	data;
	int 			length;
} iwpm_send_msg;

typedef struct iwpm_mapping_request {
	struct list_node		entry;
	struct sockaddr_storage		src_addr;
	struct sockaddr_storage		remote_addr;
	__u16 				nlmsg_type;     /* Message content */
        __u32                           nlmsg_seq;      /* Sequence number */
	__u32           		nlmsg_pid;
	__u64				assochandle;
	iwpm_send_msg *			send_msg;
	int				timeout;
	int				complete;
	int				msg_type;
} iwpm_mapping_request;

typedef struct iwpm_pending_msg {
	struct list_node	entry;
	iwpm_send_msg           send_msg;
} iwpm_pending_msg;

typedef struct iwpm_msg_parms {
	__u32		ip_ver;
	__u16		address_family;
	char		apipaddr[IWPM_IPADDR_SIZE];
	__be16		apport;
	char		cpipaddr[IWPM_IPADDR_SIZE];
	__be16		cpport;
	char		mapped_cpipaddr[IWPM_IPADDR_SIZE];
	__be16		mapped_cpport;
	unsigned char	ver;
	unsigned char	mt;
	unsigned char	pmtime;
	__u64		assochandle;
	int             msize;
} iwpm_msg_parms;

/* iwarp_pm_common.c */

void parse_iwpm_config(FILE *);

int create_iwpm_socket_v4(__u16);

int create_iwpm_socket_v6(__u16);

int create_netlink_socket(void);

void destroy_iwpm_socket(int);

int parse_iwpm_nlmsg(struct nlmsghdr *, int, struct nla_policy *, struct nlattr * [], const char *);

int parse_iwpm_msg(iwpm_wire_msg *, iwpm_msg_parms *);

void form_iwpm_request(iwpm_wire_msg *, iwpm_msg_parms *);

void form_iwpm_accept(iwpm_wire_msg *, iwpm_msg_parms *);

void form_iwpm_ack(iwpm_wire_msg *, iwpm_msg_parms *);

void form_iwpm_reject(iwpm_wire_msg *, iwpm_msg_parms *);

int send_iwpm_nlmsg(int, struct nl_msg *, int);

struct nl_msg *create_iwpm_nlmsg(__u16, int);

void print_iwpm_sockaddr(struct sockaddr_storage *, const char *, __u32);

__be16 get_sockaddr_port(struct sockaddr_storage *sockaddr);

void copy_iwpm_sockaddr(__u16, struct sockaddr_storage *, struct sockaddr_storage *,
				char *, char *, __be16 *);

int is_wcard_ipaddr(struct sockaddr_storage *);

/* iwarp_pm_helper.c */

iwpm_mapped_port *create_iwpm_mapped_port(struct sockaddr_storage *, int, __u32 flags);

iwpm_mapped_port *reopen_iwpm_mapped_port(struct sockaddr_storage *, struct sockaddr_storage *, int,
				__u32 flags);

void add_iwpm_mapped_port(iwpm_mapped_port *);

iwpm_mapped_port *find_iwpm_mapping(struct sockaddr_storage *, int);

iwpm_mapped_port *find_iwpm_same_mapping(struct sockaddr_storage *, int);

void remove_iwpm_mapped_port(iwpm_mapped_port *);

void print_iwpm_mapped_ports(void);

void free_iwpm_port(iwpm_mapped_port *);

iwpm_mapping_request *create_iwpm_map_request(struct nlmsghdr *, struct sockaddr_storage *,
					struct sockaddr_storage *, __u64, int, iwpm_send_msg *);

void add_iwpm_map_request(iwpm_mapping_request *);

int update_iwpm_map_request(__u64, struct sockaddr_storage *, int, iwpm_mapping_request *, int);

void remove_iwpm_map_request(iwpm_mapping_request *);

void form_iwpm_send_msg(int, struct sockaddr_storage *, int, iwpm_send_msg *);

int send_iwpm_msg(void (*form_msg_type)(iwpm_wire_msg *, iwpm_msg_parms *),
			iwpm_msg_parms *, struct sockaddr_storage *, int);

int add_iwpm_pending_msg(iwpm_send_msg *);

int check_same_sockaddr(struct sockaddr_storage *, struct sockaddr_storage *);

void free_iwpm_mapped_ports(void);

extern struct list_head pending_messages;
extern struct list_head mapping_reqs;

extern iwpm_client client_list[IWARP_PM_MAX_CLIENTS];

extern pthread_cond_t cond_req_complete;
extern pthread_mutex_t map_req_mutex;
extern int wake;
extern pthread_cond_t cond_pending_msg;
extern pthread_mutex_t pending_msg_mutex;

#endif
