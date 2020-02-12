/*
 * Copyright (c) 2013-2015 Intel Corporation.  All rights reserved.
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

#include "iwarp_pm.h"
#include <endian.h>

/* iwpm config params */
static const char * iwpm_param_names[IWPM_PARAM_NUM] =
	{ "nl_sock_rbuf_size" };
static int iwpm_param_vals[IWPM_PARAM_NUM] =
	{ 0 };

/**
 * get_iwpm_param()
 */
static int get_iwpm_param(char *param_name, int val)
{
	int i, ret;
	for (i = 0; i < IWPM_PARAM_NUM; i++) {
		ret = strcmp(param_name, iwpm_param_names[i]);
		if (!ret && val > 0) {
			syslog(LOG_WARNING, "get_iwpm_param: Got param (name = %s val = %d)\n", param_name, val);
			iwpm_param_vals[i] = val;
			return ret;
		}
	}
	return ret;
}

/**
 * parse_iwpm_config()
 */
void parse_iwpm_config(FILE *fp)
{
	char line_buf[128];
	char param_name[IWPM_PARAM_NAME_LEN];
	int n, val, ret;
	char *str;

	str = fgets(line_buf, 128, fp);
	while (str) {
		if (line_buf[0] == '#' || line_buf[0] == '\n')
			goto parse_next_line;
		n = sscanf(line_buf, "%64[^= ] %*[=]%d", param_name, &val);
		if (n != 2) {
			syslog(LOG_WARNING, "parse_iwpm_config: Couldn't parse a line (n = %d, name = %s, val = %d\n", n, param_name, val);
			goto parse_next_line;
		}
		ret = get_iwpm_param(param_name, val);
		if (ret)
			syslog(LOG_WARNING, "parse_iwpm_config: Couldn't find param (ret = %d)\n", ret);
parse_next_line:
		str = fgets(line_buf, 128, fp);
	}
}

/**
 * create_iwpm_socket_v4 - Create an ipv4 socket for the iwarp port mapper
 * @bind_port: UDP port to bind the socket
 *
 * Return a handle of ipv4 socket
 */
int create_iwpm_socket_v4(__u16 bind_port)
{
	sockaddr_union bind_addr;
	struct sockaddr_in *bind_in4;
	int pm_sock;
	socklen_t sockname_len;
	char ip_address_text[INET6_ADDRSTRLEN];

	/* create a socket */
	pm_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (pm_sock < 0) {
		syslog(LOG_WARNING, "create_iwpm_socket_v4: Unable to create socket. %s.\n",
				strerror(errno));
		pm_sock = -errno;
		goto create_socket_v4_exit;
	}
	/* bind the socket to the given port */
	memset(&bind_addr, 0, sizeof(bind_addr));
	bind_in4 = &bind_addr.v4_sockaddr;
	bind_in4->sin_family = AF_INET;
	bind_in4->sin_addr.s_addr = htobe32(INADDR_ANY);
	bind_in4->sin_port = htobe16(bind_port);

	if (bind(pm_sock, &bind_addr.sock_addr, sizeof(struct sockaddr_in))) {
		syslog(LOG_WARNING, "create_iwpm_socket_v4: Unable to bind socket (port = %u). %s.\n",
				bind_port, strerror(errno));
		close(pm_sock);
		pm_sock = -errno;
		goto create_socket_v4_exit;
	}

	/* get the socket name (local port number) */
	sockname_len = sizeof(struct sockaddr_in);
	if (getsockname(pm_sock, &bind_addr.sock_addr, &sockname_len)) {
		syslog(LOG_WARNING, "create_iwpm_socket_v4: Unable to get socket name. %s.\n",
				strerror(errno));
		close(pm_sock);
		pm_sock = -errno;
		goto create_socket_v4_exit;
	}

	iwpm_debug(IWARP_PM_WIRE_DBG, "create_iwpm_socket_v4: Socket IP address:port %s:%u\n",
		inet_ntop(bind_in4->sin_family, &bind_in4->sin_addr.s_addr, ip_address_text,
			INET6_ADDRSTRLEN), be16toh(bind_in4->sin_port));
create_socket_v4_exit:
	return pm_sock;
}

/**
 * create_iwpm_socket_v6 - Create an ipv6 socket for the iwarp port mapper
 * @bind_port: UDP port to bind the socket
 *
 * Return a handle of ipv6 socket
 */
int create_iwpm_socket_v6(__u16 bind_port)
{
	sockaddr_union bind_addr;
	struct sockaddr_in6 *bind_in6;
	int pm_sock, ret_value, ipv6_only;
	socklen_t sockname_len;
	char ip_address_text[INET6_ADDRSTRLEN];

	/* create a socket */
	pm_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (pm_sock < 0) {
		syslog(LOG_WARNING, "create_iwpm_socket_v6: Unable to create socket. %s.\n",
				strerror(errno));
		pm_sock = -errno;
		goto create_socket_v6_exit;
	}

	ipv6_only = 1;
	ret_value = setsockopt(pm_sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only, sizeof(ipv6_only));
	if (ret_value < 0) {
		syslog(LOG_WARNING, "create_iwpm_socket_v6: Unable to set sock options. %s.\n",
				strerror(errno));
		close(pm_sock);
		pm_sock = -errno;
		goto create_socket_v6_exit;
	}

	/* bind the socket to the given port */
	memset(&bind_addr, 0, sizeof(bind_addr));
	bind_in6 = &bind_addr.v6_sockaddr;
	bind_in6->sin6_family = AF_INET6;
	bind_in6->sin6_addr = in6addr_any;
	bind_in6->sin6_port = htobe16(bind_port);

	if (bind(pm_sock, &bind_addr.sock_addr, sizeof(struct sockaddr_in6))) {
		syslog(LOG_WARNING, "create_iwpm_socket_v6: Unable to bind socket (port = %u). %s.\n",
				bind_port, strerror(errno));
		close(pm_sock);
		pm_sock = -errno;
		goto create_socket_v6_exit;
	}

	/* get the socket name (local port number) */
	sockname_len = sizeof(struct sockaddr_in6);
	if (getsockname(pm_sock, &bind_addr.sock_addr, &sockname_len)) {
		syslog(LOG_WARNING, "create_iwpm_socket_v6: Unable to get socket name. %s.\n",
				strerror(errno));
		close(pm_sock);
		pm_sock = -errno;
		goto create_socket_v6_exit;
	}

	iwpm_debug(IWARP_PM_WIRE_DBG, "create_iwpm_socket_v6: Socket IP address:port %s:%04X\n",
		inet_ntop(bind_in6->sin6_family, &bind_in6->sin6_addr, ip_address_text,
			INET6_ADDRSTRLEN), be16toh(bind_in6->sin6_port));
create_socket_v6_exit:
	return pm_sock;
}

/**
 * create_netlink_socket - Create netlink socket for the iwarp port mapper
 */
int create_netlink_socket(void)
{
	sockaddr_union bind_addr;
	struct sockaddr_nl *bind_nl;
	int nl_sock;
	__u32 rbuf_size, opt_len;

	/* create a socket */
	nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_RDMA);
	if (nl_sock < 0) {
		syslog(LOG_WARNING, "create_netlink_socket: Unable to create socket. %s.\n",
				strerror(errno));
		nl_sock = -errno;
		goto create_nl_socket_exit;
	}

	/* bind the socket */
	memset(&bind_addr, 0, sizeof(bind_addr));
	bind_nl = &bind_addr.nl_sockaddr;
	bind_nl->nl_family = AF_NETLINK;
	bind_nl->nl_pid = getpid();
	bind_nl->nl_groups = 3; /* != 0 support multicast */

	if (bind(nl_sock, &bind_addr.sock_addr, sizeof(struct sockaddr_nl))) {
		syslog(LOG_WARNING, "create_netlink_socket: Unable to bind socket. %s.\n",
				strerror(errno));
		close(nl_sock);
		nl_sock = -errno;
		goto create_nl_socket_exit;
	}
	if (iwpm_param_vals[NL_SOCK_RBUF_SIZE] > 0) {
		rbuf_size = iwpm_param_vals[NL_SOCK_RBUF_SIZE];

		if (setsockopt(nl_sock, SOL_SOCKET, SO_RCVBUFFORCE, &rbuf_size, sizeof rbuf_size)) {
			syslog(LOG_WARNING, "create_netlink_socket: Unable to set sock option "
				"(rbuf_size = %u). %s.\n", rbuf_size, strerror(errno));
			if (setsockopt(nl_sock, SOL_SOCKET, SO_RCVBUF,
					&rbuf_size, sizeof rbuf_size)) {
				syslog(LOG_WARNING, "create_netlink_socket: "
					"Unable to set sock option %s. Closing socket\n", strerror(errno));
				close(nl_sock);
				nl_sock = -errno;
				goto create_nl_socket_exit;
               		}
		}
	}
	getsockopt(nl_sock, SOL_SOCKET, SO_RCVBUF, &rbuf_size, &opt_len);
	iwpm_debug(IWARP_PM_NETLINK_DBG, "create_netlink_socket: Setting a sock option (rbuf_size = %u).\n", rbuf_size);

create_nl_socket_exit:
	return nl_sock;
}

/**
 * destroy_iwpm_socket - Close socket
 */
void destroy_iwpm_socket(int pm_sock)
{
	if (pm_sock > 0)
		close(pm_sock);
	pm_sock = -1;
}

/**
 * check_iwpm_nlattr - Check for NULL netlink attribute
 */
static int check_iwpm_nlattr(struct nlattr *nltb[], int nla_count)
{
	int i, ret = 0;
        for (i = 1; i < nla_count; i++) {
		if (!nltb[i]) {
			iwpm_debug(IWARP_PM_NETLINK_DBG, "check_iwpm_nlattr: NULL (attr idx = %d)\n", i);
			ret = -EINVAL;
		}
	}
	return ret;
}

/**
 * parse_iwpm_nlmsg - Parse a netlink message
 * @req_nlh: netlink header of the received message to parse
 * @policy_max: the number of attributes in the policy
 * @nlmsg_policy: the attribute policy
 * @nltb: array to store the parsed attributes
 * @msg_type: netlink message type (dbg purpose)
 */
int parse_iwpm_nlmsg(struct nlmsghdr *req_nlh, int policy_max,
			struct nla_policy *nlmsg_policy, struct nlattr *nltb [],
			const char *msg_type)
{
	const char *str_err;
	int ret;

	if ((ret = nlmsg_validate(req_nlh, 0, policy_max-1, nlmsg_policy))) {
		str_err = "nlmsg_validate error";
		goto parse_nlmsg_error;
	}
	if ((ret = nlmsg_parse(req_nlh, 0, nltb, policy_max-1, nlmsg_policy))) {
		str_err = "nlmsg_parse error";
		goto parse_nlmsg_error;
	}
	if (check_iwpm_nlattr(nltb, policy_max)) {
		ret = -EINVAL;
		str_err = "NULL nlmsg attribute";
		goto parse_nlmsg_error;
	}
	return 0;
parse_nlmsg_error:
	syslog(LOG_WARNING, "parse_iwpm_nlmsg: msg type = %s (%s ret = %d)\n",
			msg_type, str_err, ret);
	return ret;
}

/**
 * send_iwpm_nlmsg - Send a netlink message
 * @nl_sock:  netlink socket to use for sending the message
 * @nlmsg:    netlink message to send
 * @dest_pid: pid of the destination of the nlmsg
 */
int send_iwpm_nlmsg(int nl_sock, struct nl_msg *nlmsg, int dest_pid)
{
	struct sockaddr_nl dest_addr;
	struct nlmsghdr *nlh = nlmsg_hdr(nlmsg);
	__u32 nlmsg_len = nlh->nlmsg_len;
	int len;

	/* fill in the netlink address of the client */
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_groups = 0;
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = dest_pid;

	/* send response to the client */
	len = sendto(nl_sock, (char *)nlh, nlmsg_len, 0,
		     	(struct sockaddr *)&dest_addr, sizeof(dest_addr));
	if (len != nlmsg_len)
		return -errno;
	return 0;
}

/**
 * create_iwpm_nlmsg - Create a netlink message
 * @nlmsg_type: type of the netlink message
 * @client:     the port mapper client to receive the message
 */
struct nl_msg *create_iwpm_nlmsg(__u16 nlmsg_type, int client_idx)
{
	struct nl_msg *nlmsg;
	struct nlmsghdr *nlh;
	__u32 seq = 0;

	nlmsg = nlmsg_alloc();
	if (!nlmsg)
		return NULL;
	if (client_idx > 0)
		seq = client_list[client_idx].nl_seq++;

	nlh = nlmsg_put(nlmsg, getpid(), seq, nlmsg_type, 0, NLM_F_REQUEST);
	if (!nlh) {
		nlmsg_free(nlmsg);
		return NULL;
	}
	return nlmsg;
}

/**
 * parse_iwpm_msg - Parse iwarp port mapper wire message
 * @pm_msg: iwpm message to be parsed
 * @msg_parms: contains the parameters of the iwpm message after parsing
 */
int parse_iwpm_msg(iwpm_wire_msg *pm_msg, iwpm_msg_parms *msg_parms)
{
	int ret_value = 0;

	msg_parms->pmtime = pm_msg->pmtime;
	msg_parms->assochandle = be64toh(pm_msg->assochandle);
	msg_parms->ip_ver = (pm_msg->magic & IWARP_PM_IPVER_MASK) >> IWARP_PM_IPVER_SHIFT;
	switch (msg_parms->ip_ver) {
	case 4:
		msg_parms->address_family = AF_INET;
		break;
	case 6:
		msg_parms->address_family = AF_INET6;
		break;
	default:
		syslog(LOG_WARNING, "parse_iwpm_msg: Invalid IP version = %d.\n",
			msg_parms->ip_ver);
		return -EINVAL;
	}
	/* port mapper protocol version */
	msg_parms->ver = (pm_msg->magic & IWARP_PM_VER_MASK) >> IWARP_PM_VER_SHIFT;
	/* message type */
	msg_parms->mt = (pm_msg->magic & IWARP_PM_MT_MASK) >> IWARP_PM_MT_SHIFT;
	msg_parms->apport = pm_msg->apport; /* accepting peer port */
	msg_parms->cpport = pm_msg->cpport; /* connecting peer port */
	/* copy accepting peer IP address */
	memcpy(&msg_parms->apipaddr, &pm_msg->apipaddr, IWPM_IPADDR_SIZE);
	/* copy connecting peer IP address */
	memcpy(&msg_parms->cpipaddr, &pm_msg->cpipaddr, IWPM_IPADDR_SIZE);
	if (msg_parms->mt == IWARP_PM_MT_REQ) {
		msg_parms->mapped_cpport = pm_msg->reserved;
		memcpy(&msg_parms->mapped_cpipaddr, &pm_msg->mapped_cpipaddr, IWPM_IPADDR_SIZE);
	}
	return ret_value;
}

/**
 * form_iwpm_msg - Form iwarp port mapper wire message
 * @pm_msg: iwpm message to be formed
 * @msg_parms: the parameters to be packed in a iwpm message
 */
static void form_iwpm_msg(iwpm_wire_msg *pm_msg, iwpm_msg_parms *msg_parms)
{
	memset(pm_msg, 0, sizeof(struct iwpm_wire_msg));
	pm_msg->pmtime = msg_parms->pmtime;
	pm_msg->assochandle = htobe64(msg_parms->assochandle);
	/* record IP version, port mapper version, message type */
	pm_msg->magic = (msg_parms->ip_ver << IWARP_PM_IPVER_SHIFT) & IWARP_PM_IPVER_MASK;
	pm_msg->magic |= (msg_parms->ver << IWARP_PM_VER_SHIFT) & IWARP_PM_VER_MASK;
	pm_msg->magic |= (msg_parms->mt << IWARP_PM_MT_SHIFT) & IWARP_PM_MT_MASK;

	pm_msg->apport = msg_parms->apport;
	pm_msg->cpport = msg_parms->cpport;
	memcpy(&pm_msg->apipaddr, &msg_parms->apipaddr, IWPM_IPADDR_SIZE);
	memcpy(&pm_msg->cpipaddr, &msg_parms->cpipaddr, IWPM_IPADDR_SIZE);
	if (msg_parms->mt == IWARP_PM_MT_REQ) {
		pm_msg->reserved = msg_parms->mapped_cpport;
		memcpy(&pm_msg->mapped_cpipaddr, &msg_parms->mapped_cpipaddr, IWPM_IPADDR_SIZE);
	}
}

/**
 * form_iwpm_request - Form iwarp port mapper request message
 * @pm_msg: iwpm message to be formed
 * @msg_parms: the parameters to be packed in a iwpm message
 **/
void form_iwpm_request(struct iwpm_wire_msg *pm_msg,
		      struct iwpm_msg_parms  *msg_parms)
{
	msg_parms->mt = IWARP_PM_MT_REQ;
	msg_parms->msize = IWARP_PM_MESSAGE_SIZE + IWPM_IPADDR_SIZE;
	form_iwpm_msg(pm_msg, msg_parms);
}

/**
 * form_iwpm_accept - Form iwarp port mapper accept message
 * @pm_msg: iwpm message to be formed
 * @msg_parms: the parameters to be packed in a iwpm message
 **/
void form_iwpm_accept(struct iwpm_wire_msg *pm_msg,
		     struct iwpm_msg_parms  *msg_parms)
{
	msg_parms->mt = IWARP_PM_MT_ACC;
	msg_parms->msize = IWARP_PM_MESSAGE_SIZE;
	form_iwpm_msg(pm_msg, msg_parms);
}

/**
 * form_iwpm_ack - Form iwarp port mapper ack message
 * @pm_msg: iwpm message to be formed
 * @msg_parms: the parameters to be packed in a iwpm message
 **/
void form_iwpm_ack(struct iwpm_wire_msg *pm_msg,
		  struct iwpm_msg_parms  *msg_parms)
{
	msg_parms->mt = IWARP_PM_MT_ACK;
	msg_parms->msize = IWARP_PM_MESSAGE_SIZE;
	form_iwpm_msg(pm_msg, msg_parms);
}

/**
 * form_iwpm_reject - Form iwarp port mapper reject message
 * @pm_msg: iwpm message to be formed
 * @msg_parms: the parameters to be packed in a iwpm message
 */
void form_iwpm_reject(struct iwpm_wire_msg *pm_msg,
		     struct iwpm_msg_parms  *msg_parms)
{
	msg_parms->mt = IWARP_PM_MT_REJ;
	msg_parms->msize = IWARP_PM_MESSAGE_SIZE;
	form_iwpm_msg(pm_msg, msg_parms);
}

/**
 * get_sockaddr_port - Report the tcp port number, contained in the sockaddr
 * @sockaddr: sockaddr storage to get the tcp port from
 */
__be16 get_sockaddr_port(struct sockaddr_storage *sockaddr)
{
	struct sockaddr_in *sockaddr_v4;
	struct sockaddr_in6 *sockaddr_v6;
	__be16 port = 0;

	switch (sockaddr->ss_family) {
	case AF_INET:
		sockaddr_v4 = (struct sockaddr_in *)sockaddr;
		port = sockaddr_v4->sin_port;
		break;
	case AF_INET6:
		sockaddr_v6 = (struct sockaddr_in6 *)sockaddr;
		port = sockaddr_v6->sin6_port;
		break;
	default:
		syslog(LOG_WARNING, "get_sockaddr_port: Invalid sockaddr family.\n");
		break;
	}
	return port;
}

/**
 * copy_iwpm_sockaddr - Copy (IP address and Port) from src to dst
 * @address_family: Internet address family
 * @src_sockaddr: socket address to copy (if NULL, use src_addr)
 * @dst_sockaddr: socket address to update (if NULL, use dst_addr)
 * @src_addr: IP address to copy (if NULL, use src_sockaddr)
 * @dst_addr: IP address to update (if NULL, use dst_sockaddr)
 * @src_port: port to copy in dst_sockaddr, if src_sockaddr = NULL
 *            port to update, if src_sockaddr != NULL and dst_sockaddr = NULL
 */
void copy_iwpm_sockaddr(__u16 addr_family, struct sockaddr_storage *src_sockaddr,
		      struct sockaddr_storage *dst_sockaddr,
		      char *src_addr, char *dst_addr, __be16 *src_port)
{
	switch (addr_family) {
	case AF_INET: {
		const struct in_addr *src = (void *)src_addr;
		struct in_addr *dst = (void *)dst_addr;
		const struct sockaddr_in *src_sockaddr_in;
		struct sockaddr_in *dst_sockaddr_in;

		if (src_sockaddr) {
			src_sockaddr_in = (const void *)src_sockaddr;
			src = &src_sockaddr_in->sin_addr;
			*src_port = src_sockaddr_in->sin_port;
		}
		if (dst_sockaddr) {
			dst_sockaddr_in = (void *)dst_sockaddr;
			dst = &dst_sockaddr_in->sin_addr;
			dst_sockaddr_in->sin_port = *src_port;
			dst_sockaddr_in->sin_family = AF_INET;
		}
		*dst = *src;
		break;
	}
	case AF_INET6: {
		const struct in6_addr *src = (void *)src_addr;
		struct in6_addr *dst = (void *)dst_addr;
		const struct sockaddr_in6 *src_sockaddr_in6;
		struct sockaddr_in6 *dst_sockaddr_in6;

		if (src_sockaddr) {
			src_sockaddr_in6 = (const void *)src_sockaddr;
			src = &src_sockaddr_in6->sin6_addr;
			*src_port = src_sockaddr_in6->sin6_port;
		}
		if (dst_sockaddr) {
			dst_sockaddr_in6 = (void *)dst_sockaddr;
			dst = &dst_sockaddr_in6->sin6_addr;
			dst_sockaddr_in6->sin6_port = *src_port;
			dst_sockaddr_in6->sin6_family = AF_INET6;
		}
		*dst = *src;
		break;
	}
	}
}

/**
 * is_wcard_ipaddr - Check if the search_addr has a wild card ip address
 */
int is_wcard_ipaddr(struct sockaddr_storage *search_addr)
{
	int ret = 0;

	switch (search_addr->ss_family) {
	case AF_INET: {
		struct sockaddr_in wcard_addr;
		struct sockaddr_in *in4addr = (struct sockaddr_in *)search_addr;
		inet_pton(AF_INET, "0.0.0.0", &wcard_addr.sin_addr);

		if (in4addr->sin_addr.s_addr == wcard_addr.sin_addr.s_addr)
			ret = 1;
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 wcard_addr;
		struct sockaddr_in6 *in6addr = (struct sockaddr_in6 *)search_addr;
		inet_pton(AF_INET6, "::", &wcard_addr.sin6_addr);

		if (!memcmp(in6addr->sin6_addr.s6_addr,
			wcard_addr.sin6_addr.s6_addr, IWPM_IPADDR_SIZE))
			ret = 1;
		break;
	}
	default:
		syslog(LOG_WARNING, "check_same_sockaddr: Invalid addr family 0x%02X\n",
			search_addr->ss_family);
		break;
	}
	return ret;
}

/**
 * print_iwpm_sockaddr - Print socket address (IP address and Port)
 * @sockaddr: socket address to print
 * @msg: message to print
 */
void print_iwpm_sockaddr(struct sockaddr_storage *sockaddr, const char *msg,
			 __u32 dbg_flag)
{
	struct sockaddr_in6 *sockaddr_v6;
	struct sockaddr_in *sockaddr_v4;
	char ip_address_text[INET6_ADDRSTRLEN];

	switch (sockaddr->ss_family) {
	case AF_INET:
		sockaddr_v4 = (struct sockaddr_in *)sockaddr;
		iwpm_debug(dbg_flag, "%s IPV4 %s:%u(0x%04X)\n", msg,
			inet_ntop(AF_INET, &sockaddr_v4->sin_addr, ip_address_text, INET6_ADDRSTRLEN),
			be16toh(sockaddr_v4->sin_port), be16toh(sockaddr_v4->sin_port));
		break;
	case AF_INET6:
		sockaddr_v6 = (struct sockaddr_in6 *)sockaddr;
		iwpm_debug(dbg_flag, "%s IPV6 %s:%u(0x%04X)\n", msg,
			inet_ntop(AF_INET6, &sockaddr_v6->sin6_addr, ip_address_text, INET6_ADDRSTRLEN),
			be16toh(sockaddr_v6->sin6_port), be16toh(sockaddr_v6->sin6_port));
		break;
	default:
		break;
	}
}
