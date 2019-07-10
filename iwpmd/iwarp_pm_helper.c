/*
 * Copyright (c) 2013-2016 Intel Corporation.  All rights reserved.
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

static LIST_HEAD(mapped_ports);		/* list of mapped ports */

/**
 * create_iwpm_map_request - Create a new map request tracking object
 * @req_nlh: netlink header of the received client message
 * @src_addr: the local address of the client initiating the request
 * @remote_addr: the destination (the port mapper peer) address
 * @assochandle: unique number per host
 * @msg_type: message types are request, accept and ack
 * @send_msg: message to retransmit to the remote port mapper peer,
 * 	      if the request isn't serviced on time.
 */
iwpm_mapping_request *create_iwpm_map_request(struct nlmsghdr *req_nlh,
				struct sockaddr_storage *src_addr, struct sockaddr_storage *remote_addr,
				 __u64 assochandle, int msg_type, iwpm_send_msg *send_msg)
{
	iwpm_mapping_request *iwpm_map_req;
	__u32 type = 0, seq = 0, pid = 0;

	/* create iwpm conversation tracking object */
	iwpm_map_req = malloc(sizeof(iwpm_mapping_request));
	if (!iwpm_map_req)
		return NULL;
	if (req_nlh) {
		type = req_nlh->nlmsg_type;
		seq = req_nlh->nlmsg_seq;
		pid = req_nlh->nlmsg_pid;
	}
	memset(iwpm_map_req, 0, sizeof(iwpm_mapping_request));
	iwpm_map_req->timeout = IWPM_MAP_REQ_TIMEOUT;
	iwpm_map_req->complete = 0;
	iwpm_map_req->msg_type = msg_type;
	iwpm_map_req->send_msg = send_msg;

	iwpm_map_req->nlmsg_type = type;
	iwpm_map_req->nlmsg_seq = seq;
	iwpm_map_req->nlmsg_pid = pid;
	/* assochandle helps match iwpm request sent to remote peer with future iwpm accept/reject */
	iwpm_map_req->assochandle = assochandle;
	if (!assochandle)
		iwpm_map_req->assochandle = (uintptr_t)iwpm_map_req;

	memcpy(&iwpm_map_req->src_addr, src_addr, sizeof(struct sockaddr_storage));
	/* keep record of remote IP address and port */
	memcpy(&iwpm_map_req->remote_addr, remote_addr, sizeof(struct sockaddr_storage));
	return iwpm_map_req;
}

/**
 * add_iwpm_map_request - Add a map request tracking object to a global list
 * @iwpm_map_req: mapping request to be saved
 */
void add_iwpm_map_request(iwpm_mapping_request *iwpm_map_req)
{
	pthread_mutex_lock(&map_req_mutex);
	list_add(&mapping_reqs, &iwpm_map_req->entry);
	/* if not wake, signal the thread that a new request has been posted */
	if (!wake)
		pthread_cond_signal(&cond_req_complete);
	pthread_mutex_unlock(&map_req_mutex);
}

/**
 * remove_iwpm_map_request - Free a map request tracking object
 * @iwpm_map_req: mapping request to be removed
 *
 * Routine must be called within lock context
 */
void remove_iwpm_map_request(iwpm_mapping_request *iwpm_map_req)
{
	if (!iwpm_map_req->complete && iwpm_map_req->msg_type != IWARP_PM_REQ_ACK) {
		iwpm_debug(IWARP_PM_RETRY_DBG, "remove_iwpm_map_request: "
			"Timeout for request (type = %u pid = %d)\n",
			iwpm_map_req->msg_type, iwpm_map_req->nlmsg_pid);
	}
	list_del(&iwpm_map_req->entry);
	if (iwpm_map_req->send_msg)
		free(iwpm_map_req->send_msg);
	free(iwpm_map_req);
}

/**
 * update_iwpm_map_request - Find and update a map request tracking object
 * @assochandle: the request assochandle to search for
 * @src_addr: the request src address to search for
 * @msg_type: the request type to search for
 * @iwpm_copy_req: to store a copy of the found map request object
 * @update: if set update the found request, otherwise don't update
 */
int update_iwpm_map_request(__u64 assochandle, struct sockaddr_storage *src_addr,
				int msg_type, iwpm_mapping_request *iwpm_copy_req, int update)
{
	iwpm_mapping_request *iwpm_map_req;
	int ret = -EINVAL;

	pthread_mutex_lock(&map_req_mutex);
	/* look for a matching entry in the list */
	list_for_each(&mapping_reqs, iwpm_map_req, entry) {
		if (assochandle == iwpm_map_req->assochandle &&
				(msg_type & iwpm_map_req->msg_type) &&
				check_same_sockaddr(src_addr, &iwpm_map_req->src_addr)) {
			ret = 0;
			/* get a copy of the request (a different thread is in charge of freeing it) */
			memcpy(iwpm_copy_req, iwpm_map_req, sizeof(iwpm_mapping_request));
			if (!update)
				goto update_map_request_exit;
			if (iwpm_map_req->complete)
				goto update_map_request_exit;

			/* update the request object */
			if (iwpm_map_req->msg_type == IWARP_PM_REQ_ACK) {
				iwpm_map_req->timeout = IWPM_MAP_REQ_TIMEOUT;
				iwpm_map_req->complete = 0;
			} else {
				/* already serviced request could be freed */
				iwpm_map_req->timeout = 0;
				iwpm_map_req->complete = 1;
			}
			goto update_map_request_exit;
		}
	}
update_map_request_exit:
	pthread_mutex_unlock(&map_req_mutex);
	return ret;
}

/**
 * send_iwpm_msg - Form and send iwpm message to the remote peer
 */
int send_iwpm_msg(void (*form_msg_type)(iwpm_wire_msg *, iwpm_msg_parms *),
			iwpm_msg_parms *msg_parms, struct sockaddr_storage *recv_addr, int send_sock)
{
	iwpm_send_msg send_msg;

	form_msg_type(&send_msg.data, msg_parms);
	form_iwpm_send_msg(send_sock, recv_addr, msg_parms->msize, &send_msg);
	return add_iwpm_pending_msg(&send_msg);
}

/**
 * check_iwpm_ip_addr - Check if the local IP address is valid
 * @local_addr:  local IP address to verify
 *
 * Check if the local IP address is used by the host ethernet interfaces
 */
static int check_iwpm_ip_addr(struct sockaddr_storage *local_addr)
{
	struct ifaddrs ifa;
	struct ifaddrs *ifap = &ifa;
	struct ifaddrs **ifa_list = &ifap;
	struct ifaddrs *ifa_current;
	int found_addr = 0;
	int ret = -EINVAL;

	/* get a list of host ethernet interfaces */
	if ((ret = getifaddrs(ifa_list)) < 0) {
		syslog(LOG_WARNING, "check_iwpm_ip_addr: Unable to get the list of interfaces (%s).\n",
				strerror(errno));
		return ret;
	}
	/* go through the list to make sure local IP address is valid */
	ifa_current = *ifa_list;
	while (ifa_current != NULL && !found_addr) {
		if (local_addr->ss_family == ifa_current->ifa_addr->sa_family) {
			switch (ifa_current->ifa_addr->sa_family) {
			case AF_INET: {
				if (!memcmp(&((struct sockaddr_in *)
					ifa_current->ifa_addr)->sin_addr.s_addr,
				   	&((struct sockaddr_in *)local_addr)->sin_addr.s_addr,
					IWARP_PM_IPV4_ADDR)) {

					found_addr = 1;
				}
				break;
			}
			case AF_INET6: {
				if (!memcmp(&((struct sockaddr_in6 *)
					ifa_current->ifa_addr)->sin6_addr.s6_addr,
				    	&((struct sockaddr_in6 *)local_addr)->sin6_addr.s6_addr,
					INET6_ADDRSTRLEN))

					found_addr = 1;
				break;
			}
			default:
				break;
			}
		}
		ifa_current = ifa_current->ifa_next;
	}
	if (found_addr)
		ret = 0;

	freeifaddrs(*ifa_list);
	return ret;
}

/**
 * get_iwpm_ip_addr - Get a mapped IP address
 * @local_addr:  local IP address to map
 * @mapped_addr: to store the mapped local IP address
 *
 * Currently, don't map the local IP address
 */
static int get_iwpm_ip_addr(struct sockaddr_storage *local_addr,
					struct sockaddr_storage *mapped_addr)
{
	int ret = check_iwpm_ip_addr(local_addr);
	if (!ret)
		memcpy(mapped_addr, local_addr, sizeof(struct sockaddr_storage));
	else
		iwpm_debug(IWARP_PM_ALL_DBG, "get_iwpm_ip_addr: Invalid local IP address.\n");

	return ret;
}

/**
 * get_iwpm_tcp_port - Get a new TCP port from the host stack
 * @addr_family: should be valid AF_INET or AF_INET6
 * @requested_port: set only if reopening of mapped port
 * @mapped_addr: to store the mapped TCP port
 * @new_sock: to store socket handle (bound to the mapped TCP port)
*/
static int get_iwpm_tcp_port(__u16 addr_family, __be16 requested_port,
					struct sockaddr_storage *mapped_addr, int *new_sock)
{
	sockaddr_union bind_addr;
	struct sockaddr_in *bind_in4;
	struct sockaddr_in6 *bind_in6;
	socklen_t sockname_len;
	__be16 *new_port = NULL, *mapped_port = NULL;
	const char *str_err = "";

	/* create a socket */
	*new_sock = socket(addr_family, SOCK_STREAM, 0);
	if (*new_sock < 0) {
		str_err = "Unable to create socket";
		goto get_tcp_port_error;
	}

	memset(&bind_addr, 0, sizeof(bind_addr));
	switch (addr_family) {
	case AF_INET:
		mapped_port = &((struct sockaddr_in *)mapped_addr)->sin_port;
		bind_in4 = &bind_addr.v4_sockaddr;
		bind_in4->sin_family = addr_family;
		bind_in4->sin_addr.s_addr = htobe32(INADDR_ANY);
		if (requested_port)
			requested_port = *mapped_port;
		bind_in4->sin_port = requested_port;
		new_port = &bind_in4->sin_port;
		break;
	case AF_INET6:
		mapped_port = &((struct sockaddr_in6 *)mapped_addr)->sin6_port;
		bind_in6 = &bind_addr.v6_sockaddr;
		bind_in6->sin6_family = addr_family;
		bind_in6->sin6_addr = in6addr_any;
		if (requested_port)
			requested_port = *mapped_port;
		bind_in6->sin6_port = requested_port;
		new_port = &bind_in6->sin6_port;
		break;
	default:
		str_err = "Invalid Internet address family";
		goto get_tcp_port_error;
	}

	if (bind(*new_sock, &bind_addr.sock_addr, sizeof(bind_addr))) {
		str_err = "Unable to bind the socket";
		goto get_tcp_port_error;
	}
	/* get the TCP port */
	sockname_len = sizeof(bind_addr);
	if (getsockname(*new_sock, &bind_addr.sock_addr, &sockname_len)) {
		str_err = "Unable to get socket name";
		goto get_tcp_port_error;
	}
	*mapped_port = *new_port;
	iwpm_debug(IWARP_PM_ALL_DBG, "get_iwpm_tcp_port: Open tcp port "
		"(addr family = %04X, requested port = %04X, mapped port = %04X).\n",
		addr_family, be16toh(requested_port), be16toh(*mapped_port));
	return 0;
get_tcp_port_error:
	syslog(LOG_WARNING, "get_iwpm_tcp_port: %s (addr family = %04X, requested port = %04X).\n",
				str_err, addr_family, be16toh(requested_port));
	return -errno;
}

/**
 * get_iwpm_port - Allocate and initialize a new mapped port object
 */
static iwpm_mapped_port *get_iwpm_port(int client_idx, struct sockaddr_storage *local_addr,
				struct sockaddr_storage *mapped_addr, int sd)
{
	iwpm_mapped_port *iwpm_port;

	iwpm_port = malloc(sizeof(iwpm_mapped_port));
	if (!iwpm_port) {
		syslog(LOG_WARNING, "get_iwpm_port: Unable to allocate a mapped port.\n");
		return NULL;
	}
	memset(iwpm_port, 0, sizeof(*iwpm_port));

	/* record local and mapped address in the mapped port object */
	memcpy(&iwpm_port->local_addr, local_addr, sizeof(struct sockaddr_storage));
	memcpy(&iwpm_port->mapped_addr, mapped_addr, sizeof(struct sockaddr_storage));
	iwpm_port->owner_client = client_idx;
	iwpm_port->sd = sd;
	atomic_init(&iwpm_port->ref_cnt, 1);
	if (is_wcard_ipaddr(local_addr))
		iwpm_port->wcard = 1;
	return iwpm_port;
}

/**
 * create_iwpm_mapped_port - Create a new mapped port object
 * @local_addr: local address to be mapped (IP address and TCP port)
 * @client_idx: the index of the client owner of the mapped port
 */
iwpm_mapped_port *create_iwpm_mapped_port(struct sockaddr_storage *local_addr, int client_idx, __u32 flags)
{
	iwpm_mapped_port *iwpm_port;
	struct sockaddr_storage mapped_addr;
	int new_sd;

	/* check the local IP address */
	if (get_iwpm_ip_addr(local_addr, &mapped_addr))
		goto create_mapped_port_error;
	/* get a tcp port from the host net stack */
	if (flags & IWPM_FLAGS_NO_PORT_MAP) {
		mapped_addr = *local_addr;
		new_sd = -1;
	} else {
		if (get_iwpm_tcp_port(local_addr->ss_family, 0, &mapped_addr, &new_sd))
			goto create_mapped_port_error;
	}

	iwpm_port = get_iwpm_port(client_idx, local_addr, &mapped_addr, new_sd);
	return iwpm_port;

create_mapped_port_error:
	iwpm_debug(IWARP_PM_ALL_DBG, "create_iwpm_mapped_port: Could not make port mapping.\n");
	return NULL;
}

/**
 * reopen_iwpm_mapped_port - Create a new mapped port object
 * @local_addr: local address to be mapped (IP address and TCP port)
 * @mapped_addr: mapped address to be remapped (IP address and TCP port)
 * @client_idx: the index of the client owner of the mapped port
 */
iwpm_mapped_port *reopen_iwpm_mapped_port(struct sockaddr_storage *local_addr,
						struct sockaddr_storage *mapped_addr, int client_idx,
						__u32 flags)
{
	iwpm_mapped_port *iwpm_port;
	int new_sd;
	const char *str_err = "";
	int ret = check_iwpm_ip_addr(local_addr);
	if (ret) {
		str_err = "Invalid local IP address";
		goto reopen_mapped_port_error;
	}
	if (local_addr->ss_family != mapped_addr->ss_family) {
		str_err = "Different local and mapped sockaddr families";
		goto reopen_mapped_port_error;
	}
	/* get a tcp port from the host net stack */
	if (flags & IWPM_FLAGS_NO_PORT_MAP) {
		new_sd = -1;
	} else {
		if (get_iwpm_tcp_port(local_addr->ss_family, htobe16(1), mapped_addr, &new_sd))
			goto reopen_mapped_port_error;
	}
	iwpm_port = get_iwpm_port(client_idx, local_addr, mapped_addr, new_sd);
	return iwpm_port;

reopen_mapped_port_error:
	iwpm_debug(IWARP_PM_ALL_DBG, "reopen_iwpm_mapped_port: Could not make port mapping (%s).\n",
			str_err);
	return NULL;
}

/**
 * add_iwpm_mapped_port - Add mapping to a global list
 * @iwpm_port: mapping to be saved
 */
void add_iwpm_mapped_port(iwpm_mapped_port *iwpm_port)
{
	static int dbg_idx = 1;
	if (atomic_load(&iwpm_port->ref_cnt) > 1)
		return;
	iwpm_debug(IWARP_PM_ALL_DBG, "add_iwpm_mapped_port: Adding a new mapping #%d\n", dbg_idx++);
	list_add(&mapped_ports, &iwpm_port->entry);
}

/**
 * check_same_sockaddr - Compare two sock addresses;
 *                       return true if they are same, false otherwise
 */
int check_same_sockaddr(struct sockaddr_storage *sockaddr_a, struct sockaddr_storage *sockaddr_b)
{
	int ret = 0;
	if (sockaddr_a->ss_family == sockaddr_b->ss_family) {
		switch (sockaddr_a->ss_family) {
		case AF_INET: {
			struct sockaddr_in *in4addr_a = (struct sockaddr_in *)sockaddr_a;
			struct sockaddr_in *in4addr_b = (struct sockaddr_in *)sockaddr_b;

			if ((in4addr_a->sin_addr.s_addr == in4addr_b->sin_addr.s_addr)
			 		&& (in4addr_a->sin_port == in4addr_b->sin_port))
				ret = 1;

			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *in6addr_a = (struct sockaddr_in6 *)sockaddr_a;
			struct sockaddr_in6 *in6addr_b = (struct sockaddr_in6 *)sockaddr_b;

			if ((!memcmp(in6addr_a->sin6_addr.s6_addr,
					in6addr_b->sin6_addr.s6_addr, IWPM_IPADDR_SIZE)) &&
					(in6addr_a->sin6_port == in6addr_b->sin6_port))
				ret = 1;

			break;
		}
		default:
			syslog(LOG_WARNING, "check_same_sockaddr: Invalid addr family 0x%02X\n",
					sockaddr_a->ss_family);
			break;
		}
	}
	return ret;
}

/**
 * find_iwpm_mapping - Find saved mapped port object
 * @search_addr: IP address and port to search for in the list
 * @not_mapped: if set, compare local addresses, otherwise compare mapped addresses
 *
 * Compares the search_sockaddr to the addresses in the list,
 * to find a saved port object with the sockaddr or
 * a wild card address with the same tcp port
 */
iwpm_mapped_port *find_iwpm_mapping(struct sockaddr_storage *search_addr,
		int not_mapped)
{
	iwpm_mapped_port *iwpm_port, *saved_iwpm_port = NULL;
	struct sockaddr_storage *current_addr;

	list_for_each(&mapped_ports, iwpm_port, entry) {
		current_addr = (not_mapped)? &iwpm_port->local_addr : &iwpm_port->mapped_addr;

		if (get_sockaddr_port(search_addr) == get_sockaddr_port(current_addr)) {
			if (check_same_sockaddr(search_addr, current_addr) ||
					iwpm_port->wcard || is_wcard_ipaddr(search_addr)) {
				saved_iwpm_port = iwpm_port;
				goto find_mapping_exit;
			}
		}
	}
find_mapping_exit:
	return saved_iwpm_port;
}

/**
 * find_iwpm_same_mapping - Find saved mapped port object
 * @search_addr: IP address and port to search for in the list
 * @not_mapped: if set, compare local addresses, otherwise compare mapped addresses
 *
 * Compares the search_sockaddr to the addresses in the list,
 * to find a saved port object with the same sockaddr
 */
iwpm_mapped_port *find_iwpm_same_mapping(struct sockaddr_storage *search_addr,
		int not_mapped)
{
	iwpm_mapped_port *iwpm_port, *saved_iwpm_port = NULL;
	struct sockaddr_storage *current_addr;

	list_for_each(&mapped_ports, iwpm_port, entry) {
		current_addr = (not_mapped)? &iwpm_port->local_addr : &iwpm_port->mapped_addr;
		if (check_same_sockaddr(search_addr, current_addr)) {
			saved_iwpm_port = iwpm_port;
			goto find_same_mapping_exit;
		}
	}
find_same_mapping_exit:
	return saved_iwpm_port;
}

/**
 * free_iwpm_port - Free mapping object
 * @iwpm_port: mapped port object to be freed
 */
void free_iwpm_port(iwpm_mapped_port *iwpm_port)
{
	if (iwpm_port->sd != -1)
		close(iwpm_port->sd);
	free(iwpm_port);
}

/**
 * remove_iwpm_mapped_port - Remove a mapping from a global list
 * @iwpm_port: mapping to be removed
 *
 * Called only by the main iwarp port mapper thread
 */
void remove_iwpm_mapped_port(iwpm_mapped_port *iwpm_port)
{
	static int dbg_idx = 1;
	iwpm_debug(IWARP_PM_ALL_DBG, "remove_iwpm_mapped_port: index = %d\n", dbg_idx++);

	list_del(&iwpm_port->entry);
}

void print_iwpm_mapped_ports(void)
{
	iwpm_mapped_port *iwpm_port;
	int i = 0;

	syslog(LOG_WARNING, "print_iwpm_mapped_ports:\n");

	list_for_each(&mapped_ports, iwpm_port, entry) {
		syslog(LOG_WARNING, "Mapping #%d\n", i++);
		print_iwpm_sockaddr(&iwpm_port->local_addr, "Local address", IWARP_PM_DEBUG);
		print_iwpm_sockaddr(&iwpm_port->mapped_addr, "Mapped address", IWARP_PM_DEBUG);
	}
}

/**
 * form_iwpm_send_msg - Form a message to send on the wire
 */
void form_iwpm_send_msg(int pm_sock, struct sockaddr_storage *dest,
			int length, iwpm_send_msg *send_msg)
{
        send_msg->pm_sock = pm_sock;
        send_msg->length = length;
        memcpy(&send_msg->dest_addr, dest, sizeof(send_msg->dest_addr));
}

/**
 * add_iwpm_pending_msg - Add wire message to a global list of pending messages
 * @send_msg: message to send to the remote port mapper peer
 */
int add_iwpm_pending_msg(iwpm_send_msg *send_msg)
{
	iwpm_pending_msg *pending_msg = malloc(sizeof(iwpm_pending_msg));
	if (!pending_msg) {
		syslog(LOG_WARNING, "add_iwpm_pending_msg: Unable to allocate message.\n");
		return -ENOMEM;
	}
	memcpy(&pending_msg->send_msg, send_msg, sizeof(iwpm_send_msg));

	pthread_mutex_lock(&pending_msg_mutex);
	list_add(&pending_messages, &pending_msg->entry);
	pthread_mutex_unlock(&pending_msg_mutex);
	/* signal the thread that a new message has been posted */
	pthread_cond_signal(&cond_pending_msg);
	return 0;
}

/**
 * free_iwpm_mapped_ports - Free all iwpm mapped port objects
 */
void free_iwpm_mapped_ports(void)
{
	iwpm_mapped_port *iwpm_port;

	while ((iwpm_port = list_pop(&mapped_ports, iwpm_mapped_port, entry)))
		free_iwpm_port(iwpm_port);
}
