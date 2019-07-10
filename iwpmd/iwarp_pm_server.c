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

#include "config.h"
#include <systemd/sd-daemon.h>
#include <getopt.h>
#include "iwarp_pm.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static const char iwpm_ulib_name [] = "iWarpPortMapperUser";
static __u16 iwpm_version = IWPM_UABI_VERSION;

LIST_HEAD(mapping_reqs);		      /* list of map tracking objects */
LIST_HEAD(pending_messages);		      /* list of pending wire messages */
iwpm_client client_list[IWARP_PM_MAX_CLIENTS];/* list of iwarp port mapper clients */
static int mapinfo_num_list[IWARP_PM_MAX_CLIENTS];   /* list of iwarp port mapper clients */

/* socket handles */
static int pmv4_sock, pmv6_sock, netlink_sock, pmv4_client_sock, pmv6_client_sock;

static pthread_t map_req_thread; /* handling mapping requests timeout */
pthread_cond_t cond_req_complete; 
pthread_mutex_t map_req_mutex = PTHREAD_MUTEX_INITIALIZER;
int wake = 0; /* set if map_req_thread is wake */

static pthread_t pending_msg_thread; /* sending iwpm wire messages */
pthread_cond_t cond_pending_msg;
pthread_mutex_t pending_msg_mutex = PTHREAD_MUTEX_INITIALIZER;

static void iwpm_cleanup(void);
static int print_mappings = 0;
static int send_iwpm_mapinfo_request(int nl_sock, int client);

/**
 * iwpm_signal_handler - Handle signals which iwarp port mapper receives
 * @signum: the number of the caught signal
 */
static void iwpm_signal_handler(int signum)
{
	switch(signum) {
		case SIGHUP:
			syslog(LOG_WARNING, "iwpm_signal_handler: Received SIGHUP signal\n");
			iwpm_cleanup();
			exit(signum);
			break;
		case SIGTERM:
			syslog(LOG_WARNING, "iwpm_signal_handler: Received SIGTERM signal\n");
			iwpm_cleanup();
			exit(EXIT_SUCCESS);
			break;
		case SIGUSR1:
			syslog(LOG_WARNING, "iwpm_signal_handler: Received SIGUSR1 signal\n");
			print_mappings = 1;
			break;
		default:
			syslog(LOG_WARNING, "iwpm_signal_handler: Unhandled signal %d\n", signum);
			break;
	}
}

/**
 * iwpm_mapping_reqs_handler - Handle mapping requests timeouts and retries
 */
static void *iwpm_mapping_reqs_handler(void *unused)
{
	iwpm_mapping_request *iwpm_map_req, *next_map_req;
	int ret = 0;

	while (1) {
		pthread_mutex_lock(&map_req_mutex);
		wake = 0;
		if (list_empty(&mapping_reqs)) {
			/* wait until a new mapping request is posted */
			ret = pthread_cond_wait(&cond_req_complete, &map_req_mutex);
			if (ret) {
				syslog(LOG_WARNING, "mapping_reqs_handler: "
					"Condition wait failed (ret = %d)\n", ret);
				pthread_mutex_unlock(&map_req_mutex);
				goto mapping_reqs_handler_exit;
			}
		}
		pthread_mutex_unlock(&map_req_mutex);
		/* update timeouts of the posted mapping requests */
		do {
			pthread_mutex_lock(&map_req_mutex);
			wake = 1;
			list_for_each_safe(&mapping_reqs, iwpm_map_req, next_map_req, entry) {
				if (iwpm_map_req->timeout > 0) {
					if (iwpm_map_req->timeout < IWPM_MAP_REQ_TIMEOUT &&
							iwpm_map_req->msg_type != IWARP_PM_REQ_ACK) {
						/* the request is still incomplete, retransmit the message (every 1sec) */
						add_iwpm_pending_msg(iwpm_map_req->send_msg);

						iwpm_debug(IWARP_PM_RETRY_DBG, "mapping_reqs_handler: "
							"Going to retransmit a msg, map request "
							"(assochandle = %llu, type = %u, timeout = %d)\n",
							iwpm_map_req->assochandle, iwpm_map_req->msg_type,
							iwpm_map_req->timeout);
					}
					iwpm_map_req->timeout--; /* hang around for 10s */
				} else {
					remove_iwpm_map_request(iwpm_map_req);
				}
			}
			pthread_mutex_unlock(&map_req_mutex);
			sleep(1);
		} while (!list_empty(&mapping_reqs));
	}
mapping_reqs_handler_exit:
	return NULL;
}

/**
 * iwpm_pending_msgs_handler - Handle sending iwarp port mapper wire messages
 */
static void *iwpm_pending_msgs_handler(void *unused)
{
	iwpm_pending_msg *pending_msg;
	iwpm_send_msg *send_msg;
	int retries = IWPM_SEND_MSG_RETRIES;
	int ret = 0;

	pthread_mutex_lock(&pending_msg_mutex);
	while (1) {
		/* wait until a new message is posted */
		ret = pthread_cond_wait(&cond_pending_msg, &pending_msg_mutex);
		if (ret) {
			syslog(LOG_WARNING, "pending_msgs_handler: "
				"Condition wait failed (ret = %d)\n", ret);
			pthread_mutex_unlock(&pending_msg_mutex);
			goto pending_msgs_handler_exit;
		}

		/* try sending out each pending message and remove it from the list */
		while ((pending_msg = list_pop(&pending_messages,
				iwpm_pending_msg, entry))) {
			retries = IWPM_SEND_MSG_RETRIES;
			while (retries) {
				send_msg = &pending_msg->send_msg;
				/* send out the message */
				int bytes_sent = sendto(send_msg->pm_sock, (char *)&send_msg->data,
							send_msg->length, 0,
							(struct sockaddr *)&send_msg->dest_addr,
							sizeof(send_msg->dest_addr));
				if (bytes_sent != send_msg->length) {
					retries--;
					syslog(LOG_WARNING, "pending_msgs_handler: "
						"Could not send to PM Socket send_msg = %p, retries = %d\n",
						send_msg, retries);
				} else
					retries = 0; /* no need to retry */
			}
			free(pending_msg);
		}
	}
	pthread_mutex_unlock(&pending_msg_mutex);

pending_msgs_handler_exit:
	return NULL;
}

static int send_iwpm_error_msg(__u32, __u16, int, int);

/* Register pid query - nlmsg attributes */
static struct nla_policy reg_pid_policy[IWPM_NLA_REG_PID_MAX] = {
        [IWPM_NLA_REG_PID_SEQ]     =  { .type = NLA_U32 },
        [IWPM_NLA_REG_IF_NAME]     =  { .type = NLA_STRING,
					.maxlen = IWPM_IFNAME_SIZE },
        [IWPM_NLA_REG_IBDEV_NAME]  =  { .type = NLA_STRING,
					.maxlen = IWPM_ULIBNAME_SIZE },
	[IWPM_NLA_REG_ULIB_NAME]   =  { .type = NLA_STRING,
					.maxlen = IWPM_ULIBNAME_SIZE }
};

/**
 * process_iwpm_register_pid - Service a client query for port mapper pid
 * @req_nlh: netlink header of the received client message
 * @client_idx: the index of the client (unique for each iwpm client)
 * @nl_sock: netlink socket to send a message back to the client
 *
 * Process a query and send a response to the client which contains the iwpm pid
 * nlmsg response attributes:
 * 		IWPM_NLA_RREG_PID_SEQ
 * 		IWPM_NLA_RREG_IBDEV_NAME
 * 		IWPM_NLA_RREG_ULIB_NAME
 * 		IWPM_NLA_RREG_ULIB_VER
 * 		IWPM_NLA_RREG_PID_ERR
 */
static int process_iwpm_register_pid(struct nlmsghdr *req_nlh, int client_idx, int nl_sock)
{
	iwpm_client *client;
	struct nlattr *nltb [IWPM_NLA_REG_PID_MAX];
	struct nl_msg *resp_nlmsg = NULL;
	const char *ifname, *devname, *libname;
	__u16 err_code = 0;
	const char *msg_type = "Register Pid Request";
	const char *str_err;
	int ret = -EINVAL;

	if (parse_iwpm_nlmsg(req_nlh, IWPM_NLA_REG_PID_MAX, reg_pid_policy, nltb, msg_type)) {
		str_err = "Received Invalid nlmsg";
		err_code = IWPM_INVALID_NLMSG_ERR;
                goto register_pid_error;
	}

	ifname = (const char *)nla_get_string(nltb[IWPM_NLA_REG_IF_NAME]);
	devname = (const char *)nla_get_string(nltb[IWPM_NLA_REG_IBDEV_NAME]);
	libname = (const char *)nla_get_string(nltb[IWPM_NLA_REG_ULIB_NAME]);

	iwpm_debug(IWARP_PM_NETLINK_DBG, "process_register_pid: PID request from "
			"IB device %s Ethernet device %s User library %s "
			"(client idx = %d, msg seq = %u).\n",
			devname, ifname, libname, client_idx, req_nlh->nlmsg_seq);

	/* register a first time client */
	client = &client_list[client_idx];
	if (!client->valid) {
		memcpy(client->ibdevname, devname, IWPM_DEVNAME_SIZE);
		memcpy(client->ifname, ifname, IWPM_IFNAME_SIZE);
		memcpy(client->ulibname, libname, IWPM_ULIBNAME_SIZE);
		client->valid = 1;
	} else { /* check client info */
		if (strcmp(client->ulibname, libname)) {
			str_err = "Incorrect library version";
			err_code = IWPM_USER_LIB_INFO_ERR;
                	goto register_pid_error;
        	}
	}
	resp_nlmsg = create_iwpm_nlmsg(req_nlh->nlmsg_type, client_idx);
	if (!resp_nlmsg) {
		ret = -ENOMEM;
		str_err = "Unable to create nlmsg response";
		goto register_pid_error;
	}
	str_err = "Invalid nlmsg attribute";
	if ((ret = nla_put_u32(resp_nlmsg, IWPM_NLA_RREG_PID_SEQ, req_nlh->nlmsg_seq)))
		goto register_pid_error;
	if ((ret = nla_put_string(resp_nlmsg, IWPM_NLA_RREG_IBDEV_NAME, devname)))
		goto register_pid_error;
	if ((ret = nla_put_string(resp_nlmsg, IWPM_NLA_RREG_ULIB_NAME, iwpm_ulib_name)))
		goto register_pid_error;
	if ((ret = nla_put_u16(resp_nlmsg, IWPM_NLA_RREG_ULIB_VER, iwpm_version)))
		goto register_pid_error;
	if ((ret = nla_put_u16(resp_nlmsg, IWPM_NLA_RREG_PID_ERR, err_code)))
		goto register_pid_error;

	if ((ret = send_iwpm_nlmsg(nl_sock, resp_nlmsg, req_nlh->nlmsg_pid))) {
		str_err = "Unable to send nlmsg response";
		goto register_pid_error;
	}
	nlmsg_free(resp_nlmsg);
	return 0;
register_pid_error:
	if (resp_nlmsg)
		nlmsg_free(resp_nlmsg);
	syslog(LOG_WARNING, "process_register_pid: %s ret = %d.\n", str_err, ret);
	if (err_code)
		send_iwpm_error_msg(req_nlh->nlmsg_seq, err_code, client_idx, nl_sock);
	return ret;
}

/* Add mapping request - nlmsg attributes */
static struct nla_policy manage_map_policy[IWPM_NLA_MANAGE_MAPPING_MAX] = {
        [IWPM_NLA_MANAGE_MAPPING_SEQ]        = { .type = NLA_U32 },
        [IWPM_NLA_MANAGE_ADDR]               = { .minlen = sizeof(struct sockaddr_storage) },
        [IWPM_NLA_MANAGE_FLAGS]              = { .type = NLA_U32 }
};

/**
 * process_iwpm_add_mapping - Service a client request for mapping of a local address
 * @req_nlh: netlink header of the received client message
 * @client_idx: the index of the client (unique for each iwpm client)
 * @nl_sock: netlink socket to send a message back to the client
 *
 * Process a mapping request for a local address and send a response to the client
 * which contains the mapped local address (IP address and TCP port)
 * nlmsg response attributes:
 *	[IWPM_NLA_RMANAGE_MAPPING_SEQ]
 *	[IWPM_NLA_RMANAGE_ADDR]
 *	[IWPM_NLA_RMANAGE_MAPPED_LOC_ADDR]
 *	[IWPM_NLA_RMANAGE_MAPPING_ERR]
 */
static int process_iwpm_add_mapping(struct nlmsghdr *req_nlh, int client_idx, int nl_sock)
{
	iwpm_mapped_port *iwpm_port = NULL;
	struct nlattr *nltb [IWPM_NLA_MANAGE_MAPPING_MAX] = {};
	struct nl_msg *resp_nlmsg = NULL;
	struct sockaddr_storage *local_addr;
	int not_mapped = 1;
	__u16 err_code = 0;
	const char *msg_type = "Add Mapping Request";
	const char *str_err = "";
	int ret = -EINVAL;
	__u32 flags;
	int max = IWPM_NLA_MANAGE_MAPPING_MAX;

	if (iwpm_version != IWPM_UABI_VERSION)
		max--;
	if (parse_iwpm_nlmsg(req_nlh, max, manage_map_policy, nltb, msg_type)) {
		err_code = IWPM_INVALID_NLMSG_ERR;
		str_err = "Received Invalid nlmsg";
		goto add_mapping_error;
	}
	local_addr = (struct sockaddr_storage *)nla_data(nltb[IWPM_NLA_MANAGE_ADDR]);
	flags = nltb[IWPM_NLA_MANAGE_FLAGS] ? nla_get_u32(nltb[IWPM_NLA_MANAGE_FLAGS]) : 0;

	iwpm_port = find_iwpm_mapping(local_addr, not_mapped);
	if (iwpm_port) {
		if (check_same_sockaddr(local_addr, &iwpm_port->local_addr) && iwpm_port->wcard) {
			atomic_fetch_add(&iwpm_port->ref_cnt, 1);
		} else {
			err_code = IWPM_DUPLICATE_MAPPING_ERR;
			str_err = "Duplicate mapped port";
			goto add_mapping_error;
		}

	} else {
		iwpm_port = create_iwpm_mapped_port(local_addr, client_idx, flags);
		if (!iwpm_port) {
			err_code = IWPM_CREATE_MAPPING_ERR;
			str_err = "Unable to create new mapping";
			goto add_mapping_error;
		}
	}
	resp_nlmsg = create_iwpm_nlmsg(req_nlh->nlmsg_type, client_idx);
	if (!resp_nlmsg) {
		ret = -ENOMEM;
		str_err = "Unable to create nlmsg response";
		goto add_mapping_free_error;
	}
	str_err = "Invalid nlmsg attribute";
	if ((ret = nla_put_u32(resp_nlmsg, IWPM_NLA_RMANAGE_MAPPING_SEQ, req_nlh->nlmsg_seq)))
		goto add_mapping_free_error;
	if ((ret = nla_put(resp_nlmsg, IWPM_NLA_RMANAGE_ADDR,
				sizeof(struct sockaddr_storage), &iwpm_port->local_addr)))
		goto add_mapping_free_error;
	if ((ret = nla_put(resp_nlmsg, IWPM_NLA_RMANAGE_MAPPED_LOC_ADDR,
				sizeof(struct sockaddr_storage), &iwpm_port->mapped_addr)))
		goto add_mapping_free_error;
	if ((ret = nla_put_u16(resp_nlmsg, IWPM_NLA_RMANAGE_MAPPING_ERR, err_code)))
		goto add_mapping_free_error;

	if ((ret = send_iwpm_nlmsg(nl_sock, resp_nlmsg, req_nlh->nlmsg_pid))) {
		str_err = "Unable to send nlmsg response";
		goto add_mapping_free_error;
	}
	/* add the new mapping to the list */
	add_iwpm_mapped_port(iwpm_port);
	nlmsg_free(resp_nlmsg);
	return 0;

add_mapping_free_error:
	if (resp_nlmsg)
		nlmsg_free(resp_nlmsg);
	if (iwpm_port) {
		if (atomic_fetch_sub(&iwpm_port->ref_cnt, 1) == 1)
			free_iwpm_port(iwpm_port);
	}
add_mapping_error:
	syslog(LOG_WARNING, "process_add_mapping: %s (failed request from client = %s).\n",
			str_err, client_list[client_idx].ibdevname);
	if (err_code) {
		/* send error message to the client */
		send_iwpm_error_msg(req_nlh->nlmsg_seq, err_code, client_idx, nl_sock);
	}
	return ret;
}

/* Query mapping request - nlmsg attributes */
static struct nla_policy query_map_policy[IWPM_NLA_QUERY_MAPPING_MAX] = {
        [IWPM_NLA_QUERY_MAPPING_SEQ]         = { .type = NLA_U32 },
        [IWPM_NLA_QUERY_LOCAL_ADDR]          = { .minlen = sizeof(struct sockaddr_storage) },
        [IWPM_NLA_QUERY_REMOTE_ADDR]         = { .minlen = sizeof(struct sockaddr_storage) },
        [IWPM_NLA_QUERY_FLAGS]               = { .type = NLA_U32 }
};

/**
 * process_iwpm_query_mapping - Service a client request for local and remote mapping
 * @req_nlh: netlink header of the received client message
 * @client_idx: the index of the client (the index is unique for each iwpm client)
 * @nl_sock: netlink socket to send a message back to the client
 *
 * Process a client request for local and remote address mapping
 * Create mapping for the local address (IP address and TCP port)
 * Send a request to the remote port mapper peer to find out the remote address mapping
 */
static int process_iwpm_query_mapping(struct nlmsghdr *req_nlh, int client_idx, int nl_sock)
{
	iwpm_mapped_port *iwpm_port = NULL;
	iwpm_mapping_request *iwpm_map_req = NULL;
	struct nlattr *nltb [IWPM_NLA_QUERY_MAPPING_MAX] = {};
	struct sockaddr_storage *local_addr, *remote_addr;
	sockaddr_union dest_addr;
	iwpm_msg_parms msg_parms;
	iwpm_send_msg *send_msg = NULL;
	int pm_client_sock;
	int not_mapped = 1;
	__u16 err_code = 0;
	const char *msg_type = "Add & Query Mapping Request";
	const char *str_err = "";
	int ret = -EINVAL;
	__u32 flags;
	int max = IWPM_NLA_QUERY_MAPPING_MAX;

	if (iwpm_version != IWPM_UABI_VERSION)
		max--;
	if (parse_iwpm_nlmsg(req_nlh, max, query_map_policy, nltb, msg_type)) {
		err_code = IWPM_INVALID_NLMSG_ERR;
		str_err = "Received Invalid nlmsg";
		goto query_mapping_error;
	}
	local_addr = (struct sockaddr_storage *)nla_data(nltb[IWPM_NLA_QUERY_LOCAL_ADDR]);
	remote_addr = (struct sockaddr_storage *)nla_data(nltb[IWPM_NLA_QUERY_REMOTE_ADDR]);
	flags = nltb[IWPM_NLA_QUERY_FLAGS] ? nla_get_u32(nltb[IWPM_NLA_QUERY_FLAGS]) : 0;

	iwpm_port = find_iwpm_mapping(local_addr, not_mapped);
	if (iwpm_port) {
		atomic_fetch_add(&iwpm_port->ref_cnt, 1);
	} else {
		iwpm_port = create_iwpm_mapped_port(local_addr, client_idx, flags);
		if (!iwpm_port) {
			err_code = IWPM_CREATE_MAPPING_ERR;
			str_err = "Unable to create new mapping";
			goto query_mapping_error;
		}
	}
	if (iwpm_port->wcard) {
		err_code = IWPM_CREATE_MAPPING_ERR;
		str_err = "Invalid wild card mapping";
		goto query_mapping_free_error;
	}
	/* create iwpm wire message */
	memcpy(&dest_addr.s_sockaddr, remote_addr, sizeof(struct sockaddr_storage));
	switch (dest_addr.s_sockaddr.ss_family) {
	case AF_INET:
		dest_addr.v4_sockaddr.sin_port = htobe16(IWARP_PM_PORT);
		msg_parms.ip_ver = 4;
		msg_parms.address_family = AF_INET;
		pm_client_sock = pmv4_client_sock;
		break;
	case AF_INET6:
		dest_addr.v6_sockaddr.sin6_port = htobe16(IWARP_PM_PORT);
		msg_parms.ip_ver = 6;
		msg_parms.address_family = AF_INET6;
		pm_client_sock = pmv6_client_sock;
		break;
	default:
		str_err = "Invalid Internet address family";
		goto query_mapping_free_error;
	}
	/* fill in the remote peer address and the local mapped address */
	copy_iwpm_sockaddr(dest_addr.s_sockaddr.ss_family, remote_addr, NULL, NULL,
				&msg_parms.apipaddr[0], &msg_parms.apport);
	copy_iwpm_sockaddr(dest_addr.s_sockaddr.ss_family, local_addr, NULL, NULL,
				&msg_parms.cpipaddr[0], &msg_parms.cpport);
	copy_iwpm_sockaddr(dest_addr.s_sockaddr.ss_family, &iwpm_port->mapped_addr, NULL, NULL,
				&msg_parms.mapped_cpipaddr[0], &msg_parms.mapped_cpport);
	msg_parms.pmtime = 0;
	msg_parms.ver = 0;
	iwpm_debug(IWARP_PM_WIRE_DBG, "process_query_mapping: Local port = 0x%04X, "
			"remote port = 0x%04X\n",
			be16toh(msg_parms.cpport), be16toh(msg_parms.apport));
	ret = -ENOMEM;
	send_msg = malloc(sizeof(iwpm_send_msg));
	if (!send_msg) {
		str_err = "Unable to allocate send msg buffer";
		goto query_mapping_free_error;
	}
	iwpm_map_req = create_iwpm_map_request(req_nlh, &iwpm_port->local_addr, remote_addr, 0,
								IWARP_PM_REQ_QUERY, send_msg);
	if (!iwpm_map_req) {
		str_err = "Unable to allocate mapping request";
		goto query_mapping_free_error;
	}
	msg_parms.assochandle = iwpm_map_req->assochandle;
	form_iwpm_request(&send_msg->data, &msg_parms);
	form_iwpm_send_msg(pm_client_sock, &dest_addr.s_sockaddr, msg_parms.msize, send_msg);

	add_iwpm_map_request(iwpm_map_req);
	add_iwpm_mapped_port(iwpm_port);

	return send_iwpm_msg(form_iwpm_request, &msg_parms, &dest_addr.s_sockaddr, pm_client_sock);
query_mapping_free_error:
	if (iwpm_port) {
		if (atomic_fetch_sub(&iwpm_port->ref_cnt, 1) == 1)
			free_iwpm_port(iwpm_port);
	}
	if (send_msg)
		free(send_msg);
	if (iwpm_map_req)
		free(iwpm_map_req);
query_mapping_error:
	syslog(LOG_WARNING, "process_query_mapping: %s (failed request from client = %s).\n",
			str_err, client_list[client_idx].ibdevname);
	if (err_code) {
		/* send error message to the client */
		send_iwpm_error_msg(req_nlh->nlmsg_seq, err_code, client_idx, nl_sock);
	}
	return ret;
}

/**
 * process_iwpm_remove_mapping - Remove a local mapping and close the mapped TCP port
 * @req_nlh: netlink header of the received client message
 * @client_idx: the index of the client (the index is unique for each iwpm client)
 * @nl_sock: netlink socket to send a message to the client
 */
static int process_iwpm_remove_mapping(struct nlmsghdr *req_nlh, int client_idx, int nl_sock)
{
	iwpm_mapped_port *iwpm_port = NULL;
	struct sockaddr_storage *local_addr;
	struct nlattr *nltb [IWPM_NLA_MANAGE_MAPPING_MAX];
	int not_mapped = 1;
	const char *msg_type = "Remove Mapping Request";
	int ret = 0;

	if (parse_iwpm_nlmsg(req_nlh, IWPM_NLA_REMOVE_MAPPING_MAX, manage_map_policy, nltb, msg_type)) {
		send_iwpm_error_msg(req_nlh->nlmsg_seq, IWPM_INVALID_NLMSG_ERR, client_idx, nl_sock);
		syslog(LOG_WARNING, "process_remove_mapping: Received Invalid nlmsg from client = %d\n",
				client_idx);
		ret = -EINVAL;
		goto remove_mapping_exit;
	}
	local_addr = (struct sockaddr_storage *)nla_data(nltb[IWPM_NLA_MANAGE_ADDR]);
	iwpm_debug(IWARP_PM_NETLINK_DBG, "process_remove_mapping: Going to remove mapping"
			" (client idx = %d)\n", client_idx);

	iwpm_port = find_iwpm_same_mapping(local_addr, not_mapped);
	if (!iwpm_port) {
		iwpm_debug(IWARP_PM_NETLINK_DBG, "process_remove_mapping: Unable to find mapped port object\n");
		print_iwpm_sockaddr(local_addr, "process_remove_mapping: Local address", IWARP_PM_ALL_DBG);
		/* the client sends a remove mapping request when terminating a connection
 		   and it is possible that there isn't a successful mapping for this connection */
		goto remove_mapping_exit;
	}
	if (iwpm_port->owner_client != client_idx) {
		syslog(LOG_WARNING, "process_remove_mapping: Invalid request from client = %d\n",
				client_idx);
		goto remove_mapping_exit;
	}
	if (atomic_fetch_sub(&iwpm_port->ref_cnt, 1) == 1) {
		remove_iwpm_mapped_port(iwpm_port);
		free_iwpm_port(iwpm_port);
	}
remove_mapping_exit:
	return ret;
}

static int send_conn_info_nlmsg(struct sockaddr_storage *local_addr,
				struct sockaddr_storage *remote_addr,
				struct sockaddr_storage *mapped_loc_addr,
				struct sockaddr_storage *mapped_rem_addr,
				int owner_client, __u16 nlmsg_type, __u32 nlmsg_seq,
				__u32 nlmsg_pid, __u16 nlmsg_err, int nl_sock)

{
	struct nl_msg *resp_nlmsg = NULL;
	const char *str_err;
	int ret;

	resp_nlmsg = create_iwpm_nlmsg(nlmsg_type, owner_client);
	if (!resp_nlmsg) {
		str_err = "Unable to create nlmsg response";
		ret = -ENOMEM;
		goto nlmsg_error;
	}
	str_err = "Invalid nlmsg attribute";
	if ((ret = nla_put_u32(resp_nlmsg, IWPM_NLA_QUERY_MAPPING_SEQ, nlmsg_seq)))
		goto nlmsg_free_error;
	if ((ret = nla_put(resp_nlmsg, IWPM_NLA_QUERY_LOCAL_ADDR,
				sizeof(struct sockaddr_storage), local_addr)))
		goto nlmsg_free_error;
	if ((ret = nla_put(resp_nlmsg, IWPM_NLA_QUERY_REMOTE_ADDR,
				sizeof(struct sockaddr_storage), remote_addr)))
		goto nlmsg_free_error;
	if ((ret = nla_put(resp_nlmsg, IWPM_NLA_RQUERY_MAPPED_LOC_ADDR,
				sizeof(struct sockaddr_storage), mapped_loc_addr)))
		goto nlmsg_free_error;
	if ((ret = nla_put(resp_nlmsg, IWPM_NLA_RQUERY_MAPPED_REM_ADDR,
				sizeof(struct sockaddr_storage), mapped_rem_addr)))
		goto nlmsg_free_error;
	if ((ret = nla_put_u16(resp_nlmsg, IWPM_NLA_RQUERY_MAPPING_ERR, nlmsg_err)))
		goto nlmsg_free_error;

	if ((ret = send_iwpm_nlmsg(nl_sock, resp_nlmsg, nlmsg_pid))) {
		str_err = "Unable to send nlmsg response";
		goto nlmsg_free_error;
	}
	nlmsg_free(resp_nlmsg);
	return 0;
nlmsg_free_error:
	if (resp_nlmsg)
		nlmsg_free(resp_nlmsg);
nlmsg_error:
	syslog(LOG_WARNING, "send_conn_info_nlmsg: %s.\n", str_err);
	return ret;
}

/**
 * process_iwpm_wire_request - Process a mapping query from remote port mapper peer
 * @msg_parms: the received iwpm request message
 * @recv_addr: address of the remote peer
 * @pm_sock: socket handle to send a response to the remote iwpm peer
 *
 * Look up the accepting peer local address to find the corresponding mapping,
 * send reject message to the remote connecting peer, if no mapping is found,
 * otherwise, send accept message with the accepting peer mapping info
 */
static int process_iwpm_wire_request(iwpm_msg_parms *msg_parms, int nl_sock,
				struct sockaddr_storage *recv_addr, int pm_sock)
{
	iwpm_mapped_port *iwpm_port;
	iwpm_mapping_request *iwpm_map_req = NULL;
	iwpm_mapping_request iwpm_copy_req;
	iwpm_send_msg *send_msg = NULL;
	struct sockaddr_storage local_addr, mapped_loc_addr;
	struct sockaddr_storage remote_addr, mapped_rem_addr;
	__u16 nlmsg_type;
	int not_mapped = 1;
	int ret = 0;

	copy_iwpm_sockaddr(msg_parms->address_family, NULL, &local_addr,
				 &msg_parms->apipaddr[0], NULL, &msg_parms->apport);
	iwpm_port = find_iwpm_mapping(&local_addr, not_mapped);
	if (!iwpm_port) {
		/* could not find mapping for the requested address */
		iwpm_debug(IWARP_PM_WIRE_DBG, "process_wire_request: "
				"Sending Reject to port mapper peer.\n");
		print_iwpm_sockaddr(&local_addr, "process_wire_request: Local address",
					IWARP_PM_ALL_DBG);
		return send_iwpm_msg(form_iwpm_reject, msg_parms, recv_addr, pm_sock);
	}
	/* record mapping in the accept message */
	if (iwpm_port->wcard)
		msg_parms->apport = get_sockaddr_port(&iwpm_port->mapped_addr);
	else
		copy_iwpm_sockaddr(msg_parms->address_family, &iwpm_port->mapped_addr,
			NULL, NULL, &msg_parms->apipaddr[0], &msg_parms->apport);

	copy_iwpm_sockaddr(msg_parms->address_family, NULL, &mapped_loc_addr,
				&msg_parms->apipaddr[0], NULL, &msg_parms->apport);

	/* check if there is already a request */
	ret = update_iwpm_map_request(msg_parms->assochandle, &mapped_loc_addr,
					IWARP_PM_REQ_ACCEPT, &iwpm_copy_req, 0);
	if (!ret) { /* found request */
		iwpm_debug(IWARP_PM_WIRE_DBG,"process_wire_request: Detected retransmission "
				"map request (assochandle = %llu type = %d timeout = %u complete = %d)\n",
				iwpm_copy_req.assochandle, iwpm_copy_req.msg_type,
				iwpm_copy_req.timeout, iwpm_copy_req.complete);
		return 0;
	}
	/* allocate response message */
	send_msg = malloc(sizeof(iwpm_send_msg));
	if (!send_msg) {
		syslog(LOG_WARNING, "process_wire_request: Unable to allocate send msg.\n");
		return -ENOMEM;
	}
	form_iwpm_accept(&send_msg->data, msg_parms);
	form_iwpm_send_msg(pm_sock, recv_addr, msg_parms->msize, send_msg);

	copy_iwpm_sockaddr(msg_parms->address_family, NULL, &remote_addr,
				 &msg_parms->cpipaddr[0], NULL, &msg_parms->cpport);
	copy_iwpm_sockaddr(msg_parms->address_family, NULL, &mapped_rem_addr,
				 &msg_parms->mapped_cpipaddr[0], NULL, &msg_parms->mapped_cpport);

	iwpm_map_req = create_iwpm_map_request(NULL, &mapped_loc_addr, &remote_addr,
					msg_parms->assochandle, IWARP_PM_REQ_ACCEPT, send_msg);
 	if (!iwpm_map_req) {
		syslog(LOG_WARNING, "process_wire_request: Unable to allocate mapping request.\n");
		free(send_msg);
		return -ENOMEM;
	}
	add_iwpm_map_request(iwpm_map_req);
	ret = send_iwpm_msg(form_iwpm_accept, msg_parms, recv_addr, pm_sock);
	if (ret) {
		syslog(LOG_WARNING, "process_wire_request: Unable to allocate accept message.\n");
		return ret;
	}
	nlmsg_type = RDMA_NL_GET_TYPE(iwpm_port->owner_client, RDMA_NL_IWPM_REMOTE_INFO);
	ret = send_conn_info_nlmsg(&iwpm_port->local_addr, &remote_addr,
				&iwpm_port->mapped_addr, &mapped_rem_addr,
				iwpm_port->owner_client, nlmsg_type, 0, 0, 0, nl_sock);
	return ret;
}

/**
 * process_iwpm_wire_accept - Process accept message from the remote port mapper peer
 * @msg_parms: the received iwpm accept message, containing the remote peer mapping info
 * @nl_sock: netlink socket to send a message to the iwpm client
 * @recv_addr: address of the remote peer
 * @pm_sock: socket handle to send ack message back to the remote peer
 *
 * Send acknowledgement to the remote/accepting peer,
 * send a netlink message with the local and remote mapping info to the iwpm client
 * nlmsg response attributes:
 *	[IWPM_NLA_QUERY_MAPPING_SEQ]
 * 	[IWPM_NLA_QUERY_LOCAL_ADDR]
 *	[IWPM_NLA_QUERY_REMOTE_ADDR]
 *	[IWPM_NLA_RQUERY_MAPPED_LOC_ADDR]
 *	[IWPM_NLA_RQUERY_MAPPED_REM_ADDR]
 *	[IWPM_NLA_RQUERY_MAPPING_ERR]
 */
static int process_iwpm_wire_accept(iwpm_msg_parms *msg_parms, int nl_sock,
					struct sockaddr_storage *recv_addr, int pm_sock)
{
	iwpm_mapping_request iwpm_map_req;
	iwpm_mapping_request *iwpm_retry_req = NULL;
	iwpm_mapped_port *iwpm_port;
	struct sockaddr_storage local_addr, remote_mapped_addr;
	int not_mapped = 1;
	const char *str_err;
	int ret;

	copy_iwpm_sockaddr(msg_parms->address_family, NULL, &local_addr,
				&msg_parms->cpipaddr[0], NULL, &msg_parms->cpport);
	copy_iwpm_sockaddr(msg_parms->address_family, NULL, &remote_mapped_addr,
				&msg_parms->apipaddr[0], NULL, &msg_parms->apport);
	ret = -EINVAL;
	iwpm_port = find_iwpm_same_mapping(&local_addr, not_mapped);
	if (!iwpm_port) {
		iwpm_debug(IWARP_PM_WIRE_DBG, "process_wire_accept: "
			"Received accept for unknown mapping.\n");
		return 0;
	}
	/* there should be a request for the accept message */
	ret = update_iwpm_map_request(msg_parms->assochandle, &iwpm_port->local_addr,
					(IWARP_PM_REQ_QUERY|IWARP_PM_REQ_ACK), &iwpm_map_req, 1);
	if (ret) {
		iwpm_debug(IWARP_PM_WIRE_DBG, "process_wire_accept: "
			"No matching mapping request (assochandle = %llu)\n",
			msg_parms->assochandle);
		return 0; /* ok when retransmission */
	}
	if (iwpm_map_req.complete)
		return 0;
	/* if the accept has already been processed and this is retransmission */
	if (iwpm_map_req.msg_type == IWARP_PM_REQ_ACK) {
		iwpm_debug(IWARP_PM_RETRY_DBG, "process_wire_accept: Detected retransmission "
				"(map request assochandle = %llu)\n", iwpm_map_req.assochandle);
		goto wire_accept_send_ack;
	}
	ret = send_conn_info_nlmsg(&iwpm_port->local_addr, &iwpm_map_req.remote_addr,
				&iwpm_port->mapped_addr, &remote_mapped_addr,
				iwpm_port->owner_client, iwpm_map_req.nlmsg_type,
				iwpm_map_req.nlmsg_seq, iwpm_map_req.nlmsg_pid, 0, nl_sock);
	if (ret) {
		str_err = "Unable to send nlmsg response";
		goto wire_accept_error;
	}
	/* object to detect retransmission */
	iwpm_retry_req = create_iwpm_map_request(NULL, &iwpm_map_req.src_addr, &iwpm_map_req.remote_addr,
					iwpm_map_req.assochandle, IWARP_PM_REQ_ACK, NULL);
	if (!iwpm_retry_req) {
		ret = -ENOMEM;
		str_err = "Unable to allocate retry request";
		goto wire_accept_error;
	}
	add_iwpm_map_request(iwpm_retry_req);
wire_accept_send_ack:
	return send_iwpm_msg(form_iwpm_ack, msg_parms, recv_addr, pm_sock);
wire_accept_error:
	syslog(LOG_WARNING, "process_iwpm_wire_accept: %s.\n", str_err);
	return ret;
}

/**
 * process_iwpm_wire_reject - Process reject message from the port mapper remote peer
 * @msg_parms: the received iwpm reject message
 * @nl_sock: netlink socket to send through a message to the iwpm client
 *
 * Send notification to the iwpm client that its
 * mapping request is rejected by the remote/accepting port mapper peer
 */
static int process_iwpm_wire_reject(iwpm_msg_parms *msg_parms, int nl_sock)
{
	iwpm_mapping_request iwpm_map_req;
	iwpm_mapped_port *iwpm_port;
	struct sockaddr_storage local_addr, remote_addr;
	int not_mapped = 1;
	__u16 err_code = IWPM_REMOTE_QUERY_REJECT;
	const char *str_err;
	int ret = -EINVAL;

	copy_iwpm_sockaddr(msg_parms->address_family, NULL, &local_addr,
				&msg_parms->cpipaddr[0], NULL, &msg_parms->cpport);
	copy_iwpm_sockaddr(msg_parms->address_family, NULL, &remote_addr,
				&msg_parms->apipaddr[0], NULL, &msg_parms->apport);

	print_iwpm_sockaddr(&local_addr, "process_wire_reject: Local address",
					IWARP_PM_ALL_DBG);
	print_iwpm_sockaddr(&remote_addr, "process_wire_reject: Remote address",
					IWARP_PM_ALL_DBG);
	ret = -EINVAL;
	iwpm_port = find_iwpm_same_mapping(&local_addr, not_mapped);
	if (!iwpm_port) {
		syslog(LOG_WARNING, "process_wire_reject: Received reject for unknown mapping.\n");
		return 0;
	}
	/* make sure there is request posted */
	ret = update_iwpm_map_request(msg_parms->assochandle, &iwpm_port->local_addr,
					IWARP_PM_REQ_QUERY, &iwpm_map_req, 1);
	if (ret) {
		iwpm_debug(IWARP_PM_WIRE_DBG, "process_wire_reject: "
			"No matching mapping request (assochandle = %llu)\n",
			msg_parms->assochandle);
		return 0; /* ok when retransmission */
	}
	if (iwpm_map_req.complete)
		return 0;

	ret = send_conn_info_nlmsg(&iwpm_port->local_addr, &iwpm_map_req.remote_addr,
				&iwpm_port->mapped_addr, &iwpm_map_req.remote_addr,
				iwpm_port->owner_client, iwpm_map_req.nlmsg_type,
				iwpm_map_req.nlmsg_seq, iwpm_map_req.nlmsg_pid, err_code, nl_sock);
	if (ret) {
		str_err = "Unable to send nlmsg response";
		goto wire_reject_error;
	}
	return 0;
wire_reject_error:
	syslog(LOG_WARNING, "process_wire_reject: %s.\n", str_err);
	return ret;
}

/**
 * process_iwpm_wire_ack - Process acknowledgement from the remote port mapper peer
 * @msg_parms: received iwpm acknowledgement
 */
static int process_iwpm_wire_ack(iwpm_msg_parms *msg_parms)
{
	iwpm_mapped_port *iwpm_port;
	iwpm_mapping_request iwpm_map_req;
	struct sockaddr_storage local_mapped_addr;
	int not_mapped = 0;
	int ret;

	copy_iwpm_sockaddr(msg_parms->address_family, NULL, &local_mapped_addr,
				&msg_parms->apipaddr[0], NULL, &msg_parms->apport);
	iwpm_port = find_iwpm_mapping(&local_mapped_addr, not_mapped);
	if (!iwpm_port) {
		iwpm_debug(IWARP_PM_WIRE_DBG, "process_wire_ack: Received ack for unknown mapping.\n");
		return 0;
	}
	/* make sure there is accept for the ack */
	ret = update_iwpm_map_request(msg_parms->assochandle, &local_mapped_addr,
					IWARP_PM_REQ_ACCEPT, &iwpm_map_req, 1);
	if (ret)
		iwpm_debug(IWARP_PM_WIRE_DBG, "process_wire_ack: No matching mapping request\n");
	return 0;
}

/* Mapping info message - nlmsg attributes */
static struct nla_policy mapinfo_policy[IWPM_NLA_MAPINFO_MAX] = {
        [IWPM_NLA_MAPINFO_LOCAL_ADDR]          = { .minlen = sizeof(struct sockaddr_storage) },
        [IWPM_NLA_MAPINFO_MAPPED_ADDR]         = { .minlen = sizeof(struct sockaddr_storage) },
        [IWPM_NLA_MAPINFO_FLAGS]               = { .type = NLA_U32 }
};

/**
 * process_iwpm_mapinfo - Process a mapping info message from the port mapper client
 * @req_nlh: netlink header of the received client message
 * @client_idx: the index of the client (the index is unique for each iwpm client)
 * @nl_sock: netlink socket to send a message to the client
 *
 * In case the userspace iwarp port mapper daemon is restarted,
 * the iwpm client needs to send a record of mappings it is currently using.
 * The port mapper needs to reopen the mapped ports used by the client.
 */
static int process_iwpm_mapinfo(struct nlmsghdr *req_nlh, int client_idx, int nl_sock)
{
	iwpm_mapped_port *iwpm_port = NULL;
	struct sockaddr_storage *local_addr, *local_mapped_addr;
	struct nlattr *nltb [IWPM_NLA_MAPINFO_MAX] = {};
	int not_mapped = 1;
	__u16 err_code = 0;
	const char *msg_type = "Mapping Info Msg";
	const char *str_err = "";
	int ret = -EINVAL;
	__u32 flags;
	int max = IWPM_NLA_MAPINFO_MAX;

	if (iwpm_version != IWPM_UABI_VERSION)
		max--;
	if (parse_iwpm_nlmsg(req_nlh, max, mapinfo_policy, nltb, msg_type)) {
		err_code = IWPM_INVALID_NLMSG_ERR;
		str_err = "Received Invalid nlmsg";
		goto process_mapinfo_error;
	}
	local_addr = (struct sockaddr_storage *)nla_data(nltb[IWPM_NLA_MAPINFO_LOCAL_ADDR]);
	local_mapped_addr = (struct sockaddr_storage *)nla_data(nltb[IWPM_NLA_MAPINFO_MAPPED_ADDR]);
	flags = nltb[IWPM_NLA_MAPINFO_FLAGS] ? nla_get_u32(nltb[IWPM_NLA_MAPINFO_FLAGS]) : 0;

	iwpm_port = find_iwpm_mapping(local_addr, not_mapped);
	if (iwpm_port) {
		/* Can be safely ignored, if the mapinfo is exactly the same,
 		 * because the client will provide all the port information it has and
 		 * it could have started using the port mapper service already */
		if (check_same_sockaddr(&iwpm_port->local_addr, local_addr) &&
				check_same_sockaddr(&iwpm_port->mapped_addr, local_mapped_addr))
			goto process_mapinfo_exit;

		/* partial duplicates matching wcard ip address aren't allowed as well */
		err_code = IWPM_DUPLICATE_MAPPING_ERR;
		str_err = "Duplicate mapped port";
		goto process_mapinfo_error;
	}
	iwpm_port = reopen_iwpm_mapped_port(local_addr, local_mapped_addr, client_idx, flags);
	if (!iwpm_port) {
		err_code = IWPM_CREATE_MAPPING_ERR;
		str_err = "Unable to create new mapping";
		goto process_mapinfo_error;
	}
	/* add the new mapping to the list */
	add_iwpm_mapped_port(iwpm_port);
process_mapinfo_exit:
	mapinfo_num_list[client_idx]++;
	return 0;
process_mapinfo_error:
	syslog(LOG_WARNING, "process_mapinfo: %s.\n", str_err);
	if (err_code) {
		/* send error message to the client */
		send_iwpm_error_msg(req_nlh->nlmsg_seq, err_code, client_idx, nl_sock);
	}
	return ret;
}

/* Mapping info message count - nlmsg attributes */
static struct nla_policy mapinfo_count_policy[IWPM_NLA_MAPINFO_SEND_MAX] = {
        [IWPM_NLA_MAPINFO_SEQ]       =  { .type = NLA_U32 },
        [IWPM_NLA_MAPINFO_SEND_NUM]  =  { .type = NLA_U32 }
};

/**
 * process_iwpm_mapinfo_count - Process mapinfo count message
 * @req_nlh: netlink header of the received message from the client
 * @client_idx: the index of the client
 * @nl_sock: netlink socket to send a message to the client
 *
 * Mapinfo count message is a mechanism for the port mapper and the client to
 * synchronize on the number of mapinfo messages which were sucessfully exchanged and processed
 */
static int process_iwpm_mapinfo_count(struct nlmsghdr *req_nlh, int client_idx, int nl_sock)
{
	struct nlattr *nltb [IWPM_NLA_MAPINFO_SEND_MAX];
	struct nl_msg *resp_nlmsg = NULL;
	const char *msg_type = "Number of Mappings Msg";
	__u32 map_count;
	__u16 err_code = 0;
	const char *str_err = "";
	int ret = -EINVAL;

	if (parse_iwpm_nlmsg(req_nlh, IWPM_NLA_MAPINFO_SEND_MAX,
					mapinfo_count_policy, nltb, msg_type)) {
		str_err = "Received Invalid nlmsg";
		err_code = IWPM_INVALID_NLMSG_ERR;
		goto mapinfo_count_error;
	}
	map_count = nla_get_u32(nltb[IWPM_NLA_MAPINFO_SEND_NUM]);
	if (map_count != mapinfo_num_list[client_idx])
		iwpm_debug(IWARP_PM_NETLINK_DBG, "get_mapinfo_count: Client (idx = %d) "
				"send mapinfo count = %u processed mapinfo count = %u.\n",
				client_idx, map_count, mapinfo_num_list[client_idx]);

	resp_nlmsg = create_iwpm_nlmsg(req_nlh->nlmsg_type, client_idx);
	if (!resp_nlmsg) {
		str_err = "Unable to create nlmsg response";
		ret = -ENOMEM;
		goto mapinfo_count_error;
	}
	str_err = "Invalid nlmsg attribute";
	if ((ret = nla_put_u32(resp_nlmsg, IWPM_NLA_MAPINFO_SEQ, req_nlh->nlmsg_seq)))
		goto mapinfo_count_free_error;
	if ((ret = nla_put_u32(resp_nlmsg, IWPM_NLA_MAPINFO_SEND_NUM, map_count)))
		goto mapinfo_count_free_error;
	if ((ret = nla_put_u32(resp_nlmsg, IWPM_NLA_MAPINFO_ACK_NUM,
						mapinfo_num_list[client_idx])))
		goto mapinfo_count_free_error;

	if ((ret = send_iwpm_nlmsg(nl_sock, resp_nlmsg, req_nlh->nlmsg_pid))) {
		str_err = "Unable to send nlmsg response";
		goto mapinfo_count_free_error;
	}
	nlmsg_free(resp_nlmsg);
	return 0;
mapinfo_count_free_error:
	if (resp_nlmsg)
		nlmsg_free(resp_nlmsg);
mapinfo_count_error:
	syslog(LOG_WARNING, "process_mapinfo_count: %s.\n", str_err);
	if (err_code) {
		/* send error message to the client */
		send_iwpm_error_msg(req_nlh->nlmsg_seq, err_code, client_idx, nl_sock);
	}
	return ret;
}

/**
 * send_iwpm_error_msg - Send error message to the iwpm client
 * @seq: last received netlink message sequence
 * @err_code: used to differentiante between errors
 * @client_idx: the index of the client
 * @nl_sock: netlink socket to send a message to the client
 */
static int send_iwpm_error_msg(__u32 seq, __u16 err_code, int client_idx, int nl_sock)
{
	struct nl_msg *resp_nlmsg;
	__u16 nlmsg_type;
	const char *str_err = "";
	int ret;

	nlmsg_type = RDMA_NL_GET_TYPE(client_idx, RDMA_NL_IWPM_HANDLE_ERR);
	resp_nlmsg = create_iwpm_nlmsg(nlmsg_type, client_idx);
	if (!resp_nlmsg) {
		ret = -ENOMEM;
		str_err = "Unable to create nlmsg response";
		goto send_error_msg_exit;
	}
	str_err = "Invalid nlmsg attribute";
	if ((ret = nla_put_u32(resp_nlmsg, IWPM_NLA_ERR_SEQ, seq)))
		goto send_error_msg_exit;
	if ((ret = nla_put_u16(resp_nlmsg, IWPM_NLA_ERR_CODE, err_code)))
		goto send_error_msg_exit;

	if ((ret = send_iwpm_nlmsg(nl_sock, resp_nlmsg, 0))) {
		str_err = "Unable to send nlmsg response";
		goto send_error_msg_exit;
	}
	nlmsg_free(resp_nlmsg);
	return 0;
send_error_msg_exit:
	if (resp_nlmsg)
		nlmsg_free(resp_nlmsg);
	syslog(LOG_WARNING, "send_iwpm_error_msg: %s (ret = %d).\n", str_err, ret);
	return ret;
}

/* Hello message - nlmsg attributes */
static struct nla_policy hello_policy[IWPM_NLA_HELLO_MAX] = {
        [IWPM_NLA_HELLO_ABI_VERSION]  =  { .type = NLA_U16 }
};

/**
 * process_iwpm_hello - Process mapinfo count message
 * @req_nlh: netlink header of the received message from the client
 * @client_idx: the index of the client
 * @nl_sock: netlink socket to send a message to the client
 *
 * Mapinfo count message is a mechanism for the port mapper and the client to
 * synchronize on the number of mapinfo messages which were sucessfully exchanged and processed
 */
static int process_iwpm_hello(struct nlmsghdr *req_nlh, int client_idx, int nl_sock)
{
	struct nlattr *nltb [IWPM_NLA_HELLO_MAX];
	const char *msg_type = "Hello Msg";
	__u16 abi_version;
	__u16 err_code = 0;
	const char *str_err = "";
	int ret = -EINVAL;

	if (req_nlh->nlmsg_type == NLMSG_ERROR) {
		abi_version = IWPM_UABI_VERSION_MIN;
	} else {
		if (parse_iwpm_nlmsg(req_nlh, IWPM_NLA_HELLO_MAX,
						hello_policy, nltb, msg_type)) {
			str_err = "Received Invalid nlmsg";
			err_code = IWPM_INVALID_NLMSG_ERR;
			goto hello_error;
		}
		abi_version = nla_get_u16(nltb[IWPM_NLA_HELLO_ABI_VERSION]);
	}
	if (abi_version > IWPM_UABI_VERSION) {
		str_err = "UABI Version mismatch";
		err_code = IWPM_VERSION_MISMATCH_ERR;
		goto hello_error;
	}
	iwpm_version = abi_version;
	iwpm_debug(IWARP_PM_NETLINK_DBG, "process_iwpm_hello: using abi_version %u\n", iwpm_version);

	send_iwpm_mapinfo_request(nl_sock, RDMA_NL_IWCM);
	if (iwpm_version == 3) {
		/* Legacy RDMA_NL_C4IW for old kernels */
		send_iwpm_mapinfo_request(nl_sock, RDMA_NL_IWCM+1);
	}
	return 0;
hello_error:
	syslog(LOG_WARNING, "process_iwpm_hello: %s.\n", str_err);
	if (err_code) {
		/* send error message to the client */
		send_iwpm_error_msg(req_nlh->nlmsg_seq, err_code, client_idx, nl_sock);
	}
	return ret;
}

/**
 * process_iwpm_netlink_msg - Dispatch received netlink messages
 * @nl_sock: netlink socket to read the messages from
 */
static int process_iwpm_netlink_msg(int nl_sock)
{
	char *recv_buffer = NULL;
	struct nlmsghdr *nlh;
	struct sockaddr_nl src_addr;
	int len, type, client_idx, op;
	socklen_t src_addr_len;
	const char *str_err = "";
	int ret = 0;

	recv_buffer = malloc(NLMSG_SPACE(IWARP_PM_RECV_PAYLOAD));
	if (!recv_buffer) {
		ret = -ENOMEM;
		str_err = "Unable to allocate receive socket buffer";
		goto process_netlink_msg_exit;
	}
	/* receive a new message */
	nlh = (struct nlmsghdr *)recv_buffer;
	memset(nlh, 0, NLMSG_SPACE(IWARP_PM_RECV_PAYLOAD));
	memset(&src_addr, 0, sizeof(src_addr));

	src_addr_len = sizeof(src_addr);
	len = recvfrom(nl_sock, (void *)nlh, NLMSG_SPACE(IWARP_PM_RECV_PAYLOAD), 0,
			(struct sockaddr *)&src_addr, &src_addr_len);
	if (len <= 0) {
		ret = -errno;
		str_err = "Unable to receive data from netlink socket";
		goto process_netlink_msg_exit;
	}
	/* loop for multiple netlink messages packed together */
	while (NLMSG_OK(nlh, len) != 0) {
		if (nlh->nlmsg_type == NLMSG_DONE) {
			goto process_netlink_msg_exit;
		}

		type = nlh->nlmsg_type;
		client_idx = RDMA_NL_GET_CLIENT(type);
		if (type == NLMSG_ERROR) {

			/* RDMA_NL_IWCM HELLO error indicates V3 kernel */
			if (nlh->nlmsg_seq == 0) {
				ret = process_iwpm_hello(nlh, client_idx, nl_sock);
			} else {
				iwpm_debug(IWARP_PM_NETLINK_DBG, "process_netlink_msg: "
					"Netlink error message seq = %u\n", nlh->nlmsg_seq);
			}
			goto process_netlink_msg_exit;
		}
		op = RDMA_NL_GET_OP(type);
		iwpm_debug(IWARP_PM_NETLINK_DBG, "process_netlink_msg: Received a new message: "
				"opcode = %u client idx = %u, client pid = %u,"
				" msg seq = %u, type = %u, length = %u.\n",
				op, client_idx, nlh->nlmsg_pid, nlh->nlmsg_seq, type, len);

		if (client_idx >= IWARP_PM_MAX_CLIENTS) {
			ret = -EINVAL;
			str_err = "Invalid client index";
			goto process_netlink_msg_exit;
		}
		switch (op) {
		case RDMA_NL_IWPM_REG_PID:
			str_err = "Register Pid request";
			ret = process_iwpm_register_pid(nlh, client_idx, nl_sock);
			break;
		case RDMA_NL_IWPM_ADD_MAPPING:
			str_err = "Add Mapping request";
			if (!client_list[client_idx].valid) {
				ret = -EINVAL;
				goto process_netlink_msg_exit;
			}
			ret = process_iwpm_add_mapping(nlh, client_idx, nl_sock);
			break;
		case RDMA_NL_IWPM_QUERY_MAPPING:
			str_err = "Query Mapping request";
			if (!client_list[client_idx].valid) {
				ret = -EINVAL;
				goto process_netlink_msg_exit;
			}
			ret = process_iwpm_query_mapping(nlh, client_idx, nl_sock);
			break;
		case RDMA_NL_IWPM_REMOVE_MAPPING:
			str_err = "Remove Mapping request";
			ret = process_iwpm_remove_mapping(nlh, client_idx, nl_sock);
			break;
		case RDMA_NL_IWPM_MAPINFO:
			ret = process_iwpm_mapinfo(nlh, client_idx, nl_sock);
			break;
		case RDMA_NL_IWPM_MAPINFO_NUM:
			ret = process_iwpm_mapinfo_count(nlh, client_idx, nl_sock);
			break;
		case RDMA_NL_IWPM_HELLO:
			ret = process_iwpm_hello(nlh, client_idx, nl_sock);
			break;
		default:
			str_err = "Netlink message with invalid opcode";
			ret = -1;
			break;
		}
		nlh = NLMSG_NEXT(nlh, len);
		if (ret)
			goto process_netlink_msg_exit;
	}

process_netlink_msg_exit:
	if (recv_buffer)
		free(recv_buffer);
	if (ret)
		syslog(LOG_WARNING, "process_netlink_msg: %s error (ret = %d).\n", str_err, ret);
	return ret;
}

/**
 * process_iwpm_msg - Dispatch iwpm wire messages, sent by the remote peer
 * @pm_sock: socket handle to read the messages from
 */
static int process_iwpm_msg(int pm_sock)
{
	iwpm_msg_parms msg_parms;
	struct sockaddr_storage recv_addr;
	iwpm_wire_msg recv_buffer; /* received message */
	int bytes_recv, ret = 0;
	int max_bytes_send = IWARP_PM_MESSAGE_SIZE + IWPM_IPADDR_SIZE;
	socklen_t recv_addr_len = sizeof(recv_addr);

	bytes_recv = recvfrom(pm_sock, &recv_buffer, max_bytes_send, 0,
			      (struct sockaddr *)&recv_addr, &recv_addr_len);

	if (bytes_recv != IWARP_PM_MESSAGE_SIZE && bytes_recv != max_bytes_send) {
		syslog(LOG_WARNING,
			"process_iwpm_msg: Unable to receive data from PM socket. %s.\n",
					strerror(errno));
		ret = -errno;
		goto process_iwpm_msg_exit;
	}
	parse_iwpm_msg(&recv_buffer, &msg_parms);

	switch (msg_parms.mt) {
	case IWARP_PM_MT_REQ:
		iwpm_debug(IWARP_PM_WIRE_DBG, "process_iwpm_msg: Received Request message.\n");
		ret = process_iwpm_wire_request(&msg_parms, netlink_sock, &recv_addr, pm_sock);
		break;
	case IWARP_PM_MT_ACK:
		iwpm_debug(IWARP_PM_WIRE_DBG, "process_iwpm_msg: Received Acknowledgement.\n");
		ret = process_iwpm_wire_ack(&msg_parms);
		break;
	case IWARP_PM_MT_ACC:
		iwpm_debug(IWARP_PM_WIRE_DBG, "process_iwpm_msg: Received Accept message.\n");
		ret = process_iwpm_wire_accept(&msg_parms, netlink_sock, &recv_addr, pm_sock);
		break;
	case IWARP_PM_MT_REJ:
		iwpm_debug(IWARP_PM_WIRE_DBG, "process_iwpm_msg: Received Reject message.\n");
		ret = process_iwpm_wire_reject(&msg_parms, netlink_sock);
		break;
	default:
		syslog(LOG_WARNING, "process_iwpm_msg: Received Invalid message type = %u.\n",
				msg_parms.mt);
	}
process_iwpm_msg_exit:
	return ret;
}

/**
 * send_iwpm_hello - Notify the client that the V4 iwarp port mapper is available
 * @nl_sock: netlink socket to send a message to the client
 *
 * Send a HELLO message including the ABI_VERSION supported by iwpmd.  If the
 * response is an ERROR message, then we know the kernel driver is < V4, so we
 * drop back to the V3 protocol.  If the kernel is >= V4, then it will reply
 * with its ABI Version.  The response is handled in iwarp_port_mapper().  Once
 * the ABI version is negotiatied, iwpmd will send a mapinfo request to get any
 * current mappings, using the correct ABI version. This allows working with
 * V3 kernels.
 */
static int send_iwpm_hello(int nl_sock)
{
	struct nl_msg *req_nlmsg;
	const char *str_err;
	__u16 nlmsg_type;
	int ret;

	nlmsg_type = RDMA_NL_GET_TYPE(RDMA_NL_IWCM, RDMA_NL_IWPM_HELLO);
	req_nlmsg = create_iwpm_nlmsg(nlmsg_type, RDMA_NL_IWCM);
	if (!req_nlmsg) {
		ret = -ENOMEM;
		str_err = "Unable to create nlmsg request";
		goto send_hello_error;
	}
	str_err = "Invalid nlmsg attribute";
	if ((ret = nla_put_u16(req_nlmsg, IWPM_NLA_HELLO_ABI_VERSION, iwpm_version)))
		goto send_hello_error;

	if ((ret = send_iwpm_nlmsg(nl_sock, req_nlmsg, 0))) {
		str_err = "Unable to send nlmsg response";
		goto send_hello_error;
	}
	nlmsg_free(req_nlmsg);
	return 0;
send_hello_error:
	if (req_nlmsg)
		nlmsg_free(req_nlmsg);
	syslog(LOG_WARNING, "send_hello_request: %s ret = %d.\n", str_err, ret);
	return ret;
}

/**
 * send_iwpm_mapinfo_request - Notify the client that the iwarp port mapper is available
 * @nl_sock: netlink socket to send a message to the client
 * @client - client to receive the message
 */
static int send_iwpm_mapinfo_request(int nl_sock, int client)
{
	struct nl_msg *req_nlmsg;
	__u16 nlmsg_type;
	const char *str_err;
	int ret;

	nlmsg_type = RDMA_NL_GET_TYPE(client, RDMA_NL_IWPM_MAPINFO);
	req_nlmsg = create_iwpm_nlmsg(nlmsg_type, client);
	if (!req_nlmsg) {
		ret = -ENOMEM;
		str_err = "Unable to create nlmsg request";
		goto send_mapinfo_error;
	}
	str_err = "Invalid nlmsg attribute";
	if ((ret = nla_put_string(req_nlmsg, IWPM_NLA_MAPINFO_ULIB_NAME, iwpm_ulib_name)))
		goto send_mapinfo_error;

	if ((ret = nla_put_u16(req_nlmsg, IWPM_NLA_MAPINFO_ULIB_VER, iwpm_version)))
		goto send_mapinfo_error;

	if ((ret = send_iwpm_nlmsg(nl_sock, req_nlmsg, 0))) {
		str_err = "Unable to send nlmsg response";
		goto send_mapinfo_error;
	}
	nlmsg_free(req_nlmsg);
	return 0;
send_mapinfo_error:
	if (req_nlmsg)
		nlmsg_free(req_nlmsg);
	syslog(LOG_WARNING, "send_mapinfo_request: %s ret = %d.\n", str_err, ret);
	return ret;
}

/** iwpm_cleanup - Close socket handles and free mapped ports */
static void iwpm_cleanup(void)
{
	free_iwpm_mapped_ports();

        destroy_iwpm_socket(netlink_sock);
        destroy_iwpm_socket(pmv6_client_sock);
        destroy_iwpm_socket(pmv6_sock);
        destroy_iwpm_socket(pmv4_client_sock);
        destroy_iwpm_socket(pmv4_sock);
	/* close up logging */
	closelog();
}

/**
 * iwarp_port_mapper - Distribute work orders for processing different types of iwpm messages
 */
static int iwarp_port_mapper(void)
{
	fd_set select_fdset; /* read fdset */
	struct timeval select_timeout;
	int select_rc, max_sock = 0, ret = 0;

	if (pmv4_sock > max_sock)
		max_sock = pmv4_sock;
	if (pmv6_sock > max_sock)
		max_sock = pmv6_sock;
	if (netlink_sock > max_sock)
		max_sock = netlink_sock;
	if (pmv4_client_sock > max_sock)
		max_sock = pmv4_client_sock;
	if (pmv6_client_sock > max_sock)
		max_sock = pmv6_client_sock;

	/* poll a set of sockets */
	do {
		do {
			if (print_mappings) {
				print_iwpm_mapped_ports();
				print_mappings = 0;
			}
			/* initialize the file sets for select */
			FD_ZERO(&select_fdset);
			/* add the UDP and Netlink sockets to the file set */
			FD_SET(pmv4_sock, &select_fdset);
			FD_SET(pmv4_client_sock, &select_fdset);
			FD_SET(pmv6_sock, &select_fdset);
			FD_SET(pmv6_client_sock, &select_fdset);
			FD_SET(netlink_sock, &select_fdset);

			/* set the timeout for select */
			select_timeout.tv_sec = 10;
			select_timeout.tv_usec = 0;
			/* timeout is an upper bound of time elapsed before select returns */
			select_rc = select(max_sock + 1, &select_fdset, NULL, NULL, &select_timeout);
		} while (select_rc == 0);
		/* select_rc is the number of fds ready for IO ( IO won't block) */

		if (select_rc == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_WARNING, "iwarp_port_mapper: Select failed (%s).\n", strerror(errno));
			ret = -errno;
			goto iwarp_port_mapper_exit;
		}

		if (FD_ISSET(pmv4_sock, &select_fdset)) {
			ret = process_iwpm_msg(pmv4_sock);
		}

		if (FD_ISSET(pmv6_sock, &select_fdset)) {
			ret = process_iwpm_msg(pmv6_sock);
		}

		if (FD_ISSET(pmv4_client_sock, &select_fdset)) {
			ret = process_iwpm_msg(pmv4_client_sock);
		}

		if (FD_ISSET(pmv6_client_sock, &select_fdset)) {
			ret = process_iwpm_msg(pmv6_client_sock);
		}

		if (FD_ISSET(netlink_sock, &select_fdset)) {
			ret = process_iwpm_netlink_msg(netlink_sock);
		}
	} while (1);

iwarp_port_mapper_exit:
	return ret;
}

/**
 * daemonize_iwpm_server - Make iwarp port mapper a daemon process
 */
static void daemonize_iwpm_server(void)
{
	if (daemon(0, 0) != 0) {
		syslog(LOG_ERR, "Failed to daemonize\n");
		exit(EXIT_FAILURE);
	}

	syslog(LOG_WARNING, "daemonize_iwpm_server: Starting iWarp Port Mapper V%d process\n",
				iwpm_version);
}

int main(int argc, char *argv[])
{
	FILE *fp;
	int c;
	int ret = EXIT_FAILURE;
	bool systemd = false;

	while (1) {
		static const struct option long_opts[] = {
			{"systemd", 0, NULL, 's'},
			{}
		};

		c = getopt_long(argc, argv, "fs", long_opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 's':
			systemd = true;
			break;
		default:
			break;

		}
	}

	openlog(NULL, LOG_NDELAY | LOG_CONS | LOG_PID, LOG_DAEMON);

	if (!systemd)
		daemonize_iwpm_server();
	umask(0); /* change file mode mask */

	fp = fopen(IWPM_CONFIG_FILE, "r");
	if (fp) {
		parse_iwpm_config(fp);
		fclose(fp);
	}
	memset(client_list, 0, sizeof(client_list));

	pmv4_sock = create_iwpm_socket_v4(IWARP_PM_PORT);
	if (pmv4_sock < 0)
		goto error_exit_v4;

	pmv4_client_sock = create_iwpm_socket_v4(0);
	if (pmv4_client_sock < 0)
		goto error_exit_v4_client;

	pmv6_sock = create_iwpm_socket_v6(IWARP_PM_PORT);
	if (pmv6_sock < 0)
		goto error_exit_v6;

	pmv6_client_sock = create_iwpm_socket_v6(0);
	if (pmv6_client_sock < 0)
		goto error_exit_v6_client;

	netlink_sock = create_netlink_socket();
	if (netlink_sock < 0)
		goto error_exit_nl;

	signal(SIGHUP, iwpm_signal_handler);
	signal(SIGTERM, iwpm_signal_handler);
	signal(SIGUSR1, iwpm_signal_handler);

	pthread_cond_init(&cond_req_complete, NULL);
	pthread_cond_init(&cond_pending_msg, NULL);

	ret = pthread_create(&map_req_thread, NULL, iwpm_mapping_reqs_handler, NULL);
	if (ret)
		goto error_exit;

	ret = pthread_create(&pending_msg_thread, NULL, iwpm_pending_msgs_handler, NULL);
	if (ret)
		goto error_exit;

	ret = send_iwpm_hello(netlink_sock);
	if (ret)
		goto error_exit;

	if (systemd)
		sd_notify(0, "READY=1");

	iwarp_port_mapper(); /* start iwarp port mapper process */

	free_iwpm_mapped_ports();
	closelog();

error_exit:
	destroy_iwpm_socket(netlink_sock);
error_exit_nl:
	destroy_iwpm_socket(pmv6_client_sock);
error_exit_v6_client:
	destroy_iwpm_socket(pmv6_sock);
error_exit_v6:
	destroy_iwpm_socket(pmv4_client_sock);
error_exit_v4_client:
	destroy_iwpm_socket(pmv4_sock);
error_exit_v4:
	syslog(LOG_WARNING, "main: Couldn't start iWarp Port Mapper.\n");
	return ret;
}
