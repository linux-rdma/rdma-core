/*
 * Copyright (c) 2013 Intel Corporation.  All rights reserved.
 * Copyright (c) Nvidia Corporation.  All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdatomic.h>
#include <netinet/tcp.h>
#include <ccan/container_of.h>
#include <inttypes.h>
#include <pthread.h>
#include <rdma/rdma_cma.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include "common.h"

#define SRV_MAX_DISCONNECT_TIME_US 60000000

static struct rdma_addrinfo hints, *rai;
static struct addrinfo *ai;
static struct rdma_event_channel *channel;
static struct oob_root oob_root;
static int oob_up = -1;
static const char *oob_port = "7471";
static char *ctrl_addr;
static char *src_addr;
static int timeout = 2000;
static int retries = 2;
static uint32_t base_qpn = 1000;
static _Atomic(uint32_t) cur_qpn;
static uint32_t mimic_qp_delay;
static bool mimic;

enum step {
	STEP_FULL_CONNECT,
	STEP_CREATE_ID,
	STEP_BIND,
	STEP_RESOLVE_ADDR,
	STEP_RESOLVE_ROUTE,
	STEP_CREATE_QP,
	STEP_INIT_QP_ATTR,
	STEP_INIT_QP,
	STEP_RTR_QP_ATTR,
	STEP_RTR_QP,
	STEP_RTS_QP_ATTR,
	STEP_RTS_QP,
	STEP_CONNECT,
	STEP_ESTABLISH,
	STEP_DISCONNECT,
	STEP_DESTROY_ID,
	STEP_DESTROY_QP,
	STEP_CNT
};

static const char *step_str[] = {
	"full connect",
	"create id",
	"bind addr",
	"resolve addr",
	"resolve route",
	"create qp",
	"init qp attr",
	"init qp",
	"rtr qp attr",
	"rtr qp",
	"rts qp attr",
	"rts qp",
	"cm connect",
	"establish",
	"disconnect",
	"destroy id",
	"destroy qp"
};

enum peer_role {
	role_connect,
	role_listen,
};

struct peer_info {
	struct sockaddr_storage sa;
	enum peer_role role;
};

struct conn {
	struct work_item work;
	struct rdma_cm_id *id;
	int sock;
	uint32_t peer_id;

	struct ibv_qp *qp;
	enum ibv_qp_state next_qps;
	enum step next_step;

	uint64_t times[STEP_CNT][2];
	int retries;
	bool server_disconnected;
};

static struct work_queue wq;

static bool is_root;
static enum peer_role role = role_connect;
static uint32_t num_peers = 2;
static uint32_t num_listeners;
static struct peer_info *peers;

static struct conn *conns;
static int conn_index;
static uint64_t times[STEP_CNT][2];
static uint32_t num_conns = 100;
static int num_threads = 1;
static _Atomic(int) disc_events;

static _Atomic(int) completed[STEP_CNT];

static struct ibv_pd *pd;
static struct ibv_cq *cq;

#define start_perf(c, s)	do { (c)->times[s][0] = gettime_us(); } while (0)
#define end_perf(c, s)		do { (c)->times[s][1] = gettime_us(); } while (0)
#define start_time(s)		do { times[s][0] = gettime_us(); } while (0)
#define end_time(s)		do { times[s][1] = gettime_us(); } while (0)


static void show_perf(void)
{
	uint64_t c, diff, max[STEP_CNT], min[STEP_CNT], sum[STEP_CNT];
	int i;

	for (i = 0; i < STEP_CNT; i++) {
		sum[i] = 0;
		max[i] = 0;
		min[i] = UINT32_MAX;
		for (c = 0; c < num_conns; c++) {
			if (conns[c].times[i][0] && conns[c].times[i][1]) {
				diff = (uint32_t) (conns[c].times[i][1] -
						   conns[c].times[i][0]);
				sum[i] += diff;
				if (diff > max[i])
					max[i] = diff;
				if (diff < min[i])
					min[i] = diff;
			}
		}
		/* Print 0 if we have no data */
		if (min[i] == UINT32_MAX)
			min[i] = 0;
	}

	/* Reporting the 'sum' of the full connect is meaningless */
	sum[STEP_FULL_CONNECT] = 0;

	if (atomic_load(&cur_qpn) == 0)
		printf("qp_conn        %10u\n", num_conns);
	else
		printf("cm_conn        %10u\n", num_conns);
	printf("threads        %10d\n", num_threads);

	printf("step             avg/conn  total(us)    us/conn    sum(us)    max(us)    min(us)\n");
	for (i = 0; i < STEP_CNT; i++) {
		diff = (uint64_t) (times[i][1] - times[i][0]);

		printf("%-13s  %10" PRIu64 " %10" PRIu64 " %10" PRIu64
		       " %10" PRIu64 " %10" PRIu64 " %10" PRIu64 "\n",
		       step_str[i], diff / num_conns, diff,
		       sum[i] / num_conns, sum[i], max[i], min[i]);
	}
}

static void sock_listen(int *listen_sock, int backlog)
{
	struct addrinfo aih = {};
	int optval = 1;
	int ret;

	aih.ai_family = AF_INET;
	aih.ai_socktype = SOCK_STREAM;
	aih.ai_flags = AI_PASSIVE;
	ret = getaddrinfo(src_addr, oob_port, &aih, &ai);
	if (ret) {
		perror("getaddrinfo");
		exit(EXIT_FAILURE);
	}

	*listen_sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (*listen_sock < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	ret = setsockopt(*listen_sock, SOL_SOCKET, SO_REUSEADDR,
			 (char *) &optval, sizeof(optval));
	if (ret) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	ret = bind(*listen_sock, ai->ai_addr, ai->ai_addrlen);
	if (ret) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	ret = listen(*listen_sock, backlog);
	if (ret) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(ai);
}

static void sock_server(void)
{
	int listen_sock;
	uint32_t i;

	printf("Server baseline socket setup\n");
	sock_listen(&listen_sock, (int) num_conns);

	printf("Accept sockets\n");
	for (i = 0; i < num_conns; i++) {
		conns[i].sock = accept(listen_sock, NULL, NULL);
		if (conns[i].sock < 0) {
			perror("accept");
			exit(EXIT_FAILURE);
		}

		if (i == 0)
			start_time(STEP_FULL_CONNECT);
	}
	end_time(STEP_FULL_CONNECT);

	printf("Closing sockets\n");
	start_time(STEP_DESTROY_ID);
	for (i = 0; i < num_conns; i++)
		close(conns[i].sock);
	end_time(STEP_DESTROY_ID);
	close(listen_sock);

	printf("Server baseline socket results:\n");
	show_perf();
}

static void create_sock(struct work_item *item)
{
	struct conn *c = container_of(item, struct conn, work);

	start_perf(c, STEP_CREATE_ID);
	c->sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (c->sock < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	end_perf(c, STEP_CREATE_ID);
	atomic_fetch_add(&completed[STEP_CREATE_ID], 1);
}

static void connect_sock(struct work_item *item)
{
	struct conn *c = container_of(item, struct conn, work);
	int ret;

	start_perf(c, STEP_CONNECT);
	ret = connect(c->sock, ai->ai_addr, ai->ai_addrlen);
	if (ret) {
		perror("connect");
		exit(EXIT_FAILURE);
	}
	end_perf(c, STEP_CONNECT);
	atomic_fetch_add(&completed[STEP_CONNECT], 1);
}

static void sock_client(void)
{
	uint32_t i;
	int ret;

	printf("Client baseline socket setup\n");
	ret = getaddrinfo(ctrl_addr, oob_port, NULL, &ai);
	if (ret) {
		perror("getaddrinfo");
		exit(EXIT_FAILURE);
	}

	start_time(STEP_FULL_CONNECT);

	printf("Creating sockets\n");
	start_time(STEP_CREATE_ID);
	for (i = 0; i < num_conns; i++)
		wq_insert(&wq, &conns[i].work, create_sock);

	while (atomic_load(&completed[STEP_CREATE_ID]) < num_conns)
		sched_yield();
	end_time(STEP_CREATE_ID);

	printf("Connecting sockets\n");
	start_time(STEP_CONNECT);
	for (i = 0; i < num_conns; i++)
		wq_insert(&wq, &conns[i].work, connect_sock);

	while (atomic_load(&completed[STEP_CONNECT]) < num_conns)
		sched_yield();
	end_time(STEP_CONNECT);

	end_time(STEP_FULL_CONNECT);

	printf("Closing sockets\n");
	start_time(STEP_DESTROY_ID);
	for (i = 0; i < num_conns; i++)
		close(conns[i].sock);
	end_time(STEP_DESTROY_ID);

	freeaddrinfo(ai);

	printf("Client baseline socket results:\n");
	show_perf();
}

static inline bool need_verbs(void)
{
	return pd == NULL;
}

static void open_verbs(struct rdma_cm_id *id)
{
	printf("\tAllocating verbs resources\n");
	pd = ibv_alloc_pd(id->verbs);
	if (!pd) {
		perror("ibv_alloc_pd");
		exit(EXIT_FAILURE);
	}

	cq = ibv_create_cq(id->verbs, 1, NULL, NULL, 0);
	if (!cq) {
		perror("ibv_create_cq");
		exit(EXIT_FAILURE);
	}
}

static pthread_mutex_t qp_mutex = PTHREAD_MUTEX_INITIALIZER;

static void create_qp(struct work_item *item)
{
	struct conn *c = container_of(item, struct conn, work);
	struct ibv_qp_init_attr attr;

	pthread_mutex_lock(&qp_mutex);
	if (need_verbs())
		open_verbs(c->id);
	pthread_mutex_unlock(&qp_mutex);

	attr.qp_context = c;
	attr.send_cq = cq;
	attr.recv_cq = cq;
	attr.srq = NULL;
	attr.qp_type = IBV_QPT_RC;
	attr.sq_sig_all = 1;

	attr.cap.max_send_wr = 1;
	attr.cap.max_recv_wr = 1;
	attr.cap.max_send_sge = 1;
	attr.cap.max_recv_sge = 1;
	attr.cap.max_inline_data = 0;

	start_perf(c, STEP_CREATE_QP);
	if (atomic_load(&cur_qpn) == 0) {
		c->qp = ibv_create_qp(pd, &attr);
		if (!c->qp) {
			perror("ibv_create_qp");
			exit(EXIT_FAILURE);
		}
	} else {
		sleep_us(mimic_qp_delay);
	}
	end_perf(c, STEP_CREATE_QP);
	atomic_fetch_add(&completed[STEP_CREATE_QP], 1);
}

static void
modify_qp(struct conn *c, enum ibv_qp_state state, enum step attr_step)
{
	struct ibv_qp_attr attr;
	int mask, ret;

	attr.qp_state = state;
	start_perf(c, attr_step);
	ret = rdma_init_qp_attr(c->id, &attr, &mask);
	if (ret) {
		perror("rdma_init_qp_attr");
		exit(EXIT_FAILURE);
	}
	end_perf(c, attr_step++);

	start_perf(c, attr_step);
	if (c->qp) {
		ret = ibv_modify_qp(c->qp, &attr, mask);
		if (ret) {
			perror("ibv_modify_qp");
			exit(EXIT_FAILURE);

		}
	} else {
		sleep_us(mimic_qp_delay);
	}
	end_perf(c, attr_step);
	atomic_fetch_add(&completed[attr_step], 1);
}

static void modify_qp_work(struct work_item *item)
{
	struct conn *c = container_of(item, struct conn, work);

	modify_qp(c, c->next_qps, c->next_step);
}

static void init_conn_param(struct conn *c, struct rdma_conn_param *param)
{
	param->private_data = rai->ai_connect;
	param->private_data_len = rai->ai_connect_len;
	param->responder_resources = 1;
	param->initiator_depth = 1;
	param->flow_control = 0;
	param->retry_count = 0;
	param->rnr_retry_count = 0;
	param->srq = 0;
	param->qp_num = c->qp ? c->qp->qp_num : atomic_fetch_add(&cur_qpn, 1);
}

static void connect_qp(struct conn *c)
{
	struct rdma_conn_param conn_param;
	int ret;

	init_conn_param(c, &conn_param);

	start_perf(c, STEP_CONNECT);
	ret = rdma_connect(c->id, &conn_param);
	if (ret) {
		perror("rdma_connect");
		exit(EXIT_FAILURE);
	}
}

static void resolve_addr(struct work_item *item)
{
	struct conn *c = container_of(item, struct conn, work);
	int ret;

	c->retries = retries;
	start_perf(c, STEP_RESOLVE_ADDR);
	ret = rdma_resolve_addr(c->id, rai->ai_src_addr,
				(struct sockaddr *) &peers[c->peer_id].sa,
				timeout);
	if (ret) {
		perror("rdma_resolve_addr");
		exit(EXIT_FAILURE);
	}
}

static void resolve_route(struct work_item *item)
{
	struct conn *c = container_of(item, struct conn, work);
	int ret;

	c->retries = retries;
	start_perf(c, STEP_RESOLVE_ROUTE);
	ret = rdma_resolve_route(c->id, timeout);
	if (ret) {
		perror("rdma_resolve_route");
		exit(EXIT_FAILURE);
	}
}

static void connect_response(struct work_item *item)
{
	struct conn *c = container_of(item, struct conn, work);

	modify_qp(c, IBV_QPS_RTR, STEP_RTR_QP_ATTR);
	modify_qp(c, IBV_QPS_RTS, STEP_RTS_QP_ATTR);

	start_perf(c, STEP_ESTABLISH);
	rdma_establish(c->id);
	end_perf(c, STEP_ESTABLISH);

	end_perf(c, STEP_CONNECT);
	end_perf(c, STEP_FULL_CONNECT);
	atomic_fetch_add(&completed[STEP_CONNECT], 1);
}

static void req_handler(struct work_item *item)
{
	struct conn *c = container_of(item, struct conn, work);
	struct rdma_conn_param conn_param;
	int ret;

	create_qp(&c->work);
	modify_qp(c, IBV_QPS_INIT, STEP_INIT_QP_ATTR);
	modify_qp(c, IBV_QPS_RTR, STEP_RTR_QP_ATTR);
	modify_qp(c, IBV_QPS_RTS, STEP_RTS_QP_ATTR);

	init_conn_param(c, &conn_param);
	ret = rdma_accept(c->id, &conn_param);
	if (ret) {
		perror("failure accepting");
		exit(EXIT_FAILURE);
	}
}

static void client_disconnect(struct work_item *item)
{
	struct conn *c = container_of(item, struct conn, work);

	start_perf(c, STEP_DISCONNECT);
	rdma_disconnect(c->id);
	end_perf(c, STEP_DISCONNECT);
	atomic_fetch_add(&completed[STEP_DISCONNECT], 1);
}

static void server_disconnect(struct work_item *item)
{
	struct conn *c = container_of(item, struct conn, work);

	c->server_disconnected = true;

	start_perf(c, STEP_DISCONNECT);
	rdma_disconnect(c->id);
	end_perf(c, STEP_DISCONNECT);

	if (atomic_load(&disc_events) >= num_conns)
		end_time(STEP_DISCONNECT);
	atomic_fetch_add(&completed[STEP_DISCONNECT], 1);
}

static void cma_handler(struct rdma_cm_id *id, struct rdma_cm_event *event)
{
	struct conn *c = id->context;

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		end_perf(c, STEP_RESOLVE_ADDR);
		atomic_fetch_add(&completed[STEP_RESOLVE_ADDR], 1);
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		end_perf(c, STEP_RESOLVE_ROUTE);
		atomic_fetch_add(&completed[STEP_RESOLVE_ROUTE], 1);
		break;
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		if (conn_index == 0) {
			printf("\tAccepting\n");
			start_time(STEP_CONNECT);
		}
		c = &conns[conn_index++];
		c->id = id;
		c->server_disconnected = false;
		id->context = c;
		wq_insert(&wq, &c->work, req_handler);
		break;
	case RDMA_CM_EVENT_CONNECT_RESPONSE:
		wq_insert(&wq, &c->work, connect_response);
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		if (atomic_fetch_add(&completed[STEP_CONNECT], 1) >=
		    num_conns - 1)
			end_time(STEP_CONNECT);
		break;
	case RDMA_CM_EVENT_ADDR_ERROR:
		if (c->retries--) {
			if (!rdma_resolve_addr(c->id, rai->ai_src_addr,
					       rai->ai_dst_addr, timeout))
				break;
		}
		printf("RDMA_CM_EVENT_ADDR_ERROR, error: %d\n", event->status);
		exit(EXIT_FAILURE);
		break;
	case RDMA_CM_EVENT_ROUTE_ERROR:
		if (c->retries--) {
			if (!rdma_resolve_route(c->id, timeout))
				break;
		}
		printf("RDMA_CM_EVENT_ROUTE_ERROR, error: %d\n", event->status);
		exit(EXIT_FAILURE);
		break;
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
		printf("event: %s, error: %d\n",
		       rdma_event_str(event->event), event->status);
		exit(EXIT_FAILURE);
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		if (role == role_listen) {
			/* To fix an issue where DREQs are not responded
			 * to, the client completes its disconnect phase
			 * as soon as it calls rdma_disconnect and does
			 * not wait for a response from the server.  The
			 * OOB sync handles that coordination.
			end_perf(c, STEP_DISCONNECT);
			atomic_fetch_add(&completed[STEP_DISCONNECT], 1);
		} else {
			 */
			if (atomic_fetch_add(&disc_events, 1) == 0) {
				printf("\tDisconnecting\n");
				start_time(STEP_DISCONNECT);
			}
			wq_insert(&wq, &c->work, server_disconnect);
		}
		break;
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		break;
	default:
		printf("Unhandled event: %d (%s)\n", event->event,
			rdma_event_str(event->event));
		exit(EXIT_FAILURE);
		break;
	}
	rdma_ack_cm_event(event);
}

static void create_ids(void)
{
	uint32_t i;
	int ret;

	printf("\tCreating IDs\n");
	start_time(STEP_CREATE_ID);
	for (i = 0; i < num_conns; i++) {
		start_perf(&conns[i], STEP_FULL_CONNECT);
		start_perf(&conns[i], STEP_CREATE_ID);
		ret = rdma_create_id(channel, &conns[i].id, &conns[i],
					hints.ai_port_space);
		if (ret) {
			perror("rdma_create_id");
			exit(EXIT_FAILURE);
		}
		end_perf(&conns[i], STEP_CREATE_ID);
	}
	end_time(STEP_CREATE_ID);
}

static void destroy_ids(void)
{
	uint32_t i;

	start_time(STEP_DESTROY_ID);
	for (i = 0; i < num_conns; i++) {
		start_perf(&conns[i], STEP_DESTROY_ID);
		if (conns[i].id)
			rdma_destroy_id(conns[i].id);
		end_perf(&conns[i], STEP_DESTROY_ID);
	}
	end_time(STEP_DESTROY_ID);
}

static void destroy_qps(void)
{
	uint32_t i;

	start_time(STEP_DESTROY_QP);
	for (i = 0; i < num_conns; i++) {
		start_perf(&conns[i], STEP_DESTROY_QP);
		if (conns[i].qp)
			ibv_destroy_qp(conns[i].qp);
		end_perf(&conns[i], STEP_DESTROY_QP);
	}
	end_time(STEP_DESTROY_QP);
}

static void *process_events(void *arg)
{
	struct rdma_cm_event *event;
	int ret;

	while (1) {
		ret = rdma_get_cm_event(channel, &event);
		if (!ret) {
			cma_handler(event->id, event);
		} else {
			perror("rdma_get_cm_event");
			exit(EXIT_FAILURE);
		}
	}

	return NULL;
}

static void server_listen(struct rdma_cm_id **listen_id)
{
	int ret;

	ret = rdma_create_id(channel, listen_id, NULL, hints.ai_port_space);
	if (ret) {
		perror("rdma_create_id");
		exit(EXIT_FAILURE);
	}

	ret = rdma_bind_addr(*listen_id, rai->ai_src_addr);
	if (ret) {
		perror("rdma_bind_addr");
		exit(EXIT_FAILURE);
	}

	ret = rdma_listen(*listen_id, 0);
	if (ret) {
		perror("rdma_listen");
		exit(EXIT_FAILURE);
	}
}

static int setup_oob(void)
{
	int listen_sock;

	listen_sock = oob_try_bind(ctrl_addr, oob_port);
	if (listen_sock < 0) {
		perror("oob_try_bind");
		exit(EXIT_FAILURE);
	}

	if (listen_sock > 0) {
		is_root = true;
		printf("Running as OOB root\n");
		return oob_root_setup(listen_sock, &oob_root, num_peers - 1);
	}

	return oob_leaf_setup(ctrl_addr, oob_port, &oob_up);
}

static void cleanup_oob(void)
{
	if (is_root)
		oob_close_root(&oob_root);
	else
		close(oob_up);
}

static void do_sync(char val)
{
	if (is_root)
		oob_syncdown(&oob_root, val);
	else
		oob_syncup(oob_up, val);
}

static void count_listeners(void)
{
	uint32_t i;

	for (i = 0; i < num_peers; i++) {
		if (peers[i].role == role_listen)
			num_listeners++;
	}

	if (num_listeners == num_peers) {
		printf("cannot have all listeners\n");
		exit(EXIT_FAILURE);
	}

	if (!num_listeners) {
		printf("need at least 1 listener\n");
		exit(EXIT_FAILURE);
	}
}

static void assign_listeners(void)
{
	uint32_t i, p = 0;

	for (i = 0; i < num_conns; i++) {
		while (peers[p].role != role_listen) {
			if (++p >= num_peers)
				p = 0;
		}
		conns[i].peer_id = p;
		if (++p >= num_peers)
			p = 0;
	}
}

static int setup_mesh(void)
{
	int ret;

	if (is_root) {
		ret = oob_gather(&oob_root, peers + 1, sizeof(*peers));
		if (ret)
			return ret;

		ret = oob_senddown(&oob_root, peers, sizeof(*peers) * num_peers);
	} else {
		ret = sock_senddata(oob_up, peers, sizeof(*peers));
		if (ret)
			return ret;

		ret = sock_recvdata(oob_up, peers, sizeof(*peers) * num_peers);
	}
	if (ret)
		return ret;

	count_listeners();
	if (role == role_connect)
		num_conns = num_conns * num_listeners;
	else
		num_conns = num_conns * (num_peers - num_listeners);

	conns = calloc(num_conns, sizeof *conns);
	if (!conns)
		return -ENOMEM;

	return 0;
}

static void reset_test(void)
{
	int i;

	conn_index = 0;
	atomic_store(&disc_events, 0);

	memset(times, 0, sizeof times);
	memset(conns, 0, sizeof(*conns) * num_conns);

	if (role == role_connect)
		assign_listeners();

	for (i = 0; i < STEP_CNT; i++)
		atomic_store(&completed[i], 0);

	do_sync(0);
}

static void server_disconnect_timeout(void)
{
	fprintf(stderr,
		"Timeout waiting for clients to disconnect (got %d/%d)\n",
		atomic_load(&completed[STEP_DISCONNECT]), num_conns);
	for (int i = 0; i < num_conns; i++) {
		if (conns[i].server_disconnected)
			continue;
		wq_insert(&wq, &conns[i].work, server_disconnect);
	}
}

static void server_connect(void)
{
	reset_test();

	do_sync(STEP_INIT_QP);

	while (atomic_load(&completed[STEP_CONNECT]) < num_conns)
		sched_yield();

	do_sync(STEP_CONNECT);

	uint64_t start_time = gettime_us();

	while (atomic_load(&completed[STEP_DISCONNECT]) < num_conns) {
		if (gettime_us() - start_time > SRV_MAX_DISCONNECT_TIME_US) {
			server_disconnect_timeout();
			start_time = gettime_us();
		}
		sched_yield();
	}

	do_sync(STEP_DISCONNECT);

	destroy_qps();
	destroy_ids();
}

static void client_connect(void)
{
	uint32_t i;
	int ret;

	reset_test();
	start_time(STEP_FULL_CONNECT);
	create_ids();

	printf("\tBinding addresses\n");
	start_time(STEP_BIND);
	for (i = 0; i < num_conns; i++) {
		start_perf(&conns[i], STEP_BIND);
		ret = rdma_bind_addr(conns[i].id, rai->ai_src_addr);
		if (ret) {
			perror("rdma_bind_addr");
			exit(EXIT_FAILURE);
		}
		end_perf(&conns[i], STEP_BIND);
	}
	end_time(STEP_BIND);

	printf("\tResolving addresses\n");
	start_time(STEP_RESOLVE_ADDR);
	for (i = 0; i < num_conns; i++)
		wq_insert(&wq, &conns[i].work, resolve_addr);

	while (atomic_load(&completed[STEP_RESOLVE_ADDR]) < num_conns)
		sched_yield();
	end_time(STEP_RESOLVE_ADDR);

	printf("\tResolving routes\n");
	start_time(STEP_RESOLVE_ROUTE);
	for (i = 0; i < num_conns; i++)
		wq_insert(&wq, &conns[i].work, resolve_route);

	while (atomic_load(&completed[STEP_RESOLVE_ROUTE]) < num_conns)
		sched_yield();
	end_time(STEP_RESOLVE_ROUTE);

	printf("\tCreating QPs\n");
	start_time(STEP_CREATE_QP);
	for (i = 0; i < num_conns; i++)
		wq_insert(&wq, &conns[i].work, create_qp);

	while (atomic_load(&completed[STEP_CREATE_QP]) < num_conns)
		sched_yield();
	end_time(STEP_CREATE_QP);

	printf("\tModify QPs to INIT\n");
	start_time(STEP_INIT_QP);
	for (i = 0; i < num_conns; i++) {
		conns[i].next_qps = IBV_QPS_INIT;
		conns[i].next_step = STEP_INIT_QP_ATTR;
		wq_insert(&wq, &conns[i].work, modify_qp_work);
	}
	while (atomic_load(&completed[STEP_INIT_QP]) < num_conns)
		sched_yield();
	end_time(STEP_INIT_QP);

	do_sync(STEP_INIT_QP);

	printf("\tConnecting\n");
	start_time(STEP_CONNECT);
	for (i = 0; i < num_conns; i++)
		connect_qp(&conns[i]);

	while (atomic_load(&completed[STEP_CONNECT]) < num_conns)
		sched_yield();
	end_time(STEP_CONNECT);
	end_time(STEP_FULL_CONNECT);

	do_sync(STEP_CONNECT);

	printf("\tDisconnecting\n");
	start_time(STEP_DISCONNECT);
	for (i = 0; i < num_conns; i++)
		wq_insert(&wq, &conns[i].work, client_disconnect);

	while (atomic_load(&completed[STEP_DISCONNECT]) < num_conns)
		sched_yield();
	end_time(STEP_DISCONNECT);

	do_sync(STEP_DISCONNECT);

	/* Wait for event threads to exit before destroying resources */
	printf("\tDestroying QPs\n");
	destroy_qps();
	printf("\tDestroying IDs\n");
	destroy_ids();
}

static void run_client(void)
{
	uint32_t save_num_conn;
	int ret;

	peers[0].role = role_connect;
	ret = setup_mesh();
	if (ret)
		exit(EXIT_FAILURE);

	printf("Client warmup\n");
	save_num_conn = num_conns;
	num_conns = num_listeners;
	client_connect();
	num_conns = save_num_conn;

	if (!mimic) {
		printf("Connect (%d) QPs test\n", num_conns);
	} else {
		printf("Connect (%d) simulated QPs test (delay %d us)\n",
			num_conns, mimic_qp_delay);
		atomic_store(&cur_qpn, base_qpn);
	}
	client_connect();
	show_perf();

	if (num_peers == 2) {
		printf("Connect (%d) test - no QPs\n", num_conns);
		atomic_store(&cur_qpn, base_qpn);
		mimic_qp_delay = 0;
		client_connect();
		show_perf();
	}
}

static void run_server(void)
{
	struct rdma_cm_id *listen_id;
	uint32_t save_num_conn;
	int ret;

	/* Configure RDMA prior to setting up the mesh */
	server_listen(&listen_id);

	peers[0].role = role_listen;
	peers[0].sa = listen_id->route.addr.src_storage;
	ret = setup_mesh();
	if (ret)
		exit(EXIT_FAILURE);

	printf("Server warmup\n");
	save_num_conn = num_conns;
	num_conns = num_peers - num_listeners;
	server_connect();
	num_conns = save_num_conn;

	if (!mimic) {
		printf("Accept (%d) QPs test\n", num_conns);
	} else {
		printf("Accept (%d) simulated QPs test (delay %d us)\n",
			num_conns, mimic_qp_delay);
		atomic_store(&cur_qpn, base_qpn);
	}
	server_connect();
	show_perf();

	if (num_peers == 2) {
		printf("Accept (%d) test - no QPs\n", num_conns);
		atomic_store(&cur_qpn, base_qpn);
		mimic_qp_delay = 0;
		server_connect();
		show_perf();
	}

	rdma_destroy_id(listen_id);
}

static char *get_src_addr(char *ifa_name)
{
	struct ifaddrs *ifaddr, *ifa;
	char ip[INET6_ADDRSTRLEN];

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		if (strcmp(ifa->ifa_name, ifa_name) != 0)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
			if (!inet_ntop(AF_INET,
				       &(((struct sockaddr_in *)ifa->ifa_addr)
						 ->sin_addr),
				       ip, INET6_ADDRSTRLEN)) {
				perror("inet_ntop_4");
				exit(EXIT_FAILURE);
			}
			break;
		}

		if (ifa->ifa_addr->sa_family == AF_INET6) {
			if (!inet_ntop(AF_INET6,
				       &(((struct sockaddr_in6 *)ifa->ifa_addr)
						 ->sin6_addr),
				       ip, INET6_ADDRSTRLEN)) {
				perror("inet_ntop_6");
				exit(EXIT_FAILURE);
			}
			break;
		}
	}

	if (!ifa) {
		fprintf(stderr, "Failed to find IP address for interface: %s\n",
			ifa_name);
		exit(EXIT_FAILURE);
	}

	freeifaddrs(ifaddr);

	printf("Picking source address %s for interface %s\n", ip, ifa_name);

	return strdup(ip);
}

int main(int argc, char **argv)
{
	pthread_t event_thread;
	bool socktest = false;
	int op, ret;

	while ((op = getopt(argc, argv, "B:b:C:c:Lm:n:P:p:q:r:Ss:t:")) != -1) {
		switch (op) {
		case 'B':
			if (src_addr)
				goto usage;
			src_addr = get_src_addr(optarg);
			break;
		case 'b':
			if (src_addr)
				goto usage;
			src_addr = optarg;
			break;
		case 'C':
			ctrl_addr = optarg;
			break;
		case 'c':
			num_conns = (uint32_t) atoi(optarg);
			break;
		case 'L':
			role = role_listen;
			break;
		case 'm':
			mimic_qp_delay = (uint32_t) atoi(optarg);
			mimic = true;
			break;
		case 'n':
			num_threads = (uint32_t) atoi(optarg);
			break;
		case 'P':
			num_peers = (uint32_t) atoi(optarg);
			if (num_peers < 2)
				goto usage;
			break;
		case 'p':
			oob_port = optarg;
			break;
		case 'q':
			base_qpn = (uint32_t) atoi(optarg);
			break;
		case 'r':
			retries = atoi(optarg);
			break;
		case 'S':
			socktest = true;
			atomic_store(&cur_qpn, 1);
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		default:
usage:
			printf("usage: %s\n", argv[0]);
			printf("\t-B bind_interface (only one of -B or -b accepted)\n");
			printf("\t-b bind_address (only one of -B or -b accepted)\n");
			printf("\t-C controller_address\n");
			printf("\t[-c num_conns] connections per listener\n");
			printf("\t[-L] run as listening server\n");
			printf("\t[-m mimic_qp_delay_us]\n");
			printf("\t[-n num_threads]\n");
			printf("\t[-P num_peers] total number of peers\n");
			printf("\t[-p oob_port]\n");
			printf("\t[-q base_qpn]\n");
			printf("\t[-r retries]\n");
			printf("\t[-S] run socket baseline test, 2 peers only\n");
			printf("\t[-t timeout_ms]\n");
			exit(EXIT_FAILURE);
		}
	}

	if (!src_addr || !ctrl_addr || (socktest && num_peers > 2))
		goto usage;

	hints.ai_port_space = RDMA_PS_TCP;
	hints.ai_qp_type = IBV_QPT_RC;
	hints.ai_flags = RAI_PASSIVE;
	ret = rdma_getaddrinfo(src_addr, NULL, &hints, &rai);
	if (ret) {
		perror("rdma_getaddrinfo");
		exit(EXIT_FAILURE);
	}

	channel = create_event_channel();
	if (!channel) {
		perror("create_event_channel");
		exit(EXIT_FAILURE);
	}

	ret = pthread_create(&event_thread, NULL, process_events, NULL);
	if (ret) {
		perror("pthread_create");
		exit(EXIT_FAILURE);
	}

	peers = calloc(num_peers, sizeof *peers);
	if (!peers)
		exit(EXIT_FAILURE);

	ret = wq_init(&wq, num_threads);
	if (ret)
		exit(EXIT_FAILURE);

	ret = setup_oob();
	if (ret)
		exit(EXIT_FAILURE);

	if (role == role_connect) {
		if (socktest)
			sock_client();
		else
			run_client();
	} else {
		if (socktest)
			sock_server();
		else
			run_server();
	}

	cleanup_oob();
	wq_cleanup(&wq);
	free(peers);
	free(conns);
	rdma_destroy_event_channel(channel);
	rdma_freeaddrinfo(rai);
	return 0;
}
