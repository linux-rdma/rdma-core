/*
 * Copyright (c) 2013 Intel Corporation.  All rights reserved.
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
#include <netinet/tcp.h>

#include <rdma/rdma_cma.h>
#include "common.h"

static struct rdma_addrinfo hints, *rai;
static struct rdma_event_channel *channel;
static const char *port = "7471";
static char *dst_addr;
static char *src_addr;
static int timeout = 2000;
static int retries = 2;

enum step {
	STEP_CREATE_ID,
	STEP_BIND,
	STEP_RESOLVE_ADDR,
	STEP_RESOLVE_ROUTE,
	STEP_CREATE_QP,
	STEP_CONNECT,
	STEP_DISCONNECT,
	STEP_DESTROY,
	STEP_CNT
};

static const char *step_str[] = {
	"create id",
	"bind addr",
	"resolve addr",
	"resolve route",
	"create qp",
	"connect",
	"disconnect",
	"destroy"
};

struct node {
	struct rdma_cm_id *id;
	struct timeval times[STEP_CNT][2];
	int error;
	int retries;
};

struct work_item {
	struct work_item *next;
	struct rdma_cm_id *id;
};

struct work_queue {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	pthread_t thread;

	void (*work_handler)(struct work_item *item);
	struct work_item *head;
	struct work_item *tail;
};

static void *wq_handler(void *arg);
static struct work_queue req_wq;
static struct work_queue disc_wq;

static struct node *nodes;
static struct timeval times[STEP_CNT][2];
static int connections = 100;
static volatile int disc_events;

static volatile int started[STEP_CNT];
static volatile int completed[STEP_CNT];
static struct ibv_qp_init_attr init_qp_attr;
static struct rdma_conn_param conn_param;

#define start_perf(n, s)	gettimeofday(&((n)->times[s][0]), NULL)
#define end_perf(n, s)		gettimeofday(&((n)->times[s][1]), NULL)
#define start_time(s)		gettimeofday(&times[s][0], NULL)
#define end_time(s)		gettimeofday(&times[s][1], NULL)

static inline bool is_client(void)
{
	return dst_addr != NULL;
}

static int
wq_init(struct work_queue *wq, void (*work_handler)(struct work_item *))
{
	int ret;

	wq->head = NULL;
	wq->tail = NULL;
	wq->work_handler = work_handler;

	ret = pthread_mutex_init(&wq->lock, NULL);
	if (ret) {
		perror("pthread_mutex_init");
		return ret;
	}

	ret = pthread_cond_init(&wq->cond, NULL);
	if (ret) {
		perror("pthread_cond_init");
		return ret;
	}

	ret = pthread_create(&wq->thread, NULL, wq_handler, wq);
	if (ret) {
		perror("pthread_create");
		return ret;
	}

	return 0;
}

static void wq_cleanup(struct work_queue *wq)
{
	pthread_join(wq->thread, NULL);
	pthread_cond_destroy(&wq->cond);
	pthread_mutex_destroy(&wq->lock);
}

static void wq_insert(struct work_queue *wq, struct work_item *item)
{
	bool empty;

	item->next = NULL;
	pthread_mutex_lock(&wq->lock);
	if (wq->head) {
		wq->tail->next = item;
		empty = false;
	} else {
		wq->head = item;
		empty = true;
	}
	wq->tail = item;
	pthread_mutex_unlock(&wq->lock);

	if (empty)
		pthread_cond_signal(&wq->cond);
}

static struct work_item *wq_remove(struct work_queue *wq)
{
	struct work_item *item;

	item = wq->head;
	wq->head = wq->head->next;
	return item;
}

static int zero_time(struct timeval *t)
{
	return !(t->tv_sec || t->tv_usec);
}

static float diff_us(struct timeval *end, struct timeval *start)
{
	return (end->tv_sec - start->tv_sec) * 1000000. + (end->tv_usec - start->tv_usec);
}

static void show_perf(void)
{
	int c, i;
	float us, max[STEP_CNT], min[STEP_CNT];

	for (i = 0; i < STEP_CNT; i++) {
		max[i] = 0;
		min[i] = 999999999.;
		for (c = 0; c < connections; c++) {
			if (!zero_time(&nodes[c].times[i][0]) &&
			    !zero_time(&nodes[c].times[i][1])) {
				us = diff_us(&nodes[c].times[i][1], &nodes[c].times[i][0]);
				if (us > max[i])
					max[i] = us;
				if (us < min[i])
					min[i] = us;
			}
		}
	}

	printf("step              total ms     max ms     min us  us / conn\n");
	for (i = 0; i < STEP_CNT; i++) {
		if (i == STEP_BIND && !src_addr)
			continue;

		us = diff_us(&times[i][1], &times[i][0]);
		printf("%-13s: %11.2f%11.2f%11.2f%11.2f\n", step_str[i], us / 1000.,
			max[i] / 1000., min[i], us / connections);
	}
}

static void addr_handler(struct node *n)
{
	end_perf(n, STEP_RESOLVE_ADDR);
	completed[STEP_RESOLVE_ADDR]++;
}

static void route_handler(struct node *n)
{
	end_perf(n, STEP_RESOLVE_ROUTE);
	completed[STEP_RESOLVE_ROUTE]++;
}

static void conn_handler(struct node *n)
{
	end_perf(n, STEP_CONNECT);
	completed[STEP_CONNECT]++;
}

static void disc_handler(struct node *n)
{
	end_perf(n, STEP_DISCONNECT);
	completed[STEP_DISCONNECT]++;
}

static void req_work_handler(struct work_item *item)
{
	struct rdma_cm_id *id;
	int ret;

	id = item->id;
	ret = rdma_create_qp(id, NULL, &init_qp_attr);
	if (ret) {
		perror("failure creating qp");
		goto err1;
	}

	ret = rdma_accept(id, NULL);
	if (ret) {
		perror("failure accepting");
		goto err2;
	}
	return;

err2:
	rdma_destroy_qp(id);
err1:
	printf("failing connection request\n");
	rdma_reject(id, NULL, 0);
	rdma_destroy_id(id);
	return;
}

static void disc_work_handler(struct work_item *item)
{
	rdma_disconnect(item->id);
	rdma_destroy_qp(item->id);
	rdma_destroy_id(item->id);
}

static void *wq_handler(void *arg)
{
	struct work_queue *wq = arg;
	struct work_item *item;
	int i;

	for (i = 0; i < connections; i++) {
		pthread_mutex_lock(&wq->lock);
		if (!wq->head)
			pthread_cond_wait(&wq->cond, &wq->lock);
		item = wq_remove(wq);
		pthread_mutex_unlock(&wq->lock);

		wq->work_handler(item);
		free(item);
	}

	return NULL;
}

static void cma_handler(struct rdma_cm_id *id, struct rdma_cm_event *event)
{
	struct node *n = id->context;
	struct work_item *item;

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		addr_handler(n);
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		route_handler(n);
		break;
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		item = malloc(sizeof *item);
		if (!item) {
			perror("out of memory accepting connect request");
			rdma_reject(id, NULL, 0);
			rdma_destroy_id(id);
		} else {
			item->id = id;
			wq_insert(&req_wq, item);
		}
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		if (n)
			conn_handler(n);
		break;
	case RDMA_CM_EVENT_ADDR_ERROR:
		if (n->retries--) {
			if (!rdma_resolve_addr(n->id, rai->ai_src_addr,
					       rai->ai_dst_addr, timeout))
				break;
		}
		printf("RDMA_CM_EVENT_ADDR_ERROR, error: %d\n", event->status);
		addr_handler(n);
		n->error = 1;
		break;
	case RDMA_CM_EVENT_ROUTE_ERROR:
		if (n->retries--) {
			if (!rdma_resolve_route(n->id, timeout))
				break;
		}
		printf("RDMA_CM_EVENT_ROUTE_ERROR, error: %d\n", event->status);
		route_handler(n);
		n->error = 1;
		break;
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
		printf("event: %s, error: %d\n",
		       rdma_event_str(event->event), event->status);
		conn_handler(n);
		n->error = 1;
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		disc_events++;
		if (!n) {
			item = malloc(sizeof *item);
			if (!item) {
				perror("out of memory queueing disconnect request, handling synchronously");
				rdma_disconnect(id);
				rdma_destroy_qp(id);
				rdma_destroy_id(id);
			} else {
				item->id = id;
				wq_insert(&disc_wq, item);
			}
		} else {
			disc_handler(n);
		}
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		/* Cleanup will occur after test completes. */
		break;
	default:
		break;
	}
	rdma_ack_cm_event(event);
}

static int create_ids(void)
{
	int ret, i;

	printf("creating id\n");
	start_time(STEP_CREATE_ID);
	for (i = 0; i < connections; i++) {
		start_perf(&nodes[i], STEP_CREATE_ID);
		ret = rdma_create_id(channel, &nodes[i].id, &nodes[i],
					hints.ai_port_space);
		if (ret)
			goto err;
		end_perf(&nodes[i], STEP_CREATE_ID);
	}
	end_time(STEP_CREATE_ID);
	return 0;

err:
	while (--i >= 0)
		rdma_destroy_id(nodes[i].id);
	return ret;
}

static void destroy_ids(void)
{
	int i;

	printf("destroying id\n");
	start_time(STEP_DESTROY);
	for (i = 0; i < connections; i++) {
		start_perf(&nodes[i], STEP_DESTROY);
		if (nodes[i].id)
			rdma_destroy_id(nodes[i].id);
		end_perf(&nodes[i], STEP_DESTROY);
	}
	end_time(STEP_DESTROY);
}

static void *process_events(void *arg)
{
	struct rdma_cm_event *event;
	int ret = 0;

	while (!ret && disc_events < connections) {
		ret = rdma_get_cm_event(channel, &event);
		if (!ret) {
			cma_handler(event->id, event);
		} else {
			perror("failure in rdma_get_cm_event in process_server_events");
			ret = errno;
		}
	}

	return NULL;
}

static int run_server(void)
{
	struct rdma_cm_id *listen_id;
	int ret;

	ret = wq_init(&req_wq, req_work_handler);
	if (ret)
		return ret;

	ret = wq_init(&disc_wq, disc_work_handler);
	if (ret)
		return ret;

	ret = rdma_create_id(channel, &listen_id, NULL, hints.ai_port_space);
	if (ret) {
		perror("listen request failed");
		return ret;
	}

	ret = rdma_bind_addr(listen_id, rai->ai_src_addr);
	if (ret) {
		perror("bind address failed");
		goto out;
	}

	ret = rdma_listen(listen_id, 0);
	if (ret) {
		perror("failure trying to listen");
		goto out;
	}

	process_events(NULL);
 out:
	rdma_destroy_id(listen_id);
	wq_cleanup(&req_wq);
	wq_cleanup(&disc_wq);
	return ret;
}

static int run_client(void)
{
	pthread_t event_thread;
	int i, ret;

	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	conn_param.retry_count = retries;
	conn_param.private_data = rai->ai_connect;
	conn_param.private_data_len = rai->ai_connect_len;

	ret = pthread_create(&event_thread, NULL, process_events, NULL);
	if (ret) {
		perror("failure creating event thread");
		return ret;
	}

	if (src_addr) {
		printf("binding source address\n");
		start_time(STEP_BIND);
		for (i = 0; i < connections; i++) {
			start_perf(&nodes[i], STEP_BIND);
			ret = rdma_bind_addr(nodes[i].id, rai->ai_src_addr);
			if (ret) {
				perror("failure bind addr");
				nodes[i].error = 1;
				continue;
			}
			end_perf(&nodes[i], STEP_BIND);
		}
		end_time(STEP_BIND);
	}

	printf("resolving address\n");
	start_time(STEP_RESOLVE_ADDR);
	for (i = 0; i < connections; i++) {
		if (nodes[i].error)
			continue;
		nodes[i].retries = retries;
		start_perf(&nodes[i], STEP_RESOLVE_ADDR);
		ret = rdma_resolve_addr(nodes[i].id, rai->ai_src_addr,
					rai->ai_dst_addr, timeout);
		if (ret) {
			perror("failure getting addr");
			nodes[i].error = 1;
			continue;
		}
		started[STEP_RESOLVE_ADDR]++;
	}
	while (started[STEP_RESOLVE_ADDR] != completed[STEP_RESOLVE_ADDR])
		sched_yield();
	end_time(STEP_RESOLVE_ADDR);

	printf("resolving route\n");
	start_time(STEP_RESOLVE_ROUTE);
	for (i = 0; i < connections; i++) {
		if (nodes[i].error)
			continue;
		nodes[i].retries = retries;
		start_perf(&nodes[i], STEP_RESOLVE_ROUTE);
		ret = rdma_resolve_route(nodes[i].id, timeout);
		if (ret) {
			perror("failure resolving route");
			nodes[i].error = 1;
			continue;
		}
		started[STEP_RESOLVE_ROUTE]++;
	}
	while (started[STEP_RESOLVE_ROUTE] != completed[STEP_RESOLVE_ROUTE])
		sched_yield();
	end_time(STEP_RESOLVE_ROUTE);

	printf("creating qp\n");
	start_time(STEP_CREATE_QP);
	for (i = 0; i < connections; i++) {
		if (nodes[i].error)
			continue;
		start_perf(&nodes[i], STEP_CREATE_QP);
		ret = rdma_create_qp(nodes[i].id, NULL, &init_qp_attr);
		if (ret) {
			perror("failure creating qp");
			nodes[i].error = 1;
			continue;
		}
		end_perf(&nodes[i], STEP_CREATE_QP);
	}
	end_time(STEP_CREATE_QP);

	printf("connecting\n");
	start_time(STEP_CONNECT);
	for (i = 0; i < connections; i++) {
		if (nodes[i].error)
			continue;
		start_perf(&nodes[i], STEP_CONNECT);
		ret = rdma_connect(nodes[i].id, &conn_param);
		if (ret) {
			perror("failure rconnecting");
			nodes[i].error = 1;
			continue;
		}
		started[STEP_CONNECT]++;
	}
	while (started[STEP_CONNECT] != completed[STEP_CONNECT])
		sched_yield();
	end_time(STEP_CONNECT);

	printf("disconnecting\n");
	start_time(STEP_DISCONNECT);
	for (i = 0; i < connections; i++) {
		if (nodes[i].error)
			continue;
		start_perf(&nodes[i], STEP_DISCONNECT);
		rdma_disconnect(nodes[i].id);
		rdma_destroy_qp(nodes[i].id);
		started[STEP_DISCONNECT]++;
	}
	while (started[STEP_DISCONNECT] != completed[STEP_DISCONNECT])
		sched_yield();
	end_time(STEP_DISCONNECT);

	return ret;
}

int main(int argc, char **argv)
{
	int op, ret;

	hints.ai_port_space = RDMA_PS_TCP;
	hints.ai_qp_type = IBV_QPT_RC;
	while ((op = getopt(argc, argv, "s:b:c:p:r:t:")) != -1) {
		switch (op) {
		case 's':
			dst_addr = optarg;
			break;
		case 'b':
			src_addr = optarg;
			break;
		case 'c':
			connections = atoi(optarg);
			break;
		case 'p':
			port = optarg;
			break;
		case 'r':
			retries = atoi(optarg);
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		default:
			printf("usage: %s\n", argv[0]);
			printf("\t[-s server_address]\n");
			printf("\t[-b bind_address]\n");
			printf("\t[-c connections]\n");
			printf("\t[-p port_number]\n");
			printf("\t[-r retries]\n");
			printf("\t[-t timeout_ms]\n");
			exit(1);
		}
	}

	init_qp_attr.cap.max_send_wr = 1;
	init_qp_attr.cap.max_recv_wr = 1;
	init_qp_attr.cap.max_send_sge = 1;
	init_qp_attr.cap.max_recv_sge = 1;
	init_qp_attr.qp_type = IBV_QPT_RC;

	if (!is_client())
		hints.ai_flags |= RAI_PASSIVE;
	ret = get_rdma_addr(src_addr, dst_addr, port, &hints, &rai);
	if (ret)
		goto out;

	channel = create_event_channel();
	if (!channel) {
		ret = -errno;
		goto freeinfo;
	}

	if (is_client()) {
		nodes = calloc(sizeof *nodes, connections);
		if (!nodes) {
			ret = -ENOMEM;
			goto destchan;
		}

		ret = create_ids();
		if (ret)
			goto freenodes;
		ret = run_client();
		destroy_ids();

		show_perf();
freenodes:
		free(nodes);
	} else {
		ret = run_server();
	}

destchan:
	rdma_destroy_event_channel(channel);
freeinfo:
	rdma_freeaddrinfo(rai);
out:
	return ret;
}
