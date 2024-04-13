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
#include <netinet/tcp.h>

#include <rdma/rdma_cma.h>
#include "common.h"


static struct rdma_addrinfo hints, *rai;
static struct rdma_event_channel *channel;
static int oob_sock = -1;
static const char *port = "7471";
static char *dst_addr;
static char *src_addr;
static int timeout = 2000;
static int retries = 2;
static uint32_t base_qpn = 1000;
static uint32_t use_qpn;
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

struct node {
	struct node *next;
	struct rdma_cm_id *id;
	struct ibv_qp *qp;

	uint64_t times[STEP_CNT][2];
	int error;
	int retries;
};

struct work_queue {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	pthread_t thread;

	void (*work_handler)(struct node *node);
	struct node *head;
	struct node *tail;
};

static void *wq_handler(void *arg);
static struct work_queue req_wq;
static struct work_queue disc_wq;

static struct node *nodes;
static int node_index;
static uint64_t times[STEP_CNT][2];
static int connections;
static volatile int disc_events;

static volatile int completed[STEP_CNT];

static struct ibv_pd *pd;
static struct ibv_cq *cq;

#define start_perf(n, s)	do { (n)->times[s][0] = gettime_us(); } while (0)
#define end_perf(n, s)		do { (n)->times[s][1] = gettime_us(); } while (0)
#define start_time(s)		do { times[s][0] = gettime_us(); } while (0)
#define end_time(s)		do { times[s][1] = gettime_us(); } while (0)


static inline bool is_client(void)
{
	return dst_addr != NULL;
}

static int
wq_init(struct work_queue *wq, void (*work_handler)(struct node *))
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
	pthread_join(wq->thread, NULL);
}

static void wq_insert(struct work_queue *wq, struct node *n)
{
	bool empty;

	n->next = NULL;
	pthread_mutex_lock(&wq->lock);
	if (wq->head) {
		wq->tail->next = n;
		empty = false;
	} else {
		wq->head = n;
		empty = true;
	}
	wq->tail = n;
	pthread_mutex_unlock(&wq->lock);

	if (empty)
		pthread_cond_signal(&wq->cond);
}

static struct node *wq_remove(struct work_queue *wq)
{
	struct node *n;

	n = wq->head;
	wq->head = wq->head->next;
	n->next = NULL;
	return n;
}

static void show_perf(int iter)
{
	uint32_t diff, max[STEP_CNT], min[STEP_CNT], sum[STEP_CNT];
	int i, c;

	for (i = 0; i < STEP_CNT; i++) {
		sum[i] = 0;
		max[i] = 0;
		min[i] = UINT32_MAX;
		for (c = 0; c < iter; c++) {
			if (nodes[c].times[i][0] && nodes[c].times[i][1]) {
				diff = (uint32_t) (nodes[c].times[i][1] -
						   nodes[c].times[i][0]);
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

	printf("step              us/conn    sum(us)    max(us)    min(us)  total(us)   avg/iter\n");
	for (i = 0; i < STEP_CNT; i++) {
		diff = (uint32_t) (times[i][1] - times[i][0]);

		printf("%-13s: %10u %10u %10u %10u %10d %10u\n",
			step_str[i], sum[i] / iter, sum[i],
			max[i], min[i], diff, diff / iter);
	}
}

static inline bool need_verbs(void)
{
	return pd == NULL;
}

static int open_verbs(struct rdma_cm_id *id)
{
	printf("\tAllocating verbs resources\n");
	pd = ibv_alloc_pd(id->verbs);
	if (!pd) {
		perror("ibv_alloc_pd");
		return -errno;
	}

	cq = ibv_create_cq(id->verbs, 1, NULL, NULL, 0);
	if (!cq) {
		perror("ibv_create_cq");
		return -errno;
	}
	return 0;
}

static int create_qp(struct node *n)
{
	struct ibv_qp_init_attr attr;
	int ret;

	if (need_verbs()) {
		ret = open_verbs(n->id);
		if (ret)
			return ret;
	}

	attr.qp_context = n;
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

	start_perf(n, STEP_CREATE_QP);
	if (!use_qpn) {
		n->qp = ibv_create_qp(pd, &attr);
		if (!n->qp) {
			ret = -errno;
			perror("ibv_create_qp");
			n->error = 1;
		}
	} else {
		sleep_us(mimic_qp_delay);
	}
	end_perf(n, STEP_CREATE_QP);

	return ret;
}

static int
modify_qp(struct node *n, enum ibv_qp_state state, enum step attr_step)
{
	struct ibv_qp_attr attr;
	int mask, ret;

	attr.qp_state = state;
	start_perf(n, attr_step);
	ret = rdma_init_qp_attr(n->id, &attr, &mask);
	if (ret) {
		perror("rdma_init_qp_attr");
		n->error = 1;
		return ret;
	}
	end_perf(n, attr_step);

	start_perf(n, attr_step + 1);
	if (n->qp) {
		ret = ibv_modify_qp(n->qp, &attr, mask);
		if (ret) {
			perror("ibv_modify_qp");
			n->error = 1;
			return ret;
		}
	} else {
		sleep_us(mimic_qp_delay);
	}
	end_perf(n, attr_step + 1);

	return 0;
}

static void init_conn_param(struct node *n, struct rdma_conn_param *param)
{
	param->private_data = rai->ai_connect;
	param->private_data_len = rai->ai_connect_len;
	param->responder_resources = 1;
	param->initiator_depth = 1;
	param->flow_control = 0;
	param->retry_count = 0;
	param->rnr_retry_count = 0;
	param->srq = 0;
	param->qp_num = n->qp ? n->qp->qp_num : use_qpn++;
}

static void connect_qp(struct node *n)
{
	struct rdma_conn_param conn_param;
	int ret;

	init_conn_param(n, &conn_param);

	start_perf(n, STEP_CONNECT);
	ret = rdma_connect(n->id, &conn_param);
	if (ret) {
		perror("rdma_connect");
		n->error = 1;
		return;
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
	int ret;

	if (n->error)
		goto endperf;

	ret = modify_qp(n, IBV_QPS_RTR, STEP_RTR_QP_ATTR);
	if (ret)
		goto out;

	ret = modify_qp(n, IBV_QPS_RTS, STEP_RTS_QP_ATTR);
	if (ret)
		goto out;

	start_perf(n, STEP_ESTABLISH);
	rdma_establish(n->id);
	end_perf(n, STEP_ESTABLISH);

out:
	if (ret)
		n->error = 1;
endperf:
	end_perf(n, STEP_CONNECT);
	end_perf(n, STEP_FULL_CONNECT);
	completed[STEP_CONNECT]++;
}

static void disc_handler(struct node *n)
{
	end_perf(n, STEP_DISCONNECT);
	completed[STEP_DISCONNECT]++;
}

static void req_work_handler(struct node *n)
{
	struct rdma_conn_param conn_param;
	int ret;

	ret = create_qp(n);
	if (ret)
		goto err1;

	ret = modify_qp(n, IBV_QPS_INIT, STEP_INIT_QP_ATTR);
	if (ret)
		goto err2;

	ret = modify_qp(n, IBV_QPS_RTR, STEP_RTR_QP_ATTR);
	if (ret)
		goto err2;

	ret = modify_qp(n, IBV_QPS_RTS, STEP_RTS_QP_ATTR);
	if (ret)
		goto err2;

	init_conn_param(n, &conn_param);
	ret = rdma_accept(n->id, &conn_param);
	if (ret) {
		perror("failure accepting");
		n->error = 1;
		goto err2;
	}
	return;

err2:
	if (n->qp)
		ibv_destroy_qp(n->qp);
err1:
	printf("failing connection request\n");
	rdma_reject(n->id, NULL, 0);
	rdma_destroy_id(n->id);
	return;
}

static void disc_work_handler(struct node *n)
{
	start_perf(n, STEP_DISCONNECT);
	rdma_disconnect(n->id);
	end_perf(n, STEP_DISCONNECT);

	if (disc_events >= connections)
		end_time(STEP_DISCONNECT);
}

static void *wq_handler(void *arg)
{
	struct work_queue *wq = arg;
	struct node *n;
	int i;

	for (i = 0; i < connections; i++) {
		pthread_mutex_lock(&wq->lock);
		if (!wq->head)
			pthread_cond_wait(&wq->cond, &wq->lock);
		n = wq_remove(wq);
		pthread_mutex_unlock(&wq->lock);

		wq->work_handler(n);
	}

	return NULL;
}

static void cma_handler(struct rdma_cm_id *id, struct rdma_cm_event *event)
{
	struct node *n = id->context;

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		addr_handler(n);
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		route_handler(n);
		break;
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		n = &nodes[node_index++];
		n->id = id;
		id->context = n;
		wq_insert(&req_wq, n);
		break;
	case RDMA_CM_EVENT_CONNECT_RESPONSE:
		conn_handler(n);
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
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
		n->error = 1;
		conn_handler(n);
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		disc_events++;
		if (is_client()) {
			disc_handler(n);
		} else {
			if (disc_events == 1)
				start_time(STEP_DISCONNECT);
			wq_insert(&disc_wq, n);
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

static int create_ids(int iter)
{
	int ret, i;

	printf("\tCreating IDs\n");
	start_time(STEP_CREATE_ID);
	for (i = 0; i < iter; i++) {
		start_perf(&nodes[i], STEP_FULL_CONNECT);
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

static void destroy_ids(int iter)
{
	int i;

	start_time(STEP_DESTROY_ID);
	for (i = 0; i < iter; i++) {
		start_perf(&nodes[i], STEP_DESTROY_ID);
		if (nodes[i].id)
			rdma_destroy_id(nodes[i].id);
		end_perf(&nodes[i], STEP_DESTROY_ID);
	}
	end_time(STEP_DESTROY_ID);
}

static void destroy_qps(int iter)
{
	int i;

	start_time(STEP_DESTROY_QP);
	for (i = 0; i < iter; i++) {
		start_perf(&nodes[i], STEP_DESTROY_QP);
		if (nodes[i].qp)
			ibv_destroy_qp(nodes[i].qp);
		end_perf(&nodes[i], STEP_DESTROY_QP);
	}
	end_time(STEP_DESTROY_QP);
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

static int server_listen(struct rdma_cm_id **listen_id)
{
	int ret;

	ret = rdma_create_id(channel, listen_id, NULL, hints.ai_port_space);
	if (ret) {
		perror("listen request failed");
		return ret;
	}

	ret = rdma_bind_addr(*listen_id, rai->ai_src_addr);
	if (ret) {
		perror("bind address failed");
		goto err;
	}

	ret = rdma_listen(*listen_id, 0);
	if (ret) {
		perror("failure trying to listen");
		goto err;
	}

	return 0;

err:
	rdma_destroy_id(*listen_id);
	*listen_id = NULL;
	return ret;
}

static void reset_test(int iter)
{
	node_index = 0;
	disc_events = 0;
	connections = iter;

	memset(times, 0, sizeof times);
	memset((void *) completed, 0, sizeof completed);
	memset(nodes, 0, sizeof(*nodes) * iter);
}

static int server_connect(int iter)
{
	int ret;

	reset_test(iter);
	ret = wq_init(&req_wq, req_work_handler);
	if (ret)
		return ret;

	ret = wq_init(&disc_wq, disc_work_handler);
	if (ret)
		return ret;

	process_events(NULL);

	/* Wait for event threads to exit before destroying resources */
	wq_cleanup(&req_wq);
	wq_cleanup(&disc_wq);
	destroy_qps(iter);
	destroy_ids(iter);
	return ret;
}

static int client_connect(int iter)
{
	pthread_t event_thread;
	int i, ret;

	reset_test(iter);
	ret = pthread_create(&event_thread, NULL, process_events, NULL);
	if (ret) {
		perror("failure creating event thread");
		return ret;
	}

	start_time(STEP_FULL_CONNECT);
	ret = create_ids(iter);
	if (ret)
		return ret;

	if (src_addr) {
		printf("\tBinding addresses\n");
		start_time(STEP_BIND);
		for (i = 0; i < iter; i++) {
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

	printf("\tResolving addresses\n");
	start_time(STEP_RESOLVE_ADDR);
	for (i = 0; i < iter; i++) {
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
	}
	while (completed[STEP_RESOLVE_ADDR] != iter)
		sched_yield();
	end_time(STEP_RESOLVE_ADDR);

	printf("\tResolving routes\n");
	start_time(STEP_RESOLVE_ROUTE);
	for (i = 0; i < iter; i++) {
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
	}
	while (completed[STEP_RESOLVE_ROUTE] != iter)
		sched_yield();
	end_time(STEP_RESOLVE_ROUTE);

	printf("\tCreating QPs\n");
	start_time(STEP_CREATE_QP);
	for (i = 0; i < iter; i++) {
		if (nodes[i].error)
			continue;
		ret = create_qp(&nodes[i]);
		if (ret)
			continue;
	}
	end_time(STEP_CREATE_QP);

	printf("\tModify QPs to INIT\n");
	start_time(STEP_INIT_QP);
	for (i = 0; i < iter; i++) {
		if (nodes[i].error)
			continue;
		ret = modify_qp(&nodes[i], IBV_QPS_INIT, STEP_INIT_QP_ATTR);
		if (ret)
			continue;
	}
	end_time(STEP_INIT_QP);

	printf("\tConnecting\n");
	start_time(STEP_CONNECT);
	for (i = 0; i < iter; i++) {
		if (nodes[i].error)
			continue;
		connect_qp(&nodes[i]);
	}
	while (completed[STEP_CONNECT] != iter)
		sched_yield();
	end_time(STEP_CONNECT);
	end_time(STEP_FULL_CONNECT);

	printf("\tDisconnecting\n");
	start_time(STEP_DISCONNECT);
	for (i = 0; i < iter; i++) {
		if (nodes[i].error)
			continue;
		start_perf(&nodes[i], STEP_DISCONNECT);
		rdma_disconnect(nodes[i].id);
	}
	while (completed[STEP_DISCONNECT] != iter)
		sched_yield();
	end_time(STEP_DISCONNECT);

	printf("\tDestroying QPs\n");
	destroy_qps(iter);
	printf("\tDestroying IDs\n");
	destroy_ids(iter);

	return ret;
}

static int run_client(int iter)
{
	int ret;

	ret = oob_client_setup(dst_addr, port, &oob_sock);
	if (ret)
		return ret;

	printf("Client warmup\n");
	ret = client_connect(1);
	if (ret)
		goto out;

	if (!mimic) {
		printf("Connect (%d) QPs test\n", iter);
	} else {
		printf("Connect (%d) simulated QPs test (delay %d us)\n",
			iter, mimic_qp_delay);
		use_qpn = base_qpn;
	}
	ret = client_connect(iter);
	if (ret)
		goto out;

	show_perf(iter);

	printf("Connect (%d) test - no QPs\n", iter);
	use_qpn = base_qpn;
	mimic_qp_delay = 0;
	ret = client_connect(iter);
	if (ret)
		goto out;

	show_perf(iter);
out:
	close(oob_sock);
	return 0;
}

static int run_server(int iter)
{
	struct rdma_cm_id *listen_id;
	int ret;

	/* Make sure we're ready for RDMA prior to any OOB sync */
	ret = server_listen(&listen_id);
	if (ret)
		return ret;

	ret = oob_server_setup(src_addr, port, &oob_sock);
	if (ret)
		goto out;

	printf("Server warmup\n");
	ret = server_connect(1);
	if (ret)
		goto out;

	if (!mimic) {
		printf("Accept (%d) QPs test\n", iter);
	} else {
		printf("Accept (%d) simulated QPs test (delay %d us)\n",
			iter, mimic_qp_delay);
		use_qpn = base_qpn;
	}
	ret = server_connect(iter);
	if (ret)
		goto out;

	show_perf(iter);

	printf("Accept (%d) test - no QPs\n", iter);
	use_qpn = base_qpn;
	mimic_qp_delay = 0;
	ret = server_connect(iter);
	if (ret)
		goto out;

	show_perf(iter);
out:
	close(oob_sock);
	rdma_destroy_id(listen_id);
	return ret;
}

int main(int argc, char **argv)
{
	int iter = 100;
	int op, ret;

	hints.ai_port_space = RDMA_PS_TCP;
	hints.ai_qp_type = IBV_QPT_RC;
	while ((op = getopt(argc, argv, "s:b:c:m:p:q:r:t:")) != -1) {
		switch (op) {
		case 's':
			dst_addr = optarg;
			break;
		case 'b':
			src_addr = optarg;
			break;
		case 'c':
			iter = atoi(optarg);
			break;
		case 'p':
			port = optarg;
			break;
		case 'q':
			base_qpn = (uint32_t) atoi(optarg);
			break;
		case 'm':
			mimic_qp_delay = (uint32_t) atoi(optarg);
			mimic = true;
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
			printf("\t[-q base_qpn]\n");
			printf("\t[-m mimic_qp_delay_us]\n");
			printf("\t[-r retries]\n");
			printf("\t[-t timeout_ms]\n");
			exit(1);
		}
	}

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

	nodes = calloc(sizeof *nodes, iter);
	if (!nodes) {
		ret = -ENOMEM;
		goto destchan;
	}

	if (is_client()) {
		ret = run_client(iter);
	} else {
		ret = run_server(iter);
	}

	free(nodes);
destchan:
	rdma_destroy_event_channel(channel);
freeinfo:
	rdma_freeaddrinfo(rai);
out:
	return ret;
}
