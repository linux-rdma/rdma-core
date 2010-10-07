/*
 * Copyright (c) 2004-2006 Intel Corporation.  All rights reserved.
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
 * $Id$
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <byteswap.h>

#include <asm/byteorder.h>
#include <netinet/in.h>

#include <infiniband/cm.h>
#include <rdma/rdma_cma.h>

struct cmtest {
	struct ibv_device	*device;
	struct ib_cm_device	*cm_dev;
	struct ibv_context	*verbs;
	struct ibv_pd		*pd;
	struct ibv_device_attr	dev_attr;

	/* cm info */
	struct ibv_sa_path_rec	path_rec;

	struct cmtest_node	*nodes;
	int			conn_index;
	int			connects_left;
	int			disconnects_left;

	/* memory region info */
	struct ibv_mr		*mr;
	void			*mem;
};

static struct cmtest test;
static int message_count = 10;
static int message_size = 100;
static int connections = 1;
static int is_server = 1;

struct cmtest_node {
	int			id;
	struct ibv_cq		*cq;
	struct ibv_qp		*qp;
	struct ib_cm_id		*cm_id;
	int			connected;
};

static int post_recvs(struct cmtest_node *node)
{
	struct ibv_recv_wr recv_wr, *recv_failure;
	struct ibv_sge sge;
	int i, ret = 0;

	if (!message_count)
		return 0;

	recv_wr.next = NULL;
	recv_wr.sg_list = &sge;
	recv_wr.num_sge = 1;
	recv_wr.wr_id = (uintptr_t) node;

	sge.length = message_size;
	sge.lkey = test.mr->lkey;
	sge.addr = (uintptr_t) test.mem;

	for (i = 0; i < message_count && !ret; i++ ) {
		ret = ibv_post_recv(node->qp, &recv_wr, &recv_failure);
		if (ret) {
			printf("failed to post receives: %d\n", ret);
			break;
		}
	}
	return ret;
}

static int modify_to_rtr(struct cmtest_node *node,
			 struct ib_cm_rep_param *rep)
{
	struct ibv_qp_attr qp_attr;
	int qp_attr_mask, ret;

	qp_attr.qp_state = IBV_QPS_INIT;
	ret = ib_cm_init_qp_attr(node->cm_id, &qp_attr, &qp_attr_mask);
	if (ret) {
		printf("failed to init QP attr for INIT: %d\n", ret);
		return ret;
	}
	ret = ibv_modify_qp(node->qp, &qp_attr, qp_attr_mask);
	if (ret) {
		printf("failed to modify QP to INIT: %d\n", ret);
		return ret;
	}
	qp_attr.qp_state = IBV_QPS_RTR;
	ret = ib_cm_init_qp_attr(node->cm_id, &qp_attr, &qp_attr_mask);
	if (ret) {
		printf("failed to init QP attr for RTR: %d\n", ret);
		return ret;
	}
	qp_attr.rq_psn = node->qp->qp_num;
	if (rep) {
		qp_attr.max_dest_rd_atomic = rep->responder_resources;
		qp_attr.max_rd_atomic = rep->initiator_depth;
	}
	ret = ibv_modify_qp(node->qp, &qp_attr, qp_attr_mask);
	if (ret) {
		printf("failed to modify QP to RTR: %d\n", ret);
		return ret;
	}
	return 0;
}

static int modify_to_rts(struct cmtest_node *node)
{
	struct ibv_qp_attr qp_attr;
	int qp_attr_mask, ret;

	qp_attr.qp_state = IBV_QPS_RTS;
	ret = ib_cm_init_qp_attr(node->cm_id, &qp_attr, &qp_attr_mask);
	if (ret) {
		printf("failed to init QP attr for RTS: %d\n", ret);
		return ret;
	}
	ret = ibv_modify_qp(node->qp, &qp_attr, qp_attr_mask);
	if (ret) {
		printf("failed to modify QP to RTS: %d\n", ret);
		return ret;
	}
	return 0;
}

static void req_handler(struct ib_cm_id *cm_id, struct ib_cm_event *event)
{
	struct cmtest_node *node;
	struct ib_cm_req_event_param *req;
	struct ib_cm_rep_param rep;
	int ret;

	if (test.conn_index == connections)
		goto error1;
	node = &test.nodes[test.conn_index++];

	req = &event->param.req_rcvd;
	memset(&rep, 0, sizeof rep);

	/*
	 * Limit the responder resources requested by the remote
	 * to our capabilities.  Note that the kernel swaps
	 * req->responder_resources and req->initiator_depth, so
	 * that req->responder_resources is actually the active
	 * side's initiator depth.
	 */
	if (req->responder_resources > test.dev_attr.max_qp_rd_atom)
		rep.responder_resources = test.dev_attr.max_qp_rd_atom;
	else
		rep.responder_resources = req->responder_resources;

	/*
	 * Note: if this side of the connection is never going to
	 * use RDMA read opreations, then initiator_depth can be set
	 * to 0 here.
	 */
	if (req->initiator_depth > test.dev_attr.max_qp_init_rd_atom)
		rep.initiator_depth = test.dev_attr.max_qp_init_rd_atom; 
	else
		rep.initiator_depth = req->initiator_depth;

	node->cm_id = cm_id;
	cm_id->context = node;

	ret = modify_to_rtr(node, &rep);
	if (ret)
		goto error2;

	ret = post_recvs(node);
	if (ret)
		goto error2;

	rep.qp_num = node->qp->qp_num;
	rep.srq = (node->qp->srq != NULL);
	rep.starting_psn = node->qp->qp_num;
	rep.target_ack_delay = 20;
	rep.flow_control = req->flow_control;
	rep.rnr_retry_count = req->rnr_retry_count;

	ret = ib_cm_send_rep(cm_id, &rep);
	if (ret) {
		printf("failed to send CM REP: %d\n", ret);
		goto error2;
	}
	return;
error2:
	test.disconnects_left--;
	test.connects_left--;
error1:
	printf("failing connection request\n");
	ib_cm_send_rej(cm_id, IB_CM_REJ_UNSUPPORTED, NULL, 0, NULL, 0);
}

static void rep_handler(struct cmtest_node *node, struct ib_cm_event *event)
{
	int ret;

	ret = modify_to_rtr(node, NULL);
	if (ret)
		goto error;

	ret = modify_to_rts(node);
	if (ret)
		goto error;

	ret = post_recvs(node);
	if (ret)
		goto error;

	ret = ib_cm_send_rtu(node->cm_id, NULL, 0);
	if (ret) {
		printf("failed to send CM RTU: %d\n", ret);
		goto error;
	}
	node->connected = 1;
	test.connects_left--;
	return;
error:
	printf("failing connection reply\n");
	ib_cm_send_rej(node->cm_id, IB_CM_REJ_UNSUPPORTED, NULL, 0, NULL, 0);
	test.disconnects_left--;
	test.connects_left--;
}

static void rtu_handler(struct cmtest_node *node)
{
	int ret;

	ret = modify_to_rts(node);
	if (ret)
		goto error;

	node->connected = 1;
	test.connects_left--;
	return;
error:
	printf("aborting connection - disconnecting\n");
	ib_cm_send_dreq(node->cm_id, NULL, 0);
	test.disconnects_left--;
	test.connects_left--;
}

static void cm_handler(struct ib_cm_id *cm_id, struct ib_cm_event *event)
{
	struct cmtest_node *node = cm_id->context;

	switch (event->event) {
	case IB_CM_REQ_RECEIVED:
		req_handler(cm_id, event);
		break;
	case IB_CM_REP_RECEIVED:
		rep_handler(node, event);
		break;
	case IB_CM_RTU_RECEIVED:
		rtu_handler(node);
		break;
	case IB_CM_DREQ_RECEIVED:
		node->connected = 0;
		ib_cm_send_drep(node->cm_id, NULL, 0);
		test.disconnects_left--;
		break;
	case IB_CM_DREP_RECEIVED:
		test.disconnects_left--;
		break;
	case IB_CM_REJ_RECEIVED:
		printf("Received REJ\n");
		/* fall through */
	case IB_CM_REQ_ERROR:
	case IB_CM_REP_ERROR:
		printf("Error sending REQ or REP\n");
		test.disconnects_left--;
		test.connects_left--;
		break;
	case IB_CM_DREQ_ERROR:
		test.disconnects_left--;
		printf("Error sending DREQ\n");
		break;
	default:
		break;
	}
}

static int init_node(struct cmtest_node *node, struct ibv_qp_init_attr *qp_attr)
{
	int cqe, ret;

	if (!is_server) {
		ret = ib_cm_create_id(test.cm_dev, &node->cm_id, node);
		if (ret) {
			printf("failed to create cm_id: %d\n", ret);
			return ret;
		}
	}

	cqe = message_count ? message_count * 2 : 2;
	node->cq = ibv_create_cq(test.verbs, cqe, node, NULL, 0);
	if (!node->cq) {
		printf("unable to create CQ\n");
		goto error1;
	}

	qp_attr->send_cq = node->cq; 
	qp_attr->recv_cq = node->cq; 
	node->qp = ibv_create_qp(test.pd, qp_attr);
	if (!node->qp) {
		printf("unable to create QP\n");
		goto error2;
	}
	return 0;
error2:
	ibv_destroy_cq(node->cq);
error1:
	if (!is_server)
		ib_cm_destroy_id(node->cm_id);
	return -1;
}

static void destroy_node(struct cmtest_node *node)
{
	ibv_destroy_qp(node->qp);
	ibv_destroy_cq(node->cq);
	if (node->cm_id)
		ib_cm_destroy_id(node->cm_id);
}

static int create_nodes(void)
{
	struct ibv_qp_init_attr qp_attr;
	int ret, i;

	test.nodes = malloc(sizeof *test.nodes * connections);
	if (!test.nodes) {
		printf("unable to allocate memory for test nodes\n");
		return -1;
	}
	memset(test.nodes, 0, sizeof *test.nodes * connections);

	memset(&qp_attr, 0, sizeof qp_attr);
	qp_attr.cap.max_send_wr = message_count ? message_count : 1;
	qp_attr.cap.max_recv_wr = message_count ? message_count : 1;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_sge = 1;
	qp_attr.qp_type = IBV_QPT_RC;

	for (i = 0; i < connections; i++) {
		test.nodes[i].id = i;
		ret = init_node(&test.nodes[i], &qp_attr);
		if (ret)
			goto error;
	}
	return 0;
error:
	while (--i >= 0)
		destroy_node(&test.nodes[i]);
	free(test.nodes);
	return ret;
}

static void destroy_nodes(void)
{
	int i;

	for (i = 0; i < connections; i++)
		destroy_node(&test.nodes[i]);
	free(test.nodes);
}

static int create_messages(void)
{
	if (!message_size)
		message_count = 0;

	if (!message_count)
		return 0;

	test.mem = malloc(message_size);
	if (!test.mem) {
		printf("failed message allocation\n");
		return -1;
	}
	test.mr = ibv_reg_mr(test.pd, test.mem, message_size,
			     IBV_ACCESS_LOCAL_WRITE);
	if (!test.mr) {
		printf("failed to reg MR\n");
		goto err;
	}
	return 0;
err:
	free(test.mem);
	return -1;
}

static void destroy_messages(void)
{
	if (!message_count)
		return;

	ibv_dereg_mr(test.mr);
	free(test.mem);
}

static int init(void)
{
	struct ibv_device **dev_list;
	int ret;

	test.connects_left = connections;
	test.disconnects_left = connections;

	dev_list = ibv_get_device_list(NULL);
	test.device = dev_list[0];
	if (!test.device)
		return -1;

	test.verbs = ibv_open_device(test.device);
	if (!test.verbs)
		return -1;

	if (ibv_query_device(test.verbs, &test.dev_attr))
		return -1;

	test.cm_dev = ib_cm_open_device(test.verbs);
	if (!test.cm_dev)
		return -1;

	test.pd = ibv_alloc_pd(test.verbs);
	if (!test.pd) {
		printf("failed to alloc PD\n");
		return -1;
	}
	ret = create_messages();
	if (ret) {
		printf("unable to create test messages\n");
		goto error1;
	}
	ret = create_nodes();
	if (ret) {
		printf("unable to create test nodes\n");
		goto error2;
	}
	return 0;
error2:
	destroy_messages();
error1:
	ibv_dealloc_pd(test.pd);
	return -1;
}

static void cleanup(void)
{
	destroy_nodes();
	destroy_messages();
	ibv_dealloc_pd(test.pd);
	ib_cm_close_device(test.cm_dev);
	ibv_close_device(test.verbs);
}

static int send_msgs(void)
{
	struct ibv_send_wr send_wr, *bad_send_wr;
	struct ibv_sge sge;
	int i, m, ret;

	send_wr.next = NULL;
	send_wr.sg_list = &sge;
	send_wr.num_sge = 1;
	send_wr.opcode = IBV_WR_SEND;
	send_wr.send_flags = IBV_SEND_SIGNALED;
	send_wr.wr_id = 0;

	sge.addr = (uintptr_t) test.mem;
	sge.length = message_size;
	sge.lkey = test.mr->lkey;

	for (i = 0; i < connections; i++) {
		if (!test.nodes[i].connected)
			continue;

		for (m = 0; m < message_count; m++) {
			ret = ibv_post_send(test.nodes[i].qp, &send_wr,
					    &bad_send_wr);
			if (ret)
				return ret;
		}
	}
	return 0;
}

static int poll_cqs(void)
{
	struct ibv_wc wc[8];
	int done, i, ret;

	for (i = 0; i < connections; i++) {
		if (!test.nodes[i].connected)
			continue;

		for (done = 0; done < message_count; done += ret) {
			ret = ibv_poll_cq(test.nodes[i].cq, 8, wc);
			if (ret < 0) {
				printf("failed polling CQ: %d\n", ret);
				return ret;
			}
		}
	}
	return 0;
}

static void connect_events(void)
{
	struct ib_cm_event *event;
	int err = 0;

	while (test.connects_left && !err) {
		err = ib_cm_get_event(test.cm_dev, &event);
		if (!err) {
			cm_handler(event->cm_id, event);
			ib_cm_ack_event(event);
		}
	}
}

static void disconnect_events(void)
{
	struct ib_cm_event *event;
	int err = 0;

	while (test.disconnects_left && !err) {
		err = ib_cm_get_event(test.cm_dev, &event);
		if (!err) {
			cm_handler(event->cm_id, event);
			ib_cm_ack_event(event);
		}
	}
}

static void run_server(void)
{
	struct ib_cm_id *listen_id;
	int i, ret;

	printf("starting server\n");
	if (ib_cm_create_id(test.cm_dev, &listen_id, &test)) {
		printf("listen request failed\n");
		return;
	}
	ret = ib_cm_listen(listen_id, __cpu_to_be64(0x1000), 0);
	if (ret) {
		printf("failure trying to listen: %d\n", ret);
		goto out;
	}

	connect_events();

	if (message_count) {
		printf("initiating data transfers\n");
		if (send_msgs())
			goto out;
		printf("receiving data transfers\n");
		if (poll_cqs())
			goto out;
		printf("data transfers complete\n");
	}

	printf("disconnecting\n");
	for (i = 0; i < connections; i++) {
		if (!test.nodes[i].connected)
			continue;

		test.nodes[i].connected = 0;
		ib_cm_send_dreq(test.nodes[i].cm_id, NULL, 0);
	}
	disconnect_events();
 	printf("disconnected\n");
out:
	ib_cm_destroy_id(listen_id);
}

static int get_dst_addr(char *dst, struct sockaddr_in *addr_in)
{
	struct addrinfo *res;
	int ret;

	ret = getaddrinfo(dst, NULL, NULL, &res);
	if (ret)
		return ret;

	if (res->ai_family != PF_INET) {
		ret = -1;
		goto out;
	}

	*addr_in = *(struct sockaddr_in *) res->ai_addr;
	addr_in->sin_port = 7471;
out:
	freeaddrinfo(res);
	return ret;
}

static int query_for_path(char *dst)
{
	struct rdma_event_channel *channel;
	struct rdma_cm_id *id;
	struct sockaddr_in addr_in;
	struct rdma_cm_event *event;
	int ret;

	ret = get_dst_addr(dst, &addr_in);
	if (ret)
		return ret;

	channel = rdma_create_event_channel();
	if (!channel)
		return -1;

	ret = rdma_create_id(channel, &id, NULL, RDMA_PS_TCP);
	if (ret)
		goto destroy_channel;

	ret = rdma_resolve_addr(id, NULL, (struct sockaddr *) &addr_in, 2000);
	if (ret)
		goto out;

	ret = rdma_get_cm_event(channel, &event);
	if (!ret && event->event != RDMA_CM_EVENT_ADDR_RESOLVED)
		ret = event->status;
	rdma_ack_cm_event(event);
	if (ret)
		goto out;

	ret = rdma_resolve_route(id, 2000);
	if (ret)
		goto out;

	ret = rdma_get_cm_event(channel, &event);
	if (!ret && event->event != RDMA_CM_EVENT_ROUTE_RESOLVED)
		ret = event->status;
	rdma_ack_cm_event(event);
	if (ret)
		goto out;

	test.path_rec = id->route.path_rec[0];
out:
	rdma_destroy_id(id);
destroy_channel:
	rdma_destroy_event_channel(channel);
	return ret;
}

static void run_client(char *dst)
{
	struct ib_cm_req_param req;
	int i, ret;

	printf("starting client\n");
	ret = query_for_path(dst);
	if (ret) {
		printf("failed path record query: %d\n", ret);
		return;
	}

	memset(&req, 0, sizeof req);
	req.primary_path = &test.path_rec;
	req.service_id = __cpu_to_be64(0x1000);

	/*
	 * When choosing the responder resources for a ULP, it is usually
	 * best to use the maximum value of the HCA.  If the other side is
	 * not going to use RDMA read, then it should zero out the
	 * initiator_depth in the REP, which will zero out the local
	 * responder_resources when we program the QP.  Generally, the
	 * initiator_depth should be either set to 0 or
	 * min(max_qp_rd_atom, max_send_wr).  Use 0 if RDMA read is
	 * never going to be sent from this side.
	 */
	req.responder_resources = test.dev_attr.max_qp_rd_atom;
	req.initiator_depth = test.dev_attr.max_qp_init_rd_atom;

	req.remote_cm_response_timeout = 20;
	req.local_cm_response_timeout = 20;
	req.retry_count = 5;
	req.max_cm_retries = 5;

	printf("connecting\n");
	for (i = 0; i < connections; i++) {
		req.qp_num = test.nodes[i].qp->qp_num;
		req.qp_type = IBV_QPT_RC;
		req.srq = (test.nodes[i].qp->srq != NULL);
		req.starting_psn = test.nodes[i].qp->qp_num;
		ret = ib_cm_send_req(test.nodes[i].cm_id, &req);
		if (ret) {
			printf("failure sending REQ: %d\n", ret);
			return;
		}
	}

	connect_events();

	if (message_count) {
		printf("receiving data transfers\n");
		if (poll_cqs())
			goto out;
		printf("initiating data transfers\n");
		if (send_msgs())
			goto out;
		printf("data transfers complete\n");
	}
out:
	disconnect_events();
}

int main(int argc, char **argv)
{
	if (argc != 1 && argc != 2) {
		printf("usage: %s [server_ip_addr]\n", argv[0]);
		exit(1);
	}

	is_server = (argc == 1);
	if (init())
		exit(1);

	if (is_server)
		run_server();
	else
		run_client(argv[1]);

	printf("test complete\n");
	cleanup();
	return 0;
}
