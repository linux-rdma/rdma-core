/*
 * Copyright (c) 2005-2011 Intel Corporation.  All rights reserved.
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
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <ctype.h>
#include <netinet/in.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>

static char *port = "7471";

static int (*run_func)();
struct rdma_cm_id *listen_id, *id;
struct ibv_mr *mr;
enum ibv_qp_type qpt = IBV_QPT_RC;

#define MSG_SIZE 16
uint8_t send_msg[MSG_SIZE];
uint8_t recv_msg[MSG_SIZE];


#ifdef IBV_XRC_OPS
#define PRINT_XRC_OPT printf("\t    x - XRC: extended-reliable-connected\n")
struct rdma_cm_id *srq_id;

/*
 * Listen for XRC RECV QP connection request.
 */
static struct rdma_cm_id * xrc_listen_recv(void)
{
	struct rdma_addrinfo hints, *res;
	struct rdma_cm_id *id;
	int ret;

	memset(&hints, 0, sizeof hints);
	hints.ai_flags = RAI_PASSIVE;
	hints.ai_port_space = RDMA_PS_IB;
	hints.ai_qp_type = IBV_QPT_XRC_RECV;
	ret = rdma_getaddrinfo(NULL, port, &hints, &res);
	if (ret) {
		printf("rdma_getaddrinfo listen recv %d\n", errno);
		return NULL;
	}

	ret = rdma_create_ep(&listen_id, res, NULL, NULL);
	rdma_freeaddrinfo(res);
	if (ret) {
		printf("rdma_create_ep listen recv %d\n", errno);
		return NULL;
	}

	ret = rdma_listen(listen_id, 0);
	if (ret) {
		printf("rdma_listen %d\n", errno);
		return NULL;
	}

	ret = rdma_get_request(listen_id, &id);
	if (ret) {
		printf("rdma_get_request %d\n", errno);
		return NULL;
	}

	return id;
}

/*
 * Create SRQ and listen for XRC SRQN lookup request.
 */
static int xrc_create_srq_listen(struct sockaddr *addr, socklen_t addr_len)
{
	struct rdma_addrinfo rai;
	struct sockaddr_storage ss;
	struct ibv_srq_init_attr attr;
	int ret;

	memset(&rai, 0, sizeof rai);
	rai.ai_flags = RAI_PASSIVE;
	rai.ai_family = addr->sa_family;
	rai.ai_qp_type = IBV_QPT_UD; /* for now */
	rai.ai_port_space = RDMA_PS_IB;
	memcpy(&ss, addr, addr_len);
	rai.ai_src_len = addr_len;
	rai.ai_src_addr = (struct sockaddr *) &ss;
	((struct sockaddr_in *) &ss)->sin_port = htons((short) atoi(port) + 1);

	ret = rdma_create_ep(&srq_id, &rai, NULL, NULL);
	if (ret) {
		printf("rdma_create_ep srq ep %d\n", errno);
		return ret;
	}

	if (!srq_id->verbs) {
		printf("rdma_create_ep failed to bind to device.\n");
		printf("XRC tests cannot use loopback addressing\n");
		return -1;
	}

	memset(&attr, 0, sizeof attr);
	attr.attr.max_wr = 1;
	attr.attr.max_sge = 1;
	attr.srq_type = IBV_SRQT_XRC;

	attr.ext.xrc.xrcd = ibv_open_xrcd(srq_id->verbs, -1, 0);
	if (!attr.ext.xrc.xrcd) {
		printf("Unable to open xrcd\n");
		return -1;
	}

	ret = rdma_create_srq(srq_id, NULL, &attr);
	if (ret) {
		printf("Unable to create srq %d\n", errno);
		return ret;
	}

	ret = rdma_listen(srq_id, 0);
	if (ret) {
		printf("rdma_listen srq id %d\n", errno);
		return ret;
	}

	return 0;
}

static int xrc_test(void)
{
	struct rdma_cm_id *conn_id, *lookup_id;
	struct ibv_qp_init_attr attr;
	struct rdma_conn_param param;
	struct rdma_cm_event *event;
	struct ibv_wc wc;
	int ret;

	conn_id = xrc_listen_recv();
	if (!conn_id)
		return -1;

	ret = xrc_create_srq_listen(rdma_get_local_addr(conn_id),
				    sizeof(struct sockaddr_storage));
	if (ret)
		return -1;

	memset(&attr, 0, sizeof attr);
	attr.qp_type = IBV_QPT_XRC_RECV;
	attr.ext.xrc_recv.xrcd = srq_id->srq->ext.xrc.xrcd;
	ret = rdma_create_qp(conn_id, NULL, &attr);
	if (ret) {
		printf("Unable to create xrc recv qp %d\n", errno);
		return ret;
	}

	ret = rdma_accept(conn_id, NULL);
	if (ret) {
		printf("rdma_accept failed for xrc recv qp %d\n", errno);
		return ret;
	}

	ret = rdma_get_request(srq_id, &lookup_id);
	if (ret) {
		printf("rdma_get_request %d\n", errno);
		return ret;
	}

	mr = rdma_reg_msgs(srq_id, recv_msg, sizeof recv_msg);
	if (!mr) {
		printf("ibv_reg_msgs %d\n", errno);
		return ret;
	}

	ret = rdma_post_recv(srq_id, NULL, recv_msg, sizeof recv_msg, mr);
	if (ret) {
		printf("rdma_post_recv %d\n", errno);
		return ret;
	}

	memset(&param, 0, sizeof param);
	param.qp_num = srq_id->srq->ext.xrc.srq_num;
	ret = rdma_accept(lookup_id, &param);
	if (ret) {
		printf("rdma_accept failed for srqn lookup %d\n", errno);
		return ret;
	}

	rdma_destroy_id(lookup_id);

	ret = rdma_get_recv_comp(srq_id, &wc);
	if (ret <= 0) {
		printf("rdma_get_recv_comp %d\n", ret);
		return ret;
	}

	ret = rdma_get_cm_event(conn_id->channel, &event);
	if (ret || event->event != RDMA_CM_EVENT_DISCONNECTED) {
		printf("Failed to get disconnect event\n");
		return -1;
	}

	rdma_ack_cm_event(event);
	rdma_disconnect(conn_id);
	rdma_destroy_ep(conn_id);
	rdma_dereg_mr(mr);
	rdma_destroy_ep(srq_id);
	rdma_destroy_ep(listen_id);
	return 0;
}

static inline int set_xrc_qpt(void)
{
	qpt = IBV_QPT_XRC_RECV;
	run_func = xrc_test;
	return 0;
}

#else
#define PRINT_XRC_OPT
#define set_xrc_qpt() -1
#endif /* IBV_XRC_OPS */


static int rc_test(void)
{
	struct rdma_addrinfo hints, *res;
	struct ibv_qp_init_attr attr;
	struct ibv_wc wc;
	int ret;

	memset(&hints, 0, sizeof hints);
	hints.ai_flags = RAI_PASSIVE;
	hints.ai_port_space = RDMA_PS_TCP;
	ret = rdma_getaddrinfo(NULL, port, &hints, &res);
	if (ret) {
		printf("rdma_getaddrinfo %d\n", errno);
		return ret;
	}

	memset(&attr, 0, sizeof attr);
	attr.cap.max_send_wr = attr.cap.max_recv_wr = 1;
	attr.cap.max_send_sge = attr.cap.max_recv_sge = 1;
	attr.cap.max_inline_data = sizeof send_msg;
	attr.sq_sig_all = 1;
	ret = rdma_create_ep(&listen_id, res, NULL, &attr);
	rdma_freeaddrinfo(res);
	if (ret) {
		printf("rdma_create_ep %d\n", errno);
		return ret;
	}

	ret = rdma_listen(listen_id, 0);
	if (ret) {
		printf("rdma_listen %d\n", errno);
		return ret;
	}

	ret = rdma_get_request(listen_id, &id);
	if (ret) {
		printf("rdma_get_request %d\n", errno);
		return ret;
	}

	mr = rdma_reg_msgs(id, recv_msg, sizeof recv_msg);
	if (!mr) {
		printf("rdma_reg_msgs %d\n", errno);
		return ret;
	}

	ret = rdma_post_recv(id, NULL, recv_msg, sizeof recv_msg, mr);
	if (ret) {
		printf("rdma_post_recv %d\n", errno);
		return ret;
	}

	ret = rdma_accept(id, NULL);
	if (ret) {
		printf("rdma_accept %d\n", errno);
		return ret;
	}

	ret = rdma_get_recv_comp(id, &wc);
	if (ret <= 0) {
		printf("rdma_get_recv_comp %d\n", ret);
		return ret;
	}

	ret = rdma_post_send(id, NULL, send_msg, sizeof send_msg, NULL, IBV_SEND_INLINE);
	if (ret) {
		printf("rdma_post_send %d\n", errno);
		return ret;
	}

	ret = rdma_get_send_comp(id, &wc);
	if (ret <= 0) {
		printf("rdma_get_send_comp %d\n", ret);
		return ret;
	}

	rdma_disconnect(id);
	rdma_dereg_mr(mr);
	rdma_destroy_ep(id);
	rdma_destroy_ep(listen_id);
	return 0;
}

static int set_qpt(char type)
{
	if (type == 'r') {
		qpt = IBV_QPT_RC;
		return 0;
	} else if (type == 'x') {
		return set_xrc_qpt();
	}
	return -1;
}

int main(int argc, char **argv)
{
	int op, ret;

	run_func = rc_test;
	while ((op = getopt(argc, argv, "p:c:")) != -1) {
		switch (op) {
		case 'p':
			port = optarg;
			break;
		case 'c':
			if (set_qpt(tolower(optarg[0])))
				goto err;
			break;
		default:
			goto err;
		}
	}

	printf("%s: start\n", argv[0]);
	ret = run_func();
	printf("%s: end %d\n", argv[0], ret);
	return ret;

err:
	printf("usage: %s\n", argv[0]);
	printf("\t[-p port_number]\n");
	printf("\t[-c communication type]\n");
	printf("\t    r - RC: reliable-connected (default)\n");
	PRINT_XRC_OPT;
	exit(1);
}
