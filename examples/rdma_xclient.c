/*
 * Copyright (c) 2010-2011 Intel Corporation.  All rights reserved.
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
#include <ctype.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>

static char *server = "127.0.0.1";
static char port[6] = "7471";

static int (*run_func)() = NULL;
struct rdma_cm_id *id;
struct ibv_mr *mr;
enum ibv_qp_type qpt = IBV_QPT_RC;

#define MSG_SIZE 16
uint8_t send_msg[MSG_SIZE];
uint8_t recv_msg[MSG_SIZE];

#ifdef IBV_XRC_OPS
#define PRINT_XRC_OPT printf("\t    x - XRC: extended-reliable-connected\n")
uint32_t srqn;

/*
 * Connect XRC SEND QP.
 */
static int xrc_connect_send(void)
{
	struct rdma_addrinfo hints, *res;
	struct ibv_qp_init_attr attr;
	int ret;

	memset(&hints, 0, sizeof hints);
	hints.ai_port_space = RDMA_PS_IB;
	hints.ai_qp_type = IBV_QPT_XRC_SEND;
	ret = rdma_getaddrinfo(server, port, &hints, &res);
	if (ret) {
		printf("rdma_getaddrinfo connect send %d\n", errno);
		return ret;
	}

	memset(&attr, 0, sizeof attr);
	attr.cap.max_send_wr = 1;
	attr.cap.max_send_sge = 1;
	attr.cap.max_inline_data = sizeof send_msg;
	attr.qp_context = id;
	attr.sq_sig_all = 1;
	ret = rdma_create_ep(&id, res, NULL, &attr);
	rdma_freeaddrinfo(res);
	if (ret) {
		printf("rdma_create_ep send qp %d\n", errno);
		return ret;
	}

	ret = rdma_connect(id, NULL);
	if (ret) {
		printf("rdma_connect send qp %d\n", errno);
		return ret;
	}

	return 0;
}

/*
 * Resolve remote SRQ number
 */
static int xrc_resolve_srqn(void)
{
	struct rdma_addrinfo hints, *res;
	struct rdma_cm_id *id;
	int ret;

	memset(&hints, 0, sizeof hints);
	hints.ai_qp_type = IBV_QPT_UD; /* for now */
	hints.ai_port_space = RDMA_PS_IB;
	sprintf(port, "%d", atoi(port) + 1);
	ret = rdma_getaddrinfo(server, port, &hints, &res);
	if (ret) {
		printf("rdma_getaddrinfo resolve srqn %d\n", errno);
		return ret;
	}

	ret = rdma_create_ep(&id, res, NULL, NULL);
	rdma_freeaddrinfo(res);
	if (ret) {
		printf("rdma_create_ep for srqn %d\n", errno);
		return ret;
	}

	ret = rdma_connect(id, NULL);
	if (ret) {
		printf("rdma_connect for srqn %d\n", errno);
		return ret;
	}

	srqn = id->event->param.ud.qp_num;
	rdma_destroy_ep(id);
	return 0;
}

static int xrc_test(void)
{
	struct ibv_send_wr wr, *bad;
	struct ibv_sge sge;
	struct ibv_wc wc;
	int ret;

	ret = xrc_connect_send();
	if (ret)
		return ret;

	ret = xrc_resolve_srqn();
	if (ret)
		return ret;

	sge.addr = (uint64_t) (uintptr_t) send_msg;
	sge.length = (uint32_t) sizeof send_msg;
	sge.lkey = 0;
	wr.wr_id = (uintptr_t) NULL;
	wr.next = NULL;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.opcode = IBV_WR_SEND;
	wr.send_flags = IBV_SEND_INLINE;
	wr.wr.xrc.remote_srqn = srqn;

	ret = ibv_post_send(id->qp, &wr, &bad);
	if (ret) {
		printf("rdma_post_send %d\n", errno);
		return ret;
	}

	ret = rdma_get_send_comp(id, &wc);
	if (ret <= 0) {
		printf("rdma_get_recv_comp %d\n", ret);
		return ret;
	}

	rdma_disconnect(id);
	rdma_destroy_ep(id);
	return 0;
}

static inline int set_xrc_qpt(void)
{
	qpt = IBV_QPT_XRC_SEND;
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
	hints.ai_port_space = RDMA_PS_TCP;
	ret = rdma_getaddrinfo(server, port, &hints, &res);
	if (ret) {
		printf("rdma_getaddrinfo %d\n", errno);
		return ret;
	}

	memset(&attr, 0, sizeof attr);
	attr.cap.max_send_wr = attr.cap.max_recv_wr = 1;
	attr.cap.max_send_sge = attr.cap.max_recv_sge = 1;
	attr.cap.max_inline_data = sizeof send_msg;
	attr.qp_context = id;
	attr.sq_sig_all = 1;
	ret = rdma_create_ep(&id, res, NULL, &attr);
	rdma_freeaddrinfo(res);
	if (ret) {
		printf("rdma_create_ep %d\n", errno);
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

	ret = rdma_connect(id, NULL);
	if (ret) {
		printf("rdma_connect %d\n", errno);
		return ret;
	}

	ret = rdma_post_send(id, NULL, send_msg, sizeof send_msg, NULL, IBV_SEND_INLINE);
	if (ret) {
		printf("rdma_post_send %d\n", errno);
		return ret;
	}

	ret = rdma_get_recv_comp(id, &wc);
	if (ret <= 0) {
		printf("rdma_get_recv_comp %d\n", ret);
		return ret;
	}

	rdma_disconnect(id);
	rdma_dereg_mr(mr);
	rdma_destroy_ep(id);
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
	while ((op = getopt(argc, argv, "s:p:c:")) != -1) {
		switch (op) {
		case 's':
			server = optarg;
			break;
		case 'p':
			strncpy(port, optarg, sizeof port - 1);
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
	printf("\t[-s server]\n");
	printf("\t[-p port_number]\n");
	printf("\t[-c communication type]\n");
	printf("\t    r - RC: reliable-connected (default)\n");
	PRINT_XRC_OPT;
	exit(1);
}
