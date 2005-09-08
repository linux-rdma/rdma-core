/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <string.h>
#include <glob.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <endian.h>
#include <byteswap.h>
#include <netinet/in.h>

#include <infiniband/sa.h>
#include <infiniband/cm.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t cpu_to_be64(uint64_t x) { return bswap_64(x); }
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t cpu_to_be64(uint64_t x) { return x; }
#endif

#define TEST_SID 0x0000000ff0000000ULL

static int cm_connect(struct ib_cm_id *cm_id)
{
	struct ib_cm_req_param param;
	struct ib_sa_path_rec sa;
	union ibv_gid *dst;
	union ibv_gid *src;

	param.qp_type       = IBV_QPT_RC;
	param.qp_num        = 0xff00;
	param.starting_psn  = 0x7000;
        param.service_id    = TEST_SID;


        param.primary_path     = &sa;
	param.alternate_path   = NULL;
	param.private_data     = NULL;
        param.private_data_len = 0;

        param.peer_to_peer               = 0;
        param.responder_resources        = 4;
        param.initiator_depth            = 4;
        param.remote_cm_response_timeout = 20;
        param.flow_control               = 1;
        param.local_cm_response_timeout  = 20;
        param.retry_count                = 2;
        param.rnr_retry_count            = 7;
        param.max_cm_retries             = 3;
        param.srq                        = 0;

	memset(&sa, 0, sizeof(sa));

	src = (union ibv_gid *)&sa.sgid;
	dst = (union ibv_gid *)&sa.dgid;

	sa.dlid = htons(0x1f9);
	sa.slid = htons(0x3e1);

	sa.reversible = 0x1000000;

	sa.pkey = 0xffff;
	sa.mtu  = IBV_MTU_1024;

	sa.mtu_selector  = 2;
	sa.rate_selector = 2;
	sa.rate          = 3;
	sa.packet_life_time_selector = 2;
	sa.packet_life_time          = 2;

	src->global.subnet_prefix = cpu_to_be64(0xfe80000000000000ULL);
	dst->global.subnet_prefix = cpu_to_be64(0xfe80000000000000ULL);
	src->global.interface_id  = cpu_to_be64(0x0002c90107fc5e11ULL);
	dst->global.interface_id  = cpu_to_be64(0x0002c90107fc5eb1ULL);

	return ib_cm_send_req(cm_id, &param);
}

int main(int argc, char **argv)
{
	struct ib_cm_event *event;
	struct ib_cm_rep_param rep;
	struct ib_cm_id *cm_id;
	int result;

	int param_c = 0;
	int status = 0;
	int mode;

	/*
	 * read command line.
	 */
	if (2 != argc ||
	    0 > (mode = atoi(argv[++param_c]))) {

		fprintf(stderr, "usage: %s <mode>\n", argv[0]);

		fprintf(stderr, "  mode - [client:1|server:0]\n");
		exit(1);
	}

	result = ib_cm_create_id(&cm_id, NULL);
	if (result) {
		printf("Error creating CM ID <%d:%d>\n", result, errno);
		goto done;
	}

	if (mode) {
		result = cm_connect(cm_id);
		if (result) {
			printf("Error <%d:%d> sending REQ\n", 
			       result, errno);
			goto done;
		}
	}
	else {
		result = ib_cm_listen(cm_id, TEST_SID, 0);
		if (result) {
			printf("Error <%d:%d> listening\n", 
			       result, errno);
			goto done;
		}
	}

	while (!status) {

		result = ib_cm_get_event(&event);
		if (result) {
			printf("Error <%d:%d> getting event\n", 
			       result, errno);
			goto done;
		}

		printf("CM ID <%p> Event <%d>\n", event->cm_id, event->event);

		switch (event->event) {
		case IB_CM_REQ_RECEIVED:

			result = ib_cm_destroy_id(cm_id);
			if (result < 0) {
				printf("Error destroying listen ID <%d:%d>\n",
				       result, errno);
				goto done;
			}
			
			cm_id = event->cm_id;

			rep.qp_num = event->param.req_rcvd.remote_qpn + 1;
			rep.starting_psn = event->param.req_rcvd.starting_psn;

			rep.private_data        = NULL;
			rep.private_data_len    = 0;

			rep.responder_resources = 4;
			rep.initiator_depth     = 4;
			rep.target_ack_delay    = 14;
			rep.failover_accepted   = 0;
			rep.flow_control        = 1;
			rep.rnr_retry_count     = 7;
			rep.srq                 = 0;

			result = ib_cm_send_rep(cm_id, &rep);
			if (result < 0) {
				printf("Error <%d:%d> sending REP\n",
				       result, errno);
				goto done;
			}
		
			break;
		case IB_CM_REP_RECEIVED:

			result = ib_cm_send_rtu(cm_id, NULL, 0);
			if (result < 0) {
				printf("Error <%d:%d> sending RTU\n",
				       result, errno);
				goto done;
			}

			break;
		case IB_CM_RTU_RECEIVED:

			result = ib_cm_send_dreq(cm_id, NULL, 0);
			if (result < 0) {
				printf("Error <%d:%d> sending DREQ\n",
				       result, errno);
				goto done;
			}

			break;
		case IB_CM_DREQ_RECEIVED:

			result = ib_cm_send_drep(cm_id, NULL, 0);
			if (result < 0) {
				printf("Error <%d:%d> sending DREP\n",
				       result, errno);
				goto done;
			}

			break;
		case IB_CM_DREP_RECEIVED:
			break;
		case IB_CM_TIMEWAIT_EXIT:
			status = 1;
			break;
		default:
			status = EINVAL;
			printf("Unhandled event <%d>\n", event->event);
			break;
		}

		result = ib_cm_ack_event(event);
		if (result) {
			printf("Error <%d:%d> freeing event\n", 
			       result, errno);
			goto done;
		}
	}


	result = ib_cm_destroy_id(cm_id);
	if (result < 0) {
		printf("Error destroying CM ID <%d:%d>\n", result, errno);
		goto done;
	}

done:
	return 0;
}
