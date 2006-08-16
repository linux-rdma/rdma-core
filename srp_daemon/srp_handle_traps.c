/*
 * Copyright (c) 2006 Mellanox Technologies. All rights reserved.
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
 * $Author: ishai Rabinovitz [ishai@mellanox.co.il]$
 * 
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <endian.h>
#include <byteswap.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <infiniband/common.h>
#include <infiniband/verbs.h>

#include "srp_ib_types.h"

#include "srp_daemon.h"

void srp_sleep(time_t sec, time_t usec)
{
	int nanosleep(const struct timespec *req, struct timespec *rem);
	struct timespec req, rem;

	if (usec > 1000) {
		sec += usec / 1000;
		usec = usec % 1000;
	}
	req.tv_sec = sec;
	req.tv_nsec = usec * 1000000;

	while (nanosleep(&req, &rem) < 0) {
		if (errno != EINTR)
			return;
		req = rem;
	}
}

/*****************************************************************************
* Function: ud_resources_init
*****************************************************************************/
void 
ud_resources_init(struct ud_resources *res)
{
	res->dev_list = NULL;
	res->ib_ctx = NULL;
	res->send_cq = NULL;
	res->recv_cq = NULL;
	res->qp = NULL;
	res->pd = NULL;
	res->mr = NULL;
	res->ah = NULL;
	res->send_buf = NULL;
	res->recv_buf = NULL;
}


/*****************************************************************************
* Function: modify_qp_to_rts
*****************************************************************************/
static int modify_qp_to_rts(struct ibv_qp *qp)
{	
	struct ibv_qp_attr attr;
	int flags;
	int rc;
	
	/* RESET -> INIT */
	memset(&attr, 0, sizeof(struct ibv_qp_attr));

	attr.qp_state = IBV_QPS_INIT;
	attr.port_num = config->port_num;
	attr.pkey_index = 0;
	attr.qkey = MY_IB_QP1_WELL_KNOWN_Q_KEY;

	flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_QKEY;

	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc) {
		fprintf(stderr, "failed to modify QP state to INIT\n");
		return rc;
	}

	/* INIT -> RTR */
	memset(&attr, 0, sizeof(attr));
	
	attr.qp_state = IBV_QPS_RTR;
 
	flags = IBV_QP_STATE;

	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc) {
		fprintf(stderr, "failed to modify QP state to RTR\n");
		return rc;
	}

	/* RTR -> RTS */
	/* memset(&attr, 0, sizeof(attr)); */
	
	attr.qp_state = IBV_QPS_RTS;
	attr.sq_psn = 0;
	
	flags = IBV_QP_STATE | IBV_QP_SQ_PSN;

	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc) {
		fprintf(stderr, "failed to modify QP state to RTS\n");
		return rc;
	}
	
	return 0;
}	

/*****************************************************************************
* Function: fill_rq_entry
*****************************************************************************/
static int fill_rq_entry(struct ud_resources *res, int cur_receive)
{
	static struct ibv_recv_wr rr;
	static struct ibv_sge sg;
	static int first = 1;
	struct ibv_recv_wr *_bad_wr = NULL;
	struct ibv_recv_wr **bad_wr = &_bad_wr;
	int ret;

	/* prepare the RR */
	if (first) {
		first = 0;
		memset(&rr, 0, sizeof(rr));
	
		sg.length = RECV_BUF_SIZE;
		sg.lkey = res->mr->lkey;
		
		rr.next = NULL;
		rr.sg_list = &sg;
		rr.num_sge = 1;
	}
	
	sg.addr = (((unsigned long)res->recv_buf) + RECV_BUF_SIZE * cur_receive);
	rr.wr_id = cur_receive;
	
	ret = ibv_post_recv(res->qp, &rr, bad_wr);
	if (ret < 0) {
		fprintf(stderr, "failed to post RR\n");
		return ret;
	}
	return 0;
}
	
/*****************************************************************************
* Function: fill_rq
*****************************************************************************/
static int fill_rq(struct ud_resources *res)
{
	int cur_receive;
	int ret;

	for (cur_receive=0; cur_receive<config->num_of_oust; ++cur_receive) {	
		ret = fill_rq_entry(res, cur_receive);
		if (ret < 0) {
			fprintf(stderr, "failed to fill_rq_entry\n");
			return ret;
		}
	}

	return 0;
} 
			
/*****************************************************************************
* Function: ud_resources_create
*****************************************************************************/
int ud_resources_create(struct ud_resources *res)
{
	struct ibv_device *ib_dev = NULL;
	size_t size;
	int i;
	int cq_size;
	int num_devices;

	/* get device names in the system */
	res->dev_list = ibv_get_device_list(&num_devices);
	if (!res->dev_list) {
		fprintf(stderr, "failed to get IB devices list\n");
		return -1;
	}

	for (i = 0; i < num_devices; i ++) {
		if (!strcmp(ibv_get_device_name(res->dev_list[i]), config->dev_name)) {
			ib_dev = res->dev_list[i];
			break;
		}
	}
	
	if (!ib_dev) {
		fprintf(stderr, "IB device %s wasn't found\n", config->dev_name);
		return -ENXIO;
	}
	
	pr_debug("Device %s was found\n", config->dev_name);
	
	/* get device handle */
	res->ib_ctx = ibv_open_device(ib_dev);
	if (!res->ib_ctx) {
		fprintf(stderr, "failed to open device %s\n", config->dev_name);
		return -ENXIO;
	}
	
	res->pd = ibv_alloc_pd(res->ib_ctx);
	if (!res->pd) {
		fprintf(stderr, "ibv_alloc_pd failed\n");
		return -1;
	}

	cq_size = config->num_of_oust;
	res->recv_cq = ibv_create_cq(res->ib_ctx, cq_size, NULL, NULL, 0);
	if (!res->recv_cq) {
		fprintf(stderr, "failed to create CQ with %u entries\n", cq_size);
		return -1;
	}
       	pr_debug("CQ was created with %u CQEs\n", cq_size);

	res->send_cq = ibv_create_cq(res->ib_ctx, 1, NULL, NULL, 0);
	if (!res->send_cq) {
		fprintf(stderr, "failed to create CQ with %u entries\n", cq_size);
		return -1;
	}
	pr_debug("CQ was created with %u CQEs\n", 1);

	size = cq_size * RECV_BUF_SIZE + SEND_SIZE;
	res->recv_buf = (void *) malloc(size);
	if (!res->recv_buf) {
		fprintf(stderr, "failed to malloc %Zu bytes to memory buffer\n", size);
		return -ENOMEM;
	}

	memset(res->recv_buf, 0, size);

	res->send_buf = res->recv_buf + cq_size * RECV_BUF_SIZE;

	res->mr = ibv_reg_mr(res->pd, res->recv_buf, size, IBV_ACCESS_LOCAL_WRITE);
	if (!res->mr) {
		fprintf(stderr, "ibv_reg_mr failed\n");
		return -1;
	}
	pr_debug("MR was created with addr=%p, lkey=0x%x,\n", res->recv_buf, res->mr->lkey);

	{
		struct ibv_qp_init_attr attr = {
			.send_cq = res->send_cq,
			.recv_cq = res->recv_cq,
			.cap     = {
				.max_send_wr  = 1,
				.max_recv_wr  = config->num_of_oust,
				.max_send_sge = 1,
				.max_recv_sge = 1				
			},
			.qp_type = IBV_QPT_UD,
			.sq_sig_all = 1,
		};

		res->qp = ibv_create_qp(res->pd, &attr);
		if (!res->qp) {
			fprintf(stderr, "failed to create QP\n");
			return -1;
		}
		pr_debug("QP was created, QP number=0x%x\n", res->qp->qp_num);
	}
	
	/* modify the QP to RTS (connect the QPs) */
	if (modify_qp_to_rts(res->qp)) {
		fprintf(stderr, "failed to modify QP state from RESET to RTS\n");
		return -1;
	}
	
	pr_debug("QPs were modified to RTS\n");

	if (fill_rq(res))
		return -1;

	res->mad_buffer = malloc(sizeof(ib_sa_mad_t));
	if (!res->mad_buffer) {
		fprintf(stderr, "Could not alloc mad_buffer, abort\n");
		return -1;
	}

	res->mad_buffer_mutex = malloc(sizeof(pthread_mutex_t));
	if (!res->mad_buffer_mutex) {
		fprintf(stderr, "Could not alloc mad_buffer_mutex, abort\n");
		return -1;
	}

	if (pthread_mutex_init(res->mad_buffer_mutex, NULL)) {
		fprintf(stderr, "Could not init mad_buffer_mutex, abort\n");
		return -1;
	}
			
	return 0;
}

int create_ah(struct ud_resources *ud_res)
{
	struct ibv_ah_attr ah_attr;

	/* create the UD AV */
	memset(&ah_attr, 0, sizeof(ah_attr));

	if (ibv_query_port(ud_res->ib_ctx, config->port_num, &ud_res->port_attr)) {
		fprintf(stderr, "ibv_query_port on port %u failed\n", config->port_num);
		return -1;
	}

	ah_attr.dlid = ud_res->port_attr.sm_lid;
	ah_attr.port_num = config->port_num;

	ud_res->ah = ibv_create_ah(ud_res->pd, &ah_attr);
	if (!ud_res->ah) {
		fprintf(stderr, "failed to create UD AV\n");
		return -1;
	}

	return 0;
}

/*****************************************************************************
* Function: ud_resources_destroy
*****************************************************************************/
int ud_resources_destroy(struct ud_resources *res)
{
	int test_result = 0;
	
	if (res->qp) {
		if (ibv_destroy_qp(res->qp)) {
			fprintf(stderr, "failed to destroy QP\n");
			test_result = 1;
		}
	}
	
	if (res->mr) {
		if (ibv_dereg_mr(res->mr)) {
			fprintf(stderr, "ibv_dereg_mr failed\n");
			test_result = 1;
		}
	}
	
	if (res->send_cq) {
		if (ibv_destroy_cq(res->send_cq)) {
			fprintf(stderr, "ibv_destroy_cq of CQ failed\n");
			test_result = 1;
		}
	}
	
	if (res->recv_cq) {
		if (ibv_destroy_cq(res->recv_cq)) {
			fprintf(stderr, "ibv_destroy_cq of CQ failed\n");
			test_result = 1;
		}
	}

	if (res->ah) {
		if (ibv_destroy_ah(res->ah)) {
			fprintf(stderr, "ibv_destroy_ah failed\n");
			test_result = 1;
		}
	}
	
	if (res->pd) {
		if (ibv_dealloc_pd(res->pd)) {
			fprintf(stderr, "ibv_dealloc_pd failed\n");
			test_result = 1;
		}
	}
	
	if (res->ib_ctx) {
		if (ibv_close_device(res->ib_ctx)) {
			fprintf(stderr, "ibv_close_device failed\n");
			test_result = 1;
		}
	}
	
	if (res->dev_list)
		ibv_free_device_list(res->dev_list);
	
	if (res->recv_buf)
		free(res->recv_buf);

	if (res->mad_buffer)
		free(res->mad_buffer);

	if (res->mad_buffer_mutex)
		free(res->mad_buffer_mutex);

	return test_result;
}	

static void fill_send_request(struct ud_resources *res, struct ibv_send_wr *psr,
       			      struct ibv_sge *psg, ib_mad_t *mad_hdr)
{
	static int wr_id=0;
	memset(psr, 0, sizeof(*psr));

	psr->next = NULL;
	psr->wr_id = wr_id++;
	psr->sg_list = psg;
	psr->num_sge = 1;
	psr->opcode = IBV_WR_SEND;
//	psr->send_flags = IBV_SEND_SIGNALED | IBV_SEND_INLINE;
	psr->send_flags = IBV_SEND_SIGNALED;
	psr->wr.ud.ah = res->ah;
	psr->wr.ud.remote_qpn = 1;
	psr->wr.ud.remote_qkey = MY_IB_QP1_WELL_KNOWN_Q_KEY;

	psg->addr = (uintptr_t) mad_hdr;
	psg->length = SEND_SIZE;
	psg->lkey = res->mr->lkey;
}

static int poll_cq(struct ibv_cq *cq, struct ibv_wc *wc, int wait)
{
	int ret;
	
	do {
		ret = ibv_poll_cq(cq, 1, wc);
		if (ret < 0) {
			fprintf(stderr, "poll CQ failed\n");
			return ret;
		}
		
		if (ret > 0 && wc->status != IBV_WC_SUCCESS) {
			fprintf(stderr, "got bad completion with status: 0x%x\n", wc->status);
			return -ret;
		}
		srp_sleep(0, 100);
	} while (wait && ret == 0); /* while no response in cq */

	return ret;
}

/*****************************************************************************
* Function: register_to_trap
*****************************************************************************/
static int register_to_trap(struct ud_resources *res, int dest_lid, int trap_num)
{
	struct ibv_send_wr sr;
	struct ibv_wc wc;
	struct ibv_sge sg;
	struct ibv_send_wr *_bad_wr = NULL;
	struct ibv_send_wr **bad_wr = &_bad_wr;
	int counter = 0;
	int rc = 0;
	int ret;

	ib_mad_t *mad_hdr = (ib_mad_t *) (res->send_buf);
        ib_sa_mad_t* p_sa_mad = (ib_sa_mad_t *) (res->send_buf);
	ib_inform_info_t *data = (ib_inform_info_t *) (p_sa_mad->data);
	static uint64_t trans_id = 0x0000FFFF;
	pr_debug("Registering to trap:%d (sm in %d)\n", trap_num, dest_lid);
	memset(res->send_buf, 0, SEND_SIZE);

	fill_send_request(res, &sr, &sg, mad_hdr);

	ib_mad_init_new(mad_hdr, /* Mad Header */
			SRP_MGMT_CLASS_SA,        /* Management Class */
			2,        /* Class Version */
			SRP_MAD_METHOD_SET,         /* Method */
			0,            /* Transaction ID - will be set before the send in the loop*/
			htons(SRP_MAD_ATTR_INFORM_INFO),   /* Attribute ID */
			0 );                       /* Attribute Modifier */


	data->lid_range_begin                  = 0xFFFF; 
	data->is_generic                       = 1;
	data->subscribe                        = 1;
	data->trap_type                        = htons(3); /* SM */
	data->g_or_v.generic.trap_num          = htons(trap_num);
        data->g_or_v.generic.node_type_msb     = 0;
        data->g_or_v.generic.node_type_lsb     = htons(4); /* Class Manager */

        p_sa_mad->comp_mask = htonll( 2 | 16 | 32 | 64 | 128 | 4096 ); 
           
	do {
		pthread_mutex_lock(res->mad_buffer_mutex);
		res->mad_buffer->base_ver = 0; // flag that the buffer is empty
		pthread_mutex_unlock(res->mad_buffer_mutex);
		mad_hdr->trans_id = htonll(trans_id++);
		ret = ibv_post_send(res->qp, &sr, bad_wr);
		if (ret) {
			fprintf(stderr, "failed to post SR\n");
			return ret;
		}
			
		ret = poll_cq(res->send_cq, &wc, 1);
		if (ret < 0)
			return ret;
		/* sleep and check for response from SA */
		do {
			srp_sleep(1, 0);
			pthread_mutex_lock(res->mad_buffer_mutex);
			if (res->mad_buffer->base_ver == 0)
				rc = 0;
			else if (res->mad_buffer->trans_id == mad_hdr->trans_id)
				rc = 1;
			else {
				res->mad_buffer->base_ver = 0;
				rc = 2;
			}
			pthread_mutex_unlock(res->mad_buffer_mutex);
		} while (rc == 2); // while old response.

	} while (rc == 0 && ++counter < 3);

	if (counter==3) {
		fprintf(stderr, "No response to inform info registration\n");
		return -EAGAIN;
	}

	return 0;
}


/*****************************************************************************
* Function: response_to_trap
*****************************************************************************/
static int response_to_trap(struct ud_resources *res, ib_sa_mad_t *mad_buffer)
{
	struct ibv_send_wr sr;
	struct ibv_sge sg;
	struct ibv_send_wr *_bad_wr = NULL;
	struct ibv_send_wr **bad_wr = &_bad_wr;
	int ret;
	struct ibv_wc wc;

	ib_sa_mad_t *response_buffer = (ib_sa_mad_t *) (res->send_buf);

	memcpy((void *) response_buffer, 
	       (void *) mad_buffer, 
	       sizeof(ib_sa_mad_t));
	response_buffer->method = SRP_SA_METHOD_REPORT_RESP;

	fill_send_request(res, &sr, &sg, (ib_mad_t *) response_buffer);
	ret = ibv_post_send(res->qp, &sr, bad_wr);
	if (ret < 0) {
		fprintf(stderr, "failed to post response\n");
		return ret;
	}
	ret = poll_cq(res->send_cq, &wc, 1);

	return ret;
}


/*****************************************************************************
* Function: get_trap_notices
*****************************************************************************/
static int get_trap_notices(struct resources *res)
{
	struct ibv_wc wc;
	int cur_receive = 0;
	int ret;
	char *buffer;
	ib_sa_mad_t *mad_buffer;
	ib_mad_notice_attr_t *notice_buffer;
	int trap_num;

	while (!res->sync_res->stop_threads) {
	
		ret = poll_cq(res->ud_res->recv_cq, &wc, 1);
		if (ret < 0)
			exit(-ret);
		
		pr_debug("get_trap_notices: Got CQE wc.wr_id=%ld\n", wc.wr_id);
		cur_receive = wc.wr_id;
		buffer = (void *)(((unsigned long)res->ud_res->recv_buf) + RECV_BUF_SIZE * cur_receive);
		mad_buffer = (ib_sa_mad_t *) (buffer + GRH_SIZE);

		if ((mad_buffer->mgmt_class == SRP_MGMT_CLASS_SA) &&
		    (mad_buffer->method == SRP_SA_METHOD_GET_RESP) &&
		    (ntohs(mad_buffer->attr_id) == SRP_MAD_ATTR_INFORM_INFO)) {
		/* this is probably a response to register to trap */
			pthread_mutex_lock(res->ud_res->mad_buffer_mutex);
			*res->ud_res->mad_buffer = *mad_buffer;
			pthread_mutex_unlock(res->ud_res->mad_buffer_mutex);
		} else if ((mad_buffer->mgmt_class == SRP_MGMT_CLASS_SA) &&
		    (mad_buffer->method == SRP_SA_METHOD_REPORT) && 
		    (ntohs(mad_buffer->attr_id) == SRP_MAD_ATTR_NOTICE))
		{ /* this is a trap notice */
			notice_buffer = (ib_mad_notice_attr_t *) (mad_buffer->data);
			trap_num = ntohs(notice_buffer->g_or_v.generic.trap_num);
			response_to_trap(res->ud_res, mad_buffer);
			if (trap_num == SRP_TRAP_JOIN)
				push_gid_to_list(res->sync_res, &notice_buffer->data_details.ntc_64_67.gid);				
			else if (trap_num == SRP_TRAP_CHANGE_CAP) {
				if (ntohl(notice_buffer->data_details.ntc_144.new_cap_mask) & SRP_IS_DM)
					push_lid_to_list(res->sync_res, ntohs(notice_buffer->data_details.ntc_144.lid));
			} else {
				fprintf(stderr, "Unhandled trap_num %d\n", trap_num);
			}
		}

		ret = fill_rq_entry(res->ud_res, cur_receive);
		if (ret < 0)
			exit(-ret);
		
	}
	return 0;
}	

void *run_thread_get_trap_notices(void *res_in)
{
	int ret;

	ret = get_trap_notices((struct resources *)res_in);

	pr_debug("get_trap_notices thread ended\n");

	pthread_exit((void *)(long)ret);
}


/*****************************************************************************
* Function: register_to_traps
*****************************************************************************/
int register_to_traps(struct ud_resources *ud_res)
{
	int rc;
	int trap_numbers[] = {SRP_TRAP_JOIN, SRP_TRAP_CHANGE_CAP};
	int i;
	
	for (i=0; i < sizeof(trap_numbers) / sizeof(*trap_numbers); ++i) {
		rc = register_to_trap(ud_res, ud_res->port_attr.sm_lid, trap_numbers[i]);
		if (rc != 0)
			return rc;
	}

	return 0;
	
} 

void *run_thread_wait_till_timeout(void *res_in)
{
	struct resources *res = (struct resources *)res_in;
	time_t cur_time, sleep_time;
  
	res->sync_res->next_recalc_time = time(NULL) + config->recalc_time;
	while (!res->sync_res->stop_threads) {
		cur_time = time(NULL);
		sleep_time = res->sync_res->next_recalc_time - cur_time;
		if (sleep_time < 0) {
			res->sync_res->recalc = 1;
			res->sync_res->next_recalc_time = time(NULL) + config->recalc_time;
		} else
			srp_sleep(sleep_time, 0);
	}
	pr_debug("wait_till_timeout thread ended\n");

	pthread_exit((void *)0);
}

void *run_thread_listen_to_events(void *res_in)
{
	struct resources *res = (struct resources *)res_in;
	struct ibv_async_event event;

	while (1) {
		if (ibv_get_async_event(res->ud_res->ib_ctx, &event)) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "ibv_get_async_event failed\n");
			exit(-errno);
		}

		pr_debug("event_type %d, port %d\n",
			 event.event_type, event.element.port_num);
	
		switch (event.event_type) {
		case IBV_EVENT_PORT_ACTIVE:
		case IBV_EVENT_PORT_ERR:
		case IBV_EVENT_SM_CHANGE:
		case IBV_EVENT_LID_CHANGE:
		case IBV_EVENT_CLIENT_REREGISTER:
			if (event.element.port_num == config->port_num) 
		    		res->sync_res->recalc = 1;
		  	break;
	  
		case IBV_EVENT_PKEY_CHANGE:
		case IBV_EVENT_DEVICE_FATAL:
		case IBV_EVENT_CQ_ERR:
		case IBV_EVENT_QP_FATAL:
		  /* clean and restart */
			fprintf(stderr, "Critical event, ending\n");
			exit(EAGAIN);
	  

 	      	 /*
  
		case IBV_EVENT_QP_REQ_ERR:
		case IBV_EVENT_QP_ACCESS_ERR:
		case IBV_EVENT_COMM_EST:
		case IBV_EVENT_SQ_DRAINED:
		case IBV_EVENT_PATH_MIG:
		case IBV_EVENT_PATH_MIG_ERR:
		case IBV_EVENT_SRQ_ERR:
		case IBV_EVENT_SRQ_LIMIT_REACHED:
		case IBV_EVENT_QP_LAST_WQE_REACHED:
	
		*/

	
		default:
			break;
		}

		ibv_ack_async_event(&event);

	}
}

