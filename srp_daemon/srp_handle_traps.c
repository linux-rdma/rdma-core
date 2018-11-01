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
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <endian.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <infiniband/verbs.h>
#include <infiniband/umad_sa.h>
#include <infiniband/umad_sm.h>

#include "srp_ib_types.h"

#include "srp_daemon.h"

void srp_sleep(time_t sec, time_t usec)
{
	struct timespec req, rem;

	if (usec > 1000) {
		sec += usec / 1000;
		usec = usec % 1000;
	}
	req.tv_sec = sec;
	req.tv_nsec = usec * 1000000;

	nanosleep(&req, &rem);
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
	res->channel = NULL;
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
	attr.qkey = UMAD_QKEY;

	flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_QKEY;

	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc) {
		pr_err("failed to modify QP state to INIT\n");
		return rc;
	}

	/* INIT -> RTR */
	memset(&attr, 0, sizeof(attr));

	attr.qp_state = IBV_QPS_RTR;

	flags = IBV_QP_STATE;

	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc) {
		pr_err("failed to modify QP state to RTR\n");
		return rc;
	}

	/* RTR -> RTS */
	/* memset(&attr, 0, sizeof(attr)); */

	attr.qp_state = IBV_QPS_RTS;
	attr.sq_psn = 0;

	flags = IBV_QP_STATE | IBV_QP_SQ_PSN;

	rc = ibv_modify_qp(qp, &attr, flags);
	if (rc) {
		pr_err("failed to modify QP state to RTS\n");
		return rc;
	}

	return 0;
}

int modify_qp_to_err(struct ibv_qp *qp)
{
	static struct ibv_qp_attr attr = {
		.qp_state = IBV_QPS_ERR,
	};

	return ibv_modify_qp(qp, &attr, IBV_QP_STATE);
}

/*****************************************************************************
* Function: fill_rq_entry
*****************************************************************************/
static int fill_rq_entry(struct ud_resources *res, int cur_receive)
{
	struct ibv_recv_wr rr;
	struct ibv_sge sg;
	struct ibv_recv_wr *_bad_wr = NULL;
	struct ibv_recv_wr **bad_wr = &_bad_wr;
	int ret;

	memset(&rr, 0, sizeof(rr));

	sg.length = RECV_BUF_SIZE;
	sg.lkey = res->mr->lkey;

	rr.next = NULL;
	rr.sg_list = &sg;
	rr.num_sge = 1;

	sg.addr = (((unsigned long)res->recv_buf) + RECV_BUF_SIZE * cur_receive);
	rr.wr_id = cur_receive;

	ret = ibv_post_recv(res->qp, &rr, bad_wr);
	if (ret < 0) {
		pr_err("failed to post RR\n");
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
			pr_err("failed to fill_rq_entry\n");
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
		pr_err("failed to get IB devices list\n");
		return -1;
	}

	for (i = 0; i < num_devices; i ++) {
		if (!strcmp(ibv_get_device_name(res->dev_list[i]), config->dev_name)) {
			ib_dev = res->dev_list[i];
			break;
		}
	}

	if (!ib_dev) {
		pr_err("IB device %s wasn't found\n", config->dev_name);
		return -ENXIO;
	}

	pr_debug("Device %s was found\n", config->dev_name);

	/* get device handle */
	res->ib_ctx = ibv_open_device(ib_dev);
	if (!res->ib_ctx) {
		pr_err("failed to open device %s\n", config->dev_name);
		return -ENXIO;
	}

	res->channel = ibv_create_comp_channel(res->ib_ctx);
	if (!res->channel) {
		pr_err("failed to create completion channel \n");
		return -ENXIO;
	}

	res->pd = ibv_alloc_pd(res->ib_ctx);
	if (!res->pd) {
		pr_err("ibv_alloc_pd failed\n");
		return -1;
	}

	cq_size = config->num_of_oust;
	res->recv_cq = ibv_create_cq(res->ib_ctx, cq_size, NULL, res->channel, 0);
	if (!res->recv_cq) {
		pr_err("failed to create CQ with %u entries\n", cq_size);
		return -1;
	}
       	pr_debug("CQ was created with %u CQEs\n", cq_size);

	if (ibv_req_notify_cq(res->recv_cq, 0)) {
		pr_err("Couldn't request CQ notification\n");
		return -1;
	}


	res->send_cq = ibv_create_cq(res->ib_ctx, 1, NULL, NULL, 0);
	if (!res->send_cq) {
		pr_err("failed to create CQ with %u entries\n", 1);
		return -1;
	}
	pr_debug("CQ was created with %u CQEs\n", 1);

	size = cq_size * RECV_BUF_SIZE + SEND_SIZE;
	res->recv_buf = malloc(size);
	if (!res->recv_buf) {
		pr_err("failed to malloc %zu bytes to memory buffer\n", size);
		return -ENOMEM;
	}

	memset(res->recv_buf, 0, size);

	res->send_buf = res->recv_buf + cq_size * RECV_BUF_SIZE;

	res->mr = ibv_reg_mr(res->pd, res->recv_buf, size, IBV_ACCESS_LOCAL_WRITE);
	if (!res->mr) {
		pr_err("ibv_reg_mr failed\n");
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
			pr_err("failed to create QP\n");
			return -1;
		}
		pr_debug("QP was created, QP number=0x%x\n", res->qp->qp_num);
	}

	/* modify the QP to RTS (connect the QPs) */
	if (modify_qp_to_rts(res->qp)) {
		pr_err("failed to modify QP state from RESET to RTS\n");
		return -1;
	}

	pr_debug("QPs were modified to RTS\n");

	if (fill_rq(res))
		return -1;

	res->mad_buffer = malloc(sizeof(struct umad_sa_packet));
	if (!res->mad_buffer) {
		pr_err("Could not alloc mad_buffer, abort\n");
		return -1;
	}

	res->mad_buffer_mutex = malloc(sizeof(pthread_mutex_t));
	if (!res->mad_buffer_mutex) {
		pr_err("Could not alloc mad_buffer_mutex, abort\n");
		return -1;
	}

	if (pthread_mutex_init(res->mad_buffer_mutex, NULL)) {
		pr_err("Could not init mad_buffer_mutex, abort\n");
		return -1;
	}

	return 0;
}

uint16_t get_port_lid(struct ibv_context *ib_ctx, int port_num,
		      uint16_t *sm_lid)
{
	struct ibv_port_attr port_attr;
	int ret;

	ret = ibv_query_port(ib_ctx, port_num, &port_attr);

	if (!ret) {
		if (sm_lid)
			*sm_lid = port_attr.sm_lid;
		return port_attr.lid;
	}

	return 0;
}

int create_ah(struct ud_resources *ud_res)
{
	struct ibv_ah_attr ah_attr;

	assert(!ud_res->ah);

	/* create the UD AV */
	memset(&ah_attr, 0, sizeof(ah_attr));

	if (ibv_query_port(ud_res->ib_ctx, config->port_num, &ud_res->port_attr)) {
		pr_err("ibv_query_port on port %u failed\n", config->port_num);
		return -1;
	}

	ah_attr.dlid = ud_res->port_attr.sm_lid;
	ah_attr.port_num = config->port_num;

	ud_res->ah = ibv_create_ah(ud_res->pd, &ah_attr);
	if (!ud_res->ah) {
		pr_err("failed to create UD AV\n");
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
			pr_err("failed to destroy QP\n");
			test_result = 1;
		}
	}

	if (res->mr) {
		if (ibv_dereg_mr(res->mr)) {
			pr_err("ibv_dereg_mr failed\n");
			test_result = 1;
		}
	}

	if (res->send_cq) {
		if (ibv_destroy_cq(res->send_cq)) {
			pr_err("ibv_destroy_cq of CQ failed\n");
			test_result = 1;
		}
	}

	if (res->recv_cq) {
		if (ibv_destroy_cq(res->recv_cq)) {
			pr_err("ibv_destroy_cq of CQ failed\n");
			test_result = 1;
		}
	}

	if (res->channel) {
		if (ibv_destroy_comp_channel(res->channel)) {
			pr_err("ibv_destroy_comp_channel failed\n");
			test_result = 1;
		}
	}

	if (res->ah) {
		if (ibv_destroy_ah(res->ah)) {
			pr_err("ibv_destroy_ah failed\n");
			test_result = 1;
		}
	}

	if (res->pd) {
		if (ibv_dealloc_pd(res->pd)) {
			pr_err("ibv_dealloc_pd failed\n");
			test_result = 1;
		}
	}

	if (res->ib_ctx) {
		if (ibv_close_device(res->ib_ctx)) {
			pr_err("ibv_close_device failed\n");
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
			      struct ibv_sge *psg, struct umad_hdr *mad_hdr)
{
	static int wr_id=0;

	assert(res->ah);

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
	psr->wr.ud.remote_qkey = UMAD_QKEY;

	psg->addr = (uintptr_t) mad_hdr;
	psg->length = SEND_SIZE;
	psg->lkey = res->mr->lkey;
}

static int stop_threads(struct sync_resources *sync_res)
{
	int result;

	pthread_mutex_lock(&sync_res->retry_mutex);
	result = sync_res->stop_threads;
	pthread_mutex_unlock(&sync_res->retry_mutex);

	return result;
}

/*****************************************************************************
 * Function: poll_cq_once
 * Poll a CQ once.
 * Returns the number of completion polled (0 or 1).
 * Returns a negative value on error.
 *****************************************************************************/
static int poll_cq_once(struct sync_resources *sync_res, struct ibv_cq *cq,
			struct ibv_wc *wc)
{
	int ret;

	ret = ibv_poll_cq(cq, 1, wc);
	if (ret < 0) {
		pr_err("poll CQ failed\n");
		return ret;
	}

	if (ret > 0 && wc->status != IBV_WC_SUCCESS) {
		if (!stop_threads(sync_res))
			pr_err("got bad completion with status: 0x%x\n",
			       wc->status);
		return -ret;
	}

	return ret;
}


static int poll_cq(struct sync_resources *sync_res, struct ibv_cq *cq,
		   struct ibv_wc *wc, struct ibv_comp_channel *channel)
{
	int ret;
	struct ibv_cq *ev_cq;
	void          *ev_ctx;

	if (channel) {
		/* There may be extra completions that
		 * were associated to the previous event.
		 * Only poll for the first one. If there are more than one,
		 * they will be handled by later call to poll_cq */
		ret = poll_cq_once(sync_res, cq, wc);
		/* return directly if there was an error or
		 * 1 completion polled */
		if (ret)
			return ret;

		if (ibv_get_cq_event(channel, &ev_cq, &ev_ctx)) {
			pr_err("Failed to get cq_event\n");
			return -1;
		}

		ibv_ack_cq_events(ev_cq, 1);

		if (ev_cq != cq) {
			pr_debug("CQ event for unknown CQ %p\n", ev_cq);
			return -1;
		}

		if (ibv_req_notify_cq(cq, 0)) {
			pr_err("Couldn't request CQ notification\n");
			return -1;
		}

	}

	do {
		ret = poll_cq_once(sync_res, cq, wc);
		if (ret < 0)
			return ret;

		if (ret == 0 && channel) {
			pr_err("Weird poll returned no cqe after CQ event\n");
			return -1;
		}
	} while (ret == 0);

	return 0;
}

/*****************************************************************************
* Function: register_to_trap
*****************************************************************************/
static int register_to_trap(struct sync_resources *sync_res,
			    struct ud_resources *res, int dest_lid,
			    int trap_num, int subscribe)
{
	struct ibv_send_wr sr;
	struct ibv_wc wc;
	struct ibv_sge sg;
	struct ibv_send_wr *_bad_wr = NULL;
	struct ibv_send_wr **bad_wr = &_bad_wr;
	int counter;
	int rc;
	int ret;
	long long unsigned comp_mask = 0;

	struct umad_hdr *mad_hdr = (struct umad_hdr *) (res->send_buf);
	struct umad_sa_packet *p_sa_mad = (struct umad_sa_packet *) (res->send_buf);
	struct ib_inform_info *data = (struct ib_inform_info *) (p_sa_mad->data);
	static uint64_t trans_id = 0x0000FFFF;

	if (subscribe)
		pr_debug("Registering to trap:%d (sm in %#x)\n", trap_num, dest_lid);
	else
		pr_debug("Deregistering from trap:%d (sm in %#x)\n", trap_num, dest_lid);

	memset(res->send_buf, 0, SEND_SIZE);

	fill_send_request(res, &sr, &sg, mad_hdr);

	umad_init_new(mad_hdr, /* Mad Header */
		      UMAD_CLASS_SUBN_ADM,        /* Management Class */
		      UMAD_SA_CLASS_VERSION,      /* Class Version */
		      UMAD_METHOD_SET,            /* Method */
		      0,            /* Transaction ID - will be set before the send in the loop*/
		      htobe16(UMAD_ATTR_INFORM_INFO),   /* Attribute ID */
		      0 );                       /* Attribute Modifier */


	data->lid_range_begin = htobe16(0xFFFF);
	data->is_generic = 1;
	data->subscribe = subscribe;
	if (trap_num == UMAD_SM_GID_IN_SERVICE_TRAP)
		data->trap_type = htobe16(3); /* SM */
	else if (trap_num == UMAD_SM_LOCAL_CHANGES_TRAP)
		data->trap_type = htobe16(4); /* Informational */
	data->g_or_v.generic.trap_num = htobe16(trap_num);
        data->g_or_v.generic.node_type_msb = 0;
	if (trap_num == UMAD_SM_GID_IN_SERVICE_TRAP)
		/* Class Manager */
		data->g_or_v.generic.node_type_lsb = htobe16(4);
	else if (trap_num == UMAD_SM_LOCAL_CHANGES_TRAP)
		/* Channel Adapter */
		data->g_or_v.generic.node_type_lsb = htobe16(1);

	comp_mask |= SRP_INFORMINFO_LID_COMP	    |
		     SRP_INFORMINFO_ISGENERIC_COMP  |
		     SRP_INFORMINFO_SUBSCRIBE_COMP  |
		     SRP_INFORMINFO_TRAPTYPE_COMP   |
		     SRP_INFORMINFO_TRAPNUM_COMP    |
		     SRP_INFORMINFO_PRODUCER_COMP;

	if (!data->subscribe) {
	    data->g_or_v.generic.qpn_resp_time_val = htobe32(res->qp->qp_num << 8);
	    comp_mask |= SRP_INFORMINFO_QPN_COMP;
	}

	p_sa_mad->comp_mask = htobe64(comp_mask);
	pr_debug("comp_mask: %llx\n", comp_mask);

	for (counter = 3, rc = 0; counter > 0 && rc == 0; counter--) {
		pthread_mutex_lock(res->mad_buffer_mutex);
		res->mad_buffer->mad_hdr.base_version = 0; // flag that the buffer is empty
		pthread_mutex_unlock(res->mad_buffer_mutex);
		mad_hdr->tid = htobe64(trans_id);
		trans_id++;

		ret = ibv_post_send(res->qp, &sr, bad_wr);
		if (ret) {
			pr_err("failed to post SR\n");
			return ret;
		}

		ret = poll_cq(sync_res, res->send_cq, &wc, NULL);
		if (ret < 0)
			return ret;

		/* sleep and check for response from SA */
		do {
			srp_sleep(1, 0);
			pthread_mutex_lock(res->mad_buffer_mutex);
			if (res->mad_buffer->mad_hdr.base_version == 0)
				rc = 0;
			else if (res->mad_buffer->mad_hdr.tid == mad_hdr->tid)
				rc = 1;
			else {
				res->mad_buffer->mad_hdr.base_version = 0;
				rc = 2;
			}
			pthread_mutex_unlock(res->mad_buffer_mutex);
		} while (rc == 2); // while old response.
	}

	if (counter == 0) {
		pr_err("No response to inform info registration\n");
		return -EAGAIN;
	}

	return 0;
}


/*****************************************************************************
* Function: response_to_trap
*****************************************************************************/
static int response_to_trap(struct sync_resources *sync_res,
			    struct ud_resources *res,
			    struct umad_sa_packet *mad_buffer)
{
	struct ibv_send_wr sr;
	struct ibv_sge sg;
	struct ibv_send_wr *_bad_wr = NULL;
	struct ibv_send_wr **bad_wr = &_bad_wr;
	int ret;
	struct ibv_wc wc;

	struct umad_sa_packet *response_buffer = (struct umad_sa_packet *) (res->send_buf);

	memcpy(response_buffer, mad_buffer, sizeof(struct umad_sa_packet));
	response_buffer->mad_hdr.method = UMAD_METHOD_REPORT_RESP;

	fill_send_request(res, &sr, &sg, (struct umad_hdr *) response_buffer);
	ret = ibv_post_send(res->qp, &sr, bad_wr);
	if (ret < 0) {
		pr_err("failed to post response\n");
		return ret;
	}
	ret = poll_cq(sync_res, res->send_cq, &wc, NULL);

	return ret;
}


/*****************************************************************************
* Function: get_trap_notices
*****************************************************************************/
static int get_trap_notices(struct resources *res)
{
	struct ibv_wc wc;
	int cur_receive = 0;
	int ret = 0;
	int pkey_index;
	__be16 pkey;
	char *buffer;
	struct umad_sa_packet *mad_buffer;
	struct ib_mad_notice_attr *notice_buffer;
	int trap_num;

	while (!stop_threads(res->sync_res)) {

		ret = poll_cq(res->sync_res, res->ud_res->recv_cq, &wc,
			      res->ud_res->channel);
		if (ret < 0)
			continue;

		pr_debug("get_trap_notices: Got CQE wc.wr_id=%lld\n", (long long int) wc.wr_id);
		cur_receive = wc.wr_id;
		buffer = res->ud_res->recv_buf + RECV_BUF_SIZE * cur_receive;
		mad_buffer = (struct umad_sa_packet *) (buffer + GRH_SIZE);

		if ((mad_buffer->mad_hdr.mgmt_class == UMAD_CLASS_SUBN_ADM) &&
		    (mad_buffer->mad_hdr.method == UMAD_METHOD_GET_RESP) &&
		    (be16toh(mad_buffer->mad_hdr.attr_id) == UMAD_ATTR_INFORM_INFO)) {
		/* this is probably a response to register to trap */
			pthread_mutex_lock(res->ud_res->mad_buffer_mutex);
			*res->ud_res->mad_buffer = *mad_buffer;
			pthread_mutex_unlock(res->ud_res->mad_buffer_mutex);
		} else if ((mad_buffer->mad_hdr.mgmt_class == UMAD_CLASS_SUBN_ADM) &&
		    (mad_buffer->mad_hdr.method == UMAD_METHOD_REPORT) &&
		    (be16toh(mad_buffer->mad_hdr.attr_id) == UMAD_ATTR_NOTICE))
		{ /* this is a trap notice */
			pkey_index = wc.pkey_index;
			ret = pkey_index_to_pkey(res->umad_res, pkey_index, &pkey);
			if (ret) {
				pr_err("get_trap_notices: Got Bad pkey_index (%d)\n",
				       pkey_index);
				wake_up_main_loop(0);
				break;
			}

			notice_buffer = (struct ib_mad_notice_attr *) (mad_buffer->data);
			trap_num = be16toh(notice_buffer->generic.trap_num);
			response_to_trap(res->sync_res, res->ud_res, mad_buffer);
			if (trap_num == UMAD_SM_GID_IN_SERVICE_TRAP)
				push_gid_to_list(res->sync_res,
						 &notice_buffer->ntc_64_67.gid,
						 be16toh(pkey));
			else if (trap_num == UMAD_SM_LOCAL_CHANGES_TRAP) {
				if (be32toh(notice_buffer->ntc_144.new_cap_mask) & SRP_IS_DM)
					push_lid_to_list(res->sync_res,
							 be16toh(notice_buffer->ntc_144.lid),
							 be16toh(pkey));
			} else {
				pr_err("Unhandled trap_num %d\n", trap_num);
			}
		}

		ret = fill_rq_entry(res->ud_res, cur_receive);
		if (ret < 0) {
			wake_up_main_loop(0);
			break;
		}
	}
	return ret;
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
int register_to_traps(struct resources *res, int subscribe)
{
	int rc;
	int trap_numbers[] = {UMAD_SM_GID_IN_SERVICE_TRAP, UMAD_SM_LOCAL_CHANGES_TRAP};
	int i;

	for (i=0; i < sizeof(trap_numbers) / sizeof(*trap_numbers); ++i) {
		rc = register_to_trap(res->sync_res, res->ud_res,
				      res->ud_res->port_attr.sm_lid,
				      trap_numbers[i], subscribe);
		if (rc != 0)
			return rc;
	}

	return 0;

}

void *run_thread_listen_to_events(void *res_in)
{
	struct resources *res = (struct resources *)res_in;
	struct ibv_async_event event;

	while (!stop_threads(res->sync_res)) {
		if (ibv_get_async_event(res->ud_res->ib_ctx, &event)) {
			if (errno != EINTR)
				pr_err("ibv_get_async_event failed (errno = %d)\n",
				       errno);
			break;
		}

		pr_debug("event_type %d, port %d\n",
			 event.event_type, event.element.port_num);

		switch (event.event_type) {
		case IBV_EVENT_PORT_ACTIVE:
		case IBV_EVENT_SM_CHANGE:
		case IBV_EVENT_LID_CHANGE:
		case IBV_EVENT_CLIENT_REREGISTER:
		case IBV_EVENT_PKEY_CHANGE:
			if (event.element.port_num == config->port_num) {
				pthread_mutex_lock(&res->sync_res->mutex);
				__schedule_rescan(res->sync_res, 0);
				wake_up_main_loop(0);
				pthread_mutex_unlock(&res->sync_res->mutex);
			}
		  	break;

		case IBV_EVENT_DEVICE_FATAL:
		case IBV_EVENT_CQ_ERR:
		case IBV_EVENT_QP_FATAL:
		  /* clean and restart */
			pr_err("Critical event %d, raising catastrophic "
			       "error signal\n", event.event_type);
			raise(SRP_CATAS_ERR);
			break;

 	      	 /*

		case IBV_EVENT_PORT_ERR:
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

	return NULL;
}

