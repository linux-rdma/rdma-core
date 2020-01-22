/*******************************************************************************
*
* Copyright (c) 2015-2016 Intel Corporation.  All rights reserved.
*
* This software is available to you under a choice of one of two
* licenses.  You may choose to be licensed under the terms of the GNU
* General Public License (GPL) Version 2, available from the file
* COPYING in the main directory of this source tree, or the
* OpenFabrics.org BSD license below:
*
*   Redistribution and use in source and binary forms, with or
*   without modification, are permitted provided that the following
*   conditions are met:
*
*    - Redistributions of source code must retain the above
*	copyright notice, this list of conditions and the following
*	disclaimer.
*
*    - Redistributions in binary form must reproduce the above
*	copyright notice, this list of conditions and the following
*	disclaimer in the documentation and/or other materials
*	provided with the distribution.
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
*******************************************************************************/

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <malloc.h>
#include <sys/mman.h>
#include <linux/if_ether.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "i40iw_umain.h"
#include "i40iw-abi.h"

/**
 * i40iw_uquery_device - call driver to query device for max resources
 * @context: user context for the device
 * @attr: where to save all the mx resources from the driver
 **/
int i40iw_uquery_device(struct ibv_context *context, struct ibv_device_attr *attr)
{
	struct ibv_query_device cmd;
	uint64_t i40iw_fw_ver;
	int ret;
	unsigned int minor, major;

	ret = ibv_cmd_query_device(context, attr, &i40iw_fw_ver, &cmd, sizeof(cmd));
	if (ret) {
		fprintf(stderr, PFX "%s: query device failed and returned status code: %d\n", __func__, ret);
		return ret;
	}

	major = (i40iw_fw_ver >> 16) & 0xffff;
	minor = i40iw_fw_ver & 0xffff;

	snprintf(attr->fw_ver, sizeof(attr->fw_ver), "%d.%d", major, minor);

	return 0;
}

/**
 * i40iw_uquery_port - get port attributes (msg size, lnk, mtu...)
 * @context: user context of the device
 * @port: port for the attributes
 * @attr: to return port attributes
 **/
int i40iw_uquery_port(struct ibv_context *context, uint8_t port, struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof(cmd));
}

/**
 * i40iw_ualloc_pd - allocates protection domain and return pd ptr
 * @context: user context of the device
 **/
struct ibv_pd *i40iw_ualloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct i40iw_ualloc_pd_resp resp;
	struct i40iw_upd *iwupd;
	void *map;

	iwupd = malloc(sizeof(*iwupd));
	if (!iwupd)
		return NULL;
	memset(&resp, 0, sizeof(resp));
	if (ibv_cmd_alloc_pd(context, &iwupd->ibv_pd, &cmd, sizeof(cmd), &resp.ibv_resp, sizeof(resp)))
		goto err_free;

	iwupd->pd_id = resp.pd_id;
	map = mmap(NULL, I40IW_HW_PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED, context->cmd_fd, 0);
	if (map == MAP_FAILED) {
		ibv_cmd_dealloc_pd(&iwupd->ibv_pd);
		goto err_free;
	}
	iwupd->db = map;

	return &iwupd->ibv_pd;

err_free:
	free(iwupd);
	return NULL;
}

/**
 * i40iw_ufree_pd - free pd resources
 * @pd: pd to free resources
 */
int i40iw_ufree_pd(struct ibv_pd *pd)
{
	int ret;
	struct i40iw_upd *iwupd;

	iwupd = to_i40iw_upd(pd);
	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	munmap((void *)iwupd->db, I40IW_HW_PAGE_SIZE);
	free(iwupd);

	return 0;
}

/**
 * i40iw_ureg_mr - register user memory region
 * @pd: pd for the mr
 * @addr: user address of the memory region
 * @length: length of the memory
 * @access: access allowed on this mr
 */
struct ibv_mr *i40iw_ureg_mr(struct ibv_pd *pd, void *addr, size_t length,
			     uint64_t hca_va, int access)
{
	struct verbs_mr *vmr;
	struct i40iw_ureg_mr cmd;
	struct ib_uverbs_reg_mr_resp resp;

	vmr = malloc(sizeof(*vmr));
	if (!vmr)
		return NULL;

	cmd.reg_type = IW_MEMREG_TYPE_MEM;

	if (ibv_cmd_reg_mr(pd, addr, length, hca_va, access, vmr, &cmd.ibv_cmd,
			   sizeof(cmd), &resp, sizeof(resp))) {
		fprintf(stderr, PFX "%s: Failed to register memory\n", __func__);
		free(vmr);
		return NULL;
	}
	return &vmr->ibv_mr;
}

/**
 * i40iw_udereg_mr - re-register memory region
 * @mr: mr that was allocated
 */
int i40iw_udereg_mr(struct verbs_mr *vmr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

	free(vmr);
	return 0;
}

/**
 * i40iw_num_of_pages - number of pages needed
 * @size: size for number of pages
 */
static inline u32 i40iw_num_of_pages(u32 size)
{
	return (size + 4095) >> 12;
}

/**
 * i40iw_ucreate_cq - create completion queue for user app
 * @context: user context of the device
 * @cqe: number of cq entries in the cq ring
 * @channel: channel info (context, refcnt..)
 * @comp_vector: save in ucq struct
 */
struct ibv_cq *i40iw_ucreate_cq(struct ibv_context *context, int cqe,
				struct ibv_comp_channel *channel, int comp_vector)
{
	struct i40iw_ucq *iwucq;
	struct i40iw_ucreate_cq cmd;
	struct i40iw_ucreate_cq_resp resp;
	struct i40iw_cq_uk_init_info info;
	int ret;
	struct i40iw_uvcontext *iwvctx = to_i40iw_uctx(context);
	u32 cqe_struct_size;
	u32 totalsize;
	u32 cq_pages;

	struct i40iw_ureg_mr reg_mr_cmd;

	struct ib_uverbs_reg_mr_resp reg_mr_resp;

	if (cqe > I40IW_MAX_CQ_SIZE)
		return NULL;

	cqe++;
	memset(&cmd, 0, sizeof(cmd));
	memset(&resp, 0, sizeof(resp));
	memset(&info, 0, sizeof(info));
	memset(&reg_mr_cmd, 0, sizeof(reg_mr_cmd));

	iwucq = malloc(sizeof(*iwucq));
	if (!iwucq)
		return NULL;
	memset(iwucq, 0, sizeof(*iwucq));

	if (pthread_spin_init(&iwucq->lock, PTHREAD_PROCESS_PRIVATE)) {
		free(iwucq);
		return NULL;
	}
	if (cqe < I40IW_U_MINCQ_SIZE)
		cqe = I40IW_U_MINCQ_SIZE;

	info.cq_size = cqe;
	iwucq->comp_vector = comp_vector;
	cqe_struct_size = sizeof(struct i40iw_cqe);
	cq_pages = i40iw_num_of_pages(info.cq_size * cqe_struct_size);
	totalsize = (cq_pages << 12) + I40E_DB_SHADOW_AREA_SIZE;

	info.cq_base = memalign(I40IW_HW_PAGE_SIZE, totalsize);

	if (!info.cq_base)
		goto err;

	memset(info.cq_base, 0, totalsize);
	info.shadow_area = (u64 *)((u8 *)info.cq_base + (cq_pages << 12));
	reg_mr_cmd.reg_type = IW_MEMREG_TYPE_CQ;

	reg_mr_cmd.cq_pages = cq_pages;

	ret = ibv_cmd_reg_mr(&iwvctx->iwupd->ibv_pd, (void *)info.cq_base,
			     totalsize, (uintptr_t)info.cq_base,
			     IBV_ACCESS_LOCAL_WRITE, &iwucq->vmr,
			     &reg_mr_cmd.ibv_cmd, sizeof(reg_mr_cmd),
			     &reg_mr_resp, sizeof(reg_mr_resp));
	if (ret) {
		fprintf(stderr, PFX "%s: failed to pin memory for CQ\n", __func__);
		goto err;
	}

	cmd.user_cq_buffer = (__u64)((uintptr_t)info.cq_base);
	ret = ibv_cmd_create_cq(context, info.cq_size, channel, comp_vector,
				&iwucq->ibv_cq, &cmd.ibv_cmd, sizeof(cmd),
				&resp.ibv_resp, sizeof(resp));
	if (ret) {
		ibv_cmd_dereg_mr(&iwucq->vmr);
		fprintf(stderr, PFX "%s: failed to create CQ\n", __func__);
		goto err;
	}

	info.cq_id = (uint16_t)resp.cq_id;
	info.shadow_area = (u64 *)((u8 *)info.shadow_area + resp.reserved);

	info.cqe_alloc_reg = (u32 *)((u8 *)iwvctx->iwupd->db + I40E_DB_CQ_OFFSET);
	ret = iwvctx->dev.ops_uk.iwarp_cq_uk_init(&iwucq->cq, &info);
	if (!ret)
		return &iwucq->ibv_cq;
	else
		fprintf(stderr, PFX "%s: failed to initialize CQ, status %d\n", __func__, ret);
err:
	if (info.cq_base)
		free(info.cq_base);
	if (pthread_spin_destroy(&iwucq->lock))
		return NULL;
	free(iwucq);
	return NULL;
}

/**
 * i40iw_udestroy_cq - destroys cq
 * @cq: ptr to cq to be destroyed
 */
int i40iw_udestroy_cq(struct ibv_cq *cq)
{
	struct i40iw_ucq *iwucq = to_i40iw_ucq(cq);
	int ret;

	ret = pthread_spin_destroy(&iwucq->lock);
	if (ret)
		return ret;

	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		return ret;

	ibv_cmd_dereg_mr(&iwucq->vmr);

	free(iwucq->cq.cq_base);
	free(iwucq);

	return 0;
}

/**
 * i40iw_upoll_cq - user app to poll cq
 * @cq: cq to poll
 * @num_entries: max cq entries to poll
 * @entry: for each completion complete entry
 */
int i40iw_upoll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *entry)
{
	struct i40iw_ucq *iwucq;
	int cqe_count = 0;
	struct i40iw_cq_poll_info cq_poll_info;
	int ret;

	iwucq = to_i40iw_ucq(cq);

	ret = pthread_spin_lock(&iwucq->lock);
	if (ret)
		return ret;
	while (cqe_count < num_entries) {
		ret = iwucq->cq.ops.iw_cq_poll_completion(&iwucq->cq, &cq_poll_info);
		if (ret == I40IW_ERR_QUEUE_EMPTY) {
			break;
		} else if (ret == I40IW_ERR_QUEUE_DESTROYED) {
			continue;
		} else if (ret) {
			fprintf(stderr, PFX "%s: Error polling CQ, status %d\n", __func__, ret);
			if (!cqe_count)
				/* Indicate error */
				cqe_count = -1;
			break;
		}
		entry->wc_flags = 0;
		entry->wr_id = cq_poll_info.wr_id;
		
		if (cq_poll_info.error) {
			entry->status = IBV_WC_WR_FLUSH_ERR;
			entry->vendor_err = cq_poll_info.major_err << 16 | cq_poll_info.minor_err;
		} else {
			entry->status = IBV_WC_SUCCESS;
		}

		switch (cq_poll_info.op_type) {
		case I40IW_OP_TYPE_RDMA_WRITE:
			entry->opcode = IBV_WC_RDMA_WRITE;
			break;
		case I40IW_OP_TYPE_RDMA_READ_INV_STAG:
		case I40IW_OP_TYPE_RDMA_READ:
			entry->opcode = IBV_WC_RDMA_READ;
			break;
		case I40IW_OP_TYPE_SEND_SOL:
		case I40IW_OP_TYPE_SEND_SOL_INV:
		case I40IW_OP_TYPE_SEND_INV:
		case I40IW_OP_TYPE_SEND:
			entry->opcode = IBV_WC_SEND;
			break;
		case I40IW_OP_TYPE_REC:
			entry->opcode = IBV_WC_RECV;
			break;
		default:
			entry->opcode = IBV_WC_RECV;
			break;
		}

		entry->imm_data = 0;
		entry->qp_num = cq_poll_info.qp_id;
		entry->src_qp = cq_poll_info.qp_id;
		entry->byte_len = cq_poll_info.bytes_xfered;
		entry++;
		cqe_count++;
	}
	pthread_spin_unlock(&iwucq->lock);
	return cqe_count;
}

/**
 * i40iw_arm_cq - arm of cq
 * @iwucq: cq to which arm
 * @cq_notify: notification params
 */
static void i40iw_arm_cq(struct i40iw_ucq *iwucq, enum i40iw_completion_notify cq_notify)
{
	iwucq->is_armed = 1;
	iwucq->arm_sol = 1;
	iwucq->skip_arm = 0;
	iwucq->skip_sol = 1;

	iwucq->cq.ops.iw_cq_request_notification(&iwucq->cq, cq_notify);
}

/**
 * i40iw_uarm_cq - callback for arm of cq
 * @cq: cq to arm
 * @solicited: to get notify params
 */
int i40iw_uarm_cq(struct ibv_cq *cq, int solicited)
{
	struct i40iw_ucq *iwucq;
	enum i40iw_completion_notify cq_notify = IW_CQ_COMPL_EVENT;
	int ret;

	iwucq = to_i40iw_ucq(cq);
	if (solicited)
		cq_notify = IW_CQ_COMPL_SOLICITED;

	ret = pthread_spin_lock(&iwucq->lock);
	if (ret)
		return ret;

	if (iwucq->is_armed) {
		if ((iwucq->arm_sol) && (!solicited)) {
			i40iw_arm_cq(iwucq, cq_notify);
		} else {
			iwucq->skip_arm = 1;
			iwucq->skip_sol &= solicited;
		}
	} else {
		i40iw_arm_cq(iwucq, cq_notify);
	}

	pthread_spin_unlock(&iwucq->lock);

	return 0;
}

/**
 * i40iw_cq_event - cq to do completion event
 * @cq: cq to arm
 */
void i40iw_cq_event(struct ibv_cq *cq)
{
	struct i40iw_ucq *iwucq;

	iwucq = to_i40iw_ucq(cq);
	if (pthread_spin_lock(&iwucq->lock))
		return;

	if (iwucq->skip_arm)
		i40iw_arm_cq(iwucq, IW_CQ_COMPL_EVENT);
	else
		iwucq->is_armed = 0;

	pthread_spin_unlock(&iwucq->lock);
}

static int i40iw_destroy_vmapped_qp(struct i40iw_uqp *iwuqp,
					struct i40iw_qp_quanta *sq_base)
{
	int ret;

	ret = ibv_cmd_destroy_qp(&iwuqp->ibv_qp);
	if (ret)
		return ret;

	if (iwuqp->push_db)
		munmap(iwuqp->push_db, I40IW_HW_PAGE_SIZE);
	if (iwuqp->push_wqe)
		munmap(iwuqp->push_wqe, I40IW_HW_PAGE_SIZE);

	ibv_cmd_dereg_mr(&iwuqp->vmr);
	free((void *)sq_base);

	return 0;
}

/**
 * i40iw_vmapped_qp - create resources for qp
 * @iwuqp: qp struct for resources
 * @pd: pd for thes qp
 * @attr: atributes of qp passed
 * @resp: response back from create qp
 * @sqdepth: depth of sq
 * @rqdepth: depth of rq
 * @info: info for initializing user level qp
 */
static int i40iw_vmapped_qp(struct i40iw_uqp *iwuqp, struct ibv_pd *pd,
			    struct ibv_qp_init_attr *attr,
			    struct i40iw_ucreate_qp_resp *resp, int sqdepth,
			    int rqdepth, struct i40iw_qp_uk_init_info *info)
{
	struct i40iw_ucreate_qp cmd;
	int sqsize, rqsize, totalqpsize;
	int ret;
	struct i40iw_ureg_mr reg_mr_cmd;
	u32 sq_pages, rq_pages;
	struct ib_uverbs_reg_mr_resp reg_mr_resp;

	memset(&reg_mr_cmd, 0, sizeof(reg_mr_cmd));
	sqsize = sqdepth * I40IW_QP_WQE_MIN_SIZE;
	rqsize = rqdepth * I40IW_QP_WQE_MIN_SIZE;

	sq_pages = i40iw_num_of_pages(sqsize);
	rq_pages = i40iw_num_of_pages(rqsize);
	sqsize = sq_pages << 12;
	rqsize = rq_pages << 12;
	totalqpsize = rqsize + sqsize + I40E_DB_SHADOW_AREA_SIZE;
	info->sq = memalign(I40IW_HW_PAGE_SIZE, totalqpsize);

	if (!info->sq) {
		fprintf(stderr, PFX "%s: failed to allocate memory for SQ\n", __func__);
		return 0;
	}

	memset(info->sq, 0, totalqpsize);
	info->rq = &info->sq[sqsize / I40IW_QP_WQE_MIN_SIZE];
	info->shadow_area = info->rq[rqsize / I40IW_QP_WQE_MIN_SIZE].elem;

	reg_mr_cmd.reg_type = IW_MEMREG_TYPE_QP;
	reg_mr_cmd.sq_pages = sq_pages;
	reg_mr_cmd.rq_pages = rq_pages;

	ret = ibv_cmd_reg_mr(pd, (void *)info->sq, totalqpsize,
			     (uintptr_t)info->sq, IBV_ACCESS_LOCAL_WRITE,
			     &iwuqp->vmr, &reg_mr_cmd.ibv_cmd,
			     sizeof(reg_mr_cmd), &reg_mr_resp,
			     sizeof(reg_mr_resp));
	if (ret) {
		fprintf(stderr, PFX "%s: failed to pin memory for SQ\n", __func__);
		free(info->sq);
		return 0;
	}
	cmd.user_wqe_buffers = (__u64)((uintptr_t)info->sq);
	cmd.user_compl_ctx = (uintptr_t)&iwuqp->qp;

	ret = ibv_cmd_create_qp(pd, &iwuqp->ibv_qp, attr, &cmd.ibv_cmd, sizeof(cmd),
				&resp->ibv_resp, sizeof(struct i40iw_ucreate_qp_resp));
	if (ret) {
		fprintf(stderr, PFX "%s: failed to create QP, status %d\n", __func__, ret);
		ibv_cmd_dereg_mr(&iwuqp->vmr);
		free(info->sq);
		return 0;
	}

	iwuqp->send_cq = to_i40iw_ucq(attr->send_cq);
	iwuqp->recv_cq = to_i40iw_ucq(attr->recv_cq);
	info->sq_size = resp->actual_sq_size;
	info->rq_size = resp->actual_rq_size;

	if (resp->push_idx != I40IW_INVALID_PUSH_PAGE_INDEX) {
		void *map;
		u64 offset;

		offset = (resp->push_idx + I40IW_BASE_PUSH_PAGE) * I40IW_HW_PAGE_SIZE;

		map = mmap(NULL, I40IW_HW_PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED,
			   pd->context->cmd_fd, offset);
		if (map == MAP_FAILED) {
			fprintf(stderr, PFX "%s: failed to map push page, errno %d\n", __func__, errno);
			info->push_wqe = NULL;
			info->push_db = NULL;
		} else {
			info->push_wqe = map;

			offset += I40IW_HW_PAGE_SIZE;
			map = mmap(NULL, I40IW_HW_PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED,
				   pd->context->cmd_fd, offset);
			if (map == MAP_FAILED) {
				fprintf(stderr, PFX "%s: failed to map push doorbell, errno %d\n", __func__, errno);
				munmap(info->push_wqe, I40IW_HW_PAGE_SIZE);
				info->push_wqe = NULL;
				info->push_db = NULL;
			} else {
				info->push_db = map;
			}
			iwuqp->push_db = info->push_db;
			iwuqp->push_wqe = info->push_wqe;
		}
	}
	return 1;
}

/**
 * i40iw_ucreate_qp - create qp on user app
 * @pd: pd for the qp
 * @attr: attributes of the qp to be created (sizes, sge, cq)
 */
struct ibv_qp *i40iw_ucreate_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct i40iw_ucreate_qp_resp resp;
	struct i40iw_uvcontext *iwvctx = to_i40iw_uctx(pd->context);
	struct i40iw_uqp *iwuqp;
	struct i40iw_qp_uk_init_info info;
	u32 sqdepth, rqdepth;
	u8 sqshift, rqshift;

	if (attr->qp_type != IBV_QPT_RC) {
		fprintf(stderr, PFX "%s: failed to create QP, unsupported QP type: 0x%x\n", __func__, attr->qp_type);
		return NULL;
	}

	if (attr->cap.max_send_sge > I40IW_MAX_WQ_FRAGMENT_COUNT)
		attr->cap.max_send_sge = I40IW_MAX_WQ_FRAGMENT_COUNT;

	if (attr->cap.max_recv_sge > I40IW_MAX_WQ_FRAGMENT_COUNT)
		attr->cap.max_recv_sge = I40IW_MAX_WQ_FRAGMENT_COUNT;

	if (attr->cap.max_inline_data > I40IW_MAX_INLINE_DATA_SIZE)
		attr->cap.max_inline_data = I40IW_MAX_INLINE_DATA_SIZE;

	i40iw_get_wqe_shift(attr->cap.max_send_sge, attr->cap.max_inline_data, &sqshift);
	if (i40iw_get_sqdepth(attr->cap.max_send_wr, sqshift, &sqdepth)) {
		fprintf(stderr, PFX "invalid SQ attributes, max_send_wr=%d max_send_sge=%d max_inline=%d\n",
			attr->cap.max_send_wr, attr->cap.max_send_sge, attr->cap.max_inline_data);
		return NULL;
	}

	switch (iwvctx->abi_ver) {
	case 4:
		i40iw_get_wqe_shift(attr->cap.max_recv_sge, 0, &rqshift);
		break;
	case 5: /* fallthrough until next ABI version */
	default:
		rqshift = I40IW_MAX_RQ_WQE_SHIFT;
		break;
	}

	if (i40iw_get_rqdepth(attr->cap.max_recv_wr, rqshift, &rqdepth)) {
		fprintf(stderr, PFX "invalid RQ attributes, max_recv_wr=%d max_recv_sge=%d\n",
			attr->cap.max_recv_wr, attr->cap.max_recv_sge);
		return NULL;
	}

	iwuqp = memalign(1024, sizeof(*iwuqp));
	if (!iwuqp)
		return NULL;
	memset(iwuqp, 0, sizeof(*iwuqp));

	if (pthread_spin_init(&iwuqp->lock, PTHREAD_PROCESS_PRIVATE))
		goto err_free_qp;

	memset(&info, 0, sizeof(info));

	info.sq_size = sqdepth >> sqshift;
	info.rq_size = rqdepth >> rqshift;
	attr->cap.max_send_wr = info.sq_size;
	attr->cap.max_recv_wr = info.rq_size;

	info.max_sq_frag_cnt = attr->cap.max_send_sge;
	info.max_rq_frag_cnt = attr->cap.max_recv_sge;

	info.wqe_alloc_reg = (u32 *)iwvctx->iwupd->db;
	info.sq_wrtrk_array = calloc(sqdepth, sizeof(*info.sq_wrtrk_array));
	info.abi_ver = iwvctx->abi_ver;

	if (!info.sq_wrtrk_array) {
		fprintf(stderr, PFX "%s: failed to allocate memory for SQ work array\n", __func__);
		goto err_destroy_lock;
	}

	info.rq_wrid_array = calloc(rqdepth, sizeof(*info.rq_wrid_array));
	if (!info.rq_wrid_array) {
		fprintf(stderr, PFX "%s: failed to allocate memory for RQ work array\n", __func__);
		goto err_free_sq_wrtrk;
	}

	iwuqp->sq_sig_all = attr->sq_sig_all;
	memset(&resp, 0, sizeof(resp));
	if (!i40iw_vmapped_qp(iwuqp, pd, attr, &resp, sqdepth, rqdepth, &info)) {
		fprintf(stderr, PFX "%s: failed to map QP\n", __func__);
		goto err_free_rq_wrid;
	}
	info.qp_id = resp.qp_id;
	iwuqp->i40iw_drv_opt = resp.i40iw_drv_opt;
	iwuqp->ibv_qp.qp_num = resp.qp_id;

	info.max_sq_frag_cnt = attr->cap.max_send_sge;
	info.max_rq_frag_cnt = attr->cap.max_recv_sge;
	info.max_inline_data = attr->cap.max_inline_data;

	if (!iwvctx->dev.ops_uk.iwarp_qp_uk_init(&iwuqp->qp, &info)) {
		attr->cap.max_send_wr = (sqdepth - I40IW_SQ_RSVD) >> sqshift;
		attr->cap.max_recv_wr = (rqdepth - I40IW_RQ_RSVD) >> rqshift;
		return &iwuqp->ibv_qp;
	}

	i40iw_destroy_vmapped_qp(iwuqp, info.sq);
err_free_rq_wrid:
	free(info.rq_wrid_array);
err_free_sq_wrtrk:
	free(info.sq_wrtrk_array);
err_destroy_lock:
	pthread_spin_destroy(&iwuqp->lock);
err_free_qp:
	free(iwuqp);
	return NULL;
}

/**
 * i40iw_uquery_qp - query qp for some attribute
 * @qp: qp for the attributes query
 * @attr: to return the attributes
 * @attr_mask: mask of what is query for
 * @init_attr: initial attributes during create_qp
 */
int i40iw_uquery_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		    struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr, &cmd, sizeof(cmd));
}

/**
 * i40iw_umodify_qp - send qp modify to driver
 * @qp: qp to modify
 * @attr: attribute to modify
 * @attr_mask: mask of the attribute
 */
int i40iw_umodify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask)
{
	struct ibv_modify_qp cmd = {};

	return ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof(cmd));
}

/**
 * i40iw_udestroy_qp - destroy qp
 * @qp: qp to destroy
 */
int i40iw_udestroy_qp(struct ibv_qp *qp)
{
	struct i40iw_uqp *iwuqp = to_i40iw_uqp(qp);
	int ret;

	ret = pthread_spin_destroy(&iwuqp->lock);
	if (ret)
		return ret;

	ret = i40iw_destroy_vmapped_qp(iwuqp, iwuqp->qp.sq_base);
	if (ret)
		return ret;

	if (iwuqp->qp.sq_wrtrk_array)
		free(iwuqp->qp.sq_wrtrk_array);
	if (iwuqp->qp.rq_wrid_array)
		free(iwuqp->qp.rq_wrid_array);
	/* Clean any pending completions from the cq(s) */
	if (iwuqp->send_cq)
		i40iw_clean_cq((void *)&iwuqp->qp, &iwuqp->send_cq->cq);

	if ((iwuqp->recv_cq) && (iwuqp->recv_cq != iwuqp->send_cq))
		i40iw_clean_cq((void *)&iwuqp->qp, &iwuqp->recv_cq->cq);

	free(iwuqp);

	return 0;
}

/**
 * i40iw_copy_sg_list - copy sg list for qp
 * @sg_list: copied into sg_list
 * @sgl: copy from sgl
 * @num_sges: count of sg entries
 */
static void i40iw_copy_sg_list(struct i40iw_sge *sg_list, struct ibv_sge *sgl,
			       int num_sges)
{
	unsigned int i;

	for (i = 0; (i < num_sges) && (i < I40IW_MAX_WQ_FRAGMENT_COUNT); i++) {
		sg_list[i].tag_off = sgl[i].addr;
		sg_list[i].len = sgl[i].length;
		sg_list[i].stag = sgl[i].lkey;
	}
}

/**
 * i40iw_post_send -  post send wr for user application
 * @ib_qp: qp ptr for wr
 * @ib_wr: work request ptr
 * @bad_wr: return of bad wr if err
 */
int i40iw_upost_send(struct ibv_qp *ib_qp, struct ibv_send_wr *ib_wr, struct ibv_send_wr **bad_wr)
{
	struct i40iw_uqp *iwuqp;
	struct i40iw_post_sq_info info;
	enum i40iw_status_code ret = 0;
	int err = 0;

	iwuqp = (struct i40iw_uqp *)ib_qp;

	err = pthread_spin_lock(&iwuqp->lock);
	if (err)
		return err;
	while (ib_wr) {
		memset(&info, 0, sizeof(info));
		info.wr_id = (u64)(ib_wr->wr_id);
		if ((ib_wr->send_flags & IBV_SEND_SIGNALED) || iwuqp->sq_sig_all)
			info.signaled = true;
		if (ib_wr->send_flags & IBV_SEND_FENCE)
			info.read_fence = true;

		switch (ib_wr->opcode) {
		case IBV_WR_SEND:
		    /* fall-through */
		case IBV_WR_SEND_WITH_INV:
			if (ib_wr->opcode == IBV_WR_SEND) {
				if (ib_wr->send_flags & IBV_SEND_SOLICITED)
					info.op_type = I40IW_OP_TYPE_SEND_SOL;
				else
					info.op_type = I40IW_OP_TYPE_SEND;
			} else {
				if (ib_wr->send_flags & IBV_SEND_SOLICITED)
					info.op_type = I40IW_OP_TYPE_SEND_SOL_INV;
				else
					info.op_type = I40IW_OP_TYPE_SEND_INV;
			}

			if (ib_wr->send_flags & IBV_SEND_INLINE) {
			  info.op.inline_send.data = (void *)(uintptr_t)ib_wr->sg_list[0].addr;
				info.op.inline_send.len = ib_wr->sg_list[0].length;
				ret = iwuqp->qp.ops.iw_inline_send(&iwuqp->qp, &info,
								   ib_wr->invalidate_rkey, false);
			} else {
				info.op.send.num_sges = ib_wr->num_sge;
				info.op.send.sg_list = (struct i40iw_sge *)ib_wr->sg_list;
				ret = iwuqp->qp.ops.iw_send(&iwuqp->qp, &info,
							    ib_wr->invalidate_rkey, false);
			}

			if (ret) {
				if (ret == I40IW_ERR_QP_TOOMANY_WRS_POSTED)
					err = -ENOMEM;
				else
					err = -EINVAL;
			}
			break;

		case IBV_WR_RDMA_WRITE:
			info.op_type = I40IW_OP_TYPE_RDMA_WRITE;

			if (ib_wr->send_flags & IBV_SEND_INLINE) {
				info.op.inline_rdma_write.data = (void *)(uintptr_t)ib_wr->sg_list[0].addr;
				info.op.inline_rdma_write.len = ib_wr->sg_list[0].length;
				info.op.inline_rdma_write.rem_addr.tag_off = ib_wr->wr.rdma.remote_addr;
				info.op.inline_rdma_write.rem_addr.stag = ib_wr->wr.rdma.rkey;
				ret = iwuqp->qp.ops.iw_inline_rdma_write(&iwuqp->qp, &info, false);
			} else {
				info.op.rdma_write.lo_sg_list = (void *)ib_wr->sg_list;
				info.op.rdma_write.num_lo_sges = ib_wr->num_sge;
				info.op.rdma_write.rem_addr.tag_off = ib_wr->wr.rdma.remote_addr;
				info.op.rdma_write.rem_addr.stag = ib_wr->wr.rdma.rkey;
				ret = iwuqp->qp.ops.iw_rdma_write(&iwuqp->qp, &info, false);
			}

			if (ret) {
				if (ret == I40IW_ERR_QP_TOOMANY_WRS_POSTED)
					err = -ENOMEM;
				else
					err = -EINVAL;
			}
			break;

		case IBV_WR_RDMA_READ:
			if (ib_wr->num_sge > I40IW_MAX_SGE_RD) {
				err = -EINVAL;
				break;
			}
			info.op_type = I40IW_OP_TYPE_RDMA_READ;
			info.op.rdma_read.rem_addr.tag_off = ib_wr->wr.rdma.remote_addr;
			info.op.rdma_read.rem_addr.stag = ib_wr->wr.rdma.rkey;
			info.op.rdma_read.lo_addr.tag_off = ib_wr->sg_list->addr;
			info.op.rdma_read.lo_addr.stag = ib_wr->sg_list->lkey;
			info.op.rdma_read.lo_addr.len = ib_wr->sg_list->length;
			ret = iwuqp->qp.ops.iw_rdma_read(&iwuqp->qp, &info, false, false);
			if (ret) {
				if (ret == I40IW_ERR_QP_TOOMANY_WRS_POSTED)
					err = -ENOMEM;
				else
					err = -EINVAL;
			}
			break;

		default:
			/* error */
			err = -EINVAL;
			fprintf(stderr, PFX "%s: post work request failed, invalid opcode: 0x%x\n", __func__, ib_wr->opcode);
			break;
		}

		if (err)
			break;

		ib_wr = ib_wr->next;
	}

	if (err)
		*bad_wr = ib_wr;
	else
		iwuqp->qp.ops.iw_qp_post_wr(&iwuqp->qp);

	pthread_spin_unlock(&iwuqp->lock);

	return err;
}

/**
 * i40iw_post_recv - post receive wr for user application
 * @ib_wr: work request for receive
 * @bad_wr: bad wr caused an error
 */
int i40iw_upost_recv(struct ibv_qp *ib_qp, struct ibv_recv_wr *ib_wr, struct ibv_recv_wr **bad_wr)
{
	struct i40iw_uqp *iwuqp = to_i40iw_uqp(ib_qp);
	enum i40iw_status_code ret = 0;
	int err = 0;
	struct i40iw_post_rq_info post_recv;
	struct i40iw_sge sg_list[I40IW_MAX_WQ_FRAGMENT_COUNT];

	memset(&post_recv, 0, sizeof(post_recv));
	err = pthread_spin_lock(&iwuqp->lock);
	if (err)
		return err;
	while (ib_wr) {
		post_recv.num_sges = ib_wr->num_sge;
		post_recv.wr_id = ib_wr->wr_id;
		i40iw_copy_sg_list(sg_list, ib_wr->sg_list, ib_wr->num_sge);
		post_recv.sg_list = sg_list;
		ret = iwuqp->qp.ops.iw_post_receive(&iwuqp->qp, &post_recv);
		if (ret) {
			fprintf(stderr, PFX "%s: failed to post receives, status %d\n", __func__, ret);
			if (ret == I40IW_ERR_QP_TOOMANY_WRS_POSTED)
				err = -ENOMEM;
			else
				err = -EINVAL;
			*bad_wr = ib_wr;
			goto error;
		}
		ib_wr = ib_wr->next;
	}

error:
	pthread_spin_unlock(&iwuqp->lock);
	return err;
}

/**
 * i40iw_async_event - handle async events from driver
 * @context: ibv_context
 * @event: event received
 */
void i40iw_async_event(struct ibv_context *context,
		       struct ibv_async_event *event)
{
	struct i40iw_uqp *iwuqp;

	switch (event->event_type) {
	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_ACCESS_ERR:
		iwuqp = to_i40iw_uqp(event->element.qp);
		iwuqp->qperr = 1;
		break;

	default:
		break;
	}
}
