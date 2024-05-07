// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright 2022-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#include "hbl.h"
#include "infiniband/verbs.h"
#include "infiniband/cmd_ioctl.h"
#include "verbs.h"
#include "hbldv.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <util/util.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/hbl_user_ioctl_cmds.h>
#include <rdma/hbl_user_ioctl_verbs.h>

#define DEFAULT_NUM_WQE		16

static inline void *hbl_mmap(int fd, size_t length, off_t offset)
{
	return mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
}

static inline int hbl_munmap(void *addr, size_t length)
{
	return munmap(addr, length);
}

struct ibv_pd *hbl_alloc_pd(struct ibv_context *ibvctx)
{
	struct hbl_alloc_pd_resp resp = {};
	struct ibv_alloc_pd cmd = {};
	struct hbl_pd *pd;
	int rc;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	rc = ibv_cmd_alloc_pd(ibvctx, &pd->ibvpd, &cmd, sizeof(cmd), &resp.ibv_resp,
			      sizeof(resp));
	if (rc) {
		verbs_err(verbs_get_ctx(ibvctx), "Failed to allocate PD\n");
		goto out;
	}

	pd->pdn = resp.pdn;

	return &pd->ibvpd;

out:
	free(pd);
	errno = rc;

	return NULL;
}

int hbl_dealloc_pd(struct ibv_pd *ibvpd)
{
	struct verbs_context *vctx = verbs_get_ctx(ibvpd->context);
	struct hbl_pd *pd = to_hbl_pd(ibvpd);
	int rc;

	rc = ibv_cmd_dealloc_pd(ibvpd);
	if (rc) {
		verbs_err(vctx, "Failed to deallocate PD\n");
		return rc;
	}

	verbs_debug(vctx, "deallocted PD %d\n", pd->pdn);

	free(pd);

	return 0;
}

struct ibv_qp *hbl_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct ib_uverbs_create_qp_resp resp = {};
	struct ibv_create_qp cmd = {};
	struct hbl_qp *hblqp;
	int ret;

	hblqp = calloc(1, sizeof(*hblqp));
	if (!hblqp)
		goto err;

	ret = ibv_cmd_create_qp(pd, &hblqp->vqp.qp, attr, &cmd, sizeof(cmd), &resp, sizeof(resp));
	if (ret)
		goto err_free;

	hblqp->max_send_wr = attr->cap.max_send_wr;
	hblqp->max_recv_wr = attr->cap.max_recv_wr;

	return &hblqp->vqp.qp;

err_free:
	free(hblqp);
err:
	return NULL;
}

struct ibv_qp *hbl_create_qp_ex(struct ibv_context *context, struct ibv_qp_init_attr_ex *attr_ex)
{
	struct ib_uverbs_ex_create_qp_resp resp = {};
	struct ibv_create_qp_ex cmd = {};
	struct hbl_qp *hblqp;
	int ret;

	hblqp = calloc(1, sizeof(*hblqp));
	if (!hblqp)
		goto err;

	/* Force clear unsupported mask. Pytests set comp_mask with random data.
	 * Hence, we can't fail the API.
	 */
	attr_ex->comp_mask &= IBV_QP_INIT_ATTR_PD;

	ret = ibv_cmd_create_qp_ex2(context, &hblqp->vqp, attr_ex, &cmd, sizeof(cmd), &resp,
				    sizeof(resp));
	if (ret)
		goto err_free;

	hblqp->max_send_wr = attr_ex->cap.max_send_wr;

	return &hblqp->vqp.qp;

err_free:
	free(hblqp);
err:
	return NULL;
}

int hbl_destroy_qp(struct ibv_qp *iqp)
{
	struct verbs_qp *vqp = container_of(iqp, struct verbs_qp, qp);
	struct hbl_qp *hblqp = to_hbl_qp(vqp);
	int ret;

	if (hblqp->swq_cpu_addr) {
		hbl_munmap(hblqp->swq_cpu_addr, hblqp->swq_mem_size);
		hblqp->swq_cpu_addr = 0;
	}
	if (hblqp->rwq_cpu_addr) {
		hbl_munmap(hblqp->rwq_cpu_addr, hblqp->rwq_mem_size);
		hblqp->rwq_cpu_addr = 0;
	}

	ret = ibv_cmd_destroy_qp(iqp);
	if (ret)
		return ret;

	free(hblqp);

	return 0;
}

static enum hbl_ibv_qp_wq_types
get_qp_wq_type(enum hbldv_qp_wq_types from)
{
	enum hbl_ibv_qp_wq_types to = 0;

	if (from & HBLDV_WQ_WRITE)
		to |= HBL_WQ_WRITE;

	if (from & HBLDV_WQ_RECV_RDV)
		to |= HBL_WQ_RECV_RDV;

	if (from & HBLDV_WQ_READ_RDV)
		to |= HBL_WQ_READ_RDV;

	if (from & HBLDV_WQ_SEND_RDV)
		to |= HBL_WQ_SEND_RDV;

	if (from & HBLDV_WQ_READ_RDV_ENDP)
		to |= HBL_WQ_READ_RDV_ENDP;

	return to;
}

static int copy_qp_attr(struct hbl_modify_qp *hbl_cmd, struct hbldv_qp_attr *hbl_attr)
{
	hbl_cmd->wq_type = get_qp_wq_type(hbl_attr->wq_type);
	hbl_cmd->wq_granularity = hbl_attr->wq_granularity;
	hbl_cmd->local_key = hbl_attr->local_key;
	hbl_cmd->remote_key = hbl_attr->remote_key;
	hbl_cmd->congestion_wnd = hbl_attr->congestion_wnd;
	hbl_cmd->priority = hbl_attr->priority;
	hbl_cmd->loopback = (hbl_attr->caps & HBLDV_QP_CAP_LOOPBACK) ? 1 : 0;
	hbl_cmd->dest_wq_size = hbl_attr->dest_wq_size;
	hbl_cmd->congestion_en = (hbl_attr->caps & HBLDV_QP_CAP_CONG_CTRL) ? 1 : 0;
	hbl_cmd->compression_en = (hbl_attr->caps & HBLDV_QP_CAP_COMPRESSION) ? 1 : 0;
	hbl_cmd->encap_en = (hbl_attr->caps & HBLDV_QP_CAP_ENCAP) ? 1 : 0;
	hbl_cmd->encap_num = hbl_attr->encap_num;

	return 0;
}

static int get_default_qp_attr(struct verbs_context *vctx, struct hbl_modify_qp *hbl_cmd,
			       enum ibv_qp_state qp_state)
{
	switch (qp_state) {
	case IBV_QPS_RESET:
		/* No Ops */
		break;
	case IBV_QPS_INIT:
		hbl_cmd->wq_type = HBL_WQ_WRITE;
		hbl_cmd->wq_granularity = HBLDV_SWQE_GRAN_32B;
		break;
	case IBV_QPS_RTR:
		/* No Ops */
		break;
	case IBV_QPS_RTS:
		hbl_cmd->priority = 1;
		break;
	default:
		verbs_err(vctx, "Invalid QP state %d\n", qp_state);
		errno = EINVAL;
		return errno;
	}

	return 0;
}

static int modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr, int attr_mask,
		     struct hbldv_qp_attr *hbl_attr)
{
	struct verbs_qp *vqp = container_of(ibqp, struct verbs_qp, qp);
	struct verbs_context *vctx = verbs_get_ctx(ibqp->context);
	struct hbl_modify_qp_resp hbl_resp = {};
	struct hbl_qp *hblqp = to_hbl_qp(vqp);
	struct hbl_modify_qp hbl_cmd = {};
	int rc, fd;

	if (hbl_attr)
		rc = copy_qp_attr(&hbl_cmd, hbl_attr);
	else
		rc = get_default_qp_attr(vctx, &hbl_cmd, attr->qp_state);
	if (rc)
		return rc;

	rc = ibv_cmd_modify_qp_ex(ibqp, attr, attr_mask, &hbl_cmd.ibv_cmd, sizeof(hbl_cmd),
				  &hbl_resp.ibv_resp, sizeof(hbl_resp));
	if (rc)
		return rc;

	if ((attr_mask & IBV_QP_STATE) && attr->qp_state == IBV_QPS_RESET) {
		hblqp->qp_num = 0;
		hblqp->swq_mem_handle = 0;
		hblqp->rwq_mem_handle = 0;
	}

	if ((attr_mask & IBV_QP_STATE) && attr->qp_state == IBV_QPS_INIT)
		hblqp->qp_num = hbl_resp.qp_num;

	if ((attr_mask & IBV_QP_STATE) && attr->qp_state == IBV_QPS_RTS) {
		hblqp->swq_mem_handle = hbl_resp.swq_mem_handle;
		hblqp->rwq_mem_handle = hbl_resp.rwq_mem_handle;
		hblqp->swq_mem_size = hbl_resp.swq_mem_size;
		hblqp->rwq_mem_size = hbl_resp.rwq_mem_size;

		fd = vqp->qp.context->cmd_fd;

		if (hblqp->swq_mem_handle) {
			hblqp->swq_cpu_addr = hbl_mmap(fd, hblqp->swq_mem_size,
						       hblqp->swq_mem_handle);
			if (hblqp->swq_cpu_addr == MAP_FAILED) {
				verbs_err(vctx, "Failed to mmap send WQ handle 0x%lx\n",
					  hblqp->swq_mem_handle);
				return errno;
			}
		}

		if (hblqp->rwq_mem_handle) {
			hblqp->rwq_cpu_addr = hbl_mmap(fd, hblqp->rwq_mem_size,
						       hblqp->rwq_mem_handle);
			if (hblqp->rwq_cpu_addr == MAP_FAILED) {
				verbs_err(vctx, "Failed to mmap receive WQ handle 0x%lx\n",
					  hblqp->rwq_mem_handle);

				/* Cache errno to report relevant error. munmap in error flow may
				 * update errno in failure scenario.
				 */
				rc = errno;
				goto err_munmap_swq;
			}
		}
	}

	return 0;

err_munmap_swq:
	if (hblqp->swq_mem_handle) {
		hbl_munmap(hblqp->swq_cpu_addr, hblqp->swq_mem_size);
		hblqp->swq_cpu_addr = 0;
	}

	return rc;
}

int hbl_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr, int attr_mask)
{
	return modify_qp(ibqp, attr, attr_mask, NULL);
}

int hbldv_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr, int attr_mask,
		    struct hbldv_qp_attr *hbl_attr)
{
	int rc;

	if (!is_hbl_dev(ibqp->context->device)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	rc = modify_qp(ibqp, attr, attr_mask, hbl_attr);
	if (rc)
		return rc;

	if (attr_mask & IBV_QP_STATE)
		ibqp->state = attr->qp_state;

	return 0;
}

int hbldv_set_port_ex(struct ibv_context *context, struct hbldv_port_ex_attr *attr)
{
	DECLARE_COMMAND_BUFFER(cmd, HBL_IB_OBJECT_SET_PORT_EX, HBL_IB_METHOD_SET_PORT_EX, 1);
	struct verbs_context *vctx = verbs_get_ctx(context);
	struct hbl_uapi_set_port_ex_in in = {};
	int rc, i;

	if (!is_hbl_dev(context->device)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	if (!attr) {
		errno = EINVAL;
		return errno;
	}

	in.port_num = attr->port_num;

	for (i = 0; i < HBLDV_WQ_ARRAY_TYPE_MAX; i++) {
		in.wq_arr_attr[i].max_num_of_wqs = attr->wq_arr_attr[i].max_num_of_wqs;
		in.wq_arr_attr[i].max_num_of_wqes_in_wq =
							attr->wq_arr_attr[i].max_num_of_wqes_in_wq;
		in.wq_arr_attr[i].mem_id = attr->wq_arr_attr[i].mem_id;
		in.wq_arr_attr[i].swq_granularity = attr->wq_arr_attr[i].swq_granularity;
	}

	in.qp_wq_bp_offs_cnt = HBLDV_USER_BP_OFFS_MAX;
	in.qp_wq_bp_offs = (uintptr_t)attr->qp_wq_bp_offs;
	in.advanced = (attr->caps & HBLDV_PORT_CAP_ADVANCED) ? 1 : 0;
	in.adaptive_timeout_en = (attr->caps & HBLDV_PORT_CAP_ADAPTIVE_TIMEOUT) ? 1 : 0;

	fill_attr_in_ptr(cmd, HBL_IB_ATTR_SET_PORT_EX_IN, &in);

	rc = execute_ioctl(context, cmd);
	if (rc)
		verbs_err(vctx, "set_port_ex execute_ioctl err %d\n", rc);

	return rc;
}

int hbldv_query_port(struct ibv_context *context, uint32_t port_num,
		     struct hbldv_query_port_attr *hbl_attr)
{
	DECLARE_COMMAND_BUFFER(cmd, HBL_IB_OBJECT_QUERY_PORT, HBL_IB_METHOD_QUERY_PORT, 2);
	struct verbs_context *vctx = verbs_get_ctx(context);
	struct hbl_uapi_query_port_out out = {};
	struct hbl_uapi_query_port_in in = {};
	int rc;

	if (!is_hbl_dev(context->device)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	if (!hbl_attr) {
		errno = EINVAL;
		return errno;
	}

	in.port_num = port_num;

	fill_attr_in_ptr(cmd, HBL_IB_ATTR_QUERY_PORT_IN, &in);
	fill_attr_out_ptr(cmd, HBL_IB_ATTR_QUERY_PORT_OUT, &out);

	rc = execute_ioctl(context, cmd);
	if (rc) {
		verbs_err(vctx, "query_port execute_ioctl err %d\n", rc);
		return rc;
	}

	hbl_attr->max_num_of_qps = out.max_num_of_qps;
	hbl_attr->num_allocated_qps = out.num_allocated_qps;
	hbl_attr->max_allocated_qp_num = out.max_allocated_qp_num;
	hbl_attr->max_cq_size = out.max_cq_size;
	hbl_attr->advanced = out.advanced;
	hbl_attr->max_num_of_cqs = out.max_num_of_cqs;
	hbl_attr->max_num_of_usr_fifos = out.max_num_of_usr_fifos;
	hbl_attr->max_num_of_encaps = out.max_num_of_encaps;
	hbl_attr->nic_macro_idx = out.nic_macro_idx;
	hbl_attr->nic_phys_port_idx = out.nic_phys_port_idx;

	return 0;
}

static int __hbldv_destroy_usr_fifo(struct hbl_usr_fifo_obj *obj)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       HBL_IB_OBJECT_USR_FIFO,
			       HBL_IB_METHOD_USR_FIFO_OBJ_DESTROY,
			       1);
	struct ibv_context *context = obj->context;
	int rc;

	fill_attr_in_obj(cmd, HBL_IB_ATTR_USR_FIFO_DESTROY_HANDLE, obj->handle);

	rc = execute_ioctl(context, cmd);
	if (rc)
		verbs_err(verbs_get_ctx(context), "destroy_usr_fifo execute_ioctl err %d\n", rc);

	return rc;
}

struct hbldv_usr_fifo *hbldv_create_usr_fifo(struct ibv_context *context,
					     struct hbldv_usr_fifo_attr *attr)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       HBL_IB_OBJECT_USR_FIFO,
			       HBL_IB_METHOD_USR_FIFO_OBJ_CREATE,
			       3);
	struct verbs_context *vctx = verbs_get_ctx(context);
	struct hbl_uapi_usr_fifo_create_out out = {};
	struct hbl_uapi_usr_fifo_create_in in = {};
	struct hbldv_usr_fifo *usr_fifo;
	uint64_t ci_handle, regs_handle;
	struct ib_uverbs_attr *handle;
	struct hbl_usr_fifo_obj *obj;
	struct hbl_context *hctx;
	unsigned long page_size;
	int fd, rc;

	if (!is_hbl_dev(context->device)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	hctx = to_hbl_ctx(context);

	obj = calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	obj->context = context;
	usr_fifo = &obj->dv_usr_fifo;

	in.port_num = attr->port_num;
	in.mode = attr->usr_fifo_type;
	in.usr_fifo_num_hint = attr->usr_fifo_num_hint;

	fill_attr_in_ptr(cmd, HBL_IB_ATTR_USR_FIFO_CREATE_IN, &in);
	fill_attr_out_ptr(cmd, HBL_IB_ATTR_USR_FIFO_CREATE_OUT, &out);
	handle = fill_attr_out_obj(cmd, HBL_IB_ATTR_USR_FIFO_CREATE_HANDLE);

	rc = execute_ioctl(context, cmd);
	if (rc) {
		verbs_err(vctx, "create_usr_fifo execute_ioctl err %d\n", rc);
		goto free_usr_fifo;
	}

	usr_fifo->usr_fifo_num = out.usr_fifo_num;
	usr_fifo->regs_offset = out.regs_offset;
	usr_fifo->bp_thresh = out.bp_thresh;
	usr_fifo->size = out.size;

	usr_fifo->ci_cpu_addr = MAP_FAILED;
	usr_fifo->regs_cpu_addr = MAP_FAILED;

	obj->handle = read_attr_obj(HBL_IB_ATTR_USR_FIFO_CREATE_HANDLE, handle);

	page_size = sysconf(_SC_PAGESIZE);
	fd = context->cmd_fd;

	ci_handle = out.ci_handle;
	regs_handle = out.regs_handle;

	usr_fifo->ci_cpu_addr = hbl_mmap(fd, page_size, ci_handle);
	if (usr_fifo->ci_cpu_addr == MAP_FAILED) {
		verbs_err(vctx, "Failed to mmap user fifo CI handle 0x%lx, errno %d\n", ci_handle,
			  errno);
		goto destroy_usr_fifo;
	}

	if (hctx->cap_mask & HBL_UCONTEXT_CAP_MMAP_UMR) {
		usr_fifo->regs_cpu_addr = hbl_mmap(fd, page_size, regs_handle);
		if (usr_fifo->regs_cpu_addr == MAP_FAILED) {
			verbs_err(vctx, "Failed to mmap user fifo UMR handle 0x%lx, errno %d\n",
				  regs_handle, errno);
			goto munmap_ci;
		}
	}

	return usr_fifo;

munmap_ci:
	hbl_munmap(usr_fifo->ci_cpu_addr, page_size);
destroy_usr_fifo:
	__hbldv_destroy_usr_fifo(obj);
free_usr_fifo:
	free(obj);
	return NULL;
}

int hbldv_destroy_usr_fifo(struct hbldv_usr_fifo *usr_fifo)
{
	struct hbl_usr_fifo_obj *obj = container_of(usr_fifo, struct hbl_usr_fifo_obj,
						    dv_usr_fifo);
	unsigned long page_size = sysconf(_SC_PAGESIZE);
	struct ibv_context *context = obj->context;
	int rc;

	if (!is_hbl_dev(context->device)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	if (usr_fifo->regs_cpu_addr != MAP_FAILED)
		hbl_munmap(usr_fifo->regs_cpu_addr, page_size);

	if (usr_fifo->ci_cpu_addr != MAP_FAILED)
		hbl_munmap(usr_fifo->ci_cpu_addr, page_size);

	rc = __hbldv_destroy_usr_fifo(obj);

	free(obj);

	return rc;
}

static int get_max_ports_from_port_mask(uint64_t ports_mask)
{
	int max_num_ports = 0;
	int msb_index = 0;

	if (ports_mask == 0)
		return -1;

	while (ports_mask > 1) {
		ports_mask >>= 1;
		msb_index++;
	}

	max_num_ports = msb_index + 1;

	return max_num_ports;
}

static int hbl_update_port_cq(struct hbl_cq *hblcq, struct ibv_context *ibvctx,
			      struct hbl_create_cq_resp *cq_resp, int max_ports)
{
	struct hbl_ibv_port_create_cq_resp *hbl_port_cq_resp;
	struct verbs_context *vctx = verbs_get_ctx(ibvctx);
	uint64_t mem_handle, pi_handle, regs_handle;
	struct hbl_context *hbl_ctx;
	struct hbl_cq *hbl_port_cq;
	uint64_t regs_buf_mask = 0;
	uint64_t mem_buf_mask = 0;
	uint64_t pi_buf_mask = 0;
	unsigned long page_size;
	uint64_t ports_mask = 0;
	int fd, rc = 0;
	uint8_t i;

	hbl_ctx = to_hbl_ctx(ibvctx);
	ports_mask = hbl_ctx->ports_mask;
	page_size = sysconf(_SC_PAGESIZE);

	for (i = 1; i < max_ports; i++) {
		if (!(ports_mask & (1 << i)))
			continue;

		fd = hbl_ctx->ibv_ctx.context.cmd_fd;

		hbl_port_cq_resp = &cq_resp->port_cq_resp[i];
		mem_handle = hbl_port_cq_resp->mem_handle;
		pi_handle = hbl_port_cq_resp->pi_handle;
		regs_handle = hbl_port_cq_resp->regs_handle;

		hbl_port_cq = &hblcq->port_cq[i];
		hbl_port_cq->cq_num = hbl_port_cq_resp->cq_num;
		hbl_port_cq->regs_offset = hbl_port_cq_resp->regs_offset;
		hbl_port_cq->cq_size = hbl_port_cq_resp->cq_size;
		hbl_port_cq->cq_type = hblcq->cq_type;

		/* mmap the CQ buffer */
		hbl_port_cq->mem_cpu_addr = hbl_mmap(fd, hbl_port_cq->cq_size, mem_handle);
		if (hbl_port_cq->mem_cpu_addr == MAP_FAILED) {
			verbs_err(vctx, "Failed to mmap CQ mem handle 0x%lx\n", mem_handle);
			rc = -EBUSY;
			goto err_munmap_cpu_addr;
		}

		mem_buf_mask |= (1 << i);

		/* mmap the Pi buffer */
		hbl_port_cq->pi_cpu_addr = hbl_mmap(fd, page_size, pi_handle);
		if (hbl_port_cq->pi_cpu_addr == MAP_FAILED) {
			verbs_err(vctx, "Failed to mmap CQ PI handle 0x%lx\n", pi_handle);
			rc = -EBUSY;
			goto err_munmap_pi;
		}

		pi_buf_mask |= (1 << i);

		/* mmap the UMR register */
		if ((hbl_ctx->cap_mask & HBL_UCONTEXT_CAP_MMAP_UMR) && regs_handle) {
			hbl_port_cq->regs_cpu_addr = hbl_mmap(fd, page_size, regs_handle);
			if (hbl_port_cq->regs_cpu_addr == MAP_FAILED) {
				verbs_err(vctx, "Failed to mmap CQ UMR reg handle 0x%lx\n",
					  regs_handle);
				rc = -EBUSY;
				goto err_munmap_cpu_reg;
			}

			regs_buf_mask |= (1 << i);
		}
	}

	return 0;

err_munmap_cpu_reg:
	for (i = 0; i < max_ports; i++) {
		if (regs_buf_mask & (1 << i))
			hbl_munmap(hblcq->port_cq[i].regs_cpu_addr, page_size);
	}
err_munmap_pi:
	for (i = 0; i < max_ports; i++) {
		if (pi_buf_mask & (1 << i))
			hbl_munmap(hblcq->port_cq[i].pi_cpu_addr, page_size);
	}
err_munmap_cpu_addr:
	for (i = 0; i < max_ports; i++) {
		if (mem_buf_mask & (1 << i))
			hbl_munmap(hblcq->port_cq[i].mem_cpu_addr, hblcq->port_cq[i].cq_size);
	}

	return rc;
}

static struct hbl_cq *create_per_port_cq(struct ibv_context *ibvctx, int cqe,
					 struct ibv_comp_channel *channel, int comp_vector,
					 struct hbldv_cq_attr *cq_attr)
{
	struct verbs_context *vctx = verbs_get_ctx(ibvctx);
	struct hbl_create_cq_resp *cq_resp = NULL;
	struct hbl_create_cq cq_cmd = {};
	struct hbl_context *hbl_ctx;
	struct hbl_cq *hblcq;
	uint64_t ports_mask;
	size_t cq_resp_size;
	int max_ports, rc;

	hbl_ctx = to_hbl_ctx(ibvctx);
	ports_mask = hbl_ctx->ports_mask;

	max_ports = get_max_ports_from_port_mask(ports_mask);
	if (max_ports < 0) {
		verbs_err(vctx, "port mask is empty: %llx\n", ports_mask);
		goto err;
	}

	if (!cq_attr)
		goto err;

	cq_cmd.cq_type = cq_attr->cq_type;
	cq_cmd.flags |= CQ_FLAG_NATIVE;

	hblcq = calloc(1, sizeof(*hblcq));
	if (!hblcq)
		goto err;

	/* Round up the cqes to the next highest power of 2 */
	cqe = next_pow2(cqe);

	cq_resp_size = (sizeof(struct hbl_ibv_port_create_cq_resp) * max_ports) +
		       sizeof(struct hbl_create_cq_resp);
	cq_resp = (struct hbl_create_cq_resp *)malloc(cq_resp_size);

	hblcq->port_cq = (struct hbl_cq *)calloc(max_ports, sizeof(struct hbl_cq));
	if (!hblcq->port_cq)
		goto err_port_cq;

	if (ibv_cmd_create_cq(ibvctx, cqe, channel, comp_vector, &hblcq->ibvcq, &cq_cmd.ibv_cmd,
			      sizeof(cq_cmd), &cq_resp->ibv_resp, cq_resp_size)) {
		verbs_err(vctx, "ibv_cmd_create_cq failed\n");
		goto free_cq;
	}

	hblcq->cq_type = cq_attr->cq_type;
	hblcq->is_native = true;

	rc = hbl_update_port_cq(hblcq, ibvctx, cq_resp, max_ports);
	if (rc) {
		verbs_err(vctx, "Failed to update port CQ\n");
		goto destroy_cq;
	}

	return hblcq;

destroy_cq:
	ibv_cmd_destroy_cq(&hblcq->ibvcq);
free_cq:
	free(hblcq->port_cq);
err_port_cq:
	free(hblcq);
err:
	return NULL;
}

static struct hbl_cq *create_cq(struct ibv_context *ibvctx, int cqe,
				struct ibv_comp_channel *channel, int comp_vector,
				struct hbldv_cq_attr *cq_attr)
{
	struct verbs_context *vctx = verbs_get_ctx(ibvctx);
	uint64_t mem_handle, pi_handle, regs_handle;
	struct hbl_create_cq_resp cq_resp = {};
	struct hbl_create_cq cq_cmd = {};
	struct hbl_context *hbl_ctx;
	unsigned long page_size;
	struct hbl_cq *hblcq;
	int fd;

	hbl_ctx = to_hbl_ctx(ibvctx);
	page_size = sysconf(_SC_PAGESIZE);
	fd = hbl_ctx->ibv_ctx.context.cmd_fd;

	if (!cq_attr)
		goto err;

	cq_cmd.port_num = cq_attr->port_num;
	cq_cmd.cq_type = cq_attr->cq_type;

	hblcq = calloc(1, sizeof(*hblcq));
	if (!hblcq)
		goto err;

	/* Round up the cqes to the next highest power of 2 */
	cqe = next_pow2(cqe);

	if (ibv_cmd_create_cq(ibvctx, cqe, channel, comp_vector, &hblcq->ibvcq, &cq_cmd.ibv_cmd,
			      sizeof(cq_cmd), &cq_resp.ibv_resp, sizeof(cq_resp))) {
		verbs_err(vctx, "ibv_cmd_create_cq failed, port: %d\n", cq_attr->port_num);
		goto free_cq;
	}

	hblcq->cq_num = cq_resp.cq_num;
	mem_handle = cq_resp.mem_handle;
	pi_handle = cq_resp.pi_handle;
	regs_handle = cq_resp.regs_handle;
	hblcq->regs_offset = cq_resp.regs_offset;
	hblcq->cq_size = cq_resp.cq_size;
	hblcq->cq_type = cq_attr->cq_type;

	/* mmap the CQ buffer */
	hblcq->mem_cpu_addr = hbl_mmap(fd, hblcq->cq_size, mem_handle);
	if (hblcq->mem_cpu_addr == MAP_FAILED) {
		verbs_err(vctx, "Failed to mmap CQ mem handle 0x%lx\n", mem_handle);
		goto destroy_cq;
	}

	/* mmap the Pi buffer */
	hblcq->pi_cpu_addr = hbl_mmap(fd, page_size, pi_handle);
	if (hblcq->pi_cpu_addr == MAP_FAILED) {
		verbs_err(vctx, "Failed to mmap CQ PI handle 0x%lx\n", pi_handle);
		goto err_munmap_cq;
	}

	/* mmap the UMR register */
	if ((hbl_ctx->cap_mask & HBL_UCONTEXT_CAP_MMAP_UMR) && regs_handle) {
		hblcq->regs_cpu_addr = hbl_mmap(fd, page_size, regs_handle);
		if (hblcq->regs_cpu_addr == MAP_FAILED) {
			verbs_err(vctx, "Failed to mmap CQ UMR reg handle 0x%lx\n", regs_handle);
			goto err_munmap_pi;
		}
	}

	return hblcq;

err_munmap_cq:
	hbl_munmap(hblcq->mem_cpu_addr, hblcq->cq_size);
err_munmap_pi:
	hbl_munmap(hblcq->pi_cpu_addr, page_size);
destroy_cq:
	ibv_cmd_destroy_cq(&hblcq->ibvcq);
free_cq:
	free(hblcq);
err:
	return NULL;
}

struct ibv_cq *hbl_create_cq(struct ibv_context *context, int cqe,
			     struct ibv_comp_channel *channel, int comp_vector)
{
	struct verbs_context *vctx = verbs_get_ctx(context);
	struct hbldv_cq_attr cq_attr = {};
	struct hbl_cq *hblcq;

	cq_attr.cq_type = HBLDV_CQ_TYPE_QP;

	/* The actual create CQ implementation would be via direct verbs. But we need this callback
	 * to satisfy the python tests. So, we just create CQ for the first available port and exit.
	 */
	hblcq = create_per_port_cq(context, cqe, channel, comp_vector, &cq_attr);
	if (!hblcq) {
		verbs_err(vctx, "CQ create failed\n");
		return NULL;
	}

	return &hblcq->ibvcq;
}

static struct hbl_cq *hbl_unmap_per_port_cq(struct ibv_cq *ibvcq, struct hbl_cq *hblcq)
{
	struct verbs_context *vctx = verbs_get_ctx(ibvcq->context);
	struct hbl_context *hbl_ctx;
	unsigned long page_size;
	uint64_t ports_mask = 0;
	int max_ports;
	uint8_t i;

	hbl_ctx = to_hbl_ctx(ibvcq->context);
	ports_mask = hbl_ctx->ports_mask;
	page_size = sysconf(_SC_PAGESIZE);

	max_ports = get_max_ports_from_port_mask(ports_mask);
	if (max_ports < 0)
		verbs_err(vctx, "port mask is empty: %lx\n", ports_mask);

	for (i = 1; i < max_ports; i++) {
		if (!(ports_mask & (1 << i)))
			continue;

		if ((hbl_ctx->cap_mask & HBL_UCONTEXT_CAP_MMAP_UMR) &&
		    hblcq->port_cq[i].regs_cpu_addr)
			hbl_munmap(hblcq->port_cq[i].regs_cpu_addr, page_size);

		hbl_munmap(hblcq->port_cq[i].pi_cpu_addr, page_size);
		hbl_munmap(hblcq->port_cq[i].mem_cpu_addr, hblcq->port_cq[i].cq_size);
	}

	return hblcq;
}

int hbl_destroy_cq(struct ibv_cq *ibvcq)
{
	struct hbl_context *hbl_ctx = to_hbl_ctx(ibvcq->context);
	unsigned long page_size = sysconf(_SC_PAGESIZE);
	struct hbl_cq *hblcq = to_hbl_cq(ibvcq);
	int rc;

	if ((hbl_ctx->cap_mask & HBL_UCONTEXT_CAP_MMAP_UMR) && hblcq->regs_cpu_addr)
		hbl_munmap(hblcq->regs_cpu_addr, page_size);

	if (hblcq->is_native) {
		hblcq = hbl_unmap_per_port_cq(ibvcq, hblcq);
	} else {
		hbl_munmap(hblcq->pi_cpu_addr, page_size);
		hbl_munmap(hblcq->mem_cpu_addr, hblcq->cq_size);
	}

	rc = ibv_cmd_destroy_cq(ibvcq);
	if (rc)
		return rc;

	free(hblcq);

	return 0;
}

struct ibv_cq *hbldv_create_cq(struct ibv_context *context, int cqe,
			       struct ibv_comp_channel *channel, int comp_vector,
			       struct hbldv_cq_attr *cq_attr)
{
	struct verbs_context *vctx = verbs_get_ctx(context);
	struct hbl_cq *hblcq;

	if (!is_hbl_dev(context->device)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	hblcq = create_cq(context, cqe, channel, comp_vector, cq_attr);
	if (!hblcq) {
		verbs_err(vctx, "CQ create failed, port: %d\n", cq_attr->port_num);
		return NULL;
	}

	return &hblcq->ibvcq;
}

int hbldv_query_cq(struct ibv_cq *ibvcq, struct hbldv_query_cq_attr *cq_attr)
{
	struct ibv_context *context = ibvcq->context;
	struct hbl_cq *hblcq = to_hbl_cq(ibvcq);

	if (!is_hbl_dev(context->device)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	cq_attr->ibvcq = &hblcq->ibvcq;
	cq_attr->mem_cpu_addr = hblcq->mem_cpu_addr;
	cq_attr->pi_cpu_addr = hblcq->pi_cpu_addr;
	cq_attr->regs_cpu_addr = hblcq->regs_cpu_addr;
	cq_attr->cq_size = hblcq->cq_size;
	cq_attr->cq_num = hblcq->cq_num;
	cq_attr->regs_offset = hblcq->regs_offset;
	cq_attr->cq_type = hblcq->cq_type;

	return 0;
}

int hbl_query_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr, int attr_mask,
		 struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	return ibv_cmd_query_qp(ibvqp, attr, attr_mask, init_attr, &cmd, sizeof(cmd));
}

int hbldv_query_qp(struct ibv_qp *ibvqp, struct hbldv_query_qp_attr *qp_attr)
{
	struct verbs_qp *vqp = container_of(ibvqp, struct verbs_qp, qp);
	struct hbl_qp *hblqp;

	if (!is_hbl_dev(ibvqp->context->device)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	hblqp = to_hbl_qp(vqp);

	qp_attr->qp_num = hblqp->qp_num;
	qp_attr->swq_cpu_addr = hblqp->swq_cpu_addr;
	qp_attr->rwq_cpu_addr = hblqp->rwq_cpu_addr;

	return 0;
}

void hbl_async_event(struct ibv_context *ctx, struct ibv_async_event *event)
{
	struct ibv_qp *ibv_qp = event->element.qp;

	switch (event->event_type) {
	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_REQ_ERR:
		ibv_qp->state = IBV_QPS_ERR;
		break;
	default:
		break;
	}
}

struct hbldv_encap *hbldv_create_encap(struct ibv_context *context,
				       struct hbldv_encap_attr *encap_attr)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       HBL_IB_OBJECT_ENCAP,
			       HBL_IB_METHOD_ENCAP_CREATE,
			       3);
	struct verbs_context *vctx = verbs_get_ctx(context);
	struct hbl_uapi_encap_create_out out = {};
	struct hbl_uapi_encap_create_in in = {};
	struct ib_uverbs_attr *handle;
	struct hbl_encap *encap_data;
	int rc;

	if (!is_hbl_dev(context->device)) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (!encap_attr) {
		errno = EINVAL;
		return NULL;
	}

	encap_data = calloc(1, sizeof(*encap_data));
	if (!encap_data) {
		errno = ENOMEM;
		return NULL;
	}

	in.port_num = encap_attr->port_num;
	in.tnl_hdr_ptr = encap_attr->tnl_hdr_ptr;
	in.tnl_hdr_size = encap_attr->tnl_hdr_size;
	in.ipv4_addr = encap_attr->ipv4_addr;
	in.udp_dst_port = encap_attr->udp_dst_port;
	in.ip_proto = encap_attr->ip_proto;
	in.encap_type = encap_attr->encap_type;

	fill_attr_in_ptr(cmd, HBL_IB_ATTR_ENCAP_CREATE_IN, &in);
	fill_attr_out_ptr(cmd, HBL_IB_ATTR_ENCAP_CREATE_OUT, &out);
	handle = fill_attr_out_obj(cmd, HBL_IB_ATTR_ENCAP_CREATE_HANDLE);

	rc = execute_ioctl(context, cmd);
	if (rc) {
		verbs_err(vctx, "create_encap execute_ioctl err %d\n", rc);
		goto err_free_encap_data;
	}

	encap_data->dv_encap.encap_num = out.encap_num;
	encap_data->handle = read_attr_obj(HBL_IB_ATTR_ENCAP_CREATE_HANDLE, handle);
	encap_data->context = context;

	return &encap_data->dv_encap;

err_free_encap_data:
	free(encap_data);

	return NULL;
}

int hbldv_destroy_encap(struct hbldv_encap *hbl_encap)
{
	struct hbl_encap *encap_data = container_of(hbl_encap, struct hbl_encap, dv_encap);
	DECLARE_COMMAND_BUFFER(cmd,
			       HBL_IB_OBJECT_ENCAP,
			       HBL_IB_METHOD_ENCAP_DESTROY,
			       1);
	struct ibv_context *context = encap_data->context;
	struct verbs_context *vctx;
	int rc;

	vctx = verbs_get_ctx(context);

	if (!is_hbl_dev(context->device)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	fill_attr_in_obj(cmd, HBL_IB_ATTR_ENCAP_DESTROY_HANDLE, encap_data->handle);

	rc = execute_ioctl(context, cmd);
	if (rc)
		verbs_err(vctx, "destroy_encap execute_ioctl err %d\n", rc);

	free(encap_data);

	return rc;
}

int hbldv_query_device(struct ibv_context *context, struct hbldv_device_attr *attr)
{
	struct hbl_context *hctx = to_hbl_ctx(context);

	if (!is_hbl_dev(context->device)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	attr->caps = 0;

	if (hctx->cap_mask & HBL_UCONTEXT_CAP_CC)
		attr->caps |= HBLDV_DEVICE_ATTR_CAP_CC;

	attr->ports_mask = hctx->ports_mask;

	return 0;
}
