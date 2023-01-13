// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (C) 2019 - 2020 Intel Corporation */
#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>
#include <linux/if_ether.h>
#include <infiniband/opcode.h>

#include "umain.h"
#include "abi.h"

static inline void print_fw_ver(uint64_t fw_ver, char *str, size_t len)
{
	uint16_t major, minor;

	major = fw_ver >> 32 & 0xffff;
	minor = fw_ver & 0xffff;

	snprintf(str, len, "%d.%d", major, minor);
}

/**
 * irdma_uquery_device_ex - query device attributes including extended properties
 * @context: user context for the device
 * @input: extensible input struct for ibv_query_device_ex verb
 * @attr: extended device attribute struct
 * @attr_size: size of extended device attribute struct
 **/
int irdma_uquery_device_ex(struct ibv_context *context,
			   const struct ibv_query_device_ex_input *input,
			   struct ibv_device_attr_ex *attr, size_t attr_size)
{
	struct ib_uverbs_ex_query_device_resp resp = {};
	size_t resp_size = sizeof(resp);
	int ret;

	ret = ibv_cmd_query_device_any(context, input, attr, attr_size,
				       &resp, &resp_size);
	if (ret)
		return ret;

	print_fw_ver(resp.base.fw_ver, attr->orig_attr.fw_ver, sizeof(attr->orig_attr.fw_ver));

	return 0;
}

/**
 * irdma_uquery_port - get port attributes (msg size, lnk, mtu...)
 * @context: user context of the device
 * @port: port for the attributes
 * @attr: to return port attributes
 **/
int irdma_uquery_port(struct ibv_context *context, uint8_t port,
		      struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof(cmd));
}

/**
 * irdma_ualloc_pd - allocates protection domain and return pd ptr
 * @context: user context of the device
 **/
struct ibv_pd *irdma_ualloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct irdma_ualloc_pd_resp resp = {};
	struct irdma_upd *iwupd;
	int err;

	iwupd = malloc(sizeof(*iwupd));
	if (!iwupd)
		return NULL;

	err = ibv_cmd_alloc_pd(context, &iwupd->ibv_pd, &cmd, sizeof(cmd),
			       &resp.ibv_resp, sizeof(resp));
	if (err)
		goto err_free;

	iwupd->pd_id = resp.pd_id;

	return &iwupd->ibv_pd;

err_free:
	free(iwupd);
	errno = err;
	return NULL;
}

/**
 * irdma_ufree_pd - free pd resources
 * @pd: pd to free resources
 */
int irdma_ufree_pd(struct ibv_pd *pd)
{
	struct irdma_upd *iwupd;
	int ret;

	iwupd = container_of(pd, struct irdma_upd, ibv_pd);
	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	free(iwupd);

	return 0;
}

/**
 * irdma_ureg_mr - register user memory region
 * @pd: pd for the mr
 * @addr: user address of the memory region
 * @length: length of the memory
 * @hca_va: hca_va
 * @access: access allowed on this mr
 */
struct ibv_mr *irdma_ureg_mr(struct ibv_pd *pd, void *addr, size_t length,
			     uint64_t hca_va, int access)
{
	struct irdma_umr *umr;
	struct irdma_ureg_mr cmd;
	struct ib_uverbs_reg_mr_resp resp;
	int err;

	umr = malloc(sizeof(*umr));
	if (!umr)
		return NULL;

	cmd.reg_type = IRDMA_MEMREG_TYPE_MEM;
	err = ibv_cmd_reg_mr(pd, addr, length,
			     hca_va, access, &umr->vmr, &cmd.ibv_cmd,
			     sizeof(cmd), &resp, sizeof(resp));
	if (err) {
		free(umr);
		errno = err;
		return NULL;
	}
	umr->acc_flags = access;

	return &umr->vmr.ibv_mr;
}

/**
 * irdma_udereg_mr - re-register memory region
 * @vmr: mr that was allocated
 */
int irdma_udereg_mr(struct verbs_mr *vmr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

	free(vmr);

	return 0;
}

/**
 * irdma_ualloc_mw - allocate memory window
 * @pd: protection domain
 * @type: memory window type
 */
struct ibv_mw *irdma_ualloc_mw(struct ibv_pd *pd, enum ibv_mw_type type)
{
	struct ibv_mw *mw;
	struct ibv_alloc_mw cmd;
	struct ib_uverbs_alloc_mw_resp resp;

	if (type != IBV_MW_TYPE_1) {
		errno = ENOTSUP;
		return NULL;
	}

	mw = calloc(1, sizeof(*mw));
	if (!mw)
		return NULL;

	if (ibv_cmd_alloc_mw(pd, type, mw, &cmd, sizeof(cmd), &resp,
			     sizeof(resp))) {
		free(mw);
		return NULL;
	}

	return mw;
}

/**
 * irdma_ubind_mw - bind a memory window
 * @qp: qp to post WR
 * @mw: memory window to bind
 * @mw_bind: bind info
 */
int irdma_ubind_mw(struct ibv_qp *qp, struct ibv_mw *mw,
		   struct ibv_mw_bind *mw_bind)
{
	struct ibv_mw_bind_info	*bind_info = &mw_bind->bind_info;
	struct verbs_mr *vmr = verbs_get_mr(bind_info->mr);
	struct irdma_umr *umr = container_of(vmr, struct irdma_umr, vmr);

	struct ibv_send_wr wr = {};
	struct ibv_send_wr *bad_wr;
	int err;

	if (vmr->mr_type != IBV_MR_TYPE_MR)
		return ENOTSUP;

	if (umr->acc_flags & IBV_ACCESS_ZERO_BASED)
		return EINVAL;

	wr.opcode = IBV_WR_BIND_MW;
	wr.bind_mw.bind_info = mw_bind->bind_info;
	wr.bind_mw.mw = mw;
	wr.bind_mw.rkey = ibv_inc_rkey(mw->rkey);

	wr.wr_id = mw_bind->wr_id;
	wr.send_flags = mw_bind->send_flags;

	err = irdma_upost_send(qp, &wr, &bad_wr);
	if (!err)
		mw->rkey = wr.bind_mw.rkey;

	return err;
}

/**
 * irdma_udealloc_mw - deallocate memory window
 * @mw: memory window to dealloc
 */
int irdma_udealloc_mw(struct ibv_mw *mw)
{
	int ret;

	ret = ibv_cmd_dealloc_mw(mw);
	if (ret)
		return ret;
	free(mw);

	return 0;
}

static void *irdma_alloc_hw_buf(size_t size)
{
	void *buf;

	buf = memalign(IRDMA_HW_PAGE_SIZE, size);

	if (!buf)
		return NULL;
	if (ibv_dontfork_range(buf, size)) {
		free(buf);
		return NULL;
	}

	return buf;
}

static void irdma_free_hw_buf(void *buf, size_t size)
{
	ibv_dofork_range(buf, size);
	free(buf);
}

/**
 * get_cq_size - returns actual cqe needed by HW
 * @ncqe: minimum cqes requested by application
 * @hw_rev: HW generation
 */
static inline int get_cq_size(int ncqe, __u8 hw_rev)
{
	ncqe++;

	/* Completions with immediate require 1 extra entry */
	if (hw_rev > IRDMA_GEN_1)
		ncqe *= 2;

	if (ncqe < IRDMA_U_MINCQ_SIZE)
		ncqe = IRDMA_U_MINCQ_SIZE;

	return ncqe;
}

static inline size_t get_cq_total_bytes(__u32 cq_size)
{
	return roundup(cq_size * sizeof(struct irdma_cqe), IRDMA_HW_PAGE_SIZE);
}

/**
 * ucreate_cq - irdma util function to create a CQ
 * @context: ibv context
 * @attr_ex: CQ init attributes
 * @ext_cq: flag to create an extendable or normal CQ
 */
static struct ibv_cq_ex *ucreate_cq(struct ibv_context *context,
				    struct ibv_cq_init_attr_ex *attr_ex,
				    bool ext_cq)
{
	struct irdma_cq_uk_init_info info = {};
	struct irdma_ureg_mr reg_mr_cmd = {};
	struct irdma_ucreate_cq_ex cmd = {};
	struct irdma_ucreate_cq_ex_resp resp = {};
	struct ib_uverbs_reg_mr_resp reg_mr_resp = {};
	struct irdma_ureg_mr reg_mr_shadow_cmd = {};
	struct ib_uverbs_reg_mr_resp reg_mr_shadow_resp = {};
	struct irdma_uk_attrs *uk_attrs;
	struct irdma_uvcontext *iwvctx;
	struct irdma_ucq *iwucq;
	size_t total_size;
	__u32 cq_pages;
	int ret, ncqe;
	__u8 hw_rev;

	iwvctx = container_of(context, struct irdma_uvcontext, ibv_ctx.context);
	uk_attrs = &iwvctx->uk_attrs;
	hw_rev = uk_attrs->hw_rev;

	if (ext_cq && hw_rev == IRDMA_GEN_1) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (attr_ex->cqe < IRDMA_MIN_CQ_SIZE || attr_ex->cqe > uk_attrs->max_hw_cq_size) {
		errno = EINVAL;
		return NULL;
	}

	/* save the cqe requested by application */
	ncqe = attr_ex->cqe;
	iwucq = calloc(1, sizeof(*iwucq));
	if (!iwucq)
		return NULL;

	if (pthread_spin_init(&iwucq->lock, PTHREAD_PROCESS_PRIVATE)) {
		free(iwucq);
		return NULL;
	}

	info.cq_size = get_cq_size(attr_ex->cqe, hw_rev);
	iwucq->comp_vector = attr_ex->comp_vector;
	list_head_init(&iwucq->resize_list);
	total_size = get_cq_total_bytes(info.cq_size);
	cq_pages = total_size >> IRDMA_HW_PAGE_SHIFT;

	if (!(uk_attrs->feature_flags & IRDMA_FEATURE_CQ_RESIZE))
		total_size = (cq_pages << IRDMA_HW_PAGE_SHIFT) + IRDMA_DB_SHADOW_AREA_SIZE;

	iwucq->buf_size = total_size;
	info.cq_base = irdma_alloc_hw_buf(total_size);
	if (!info.cq_base)
		goto err_cq_base;

	memset(info.cq_base, 0, total_size);
	reg_mr_cmd.reg_type = IRDMA_MEMREG_TYPE_CQ;
	reg_mr_cmd.cq_pages = cq_pages;

	ret = ibv_cmd_reg_mr(&iwvctx->iwupd->ibv_pd, info.cq_base,
			     total_size, (uintptr_t)info.cq_base,
			     IBV_ACCESS_LOCAL_WRITE, &iwucq->vmr,
			     &reg_mr_cmd.ibv_cmd, sizeof(reg_mr_cmd),
			     &reg_mr_resp, sizeof(reg_mr_resp));
	if (ret) {
		errno = ret;
		goto err_dereg_mr;
	}

	iwucq->vmr.ibv_mr.pd = &iwvctx->iwupd->ibv_pd;

	if (uk_attrs->feature_flags & IRDMA_FEATURE_CQ_RESIZE) {
		info.shadow_area = irdma_alloc_hw_buf(IRDMA_DB_SHADOW_AREA_SIZE);
		if (!info.shadow_area)
			goto err_dereg_mr;

		memset(info.shadow_area, 0, IRDMA_DB_SHADOW_AREA_SIZE);
		reg_mr_shadow_cmd.reg_type = IRDMA_MEMREG_TYPE_CQ;
		reg_mr_shadow_cmd.cq_pages = 1;

		ret = ibv_cmd_reg_mr(&iwvctx->iwupd->ibv_pd, info.shadow_area,
				     IRDMA_DB_SHADOW_AREA_SIZE, (uintptr_t)info.shadow_area,
				     IBV_ACCESS_LOCAL_WRITE, &iwucq->vmr_shadow_area,
				     &reg_mr_shadow_cmd.ibv_cmd, sizeof(reg_mr_shadow_cmd),
				     &reg_mr_shadow_resp, sizeof(reg_mr_shadow_resp));
		if (ret) {
			errno = ret;
			goto err_dereg_shadow;
		}

		iwucq->vmr_shadow_area.ibv_mr.pd = &iwvctx->iwupd->ibv_pd;

	} else {
		info.shadow_area = (__le64 *)((__u8 *)info.cq_base +
					      (cq_pages << IRDMA_HW_PAGE_SHIFT));
	}

	attr_ex->cqe = info.cq_size;
	cmd.user_cq_buf = (__u64)((uintptr_t)info.cq_base);
	cmd.user_shadow_area = (__u64)((uintptr_t)info.shadow_area);

	ret = ibv_cmd_create_cq_ex(context, attr_ex, &iwucq->verbs_cq,
				   &cmd.ibv_cmd, sizeof(cmd), &resp.ibv_resp,
				   sizeof(resp), 0);
	if (ret) {
		errno = ret;
		goto err_dereg_shadow;
	}

	if (ext_cq)
		irdma_ibvcq_ex_fill_priv_funcs(iwucq, attr_ex);
	info.cq_id = resp.cq_id;
	/* Do not report the cqe's burned by HW */
	iwucq->verbs_cq.cq.cqe = ncqe;

	info.cqe_alloc_db = (__u32 *)((__u8 *)iwvctx->db + IRDMA_DB_CQ_OFFSET);
	irdma_uk_cq_init(&iwucq->cq, &info);

	return &iwucq->verbs_cq.cq_ex;

err_dereg_shadow:
	ibv_cmd_dereg_mr(&iwucq->vmr);
	if (iwucq->vmr_shadow_area.ibv_mr.handle) {
		ibv_cmd_dereg_mr(&iwucq->vmr_shadow_area);
		irdma_free_hw_buf(info.shadow_area, IRDMA_HW_PAGE_SIZE);
	}
err_dereg_mr:
	irdma_free_hw_buf(info.cq_base, total_size);
err_cq_base:
	pthread_spin_destroy(&iwucq->lock);

	free(iwucq);

	return NULL;
}

struct ibv_cq *irdma_ucreate_cq(struct ibv_context *context, int cqe,
				struct ibv_comp_channel *channel,
				int comp_vector)
{
	struct ibv_cq_init_attr_ex attr_ex = {
		.cqe = cqe,
		.channel = channel,
		.comp_vector = comp_vector,
	};
	struct ibv_cq_ex *ibvcq_ex;

	ibvcq_ex = ucreate_cq(context, &attr_ex, false);

	return ibvcq_ex ? ibv_cq_ex_to_cq(ibvcq_ex) : NULL;
}

struct ibv_cq_ex *irdma_ucreate_cq_ex(struct ibv_context *context,
				      struct ibv_cq_init_attr_ex *attr_ex)
{
	if (attr_ex->wc_flags & ~IRDMA_CQ_SUPPORTED_WC_FLAGS) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return ucreate_cq(context, attr_ex, true);
}

/**
 * irdma_free_cq_buf - free memory for cq buffer
 * @cq_buf: cq buf to free
 */
static void irdma_free_cq_buf(struct irdma_cq_buf *cq_buf)
{
	ibv_cmd_dereg_mr(&cq_buf->vmr);
	irdma_free_hw_buf(cq_buf->cq.cq_base, get_cq_total_bytes(cq_buf->cq.cq_size));
	free(cq_buf);
}

/**
 * irdma_process_resize_list - process the cq list to remove buffers
 * @iwucq: cq which owns the list
 * @lcqe_buf: cq buf where the last cqe is found
 */
static int irdma_process_resize_list(struct irdma_ucq *iwucq,
				     struct irdma_cq_buf *lcqe_buf)
{
	struct irdma_cq_buf *cq_buf, *next;
	int cq_cnt = 0;

	list_for_each_safe(&iwucq->resize_list, cq_buf, next, list) {
		if (cq_buf == lcqe_buf)
			return cq_cnt;

		list_del(&cq_buf->list);
		irdma_free_cq_buf(cq_buf);
		cq_cnt++;
	}

	return cq_cnt;
}

/**
 * irdma_udestroy_cq - destroys cq
 * @cq: ptr to cq to be destroyed
 */
int irdma_udestroy_cq(struct ibv_cq *cq)
{
	struct irdma_uk_attrs *uk_attrs;
	struct irdma_uvcontext *iwvctx;
	struct irdma_ucq *iwucq;
	int ret;

	iwucq = container_of(cq, struct irdma_ucq, verbs_cq.cq);
	iwvctx = container_of(cq->context, struct irdma_uvcontext,
			      ibv_ctx.context);
	uk_attrs = &iwvctx->uk_attrs;

	ret = pthread_spin_destroy(&iwucq->lock);
	if (ret)
		goto err;

	irdma_process_resize_list(iwucq, NULL);
	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		goto err;

	ibv_cmd_dereg_mr(&iwucq->vmr);
	irdma_free_hw_buf(iwucq->cq.cq_base, iwucq->buf_size);

	if (uk_attrs->feature_flags & IRDMA_FEATURE_CQ_RESIZE) {
		ibv_cmd_dereg_mr(&iwucq->vmr_shadow_area);
		irdma_free_hw_buf(iwucq->cq.shadow_area, IRDMA_DB_SHADOW_AREA_SIZE);
	}
	free(iwucq);
	return 0;

err:
	return ret;
}

static enum ibv_wc_status irdma_flush_err_to_ib_wc_status(enum irdma_flush_opcode opcode)
{
	switch (opcode) {
	case FLUSH_PROT_ERR:
		return IBV_WC_LOC_PROT_ERR;
	case FLUSH_REM_ACCESS_ERR:
		return IBV_WC_REM_ACCESS_ERR;
	case FLUSH_LOC_QP_OP_ERR:
		return IBV_WC_LOC_QP_OP_ERR;
	case FLUSH_REM_OP_ERR:
		return IBV_WC_REM_OP_ERR;
	case FLUSH_LOC_LEN_ERR:
		return IBV_WC_LOC_LEN_ERR;
	case FLUSH_GENERAL_ERR:
		return IBV_WC_WR_FLUSH_ERR;
	case FLUSH_RETRY_EXC_ERR:
		return IBV_WC_RETRY_EXC_ERR;
	case FLUSH_MW_BIND_ERR:
		return IBV_WC_MW_BIND_ERR;
	case FLUSH_REM_INV_REQ_ERR:
		return IBV_WC_REM_INV_REQ_ERR;
	case FLUSH_FATAL_ERR:
	default:
		return IBV_WC_FATAL_ERR;
	}
}

static inline void set_ib_wc_op_sq(struct irdma_cq_poll_info *cur_cqe, struct ibv_wc *entry)
{
	switch (cur_cqe->op_type) {
	case IRDMA_OP_TYPE_RDMA_WRITE:
	case IRDMA_OP_TYPE_RDMA_WRITE_SOL:
		entry->opcode = IBV_WC_RDMA_WRITE;
		break;
	case IRDMA_OP_TYPE_RDMA_READ:
		entry->opcode = IBV_WC_RDMA_READ;
		break;
	case IRDMA_OP_TYPE_SEND_SOL:
	case IRDMA_OP_TYPE_SEND_SOL_INV:
	case IRDMA_OP_TYPE_SEND_INV:
	case IRDMA_OP_TYPE_SEND:
		entry->opcode = IBV_WC_SEND;
		break;
	case IRDMA_OP_TYPE_BIND_MW:
		entry->opcode = IBV_WC_BIND_MW;
		break;
	case IRDMA_OP_TYPE_INV_STAG:
		entry->opcode = IBV_WC_LOCAL_INV;
		break;
	default:
		entry->status = IBV_WC_GENERAL_ERR;
	}
}

static inline void set_ib_wc_op_rq(struct irdma_cq_poll_info *cur_cqe,
				   struct ibv_wc *entry, bool send_imm_support)
{
	/**
	 * iWARP does not support sendImm, so the presence of Imm data
	 * must be WriteImm.
	 */
	if (!send_imm_support) {
		entry->opcode = cur_cqe->imm_valid ? IBV_WC_RECV_RDMA_WITH_IMM :
				IBV_WC_RECV;
		return;
	}
	switch (cur_cqe->op_type) {
	case IBV_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE:
	case IBV_OPCODE_RDMA_WRITE_LAST_WITH_IMMEDIATE:
		entry->opcode = IBV_WC_RECV_RDMA_WITH_IMM;
		break;
	default:
		entry->opcode = IBV_WC_RECV;
	}
}

/**
 * irdma_process_cqe_ext - process current cqe for extended CQ
 * @cur_cqe - current cqe info
 */
static void irdma_process_cqe_ext(struct irdma_cq_poll_info *cur_cqe)
{
	struct irdma_ucq *iwucq = container_of(cur_cqe, struct irdma_ucq, cur_cqe);
	struct ibv_cq_ex *ibvcq_ex = &iwucq->verbs_cq.cq_ex;

	ibvcq_ex->wr_id = cur_cqe->wr_id;
	if (cur_cqe->error)
		ibvcq_ex->status = (cur_cqe->comp_status == IRDMA_COMPL_STATUS_FLUSHED) ?
				   irdma_flush_err_to_ib_wc_status(cur_cqe->minor_err) : IBV_WC_GENERAL_ERR;
	else
		ibvcq_ex->status = IBV_WC_SUCCESS;
}

/**
 * irdma_process_cqe - process current cqe info
 * @entry - ibv_wc object to fill in for non-extended CQ
 * @cur_cqe - current cqe info
 */
static void irdma_process_cqe(struct ibv_wc *entry, struct irdma_cq_poll_info *cur_cqe)
{
	struct irdma_qp_uk *qp;
	struct ibv_qp *ib_qp;

	entry->wc_flags = 0;
	entry->wr_id = cur_cqe->wr_id;
	entry->qp_num = cur_cqe->qp_id;
	qp = cur_cqe->qp_handle;
	ib_qp = qp->back_qp;

	if (cur_cqe->error) {
		entry->status = (cur_cqe->comp_status == IRDMA_COMPL_STATUS_FLUSHED) ?
				irdma_flush_err_to_ib_wc_status(cur_cqe->minor_err) : IBV_WC_GENERAL_ERR;
		entry->vendor_err = cur_cqe->major_err << 16 |
				    cur_cqe->minor_err;
	} else {
		entry->status = IBV_WC_SUCCESS;
	}

	if (cur_cqe->imm_valid) {
		entry->imm_data = htonl(cur_cqe->imm_data);
		entry->wc_flags |= IBV_WC_WITH_IMM;
	}

	if (cur_cqe->q_type == IRDMA_CQE_QTYPE_SQ) {
		set_ib_wc_op_sq(cur_cqe, entry);
	} else {
		set_ib_wc_op_rq(cur_cqe, entry,
				qp->qp_caps & IRDMA_SEND_WITH_IMM ?
				true : false);
		if (ib_qp->qp_type != IBV_QPT_UD &&
		    cur_cqe->stag_invalid_set) {
			entry->invalidated_rkey = cur_cqe->inv_stag;
			entry->wc_flags |= IBV_WC_WITH_INV;
		}
	}

	if (ib_qp->qp_type == IBV_QPT_UD) {
		entry->src_qp = cur_cqe->ud_src_qpn;
		entry->wc_flags |= IBV_WC_GRH;
	} else {
		entry->src_qp = cur_cqe->qp_id;
	}
	entry->byte_len = cur_cqe->bytes_xfered;
}

/**
 * irdma_poll_one - poll one entry of the CQ
 * @ukcq: ukcq to poll
 * @cur_cqe: current CQE info to be filled in
 * @entry: ibv_wc object to be filled for non-extended CQ or NULL for extended CQ
 *
 * Returns the internal irdma device error code or 0 on success
 */
static int irdma_poll_one(struct irdma_cq_uk *ukcq, struct irdma_cq_poll_info *cur_cqe,
			  struct ibv_wc *entry)
{
	int ret = irdma_uk_cq_poll_cmpl(ukcq, cur_cqe);

	if (ret)
		return ret;

	if (!entry)
		irdma_process_cqe_ext(cur_cqe);
	else
		irdma_process_cqe(entry, cur_cqe);

	return 0;
}

/**
 * __irdma_upoll_cq - irdma util function to poll device CQ
 * @iwucq: irdma cq to poll
 * @num_entries: max cq entries to poll
 * @entry: pointer to array of ibv_wc objects to be filled in for each completion or NULL if ext CQ
 *
 * Returns non-negative value equal to the number of completions
 * found. On failure, -EINVAL
 */
static int __irdma_upoll_cq(struct irdma_ucq *iwucq, int num_entries,
			    struct ibv_wc *entry)
{
	struct irdma_cq_buf *cq_buf, *next;
	struct irdma_cq_buf *last_buf = NULL;
	struct irdma_cq_poll_info *cur_cqe = &iwucq->cur_cqe;
	bool cq_new_cqe = false;
	int resized_bufs = 0;
	int npolled = 0;
	int ret;

	/* go through the list of previously resized CQ buffers */
	list_for_each_safe(&iwucq->resize_list, cq_buf, next, list) {
		while (npolled < num_entries) {
			ret = irdma_poll_one(&cq_buf->cq, cur_cqe,
					     entry ? entry + npolled : NULL);
			if (!ret) {
				++npolled;
				cq_new_cqe = true;
				continue;
			}
			if (ret == IRDMA_ERR_Q_EMPTY)
				break;
			 /* QP using the CQ is destroyed. Skip reporting this CQE */
			if (ret == IRDMA_ERR_Q_DESTROYED) {
				cq_new_cqe = true;
				continue;
			}
			goto error;
		}

		/* save the resized CQ buffer which received the last cqe */
		if (cq_new_cqe)
			last_buf = cq_buf;
		cq_new_cqe = false;
	}

	/* check the current CQ for new cqes */
	while (npolled < num_entries) {
		ret = irdma_poll_one(&iwucq->cq, cur_cqe,
				     entry ? entry + npolled : NULL);
		if (!ret) {
			++npolled;
			cq_new_cqe = true;
			continue;
		}
		if (ret == IRDMA_ERR_Q_EMPTY)
			break;
		/* QP using the CQ is destroyed. Skip reporting this CQE */
		if (ret == IRDMA_ERR_Q_DESTROYED) {
			cq_new_cqe = true;
			continue;
		}
		goto error;
	}

	if (cq_new_cqe)
		/* all previous CQ resizes are complete */
		resized_bufs = irdma_process_resize_list(iwucq, NULL);
	else if (last_buf)
		/* only CQ resizes up to the last_buf are complete */
		resized_bufs = irdma_process_resize_list(iwucq, last_buf);
	if (resized_bufs)
		/* report to the HW the number of complete CQ resizes */
		irdma_uk_cq_set_resized_cnt(&iwucq->cq, resized_bufs);

	return npolled;

error:

	return -EINVAL;
}

/**
 * irdma_upoll_cq - verb API callback to poll device CQ
 * @cq: ibv_cq to poll
 * @num_entries: max cq entries to poll
 * @entry: pointer to array of ibv_wc objects to be filled in for each completion
 *
 * Returns non-negative value equal to the number of completions
 * found and a negative error code on failure
 */
int irdma_upoll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *entry)
{
	struct irdma_ucq *iwucq;
	int ret;

	iwucq = container_of(cq, struct irdma_ucq, verbs_cq.cq);
	ret = pthread_spin_lock(&iwucq->lock);
	if (ret)
		return -ret;

	ret = __irdma_upoll_cq(iwucq, num_entries, entry);

	pthread_spin_unlock(&iwucq->lock);

	return ret;
}

/**
 * irdma_start_poll - verb_ex API callback to poll batch of WC's
 * @ibvcq_ex: ibv extended CQ
 * @attr: attributes (not used)
 *
 * Start polling batch of work completions. Return 0 on success, ENONENT when
 * no completions are available on CQ. And an error code on errors
 */
static int irdma_start_poll(struct ibv_cq_ex *ibvcq_ex, struct ibv_poll_cq_attr *attr)
{
	struct irdma_ucq *iwucq;
	int ret;

	iwucq = container_of(ibvcq_ex, struct irdma_ucq, verbs_cq.cq_ex);
	ret = pthread_spin_lock(&iwucq->lock);
	if (ret)
		return ret;

	ret = __irdma_upoll_cq(iwucq, 1, NULL);
	if (ret == 1)
		return 0;

	/* No Completions on CQ */
	if (!ret)
		ret = ENOENT;

	pthread_spin_unlock(&iwucq->lock);

	return ret;
}

/**
 * irdma_next_poll - verb_ex API callback to get next WC
 * @ibvcq_ex: ibv extended CQ
 *
 * Return 0 on success, ENONENT when no completions are available on CQ.
 * And an error code on errors
 */
static int irdma_next_poll(struct ibv_cq_ex *ibvcq_ex)
{
	struct irdma_ucq *iwucq;
	int ret;

	iwucq = container_of(ibvcq_ex, struct irdma_ucq, verbs_cq.cq_ex);
	ret = __irdma_upoll_cq(iwucq, 1, NULL);
	if (ret == 1)
		return 0;

	/* No Completions on CQ */
	if (!ret)
		ret = ENOENT;

	return ret;
}

/**
 * irdma_end_poll - verb_ex API callback to end polling of WC's
 * @ibvcq_ex: ibv extended CQ
 */
static void irdma_end_poll(struct ibv_cq_ex *ibvcq_ex)
{
	struct irdma_ucq *iwucq = container_of(ibvcq_ex, struct irdma_ucq,
					       verbs_cq.cq_ex);

	pthread_spin_unlock(&iwucq->lock);
}

/**
 * irdma_wc_read_completion_ts - Get completion timestamp
 * @ibvcq_ex: ibv extended CQ
 *
 * Get completion timestamp in HCA clock units
 */
static uint64_t irdma_wc_read_completion_ts(struct ibv_cq_ex *ibvcq_ex)
{
	struct irdma_ucq *iwucq = container_of(ibvcq_ex, struct irdma_ucq,
					       verbs_cq.cq_ex);
#define HCA_CORE_CLOCK_800_MHZ 800

	return iwucq->cur_cqe.tcp_seq_num_rtt / HCA_CORE_CLOCK_800_MHZ;
}

/**
 * irdma_wc_read_completion_wallclock_ns - Get completion timestamp in ns
 * @ibvcq_ex: ibv extended CQ
 *
 * Get completion timestamp from current completion in wall clock nanoseconds
 */
static uint64_t irdma_wc_read_completion_wallclock_ns(struct ibv_cq_ex *ibvcq_ex)
{
	struct irdma_ucq *iwucq = container_of(ibvcq_ex, struct irdma_ucq,
					       verbs_cq.cq_ex);

	/* RTT is in usec */
	return iwucq->cur_cqe.tcp_seq_num_rtt * 1000;
}

static enum ibv_wc_opcode irdma_wc_read_opcode(struct ibv_cq_ex *ibvcq_ex)
{
	struct irdma_ucq *iwucq = container_of(ibvcq_ex, struct irdma_ucq,
					       verbs_cq.cq_ex);

	switch (iwucq->cur_cqe.op_type) {
	case IRDMA_OP_TYPE_RDMA_WRITE:
	case IRDMA_OP_TYPE_RDMA_WRITE_SOL:
		return IBV_WC_RDMA_WRITE;
	case IRDMA_OP_TYPE_RDMA_READ:
		return IBV_WC_RDMA_READ;
	case IRDMA_OP_TYPE_SEND_SOL:
	case IRDMA_OP_TYPE_SEND_SOL_INV:
	case IRDMA_OP_TYPE_SEND_INV:
	case IRDMA_OP_TYPE_SEND:
		return IBV_WC_SEND;
	case IRDMA_OP_TYPE_BIND_MW:
		return IBV_WC_BIND_MW;
	case IRDMA_OP_TYPE_REC:
		return IBV_WC_RECV;
	case IRDMA_OP_TYPE_REC_IMM:
		return IBV_WC_RECV_RDMA_WITH_IMM;
	case IRDMA_OP_TYPE_INV_STAG:
		return IBV_WC_LOCAL_INV;
	}

	return 0;
}

static uint32_t irdma_wc_read_vendor_err(struct ibv_cq_ex *ibvcq_ex)
{
	struct irdma_cq_poll_info *cur_cqe;
	struct irdma_ucq *iwucq;

	iwucq = container_of(ibvcq_ex, struct irdma_ucq, verbs_cq.cq_ex);
	cur_cqe = &iwucq->cur_cqe;

	return cur_cqe->error ? cur_cqe->major_err << 16 | cur_cqe->minor_err : 0;
}

static unsigned int irdma_wc_read_wc_flags(struct ibv_cq_ex *ibvcq_ex)
{
	struct irdma_cq_poll_info *cur_cqe;
	struct irdma_ucq *iwucq;
	struct irdma_qp_uk *qp;
	struct ibv_qp *ib_qp;
	unsigned int wc_flags = 0;

	iwucq = container_of(ibvcq_ex, struct irdma_ucq, verbs_cq.cq_ex);
	cur_cqe = &iwucq->cur_cqe;
	qp = cur_cqe->qp_handle;
	ib_qp = qp->back_qp;

	if (cur_cqe->imm_valid)
		wc_flags |= IBV_WC_WITH_IMM;

	if (ib_qp->qp_type == IBV_QPT_UD) {
		wc_flags |= IBV_WC_GRH;
	} else {
		if (cur_cqe->stag_invalid_set) {
			switch (cur_cqe->op_type) {
			case IRDMA_OP_TYPE_REC:
				wc_flags |= IBV_WC_WITH_INV;
				break;
			case IRDMA_OP_TYPE_REC_IMM:
				wc_flags |= IBV_WC_WITH_INV;
				break;
			}
		}
	}

	return wc_flags;
}

static uint32_t irdma_wc_read_byte_len(struct ibv_cq_ex *ibvcq_ex)
{
	struct irdma_ucq *iwucq = container_of(ibvcq_ex, struct irdma_ucq,
					       verbs_cq.cq_ex);

	return iwucq->cur_cqe.bytes_xfered;
}

static __be32 irdma_wc_read_imm_data(struct ibv_cq_ex *ibvcq_ex)
{
	struct irdma_cq_poll_info *cur_cqe;
	struct irdma_ucq *iwucq;

	iwucq = container_of(ibvcq_ex, struct irdma_ucq, verbs_cq.cq_ex);
	cur_cqe = &iwucq->cur_cqe;

	return cur_cqe->imm_valid ? htonl(cur_cqe->imm_data) : 0;
}

static uint32_t irdma_wc_read_qp_num(struct ibv_cq_ex *ibvcq_ex)
{
	struct irdma_ucq *iwucq = container_of(ibvcq_ex, struct irdma_ucq,
					       verbs_cq.cq_ex);

	return iwucq->cur_cqe.qp_id;
}

static uint32_t irdma_wc_read_src_qp(struct ibv_cq_ex *ibvcq_ex)
{
	struct irdma_cq_poll_info *cur_cqe;
	struct irdma_ucq *iwucq;
	struct irdma_qp_uk *qp;
	struct ibv_qp *ib_qp;

	iwucq = container_of(ibvcq_ex, struct irdma_ucq, verbs_cq.cq_ex);
	cur_cqe = &iwucq->cur_cqe;
	qp = cur_cqe->qp_handle;
	ib_qp = qp->back_qp;

	return ib_qp->qp_type == IBV_QPT_UD ? cur_cqe->ud_src_qpn : cur_cqe->qp_id;
}

static uint32_t irdma_wc_read_slid(struct ibv_cq_ex *ibvcq_ex)
{
	return 0;
}

static uint8_t irdma_wc_read_sl(struct ibv_cq_ex *ibvcq_ex)
{
	return 0;
}

static uint8_t irdma_wc_read_dlid_path_bits(struct ibv_cq_ex *ibvcq_ex)
{
	return 0;
}

void irdma_ibvcq_ex_fill_priv_funcs(struct irdma_ucq *iwucq,
				    struct ibv_cq_init_attr_ex *attr_ex)
{
	struct ibv_cq_ex *ibvcq_ex = &iwucq->verbs_cq.cq_ex;

	ibvcq_ex->start_poll = irdma_start_poll;
	ibvcq_ex->end_poll = irdma_end_poll;
	ibvcq_ex->next_poll = irdma_next_poll;

	if (attr_ex->wc_flags & IBV_WC_EX_WITH_COMPLETION_TIMESTAMP) {
		ibvcq_ex->read_completion_ts = irdma_wc_read_completion_ts;
		iwucq->report_rtt = true;
	}
	if (attr_ex->wc_flags & IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK) {
		ibvcq_ex->read_completion_wallclock_ns = irdma_wc_read_completion_wallclock_ns;
		iwucq->report_rtt = true;
	}

	ibvcq_ex->read_opcode = irdma_wc_read_opcode;
	ibvcq_ex->read_vendor_err = irdma_wc_read_vendor_err;
	ibvcq_ex->read_wc_flags = irdma_wc_read_wc_flags;

	if (attr_ex->wc_flags & IBV_WC_EX_WITH_BYTE_LEN)
		ibvcq_ex->read_byte_len = irdma_wc_read_byte_len;
	if (attr_ex->wc_flags & IBV_WC_EX_WITH_IMM)
		ibvcq_ex->read_imm_data = irdma_wc_read_imm_data;
	if (attr_ex->wc_flags & IBV_WC_EX_WITH_QP_NUM)
		ibvcq_ex->read_qp_num = irdma_wc_read_qp_num;
	if (attr_ex->wc_flags & IBV_WC_EX_WITH_SRC_QP)
		ibvcq_ex->read_src_qp = irdma_wc_read_src_qp;
	if (attr_ex->wc_flags & IBV_WC_EX_WITH_SLID)
		ibvcq_ex->read_slid = irdma_wc_read_slid;
	if (attr_ex->wc_flags & IBV_WC_EX_WITH_SL)
		ibvcq_ex->read_sl = irdma_wc_read_sl;
	if (attr_ex->wc_flags & IBV_WC_EX_WITH_DLID_PATH_BITS)
		ibvcq_ex->read_dlid_path_bits = irdma_wc_read_dlid_path_bits;
}

/**
 * irdma_arm_cq - arm of cq
 * @iwucq: cq to which arm
 * @cq_notify: notification params
 */
static void irdma_arm_cq(struct irdma_ucq *iwucq,
			 enum irdma_cmpl_notify cq_notify)
{
	iwucq->is_armed = true;
	iwucq->arm_sol = true;
	iwucq->skip_arm = false;
	iwucq->skip_sol = true;
	irdma_uk_cq_request_notification(&iwucq->cq, cq_notify);
}

/**
 * irdma_uarm_cq - callback for arm of cq
 * @cq: cq to arm
 * @solicited: to get notify params
 */
int irdma_uarm_cq(struct ibv_cq *cq, int solicited)
{
	struct irdma_ucq *iwucq;
	enum irdma_cmpl_notify cq_notify = IRDMA_CQ_COMPL_EVENT;
	int ret;

	iwucq = container_of(cq, struct irdma_ucq, verbs_cq.cq);
	if (solicited)
		cq_notify = IRDMA_CQ_COMPL_SOLICITED;

	ret = pthread_spin_lock(&iwucq->lock);
	if (ret)
		return ret;

	if (iwucq->is_armed) {
		if (iwucq->arm_sol && !solicited) {
			irdma_arm_cq(iwucq, cq_notify);
		} else {
			iwucq->skip_arm = true;
			iwucq->skip_sol = solicited ? true : false;
		}
	} else {
		irdma_arm_cq(iwucq, cq_notify);
	}

	pthread_spin_unlock(&iwucq->lock);

	return 0;
}

/**
 * irdma_cq_event - cq to do completion event
 * @cq: cq to arm
 */
void irdma_cq_event(struct ibv_cq *cq)
{
	struct irdma_ucq *iwucq;

	iwucq = container_of(cq, struct irdma_ucq, verbs_cq.cq);
	if (pthread_spin_lock(&iwucq->lock))
		return;

	if (iwucq->skip_arm)
		irdma_arm_cq(iwucq, IRDMA_CQ_COMPL_EVENT);
	else
		iwucq->is_armed = false;

	pthread_spin_unlock(&iwucq->lock);
}

void *irdma_mmap(int fd, off_t offset)
{
	void *map;

	map = mmap(NULL, IRDMA_HW_PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED,
		   fd, offset);
	if (map == MAP_FAILED)
		return map;

	if (ibv_dontfork_range(map, IRDMA_HW_PAGE_SIZE)) {
		munmap(map, IRDMA_HW_PAGE_SIZE);
		return MAP_FAILED;
	}

	return map;
}

void irdma_munmap(void *map)
{
	ibv_dofork_range(map, IRDMA_HW_PAGE_SIZE);
	munmap(map, IRDMA_HW_PAGE_SIZE);
}

/**
 * irdma_destroy_vmapped_qp - destroy resources for qp
 * @iwuqp: qp struct for resources
 */
static int irdma_destroy_vmapped_qp(struct irdma_uqp *iwuqp)
{
	int ret;

	ret = ibv_cmd_destroy_qp(&iwuqp->ibv_qp);
	if (ret)
		return ret;

	if (iwuqp->qp.push_db)
		irdma_munmap(iwuqp->qp.push_db);
	if (iwuqp->qp.push_wqe)
		irdma_munmap(iwuqp->qp.push_wqe);

	ibv_cmd_dereg_mr(&iwuqp->vmr);

	return 0;
}

/**
 * irdma_vmapped_qp - create resources for qp
 * @iwuqp: qp struct for resources
 * @pd: pd for the qp
 * @attr: attributes of qp passed
 * @resp: response back from create qp
 * @sqdepth: depth of sq
 * @rqdepth: depth of rq
 * @info: info for initializing user level qp
 * @abi_ver: abi version of the create qp command
 */
static int irdma_vmapped_qp(struct irdma_uqp *iwuqp, struct ibv_pd *pd,
			    struct ibv_qp_init_attr *attr, int sqdepth,
			    int rqdepth, struct irdma_qp_uk_init_info *info,
			    bool legacy_mode)
{
	struct irdma_ucreate_qp cmd = {};
	size_t sqsize, rqsize, totalqpsize;
	struct irdma_ucreate_qp_resp resp = {};
	struct irdma_ureg_mr reg_mr_cmd = {};
	struct ib_uverbs_reg_mr_resp reg_mr_resp = {};
	int ret;

	sqsize = roundup(sqdepth * IRDMA_QP_WQE_MIN_SIZE, IRDMA_HW_PAGE_SIZE);
	rqsize = roundup(rqdepth * IRDMA_QP_WQE_MIN_SIZE, IRDMA_HW_PAGE_SIZE);
	totalqpsize = rqsize + sqsize + IRDMA_DB_SHADOW_AREA_SIZE;
	info->sq = irdma_alloc_hw_buf(totalqpsize);
	iwuqp->buf_size = totalqpsize;

	if (!info->sq)
		return ENOMEM;

	memset(info->sq, 0, totalqpsize);
	info->rq = &info->sq[sqsize / IRDMA_QP_WQE_MIN_SIZE];
	info->shadow_area = info->rq[rqsize / IRDMA_QP_WQE_MIN_SIZE].elem;

	reg_mr_cmd.reg_type = IRDMA_MEMREG_TYPE_QP;
	reg_mr_cmd.sq_pages = sqsize >> IRDMA_HW_PAGE_SHIFT;
	reg_mr_cmd.rq_pages = rqsize >> IRDMA_HW_PAGE_SHIFT;

	ret = ibv_cmd_reg_mr(pd, info->sq, totalqpsize,
			     (uintptr_t)info->sq, IBV_ACCESS_LOCAL_WRITE,
			     &iwuqp->vmr, &reg_mr_cmd.ibv_cmd,
			     sizeof(reg_mr_cmd), &reg_mr_resp,
			     sizeof(reg_mr_resp));
	if (ret)
		goto err_dereg_mr;

	cmd.user_wqe_bufs = (__u64)((uintptr_t)info->sq);
	cmd.user_compl_ctx = (__u64)(uintptr_t)&iwuqp->qp;
	ret = ibv_cmd_create_qp(pd, &iwuqp->ibv_qp, attr, &cmd.ibv_cmd,
				sizeof(cmd), &resp.ibv_resp,
				sizeof(struct irdma_ucreate_qp_resp));
	if (ret)
		goto err_qp;

	info->sq_size = resp.actual_sq_size;
	info->rq_size = resp.actual_rq_size;
	info->first_sq_wq = legacy_mode ? 1 : resp.lsmm;
	info->qp_caps = resp.qp_caps;
	info->qp_id = resp.qp_id;
	iwuqp->irdma_drv_opt = resp.irdma_drv_opt;
	iwuqp->ibv_qp.qp_num = resp.qp_id;

	iwuqp->send_cq = container_of(attr->send_cq, struct irdma_ucq,
				      verbs_cq.cq);
	iwuqp->recv_cq = container_of(attr->recv_cq, struct irdma_ucq,
				      verbs_cq.cq);
	iwuqp->send_cq->uqp = iwuqp;
	iwuqp->recv_cq->uqp = iwuqp;

	return 0;
err_qp:
	ibv_cmd_dereg_mr(&iwuqp->vmr);
err_dereg_mr:
	irdma_free_hw_buf(info->sq, iwuqp->buf_size);
	return ret;
}

/**
 * irdma_ucreate_qp - create qp on user app
 * @pd: pd for the qp
 * @attr: attributes of the qp to be created (sizes, sge, cq)
 */
struct ibv_qp *irdma_ucreate_qp(struct ibv_pd *pd,
				struct ibv_qp_init_attr *attr)
{
	struct irdma_qp_uk_init_info info = {};
	struct irdma_uk_attrs *uk_attrs;
	struct irdma_uvcontext *iwvctx;
	struct irdma_uqp *iwuqp;
	__u32 sqdepth, rqdepth;
	__u8 sqshift, rqshift;
	int status;

	if (attr->qp_type != IBV_QPT_RC && attr->qp_type != IBV_QPT_UD) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	iwvctx = container_of(pd->context, struct irdma_uvcontext,
			      ibv_ctx.context);
	uk_attrs = &iwvctx->uk_attrs;

	if (attr->cap.max_send_sge > uk_attrs->max_hw_wq_frags ||
	    attr->cap.max_recv_sge > uk_attrs->max_hw_wq_frags ||
	    attr->cap.max_inline_data > uk_attrs->max_hw_inline) {
		errno = EINVAL;
		return NULL;
	}

	irdma_get_wqe_shift(uk_attrs,
			    uk_attrs->hw_rev > IRDMA_GEN_1 ? attr->cap.max_send_sge + 1 :
				attr->cap.max_send_sge,
			    attr->cap.max_inline_data, &sqshift);
	status = irdma_get_sqdepth(uk_attrs, attr->cap.max_send_wr, sqshift,
				   &sqdepth);
	if (status) {
		errno = EINVAL;
		return NULL;
	}

	if (uk_attrs->hw_rev == IRDMA_GEN_1 && iwvctx->abi_ver > 4)
		rqshift = IRDMA_MAX_RQ_WQE_SHIFT_GEN1;
	else
		irdma_get_wqe_shift(uk_attrs, attr->cap.max_recv_sge, 0,
				    &rqshift);

	status = irdma_get_rqdepth(uk_attrs, attr->cap.max_recv_wr, rqshift,
				   &rqdepth);
	if (status) {
		errno = EINVAL;
		return NULL;
	}

	iwuqp = memalign(1024, sizeof(*iwuqp));
	if (!iwuqp)
		return NULL;

	memset(iwuqp, 0, sizeof(*iwuqp));

	if (pthread_spin_init(&iwuqp->lock, PTHREAD_PROCESS_PRIVATE))
		goto err_free_qp;

	info.sq_size = sqdepth >> sqshift;
	info.rq_size = rqdepth >> rqshift;
	attr->cap.max_send_wr = info.sq_size;
	attr->cap.max_recv_wr = info.rq_size;

	info.uk_attrs = uk_attrs;
	info.max_sq_frag_cnt = attr->cap.max_send_sge;
	info.max_rq_frag_cnt = attr->cap.max_recv_sge;
	iwuqp->recv_sges = calloc(attr->cap.max_recv_sge, sizeof(*iwuqp->recv_sges));
	if (!iwuqp->recv_sges)
		goto err_destroy_lock;

	info.wqe_alloc_db = (__u32 *)iwvctx->db;
	info.abi_ver = iwvctx->abi_ver;
	info.legacy_mode = iwvctx->legacy_mode;
	info.sq_wrtrk_array = calloc(sqdepth, sizeof(*info.sq_wrtrk_array));
	if (!info.sq_wrtrk_array)
		goto err_free_rsges;

	info.rq_wrid_array = calloc(rqdepth, sizeof(*info.rq_wrid_array));
	if (!info.rq_wrid_array)
		goto err_free_sq_wrtrk;

	iwuqp->sq_sig_all = attr->sq_sig_all;
	iwuqp->qp_type = attr->qp_type;
	status = irdma_vmapped_qp(iwuqp, pd, attr, sqdepth, rqdepth, &info, iwvctx->legacy_mode);
	if (status) {
		errno = status;
		goto err_free_rq_wrid;
	}

	iwuqp->qp.back_qp = iwuqp;
	iwuqp->qp.lock = &iwuqp->lock;

	info.max_sq_frag_cnt = attr->cap.max_send_sge;
	info.max_rq_frag_cnt = attr->cap.max_recv_sge;
	info.max_inline_data = attr->cap.max_inline_data;
	status = irdma_uk_qp_init(&iwuqp->qp, &info);
	if (status) {
		errno = EINVAL;
		goto err_free_vmap_qp;
	}

	attr->cap.max_send_wr = (sqdepth - IRDMA_SQ_RSVD) >> sqshift;
	attr->cap.max_recv_wr = (rqdepth - IRDMA_RQ_RSVD) >> rqshift;
	return &iwuqp->ibv_qp;

err_free_vmap_qp:
	irdma_destroy_vmapped_qp(iwuqp);
	irdma_free_hw_buf(info.sq, iwuqp->buf_size);
err_free_rq_wrid:
	free(info.rq_wrid_array);
err_free_sq_wrtrk:
	free(info.sq_wrtrk_array);
err_free_rsges:
	free(iwuqp->recv_sges);
err_destroy_lock:
	pthread_spin_destroy(&iwuqp->lock);
err_free_qp:
	free(iwuqp);

	return NULL;
}

/**
 * irdma_uquery_qp - query qp for some attribute
 * @qp: qp for the attributes query
 * @attr: to return the attributes
 * @attr_mask: mask of what is query for
 * @init_attr: initial attributes during create_qp
 */
int irdma_uquery_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		    struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr, &cmd,
				sizeof(cmd));
}

/**
 * irdma_umodify_qp - send qp modify to driver
 * @qp: qp to modify
 * @attr: attribute to modify
 * @attr_mask: mask of the attribute
 */
int irdma_umodify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask)
{
	struct irdma_umodify_qp_resp resp = {};
	struct ibv_modify_qp cmd = {};
	struct irdma_umodify_qp cmd_ex = {};
	struct irdma_uvcontext *iwctx;
	struct irdma_uqp *iwuqp;

	iwuqp = container_of(qp, struct irdma_uqp, ibv_qp);
	iwctx = container_of(qp->context, struct irdma_uvcontext,
			     ibv_ctx.context);

	if (iwuqp->qp.qp_caps & IRDMA_PUSH_MODE &&
	    attr_mask & IBV_QP_STATE && iwctx->uk_attrs.hw_rev > IRDMA_GEN_1) {
		__u64 offset;
		void *map;
		int ret;

		ret = ibv_cmd_modify_qp_ex(qp, attr, attr_mask, &cmd_ex.ibv_cmd,
					   sizeof(cmd_ex), &resp.ibv_resp, sizeof(resp));
		if (ret || !resp.push_valid)
			return ret;

		if (iwuqp->qp.push_wqe)
			return ret;

		offset = resp.push_wqe_mmap_key;
		map = irdma_mmap(qp->context->cmd_fd, offset);
		if (map == MAP_FAILED)
			return ret;

		iwuqp->qp.push_wqe = map;

		offset = resp.push_db_mmap_key;
		map = irdma_mmap(qp->context->cmd_fd, offset);
		if (map == MAP_FAILED) {
			irdma_munmap(iwuqp->qp.push_wqe);
			iwuqp->qp.push_wqe = NULL;
			return ret;
		}
		iwuqp->qp.push_wqe += resp.push_offset;
		iwuqp->qp.push_db = map + resp.push_offset;

		return ret;
	} else {
		return ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof(cmd));
	}
}

static void irdma_issue_flush(struct ibv_qp *qp, bool sq_flush, bool rq_flush)
{
	struct ib_uverbs_ex_modify_qp_resp resp = {};
	struct irdma_umodify_qp cmd_ex = {};
	struct ibv_qp_attr attr = {};

	attr.qp_state = IBV_QPS_ERR;
	cmd_ex.sq_flush = sq_flush;
	cmd_ex.rq_flush = rq_flush;

	ibv_cmd_modify_qp_ex(qp, &attr, IBV_QP_STATE,
			     &cmd_ex.ibv_cmd, sizeof(cmd_ex),
			     &resp, sizeof(resp));
}

/**
 * irdma_clean_cqes - clean cq entries for qp
 * @qp: qp for which completions are cleaned
 * @iwcq: cq to be cleaned
 */
static void irdma_clean_cqes(struct irdma_qp_uk *qp, struct irdma_ucq *iwucq)
{
	struct irdma_cq_uk *ukcq = &iwucq->cq;
	int ret;

	ret = pthread_spin_lock(&iwucq->lock);
	if (ret)
		return;

	irdma_uk_clean_cq(qp, ukcq);
	pthread_spin_unlock(&iwucq->lock);
}

/**
 * irdma_udestroy_qp - destroy qp
 * @qp: qp to destroy
 */
int irdma_udestroy_qp(struct ibv_qp *qp)
{
	struct irdma_uqp *iwuqp;
	int ret;

	iwuqp = container_of(qp, struct irdma_uqp, ibv_qp);
	ret = pthread_spin_destroy(&iwuqp->lock);
	if (ret)
		goto err;

	ret = irdma_destroy_vmapped_qp(iwuqp);
	if (ret)
		goto err;

	/* Clean any pending completions from the cq(s) */
	if (iwuqp->send_cq)
		irdma_clean_cqes(&iwuqp->qp, iwuqp->send_cq);

	if (iwuqp->recv_cq && iwuqp->recv_cq != iwuqp->send_cq)
		irdma_clean_cqes(&iwuqp->qp, iwuqp->recv_cq);

	if (iwuqp->qp.sq_wrtrk_array)
		free(iwuqp->qp.sq_wrtrk_array);
	if (iwuqp->qp.rq_wrid_array)
		free(iwuqp->qp.rq_wrid_array);

	irdma_free_hw_buf(iwuqp->qp.sq_base, iwuqp->buf_size);
	free(iwuqp->recv_sges);
	free(iwuqp);
	return 0;

err:
	return ret;
}

/**
 * irdma_copy_sg_list - copy sg list for qp
 * @sg_list: copied into sg_list
 * @sgl: copy from sgl
 * @num_sges: count of sg entries
 * @max_sges: count of max supported sg entries
 */
static void irdma_copy_sg_list(struct irdma_sge *sg_list, struct ibv_sge *sgl,
			       int num_sges)
{
	int i;

	for (i = 0; i < num_sges; i++) {
		sg_list[i].tag_off = sgl[i].addr;
		sg_list[i].len = sgl[i].length;
		sg_list[i].stag = sgl[i].lkey;
	}
}

/**
 * irdma_post_send -  post send wr for user application
 * @ib_qp: qp to post wr
 * @ib_wr: work request ptr
 * @bad_wr: return of bad wr if err
 */
int irdma_upost_send(struct ibv_qp *ib_qp, struct ibv_send_wr *ib_wr,
		     struct ibv_send_wr **bad_wr)
{
	struct irdma_post_sq_info info;
	struct irdma_uvcontext *iwvctx;
	struct irdma_uk_attrs *uk_attrs;
	enum irdma_status_code ret = 0;
	struct irdma_uqp *iwuqp;
	bool reflush = false;
	int err = 0;

	iwuqp = container_of(ib_qp, struct irdma_uqp, ibv_qp);
	iwvctx = container_of(ib_qp->context, struct irdma_uvcontext,
			      ibv_ctx.context);
	uk_attrs = &iwvctx->uk_attrs;

	err = pthread_spin_lock(&iwuqp->lock);
	if (err)
		return err;

	if (!IRDMA_RING_MORE_WORK(iwuqp->qp.sq_ring) &&
	    ib_qp->state == IBV_QPS_ERR)
		reflush = true;

	while (ib_wr) {
		memset(&info, 0, sizeof(info));
		info.wr_id = (__u64)(ib_wr->wr_id);
		if ((ib_wr->send_flags & IBV_SEND_SIGNALED) ||
		    iwuqp->sq_sig_all)
			info.signaled = true;
		if (ib_wr->send_flags & IBV_SEND_FENCE)
			info.read_fence = true;
		if (iwuqp->send_cq->report_rtt)
			info.report_rtt = true;

		switch (ib_wr->opcode) {
		case IBV_WR_SEND_WITH_IMM:
			if (iwuqp->qp.qp_caps & IRDMA_SEND_WITH_IMM) {
				info.imm_data_valid = true;
				info.imm_data = ntohl(ib_wr->imm_data);
			} else {
				err = EINVAL;
				break;
			}
			SWITCH_FALLTHROUGH;
		case IBV_WR_SEND:
		case IBV_WR_SEND_WITH_INV:
			if (ib_wr->opcode == IBV_WR_SEND ||
			    ib_wr->opcode == IBV_WR_SEND_WITH_IMM) {
				if (ib_wr->send_flags & IBV_SEND_SOLICITED)
					info.op_type = IRDMA_OP_TYPE_SEND_SOL;
				else
					info.op_type = IRDMA_OP_TYPE_SEND;
			} else {
				if (ib_wr->send_flags & IBV_SEND_SOLICITED)
					info.op_type = IRDMA_OP_TYPE_SEND_SOL_INV;
				else
					info.op_type = IRDMA_OP_TYPE_SEND_INV;
				info.stag_to_inv = ib_wr->invalidate_rkey;
			}
			info.op.send.num_sges = ib_wr->num_sge;
			info.op.send.sg_list = (struct irdma_sge *)ib_wr->sg_list;
			if (ib_qp->qp_type == IBV_QPT_UD) {
				struct irdma_uah *ah  = container_of(ib_wr->wr.ud.ah,
								     struct irdma_uah, ibv_ah);

				info.op.send.ah_id = ah->ah_id;
				info.op.send.qkey = ib_wr->wr.ud.remote_qkey;
				info.op.send.dest_qp = ib_wr->wr.ud.remote_qpn;
			}

			if (ib_wr->send_flags & IBV_SEND_INLINE)
				ret = irdma_uk_inline_send(&iwuqp->qp, &info, false);
			else
				ret = irdma_uk_send(&iwuqp->qp, &info, false);
			if (ret)
				err = (ret == IRDMA_ERR_QP_TOOMANY_WRS_POSTED) ? ENOMEM : EINVAL;
			break;
		case IBV_WR_RDMA_WRITE_WITH_IMM:
			if (iwuqp->qp.qp_caps & IRDMA_WRITE_WITH_IMM) {
				info.imm_data_valid = true;
				info.imm_data = ntohl(ib_wr->imm_data);
			} else {
				err = EINVAL;
				break;
			}
			SWITCH_FALLTHROUGH;
		case IBV_WR_RDMA_WRITE:
			if (ib_wr->send_flags & IBV_SEND_SOLICITED)
				info.op_type = IRDMA_OP_TYPE_RDMA_WRITE_SOL;
			else
				info.op_type = IRDMA_OP_TYPE_RDMA_WRITE;

			info.op.rdma_write.num_lo_sges = ib_wr->num_sge;
			info.op.rdma_write.lo_sg_list = (void *)ib_wr->sg_list;
			info.op.rdma_write.rem_addr.tag_off = ib_wr->wr.rdma.remote_addr;
			info.op.rdma_write.rem_addr.stag = ib_wr->wr.rdma.rkey;
			if (ib_wr->send_flags & IBV_SEND_INLINE)
				ret = irdma_uk_inline_rdma_write(&iwuqp->qp, &info, false);
			else
				ret = irdma_uk_rdma_write(&iwuqp->qp, &info, false);
			if (ret)
				err = (ret == IRDMA_ERR_QP_TOOMANY_WRS_POSTED) ? ENOMEM : EINVAL;
			break;
		case IBV_WR_RDMA_READ:
			if (ib_wr->num_sge > uk_attrs->max_hw_read_sges) {
				err = EINVAL;
				break;
			}
			info.op_type = IRDMA_OP_TYPE_RDMA_READ;
			info.op.rdma_read.rem_addr.tag_off = ib_wr->wr.rdma.remote_addr;
			info.op.rdma_read.rem_addr.stag = ib_wr->wr.rdma.rkey;

			info.op.rdma_read.lo_sg_list = (void *)ib_wr->sg_list;
			info.op.rdma_read.num_lo_sges = ib_wr->num_sge;
			ret = irdma_uk_rdma_read(&iwuqp->qp, &info, false, false);
			if (ret)
				err = (ret == IRDMA_ERR_QP_TOOMANY_WRS_POSTED) ? ENOMEM : EINVAL;
			break;
		case IBV_WR_BIND_MW:
			if (ib_qp->qp_type != IBV_QPT_RC) {
				err = EINVAL;
				break;
			}
			info.op_type = IRDMA_OP_TYPE_BIND_MW;
			info.op.bind_window.mr_stag = ib_wr->bind_mw.bind_info.mr->rkey;
			info.op.bind_window.mem_window_type_1 = true;
			info.op.bind_window.mw_stag = ib_wr->bind_mw.rkey;

			if (ib_wr->bind_mw.bind_info.mw_access_flags & IBV_ACCESS_ZERO_BASED) {
				info.op.bind_window.addressing_type = IRDMA_ADDR_TYPE_ZERO_BASED;
				info.op.bind_window.va =  NULL;
			} else {
				info.op.bind_window.addressing_type = IRDMA_ADDR_TYPE_VA_BASED;
				info.op.bind_window.va =
						(void *)(uintptr_t)ib_wr->bind_mw.bind_info.addr;
			}
			info.op.bind_window.bind_len = ib_wr->bind_mw.bind_info.length;
			info.op.bind_window.ena_reads =
				(ib_wr->bind_mw.bind_info.mw_access_flags & IBV_ACCESS_REMOTE_READ) ? 1 : 0;
			info.op.bind_window.ena_writes =
				(ib_wr->bind_mw.bind_info.mw_access_flags & IBV_ACCESS_REMOTE_WRITE) ? 1 : 0;

			ret = irdma_uk_mw_bind(&iwuqp->qp, &info, false);
			if (ret)
				err = (ret == IRDMA_ERR_QP_TOOMANY_WRS_POSTED) ? ENOMEM : EINVAL;
			break;
		case IBV_WR_LOCAL_INV:
			info.op_type = IRDMA_OP_TYPE_INV_STAG;
			info.op.inv_local_stag.target_stag = ib_wr->invalidate_rkey;
			ret = irdma_uk_stag_local_invalidate(&iwuqp->qp, &info, true);
			if (ret)
				err = (ret == IRDMA_ERR_QP_TOOMANY_WRS_POSTED) ? ENOMEM : EINVAL;
			break;
		default:
			/* error */
			err = EINVAL;
			break;
		}
		if (err)
			break;

		ib_wr = ib_wr->next;
	}

	if (err)
		*bad_wr = ib_wr;

	irdma_uk_qp_post_wr(&iwuqp->qp);
	if (reflush)
		irdma_issue_flush(ib_qp, 1, 0);

	pthread_spin_unlock(&iwuqp->lock);

	return err;
}

/**
 * irdma_post_recv - post receive wr for user application
 * @ib_wr: work request for receive
 * @bad_wr: bad wr caused an error
 */
int irdma_upost_recv(struct ibv_qp *ib_qp, struct ibv_recv_wr *ib_wr,
		     struct ibv_recv_wr **bad_wr)
{
	struct irdma_post_rq_info post_recv = {};
	enum irdma_status_code ret = 0;
	struct irdma_sge *sg_list;
	struct irdma_uqp *iwuqp;
	bool reflush = false;
	int err = 0;

	iwuqp = container_of(ib_qp, struct irdma_uqp, ibv_qp);
	sg_list = iwuqp->recv_sges;

	err = pthread_spin_lock(&iwuqp->lock);
	if (err)
		return err;

	if (!IRDMA_RING_MORE_WORK(iwuqp->qp.rq_ring) &&
	    ib_qp->state == IBV_QPS_ERR)
		reflush = true;

	while (ib_wr) {
		if (ib_wr->num_sge > iwuqp->qp.max_rq_frag_cnt) {
			*bad_wr = ib_wr;
			err = EINVAL;
			goto error;
		}
		post_recv.num_sges = ib_wr->num_sge;
		post_recv.wr_id = ib_wr->wr_id;
		irdma_copy_sg_list(sg_list, ib_wr->sg_list, ib_wr->num_sge);
		post_recv.sg_list = sg_list;
		ret = irdma_uk_post_receive(&iwuqp->qp, &post_recv);
		if (ret) {
			err = (ret == IRDMA_ERR_QP_TOOMANY_WRS_POSTED) ? ENOMEM : EINVAL;
			*bad_wr = ib_wr;
			goto error;
		}

		if (reflush)
			irdma_issue_flush(ib_qp, 0, 1);

		ib_wr = ib_wr->next;
	}
error:
	pthread_spin_unlock(&iwuqp->lock);

	return err;
}

/**
 * irdma_ucreate_ah - create address handle associated with a pd
 * @ibpd: pd for the address handle
 * @attr: attributes of address handle
 */
struct ibv_ah *irdma_ucreate_ah(struct ibv_pd *ibpd, struct ibv_ah_attr *attr)
{
	struct irdma_uah *ah;
	union ibv_gid sgid;
	struct irdma_ucreate_ah_resp resp;
	int err;

	err = ibv_query_gid(ibpd->context, attr->port_num, attr->grh.sgid_index,
			    &sgid);
	if (err) {
		errno = err;
		return NULL;
	}

	ah = calloc(1, sizeof(*ah));
	if (!ah)
		return NULL;

	err = ibv_cmd_create_ah(ibpd, &ah->ibv_ah, attr, &resp.ibv_resp,
				sizeof(resp));
	if (err) {
		free(ah);
		errno = err;
		return NULL;
	}

	ah->ah_id = resp.ah_id;

	return &ah->ibv_ah;
}

/**
 * irdma_udestroy_ah - destroy the address handle
 * @ibah: address handle
 */
int irdma_udestroy_ah(struct ibv_ah *ibah)
{
	struct irdma_uah *ah;
	int ret;

	ah = container_of(ibah, struct irdma_uah, ibv_ah);

	ret = ibv_cmd_destroy_ah(ibah);
	if (ret)
		return ret;

	free(ah);

	return 0;
}

/**
 * irdma_uattach_mcast - Attach qp to multicast group implemented
 * @qp: The queue pair
 * @gid:The Global ID for multicast group
 * @lid: The Local ID
 */
int irdma_uattach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
			uint16_t lid)
{
	return ibv_cmd_attach_mcast(qp, gid, lid);
}

/**
 * irdma_udetach_mcast - Detach qp from multicast group
 * @qp: The queue pair
 * @gid:The Global ID for multicast group
 * @lid: The Local ID
 */
int irdma_udetach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
			uint16_t lid)
{
	return ibv_cmd_detach_mcast(qp, gid, lid);
}

/**
 * irdma_uresize_cq - resizes a cq
 * @cq: cq to resize
 * @cqe: the number of cqes of the new cq
 */
int irdma_uresize_cq(struct ibv_cq *cq, int cqe)
{
	struct irdma_uvcontext *iwvctx;
	struct irdma_uk_attrs *uk_attrs;
	struct irdma_uresize_cq cmd = {};
	struct ib_uverbs_resize_cq_resp resp = {};
	struct irdma_ureg_mr reg_mr_cmd = {};
	struct ib_uverbs_reg_mr_resp reg_mr_resp = {};
	struct irdma_cq_buf *cq_buf = NULL;
	struct irdma_cqe *cq_base = NULL;
	struct verbs_mr new_mr = {};
	struct irdma_ucq *iwucq;
	size_t cq_size;
	__u32 cq_pages;
	int cqe_needed;
	int ret = 0;

	iwucq = container_of(cq, struct irdma_ucq, verbs_cq.cq);
	iwvctx = container_of(cq->context, struct irdma_uvcontext,
			      ibv_ctx.context);
	uk_attrs = &iwvctx->uk_attrs;

	if (!(uk_attrs->feature_flags & IRDMA_FEATURE_CQ_RESIZE))
		return EOPNOTSUPP;

	if (cqe > IRDMA_MAX_CQ_SIZE)
		return EINVAL;

	cqe_needed = cqe + 1;
	if (uk_attrs->hw_rev > IRDMA_GEN_1)
		cqe_needed *= 2;

	if (cqe_needed < IRDMA_U_MINCQ_SIZE)
		cqe_needed = IRDMA_U_MINCQ_SIZE;

	if (cqe_needed == iwucq->cq.cq_size)
		return 0;

	cq_size = get_cq_total_bytes(cqe_needed);
	cq_pages = cq_size >> IRDMA_HW_PAGE_SHIFT;
	cq_base = irdma_alloc_hw_buf(cq_size);
	if (!cq_base)
		return ENOMEM;

	memset(cq_base, 0, cq_size);

	cq_buf = malloc(sizeof(*cq_buf));
	if (!cq_buf) {
		ret = ENOMEM;
		goto err_buf;
	}

	new_mr.ibv_mr.pd = iwucq->vmr.ibv_mr.pd;
	reg_mr_cmd.reg_type = IRDMA_MEMREG_TYPE_CQ;
	reg_mr_cmd.cq_pages = cq_pages;

	ret = ibv_cmd_reg_mr(new_mr.ibv_mr.pd, cq_base, cq_size,
			     (uintptr_t)cq_base, IBV_ACCESS_LOCAL_WRITE,
			     &new_mr, &reg_mr_cmd.ibv_cmd, sizeof(reg_mr_cmd),
			     &reg_mr_resp, sizeof(reg_mr_resp));
	if (ret)
		goto err_dereg_mr;

	ret = pthread_spin_lock(&iwucq->lock);
	if (ret)
		goto err_lock;

	cmd.user_cq_buffer = (__u64)((uintptr_t)cq_base);
	ret = ibv_cmd_resize_cq(&iwucq->verbs_cq.cq, cqe_needed, &cmd.ibv_cmd,
				sizeof(cmd), &resp, sizeof(resp));
	if (ret)
		goto err_resize;

	memcpy(&cq_buf->cq, &iwucq->cq, sizeof(cq_buf->cq));
	cq_buf->vmr = iwucq->vmr;
	iwucq->vmr = new_mr;
	irdma_uk_cq_resize(&iwucq->cq, cq_base, cqe_needed);
	iwucq->verbs_cq.cq.cqe = cqe;
	list_add_tail(&iwucq->resize_list, &cq_buf->list);

	pthread_spin_unlock(&iwucq->lock);

	return ret;

err_resize:
	pthread_spin_unlock(&iwucq->lock);
err_lock:
	ibv_cmd_dereg_mr(&new_mr);
err_dereg_mr:
	free(cq_buf);
err_buf:
	irdma_free_hw_buf(cq_base, cq_size);
	return ret;
}
