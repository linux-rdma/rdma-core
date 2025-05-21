// SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
/*
 * Copyright (c) 2024 ZTE Corporation.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
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
#include <infiniband/driver.h>
#include <ccan/container_of.h>

#include "zxdh_zrdma.h"
#include "zxdh_abi.h"
#include "zxdh_verbs.h"

uint32_t zxdh_debug_mask;

static const unsigned int zxdh_roce_mtu[] = {
	[IBV_MTU_256] = 256,   [IBV_MTU_512] = 512,   [IBV_MTU_1024] = 1024,
	[IBV_MTU_2048] = 2048, [IBV_MTU_4096] = 4096,
};

static inline unsigned int mtu_enum_to_int(enum ibv_mtu mtu)
{
	return zxdh_roce_mtu[mtu];
}

/**
 * zxdh_get_inline_data - get inline_multi_sge data
 * @inline_data: uint8_t*
 * @ib_wr: work request ptr
 * @len: sge total length
 */
static int zxdh_get_inline_data(uint8_t *inline_data, struct ibv_send_wr *ib_wr,
				__u32 *len)
{
	int num = 0;
	int offset = 0;

	while (num < ib_wr->num_sge) {
		*len += ib_wr->sg_list[num].length;
		if (*len > ZXDH_MAX_INLINE_DATA_SIZE) {
			printf("err:inline bytes over max inline length\n");
			return -EINVAL;
		}
		memcpy(inline_data + offset,
		       (void *)(uintptr_t)ib_wr->sg_list[num].addr,
		       ib_wr->sg_list[num].length);
		offset += ib_wr->sg_list[num].length;
		num++;
	}
	return 0;
}

/**
 * zxdh_uquery_device_ex - query device attributes including extended properties
 * @context: user context for the device
 * @input: extensible input struct for ibv_query_device_ex verb
 * @attr: extended device attribute struct
 * @attr_size: size of extended device attribute struct
 **/
int zxdh_uquery_device_ex(struct ibv_context *context,
			  const struct ibv_query_device_ex_input *input,
			  struct ibv_device_attr_ex *attr, size_t attr_size)
{
	return 0;
}

/**
 * zxdh_uquery_port - get port attributes (msg size, lnk, mtu...)
 * @context: user context of the device
 * @port: port for the attributes
 * @attr: to return port attributes
 **/
int zxdh_uquery_port(struct ibv_context *context, uint8_t port,
		     struct ibv_port_attr *attr)
{
	return 0;
}

/**
 * zxdh_ualloc_pd - allocates protection domain and return pd ptr
 * @context: user context of the device
 **/
struct ibv_pd *zxdh_ualloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct zxdh_ualloc_pd_resp resp = {};
	struct zxdh_upd *iwupd;
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
 * zxdh_ufree_pd - free pd resources
 * @pd: pd to free resources
 */
int zxdh_ufree_pd(struct ibv_pd *pd)
{
	struct zxdh_upd *iwupd;
	int ret;

	iwupd = container_of(pd, struct zxdh_upd, ibv_pd);
	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	free(iwupd);

	return 0;
}

/**
 * zxdh_ureg_mr - register user memory region
 * @pd: pd for the mr
 * @addr: user address of the memory region
 * @length: length of the memory
 * @hca_va: hca_va
 * @access: access allowed on this mr
 */
struct ibv_mr *zxdh_ureg_mr(struct ibv_pd *pd, void *addr, size_t length,
			    uint64_t hca_va, int access)
{
	struct zxdh_umr *umr;
	struct zxdh_ureg_mr cmd;
	struct zxdh_ureg_mr_resp resp = {};
	int err;

	umr = malloc(sizeof(*umr));
	if (!umr)
		return NULL;

	cmd.reg_type = ZXDH_MEMREG_TYPE_MEM;
	err = ibv_cmd_reg_mr(pd, addr, length, hca_va, access, &umr->vmr,
			     &cmd.ibv_cmd, sizeof(cmd), &resp.ibv_resp,
			     sizeof(resp));
	if (err) {
		free(umr);
		errno = err;
		return NULL;
	}
	umr->acc_flags = access;
	umr->host_page_size = resp.host_page_size;
	umr->leaf_pbl_size = resp.leaf_pbl_size;
	umr->mr_pa_pble_index = resp.mr_pa_hig;
	umr->mr_pa_pble_index = (umr->mr_pa_pble_index << 32) | resp.mr_pa_low;

	return &umr->vmr.ibv_mr;
}

/*
 * zxdh_urereg_mr - re-register memory region
 * @vmr: mr that was allocated
 * @flags: bit mask to indicate which of the attr's of MR modified
 * @pd: pd of the mr
 * @addr: user address of the memory region
 * @length: length of the memory
 * @access: access allowed on this mr
 */
int zxdh_urereg_mr(struct verbs_mr *vmr, int flags, struct ibv_pd *pd,
		   void *addr, size_t length, int access)
{
	struct zxdh_urereg_mr cmd = {};
	struct ib_uverbs_rereg_mr_resp resp;

	cmd.reg_type = ZXDH_MEMREG_TYPE_MEM;
	return ibv_cmd_rereg_mr(vmr, flags, addr, length, (uintptr_t)addr,
				access, pd, &cmd.ibv_cmd, sizeof(cmd), &resp,
				sizeof(resp));
}

/**
 * zxdh_udereg_mr - re-register memory region
 * @vmr: mr that was allocated
 */
int zxdh_udereg_mr(struct verbs_mr *vmr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

	free(vmr);

	return 0;
}

/**
 * zxdh_ualloc_mw - allocate memory window
 * @pd: protection domain
 * @type: memory window type
 */
struct ibv_mw *zxdh_ualloc_mw(struct ibv_pd *pd, enum ibv_mw_type type)
{
	struct ibv_mw *mw;
	struct ibv_alloc_mw cmd;
	struct ib_uverbs_alloc_mw_resp resp;

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
 * zxdh_ubind_mw - bind a memory window
 * @qp: qp to post WR
 * @mw: memory window to bind
 * @mw_bind: bind info
 */
int zxdh_ubind_mw(struct ibv_qp *qp, struct ibv_mw *mw,
		  struct ibv_mw_bind *mw_bind)
{
	struct ibv_mw_bind_info *bind_info = &mw_bind->bind_info;
	struct verbs_mr *vmr = verbs_get_mr(bind_info->mr);
	struct zxdh_umr *umr = container_of(vmr, struct zxdh_umr, vmr);
	struct ibv_send_wr wr = {};
	struct ibv_send_wr *bad_wr;
	int err;

	if (vmr->mr_type != IBV_MR_TYPE_MR)
		return -ENOTSUP;

	if (umr->acc_flags & IBV_ACCESS_ZERO_BASED)
		return -EINVAL;

	if (mw->type != IBV_MW_TYPE_1)
		return -EINVAL;

	wr.opcode = IBV_WR_BIND_MW;
	wr.bind_mw.bind_info = mw_bind->bind_info;
	wr.bind_mw.mw = mw;
	wr.bind_mw.rkey = ibv_inc_rkey(mw->rkey);

	wr.wr_id = mw_bind->wr_id;
	wr.send_flags = mw_bind->send_flags;

	err = zxdh_upost_send(qp, &wr, &bad_wr);
	if (!err)
		mw->rkey = wr.bind_mw.rkey;

	return err;
}

/**
 * zxdh_udealloc_mw - deallocate memory window
 * @mw: memory window to dealloc
 */
int zxdh_udealloc_mw(struct ibv_mw *mw)
{
	int ret;

	ret = ibv_cmd_dealloc_mw(mw);
	if (ret)
		return ret;
	free(mw);

	return 0;
}

static void *zxdh_alloc_hw_buf(size_t size)
{
	void *buf;

	buf = memalign(ZXDH_HW_PAGE_SIZE, size);

	if (!buf)
		return NULL;
	if (ibv_dontfork_range(buf, size)) {
		free(buf);
		return NULL;
	}

	return buf;
}

static void zxdh_free_hw_buf(void *buf, size_t size)
{
	ibv_dofork_range(buf, size);
	free(buf);
}

/**
 * get_cq_size - returns actual cqe needed by HW
 * @ncqe: minimum cqes requested by application
 */
static inline int get_cq_size(int ncqe)
{
	if (ncqe < ZXDH_U_MINCQ_SIZE)
		ncqe = ZXDH_U_MINCQ_SIZE;
	return ncqe;
}

static inline size_t get_cq_total_bytes(__u32 cq_size)
{
	return roundup(cq_size * sizeof(struct zxdh_cqe), ZXDH_HW_PAGE_SIZE);
}

/**
 * ucreate_cq - zxdh util function to create a CQ
 * @context: ibv context
 * @attr_ex: CQ init attributes
 * @ext_cq: flag to create an extendable or normal CQ
 */
static struct ibv_cq_ex *ucreate_cq(struct ibv_context *context,
				    struct ibv_cq_init_attr_ex *attr_ex,
				    bool ext_cq)
{
	struct zxdh_cq_init_info info = {};
	struct zxdh_ureg_mr reg_mr_cmd = {};
	struct zxdh_ucreate_cq_ex cmd = {};
	struct zxdh_ucreate_cq_ex_resp resp = {};
	struct ib_uverbs_reg_mr_resp reg_mr_resp = {};
	struct zxdh_ureg_mr reg_mr_shadow_cmd = {};
	struct ib_uverbs_reg_mr_resp reg_mr_shadow_resp = {};
	struct zxdh_dev_attrs *dev_attrs;
	struct zxdh_uvcontext *iwvctx;
	struct zxdh_ucq *iwucq;
	size_t total_size;
	__u32 cq_pages;
	int ret, ncqe;
	__u64 resize_supported;

	iwvctx = container_of(context, struct zxdh_uvcontext, ibv_ctx.context);
	dev_attrs = &iwvctx->dev_attrs;

	if (attr_ex->cqe < ZXDH_MIN_CQ_SIZE ||
	    attr_ex->cqe > dev_attrs->max_hw_cq_size) {
		errno = EINVAL;
		return NULL;
	}

	info.cq_size = get_cq_size(attr_ex->cqe);
	info.cq_size = zxdh_cq_round_up(info.cq_size);
	if (info.cq_size > dev_attrs->max_hw_cq_size) {
		errno = EINVAL;
		return NULL;
	}

	/* save the cqe requested by application */
	ncqe = attr_ex->cqe;
	iwucq = calloc(1, sizeof(*iwucq));
	if (!iwucq)
		return NULL;

	ret = pthread_spin_init(&iwucq->lock, PTHREAD_PROCESS_PRIVATE);
	if (ret) {
		errno = ret;
		free(iwucq);
		return NULL;
	}

	iwucq->resize_enable = false;
	iwucq->comp_vector = attr_ex->comp_vector;
	list_head_init(&iwucq->resize_list);
	total_size = get_cq_total_bytes(info.cq_size);
	cq_pages = total_size >> ZXDH_HW_PAGE_SHIFT;
	resize_supported = dev_attrs->feature_flags & ZXDH_FEATURE_CQ_RESIZE;

	if (!resize_supported)
		total_size = (cq_pages << ZXDH_HW_PAGE_SHIFT) +
			     ZXDH_DB_SHADOW_AREA_SIZE;

	iwucq->buf_size = total_size;
	info.cq_base = zxdh_alloc_hw_buf(total_size);
	if (!info.cq_base)
		goto err_cq_base;

	memset(info.cq_base, 0, total_size);
	reg_mr_cmd.reg_type = ZXDH_MEMREG_TYPE_CQ;
	reg_mr_cmd.cq_pages = cq_pages;

	ret = ibv_cmd_reg_mr(&iwvctx->iwupd->ibv_pd, info.cq_base, total_size,
			     (uintptr_t)info.cq_base, IBV_ACCESS_LOCAL_WRITE,
			     &iwucq->vmr, &reg_mr_cmd.ibv_cmd,
			     sizeof(reg_mr_cmd), &reg_mr_resp,
			     sizeof(reg_mr_resp));
	if (ret) {
		errno = ret;
		goto err_dereg_mr;
	}

	iwucq->vmr.ibv_mr.pd = &iwvctx->iwupd->ibv_pd;

	if (resize_supported) {
		info.shadow_area = zxdh_alloc_hw_buf(ZXDH_DB_SHADOW_AREA_SIZE);
		if (!info.shadow_area)
			goto err_dereg_mr;

		memset(info.shadow_area, 0, ZXDH_DB_SHADOW_AREA_SIZE);
		reg_mr_shadow_cmd.reg_type = ZXDH_MEMREG_TYPE_CQ;
		reg_mr_shadow_cmd.cq_pages = 1;

		ret = ibv_cmd_reg_mr(
			&iwvctx->iwupd->ibv_pd, info.shadow_area,
			ZXDH_DB_SHADOW_AREA_SIZE, (uintptr_t)info.shadow_area,
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
					      (cq_pages << ZXDH_HW_PAGE_SHIFT));
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
		zxdh_ibvcq_ex_fill_priv_funcs(iwucq, attr_ex);
	info.cq_id = resp.cq_id;
	/* Do not report the cqe's burned by HW */
	iwucq->verbs_cq.cq.cqe = ncqe;

	info.cqe_alloc_db =
		(__u32 *)((__u8 *)iwvctx->cq_db + ZXDH_DB_CQ_OFFSET);
	zxdh_cq_init(&iwucq->cq, &info);

	return &iwucq->verbs_cq.cq_ex;

err_dereg_shadow:
	ibv_cmd_dereg_mr(&iwucq->vmr);
	if (iwucq->vmr_shadow_area.ibv_mr.handle) {
		ibv_cmd_dereg_mr(&iwucq->vmr_shadow_area);
		if (resize_supported)
			zxdh_free_hw_buf(info.shadow_area,
					 ZXDH_DB_SHADOW_AREA_SIZE);
	}
err_dereg_mr:
	zxdh_free_hw_buf(info.cq_base, total_size);
err_cq_base:
	pthread_spin_destroy(&iwucq->lock);

	free(iwucq);

	return NULL;
}

struct ibv_cq *zxdh_ucreate_cq(struct ibv_context *context, int cqe,
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

struct ibv_cq_ex *zxdh_ucreate_cq_ex(struct ibv_context *context,
				     struct ibv_cq_init_attr_ex *attr_ex)
{
	if (attr_ex->wc_flags & ~ZXDH_CQ_SUPPORTED_WC_FLAGS) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	return ucreate_cq(context, attr_ex, true);
}

/**
 * zxdh_free_cq_buf - free memory for cq buffer
 * @cq_buf: cq buf to free
 */
static void zxdh_free_cq_buf(struct zxdh_cq_buf *cq_buf)
{
	ibv_cmd_dereg_mr(&cq_buf->vmr);
	zxdh_free_hw_buf(cq_buf->cq.cq_base,
			 get_cq_total_bytes(cq_buf->cq.cq_size));
	free(cq_buf);
}

/**
 * zxdh_process_resize_list - process the cq list to remove buffers
 * @iwucq: cq which owns the list
 * @lcqe_buf: cq buf where the last cqe is found
 */
static int zxdh_process_resize_list(struct zxdh_ucq *iwucq,
				    struct zxdh_cq_buf *lcqe_buf)
{
	struct zxdh_cq_buf *cq_buf, *next;
	int cq_cnt = 0;

	list_for_each_safe(&iwucq->resize_list, cq_buf, next, list) {
		if (cq_buf == lcqe_buf)
			return cq_cnt;

		list_del(&cq_buf->list);
		zxdh_free_cq_buf(cq_buf);
		cq_cnt++;
	}

	return cq_cnt;
}

/**
 * zxdh_udestroy_cq - destroys cq
 * @cq: ptr to cq to be destroyed
 */
int zxdh_udestroy_cq(struct ibv_cq *cq)
{
	struct zxdh_dev_attrs *dev_attrs;
	struct zxdh_uvcontext *iwvctx;
	struct zxdh_ucq *iwucq;
	__u64 cq_shadow_temp;
	int ret;

	iwucq = container_of(cq, struct zxdh_ucq, verbs_cq.cq);
	iwvctx = container_of(cq->context, struct zxdh_uvcontext,
			      ibv_ctx.context);
	dev_attrs = &iwvctx->dev_attrs;

	ret = pthread_spin_destroy(&iwucq->lock);
	if (ret)
		goto err;

	get_64bit_val(iwucq->cq.shadow_area, 0, &cq_shadow_temp);

	zxdh_process_resize_list(iwucq, NULL);
	ret = ibv_cmd_destroy_cq(cq);
	if (ret)
		goto err;

	ibv_cmd_dereg_mr(&iwucq->vmr);
	zxdh_free_hw_buf(iwucq->cq.cq_base, iwucq->buf_size);

	if (dev_attrs->feature_flags & ZXDH_FEATURE_CQ_RESIZE) {
		ibv_cmd_dereg_mr(&iwucq->vmr_shadow_area);
		zxdh_free_hw_buf(iwucq->cq.shadow_area,
				 ZXDH_DB_SHADOW_AREA_SIZE);
	}
	free(iwucq);
	return 0;

err:
	return ret;
}

int zxdh_umodify_cq(struct ibv_cq *cq, struct ibv_modify_cq_attr *attr)
{
	struct ibv_modify_cq cmd = {};

	return ibv_cmd_modify_cq(cq, attr, &cmd, sizeof(cmd));
}

static enum ibv_wc_status
zxdh_err_to_ib_wc_status(__u32 opcode)
{
	switch (opcode) {
	case ZXDH_RX_WQE_LEN_ERR:
		return IBV_WC_LOC_LEN_ERR;
	case ZXDH_TX_ACK_SYS_TOP_VADDR_LEN_CHECK_ERR:
	case ZXDH_TX_ACK_SYS_TOP_LKEY_CHECK_ERR:
	case ZXDH_TX_ACK_SYS_TOP_ACCESS_RIGHT_CHECK_ERR:
	case ZXDH_RX_MR_MW_STATE_FREE_ERR:
	case ZXDH_RX_MR_MW_STATE_INVALID_ERR:
	case ZXDH_RX_MR_MW_PD_CHECK_ERR:
	case ZXDH_RX_MR_MW_KEY_CHECK_ERR:
	case ZXDH_RX_MR_MW_STAG_INDEX_CHECK_ERR:
	case ZXDH_RX_MR_MW_BOUNDARY_CHECK_ERR:
	case ZXDH_RX_MR_MW_0STAG_INDEX_CHECK_ERR:
	case ZXDH_RX_MW_STATE_INVALID_ERR:
	case ZXDH_RX_MW_PD_CHECK_ERR:
	case ZXDH_RX_MW_STAG_INDEX_CHECK_ERR:
	case ZXDH_RX_MW_SHARE_MR_CHECK_ERR:
	case ZXDH_RX_MR_PD_CHECK_ERR:
	case ZXDH_RX_MR_SHARE_MR_CHECK_ERR:
	case ZXDH_RX_MR_MW_ACCESS_CHECK_ERR:
		return IBV_WC_LOC_PROT_ERR;
	case ZXDH_TX_PARSE_TOP_WQE_FLUSH:
		return IBV_WC_WR_FLUSH_ERR;
	case ZXDH_TX_ACK_SYS_TOP_NAK_INVALID_REQ:
		return IBV_WC_REM_INV_REQ_ERR;
	case ZXDH_TX_ACK_SYS_TOP_NAK_REMOTE_ACCESS_ERR:
	case ZXDH_RX_MW_RKEY_CHECK_ERR:
	case ZXDH_RX_MR_RKEY_CHECK_ERR:
		return IBV_WC_REM_ACCESS_ERR;
	case ZXDH_TX_ACK_SYS_TOP_NAK_REMOTE_OPERATIONAL_ERR:
		return IBV_WC_REM_OP_ERR;
	case ZXDH_TX_ACK_SYS_TOP_NAK_RETRY_LIMIT:
	case ZXDH_TX_ACK_SYS_TOP_READ_RETRY_LIMIT:
	case ZXDH_TX_ACK_SYS_TOP_TIMEOUT_RETRY_LIMIT:
		return IBV_WC_RETRY_EXC_ERR;
	case ZXDH_TX_ACK_SYS_TOP_RNR_RETRY_LIMIT:
		return IBV_WC_RNR_RETRY_EXC_ERR;
	case ZXDH_TX_PARSE_TOP_AXI_ERR:
	case ZXDH_RX_AXI_RESP_ERR:
		return IBV_WC_FATAL_ERR;
	default:
		return IBV_WC_GENERAL_ERR;
	}
}

/**
 * zxdh_process_cqe_ext - process current cqe for extended CQ
 * @cur_cqe - current cqe info
 */
static inline void zxdh_process_cqe_ext(struct zxdh_cq_poll_info *cur_cqe)
{
	struct zxdh_ucq *iwucq =
		container_of(cur_cqe, struct zxdh_ucq, cur_cqe);
	struct ibv_cq_ex *ibvcq_ex = &iwucq->verbs_cq.cq_ex;

	ibvcq_ex->wr_id = cur_cqe->wr_id;
	if (cur_cqe->error)
		ibvcq_ex->status =
			zxdh_err_to_ib_wc_status(cur_cqe->major_err << 16 |
					cur_cqe->minor_err);
	else
		ibvcq_ex->status = IBV_WC_SUCCESS;
}

/**
 * zxdh_process_cqe - process current cqe info
 * @entry - ibv_wc object to fill in for non-extended CQ
 * @cur_cqe - current cqe info
 */
static inline void zxdh_process_cqe(struct ibv_wc *entry,
				    struct zxdh_cq_poll_info *cur_cqe)
{
	struct zxdh_qp *qp;
	struct ibv_qp *ib_qp;

	entry->wc_flags = 0;
	entry->wr_id = cur_cqe->wr_id;
	entry->qp_num = cur_cqe->qp_id;
	qp = cur_cqe->qp_handle;
	ib_qp = qp->back_qp;

	if (cur_cqe->error) {
		entry->status =
			zxdh_err_to_ib_wc_status(cur_cqe->major_err << 16 |
					cur_cqe->minor_err);
		entry->vendor_err =
			cur_cqe->major_err << 16 | cur_cqe->minor_err;
	} else {
		entry->status = IBV_WC_SUCCESS;
	}

	if (cur_cqe->imm_valid) {
		entry->imm_data = htonl(cur_cqe->imm_data);
		entry->wc_flags |= IBV_WC_WITH_IMM;
	}

	switch (cur_cqe->op_type) {
	case ZXDH_OP_TYPE_SEND:
	case ZXDH_OP_TYPE_SEND_WITH_IMM:
	case ZXDH_OP_TYPE_SEND_INV:
	case ZXDH_OP_TYPE_UD_SEND:
	case ZXDH_OP_TYPE_UD_SEND_WITH_IMM:
		entry->opcode = IBV_WC_SEND;
		break;
	case ZXDH_OP_TYPE_WRITE:
	case ZXDH_OP_TYPE_WRITE_WITH_IMM:
		entry->opcode = IBV_WC_RDMA_WRITE;
		break;
	case ZXDH_OP_TYPE_READ:
		entry->opcode = IBV_WC_RDMA_READ;
		break;
	case ZXDH_OP_TYPE_BIND_MW:
		entry->opcode = IBV_WC_BIND_MW;
		break;
	case ZXDH_OP_TYPE_LOCAL_INV:
		entry->opcode = IBV_WC_LOCAL_INV;
		break;
	case ZXDH_OP_TYPE_REC:
		entry->opcode = IBV_WC_RECV;
		if (ib_qp->qp_type != IBV_QPT_UD && cur_cqe->stag_invalid_set) {
			entry->invalidated_rkey = cur_cqe->inv_stag;
			entry->wc_flags |= IBV_WC_WITH_INV;
		}
		break;
	case ZXDH_OP_TYPE_REC_IMM:
		entry->opcode = IBV_WC_RECV_RDMA_WITH_IMM;
		if (ib_qp->qp_type != IBV_QPT_UD && cur_cqe->stag_invalid_set) {
			entry->invalidated_rkey = cur_cqe->inv_stag;
			entry->wc_flags |= IBV_WC_WITH_INV;
		}
		break;
	default:
		entry->status = IBV_WC_GENERAL_ERR;
		return;
	}

	if (ib_qp->qp_type == IBV_QPT_UD) {
		entry->src_qp = cur_cqe->ud_src_qpn;
		entry->wc_flags |= IBV_WC_GRH;
		entry->sl = cur_cqe->ipv4 ? 2 : 1;
	} else {
		entry->src_qp = cur_cqe->qp_id;
	}
	entry->byte_len = cur_cqe->bytes_xfered;
}

/**
 * zxdh_poll_one - poll one entry of the CQ
 * @cq: cq to poll
 * @cur_cqe: current CQE info to be filled in
 * @entry: ibv_wc object to be filled for non-extended CQ or NULL for extended CQ
 *
 * Returns the internal zxdh device error code or 0 on success
 */
static int zxdh_poll_one(struct zxdh_cq *cq,
			 struct zxdh_cq_poll_info *cur_cqe,
			 struct ibv_wc *entry)
{
	int ret = zxdh_cq_poll_cmpl(cq, cur_cqe);

	if (ret)
		return ret;

	if (entry)
		zxdh_process_cqe(entry, cur_cqe);
	else
		zxdh_process_cqe_ext(cur_cqe);

	return 0;
}

/**
 * __zxdh_upoll_resize_cq - zxdh util function to poll device CQ
 * @iwucq: zxdh cq to poll
 * @num_entries: max cq entries to poll
 * @entry: pointer to array of ibv_wc objects to be filled in for each completion or NULL if ext CQ
 *
 * Returns non-negative value equal to the number of completions
 * found. On failure, -EINVAL
 */
static int __zxdh_upoll_resize_cq(struct zxdh_ucq *iwucq, int num_entries,
				  struct ibv_wc *entry)
{
	struct zxdh_cq_buf *cq_buf, *next;
	struct zxdh_cq_buf *last_buf = NULL;
	struct zxdh_cq_poll_info *cur_cqe = &iwucq->cur_cqe;
	bool cq_new_cqe = false;
	int resized_bufs = 0;
	int npolled = 0;
	int ret;

	/* go through the list of previously resized CQ buffers */
	list_for_each_safe(&iwucq->resize_list, cq_buf, next, list) {
		while (npolled < num_entries) {
			ret = zxdh_poll_one(&cq_buf->cq, cur_cqe,
					    entry ? entry + npolled : NULL);
			if (ret == ZXDH_SUCCESS) {
				++npolled;
				cq_new_cqe = true;
				continue;
			}
			if (ret == ZXDH_ERR_Q_EMPTY)
				break;
			if (ret == ZXDH_ERR_RETRY_ACK_NOT_EXCEED_ERR)
				break;
			/* QP using the CQ is destroyed. Skip reporting this CQE */
			if (ret == ZXDH_ERR_Q_DESTROYED) {
				cq_new_cqe = true;
				continue;
			}
			printf("__zrdma_upoll_cq resize goto error failed\n");
			goto error;
		}

		/* save the resized CQ buffer which received the last cqe */
		if (cq_new_cqe)
			last_buf = cq_buf;
		cq_new_cqe = false;
	}

	/* check the current CQ for new cqes */
	while (npolled < num_entries) {
		ret = zxdh_poll_one(&iwucq->cq, cur_cqe,
				    entry ? entry + npolled : NULL);
		if (ret == ZXDH_SUCCESS) {
			++npolled;
			cq_new_cqe = true;
			continue;
		}
		if (ret == ZXDH_ERR_Q_EMPTY)
			break;
		if (ret == ZXDH_ERR_RETRY_ACK_NOT_EXCEED_ERR)
			break;
		/* QP using the CQ is destroyed. Skip reporting this CQE */
		if (ret == ZXDH_ERR_Q_DESTROYED) {
			cq_new_cqe = true;
			continue;
		}
		printf("__zrdma_upoll_cq goto error failed\n");
		goto error;
	}
	if (cq_new_cqe)
		/* all previous CQ resizes are complete */
		resized_bufs = zxdh_process_resize_list(iwucq, NULL);
	else if (last_buf)
		/* only CQ resizes up to the last_buf are complete */
		resized_bufs = zxdh_process_resize_list(iwucq, last_buf);
	if (resized_bufs)
		/* report to the HW the number of complete CQ resizes */
		zxdh_cq_set_resized_cnt(&iwucq->cq, resized_bufs);

	return npolled;

error:

	return -EINVAL;
}

/**
 * __zxdh_upoll_current_cq - zxdh util function to poll device CQ
 * @iwucq: zxdh cq to poll
 * @num_entries: max cq entries to poll
 * @entry: pointer to array of ibv_wc objects to be filled in for each completion or NULL if ext CQ
 *
 * Returns non-negative value equal to the number of completions
 * found. On failure, -EINVAL
 */
static int __zxdh_upoll_curent_cq(struct zxdh_ucq *iwucq, int num_entries,
				  struct ibv_wc *entry)
{
	struct zxdh_cq_poll_info *cur_cqe = &iwucq->cur_cqe;
	int npolled = 0;
	int ret;

	/* check the current CQ for new cqes */
	while (npolled < num_entries) {
		ret = zxdh_poll_one(&iwucq->cq, cur_cqe,
				    entry ? entry + npolled : NULL);
		if (unlikely(ret != ZXDH_SUCCESS))
			break;
		++npolled;
	}
	return npolled;
}

/**
 * zxdh_upoll_cq - verb API callback to poll device CQ
 * @cq: ibv_cq to poll
 * @num_entries: max cq entries to poll
 * @entry: pointer to array of ibv_wc objects to be filled in for each completion
 *
 * Returns non-negative value equal to the number of completions
 * found and a negative error code on failure
 */
int zxdh_upoll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *entry)
{
	struct zxdh_ucq *iwucq;
	int ret;

	iwucq = container_of(cq, struct zxdh_ucq, verbs_cq.cq);
	ret = pthread_spin_lock(&iwucq->lock);
	if (ret)
		return -ret;

	if (likely(!iwucq->resize_enable))
		ret = __zxdh_upoll_curent_cq(iwucq, num_entries, entry);
	else
		ret = __zxdh_upoll_resize_cq(iwucq, num_entries, entry);

	pthread_spin_unlock(&iwucq->lock);

	return ret;
}

/**
 * zxdh_start_poll - verb_ex API callback to poll batch of WC's
 * @ibvcq_ex: ibv extended CQ
 * @attr: attributes (not used)
 *
 * Start polling batch of work completions. Return 0 on success, ENONENT when
 * no completions are available on CQ. And an error code on errors
 */
static int zxdh_start_poll(struct ibv_cq_ex *ibvcq_ex,
			   struct ibv_poll_cq_attr *attr)
{
	struct zxdh_ucq *iwucq;
	int ret;

	iwucq = container_of(ibvcq_ex, struct zxdh_ucq, verbs_cq.cq_ex);
	ret = pthread_spin_lock(&iwucq->lock);
	if (ret)
		return ret;

	if (!iwucq->resize_enable) {
		ret = __zxdh_upoll_curent_cq(iwucq, 1, NULL);
		if (ret == 1)
			return 0;
	} else {
		ret = __zxdh_upoll_resize_cq(iwucq, 1, NULL);
		if (ret == 1)
			return 0;
	}

	/* No Completions on CQ */
	if (!ret)
		ret = ENOENT;

	pthread_spin_unlock(&iwucq->lock);

	return ret;
}

/**
 * zxdh_next_poll - verb_ex API callback to get next WC
 * @ibvcq_ex: ibv extended CQ
 *
 * Return 0 on success, ENONENT when no completions are available on CQ.
 * And an error code on errors
 */
static int zxdh_next_poll(struct ibv_cq_ex *ibvcq_ex)
{
	struct zxdh_ucq *iwucq;
	int ret;

	iwucq = container_of(ibvcq_ex, struct zxdh_ucq, verbs_cq.cq_ex);
	if (!iwucq->resize_enable) {
		ret = __zxdh_upoll_curent_cq(iwucq, 1, NULL);
		if (ret == 1)
			return 0;
	} else {
		ret = __zxdh_upoll_resize_cq(iwucq, 1, NULL);
		if (ret == 1)
			return 0;
	}

	/* No Completions on CQ */
	if (!ret)
		ret = ENOENT;

	return ret;
}

/**
 * zxdh_end_poll - verb_ex API callback to end polling of WC's
 * @ibvcq_ex: ibv extended CQ
 */
static void zxdh_end_poll(struct ibv_cq_ex *ibvcq_ex)
{
	struct zxdh_ucq *iwucq =
		container_of(ibvcq_ex, struct zxdh_ucq, verbs_cq.cq_ex);

	pthread_spin_unlock(&iwucq->lock);
}

/**
 * zxdh_wc_read_completion_ts - Get completion timestamp
 * @ibvcq_ex: ibv extended CQ
 *
 * Get completion timestamp in HCA clock units
 */
static uint64_t zxdh_wc_read_completion_ts(struct ibv_cq_ex *ibvcq_ex)
{
	struct zxdh_ucq *iwucq =
		container_of(ibvcq_ex, struct zxdh_ucq, verbs_cq.cq_ex);
#define HCA_CORE_CLOCK_800_MHZ 800

	return iwucq->cur_cqe.tcp_seq_num_rtt / HCA_CORE_CLOCK_800_MHZ;
}

/**
 * zxdh_wc_read_completion_wallclock_ns - Get completion timestamp in ns
 * @ibvcq_ex: ibv extended CQ
 *
 * Get completion timestamp from current completion in wall clock nanoseconds
 */
static uint64_t zxdh_wc_read_completion_wallclock_ns(struct ibv_cq_ex *ibvcq_ex)
{
	struct zxdh_ucq *iwucq =
		container_of(ibvcq_ex, struct zxdh_ucq, verbs_cq.cq_ex);

	/* RTT is in usec */
	return (uint64_t)iwucq->cur_cqe.tcp_seq_num_rtt * 1000;
}

static enum ibv_wc_opcode zxdh_wc_read_opcode(struct ibv_cq_ex *ibvcq_ex)
{
	struct zxdh_ucq *iwucq =
		container_of(ibvcq_ex, struct zxdh_ucq, verbs_cq.cq_ex);

	switch (iwucq->cur_cqe.op_type) {
	case ZXDH_OP_TYPE_WRITE:
	case ZXDH_OP_TYPE_WRITE_WITH_IMM:
		return IBV_WC_RDMA_WRITE;
	case ZXDH_OP_TYPE_READ:
		return IBV_WC_RDMA_READ;
	case ZXDH_OP_TYPE_SEND:
	case ZXDH_OP_TYPE_SEND_WITH_IMM:
	case ZXDH_OP_TYPE_SEND_INV:
	case ZXDH_OP_TYPE_UD_SEND:
	case ZXDH_OP_TYPE_UD_SEND_WITH_IMM:
		return IBV_WC_SEND;
	case ZXDH_OP_TYPE_BIND_MW:
		return IBV_WC_BIND_MW;
	case ZXDH_OP_TYPE_REC:
		return IBV_WC_RECV;
	case ZXDH_OP_TYPE_REC_IMM:
		return IBV_WC_RECV_RDMA_WITH_IMM;
	case ZXDH_OP_TYPE_LOCAL_INV:
		return IBV_WC_LOCAL_INV;
	}

	return 0;
}

static uint32_t zxdh_wc_read_vendor_err(struct ibv_cq_ex *ibvcq_ex)
{
	struct zxdh_cq_poll_info *cur_cqe;
	struct zxdh_ucq *iwucq;

	iwucq = container_of(ibvcq_ex, struct zxdh_ucq, verbs_cq.cq_ex);
	cur_cqe = &iwucq->cur_cqe;

	return cur_cqe->error ? cur_cqe->major_err << 16 | cur_cqe->minor_err :
				0;
}

static unsigned int zxdh_wc_read_wc_flags(struct ibv_cq_ex *ibvcq_ex)
{
	struct zxdh_cq_poll_info *cur_cqe;
	struct zxdh_ucq *iwucq;
	struct zxdh_qp *qp;
	struct ibv_qp *ib_qp;
	unsigned int wc_flags = 0;

	iwucq = container_of(ibvcq_ex, struct zxdh_ucq, verbs_cq.cq_ex);
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
			case ZXDH_OP_TYPE_REC:
				wc_flags |= IBV_WC_WITH_INV;
				break;
			case ZXDH_OP_TYPE_REC_IMM:
				wc_flags |= IBV_WC_WITH_INV;
				break;
			}
		}
	}

	return wc_flags;
}

static uint32_t zxdh_wc_read_byte_len(struct ibv_cq_ex *ibvcq_ex)
{
	struct zxdh_ucq *iwucq =
		container_of(ibvcq_ex, struct zxdh_ucq, verbs_cq.cq_ex);

	return iwucq->cur_cqe.bytes_xfered;
}

static __be32 zxdh_wc_read_imm_data(struct ibv_cq_ex *ibvcq_ex)
{
	struct zxdh_cq_poll_info *cur_cqe;
	struct zxdh_ucq *iwucq;

	iwucq = container_of(ibvcq_ex, struct zxdh_ucq, verbs_cq.cq_ex);
	cur_cqe = &iwucq->cur_cqe;

	return cur_cqe->imm_valid ? htonl(cur_cqe->imm_data) : 0;
}

static uint32_t zxdh_wc_read_qp_num(struct ibv_cq_ex *ibvcq_ex)
{
	struct zxdh_ucq *iwucq =
		container_of(ibvcq_ex, struct zxdh_ucq, verbs_cq.cq_ex);

	return iwucq->cur_cqe.qp_id;
}

static uint32_t zxdh_wc_read_src_qp(struct ibv_cq_ex *ibvcq_ex)
{
	struct zxdh_cq_poll_info *cur_cqe;
	struct zxdh_ucq *iwucq;
	struct zxdh_qp *qp;
	struct ibv_qp *ib_qp;

	iwucq = container_of(ibvcq_ex, struct zxdh_ucq, verbs_cq.cq_ex);
	cur_cqe = &iwucq->cur_cqe;
	qp = cur_cqe->qp_handle;
	ib_qp = qp->back_qp;

	return ib_qp->qp_type == IBV_QPT_UD ? cur_cqe->ud_src_qpn :
					      cur_cqe->qp_id;
}

static uint32_t zxdh_wc_read_slid(struct ibv_cq_ex *ibvcq_ex)
{
	return 0;
}

static uint8_t zxdh_wc_read_sl(struct ibv_cq_ex *ibvcq_ex)
{
	return 0;
}

static uint8_t zxdh_wc_read_dlid_path_bits(struct ibv_cq_ex *ibvcq_ex)
{
	return 0;
}

void zxdh_ibvcq_ex_fill_priv_funcs(struct zxdh_ucq *iwucq,
				   struct ibv_cq_init_attr_ex *attr_ex)
{
	struct ibv_cq_ex *ibvcq_ex = &iwucq->verbs_cq.cq_ex;

	ibvcq_ex->start_poll = zxdh_start_poll;
	ibvcq_ex->end_poll = zxdh_end_poll;
	ibvcq_ex->next_poll = zxdh_next_poll;

	if (attr_ex->wc_flags & IBV_WC_EX_WITH_COMPLETION_TIMESTAMP) {
		ibvcq_ex->read_completion_ts = zxdh_wc_read_completion_ts;
		iwucq->report_rtt = true;
	}
	if (attr_ex->wc_flags & IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK) {
		ibvcq_ex->read_completion_wallclock_ns =
			zxdh_wc_read_completion_wallclock_ns;
		iwucq->report_rtt = true;
	}

	ibvcq_ex->read_opcode = zxdh_wc_read_opcode;
	ibvcq_ex->read_vendor_err = zxdh_wc_read_vendor_err;
	ibvcq_ex->read_wc_flags = zxdh_wc_read_wc_flags;

	if (attr_ex->wc_flags & IBV_WC_EX_WITH_BYTE_LEN)
		ibvcq_ex->read_byte_len = zxdh_wc_read_byte_len;
	if (attr_ex->wc_flags & IBV_WC_EX_WITH_IMM)
		ibvcq_ex->read_imm_data = zxdh_wc_read_imm_data;
	if (attr_ex->wc_flags & IBV_WC_EX_WITH_QP_NUM)
		ibvcq_ex->read_qp_num = zxdh_wc_read_qp_num;
	if (attr_ex->wc_flags & IBV_WC_EX_WITH_SRC_QP)
		ibvcq_ex->read_src_qp = zxdh_wc_read_src_qp;
	if (attr_ex->wc_flags & IBV_WC_EX_WITH_SLID)
		ibvcq_ex->read_slid = zxdh_wc_read_slid;
	if (attr_ex->wc_flags & IBV_WC_EX_WITH_SL)
		ibvcq_ex->read_sl = zxdh_wc_read_sl;
	if (attr_ex->wc_flags & IBV_WC_EX_WITH_DLID_PATH_BITS)
		ibvcq_ex->read_dlid_path_bits = zxdh_wc_read_dlid_path_bits;
}

/**
 * zxdh_arm_cq - arm of cq
 * @iwucq: cq to which arm
 * @cq_notify: notification params
 */
static void zxdh_arm_cq(struct zxdh_ucq *iwucq, enum zxdh_cmpl_notify cq_notify)
{
	iwucq->is_armed = true;
	iwucq->last_notify = cq_notify;

	zxdh_cq_request_notification(&iwucq->cq, cq_notify);
}

/**
 * zxdh_uarm_cq - callback for arm of cq
 * @cq: cq to arm
 * @solicited: to get notify params
 */
int zxdh_uarm_cq(struct ibv_cq *cq, int solicited)
{
	struct zxdh_ucq *iwucq;
	enum zxdh_cmpl_notify cq_notify = ZXDH_CQ_COMPL_EVENT;
	bool promo_event = false;
	int ret;

	iwucq = container_of(cq, struct zxdh_ucq, verbs_cq.cq);
	if (solicited) {
		cq_notify = ZXDH_CQ_COMPL_SOLICITED;
	} else {
		if (iwucq->last_notify == ZXDH_CQ_COMPL_SOLICITED)
			promo_event = true;
	}

	ret = pthread_spin_lock(&iwucq->lock);
	if (ret)
		return ret;

	if (!iwucq->is_armed || promo_event)
		zxdh_arm_cq(iwucq, cq_notify);

	pthread_spin_unlock(&iwucq->lock);

	return 0;
}

/**
 * zxdh_cq_event - cq to do completion event
 * @cq: cq to arm
 */
void zxdh_cq_event(struct ibv_cq *cq)
{
	struct zxdh_ucq *iwucq;

	iwucq = container_of(cq, struct zxdh_ucq, verbs_cq.cq);
	if (pthread_spin_lock(&iwucq->lock))
		return;

	iwucq->is_armed = false;

	pthread_spin_unlock(&iwucq->lock);
}

void *zxdh_mmap(int fd, off_t offset)
{
	void *map;

	map = mmap(NULL, ZXDH_HW_PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED,
		   fd, offset);
	if (map == MAP_FAILED)
		return map;

	if (ibv_dontfork_range(map, ZXDH_HW_PAGE_SIZE)) {
		munmap(map, ZXDH_HW_PAGE_SIZE);
		return MAP_FAILED;
	}

	return map;
}

void zxdh_munmap(void *map)
{
	ibv_dofork_range(map, ZXDH_HW_PAGE_SIZE);
	munmap(map, ZXDH_HW_PAGE_SIZE);
}

/**
 * zxdh_destroy_vmapped_qp - destroy resources for qp
 * @iwuqp: qp struct for resources
 */
static int zxdh_destroy_vmapped_qp(struct zxdh_uqp *iwuqp)
{
	int ret;

	ret = ibv_cmd_destroy_qp(&iwuqp->vqp.qp);
	if (ret)
		return ret;

	ibv_cmd_dereg_mr(&iwuqp->vmr);

	return 0;
}

/**
 * zxdh_vmapped_qp - create resources for qp
 * @iwuqp: qp struct for resources
 * @pd: pd for the qp
 * @attr: attributes of qp passed
 * @resp: response back from create qp
 * @sqdepth: depth of sq
 * @rqdepth: depth of rq
 * @info: info for initializing user level qp
 * @abi_ver: abi version of the create qp command
 */
static int zxdh_vmapped_qp(struct zxdh_uqp *iwuqp, struct ibv_pd *pd,
			   struct ibv_qp_init_attr *attr, int sqdepth,
			   int rqdepth, struct zxdh_qp_init_info *info,
			   bool legacy_mode)
{
	struct zxdh_ucreate_qp cmd = {};
	size_t sqsize, rqsize, totalqpsize;
	struct zxdh_ucreate_qp_resp resp = {};
	struct zxdh_ureg_mr reg_mr_cmd = {};
	struct ib_uverbs_reg_mr_resp reg_mr_resp = {};
	int ret;

	rqsize = 0;
	sqsize = roundup(sqdepth * ZXDH_QP_SQE_MIN_SIZE, ZXDH_HW_PAGE_SIZE);
	if (iwuqp->is_srq == false) {
		rqsize = roundup(rqdepth * ZXDH_QP_RQE_MIN_SIZE,
				 ZXDH_HW_PAGE_SIZE);
		totalqpsize = rqsize + sqsize + ZXDH_DB_SHADOW_AREA_SIZE;
	} else {
		totalqpsize = sqsize + ZXDH_DB_SHADOW_AREA_SIZE;
	}
	info->sq = zxdh_alloc_hw_buf(totalqpsize);
	iwuqp->buf_size = totalqpsize;

	if (!info->sq)
		return -ENOMEM;

	memset(info->sq, 0, totalqpsize);
	if (iwuqp->is_srq == false) {
		info->rq = (struct zxdh_qp_rq_quanta *)&info
				   ->sq[sqsize / ZXDH_QP_SQE_MIN_SIZE];
		info->shadow_area =
			info->rq[rqsize / ZXDH_QP_RQE_MIN_SIZE].elem;
		reg_mr_cmd.rq_pages = rqsize >> ZXDH_HW_PAGE_SHIFT;
	} else {
		info->shadow_area =
			(__le64 *)&info->sq[sqsize / ZXDH_QP_SQE_MIN_SIZE];
	}
	reg_mr_cmd.reg_type = ZXDH_MEMREG_TYPE_QP;
	reg_mr_cmd.sq_pages = sqsize >> ZXDH_HW_PAGE_SHIFT;

	ret = ibv_cmd_reg_mr(pd, info->sq, totalqpsize, (uintptr_t)info->sq,
			     IBV_ACCESS_LOCAL_WRITE, &iwuqp->vmr,
			     &reg_mr_cmd.ibv_cmd, sizeof(reg_mr_cmd),
			     &reg_mr_resp, sizeof(reg_mr_resp));
	if (ret)
		goto err_dereg_mr;

	cmd.user_wqe_bufs = (__u64)((uintptr_t)info->sq);
	cmd.user_compl_ctx = (__u64)(uintptr_t)&iwuqp->qp;
	ret = ibv_cmd_create_qp(pd, &iwuqp->vqp.qp, attr, &cmd.ibv_cmd,
				sizeof(cmd), &resp.ibv_resp,
				sizeof(struct zxdh_ucreate_qp_resp));
	if (ret)
		goto err_qp;

	info->sq_size = resp.actual_sq_size;
	info->rq_size = resp.actual_rq_size;
	info->qp_caps = resp.qp_caps;
	info->qp_id = resp.qp_id;
	iwuqp->zxdh_drv_opt = resp.zxdh_drv_opt;
	iwuqp->vqp.qp.qp_num = resp.qp_id;

	iwuqp->send_cq =
		container_of(attr->send_cq, struct zxdh_ucq, verbs_cq.cq);
	iwuqp->recv_cq =
		container_of(attr->recv_cq, struct zxdh_ucq, verbs_cq.cq);
	iwuqp->send_cq->uqp = iwuqp;
	iwuqp->recv_cq->uqp = iwuqp;

	return 0;
err_qp:
	ibv_cmd_dereg_mr(&iwuqp->vmr);
err_dereg_mr:
	zxdh_free_hw_buf(info->sq, iwuqp->buf_size);
	return ret;
}

static void zxdh_wr_local_inv(struct ibv_qp_ex *ibqp, uint32_t invalidate_rkey)
{
	struct zxdh_uqp *qp = container_of(ibqp, struct zxdh_uqp, vqp.qp_ex);
	struct ibv_send_wr wr = {};
	struct ibv_send_wr *bad_wr = NULL;

	wr.opcode = IBV_WR_LOCAL_INV;
	wr.invalidate_rkey = invalidate_rkey;

	zxdh_upost_send(&qp->vqp.qp, &wr, &bad_wr);
}

static void zxdh_send_wr_send_inv(struct ibv_qp_ex *ibqp,
				  uint32_t invalidate_rkey)
{
	struct zxdh_uqp *qp = container_of(ibqp, struct zxdh_uqp, vqp.qp_ex);
	struct ibv_send_wr wr = {};
	struct ibv_send_wr *bad_wr = NULL;

	wr.opcode = IBV_WR_SEND_WITH_INV;
	wr.invalidate_rkey = invalidate_rkey;

	zxdh_upost_send(&qp->vqp.qp, &wr, &bad_wr);
}

static void zxdh_wr_bind_mw(struct ibv_qp_ex *ibqp, struct ibv_mw *ibmw,
			    uint32_t rkey, const struct ibv_mw_bind_info *info)
{
	struct zxdh_uqp *qp = container_of(ibqp, struct zxdh_uqp, vqp.qp_ex);
	struct ibv_send_wr wr = {};
	struct ibv_send_wr *bad_wr = NULL;

	if (ibmw->type != IBV_MW_TYPE_2)
		return;

	wr.opcode = IBV_WR_BIND_MW;
	wr.bind_mw.bind_info = *info;
	wr.bind_mw.mw = ibmw;
	wr.bind_mw.rkey = rkey;

	zxdh_upost_send(&qp->vqp.qp, &wr, &bad_wr);
}

static struct ibv_qp *create_qp(struct ibv_context *ibv_ctx,
				struct ibv_qp_init_attr_ex *attr_ex)
{
	struct zxdh_qp_init_info info = {};
	struct zxdh_dev_attrs *dev_attrs;
	struct zxdh_uvcontext *iwvctx;
	struct zxdh_uqp *iwuqp;
	struct zxdh_usrq *iwusrq;
	struct ibv_pd *pd = attr_ex->pd;
	struct ibv_qp_init_attr *attr;
	__u32 sqdepth, rqdepth;
	__u8 sqshift, rqshift;
	int status;

	attr = calloc(1, sizeof(*attr));
	if (!attr)
		return NULL;

	memcpy(attr, attr_ex, sizeof(*attr));

	if (attr->qp_type != IBV_QPT_RC && attr->qp_type != IBV_QPT_UD) {
		errno = EOPNOTSUPP;
		free(attr);
		return NULL;
	}

	iwvctx = container_of(ibv_ctx, struct zxdh_uvcontext, ibv_ctx.context);
	dev_attrs = &iwvctx->dev_attrs;

	if (attr->cap.max_send_sge > dev_attrs->max_hw_wq_frags ||
	    attr->cap.max_recv_sge > dev_attrs->max_hw_wq_frags) {
		errno = EINVAL;
		free(attr);
		return NULL;
	}

	if (attr->cap.max_inline_data > dev_attrs->max_hw_inline) {
		zxdh_dbg(ZXDH_DBG_QP, "max_inline_data over max_hw_inline\n");
		attr->cap.max_inline_data = dev_attrs->max_hw_inline;
	}

	zxdh_get_sq_wqe_shift(attr->cap.max_send_sge,
			      attr->cap.max_inline_data, &sqshift);
	status = zxdh_get_sqdepth(dev_attrs, attr->cap.max_send_wr, sqshift,
				  &sqdepth);
	if (status) {
		errno = EINVAL;
		free(attr);
		return NULL;
	}

	zxdh_get_rq_wqe_shift(attr->cap.max_recv_sge, &rqshift);
	status = zxdh_get_rqdepth(dev_attrs, attr->cap.max_recv_wr, rqshift,
				  &rqdepth);
	if (status) {
		errno = EINVAL;
		free(attr);
		return NULL;
	}

	iwuqp = memalign(1024, sizeof(*iwuqp));
	if (!iwuqp) {
		free(attr);
		return NULL;
	}

	memset(iwuqp, 0, sizeof(*iwuqp));

	if (attr_ex->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS) {
		if (attr_ex->send_ops_flags & ~IBV_QP_EX_WITH_BIND_MW) {
			errno = EOPNOTSUPP;
			free(iwuqp);
			free(attr);
			return NULL;
		}

		iwuqp->vqp.comp_mask |= VERBS_QP_EX;
		if (attr_ex->send_ops_flags & IBV_QP_EX_WITH_BIND_MW)
			iwuqp->vqp.qp_ex.wr_bind_mw = zxdh_wr_bind_mw;

		if (attr_ex->send_ops_flags & IBV_QP_EX_WITH_SEND_WITH_INV)
			iwuqp->vqp.qp_ex.wr_send_inv = zxdh_send_wr_send_inv;

		if (attr_ex->send_ops_flags & IBV_QP_EX_WITH_LOCAL_INV)
			iwuqp->vqp.qp_ex.wr_local_inv = zxdh_wr_local_inv;
	}

	if (pthread_spin_init(&iwuqp->lock, PTHREAD_PROCESS_PRIVATE))
		goto err_free_qp;

	info.sq_size = sqdepth >> sqshift;
	info.rq_size = rqdepth >> rqshift;
	attr->cap.max_send_wr = info.sq_size;
	attr->cap.max_recv_wr = info.rq_size;

	info.dev_attrs = dev_attrs;
	info.max_sq_frag_cnt = attr->cap.max_send_sge;
	info.max_rq_frag_cnt = attr->cap.max_recv_sge;

	if (attr->srq != NULL) {
		iwuqp->is_srq = true;
		iwusrq = container_of(attr->srq, struct zxdh_usrq, ibv_srq);
		iwuqp->srq = iwusrq;
		iwuqp->qp.is_srq = true;
	}

	if (iwuqp->is_srq == false) {
		iwuqp->recv_sges = calloc(attr->cap.max_recv_sge,
					  sizeof(*iwuqp->recv_sges));
		if (!iwuqp->recv_sges)
			goto err_destroy_lock;
	}

	info.wqe_alloc_db =
		(__u32 *)((__u8 *)iwvctx->sq_db + ZXDH_DB_SQ_OFFSET);
	info.abi_ver = iwvctx->abi_ver;
	info.legacy_mode = iwvctx->legacy_mode;
	info.sq_wrtrk_array = calloc(sqdepth, sizeof(*info.sq_wrtrk_array));
	if (!info.sq_wrtrk_array)
		goto err_free_rsges;

	if (iwuqp->is_srq == false) {
		info.rq_wrid_array =
			calloc(info.rq_size, sizeof(*info.rq_wrid_array));
		if (!info.rq_wrid_array)
			goto err_free_sq_wrtrk;
	}

	iwuqp->sq_sig_all = attr->sq_sig_all;
	iwuqp->qp_type = attr->qp_type;
	if (attr->qp_type == IBV_QPT_UD)
		info.type = ZXDH_QP_TYPE_ROCE_UD;
	else
		info.type = ZXDH_QP_TYPE_ROCE_RC;
	status = zxdh_vmapped_qp(iwuqp, pd, attr, sqdepth, rqdepth, &info,
				 iwvctx->legacy_mode);
	if (status) {
		errno = status;
		goto err_free_rq_wrid;
	}

	iwuqp->qp.back_qp = iwuqp;
	iwuqp->qp.lock = &iwuqp->lock;
	info.max_sq_frag_cnt = attr->cap.max_send_sge;
	info.max_rq_frag_cnt = attr->cap.max_recv_sge;
	info.max_inline_data = attr->cap.max_inline_data;
	if (info.type == ZXDH_QP_TYPE_ROCE_RC) {
		iwuqp->qp.split_sg_list =
			calloc(2 * dev_attrs->max_hw_read_sges,
			       sizeof(*iwuqp->qp.split_sg_list));
		if (!iwuqp->qp.split_sg_list)
			goto err_free_vmap_qp;
	}
	status = zxdh_qp_init(&iwuqp->qp, &info);
	if (status) {
		errno = EINVAL;
		goto err_free_sg_list;
	}
	iwuqp->qp.mtu = mtu_enum_to_int(IBV_MTU_1024);
	attr->cap.max_send_wr = (sqdepth - ZXDH_SQ_RSVD) >> sqshift;
	attr->cap.max_recv_wr = (rqdepth - ZXDH_RQ_RSVD) >> rqshift;
	memcpy(attr_ex, attr, sizeof(*attr));
	free(attr);
	return &iwuqp->vqp.qp;

err_free_sg_list:
	if (iwuqp->qp.split_sg_list)
		free(iwuqp->qp.split_sg_list);
err_free_vmap_qp:
	zxdh_destroy_vmapped_qp(iwuqp);
	zxdh_free_hw_buf(info.sq, iwuqp->buf_size);
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
	free(attr);

	return NULL;
}

/**
 * zxdh_ucreate_qp - create qp on user app
 * @pd: pd for the qp
 * @attr: attributes of the qp to be created (sizes, sge, cq)
 */
struct ibv_qp *zxdh_ucreate_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct ibv_qp_init_attr_ex attrx = {};
	struct ibv_qp *qp;

	memcpy(&attrx, attr, sizeof(*attr));
	attrx.comp_mask = IBV_QP_INIT_ATTR_PD;
	attrx.pd = pd;

	qp = create_qp(pd->context, &attrx);
	if (qp)
		memcpy(attr, &attrx, sizeof(*attr));

	return qp;
}

/**
 * zxdh_ucreate_qp_ex - create qp_ex on user app
 * @context: user context of the device
 * @attr: attributes of the qp_ex to be created
 */
struct ibv_qp *zxdh_ucreate_qp_ex(struct ibv_context *context,
				  struct ibv_qp_init_attr_ex *attr)
{
	return create_qp(context, attr);
}

/**
 * zxdh_uquery_qp - query qp for some attribute
 * @qp: qp for the attributes query
 * @attr: to return the attributes
 * @attr_mask: mask of what is query for
 * @init_attr: initial attributes during create_qp
 */
int zxdh_uquery_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask,
		   struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr, &cmd,
				sizeof(cmd));
}

/**
 * zxdh_clean_cqes - clean cq entries for qp
 * @qp: qp for which completions are cleaned
 * @iwcq: cq to be cleaned
 */
static void zxdh_clean_cqes(struct zxdh_qp *qp, struct zxdh_ucq *iwucq)
{
	struct zxdh_cq *ukcq = &iwucq->cq;
	int ret;

	ret = pthread_spin_lock(&iwucq->lock);
	if (ret)
		return;

	zxdh_clean_cq(qp, ukcq);
	pthread_spin_unlock(&iwucq->lock);
}

static void zxdh_init_qp_indices(struct zxdh_qp *qp)
{
	__u32 sq_ring_size;

	sq_ring_size = ZXDH_RING_SIZE(qp->sq_ring);
	ZXDH_RING_INIT(qp->sq_ring, sq_ring_size);
	ZXDH_RING_INIT(qp->initial_ring, sq_ring_size);
	qp->swqe_polarity = 0;
	qp->swqe_polarity_deferred = 1;
	qp->rwqe_polarity = 0;
	qp->rwqe_signature = 0;
	ZXDH_RING_INIT(qp->rq_ring, qp->rq_size);
}

/**
 * zxdh_umodify_qp - send qp modify to driver
 * @qp: qp to modify
 * @attr: attribute to modify
 * @attr_mask: mask of the attribute
 */
int zxdh_umodify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask)
{
	struct zxdh_uqp *iwuqp;
	struct zxdh_umodify_qp_resp resp = {};
	struct ibv_modify_qp cmd = {};
	struct zxdh_umodify_qp cmd_ex = {};
	int ret;
	__u16 mtu = 0;

	iwuqp = container_of(qp, struct zxdh_uqp, vqp.qp);
	if (attr_mask & IBV_QP_STATE || attr_mask & IBV_QP_RATE_LIMIT) {
		ret = ibv_cmd_modify_qp_ex(qp, attr, attr_mask, &cmd_ex.ibv_cmd,
					   sizeof(cmd_ex), &resp.ibv_resp,
					   sizeof(resp));
	} else {
		ret = ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof(cmd));
	}

	if (!ret &&
		(attr_mask & IBV_QP_STATE) &&
		attr->qp_state == IBV_QPS_RESET) {
		if (iwuqp->send_cq)
			zxdh_clean_cqes(&iwuqp->qp, iwuqp->send_cq);

		if (iwuqp->recv_cq && iwuqp->recv_cq != iwuqp->send_cq)
			zxdh_clean_cqes(&iwuqp->qp, iwuqp->recv_cq);
		zxdh_init_qp_indices(&iwuqp->qp);
	}

	if (!ret && (attr_mask & IBV_QP_PATH_MTU) &&
	    qp->qp_type == IBV_QPT_RC) {
		mtu = mtu_enum_to_int(attr->path_mtu);
		if (mtu == 0)
			return -EINVAL;
		iwuqp->qp.mtu = mtu;
	}
	if (!ret && (attr_mask & IBV_QP_SQ_PSN) && qp->qp_type == IBV_QPT_RC) {
		iwuqp->qp.next_psn = attr->sq_psn;
		iwuqp->qp.cqe_last_ack_qsn = attr->sq_psn - 1;
		iwuqp->qp.qp_last_ack_qsn = attr->sq_psn - 1;
		iwuqp->qp.cqe_retry_cnt = 0;
		iwuqp->qp.qp_reset_cnt = 0;
	}
	return ret;
}

static void zxdh_issue_flush(struct ibv_qp *qp, bool sq_flush, bool rq_flush)
{
	struct ib_uverbs_ex_modify_qp_resp resp = {};
	struct zxdh_umodify_qp cmd_ex = {};
	struct ibv_qp_attr attr = {};

	attr.qp_state = IBV_QPS_ERR;
	cmd_ex.sq_flush = sq_flush;
	cmd_ex.rq_flush = rq_flush;

	ibv_cmd_modify_qp_ex(qp, &attr, IBV_QP_STATE, &cmd_ex.ibv_cmd,
			     sizeof(cmd_ex), &resp, sizeof(resp));
}

/**
 * zxdh_udestroy_qp - destroy qp
 * @qp: qp to destroy
 */
int zxdh_udestroy_qp(struct ibv_qp *qp)
{
	struct zxdh_uqp *iwuqp;
	int ret;

	iwuqp = container_of(qp, struct zxdh_uqp, vqp.qp);
	ret = pthread_spin_destroy(&iwuqp->lock);
	if (ret)
		goto err;

	iwuqp->qp.destroy_pending = true;

	ret = zxdh_destroy_vmapped_qp(iwuqp);
	if (ret)
		goto err;

	/* Clean any pending completions from the cq(s) */
	if (iwuqp->send_cq)
		zxdh_clean_cqes(&iwuqp->qp, iwuqp->send_cq);

	if (iwuqp->recv_cq && iwuqp->recv_cq != iwuqp->send_cq)
		zxdh_clean_cqes(&iwuqp->qp, iwuqp->recv_cq);

	if (iwuqp->qp.sq_wrtrk_array)
		free(iwuqp->qp.sq_wrtrk_array);
	if (iwuqp->qp.rq_wrid_array)
		free(iwuqp->qp.rq_wrid_array);
	if (iwuqp->qp.split_sg_list)
		free(iwuqp->qp.split_sg_list);

	zxdh_free_hw_buf(iwuqp->qp.sq_base, iwuqp->buf_size);
	free(iwuqp->recv_sges);
	free(iwuqp);
	return 0;

err:
	return ret;
}

/**
 * zxdh_copy_sg_list - copy sg list for qp
 * @sg_list: copied into sg_list
 * @sgl: copy from sgl
 * @num_sges: count of sg entries
 * @max_sges: count of max supported sg entries
 */
static void zxdh_copy_sg_list(struct zxdh_sge *sg_list, struct ibv_sge *sgl,
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
 * calc_type2_mw_stag - calculate type 2 MW stag
 * @rkey: desired rkey of the MW
 * @mw_rkey: type2 memory window rkey
 *
 * compute type2 memory window stag by taking lower 8 bits
 * of the desired rkey and leaving 24 bits if mw->rkey unchanged
 */
static inline __u32 calc_type2_mw_stag(__u32 rkey, __u32 mw_rkey)
{
	const __u32 mask = 0xff;

	return (rkey & mask) | (mw_rkey & ~mask);
}

/**
 * zxdh_post_send -  post send wr for user application
 * @ib_qp: qp to post wr
 * @ib_wr: work request ptr
 * @bad_wr: return of bad wr if err
 */
int zxdh_upost_send(struct ibv_qp *ib_qp, struct ibv_send_wr *ib_wr,
		    struct ibv_send_wr **bad_wr)
{
	struct zxdh_post_sq_info info;
	struct zxdh_uvcontext *iwvctx;
	struct zxdh_dev_attrs *dev_attrs;
	enum zxdh_status_code ret = 0;
	struct zxdh_uqp *iwuqp;
	bool reflush = false;
	int err = 0;
	struct verbs_mr *vmr = NULL;
	struct zxdh_umr *umr = NULL;
	__u64 mr_va = 0, mw_va = 0, value_dffer = 0, mw_pa_pble_index = 0;
	__u16 mr_offset = 0;

	iwuqp = container_of(ib_qp, struct zxdh_uqp, vqp.qp);
	iwvctx = container_of(ib_qp->context, struct zxdh_uvcontext,
			      ibv_ctx.context);
	dev_attrs = &iwvctx->dev_attrs;

	err = pthread_spin_lock(&iwuqp->lock);
	if (err)
		return err;

	if (!ZXDH_RING_MORE_WORK(iwuqp->qp.sq_ring) &&
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

		switch (ib_wr->opcode) {
		case IBV_WR_SEND_WITH_IMM:
			if (iwuqp->qp.qp_caps & ZXDH_SEND_WITH_IMM) {
				info.imm_data_valid = true;
				info.imm_data = ntohl(ib_wr->imm_data);
			} else {
				err = EINVAL;
				break;
			}
			SWITCH_FALLTHROUGH;
		case IBV_WR_SEND:
		case IBV_WR_SEND_WITH_INV:
			if (ib_wr->send_flags & IBV_SEND_SOLICITED)
				info.solicited = 1;

			if (ib_wr->opcode == IBV_WR_SEND) {
				if (ib_qp->qp_type == IBV_QPT_UD)
					info.op_type = ZXDH_OP_TYPE_UD_SEND;
				else
					info.op_type = ZXDH_OP_TYPE_SEND;
			} else if (ib_wr->opcode == IBV_WR_SEND_WITH_IMM) {
				if (ib_qp->qp_type == IBV_QPT_UD)
					info.op_type =
						ZXDH_OP_TYPE_UD_SEND_WITH_IMM;
				else
					info.op_type =
						ZXDH_OP_TYPE_SEND_WITH_IMM;
			} else {
				info.op_type = ZXDH_OP_TYPE_SEND_INV;
				info.stag_to_inv = ib_wr->invalidate_rkey;
			}

			if ((ib_wr->send_flags & IBV_SEND_INLINE) &&
			    (ib_wr->num_sge != 0)) {
				ret = zxdh_get_inline_data(
					iwuqp->inline_data, ib_wr,
					&info.op.inline_rdma_send.len);
				if (ret) {
					printf("err:zxdh_get_inline_data fail\n");
					pthread_spin_unlock(&iwuqp->lock);
					return -EINVAL;
				}
				info.op.inline_rdma_send.data =
					iwuqp->inline_data;
				if (ib_qp->qp_type == IBV_QPT_UD) {
					struct zxdh_uah *ah =
						container_of(ib_wr->wr.ud.ah,
							     struct zxdh_uah,
							     ibv_ah);
					info.op.inline_rdma_send.ah_id =
						ah->ah_id;
					info.op.inline_rdma_send.qkey =
						ib_wr->wr.ud.remote_qkey;
					info.op.inline_rdma_send.dest_qp =
						ib_wr->wr.ud.remote_qpn;
					ret = zxdh_ud_inline_send(
						&iwuqp->qp, &info, false);
				} else {
					ret = zxdh_rc_inline_send(
						&iwuqp->qp, &info, false);
				}
			} else {
				info.op.send.num_sges = ib_wr->num_sge;
				info.op.send.sg_list =
					(struct zxdh_sge *)ib_wr->sg_list;
				if (ib_qp->qp_type == IBV_QPT_UD) {
					struct zxdh_uah *ah =
						container_of(ib_wr->wr.ud.ah,
							     struct zxdh_uah,
							     ibv_ah);

					info.op.inline_rdma_send.ah_id =
						ah->ah_id;
					info.op.inline_rdma_send.qkey =
						ib_wr->wr.ud.remote_qkey;
					info.op.inline_rdma_send.dest_qp =
						ib_wr->wr.ud.remote_qpn;
					ret = zxdh_ud_send(&iwuqp->qp, &info,
							      false);
				} else {
					ret = zxdh_rc_send(&iwuqp->qp, &info,
							      false);
				}
			}
			if (ret)
				err = (ret == ZXDH_ERR_QP_TOOMANY_WRS_POSTED) ?
					      ENOMEM :
					      EINVAL;
			break;
		case IBV_WR_RDMA_WRITE_WITH_IMM:
			if (iwuqp->qp.qp_caps & ZXDH_WRITE_WITH_IMM) {
				info.imm_data_valid = true;
				info.imm_data = ntohl(ib_wr->imm_data);
			} else {
				err = -EINVAL;
				break;
			}
			SWITCH_FALLTHROUGH;
		case IBV_WR_RDMA_WRITE:
			if (ib_wr->send_flags & IBV_SEND_SOLICITED)
				info.solicited = 1;

			if (ib_wr->opcode == IBV_WR_RDMA_WRITE)
				info.op_type = ZXDH_OP_TYPE_WRITE;
			else
				info.op_type = ZXDH_OP_TYPE_WRITE_WITH_IMM;

			if ((ib_wr->send_flags & IBV_SEND_INLINE) &&
			    (ib_wr->num_sge != 0)) {
				ret = zxdh_get_inline_data(
					iwuqp->inline_data, ib_wr,
					&info.op.inline_rdma_write.len);
				if (ret) {
					printf("err:zxdh_get_inline_data fail\n");
					pthread_spin_unlock(&iwuqp->lock);
					return -EINVAL;
				}
				info.op.inline_rdma_write.data =
					iwuqp->inline_data;
				info.op.inline_rdma_write.rem_addr.tag_off =
					ib_wr->wr.rdma.remote_addr;
				info.op.inline_rdma_write.rem_addr.stag =
					ib_wr->wr.rdma.rkey;
				ret = zxdh_inline_rdma_write(&iwuqp->qp,
								&info, false);
			} else {
				info.op.rdma_write.lo_sg_list =
					(void *)ib_wr->sg_list;
				info.op.rdma_write.num_lo_sges = ib_wr->num_sge;
				info.op.rdma_write.rem_addr.tag_off =
					ib_wr->wr.rdma.remote_addr;
				info.op.rdma_write.rem_addr.stag =
					ib_wr->wr.rdma.rkey;
				ret = zxdh_rdma_write(&iwuqp->qp, &info,
							 false);
			}
			if (ret)
				err = (ret == ZXDH_ERR_QP_TOOMANY_WRS_POSTED) ?
					      ENOMEM :
					      EINVAL;
			break;
		case IBV_WR_RDMA_READ:
			if (ib_wr->num_sge > dev_attrs->max_hw_read_sges) {
				err = EINVAL;
				break;
			}
			info.op_type = ZXDH_OP_TYPE_READ;
			info.op.rdma_read.rem_addr.tag_off =
				ib_wr->wr.rdma.remote_addr;
			info.op.rdma_read.rem_addr.stag = ib_wr->wr.rdma.rkey;

			info.op.rdma_read.lo_sg_list = (void *)ib_wr->sg_list;
			info.op.rdma_read.num_lo_sges = ib_wr->num_sge;
			ret = zxdh_rdma_read(&iwuqp->qp, &info, false,
						false);
			if (ret)
				err = (ret == ZXDH_ERR_QP_TOOMANY_WRS_POSTED) ?
					      ENOMEM :
					      EINVAL;
			break;
		case IBV_WR_BIND_MW:
			vmr = verbs_get_mr(ib_wr->bind_mw.bind_info.mr);
			umr = container_of(vmr, struct zxdh_umr, vmr);
			mr_va = (uintptr_t)ib_wr->bind_mw.bind_info.mr->addr;
			mw_va = ib_wr->bind_mw.bind_info.addr;
			mr_offset = 0;
			value_dffer = 0;
			mw_pa_pble_index = 0;

			if (ib_qp->qp_type != IBV_QPT_RC) {
				err = EINVAL;
				break;
			}
			info.op_type = ZXDH_OP_TYPE_BIND_MW;
			info.op.bind_window.mr_stag =
				ib_wr->bind_mw.bind_info.mr->rkey;

			if (ib_wr->bind_mw.mw->type == IBV_MW_TYPE_1) {
				info.op.bind_window.mem_window_type_1 = true;
				info.op.bind_window.mw_stag =
					ib_wr->bind_mw.rkey;
			} else {
				info.op.bind_window.mem_window_type_1 = false;
				info.op.bind_window.mw_stag =
					calc_type2_mw_stag(
						ib_wr->bind_mw.rkey,
						ib_wr->bind_mw.mw->rkey);
				ib_wr->bind_mw.mw->rkey =
					info.op.bind_window.mw_stag;
			}

			if (ib_wr->bind_mw.bind_info.mw_access_flags &
			    IBV_ACCESS_ZERO_BASED) {
				info.op.bind_window.addressing_type =
					ZXDH_ADDR_TYPE_ZERO_BASED;
				if (ib_wr->bind_mw.mw->type == IBV_MW_TYPE_1) {
					err = EINVAL;
					break;
				}

				info.op.bind_window.addressing_type =
					ZXDH_ADDR_TYPE_ZERO_BASED;
				info.op.bind_window.host_page_size =
					umr->host_page_size;
				if (umr->host_page_size == ZXDH_PAGE_SIZE_4K) {
					mr_offset = mr_va & 0x0fff;
					value_dffer = mw_va - mr_va;
					if (umr->leaf_pbl_size == 3) {
						mw_pa_pble_index =
							(mr_offset +
							 value_dffer) /
							(4096 * 512);
						info.op.bind_window
							.mw_pa_pble_index =
							umr->mr_pa_pble_index +
							mw_pa_pble_index;
						mw_pa_pble_index =
							((mr_offset +
							  value_dffer) /
							 4096) %
							512;

						info.op.bind_window
							.root_leaf_offset =
							(__u16)mw_pa_pble_index;
						info.op.bind_window.va =
							(void *)(uintptr_t)(mw_va &
									    0x0fff);
						info.op.bind_window
							.leaf_pbl_size = 3;

					} else if (umr->leaf_pbl_size == 1) {
						mw_pa_pble_index =
							(mr_offset +
							 value_dffer) /
							4096;
						info.op.bind_window
							.mw_pa_pble_index =
							umr->mr_pa_pble_index +
							mw_pa_pble_index;
						info.op.bind_window
							.leaf_pbl_size = 1;
						info.op.bind_window.va =
							(void *)(uintptr_t)(mw_va &
									    0x0fff);
						info.op.bind_window
							.root_leaf_offset = 0;
					} else {
						mw_pa_pble_index =
							umr->mr_pa_pble_index +
							mr_offset + value_dffer;
						info.op.bind_window.va =
							(void *)(uintptr_t)(mw_va &
									    0x0fff);
						info.op.bind_window
							.mw_pa_pble_index =
							mw_pa_pble_index;
						info.op.bind_window
							.leaf_pbl_size = 0;
						info.op.bind_window
							.root_leaf_offset = 0;
					}

				} else if (umr->host_page_size ==
					   ZXDH_PAGE_SIZE_2M) {
					mr_offset = mr_va & 0x1FFFFF;
					value_dffer = mw_va - mr_va;
					if (umr->leaf_pbl_size == 3) {
						mw_pa_pble_index =
							(mr_offset +
							 value_dffer) /
							((4096 * 512) * 512);
						info.op.bind_window
							.mw_pa_pble_index =
							umr->mr_pa_pble_index +
							mw_pa_pble_index;
						mw_pa_pble_index =
							((mr_offset +
							  value_dffer) /
							 (4096 * 512)) %
							512;

						info.op.bind_window
							.root_leaf_offset =
							(__u16)mw_pa_pble_index;
						info.op.bind_window.va =
							(void *)(uintptr_t)(mw_va &
									    0x1FFFFF);
						info.op.bind_window
							.leaf_pbl_size = 3;

					} else if (umr->leaf_pbl_size == 1) {
						mw_pa_pble_index =
							(mr_offset +
							 value_dffer) /
							(4096 * 512);
						info.op.bind_window
							.mw_pa_pble_index =
							umr->mr_pa_pble_index +
							mw_pa_pble_index;
						info.op.bind_window
							.leaf_pbl_size = 1;
						info.op.bind_window.va =
							(void *)(uintptr_t)(mw_va &
									    0x1FFFFF);
						info.op.bind_window
							.root_leaf_offset = 0;
					} else {
						mw_pa_pble_index =
							umr->mr_pa_pble_index +
							mr_offset + value_dffer;
						info.op.bind_window.va =
							(void *)(uintptr_t)(mw_va &
									    0x1FFFFF);
						info.op.bind_window
							.mw_pa_pble_index =
							mw_pa_pble_index;
						info.op.bind_window
							.leaf_pbl_size = 0;
						info.op.bind_window
							.root_leaf_offset = 0;
					}
				} else if (umr->host_page_size ==
					   ZXDH_PAGE_SIZE_1G) {
					mr_offset = mr_va & 0x3FFFFFFF;
					value_dffer = mw_va - mr_va;
					if (umr->leaf_pbl_size == 1) {
						mw_pa_pble_index =
							(mr_offset +
							 value_dffer) /
							(1024 * 1024 * 1024);
						info.op.bind_window
							.mw_pa_pble_index =
							umr->mr_pa_pble_index +
							mw_pa_pble_index;
						info.op.bind_window
							.leaf_pbl_size = 1;
						info.op.bind_window.va =
							(void *)(uintptr_t)(mw_va &
									    0x3FFFFFFF);
						info.op.bind_window
							.root_leaf_offset = 0;
					} else if (umr->leaf_pbl_size == 0) {
						mw_pa_pble_index =
							umr->mr_pa_pble_index +
							mr_offset + value_dffer;
						info.op.bind_window.va =
							(void *)(uintptr_t)(mw_va &
									    0x3FFFFFFF);
						info.op.bind_window
							.mw_pa_pble_index =
							mw_pa_pble_index;
						info.op.bind_window
							.leaf_pbl_size = 0;
						info.op.bind_window
							.root_leaf_offset = 0;
					}
				}

			} else {
				info.op.bind_window.addressing_type =
					ZXDH_ADDR_TYPE_VA_BASED;
				info.op.bind_window.va =
					(void *)(uintptr_t)
						ib_wr->bind_mw.bind_info.addr;
				info.op.bind_window.host_page_size =
					umr->host_page_size;

				if (umr->host_page_size == ZXDH_PAGE_SIZE_4K) {
					mr_offset = mr_va & 0x0fff;
					value_dffer = mw_va - mr_va;
					if (umr->leaf_pbl_size == 3) {
						mw_pa_pble_index =
							(mr_offset +
							 value_dffer) /
							(4096 * 512);
						info.op.bind_window
							.mw_pa_pble_index =
							umr->mr_pa_pble_index +
							mw_pa_pble_index;
						mw_pa_pble_index =
							((mr_offset +
							  value_dffer) /
							 4096) %
							512;
						info.op.bind_window
							.root_leaf_offset =
							(__u16)mw_pa_pble_index;
						info.op.bind_window
							.leaf_pbl_size = 3;
					} else if (umr->leaf_pbl_size == 1) {
						info.op.bind_window
							.mw_pa_pble_index =
							umr->mr_pa_pble_index +
							((mr_offset +
							  value_dffer) /
							 4096);
						info.op.bind_window
							.leaf_pbl_size = 1;
						info.op.bind_window
							.root_leaf_offset = 0;
					} else {
						info.op.bind_window
							.leaf_pbl_size = 0;
						info.op.bind_window
							.mw_pa_pble_index =
							umr->mr_pa_pble_index +
							(mr_va & 0x0fff) +
							(mw_va - mr_va);
						info.op.bind_window
							.root_leaf_offset = 0;
					}
				} else if (umr->host_page_size ==
					   ZXDH_PAGE_SIZE_2M) {
					mr_offset = mr_va & 0x1FFFFF;
					value_dffer = mw_va - mr_va;
					if (umr->leaf_pbl_size == 3) {
						mw_pa_pble_index =
							(mr_offset +
							 value_dffer) /
							((4096 * 512) * 512);
						info.op.bind_window
							.mw_pa_pble_index =
							umr->mr_pa_pble_index +
							mw_pa_pble_index;
						mw_pa_pble_index =
							((mr_offset +
							  value_dffer) /
							 (4096 * 512)) %
							512;
						info.op.bind_window
							.root_leaf_offset =
							(__u16)mw_pa_pble_index;
						info.op.bind_window
							.leaf_pbl_size = 3;
					} else if (umr->leaf_pbl_size == 1) {
						info.op.bind_window
							.mw_pa_pble_index =
							umr->mr_pa_pble_index +
							((mr_offset +
							  value_dffer) /
							 (4096 * 512));
						info.op.bind_window
							.leaf_pbl_size = 1;
						info.op.bind_window
							.root_leaf_offset = 0;
					} else {
						info.op.bind_window
							.leaf_pbl_size = 0;
						info.op.bind_window
							.mw_pa_pble_index =
							umr->mr_pa_pble_index +
							(mr_va & 0x1FFFFF) +
							(mw_va - mr_va);
						info.op.bind_window
							.root_leaf_offset = 0;
					}
				} else if (umr->host_page_size ==
					   ZXDH_PAGE_SIZE_1G) {
					mr_offset = mr_va & 0x3FFFFFFF;
					value_dffer = mw_va - mr_va;
					if (umr->leaf_pbl_size == 1) {
						info.op.bind_window
							.mw_pa_pble_index =
							umr->mr_pa_pble_index +
							((mr_offset +
							  value_dffer) /
							 (1024 * 1024 * 1024));
						info.op.bind_window
							.leaf_pbl_size = 1;
						info.op.bind_window
							.root_leaf_offset = 0;
					} else if (umr->leaf_pbl_size == 0) {
						info.op.bind_window
							.leaf_pbl_size = 0;
						info.op.bind_window
							.mw_pa_pble_index =
							umr->mr_pa_pble_index +
							(mr_va & 0x3FFFFFFF) +
							(mw_va - mr_va);
						info.op.bind_window
							.root_leaf_offset = 0;
					}
				}
			}

			info.op.bind_window.bind_len =
				ib_wr->bind_mw.bind_info.length;
			info.op.bind_window.ena_reads =
				(ib_wr->bind_mw.bind_info.mw_access_flags &
				 IBV_ACCESS_REMOTE_READ) ?
					1 :
					0;
			info.op.bind_window.ena_writes =
				(ib_wr->bind_mw.bind_info.mw_access_flags &
				 IBV_ACCESS_REMOTE_WRITE) ?
					1 :
					0;

			ret = zxdh_mw_bind(&iwuqp->qp, &info, false);
			if (ret)
				err = ENOMEM;

			break;
		case IBV_WR_LOCAL_INV:
			info.op_type = ZXDH_OP_TYPE_LOCAL_INV;
			info.op.inv_local_stag.target_stag =
				ib_wr->invalidate_rkey;
			ret = zxdh_stag_local_invalidate(&iwuqp->qp, &info,
							    true);
			if (ret)
				err = ENOMEM;
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

	zxdh_qp_post_wr(&iwuqp->qp);
	if (reflush)
		zxdh_issue_flush(ib_qp, 1, 0);

	pthread_spin_unlock(&iwuqp->lock);

	return err;
}

/**
 * zxdh_post_recv - post receive wr for user application
 * @ib_wr: work request for receive
 * @bad_wr: bad wr caused an error
 */
int zxdh_upost_recv(struct ibv_qp *ib_qp, struct ibv_recv_wr *ib_wr,
		    struct ibv_recv_wr **bad_wr)
{
	struct zxdh_post_rq_info post_recv = {};
	enum zxdh_status_code ret = 0;
	struct zxdh_sge *sg_list;
	struct zxdh_uqp *iwuqp;
	bool reflush = false;
	int err = 0;

	iwuqp = container_of(ib_qp, struct zxdh_uqp, vqp.qp);
	sg_list = iwuqp->recv_sges;

	if (unlikely(ib_qp->state == IBV_QPS_RESET || ib_qp->srq)) {
		*bad_wr = ib_wr;
		printf("err:post recv at reset or using srq\n");
		return -EINVAL;
	}

	err = pthread_spin_lock(&iwuqp->lock);
	if (err)
		return err;

	if (unlikely(!ZXDH_RING_MORE_WORK(iwuqp->qp.rq_ring)) &&
	    ib_qp->state == IBV_QPS_ERR)
		reflush = true;

	while (ib_wr) {
		if (unlikely(ib_wr->num_sge > iwuqp->qp.max_rq_frag_cnt)) {
			*bad_wr = ib_wr;
			err = EINVAL;
			goto error;
		}
		post_recv.num_sges = ib_wr->num_sge;
		post_recv.wr_id = ib_wr->wr_id;
		zxdh_copy_sg_list(sg_list, ib_wr->sg_list, ib_wr->num_sge);
		post_recv.sg_list = sg_list;
		ret = zxdh_post_receive(&iwuqp->qp, &post_recv);
		if (unlikely(ret)) {
			err = (ret == ZXDH_ERR_QP_TOOMANY_WRS_POSTED) ? ENOMEM :
									EINVAL;
			*bad_wr = ib_wr;
			goto error;
		}

		if (reflush)
			zxdh_issue_flush(ib_qp, 0, 1);

		ib_wr = ib_wr->next;
	}
error:
	zxdh_qp_set_shadow_area(&iwuqp->qp);
	pthread_spin_unlock(&iwuqp->lock);

	return err;
}

/**
 * zxdh_ucreate_ah - create address handle associated with a pd
 * @ibpd: pd for the address handle
 * @attr: attributes of address handle
 */
struct ibv_ah *zxdh_ucreate_ah(struct ibv_pd *ibpd, struct ibv_ah_attr *attr)
{
	struct zxdh_uah *ah;
	union ibv_gid sgid;
	struct zxdh_ucreate_ah_resp resp;
	int err;

	memset(&resp, 0, sizeof(resp));
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
 * zxdh_udestroy_ah - destroy the address handle
 * @ibah: address handle
 */
int zxdh_udestroy_ah(struct ibv_ah *ibah)
{
	struct zxdh_uah *ah;
	int ret;

	ah = container_of(ibah, struct zxdh_uah, ibv_ah);

	ret = ibv_cmd_destroy_ah(ibah);
	if (ret)
		return ret;

	free(ah);

	return 0;
}

/**
 * zxdh_uattach_mcast - Attach qp to multicast group implemented
 * @qp: The queue pair
 * @gid:The Global ID for multicast group
 * @lid: The Local ID
 */
int zxdh_uattach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
		       uint16_t lid)
{
	return 0;
}

/**
 * zxdh_udetach_mcast - Detach qp from multicast group
 * @qp: The queue pair
 * @gid:The Global ID for multicast group
 * @lid: The Local ID
 */
int zxdh_udetach_mcast(struct ibv_qp *qp, const union ibv_gid *gid,
		       uint16_t lid)
{
	return 0;
}

/**
 * zxdh_uresize_cq - resizes a cq
 * @cq: cq to resize
 * @cqe: the number of cqes of the new cq
 */
int zxdh_uresize_cq(struct ibv_cq *cq, int cqe)
{
	struct zxdh_uvcontext *iwvctx;
	struct zxdh_dev_attrs *dev_attrs;
	struct zxdh_uresize_cq cmd = {};
	struct ib_uverbs_resize_cq_resp resp = {};
	struct zxdh_ureg_mr reg_mr_cmd = {};
	struct ib_uverbs_reg_mr_resp reg_mr_resp = {};
	struct zxdh_cq_buf *cq_buf = NULL;
	struct zxdh_cqe *cq_base = NULL;
	struct verbs_mr new_mr = {};
	struct zxdh_ucq *iwucq;
	size_t cq_size;
	__u32 cq_pages;
	int cqe_needed;
	int ret = 0;

	iwucq = container_of(cq, struct zxdh_ucq, verbs_cq.cq);
	iwvctx = container_of(cq->context, struct zxdh_uvcontext,
			      ibv_ctx.context);
	dev_attrs = &iwvctx->dev_attrs;

	if (!(dev_attrs->feature_flags & ZXDH_FEATURE_CQ_RESIZE))
		return -EOPNOTSUPP;

	if (cqe > dev_attrs->max_hw_cq_size)
		return -EINVAL;

	cqe_needed = zxdh_cq_round_up(cqe);

	if (cqe_needed < ZXDH_U_MINCQ_SIZE)
		cqe_needed = ZXDH_U_MINCQ_SIZE;

	if (cqe_needed == iwucq->cq.cq_size)
		return 0;

	cq_size = get_cq_total_bytes(cqe_needed);
	cq_pages = cq_size >> ZXDH_HW_PAGE_SHIFT;
	cq_base = zxdh_alloc_hw_buf(cq_size);
	if (!cq_base)
		return -ENOMEM;

	memset(cq_base, 0, cq_size);

	cq_buf = malloc(sizeof(*cq_buf));
	if (!cq_buf) {
		ret = -ENOMEM;
		goto err_buf;
	}

	ret = pthread_spin_lock(&iwucq->lock);
	if (ret)
		goto err_lock;

	new_mr.ibv_mr.pd = iwucq->vmr.ibv_mr.pd;
	reg_mr_cmd.reg_type = ZXDH_MEMREG_TYPE_CQ;
	reg_mr_cmd.cq_pages = cq_pages;

	ret = ibv_cmd_reg_mr(new_mr.ibv_mr.pd, cq_base, cq_size,
			     (uintptr_t)cq_base, IBV_ACCESS_LOCAL_WRITE,
			     &new_mr, &reg_mr_cmd.ibv_cmd, sizeof(reg_mr_cmd),
			     &reg_mr_resp, sizeof(reg_mr_resp));
	if (ret)
		goto err_dereg_mr;

	cmd.user_cq_buffer = (__u64)((uintptr_t)cq_base);
	ret = ibv_cmd_resize_cq(&iwucq->verbs_cq.cq, cqe_needed, &cmd.ibv_cmd,
				sizeof(cmd), &resp, sizeof(resp));
	if (ret)
		goto err_resize;

	memcpy(&cq_buf->cq, &iwucq->cq, sizeof(cq_buf->cq));
	cq_buf->vmr = iwucq->vmr;
	iwucq->vmr = new_mr;
	zxdh_cq_resize(&iwucq->cq, cq_base, cqe_needed);
	iwucq->verbs_cq.cq.cqe = cqe;
	list_add_tail(&iwucq->resize_list, &cq_buf->list);
	iwucq->resize_enable = true;
	pthread_spin_unlock(&iwucq->lock);

	return ret;

err_resize:
	ibv_cmd_dereg_mr(&new_mr);
err_dereg_mr:
	pthread_spin_unlock(&iwucq->lock);
err_lock:
	free(cq_buf);
err_buf:
	zxdh_free_hw_buf(cq_base, cq_size);
	return ret;
}

/**
 * zxdh_ucreate_srq - create srq on user app
 * @pd: pd for the srq
 * @srq_init_attr: attributes of the srq to be created (sizes, sge)
 */
struct ibv_srq *zxdh_ucreate_srq(struct ibv_pd *pd,
				 struct ibv_srq_init_attr *srq_init_attr)
{
	return NULL;
}

/**
 * zxdh_udestroy_srq - destroy srq on user app
 * @srq: srq to destroy
 */
int zxdh_udestroy_srq(struct ibv_srq *srq)
{
	return 0;
}

/**
 * zxdh_umodify_srq - modify srq on user app
 * @srq: srq to destroy
 */
int zxdh_umodify_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr,
		     int srq_attr_mask)
{
	return 0;
}

/**
 * zxdh_uquery_srq - query srq on user app
 * @srq: srq to query
 * @srq_attr: attributes of the srq to be query
 */
int zxdh_uquery_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr)
{
	return 0;
}

/**
 * zxdh_upost_srq_recv - post srq recv on user app
 * @srq: srq to post recv
 * @recv_wr: a list of work requests to post on the receive queue
 * @bad_recv_wr: pointer to first rejected wr
 */
int zxdh_upost_srq_recv(struct ibv_srq *srq, struct ibv_recv_wr *recv_wr,
			struct ibv_recv_wr **bad_recv_wr)
{
	return 0;
}

/**
 * zxdh_uget_srq_num - get srq num on user app
 * @srq: srq to get num
 * @srq_num: to get srq num
 */
int zxdh_uget_srq_num(struct ibv_srq *srq, uint32_t *srq_num)
{
	return 0;
}

void zxdh_set_debug_mask(void)
{
	char *env;

	env = getenv("ZXDH_DEBUG_MASK");
	if (env)
		zxdh_debug_mask = strtol(env, NULL, 0);
}
