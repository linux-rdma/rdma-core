// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018-2025 Advanced Micro Devices, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <infiniband/verbs.h>
#include <linux/types.h>
#include <util/util.h>

#include "ionic_fw.h"
#include "ionic.h"

static void ionic_reserve_sync_cq(struct ionic_ctx *ctx, struct ionic_cq *cq);
static int ionic_poll_cq(struct ibv_cq *ibcq, int nwc, struct ibv_wc *wc);

#ifdef __x86_64__
static bool ionic_have_movdir64b;

#ifndef bit_MOVDIR64B
#define bit_MOVDIR64B	BIT(28)
#endif

static inline bool have_movdir64b(void)
{
#if (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4))
	unsigned int ax, bx, cx, dx, count = 0, leaf = 7;

	/* Return highest supported cpuid input value.  */
	__asm__ volatile ("cpuid\n\t"
			  : "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx)
			  : "0" (leaf));

	if (ax == 0 || ax < leaf)
		return 0;

	__asm__ volatile ("cpuid\n\t"
			  : "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx)
			  : "0" (leaf), "2" (count));

	return cx & bit_MOVDIR64B ? 1 : 0;
#else
	return 0;
#endif
}

static __attribute__((constructor))
void init_ionic_mmio_memcpy(void)
{
	ionic_have_movdir64b = have_movdir64b();
}

static inline void ionic_movdir64b_mmio_memcpy_x64_64(void *dst, const void *src)
{
	const struct { char _[64]; } *__src = src;
	struct { char _[64]; } *__dst = dst;

	/*
	 * Caller must guarantee:
	 *   assert(((uintptr_t)dst) % 64 == 0);
	 *   assert(((uintptr_t)src) % 64 == 0);
	 */

	/*
	 * MOVDIR64B %(rdx), rax.
	 *
	 * Both __src and __dst must be memory constraints in order to tell the
	 * compiler that no other memory accesses should be reordered around
	 * this one.
	 *
	 * Also, both must be supplied as lvalues because this tells
	 * the compiler what the object is (its size) the instruction accesses.
	 * I.e., not the pointers but what they point to, thus the deref'ing '*'.
	 */
	asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02"
		     : "+m" (*__dst)
		     :  "m" (*__src), "a" (__dst), "d" (__src));
}

static inline void ionic_movdir64b_mmio_memcpy_x64(void *dst, const void *src,
						   size_t bytecnt)
{
	/*
	 * Caller must guarantee:
	 *   assert(bytecnt != 0);
	 *   assert((bytecnt % 64) == 0);
	 *   assert(((uintptr_t)dst) % 64 == 0);
	 *   assert(((uintptr_t)src) % 64 == 0);
	 */

	do {
		ionic_movdir64b_mmio_memcpy_x64_64(dst, src);
		bytecnt -= 64;
		src += 64;
		dst += 64;
	} while (bytecnt > 0);
}
#endif /* #if defined(__x86_64__) */

static inline void ionic_mmio_memcpy_x64_64(void *dst, const void *src)
{
#ifdef __x86_64__
	if (likely(ionic_have_movdir64b))
		ionic_movdir64b_mmio_memcpy_x64_64(dst, src);
	else
#endif
		mmio_memcpy_x64(dst, src, 64);
}

static inline void ionic_mmio_memcpy_x64(void *dst, const void *src, size_t bytecnt)
{
#ifdef __x86_64__
	if (likely(ionic_have_movdir64b))
		ionic_movdir64b_mmio_memcpy_x64(dst, src, bytecnt);
	else
#endif
		mmio_memcpy_x64(dst, src, bytecnt);
}

#define ionic_cq_spin_lock(cq) do {			\
	if (unlikely(!(cq)->lockfree))			\
		pthread_spin_lock(&(cq)->lock);		\
} while (0)

#define ionic_cq_spin_trylock(cq)			\
	(likely((cq)->lockfree) ?			\
	 0 : pthread_spin_trylock(&(cq)->lock))

#define ionic_cq_spin_unlock(cq) do {			\
	if (unlikely(!(cq)->lockfree))			\
		pthread_spin_unlock(&(cq)->lock);	\
} while (0)

#define ionic_rq_spin_lock(qp) do {			\
	if (unlikely(!(qp)->lockfree))			\
		pthread_spin_lock(&(qp)->rq.lock);	\
} while (0)

#define ionic_rq_spin_unlock(qp) do {			\
	if (unlikely(!(qp)->lockfree))			\
		pthread_spin_unlock(&(qp)->rq.lock);	\
} while (0)

#define ionic_sq_spin_lock(qp) do {			\
	if (unlikely(!(qp)->lockfree))			\
		pthread_spin_lock(&(qp)->sq.lock);	\
} while (0)

#define ionic_sq_spin_unlock(qp) do {			\
	if (unlikely(!(qp)->lockfree))			\
		pthread_spin_unlock(&(qp)->sq.lock);	\
} while (0)

#define IONIC_OP(version, opname) \
	((version) < 2 ? IONIC_V1_OP_##opname : IONIC_V2_OP_##opname)

static int ionic_query_device_ex(struct ibv_context *ibctx,
				 const struct ibv_query_device_ex_input *input,
				 struct ibv_device_attr_ex *ex,
				 size_t ex_size)
{
	struct ibv_device_attr *dev_attr = &ex->orig_attr;
	struct ib_uverbs_ex_query_device_resp resp = {};
	size_t resp_size = sizeof(resp);
	int rc;

	rc = ibv_cmd_query_device_any(ibctx, input, ex, ex_size, &resp, &resp_size);
	if (rc)
		return rc;

	rc = ibv_read_sysfs_file(ibctx->device->ibdev_path, "fw_ver",
				 dev_attr->fw_ver, sizeof(dev_attr->fw_ver));
	if (rc < 0)
		dev_attr->fw_ver[0] = 0;

	return 0;
}

static int ionic_query_port(struct ibv_context *ibctx, uint8_t port,
			    struct ibv_port_attr *port_attr)
{
	struct ibv_query_port req = {};

	return ibv_cmd_query_port(ibctx, port, port_attr,
				  &req, sizeof(req));
}

static struct ibv_pd *ionic_alloc_parent_domain(struct ibv_context *context,
						struct ibv_parent_domain_init_attr *attr)
{
	struct ionic_pd *pd, *init_pd;
	struct ibv_pd *root_ibpd;
	int rc;

	if (ibv_check_alloc_parent_domain(attr)) {
		rc = errno;
		goto err_pd;
	}

	if (!check_comp_mask(attr->comp_mask,
			     IBV_PARENT_DOMAIN_INIT_ATTR_ALLOCATORS |
			     IBV_PARENT_DOMAIN_INIT_ATTR_PD_CONTEXT)) {
		rc = EINVAL;
		goto err_pd;
	}

	pd = calloc(1, sizeof(*pd));
	if (!pd) {
		rc = errno;
		goto err_pd;
	}

	init_pd = to_ionic_pd(attr->pd);
	root_ibpd = ionic_root_ibpd(init_pd);

	ibv_initialize_parent_domain(&pd->ibpd, root_ibpd);

	pd->root_ibpd = root_ibpd;
	pd->udma_mask = init_pd->udma_mask;
	pd->sq_cmb = init_pd->sq_cmb;
	pd->rq_cmb = init_pd->rq_cmb;

	if (attr->comp_mask & IBV_PARENT_DOMAIN_INIT_ATTR_ALLOCATORS) {
		pd->alloc = attr->alloc;
		pd->free = attr->free;
	}

	if (attr->comp_mask & IBV_PARENT_DOMAIN_INIT_ATTR_PD_CONTEXT)
		pd->pd_context = attr->pd_context;

	return &pd->ibpd;

err_pd:
	errno = rc;
	return NULL;
}

static struct ibv_pd *ionic_alloc_pd(struct ibv_context *ibctx)
{
	struct ionic_ctx *ctx = to_ionic_ctx(ibctx);
	struct ionic_pd *pd;
	struct ibv_alloc_pd req = {};
	struct ib_uverbs_alloc_pd_resp resp = {};
	int rc;

	pd = calloc(1, sizeof(*pd));
	if (!pd) {
		rc = errno;
		goto err_pd;
	}

	pd->root_ibpd = &pd->ibpd;

	rc = ibv_cmd_alloc_pd(ibctx, &pd->ibpd,
			      &req, sizeof(req),
			      &resp, sizeof(resp));
	if (rc)
		goto err_cmd;

	pd->udma_mask = ionic_ctx_udma_mask(ctx);

	pd->sq_cmb = IONIC_CMB_ENABLE;
	if (ctx->sq_expdb)
		pd->sq_cmb |= IONIC_CMB_EXPDB;

	pd->rq_cmb = IONIC_CMB_ENABLE;
	if (ctx->rq_expdb)
		pd->rq_cmb |= IONIC_CMB_EXPDB;

	return &pd->ibpd;

err_cmd:
	free(pd);
err_pd:
	errno = rc;
	return NULL;
}

static int ionic_dealloc_pd(struct ibv_pd *ibpd)
{
	struct ionic_pd *pd = to_ionic_pd(ibpd);
	int rc;

	if (&pd->ibpd == pd->root_ibpd) {
		rc = ibv_cmd_dealloc_pd(&pd->ibpd);
		if (rc)
			return rc;
	}

	free(pd);

	return 0;
}

static struct ibv_mr *ionic_reg_dmabuf_mr(struct ibv_pd *ibpd, uint64_t offset,
					  size_t length, uint64_t iova,
					  int fd, int access)
{
	struct ibv_pd *root_ibpd = to_ionic_root_ibpd(ibpd);
	struct verbs_mr *vmr;
	int rc;

	vmr = calloc(1, sizeof(*vmr));
	if (!vmr) {
		rc = errno;
		goto err_mr;
	}

	rc = ibv_cmd_reg_dmabuf_mr(root_ibpd, offset, length, iova, fd, access, vmr, NULL);
	if (rc)
		goto err_cmd;

	return &vmr->ibv_mr;

err_cmd:
	free(vmr);
err_mr:
	errno = rc;
	return NULL;
}

static struct ibv_mr *ionic_reg_mr(struct ibv_pd *ibpd,
				   void *addr,
				   size_t len,
				   uint64_t hca_va,
				   int access)
{
	struct ibv_pd *root_ibpd = to_ionic_root_ibpd(ibpd);
	struct verbs_mr *vmr;
	struct ib_uverbs_reg_mr_resp resp = {};
	struct ibv_reg_mr req = {};
	int rc;

	vmr = calloc(1, sizeof(*vmr));
	if (!vmr) {
		rc = errno;
		goto err_mr;
	}

	rc = ibv_cmd_reg_mr(root_ibpd, addr, len,
			    hca_va,
			    access, vmr,
			    &req, sizeof(req),
			    &resp, sizeof(resp));
	if (rc)
		goto err_cmd;

	return &vmr->ibv_mr;

err_cmd:
	free(vmr);
err_mr:
	errno = rc;
	return NULL;
}

static int ionic_dereg_mr(struct verbs_mr *vmr)
{
	int rc;

	rc = ibv_cmd_dereg_mr(vmr);
	if (rc)
		return rc;

	free(vmr);

	return 0;
}

static void ionic_vcq_cq_deinit(struct ionic_cq *cq)
{
	if (!cq->vcq)
		return;

	cq->vcq = NULL;
	ionic_queue_destroy(&cq->q);
	pthread_spin_destroy(&cq->lock);
}

static int ionic_vcq_cq_init1(struct ionic_ctx *ctx,
			      struct ionic_vcq *vcq,
			      struct ionic_cq *cq,
			      struct ibv_cq_init_attr_ex *ex,
			      struct ionic_pd *pd,
			      struct ionic_qdesc *req_cq)
{
	int rc;

	cq->vcq = vcq;

	cq->lockfree = false;
	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);
	list_head_init(&cq->poll_sq);
	list_head_init(&cq->poll_rq);
	list_head_init(&cq->flush_sq);
	list_head_init(&cq->flush_rq);

	rc = ionic_queue_init(&cq->q, pd, IONIC_PD_TAG_CQ,
			      ctx->pg_shift, ex->cqe + IONIC_CQ_GRACE,
			      sizeof(struct ionic_v1_cqe));
	if (rc)
		goto err_queue;

	cq->color = true;
	cq->reserve = cq->q.mask;
	cq->reserve_pending = 0;

	req_cq->addr = (uintptr_t)cq->q.ptr;
	req_cq->size = cq->q.size;
	req_cq->mask = cq->q.mask;
	req_cq->depth_log2 = cq->q.depth_log2;
	req_cq->stride_log2 = cq->q.stride_log2;

	return 0;

err_queue:
	pthread_spin_destroy(&cq->lock);

	return rc;
}

static void ionic_vcq_cq_init2(struct ionic_cq *cq, uint32_t resp_cqid)
{
	cq->cqid = resp_cqid;

	ionic_queue_dbell_init(&cq->q, cq->cqid);
}

/*
 * NOTE: ionic_start_poll, ionic_next_poll and ionic_end_poll provide a
 * minimal implementations of the ibv_cq_ex polling mechanism, sufficient to
 * make functional tests pass but not performant. The intention of the API is
 * that start_poll should take any required locks, next_poll should assume the
 * locks are held and end_poll should release them.
 */
static int ionic_start_poll(struct ibv_cq_ex *ibcq_ex, struct ibv_poll_cq_attr *attr)
{
	struct ibv_cq *ibcq = ibv_cq_ex_to_cq(ibcq_ex);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);

	int rc = ionic_poll_cq(ibcq, 1, &vcq->cur_wc);

	if (rc != 1) /* no completions ready or poll failed */
		return (rc == 0) ? ENOENT : rc;

	ibcq_ex->wr_id = vcq->cur_wc.wr_id;
	ibcq_ex->status = vcq->cur_wc.status;
	return 0;
}

static int ionic_next_poll(struct ibv_cq_ex *ibcq_ex)
{
	return ionic_start_poll(ibcq_ex, NULL);
}

static void ionic_end_poll(struct ibv_cq_ex *ibcq_ex)
{
	/* nothing to do here */
}

static enum ibv_wc_opcode ionic_wc_read_opcode(struct ibv_cq_ex *ibcq_ex)
{
	struct ibv_cq *ibcq = ibv_cq_ex_to_cq(ibcq_ex);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);

	return vcq->cur_wc.opcode;
}

static uint32_t ionic_wc_read_vendor_err(struct ibv_cq_ex *ibcq_ex)
{
	struct ibv_cq *ibcq = ibv_cq_ex_to_cq(ibcq_ex);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);

	return vcq->cur_wc.vendor_err;
}

static uint32_t ionic_wc_read_byte_len(struct ibv_cq_ex *ibcq_ex)
{
	struct ibv_cq *ibcq = ibv_cq_ex_to_cq(ibcq_ex);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);

	return vcq->cur_wc.byte_len;
}

static __be32 ionic_wc_read_imm_data(struct ibv_cq_ex *ibcq_ex)
{
	struct ibv_cq *ibcq = ibv_cq_ex_to_cq(ibcq_ex);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);

	return vcq->cur_wc.imm_data;
}

static uint32_t ionic_wc_read_qp_num(struct ibv_cq_ex *ibcq_ex)
{
	struct ibv_cq *ibcq = ibv_cq_ex_to_cq(ibcq_ex);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);

	return vcq->cur_wc.qp_num;
}

static uint32_t ionic_wc_read_src_qp(struct ibv_cq_ex *ibcq_ex)
{
	struct ibv_cq *ibcq = ibv_cq_ex_to_cq(ibcq_ex);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);

	return vcq->cur_wc.src_qp;
}

static unsigned int ionic_wc_read_wc_flags(struct ibv_cq_ex *ibcq_ex)
{
	struct ibv_cq *ibcq = ibv_cq_ex_to_cq(ibcq_ex);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);

	return vcq->cur_wc.wc_flags;
}

static uint8_t ionic_wc_read_sl(struct ibv_cq_ex *ibcq_ex)
{
	struct ibv_cq *ibcq = ibv_cq_ex_to_cq(ibcq_ex);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);

	return vcq->cur_wc.sl;
}

static uint32_t ionic_wc_read_slid(struct ibv_cq_ex *ibcq_ex)
{
	struct ibv_cq *ibcq = ibv_cq_ex_to_cq(ibcq_ex);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);

	return vcq->cur_wc.slid;
}

static uint8_t ionic_wc_read_dlid_path_bits(struct ibv_cq_ex *ibcq_ex)
{
	struct ibv_cq *ibcq = ibv_cq_ex_to_cq(ibcq_ex);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);

	return vcq->cur_wc.dlid_path_bits;
}

static struct ibv_cq_ex *ionic_create_cq_ex(struct ibv_context *ibctx,
					    struct ibv_cq_init_attr_ex *ex)
{
	struct ionic_ctx *ctx = to_ionic_ctx(ibctx);
	struct ionic_pd *pd = NULL;
	struct ionic_vcq *vcq;
	struct uionic_cq req = {};
	struct uionic_cq_resp resp = {};
	int cq_i, rc;

	if (ex->wc_flags & ~IONIC_CQ_SUPPORTED_WC_FLAGS) {
		rc = ENOTSUP;
		goto err;
	}

	if (ex->cqe < 1 || ex->cqe + IONIC_CQ_GRACE > 0xffff) {
		rc = EINVAL;
		goto err;
	}

	vcq = calloc(1, sizeof(*vcq));
	if (!vcq) {
		rc = ENOMEM;
		goto err;
	}

	if (ex->comp_mask & IBV_CQ_INIT_ATTR_MASK_PD) {
		pd = to_ionic_pd(ex->parent_domain);
		vcq->udma_mask = pd->udma_mask;
	} else {
		vcq->udma_mask = ionic_ctx_udma_mask(ctx);
	}

	for (cq_i = 0; cq_i < ctx->udma_count; ++cq_i) {
		if (!(vcq->udma_mask & BIT(cq_i)))
			continue;

		rc = ionic_vcq_cq_init1(ctx, vcq, &vcq->cq[cq_i], ex, pd, &req.cq[cq_i]);
		if (rc)
			goto err_cq;
	}

	req.udma_mask = vcq->udma_mask;

	rc = ibv_cmd_create_cq(ibctx, ex->cqe, ex->channel,
			       ex->comp_vector, &vcq->vcq.cq,
			       &req.ibv_cmd, sizeof(req),
			       &resp.ibv_resp, sizeof(resp));
	if (rc)
		goto err_cmd;

	if (resp.udma_mask != vcq->udma_mask) {
		rc = EINVAL;
		goto err_udma;
	}

	for (cq_i = 0; cq_i < ctx->udma_count; ++cq_i) {
		if (!(vcq->udma_mask & BIT(cq_i)))
			continue;

		ionic_vcq_cq_init2(&vcq->cq[cq_i], resp.cqid[cq_i]);
	}

	vcq->vcq.cq_ex.start_poll = ionic_start_poll;
	vcq->vcq.cq_ex.next_poll = ionic_next_poll;
	vcq->vcq.cq_ex.end_poll = ionic_end_poll;

	vcq->vcq.cq_ex.read_opcode = ionic_wc_read_opcode;
	vcq->vcq.cq_ex.read_vendor_err = ionic_wc_read_vendor_err;
	vcq->vcq.cq_ex.read_wc_flags = ionic_wc_read_wc_flags;

	if (ex->wc_flags & IBV_WC_EX_WITH_BYTE_LEN)
		vcq->vcq.cq_ex.read_byte_len = ionic_wc_read_byte_len;
	if (ex->wc_flags & IBV_WC_EX_WITH_IMM)
		vcq->vcq.cq_ex.read_imm_data = ionic_wc_read_imm_data;
	if (ex->wc_flags & IBV_WC_EX_WITH_QP_NUM)
		vcq->vcq.cq_ex.read_qp_num = ionic_wc_read_qp_num;
	if (ex->wc_flags & IBV_WC_EX_WITH_SRC_QP)
		vcq->vcq.cq_ex.read_src_qp = ionic_wc_read_src_qp;
	if (ex->wc_flags & IBV_WC_EX_WITH_SL)
		vcq->vcq.cq_ex.read_sl = ionic_wc_read_sl;
	if (ex->wc_flags & IBV_WC_EX_WITH_SLID)
		vcq->vcq.cq_ex.read_slid = ionic_wc_read_slid;
	if (ex->wc_flags & IBV_WC_EX_WITH_DLID_PATH_BITS)
		vcq->vcq.cq_ex.read_dlid_path_bits = ionic_wc_read_dlid_path_bits;

	return &vcq->vcq.cq_ex;

err_udma:
	(void)ibv_cmd_destroy_cq(&vcq->vcq.cq);
err_cmd:
	while (cq_i) {
		--cq_i;
		if (!(vcq->udma_mask & BIT(cq_i)))
			continue;
		ionic_vcq_cq_deinit(&vcq->cq[cq_i]);
err_cq:
		;
	}
	free(vcq);
err:
	errno = rc;
	return NULL;
}

static struct ibv_cq *ionic_create_cq(struct ibv_context *ibctx, int ncqe,
				      struct ibv_comp_channel *channel,
				      int vec)
{
	struct ibv_cq_init_attr_ex ex = {
		.cqe = ncqe,
		.channel = channel,
		.comp_vector = vec,
	};
	struct ibv_cq_ex *ibcq;

	if (ncqe < 0) {
		errno = EINVAL;
		return NULL;
	}

	ibcq = ionic_create_cq_ex(ibctx, &ex);

	return ibv_cq_ex_to_cq(ibcq);
}

static int ionic_destroy_cq(struct ibv_cq *ibcq)
{
	struct ionic_ctx *ctx = to_ionic_ctx(ibcq->context);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);
	int cq_i, rc;

	rc = ibv_cmd_destroy_cq(ibcq);
	if (rc)
		return rc;

	for (cq_i = ctx->udma_count; cq_i;) {
		--cq_i;

		if (!(vcq->udma_mask & BIT(cq_i)))
			continue;

		ionic_vcq_cq_deinit(&vcq->cq[cq_i]);
	}

	free(vcq);

	return 0;
}

static int ionic_flush_recv(struct ionic_qp *qp, struct ibv_wc *wc)
{
	struct ionic_rq_meta *meta;
	struct ionic_v1_wqe *wqe;
	struct ionic_ctx *ctx;
	uint64_t wqe_idx;

	if (!qp->rq.flush)
		return 0;

	if (ionic_queue_empty(&qp->rq.queue))
		return 0;

	wqe = ionic_queue_at_cons(&qp->rq.queue);
	wqe_idx = le64toh(wqe->base.wqe_idx);
	ctx = to_ionic_ctx(qp->vqp.qp.context);

	/* wqe_idx must be a valid queue index */
	if (unlikely(wqe_idx >> qp->rq.queue.depth_log2)) {
		verbs_err(&ctx->vctx, "invalid id %#lx", (unsigned long)wqe_idx);
		return -EIO;
	}

	/* wqe_idx must indicate a request that is outstanding */
	meta = &qp->rq.meta[wqe_idx];
	if (unlikely(meta->next != IONIC_META_POSTED)) {
		verbs_err(&ctx->vctx, "wqe not posted %#lx", (unsigned long)wqe_idx);
		return -EIO;
	}

	ionic_queue_consume(&qp->rq.queue);

	memset(wc, 0, sizeof(*wc));

	wc->status = IBV_WC_WR_FLUSH_ERR;
	wc->wr_id = meta->wrid;
	wc->qp_num = qp->qpid;

	meta->next = qp->rq.meta_head;
	qp->rq.meta_head = meta;

	return 1;
}

static int ionic_flush_recv_many(struct ionic_qp *qp,
				 struct ibv_wc *wc, int nwc)
{
	int rc = 0, npolled = 0;

	while (npolled < nwc) {
		rc = ionic_flush_recv(qp, wc + npolled);
		if (rc <= 0)
			break;

		npolled += rc;
	}

	return npolled ?: rc;
}

static int ionic_flush_send(struct ionic_qp *qp, struct ibv_wc *wc)
{
	struct ionic_sq_meta *meta;

	if (!qp->sq.flush)
		return 0;

	if (ionic_queue_empty(&qp->sq.queue))
		return 0;

	meta = &qp->sq.meta[qp->sq.queue.cons];

	ionic_queue_consume(&qp->sq.queue);

	memset(wc, 0, sizeof(*wc));

	wc->status = IBV_WC_WR_FLUSH_ERR;
	wc->wr_id = meta->wrid;
	wc->qp_num = qp->qpid;

	return 1;
}

static int ionic_flush_send_many(struct ionic_qp *qp,
				 struct ibv_wc *wc, int nwc)
{
	int rc = 0, npolled = 0;

	while (npolled < nwc) {
		rc = ionic_flush_send(qp, wc + npolled);
		if (rc <= 0)
			break;

		npolled += rc;
	}

	return npolled ?: rc;
}

static int ionic_poll_recv(struct ionic_ctx *ctx, struct ionic_cq *cq,
			   struct ionic_qp *cqe_qp, struct ionic_v1_cqe *cqe,
			   struct ibv_wc *wc)
{
	struct ionic_qp *qp = NULL;
	struct ionic_rq_meta *meta;
	uint16_t vlan_tag, wqe_idx;
	uint32_t src_qpn, st_len;
	uint8_t op;

	if (cqe_qp->rq.flush)
		return 0;

	qp = cqe_qp;

	st_len = be32toh(cqe->status_length);

	/* ignore wqe_idx in case of flush error */
	if (ionic_v1_cqe_error(cqe) && st_len == IONIC_STS_WQE_FLUSHED_ERR) {
		cqe_qp->rq.flush = true;
		cq->flush = true;
		list_del(&cqe_qp->cq_flush_rq);
		list_add_tail(&cq->flush_rq, &cqe_qp->cq_flush_rq);

		/* posted recvs (if any) flushed by ionic_flush_recv */
		return 0;
	}

	/* there had better be something in the recv queue to complete */
	if (ionic_queue_empty(&qp->rq.queue)) {
		verbs_err(&ctx->vctx, "rq is empty %u", qp->qpid);
		return -EIO;
	}

	wqe_idx = le64toh(cqe->recv.wqe_idx) & IONIC_V1_CQE_WQE_IDX_MASK;

	/* wqe_idx must be a valid queue index */
	if (unlikely(wqe_idx >> qp->rq.queue.depth_log2)) {
		verbs_err(&ctx->vctx, "invalid id %#lx", (unsigned long)wqe_idx);
		return -EIO;
	}

	/* wqe_idx must indicate a request that is outstanding */
	meta = &qp->rq.meta[qp->rq.meta_idx[wqe_idx]];
	if (unlikely(meta->next != IONIC_META_POSTED)) {
		verbs_err(&ctx->vctx, "wqe is not posted for idx %lu meta_idx %u qpid %u rq.prod %u rq.cons %u cqid %u",
			  (unsigned long)wqe_idx,
			  qp->rq.meta_idx[wqe_idx],
			  qp->qpid, qp->rq.queue.prod,
			  qp->rq.queue.cons, cq->cqid);
		return -EIO;
	}

	meta->next = qp->rq.meta_head;
	qp->rq.meta_head = meta;

	memset(wc, 0, sizeof(*wc));

	wc->wr_id = meta->wrid;
	wc->qp_num = cqe_qp->qpid;

	if (ionic_v1_cqe_error(cqe)) {
		wc->vendor_err = st_len;
		wc->status = ionic_to_ibv_status(st_len);

		cqe_qp->rq.flush = true;
		cq->flush = true;
		list_del(&cqe_qp->cq_flush_rq);
		list_add_tail(&cq->flush_rq, &cqe_qp->cq_flush_rq);

		verbs_err(&ctx->vctx, "cqe with error %u for %#x (recv), qpid %u cqid %u",
			  wc->status, be32toh(cqe->send.msg_msn),
			  qp->qpid, cq->cqid);

		goto out;
	}

	wc->vendor_err = 0;
	wc->status = IBV_WC_SUCCESS;

	src_qpn = be32toh(cqe->recv.src_qpn_op);
	op = src_qpn >> IONIC_V1_CQE_RECV_OP_SHIFT;

	src_qpn &= IONIC_V1_CQE_RECV_QPN_MASK;
	op &= IONIC_V1_CQE_RECV_OP_MASK;

	wc->opcode = IBV_WC_RECV;
	switch (op) {
	case IONIC_V1_CQE_RECV_OP_RDMA_IMM:
		wc->opcode = IBV_WC_RECV_RDMA_WITH_IMM;
		SWITCH_FALLTHROUGH;
	case IONIC_V1_CQE_RECV_OP_SEND_IMM:
		wc->wc_flags |= IBV_WC_WITH_IMM;
		wc->imm_data = cqe->recv.imm_data_rkey; /* be32 in wc */
		break;
	case IONIC_V1_CQE_RECV_OP_SEND_INV:
		wc->wc_flags |= IBV_WC_WITH_INV;
		wc->invalidated_rkey = be32toh(cqe->recv.imm_data_rkey);
	}

	wc->byte_len = st_len;
	wc->src_qp = src_qpn;

	if (qp->vqp.qp.qp_type == IBV_QPT_UD) {
		wc->wc_flags |= IBV_WC_GRH;

		/* vlan_tag in cqe will be valid from dpath even if no vlan */
		vlan_tag = be16toh(cqe->recv.vlan_tag);
		wc->sl = vlan_tag >> 13; /* 802.1q PCP */
	}

	wc->pkey_index = 0;

out:
	verbs_debug(&ctx->vctx,  "poll cq %u qp %u cons %u st %u wrid %" PRIx64 " op %u len %u",
		    cq->cqid, qp->qpid, qp->rq.queue.cons, wc->status,
		    meta->wrid, wc->opcode, st_len);
	cq->reserve_pending++;
	ionic_queue_consume(&qp->rq.queue);

	return 1;
}

static bool ionic_peek_send(struct ionic_qp *qp)
{
	struct ionic_sq_meta *meta;

	if (qp->sq.flush)
		return 0;

	/* completed all send queue requests? */
	if (ionic_queue_empty(&qp->sq.queue))
		return false;

	meta = &qp->sq.meta[qp->sq.queue.cons];

	/* waiting for remote completion? */
	if (meta->remote && meta->seq == qp->sq.msn_cons)
		return false;

	/* waiting for local completion? */
	if (!meta->remote && !meta->local_comp)
		return false;

	return true;
}

static int ionic_poll_send(struct ionic_ctx *ctx,
			   struct ionic_cq *cq,
			   struct ionic_qp *qp,
			   struct ibv_wc *wc)
{
	struct ionic_sq_meta *meta;

	if (qp->sq.flush)
		return 0;

	do {
		/* completed all send queue requests? */
		if (ionic_queue_empty(&qp->sq.queue))
			goto out_empty;

		meta = &qp->sq.meta[qp->sq.queue.cons];

		/* waiting for remote completion? */
		if (meta->remote && meta->seq == qp->sq.msn_cons)
			goto out_empty;

		/* waiting for local completion? */
		if (!meta->remote && !meta->local_comp)
			goto out_empty;

		verbs_debug(&ctx->vctx, "poll cq %u qp %u cons %u st %u wr %" PRIx64 " op %u l %u",
			    cq->cqid, qp->qpid, qp->sq.queue.cons, meta->ibsts,
			    meta->wrid, meta->ibop, meta->len);
		cq->reserve_pending++;
		ionic_queue_consume(&qp->sq.queue);

		/* produce wc only if signaled or error status */
	} while (!meta->signal && meta->ibsts == IBV_WC_SUCCESS);

	memset(wc, 0, sizeof(*wc));

	wc->status = meta->ibsts;
	wc->wr_id = meta->wrid;
	wc->qp_num = qp->qpid;

	if (meta->ibsts == IBV_WC_SUCCESS) {
		wc->byte_len = meta->len;
		wc->opcode = meta->ibop;
	} else {
		wc->vendor_err = meta->len;

		qp->sq.flush = true;
		cq->flush = true;
		list_del(&qp->cq_flush_sq);
		list_add_tail(&cq->flush_sq, &qp->cq_flush_sq);
	}

	return 1;

out_empty:
	if (qp->sq.flush_rcvd) {
		qp->sq.flush = true;
		cq->flush = true;
		list_del(&qp->cq_flush_sq);
		list_add_tail(&cq->flush_sq, &qp->cq_flush_sq);
	}
	return 0;
}

static int ionic_poll_send_many(struct ionic_ctx *ctx,
				struct ionic_cq *cq,
				struct ionic_qp *qp,
				struct ibv_wc *wc, int nwc)
{
	int rc = 0, npolled = 0;

	while (npolled < nwc) {
		rc = ionic_poll_send(ctx, cq, qp, wc + npolled);
		if (rc <= 0)
			break;

		npolled += rc;
	}

	return npolled ?: rc;
}

static int ionic_validate_cons(uint16_t prod, uint16_t cons,
			       uint16_t comp, uint16_t mask)
{
	if (((prod - cons) & mask) <= ((comp - cons) & mask))
		return -EIO;

	return 0;
}

static int ionic_comp_msn(struct ionic_ctx *ctx,
			  struct ionic_qp *qp,
			  struct ionic_v1_cqe *cqe)
{
	struct ionic_sq_meta *meta;
	uint16_t cqe_seq, cqe_idx;
	int rc;

	if (qp->sq.flush)
		return 0;

	cqe_seq = be32toh(cqe->send.msg_msn) & qp->sq.queue.mask;

	rc = ionic_validate_cons(qp->sq.msn_prod,
				 qp->sq.msn_cons,
				 cqe_seq - 1,
				 qp->sq.queue.mask);
	if (rc) {
		struct ionic_cq *cq =
			to_ionic_vcq_cq(qp->vqp.qp.send_cq, qp->udma_idx);

		verbs_err(&ctx->vctx, "wqe is not posted for %#x (msn), qpid %u cqid %u seq %u for prod %u cons %u\n",
			  be32toh(cqe->send.msg_msn), qp->qpid, cq->cqid,
			  cqe_seq, qp->sq.msn_prod, qp->sq.msn_cons);
		return rc;
	}

	qp->sq.msn_cons = cqe_seq;

	if (ionic_v1_cqe_error(cqe)) {
		struct ionic_cq *cq =
			to_ionic_vcq_cq(qp->vqp.qp.send_cq, qp->udma_idx);

		cqe_idx = qp->sq.msn_idx[(cqe_seq - 1) & qp->sq.queue.mask];

		meta = &qp->sq.meta[cqe_idx];
		meta->len = be32toh(cqe->status_length);
		meta->ibsts = ionic_to_ibv_status(meta->len);

		verbs_err(&ctx->vctx, "cqe with error %u for %#x (msn), qpid %u cqid %u",
			  meta->ibsts, be32toh(cqe->send.msg_msn),
			  qp->qpid, cq->cqid);
	}

	return 0;
}

static int ionic_comp_npg(struct ionic_ctx *ctx,
			  struct ionic_qp *qp,
			  struct ionic_v1_cqe *cqe)
{
	struct ionic_sq_meta *meta;
	uint16_t wqe_idx;
	uint32_t st_len;

	if (qp->sq.flush)
		return 0;

	st_len = be32toh(cqe->status_length);

	if (ionic_v1_cqe_error(cqe) && st_len == IONIC_STS_WQE_FLUSHED_ERR) {
		/* Flush cqe does not consume a wqe on the device, and maybe
		 * no such work request is posted.
		 *
		 * The driver should begin flushing after the last indicated
		 * normal or error completion.  Here, only set a hint that the
		 * flush request was indicated.  In poll_send, if nothing more
		 * can be polled normally, then begin flushing.
		 */
		qp->sq.flush_rcvd = true;
		return 0;
	}

	wqe_idx = le64toh(cqe->send.npg_wqe_idx) & qp->sq.queue.mask;
	meta = &qp->sq.meta[wqe_idx];
	meta->local_comp = true;

	if (ionic_v1_cqe_error(cqe)) {
		struct ionic_cq *cq =
			to_ionic_vcq_cq(qp->vqp.qp.send_cq, qp->udma_idx);

		meta->len = st_len;
		meta->ibsts = ionic_to_ibv_status(st_len);
		meta->remote = false;
		verbs_err(&ctx->vctx, "cqe with error %s for %#x (npg), qpid %u cqid %u",
			  ibv_wc_status_str(meta->ibsts),
			  be32toh(cqe->send.msg_msn),
			  qp->qpid, cq->cqid);
	}

	return 0;
}

static bool ionic_next_cqe(struct ionic_ctx *ctx,
			   struct ionic_cq *cq,
			   struct ionic_v1_cqe **cqe)
{
	struct ionic_v1_cqe *qcqe = ionic_queue_at_prod(&cq->q);

	if (unlikely(cq->color != ionic_v1_cqe_color(qcqe)))
		return false;

	udma_from_device_barrier();

	ionic_dbg_xdump(ctx, "cqe", qcqe, 1u << cq->q.stride_log2);
	*cqe = qcqe;

	return true;
}

static void ionic_clean_cq(struct ionic_cq *cq, uint32_t qpid)
{
	struct ionic_v1_cqe *qcqe;
	int prod, qtf, qid;
	bool color;

	color = cq->color;
	prod = cq->q.prod;
	qcqe = ionic_queue_at(&cq->q, prod);

	while (color == ionic_v1_cqe_color(qcqe)) {
		qtf = ionic_v1_cqe_qtf(qcqe);
		qid = ionic_v1_cqe_qtf_qid(qtf);

		if (qid == qpid)
			ionic_v1_cqe_clean(qcqe);

		prod = ionic_queue_next(&cq->q, prod);
		qcqe = ionic_queue_at(&cq->q, prod);
		color = ionic_color_wrap(prod, color);
	}
}

static void ionic_reserve_sync_cq(struct ionic_ctx *ctx, struct ionic_cq *cq)
{
	if (!ionic_queue_empty(&cq->q)) {
		cq->reserve += cq->reserve_pending;
		cq->reserve_pending = 0;
		cq->q.cons = cq->q.prod;

		verbs_debug(&ctx->vctx, "dbell cq %u val %" PRIx64 " rsv %d",
			    cq->cqid, ionic_queue_dbell_val(&cq->q),
			    cq->reserve);
		ionic_dbell_ring(&ctx->dbpage[ctx->cq_qtype],
				 ionic_queue_dbell_val(&cq->q));
	}
}

static void ionic_arm_cq(struct ionic_ctx *ctx, struct ionic_cq *cq)
{
	uint64_t dbell_val = cq->q.dbell;

	if (cq->deferred_arm_sol_only) {
		cq->arm_sol_prod = ionic_queue_next(&cq->q, cq->arm_sol_prod);
		dbell_val |= cq->arm_sol_prod | IONIC_DBELL_RING_SONLY;
	} else {
		cq->arm_any_prod = ionic_queue_next(&cq->q, cq->arm_any_prod);
		dbell_val |= cq->arm_any_prod | IONIC_DBELL_RING_ARM;
	}

	verbs_debug(&ctx->vctx, "dbell cq %u val %" PRIx64 " (%s)",
		    cq->cqid, dbell_val,
		    cq->deferred_arm_sol_only ? "sonly" : "arm");
	ionic_dbell_ring(&ctx->dbpage[ctx->cq_qtype], dbell_val);
}

static void ionic_reserve_cq(struct ionic_ctx *ctx, struct ionic_cq *cq,
			     int spend)
{
	cq->reserve -= spend;

	if (cq->reserve <= 0 || cq->deferred_arm)
		ionic_reserve_sync_cq(ctx, cq);

	if (cq->deferred_arm) {
		ionic_arm_cq(ctx, cq);
		cq->deferred_arm = false;
	}
}

static int ionic_poll_vcq_cq(struct ionic_ctx *ctx, struct ionic_cq *cq,
			     int nwc, struct ibv_wc *wc)
{
	struct ionic_qp *qp, *qp_next;
	struct ionic_v1_cqe *cqe;
	uint32_t qtf, qid;
	uint8_t type;
	bool peek;
	int rc = 0, npolled = 0;
	uint16_t old_prod;

	if (nwc < 1)
		return 0;

	ionic_cq_spin_lock(cq);
	++cq->cqseq;

	old_prod = cq->q.prod;

	/* poll already indicated work completions for send queue */

	list_for_each_safe(&cq->poll_sq, qp, qp_next, cq_poll_sq) {
		if (npolled == nwc)
			goto out;

		ionic_sq_spin_lock(qp);
		rc = ionic_poll_send_many(ctx, cq, qp, wc + npolled, nwc - npolled);
		peek = ionic_peek_send(qp);
		ionic_sq_spin_unlock(qp);

		if (rc < 0)
			goto out;

		npolled += rc;

		if (!peek)
			list_del_init(&qp->cq_poll_sq);
	}

	/* poll for more work completions */

	while (likely(ionic_next_cqe(ctx, cq, &cqe))) {
		if (npolled == nwc)
			goto out;

		qtf = ionic_v1_cqe_qtf(cqe);
		qid = ionic_v1_cqe_qtf_qid(qtf);
		type = ionic_v1_cqe_qtf_type(qtf);

		qp = ionic_tbl_lookup(&ctx->qp_tbl, qid);

		if (unlikely(!qp)) {
			verbs_err(&ctx->vctx, "cq %d pos %d missing qp for qid %#x",
				  cq->cqid, cq->q.prod, qid);
			goto cq_next;
		}

		switch (type) {
		case IONIC_V1_CQE_TYPE_RECV:
			ionic_rq_spin_lock(qp);
			rc = ionic_poll_recv(ctx, cq, qp, cqe, wc + npolled);
			ionic_rq_spin_unlock(qp);

			if (rc < 0)
				goto out;

			npolled += rc;
			break;

		case IONIC_V1_CQE_TYPE_SEND_MSN:
			ionic_sq_spin_lock(qp);
			rc = ionic_comp_msn(ctx, qp, cqe);
			if (!rc) {
				rc = ionic_poll_send_many(ctx, cq, qp,
							  wc + npolled,
							  nwc - npolled);
				peek = ionic_peek_send(qp);
			}
			ionic_sq_spin_unlock(qp);

			if (rc < 0)
				goto out;

			npolled += rc;

			if (peek) {
				list_del(&qp->cq_poll_sq);
				list_add_tail(&cq->poll_sq, &qp->cq_poll_sq);
			}

			break;

		case IONIC_V1_CQE_TYPE_SEND_NPG:
			ionic_sq_spin_lock(qp);
			rc = ionic_comp_npg(ctx, qp, cqe);
			if (!rc) {
				rc = ionic_poll_send_many(ctx, cq, qp,
							  wc + npolled,
							  nwc - npolled);
				peek = ionic_peek_send(qp);
			}
			ionic_sq_spin_unlock(qp);

			if (rc < 0)
				goto out;

			npolled += rc;

			if (peek) {
				list_del(&qp->cq_poll_sq);
				list_add_tail(&cq->poll_sq, &qp->cq_poll_sq);
			}

			break;

		case IONIC_V1_CQE_TYPE_RECV_INDIR:
			list_del(&qp->cq_poll_rq);
			list_add_tail(&cq->poll_rq, &qp->cq_poll_rq);
			break;

		default:
			verbs_err(&ctx->vctx, "unexpected cqe type %u", type);
			rc = -EIO;
			goto out;
		}

cq_next:
		ionic_queue_produce(&cq->q);
		cq->color = ionic_color_wrap(cq->q.prod, cq->color);
	}

	/* lastly, flush send and recv queues */
	if (likely(!cq->flush))
		goto out;

	cq->flush = false;

	list_for_each_safe(&cq->flush_sq, qp, qp_next, cq_flush_sq) {
		if (npolled == nwc)
			goto out;

		ionic_sq_spin_lock(qp);
		rc = ionic_flush_send_many(qp, wc + npolled, nwc - npolled);
		ionic_sq_spin_unlock(qp);

		if (rc > 0)
			npolled += rc;

		if (npolled < nwc)
			list_del_init(&qp->cq_flush_sq);
		else
			cq->flush = true;
	}

	list_for_each_safe(&cq->flush_rq, qp, qp_next, cq_flush_rq) {
		if (npolled == nwc)
			goto out;

		ionic_rq_spin_lock(qp);
		rc = ionic_flush_recv_many(qp, wc + npolled, nwc - npolled);
		ionic_rq_spin_unlock(qp);

		if (rc > 0)
			npolled += rc;

		if (npolled < nwc)
			list_del_init(&qp->cq_flush_rq);
		else
			cq->flush = true;
	}

out:
	ionic_reserve_cq(ctx, cq, 0);

	old_prod = (cq->q.prod - old_prod) & cq->q.mask;

	ionic_cq_spin_unlock(cq);

	return npolled ?: rc;
}

/*
 * Note about rc: (noted here because poll is different)
 *
 * Functions without "poll" in the name, if they return an integer, return
 * zero on success, or a positive error number.  Functions returning a
 * pointer return NULL on error and set errno to a positive error number.
 *
 * Functions with "poll" in the name return negative error numbers, or
 * greater or equal to zero number of completions on success.
 */
static int ionic_poll_cq(struct ibv_cq *ibcq, int nwc, struct ibv_wc *wc)
{
	struct ionic_ctx *ctx = to_ionic_ctx(ibcq->context);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);
	int rc_tmp, rc = 0, npolled = 0;
	int cq_i, cq_x, cq_ix;

	cq_x = vcq->poll_idx;

	vcq->poll_idx ^= ctx->udma_count - 1;

	for (cq_i = 0; npolled < nwc && cq_i < ctx->udma_count; ++cq_i) {
		cq_ix = cq_i ^ cq_x;

		if (!(vcq->udma_mask & BIT(cq_ix)))
			continue;

		rc_tmp = ionic_poll_vcq_cq(ctx, &vcq->cq[cq_ix],
					   nwc - npolled, wc + npolled);

		if (rc_tmp >= 0)
			npolled += rc_tmp;
		else if (!rc)
			rc = rc_tmp;
	}

	return npolled ?: rc;
}

static void ionic_req_notify_vcq_cq(struct ionic_cq *cq, int solicited_only)
{
	ionic_cq_spin_lock(cq);

	if (cq->deferred_arm && !cq->deferred_arm_sol_only)
		solicited_only = 0; /* do not downgrade scheduled ARM to SARM */

	cq->deferred_arm = true;
	cq->deferred_arm_sol_only = (bool)solicited_only;

	ionic_cq_spin_unlock(cq);
}

static int ionic_req_notify_cq(struct ibv_cq *ibcq, int solicited_only)
{
	struct ionic_ctx *ctx = to_ionic_ctx(ibcq->context);
	struct ionic_vcq *vcq = to_ionic_vcq(ibcq);
	int cq_i;

	if (!vcq->vcq.cq.channel)
		return -ENOENT;

	for (cq_i = 0; cq_i < ctx->udma_count; ++cq_i) {
		if (!(vcq->udma_mask & BIT(cq_i)))
			continue;

		ionic_req_notify_vcq_cq(&vcq->cq[cq_i], solicited_only);
	}

	return 0;
}

static bool ionic_expdb_wqe_size_supported(struct ionic_ctx *ctx,
					   uint32_t wqe_size)
{
	switch (wqe_size) {
	case 64: return ctx->expdb_mask & IONIC_EXPDB_64;
	case 128: return ctx->expdb_mask & IONIC_EXPDB_128;
	case 256: return ctx->expdb_mask & IONIC_EXPDB_256;
	case 512: return ctx->expdb_mask & IONIC_EXPDB_512;
	}

	return false;
}

static int ionic_set_cmb(struct ionic_ctx *ctx, struct ionic_queue *queue,
			 uint8_t cmb, uint64_t cmb_offset, uint8_t qtype,
			 void **cmb_ptr)
{
	uint64_t db_base, db_data;
	uint16_t wqe_sz, pos;
	__le64 *db_addr;
	void *db_ptr;

	if (!(cmb & IONIC_CMB_ENABLE)) {
		*cmb_ptr = NULL;
		return 0;
	}

	*cmb_ptr = ionic_map_device(queue->size, ctx->vctx.context.cmd_fd,
				    cmb_offset);
	if (!*cmb_ptr)
		return errno;

	if (cmb & IONIC_CMB_EXPDB) {
		/* Pre-fill express doorbells into our buffer */
		wqe_sz = 1 << queue->stride_log2;
		db_ptr = queue->ptr + wqe_sz - IONIC_EXP_DBELL_SZ;

		/* Assume ring 0 */
		db_base = ((uint64_t)qtype << 48) | queue->dbell |
			((0x03 | 0x8) << 19); /* SCHED_SET | PICI_PISET */

		for (pos = 0; pos <= queue->mask; pos++, db_ptr += wqe_sz) {
			db_addr = (__le64 *)db_ptr;
			db_data = db_base | ((pos + 1) & queue->mask);
			*db_addr = htole64(db_data);
		}
	}

	return 0;
}

static int ionic_qp_sq_init(struct ionic_ctx *ctx, struct ionic_qp *qp, struct ionic_pd *pd,
			    int max_wr, int max_sge, int max_data)
{
	uint32_t wqe_size;
	int rc;

	if (!qp->has_sq)
		return 0;

	if (max_wr < 0 || max_wr > 0xffff)
		return EINVAL;
	if (max_sge < 0)
		return EINVAL;
	if (max_sge > ionic_v1_send_wqe_max_sge(ctx->max_stride, 0, false))
		return EINVAL;
	if (max_data < 0)
		return EINVAL;
	if (max_data > ionic_v1_send_wqe_max_data(ctx->max_stride, false))
		return EINVAL;

	qp->sq.spec = ionic_v1_use_spec_sge(max_sge, ctx->spec);

	if (qp->sq.cmb & IONIC_CMB_EXPDB) {
		wqe_size = ionic_v1_send_wqe_min_size(max_sge, max_data,
						      qp->sq.spec, true);

		if (!ionic_expdb_wqe_size_supported(ctx, wqe_size))
			qp->sq.cmb &= ~IONIC_CMB_EXPDB;
	}

	if (!(qp->sq.cmb & IONIC_CMB_EXPDB))
		wqe_size = ionic_v1_send_wqe_min_size(max_sge, max_data,
						      qp->sq.spec, false);

	rc = ionic_queue_init(&qp->sq.queue, pd, IONIC_PD_TAG_SQ,
			      ctx->pg_shift, max_wr, wqe_size);
	if (rc)
		goto err_sq;

	qp->sq.cmb_ptr = NULL;
	qp->sq.cmb_prod = 0;
	qp->sq.color = true;

	qp->sq.meta = calloc((uint32_t)qp->sq.queue.mask + 1,
			     sizeof(*qp->sq.meta));
	if (!qp->sq.meta) {
		rc = ENOMEM;
		goto err_sq_meta;
	}

	qp->sq.msn_idx = calloc((uint32_t)qp->sq.queue.mask + 1,
				sizeof(*qp->sq.msn_idx));
	if (!qp->sq.msn_idx) {
		rc = ENOMEM;
		goto err_sq_msn;
	}

	return 0;

err_sq_msn:
	free(qp->sq.meta);
err_sq_meta:
	ionic_queue_destroy(&qp->sq.queue);
err_sq:
	return rc;
}

static void ionic_qp_sq_destroy(struct ionic_qp *qp)
{
	if (!qp->has_sq)
		return;

	free(qp->sq.msn_idx);
	free(qp->sq.meta);
	ionic_queue_destroy(&qp->sq.queue);
}

static int ionic_qp_rq_init(struct ionic_ctx *ctx, struct ionic_qp *qp, struct ionic_pd *pd,
			    int max_wr, int max_sge)
{
	uint32_t wqe_size;
	uint64_t pd_tag;
	int rc, i;

	if (!qp->has_rq)
		return 0;

	if (max_wr < 0 || max_wr > 0xffff)
		return EINVAL;
	if (max_sge < 0)
		return EINVAL;
	if (max_sge > ionic_v1_recv_wqe_max_sge(ctx->max_stride, 0, false))
		return EINVAL;

	pd_tag = IONIC_PD_TAG_RQ;
	qp->rq.spec = ionic_v1_use_spec_sge(max_sge, ctx->spec);

	if (qp->rq.cmb & IONIC_CMB_EXPDB) {
		wqe_size = ionic_v1_recv_wqe_min_size(max_sge, qp->rq.spec, true);

		if (!ionic_expdb_wqe_size_supported(ctx, wqe_size))
			qp->rq.cmb &= ~IONIC_CMB_EXPDB;
	}

	if (!(qp->rq.cmb & IONIC_CMB_EXPDB))
		wqe_size = ionic_v1_recv_wqe_min_size(max_sge, qp->rq.spec, false);

	rc = ionic_queue_init(&qp->rq.queue, pd, pd_tag, ctx->pg_shift, max_wr, wqe_size);
	if (rc)
		goto err_rq;

	qp->rq.cmb_ptr = NULL;
	qp->rq.cmb_prod = 0;

	qp->rq.meta = calloc((uint32_t)qp->rq.queue.mask + 1,
			     sizeof(*qp->rq.meta));
	if (!qp->rq.meta) {
		rc = ENOMEM;
		goto err_rq_meta;
	}

	for (i = 0; i < qp->rq.queue.mask; ++i)
		qp->rq.meta[i].next = &qp->rq.meta[i + 1];

	qp->rq.meta[i].next = IONIC_META_LAST;
	qp->rq.meta_head = &qp->rq.meta[0];

	qp->rq.meta_idx = calloc((uint32_t)qp->rq.queue.mask + 1,
				 sizeof(*qp->rq.meta_idx));
	if (!qp->rq.meta_idx) {
		rc = ENOMEM;
		goto err_rq_meta_idx;
	}

	return 0;

err_rq_meta_idx:
	free(qp->rq.meta);
err_rq_meta:
	ionic_queue_destroy(&qp->rq.queue);
err_rq:
	return rc;
}

static void ionic_qp_rq_destroy(struct ionic_qp *qp)
{
	if (!qp->has_rq)
		return;

	free(qp->rq.meta_idx);
	free(qp->rq.meta);
	ionic_queue_destroy(&qp->rq.queue);
}

static struct ibv_qp *ionic_create_qp_ex(struct ibv_context *ibctx,
					 struct ibv_qp_init_attr_ex *ex)
{
	struct ionic_ctx *ctx = to_ionic_ctx(ibctx);
	struct ionic_pd *pd = to_ionic_pd(ex->pd);
	struct uionic_qp_resp resp;
	struct uionic_qp req;
	struct ionic_qp *qp;
	struct ionic_cq *cq;
	int rc;

	qp = calloc(1, sizeof(*qp));
	if (!qp) {
		rc = ENOMEM;
		goto err_qp;
	}

	qp->vqp.qp.qp_type = ex->qp_type;
	qp->has_sq = true;
	qp->has_rq = true;
	qp->lockfree = false;

	list_node_init(&qp->cq_poll_sq);
	list_node_init(&qp->cq_poll_rq);
	list_node_init(&qp->cq_flush_sq);
	list_node_init(&qp->cq_flush_rq);

	pthread_spin_init(&qp->sq.lock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&qp->rq.lock, PTHREAD_PROCESS_PRIVATE);

	qp->sq.cmb = pd->sq_cmb;
	qp->rq.cmb = pd->rq_cmb;

	rc = ionic_qp_sq_init(ctx, qp, pd, ex->cap.max_send_wr,
			      ex->cap.max_send_sge, ex->cap.max_inline_data);
	if (rc)
		goto err_sq;

	rc = ionic_qp_rq_init(ctx, qp, pd, ex->cap.max_recv_wr,
			      ex->cap.max_recv_sge);
	if (rc)
		goto err_rq;

	req.sq.addr = (uintptr_t)qp->sq.queue.ptr;
	req.sq.size = qp->sq.queue.size;
	req.sq.mask = qp->sq.queue.mask;
	req.sq.depth_log2 = qp->sq.queue.depth_log2;
	req.sq.stride_log2 = qp->sq.queue.stride_log2;
	req.sq_cmb = qp->sq.cmb;

	req.rq.addr = (uintptr_t)qp->rq.queue.ptr;
	req.rq.size = qp->rq.queue.size;
	req.rq.mask = qp->rq.queue.mask;
	req.rq.depth_log2 = qp->rq.queue.depth_log2;
	req.rq.stride_log2 = qp->rq.queue.stride_log2;
	req.rq_cmb = qp->rq.cmb;

	req.sq_spec = qp->sq.spec;
	req.rq_spec = qp->rq.spec;

	req.udma_mask = pd->udma_mask;

	rc = ibv_cmd_create_qp_ex2(ibctx, &qp->vqp, ex,
				   &req.ibv_cmd,
				   sizeof(req),
				   &resp.ibv_resp,
				   sizeof(resp));
	if (rc)
		goto err_cmd;

	qp->qpid = resp.qpid;
	qp->udma_idx = resp.udma_idx;

	ionic_queue_dbell_init(&qp->sq.queue, qp->qpid);
	ionic_queue_dbell_init(&qp->rq.queue, qp->qpid);

	qp->sq.cmb = resp.sq_cmb;
	qp->rq.cmb = resp.rq_cmb;

	rc = ionic_set_cmb(ctx, &qp->sq.queue, qp->sq.cmb, resp.sq_cmb_offset,
			   ctx->sq_qtype, &qp->sq.cmb_ptr);
	if (rc)
		goto err_cmb;

	rc = ionic_set_cmb(ctx, &qp->rq.queue, qp->rq.cmb, resp.rq_cmb_offset,
			   ctx->rq_qtype, &qp->rq.cmb_ptr);
	if (rc)
		goto err_cmb;

	pthread_mutex_lock(&ctx->mut);
	ionic_tbl_alloc_node(&ctx->qp_tbl);
	ionic_tbl_insert(&ctx->qp_tbl, qp, qp->qpid);
	pthread_mutex_unlock(&ctx->mut);

	if (qp->has_sq) {
		cq = to_ionic_vcq_cq(qp->vqp.qp.send_cq, qp->udma_idx);
		ionic_cq_spin_lock(cq);
		ionic_cq_spin_unlock(cq);

		ex->cap.max_send_wr = qp->sq.queue.mask;
		ex->cap.max_send_sge =
			ionic_v1_send_wqe_max_sge(qp->sq.queue.stride_log2, qp->sq.spec,
						  qp->sq.cmb & IONIC_CMB_EXPDB);
		ex->cap.max_inline_data =
			ionic_v1_send_wqe_max_data(qp->sq.queue.stride_log2,
						   qp->sq.cmb & IONIC_CMB_EXPDB);
	}

	if (qp->has_rq) {
		cq = to_ionic_vcq_cq(qp->vqp.qp.recv_cq, qp->udma_idx);
		ionic_cq_spin_lock(cq);
		ionic_cq_spin_unlock(cq);

		ex->cap.max_recv_wr = qp->rq.queue.mask;
		ex->cap.max_recv_sge =
			ionic_v1_recv_wqe_max_sge(qp->rq.queue.stride_log2, qp->rq.spec,
						  qp->rq.cmb & IONIC_CMB_EXPDB);
	}

	return &qp->vqp.qp;

err_cmb:
	ibv_cmd_destroy_qp(&qp->vqp.qp);
	ionic_unmap(qp->sq.cmb_ptr, qp->sq.queue.size);
	ionic_unmap(qp->rq.cmb_ptr, qp->rq.queue.size);
err_cmd:
	ionic_qp_rq_destroy(qp);
err_rq:
	ionic_qp_sq_destroy(qp);
err_sq:
	pthread_spin_destroy(&qp->rq.lock);
	pthread_spin_destroy(&qp->sq.lock);
	free(qp);
err_qp:
	errno = rc;
	return NULL;
}

static void ionic_flush_qp(struct ionic_ctx *ctx, struct ionic_qp *qp)
{
	struct ionic_cq *cq;

	if (qp->vqp.qp.send_cq) {
		cq = to_ionic_vcq_cq(qp->vqp.qp.send_cq, qp->udma_idx);

		/* Hold the CQ lock and QP sq_lock while setting up flush */
		ionic_cq_spin_lock(cq);
		ionic_sq_spin_lock(qp);
		qp->sq.flush = true;

		if (!ionic_queue_empty(&qp->sq.queue)) {
			cq->flush = true;
			list_del(&qp->cq_flush_sq);
			list_add_tail(&cq->flush_sq, &qp->cq_flush_sq);
		}

		ionic_sq_spin_unlock(qp);
		ionic_cq_spin_unlock(cq);
	}

	if (qp->vqp.qp.recv_cq) {
		cq = to_ionic_vcq_cq(qp->vqp.qp.recv_cq, qp->udma_idx);

		/* Hold the CQ lock and QP rq_lock while setting up flush */
		ionic_cq_spin_lock(cq);
		ionic_rq_spin_lock(qp);
		qp->rq.flush = true;

		if (!ionic_queue_empty(&qp->rq.queue)) {
			cq->flush = true;
			list_del(&qp->cq_flush_rq);
			list_add_tail(&cq->flush_rq, &qp->cq_flush_rq);
		}

		ionic_rq_spin_unlock(qp);
		ionic_cq_spin_unlock(cq);
	}
}

static void ionic_reset_qp(struct ionic_ctx *ctx, struct ionic_qp *qp)
{
	struct ionic_cq *cq;
	int i;

	if (qp->vqp.qp.send_cq) {
		cq = to_ionic_vcq_cq(qp->vqp.qp.send_cq, qp->udma_idx);
		ionic_cq_spin_lock(cq);
		ionic_clean_cq(cq, qp->qpid);
		ionic_cq_spin_unlock(cq);
	}

	if (qp->vqp.qp.recv_cq) {
		cq = to_ionic_vcq_cq(qp->vqp.qp.recv_cq, qp->udma_idx);
		ionic_cq_spin_lock(cq);
		ionic_clean_cq(cq, qp->qpid);
		ionic_cq_spin_unlock(cq);
	}

	if (qp->has_sq) {
		ionic_sq_spin_lock(qp);
		qp->sq.flush = false;
		qp->sq.flush_rcvd = false;
		qp->sq.msn_prod = 0;
		qp->sq.msn_cons = 0;
		qp->sq.cmb_prod = 0;
		qp->sq.old_prod = 0;
		qp->sq.queue.prod = 0;
		qp->sq.queue.cons = 0;
		ionic_sq_spin_unlock(qp);
	}

	if (qp->has_rq) {
		ionic_rq_spin_lock(qp);
		qp->rq.flush = false;
		qp->rq.queue.prod = 0;
		qp->rq.queue.cons = 0;
		qp->rq.cmb_prod = 0;
		qp->rq.old_prod = 0;
		for (i = 0; i < qp->rq.queue.mask; ++i)
			qp->rq.meta[i].next = &qp->rq.meta[i + 1];
		qp->rq.meta[i].next = IONIC_META_LAST;
		qp->rq.meta_head = &qp->rq.meta[0];
		ionic_rq_spin_unlock(qp);
	}
}

static int ionic_modify_qp(struct ibv_qp *ibqp,
			   struct ibv_qp_attr *attr,
			   int attr_mask)
{
	struct ionic_ctx *ctx = to_ionic_ctx(ibqp->context);
	struct ionic_qp *qp = to_ionic_qp(ibqp);
	struct ibv_modify_qp cmd = {};
	int rc;

	if (!attr_mask)
		return 0;

	rc = ibv_cmd_modify_qp(ibqp, attr, attr_mask, &cmd, sizeof(cmd));
	if (rc)
		goto err_cmd;

	if (attr_mask & IBV_QP_STATE) {
		if (attr->qp_state == IBV_QPS_ERR)
			ionic_flush_qp(ctx, qp);
		else if (attr->qp_state == IBV_QPS_RESET)
			ionic_reset_qp(ctx, qp);
	}

err_cmd:
	if (attr_mask & IBV_QP_STATE)
		verbs_debug(&ctx->vctx, "modify qp %u state %u -> %u rc %d",
			    qp->qpid, qp->vqp.qp.state, attr->qp_state, rc);

	return rc;
}

static int ionic_query_qp(struct ibv_qp *ibqp,
			  struct ibv_qp_attr *attr,
			  int attr_mask,
			  struct ibv_qp_init_attr *init_attr)
{
	struct ionic_qp *qp = to_ionic_qp(ibqp);
	struct ionic_ctx *ctx = to_ionic_ctx(ibqp->context);
	struct ibv_query_qp cmd;
	int rc;

	rc = ibv_cmd_query_qp(ibqp, attr, attr_mask, init_attr,
			      &cmd, sizeof(cmd));

	if (qp->has_sq) {
		init_attr->cap.max_send_wr = qp->sq.queue.mask;
		init_attr->cap.max_send_sge =
			ionic_v1_send_wqe_max_sge(qp->sq.queue.stride_log2, qp->sq.spec,
						  qp->sq.cmb & IONIC_CMB_EXPDB);
		init_attr->cap.max_inline_data =
			ionic_v1_send_wqe_max_data(qp->sq.queue.stride_log2,
						   qp->sq.cmb & IONIC_CMB_EXPDB);
	}

	if (qp->has_rq) {
		init_attr->cap.max_recv_wr = qp->rq.queue.mask;
		init_attr->cap.max_recv_sge =
			ionic_v1_send_wqe_max_sge(qp->rq.queue.stride_log2, qp->rq.spec,
						  qp->rq.cmb & IONIC_CMB_EXPDB);
	}

	attr->cap = init_attr->cap;

	verbs_debug(&ctx->vctx, "query qp %u attr_state %u rc %d",
		    qp->qpid, attr->qp_state, rc);

	return rc;
}

static int ionic_destroy_qp(struct ibv_qp *ibqp)
{
	struct ionic_ctx *ctx = to_ionic_ctx(ibqp->context);
	struct ionic_qp *qp = to_ionic_qp(ibqp);
	struct ionic_cq *cq;
	int rc;

	rc = ibv_cmd_destroy_qp(ibqp);
	if (rc)
		return rc;

	pthread_mutex_lock(&ctx->mut);
	ionic_tbl_free_node(&ctx->qp_tbl);
	ionic_tbl_delete(&ctx->qp_tbl, qp->qpid);
	pthread_mutex_unlock(&ctx->mut);

	if (qp->vqp.qp.send_cq) {
		cq = to_ionic_vcq_cq(qp->vqp.qp.send_cq, qp->udma_idx);
		ionic_cq_spin_lock(cq);
		ionic_clean_cq(cq, qp->qpid);
		list_del(&qp->cq_poll_sq);
		list_del(&qp->cq_flush_sq);
		ionic_cq_spin_unlock(cq);
	}

	if (qp->vqp.qp.recv_cq) {
		cq = to_ionic_vcq_cq(qp->vqp.qp.recv_cq, qp->udma_idx);
		ionic_cq_spin_lock(cq);
		ionic_clean_cq(cq, qp->qpid);
		list_del(&qp->cq_poll_rq);
		list_del(&qp->cq_flush_rq);
		ionic_cq_spin_unlock(cq);
	}

	ionic_unmap(qp->sq.cmb_ptr, qp->sq.queue.size);
	ionic_unmap(qp->rq.cmb_ptr, qp->rq.queue.size);

	pthread_spin_destroy(&qp->rq.lock);
	pthread_spin_destroy(&qp->sq.lock);
	ionic_qp_rq_destroy(qp);
	ionic_qp_sq_destroy(qp);
	free(qp);

	return 0;
}

static int64_t ionic_prep_inline(void *data, uint32_t max_data,
				 struct ibv_sge *ibv_sgl, int num_sge)
{
	int64_t len = 0, sg_len;
	int sg_i;

	for (sg_i = 0; sg_i < num_sge; ++sg_i) {
		sg_len = ibv_sgl[sg_i].length;

		/* greater than max inline data is invalid */
		if (unlikely(len + sg_len > max_data))
			return -EINVAL;

		memcpy(data + len, (void *)(uintptr_t)ibv_sgl[sg_i].addr, sg_len);

		len += sg_len;
	}

	return len;
}

static int64_t ionic_v1_prep_pld(struct ionic_v1_wqe *wqe,
				 union ionic_v1_pld *pld,
				 int spec, uint32_t max_sge,
				 struct ibv_sge *ibv_sgl,
				 int num_sge)
{
	static const int64_t bit_31 = 1l << 31;
	int64_t len = 0, sg_len;
	struct ionic_sge *sgl;
	__be32 *spec32 = NULL;
	__be16 *spec16 = NULL;
	int sg_i = 0;

	if (unlikely(num_sge < 0 || (uint32_t)num_sge > max_sge))
		return -EINVAL;

	if (spec && num_sge > IONIC_V1_SPEC_FIRST_SGE) {
		sg_i = IONIC_V1_SPEC_FIRST_SGE;

		if (num_sge > 8) {
			wqe->base.flags |= htobe16(IONIC_V1_FLAG_SPEC16);
			spec16 = pld->spec16;
		} else {
			wqe->base.flags |= htobe16(IONIC_V1_FLAG_SPEC32);
			spec32 = pld->spec32;
		}
	}

	sgl = &pld->sgl[sg_i];

	for (sg_i = 0; sg_i < num_sge; ++sg_i) {
		sg_len = ibv_sgl[sg_i].length;

		/* greater than 2GB data is invalid */
		if (unlikely(len + sg_len > bit_31))
			return -EINVAL;

		sgl[sg_i].va = htobe64(ibv_sgl[sg_i].addr);
		sgl[sg_i].len = htobe32(sg_len);
		sgl[sg_i].lkey = htobe32(ibv_sgl[sg_i].lkey);

		if (spec32) {
			spec32[sg_i] = sgl[sg_i].len;
		} else if (spec16) {
			if (unlikely(sg_len > UINT16_MAX))
				return -EINVAL;
			spec16[sg_i] = htobe16(sg_len);
		}

		len += sg_len;
	}

	return len;
}

static void ionic_v1_prep_base(struct ionic_qp *qp,
			       struct ibv_send_wr *wr,
			       struct ionic_sq_meta *meta,
			       struct ionic_v1_wqe *wqe)
{
	struct ionic_ctx *ctx = to_ionic_ctx(qp->vqp.qp.context);

	meta->wrid = wr->wr_id;
	meta->ibsts = IBV_WC_SUCCESS;
	meta->signal = false;
	meta->local_comp = false;

	wqe->base.wqe_idx = htole64(qp->sq.queue.prod);
	if (qp->sq.color)
		wqe->base.flags |= htobe16(IONIC_V1_FLAG_COLOR);

	if (wr->send_flags & IBV_SEND_FENCE)
		wqe->base.flags |= htobe16(IONIC_V1_FLAG_FENCE);

	if (wr->send_flags & IBV_SEND_SOLICITED)
		wqe->base.flags |= htobe16(IONIC_V1_FLAG_SOL);

	if (wr->send_flags & IBV_SEND_SIGNALED) {
		wqe->base.flags |= htobe16(IONIC_V1_FLAG_SIG);
		meta->signal = true;
	}

	meta->seq = qp->sq.msn_prod;
	meta->remote = qp->vqp.qp.qp_type != IBV_QPT_UD &&
		!ionic_ibop_is_local(wr->opcode);

	if (meta->remote) {
		qp->sq.msn_idx[meta->seq] = qp->sq.queue.prod;
		qp->sq.msn_prod = ionic_queue_next(&qp->sq.queue, qp->sq.msn_prod);
	}

	verbs_debug(&ctx->vctx, "post send %u prod %u",
		    qp->qpid, qp->sq.queue.prod);
	ionic_dbg_xdump(ctx, "wqe", wqe, 1u << qp->sq.queue.stride_log2);

	ionic_queue_produce(&qp->sq.queue);
	qp->sq.color = ionic_color_wrap(qp->sq.queue.prod, qp->sq.color);
}

static int ionic_v1_prep_common(struct ionic_qp *qp,
				struct ibv_send_wr *wr,
				struct ionic_sq_meta *meta,
				struct ionic_v1_wqe *wqe)
{
	int64_t signed_len;
	uint32_t mval;

	if (wr->send_flags & IBV_SEND_INLINE) {
		wqe->base.num_sge_key = 0;
		wqe->base.flags |= htobe16(IONIC_V1_FLAG_INL);
		mval = ionic_v1_send_wqe_max_data(qp->sq.queue.stride_log2,
						  qp->sq.cmb & IONIC_CMB_EXPDB);
		signed_len = ionic_prep_inline(wqe->common.pld.data, mval,
					       wr->sg_list, wr->num_sge);
	} else {
		wqe->base.num_sge_key = wr->num_sge;
		mval = ionic_v1_send_wqe_max_sge(qp->sq.queue.stride_log2, qp->sq.spec,
						 qp->sq.cmb & IONIC_CMB_EXPDB);
		signed_len = ionic_v1_prep_pld(wqe, &wqe->common.pld,
					       qp->sq.spec, mval,
					       wr->sg_list, wr->num_sge);
	}

	if (unlikely(signed_len < 0))
		return -signed_len;

	meta->len = signed_len;
	wqe->common.length = htobe32(signed_len);

	ionic_v1_prep_base(qp, wr, meta, wqe);

	return 0;
}

static void ionic_prep_sq_wqe(struct ionic_qp *qp, void *wqe)
{
	uint32_t wqe_sz = 1u << qp->sq.queue.stride_log2;

	if (qp->sq.cmb & IONIC_CMB_EXPDB)
		memset(wqe, 0, wqe_sz - IONIC_EXP_DBELL_SZ);
	else
		memset(wqe, 0, wqe_sz);
}

static void ionic_prep_rq_wqe(struct ionic_qp *qp, void *wqe)
{
	uint32_t wqe_sz = 1u << qp->rq.queue.stride_log2;

	if (qp->rq.cmb & IONIC_CMB_EXPDB)
		memset(wqe, 0, wqe_sz - IONIC_EXP_DBELL_SZ);
	else
		memset(wqe, 0, wqe_sz);
}

static int ionic_v1_prep_send(struct ionic_qp *qp,
			      struct ibv_send_wr *wr)
{
	struct ionic_ctx *ctx = to_ionic_ctx(qp->vqp.qp.context);
	struct ionic_sq_meta *meta;
	struct ionic_v1_wqe *wqe;

	meta = &qp->sq.meta[qp->sq.queue.prod];
	wqe = ionic_queue_at_prod(&qp->sq.queue);

	ionic_prep_sq_wqe(qp, wqe);

	meta->ibop = IBV_WC_SEND;

	switch (wr->opcode) {
	case IBV_WR_SEND:
		wqe->base.op = IONIC_OP(ctx->version, SEND);
		break;
	case IBV_WR_SEND_WITH_IMM:
		wqe->base.op = IONIC_OP(ctx->version, SEND_IMM);
		wqe->base.imm_data_key = wr->imm_data;
		break;
	case IBV_WR_SEND_WITH_INV:
		wqe->base.op = IONIC_OP(ctx->version, SEND_INV);
		wqe->base.imm_data_key = htobe32(wr->invalidate_rkey);
		break;
	default:
		return EINVAL;
	}

	return ionic_v1_prep_common(qp, wr, meta, wqe);
}

static int ionic_v1_prep_send_ud(struct ionic_qp *qp, struct ibv_send_wr *wr)
{
	struct ionic_ctx *ctx = to_ionic_ctx(qp->vqp.qp.context);
	struct ionic_sq_meta *meta;
	struct ionic_v1_wqe *wqe;
	struct ionic_ah *ah;

	if (unlikely(!wr->wr.ud.ah))
		return EINVAL;

	ah = to_ionic_ah(wr->wr.ud.ah);

	meta = &qp->sq.meta[qp->sq.queue.prod];
	wqe = ionic_queue_at_prod(&qp->sq.queue);

	ionic_prep_sq_wqe(qp, wqe);

	wqe->common.send.ah_id = htobe32(ah->ahid);
	wqe->common.send.dest_qpn = htobe32(wr->wr.ud.remote_qpn);
	wqe->common.send.dest_qkey = htobe32(wr->wr.ud.remote_qkey);

	meta->ibop = IBV_WC_SEND;

	switch (wr->opcode) {
	case IBV_WR_SEND:
		wqe->base.op = IONIC_OP(ctx->version, SEND);
		break;
	case IBV_WR_SEND_WITH_IMM:
		wqe->base.op = IONIC_OP(ctx->version, SEND_IMM);
		wqe->base.imm_data_key = wr->imm_data;
		break;
	default:
		return EINVAL;
	}

	return ionic_v1_prep_common(qp, wr, meta, wqe);
}

static int ionic_v1_prep_rdma(struct ionic_qp *qp,
			      struct ibv_send_wr *wr)
{
	struct ionic_ctx *ctx = to_ionic_ctx(qp->vqp.qp.context);
	struct ionic_sq_meta *meta;
	struct ionic_v1_wqe *wqe;

	meta = &qp->sq.meta[qp->sq.queue.prod];
	wqe = ionic_queue_at_prod(&qp->sq.queue);

	ionic_prep_sq_wqe(qp, wqe);

	meta->ibop = IBV_WC_RDMA_WRITE;

	switch (wr->opcode) {
	case IBV_WR_RDMA_READ:
		if (wr->send_flags & (IBV_SEND_SOLICITED | IBV_SEND_INLINE))
			return EINVAL;
		meta->ibop = IBV_WC_RDMA_READ;
		wqe->base.op = IONIC_OP(ctx->version, RDMA_READ);
		break;
	case IBV_WR_RDMA_WRITE:
		if (wr->send_flags & IBV_SEND_SOLICITED)
			return EINVAL;
		wqe->base.op = IONIC_OP(ctx->version, RDMA_WRITE);
		break;
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		wqe->base.op = IONIC_OP(ctx->version, RDMA_WRITE_IMM);
		wqe->base.imm_data_key = wr->imm_data;
		break;
	default:
		return EINVAL;
	}

	wqe->common.rdma.remote_va_high =
		htobe32(wr->wr.rdma.remote_addr >> 32);
	wqe->common.rdma.remote_va_low = htobe32(wr->wr.rdma.remote_addr);
	wqe->common.rdma.remote_rkey = htobe32(wr->wr.rdma.rkey);

	return ionic_v1_prep_common(qp, wr, meta, wqe);
}

static int ionic_v1_prep_atomic(struct ionic_qp *qp,
				struct ibv_send_wr *wr)
{
	struct ionic_ctx *ctx = to_ionic_ctx(qp->vqp.qp.context);
	struct ionic_sq_meta *meta;
	struct ionic_v1_wqe *wqe;

	if (wr->num_sge != 1 || wr->sg_list[0].length != 8)
		return EINVAL;

	if (wr->send_flags & (IBV_SEND_SOLICITED | IBV_SEND_INLINE))
		return EINVAL;

	meta = &qp->sq.meta[qp->sq.queue.prod];
	wqe = ionic_queue_at_prod(&qp->sq.queue);

	ionic_prep_sq_wqe(qp, wqe);

	switch (wr->opcode) {
	case IBV_WR_ATOMIC_CMP_AND_SWP:
		meta->ibop = IBV_WC_COMP_SWAP;
		wqe->base.op = IONIC_OP(ctx->version, ATOMIC_CS);
		wqe->atomic.swap_add_high = htobe32(wr->wr.atomic.swap >> 32);
		wqe->atomic.swap_add_low = htobe32(wr->wr.atomic.swap);
		wqe->atomic.compare_high =
			htobe32(wr->wr.atomic.compare_add >> 32);
		wqe->atomic.compare_low = htobe32(wr->wr.atomic.compare_add);
		break;
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		meta->ibop = IBV_WC_FETCH_ADD;
		wqe->base.op = IONIC_OP(ctx->version, ATOMIC_FA);
		wqe->atomic.swap_add_high =
			htobe32(wr->wr.atomic.compare_add >> 32);
		wqe->atomic.swap_add_low = htobe32(wr->wr.atomic.compare_add);
		break;
	default:
		return EINVAL;
	}

	wqe->atomic.remote_va_high = htobe32(wr->wr.atomic.remote_addr >> 32);
	wqe->atomic.remote_va_low = htobe32(wr->wr.atomic.remote_addr);
	wqe->atomic.remote_rkey = htobe32(wr->wr.atomic.rkey);

	wqe->base.num_sge_key = 1;

	/*
	 * The fields above are common to atomic and atomic_v2. Deal now with
	 * the fields that differ.
	 */
	if (likely(ctx->version >= 2)) {
		wqe->atomic_v2.local_va = htobe64(wr->sg_list[0].addr);
		wqe->atomic_v2.lkey = htobe32(wr->sg_list[0].lkey);
	} else {
		wqe->atomic.sge.va = htobe64(wr->sg_list[0].addr);
		wqe->atomic.sge.len = htobe32(8);
		wqe->atomic.sge.lkey = htobe32(wr->sg_list[0].lkey);
	}

	ionic_v1_prep_base(qp, wr, meta, wqe);

	return 0;
}

static int ionic_v1_prep_inv(struct ionic_qp *qp, struct ibv_send_wr *wr)
{
	struct ionic_ctx *ctx = to_ionic_ctx(qp->vqp.qp.context);
	struct ionic_sq_meta *meta;
	struct ionic_v1_wqe *wqe;

	if (wr->send_flags & (IBV_SEND_SOLICITED | IBV_SEND_INLINE))
		return EINVAL;

	meta = &qp->sq.meta[qp->sq.queue.prod];
	meta->ibop = IBV_WC_LOCAL_INV;
	wqe = ionic_queue_at_prod(&qp->sq.queue);

	ionic_prep_sq_wqe(qp, wqe);

	wqe->base.op = IONIC_OP(ctx->version, LOCAL_INV);
	wqe->base.imm_data_key = htobe32(wr->invalidate_rkey);

	ionic_v1_prep_base(qp, wr, meta, wqe);

	return 0;
}

static int ionic_v1_prep_bind(struct ionic_qp *qp,
			      struct ibv_send_wr *wr,
			      bool send_path)
{
	struct ionic_ctx *ctx = to_ionic_ctx(qp->vqp.qp.context);
	struct ionic_sq_meta *meta;
	struct ionic_v1_wqe *wqe;
	int flags;

	if (wr->send_flags & (IBV_SEND_SOLICITED | IBV_SEND_INLINE))
		return EINVAL;

	/* type 1 must use bind_mw; type 2 must use post_send */
	if (send_path == (wr->bind_mw.mw->type == IBV_MW_TYPE_1))
		return EINVAL;

	/* only type 1 can unbind with zero length */
	if (!wr->bind_mw.bind_info.length &&
	    wr->bind_mw.mw->type != IBV_MW_TYPE_1)
		return EINVAL;

	meta = &qp->sq.meta[qp->sq.queue.prod];
	meta->ibop = IBV_WC_BIND_MW;
	wqe = ionic_queue_at_prod(&qp->sq.queue);

	ionic_prep_sq_wqe(qp, wqe);

	flags = to_ionic_mr_flags(wr->bind_mw.bind_info.mw_access_flags);

	if (wr->bind_mw.mw->type == IBV_MW_TYPE_1)
		flags |= IONIC_MRF_MW_1;
	else
		flags |= IONIC_MRF_MW_2;

	wqe->base.op = IONIC_OP(ctx->version, BIND_MW);
	wqe->base.num_sge_key = wr->bind_mw.rkey;
	wqe->base.imm_data_key = htobe32(wr->bind_mw.mw->rkey);
	wqe->bind_mw.va = htobe64(wr->bind_mw.bind_info.addr);
	wqe->bind_mw.length = htobe64(wr->bind_mw.bind_info.length);
	wqe->bind_mw.lkey = htobe32(wr->bind_mw.bind_info.mr->lkey);
	wqe->bind_mw.flags = htobe16(flags);

	ionic_v1_prep_base(qp, wr, meta, wqe);

	return 0;
}

static int ionic_v1_prep_one_rc(struct ionic_qp *qp,
				struct ibv_send_wr *wr,
				bool send_path)
{
	struct ionic_ctx *ctx = to_ionic_ctx(qp->vqp.qp.context);
	int rc = 0;

	switch (wr->opcode) {
	case IBV_WR_SEND:
	case IBV_WR_SEND_WITH_IMM:
	case IBV_WR_SEND_WITH_INV:
		rc = ionic_v1_prep_send(qp, wr);
		break;
	case IBV_WR_RDMA_READ:
	case IBV_WR_RDMA_WRITE:
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		rc = ionic_v1_prep_rdma(qp, wr);
		break;
	case IBV_WR_ATOMIC_CMP_AND_SWP:
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		rc = ionic_v1_prep_atomic(qp, wr);
		break;
	case IBV_WR_LOCAL_INV:
		rc = ionic_v1_prep_inv(qp, wr);
		break;
	case IBV_WR_BIND_MW:
		rc = ionic_v1_prep_bind(qp, wr, send_path);
		break;
	default:
		verbs_warn(&ctx->vctx, "invalid opcode %d", wr->opcode);
		rc = EINVAL;
	}

	return rc;
}

static int ionic_v1_prep_one_ud(struct ionic_qp *qp,
				struct ibv_send_wr *wr)
{
	struct ionic_ctx *ctx = to_ionic_ctx(qp->vqp.qp.context);
	int rc = 0;

	switch (wr->opcode) {
	case IBV_WR_SEND:
	case IBV_WR_SEND_WITH_IMM:
		rc = ionic_v1_prep_send_ud(qp, wr);
		break;
	default:
		verbs_warn(&ctx->vctx, "invalid opcode %d", wr->opcode);
		rc = EINVAL;
	}

	return rc;
}

static void ionic_post_cmb_common(struct ionic_ctx *ctx,
				  struct ionic_queue *queue,
				  uint8_t cmb,
				  void *cmb_ptr,
				  uint16_t *cmb_prod,
				  uint8_t qtype,
				  uint32_t qpid)
{
	void *cmb_dst_ptr;
	void *wqe_src_ptr;
	uint32_t stride;
	uint16_t pos, end;
	uint8_t stride_log2, cmb_wc;

	stride_log2 = queue->stride_log2;

	pos = *cmb_prod;
	end = queue->prod;

	cmb_wc = !(cmb & IONIC_CMB_UC);

	if (cmb & IONIC_CMB_EXPDB) {
		/* Express doorbell mode: copy each WQE individually with barriers */
		while (pos != end) {
			cmb_dst_ptr = cmb_ptr + ((size_t)pos << stride_log2);
			wqe_src_ptr = ionic_queue_at(queue, pos);

			stride = 1u << stride_log2;
			do {
				udma_to_device_barrier();
				/* only fence before last 64B of each
				 * WC wqe, no need to mmio_wc_start()
				 */
				if (cmb_wc && stride <= 64)
					mmio_flush_writes();
				ionic_mmio_memcpy_x64_64(cmb_dst_ptr, wqe_src_ptr);

				stride -= 64;
				cmb_dst_ptr += 64;
				wqe_src_ptr += 64;
			} while (stride);

			pos = ionic_queue_next(queue, pos);
		}
	} else {
		/* Regular doorbell mode: bulk copy with wrap-around handling */
		if (pos > end) {
			/* Handle wrap-around case: copy from pos to end of ring */
			cmb_dst_ptr = cmb_ptr + ((size_t)pos << stride_log2);
			wqe_src_ptr = ionic_queue_at(queue, pos);
			stride = (uint32_t)(queue->mask - pos + 1) << stride_log2;

			ionic_mmio_memcpy_x64(cmb_dst_ptr, wqe_src_ptr, stride);

			pos = 0;
		}

		if (pos < end) {
			/* Copy from pos to end */
			cmb_dst_ptr = cmb_ptr + ((size_t)pos << stride_log2);
			wqe_src_ptr = ionic_queue_at(queue, pos);
			stride = (uint32_t)(end - pos) << stride_log2;

			ionic_mmio_memcpy_x64(cmb_dst_ptr, wqe_src_ptr, stride);

			pos = end;
		}

		if (cmb_wc)
			mmio_flush_writes();

		/* Ring doorbell */
		verbs_debug(&ctx->vctx, "dbell qp %u qtype %d val %" PRIx64,
			    qpid, qtype, queue->dbell | pos);
		ionic_dbell_ring(&ctx->dbpage[qtype], queue->dbell | pos);
	}

	*cmb_prod = end;
}

static void ionic_post_send_cmb(struct ionic_ctx *ctx, struct ionic_qp *qp)
{
	ionic_post_cmb_common(ctx,
			      &qp->sq.queue,
			      qp->sq.cmb,
			      qp->sq.cmb_ptr,
			      &qp->sq.cmb_prod,
			      ctx->sq_qtype,
			      qp->qpid);
}

static void ionic_post_recv_cmb(struct ionic_ctx *ctx, struct ionic_qp *qp)
{
	ionic_post_cmb_common(ctx,
			      &qp->rq.queue,
			      qp->rq.cmb,
			      qp->rq.cmb_ptr,
			      &qp->rq.cmb_prod,
			      ctx->rq_qtype,
			      qp->qpid);
}

static int ionic_post_send_common(struct ionic_ctx *ctx,
				  struct ionic_cq *cq,
				  struct ionic_qp *qp,
				  struct ibv_send_wr *wr,
				  struct ibv_send_wr **bad,
				  bool send_path)
{
	int spend, rc = 0;
	uint16_t old_prod;

	if (unlikely(!bad))
		return EINVAL;

	if (unlikely(!qp->has_sq)) {
		*bad = wr;
		return EINVAL;
	}

	if (unlikely(qp->vqp.qp.state < IBV_QPS_RTS)) {
		*bad = wr;
		return EINVAL;
	}

	ionic_sq_spin_lock(qp);

	old_prod = qp->sq.queue.prod;

	while (wr) {
		if (ionic_queue_full(&qp->sq.queue)) {
			verbs_info(&ctx->vctx,
				   "send queue full cons %u prod %u",
				   qp->sq.queue.cons, qp->sq.queue.prod);
			rc = ENOMEM;
			goto out;
		}

		if (qp->vqp.qp.qp_type == IBV_QPT_UD)
			rc = ionic_v1_prep_one_ud(qp, wr);
		else
			rc = ionic_v1_prep_one_rc(qp, wr, send_path);
		if (rc)
			goto out;

		wr = wr->next;
	}

out:
	old_prod = (qp->sq.queue.prod - old_prod) & qp->sq.queue.mask;

	if (ionic_cq_spin_trylock(cq)) {
		ionic_sq_spin_unlock(qp);
		ionic_cq_spin_lock(cq);
		ionic_sq_spin_lock(qp);
	}

	if (likely(qp->sq.queue.prod != qp->sq.old_prod)) {
		/* ring cq doorbell just in time */
		spend = (qp->sq.queue.prod - qp->sq.old_prod) & qp->sq.queue.mask;
		ionic_reserve_cq(ctx, cq, spend);

		qp->sq.old_prod = qp->sq.queue.prod;

		if (qp->sq.cmb_ptr) {
			ionic_post_send_cmb(ctx, qp);
		} else {
			udma_to_device_barrier();
			verbs_debug(&ctx->vctx, "dbell qp %u sq val %" PRIx64,
				    qp->qpid, ionic_queue_dbell_val(&qp->sq.queue));
			ionic_dbell_ring(&ctx->dbpage[ctx->sq_qtype],
					 ionic_queue_dbell_val(&qp->sq.queue));
		}
	}

	if (qp->sq.flush) {
		cq->flush = true;
		list_del(&qp->cq_flush_sq);
		list_add_tail(&cq->flush_sq, &qp->cq_flush_sq);
	}

	ionic_sq_spin_unlock(qp);
	ionic_cq_spin_unlock(cq);

	*bad = wr;
	return rc;
}

static int ionic_v1_prep_recv(struct ionic_qp *qp,
			      struct ibv_recv_wr *wr)
{
	struct ionic_ctx *ctx = to_ionic_ctx(qp->vqp.qp.context);
	struct ionic_rq_meta *meta;
	struct ionic_v1_wqe *wqe;
	int64_t signed_len;
	uint32_t mval;

	wqe = ionic_queue_at_prod(&qp->rq.queue);

	/* if wqe is owned by device, caller can try posting again soon */
	if (wqe->base.flags & htobe16(IONIC_V1_FLAG_FENCE))
		return -EAGAIN;

	meta = qp->rq.meta_head;
	if (unlikely(meta == IONIC_META_LAST) ||
	    unlikely(meta == IONIC_META_POSTED))
		return -EIO;

	ionic_prep_rq_wqe(qp, wqe);

	mval = ionic_v1_recv_wqe_max_sge(qp->rq.queue.stride_log2,
					 qp->rq.spec, qp->rq.cmb & IONIC_CMB_EXPDB);
	signed_len = ionic_v1_prep_pld(wqe, &wqe->recv.pld,
				       qp->rq.spec, mval,
				       wr->sg_list, wr->num_sge);
	if (signed_len < 0)
		return -signed_len;

	meta->wrid = wr->wr_id;

	wqe->base.wqe_idx = htole64(qp->rq.queue.prod);
	wqe->base.num_sge_key = wr->num_sge;

	qp->rq.meta_idx[qp->rq.queue.prod] = meta - qp->rq.meta;

	/* total length for recv goes in base imm_data_key */
	wqe->base.imm_data_key = htobe32(signed_len);

	verbs_debug(&ctx->vctx, "post recv %u prod %u",
		    qp->qpid, qp->rq.queue.prod);
	ionic_dbg_xdump(ctx, "wqe", wqe, 1u << qp->rq.queue.stride_log2);
	ionic_queue_produce(&qp->rq.queue);

	qp->rq.meta_head = meta->next;
	meta->next = IONIC_META_POSTED;

	return 0;
}

static int ionic_post_recv_common(struct ionic_ctx *ctx,
				  struct ionic_cq *cq,
				  struct ionic_qp *qp,
				  struct ibv_recv_wr *wr,
				  struct ibv_recv_wr **bad)
{
	int spend, rc = 0;
	uint16_t old_prod;

	if (unlikely(!bad))
		return EINVAL;

	if (unlikely(!qp->has_rq)) {
		*bad = wr;
		return EINVAL;
	}

	if (unlikely(qp->vqp.qp.state < IBV_QPS_INIT)) {
		*bad = wr;
		return EINVAL;
	}

	ionic_rq_spin_lock(qp);

	old_prod = qp->rq.queue.prod;

	while (wr) {
		if (ionic_queue_full(&qp->rq.queue)) {
			verbs_info(&ctx->vctx, "recv queue full cons %u prod %u",
				   qp->rq.queue.cons, qp->rq.queue.prod);
			rc = ENOMEM;
			goto out;
		}

		rc = ionic_v1_prep_recv(qp, wr);
		if (rc)
			goto out;

		wr = wr->next;
	}

out:
	old_prod = (qp->rq.queue.prod - old_prod) & qp->rq.queue.mask;

	if (!cq) {
		ionic_rq_spin_unlock(qp);
		goto out_unlocked;
	}

	if (ionic_cq_spin_trylock(cq)) {
		ionic_rq_spin_unlock(qp);
		ionic_cq_spin_lock(cq);
		ionic_rq_spin_lock(qp);
	}

	if (likely(qp->rq.queue.prod != qp->rq.old_prod)) {
		/* ring cq doorbell just in time */
		spend = (qp->rq.queue.prod - qp->rq.old_prod) & qp->rq.queue.mask;
		ionic_reserve_cq(ctx, cq, spend);

		qp->rq.old_prod = qp->rq.queue.prod;

		if (qp->rq.cmb_ptr) {
			ionic_post_recv_cmb(ctx, qp);
		} else {
			udma_to_device_barrier();
			verbs_debug(&ctx->vctx, "dbell qp %u rq val %" PRIx64,
				    qp->qpid,
				    ionic_queue_dbell_val(&qp->rq.queue));
			ionic_dbell_ring(&ctx->dbpage[ctx->rq_qtype],
					 ionic_queue_dbell_val(&qp->rq.queue));
		}
	}

	if (qp->rq.flush) {
		cq->flush = true;
		list_del(&qp->cq_flush_rq);
		list_add_tail(&cq->flush_rq, &qp->cq_flush_rq);
	}

	ionic_rq_spin_unlock(qp);
	ionic_cq_spin_unlock(cq);

out_unlocked:
	*bad = wr;

	return rc;
}

static int ionic_post_send(struct ibv_qp *ibqp,
			   struct ibv_send_wr *wr,
			   struct ibv_send_wr **bad)
{
	struct ionic_ctx *ctx = to_ionic_ctx(ibqp->context);
	struct ionic_qp *qp = to_ionic_qp(ibqp);
	struct ionic_cq *cq = to_ionic_vcq_cq(qp->vqp.qp.send_cq, qp->udma_idx);

	return ionic_post_send_common(ctx, cq, qp, wr, bad, true);
}

static int ionic_post_recv(struct ibv_qp *ibqp,
			   struct ibv_recv_wr *wr,
			   struct ibv_recv_wr **bad)
{
	struct ionic_ctx *ctx = to_ionic_ctx(ibqp->context);
	struct ionic_qp *qp = to_ionic_qp(ibqp);
	struct ionic_cq *cq = to_ionic_vcq_cq(qp->vqp.qp.recv_cq, qp->udma_idx);

	return ionic_post_recv_common(ctx, cq, qp, wr, bad);
}

static struct ibv_qp *ionic_create_qp(struct ibv_pd *ibpd,
				      struct ibv_qp_init_attr *attr)
{
	struct ibv_qp_init_attr_ex ex = {
		.qp_context = attr->qp_context,
		.send_cq = attr->send_cq,
		.recv_cq = attr->recv_cq,
		.srq = attr->srq,
		.cap = attr->cap,
		.qp_type = attr->qp_type,
		.sq_sig_all = attr->sq_sig_all,
		.comp_mask = IBV_QP_INIT_ATTR_PD,
		.pd = ibpd,
	};
	struct verbs_context *vctx;
	struct ibv_qp *ibqp;

	vctx = container_of(ibpd->context, struct verbs_context, context);
	ibqp = vctx->create_qp_ex(&vctx->context, &ex);

	attr->cap = ex.cap;

	return ibqp;
}

static struct ibv_ah *ionic_create_ah(struct ibv_pd *ibpd,
				      struct ibv_ah_attr *attr)
{
	struct ibv_pd *root_ibpd = to_ionic_root_ibpd(ibpd);
	struct uionic_ah_resp resp;
	struct ionic_ah *ah;
	int rc;

	ah = calloc(1, sizeof(*ah));
	if (!ah) {
		rc = errno;
		goto err_ah;
	}

	rc = ibv_cmd_create_ah(root_ibpd, &ah->ibah, attr,
			       &resp.ibv_resp, sizeof(resp));
	if (rc)
		goto err_cmd;

	ah->ahid = resp.ahid;

	return &ah->ibah;

err_cmd:
	free(ah);
err_ah:
	errno = rc;
	return NULL;
}

static int ionic_destroy_ah(struct ibv_ah *ibah)
{
	struct ionic_ah *ah = to_ionic_ah(ibah);
	int rc;

	rc = ibv_cmd_destroy_ah(ibah);
	if (rc)
		return rc;

	free(ah);

	return 0;
}

static struct ibv_mw *ionic_alloc_mw(struct ibv_pd *ibpd,
				     enum ibv_mw_type type)
{
	struct ibv_pd *root_ibpd = to_ionic_root_ibpd(ibpd);
	struct ib_uverbs_alloc_mw_resp resp;
	struct ibv_alloc_mw cmd;
	struct ibv_mw *ibmw;
	int rc;

	ibmw = calloc(1, sizeof(*ibmw));
	if (!ibmw) {
		rc = errno;
		goto err_mw;
	}

	rc = ibv_cmd_alloc_mw(root_ibpd, type, ibmw,
			      &cmd, sizeof(cmd),
			      &resp, sizeof(resp));
	if (rc)
		goto err_cmd;

	return ibmw;

err_cmd:
	free(ibmw);
err_mw:
	errno = rc;
	return NULL;
}

static int ionic_bind_mw(struct ibv_qp *ibqp, struct ibv_mw *ibmw,
			 struct ibv_mw_bind *bind)
{
	struct ionic_ctx *ctx = to_ionic_ctx(ibqp->context);
	struct ionic_qp *qp = to_ionic_qp(ibqp);
	struct ionic_cq *cq = to_ionic_vcq_cq(qp->vqp.qp.send_cq, qp->udma_idx);
	struct ibv_send_wr *bad;
	struct ibv_send_wr wr = {
		.opcode = IBV_WR_BIND_MW,
		.wr_id = bind->wr_id,
		.send_flags = bind->send_flags,
		.bind_mw = {
			.mw = ibmw,
			.rkey = ibmw->rkey,
			.bind_info = bind->bind_info,
		}
	};
	int rc;

	if (bind->bind_info.length)
		wr.bind_mw.rkey = ibv_inc_rkey(ibmw->rkey);

	rc = ionic_post_send_common(ctx, cq, qp, &wr, &bad, false);
	if (!rc)
		ibmw->rkey = wr.bind_mw.rkey;

	return rc;
}

static int ionic_dealloc_mw(struct ibv_mw *ibmw)
{
	int rc;

	rc = ibv_cmd_dealloc_mw(ibmw);
	if (rc)
		return rc;

	free(ibmw);

	return 0;
}

static void ionic_free_context(struct ibv_context *ibctx)
{
	struct ionic_ctx *ctx = to_ionic_ctx(ibctx);

	ionic_tbl_destroy(&ctx->qp_tbl);

	pthread_mutex_destroy(&ctx->mut);

	ionic_unmap(ctx->dbpage_page, 1u << ctx->pg_shift);

	verbs_uninit_context(&ctx->vctx);

	free(ctx);
}

bool is_ionic_ctx(struct ibv_context *ibctx)
{
	/* whatever we do here must be safe with non-ionic ibctx. */
	struct verbs_context *vctx = verbs_get_ctx_op(ibctx, alloc_parent_domain);

	return vctx && vctx->alloc_parent_domain == ionic_alloc_parent_domain;
}

static const struct verbs_context_ops ionic_ctx_ops = {
	.query_device_ex	= ionic_query_device_ex,
	.query_port		= ionic_query_port,
	.alloc_parent_domain	= ionic_alloc_parent_domain,
	.alloc_pd		= ionic_alloc_pd,
	.dealloc_pd		= ionic_dealloc_pd,
	.reg_dmabuf_mr		= ionic_reg_dmabuf_mr,
	.reg_mr			= ionic_reg_mr,
	.dereg_mr		= ionic_dereg_mr,
	.create_cq		= ionic_create_cq,
	.create_cq_ex		= ionic_create_cq_ex,
	.poll_cq		= ionic_poll_cq,
	.req_notify_cq		= ionic_req_notify_cq,
	.destroy_cq		= ionic_destroy_cq,
	.create_qp		= ionic_create_qp,
	.create_qp_ex		= ionic_create_qp_ex,
	.query_qp		= ionic_query_qp,
	.modify_qp		= ionic_modify_qp,
	.destroy_qp		= ionic_destroy_qp,
	.post_send		= ionic_post_send,
	.post_recv		= ionic_post_recv,
	.create_ah		= ionic_create_ah,
	.destroy_ah		= ionic_destroy_ah,
	.alloc_mw		= ionic_alloc_mw,
	.bind_mw		= ionic_bind_mw,
	.dealloc_mw		= ionic_dealloc_mw,
	.free_context		= ionic_free_context,
};

void ionic_verbs_set_ops(struct ionic_ctx *ctx)
{
	verbs_set_ops(&ctx->vctx, &ionic_ctx_ops);
}
