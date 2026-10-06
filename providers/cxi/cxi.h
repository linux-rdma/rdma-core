/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2025 HPE. All rights reserved.
 */

#ifndef CXI_H
#define CXI_H

#include <util/util.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>
#include <infiniband/driver.h>

enum cxi_builder_opcode {
	CXI_WR_RDMA_WRITE_WITH_IMM64 = 16,
	CXI_WR_RDMA_WRITE64_WITH_IMM,
	CXI_WR_RDMA_WRITE64_WITH_IMM64,
	CXI_WR_SEND_WITH_IMM64,
};

#include <rdma/cxiverbs-abi.h>

/*
 * Hardware ring/EQ definitions (struct cxi_cq, struct cxi_eq, cxi_cq_init(),
 * cxi_eq_init(), cxi_cq_emit_*(), cxi_build_dfa(), ...). The kernel keeps its
 * copy in include/linux/hpe/cxi/ rather than uapi, so the provider carries a
 * userspace copy that must be kept in step with it.
 */
#include "cxi_prov_hw.h"

/* PCI device IDs */
#define PCI_VENDOR_ID_CRAY 0x17db
#define PCI_DEVICE_ID_CASSINI_1 0x0501
#define PCI_VENDOR_ID_HPE 0x1590
#define PCI_DEVICE_ID_CASSINI_2 0x0371

/*
 * QPN encoding, mirrors the kernel's include/uapi/rdma/cxiverbs-abi.h:
 * bit 31 = addr_mode, bits[23:12] = Resource Index, bits[11:0] = PIDonFEP.
 * The Resource Index is the peer's PTE pid_offset, not a CXI service ID.
 */
#define CXI_QPN_PID_MASK 0xfffU
#define CXI_QPN_RI_SHIFT 12U
#define CXI_QPN_RI_MASK 0xfff000U

#define CXI_QPN_RI(qpn) (((qpn) & CXI_QPN_RI_MASK) >> CXI_QPN_RI_SHIFT)

#define CXI_MAX_QPS 1024U
#define CXI_QP_SLOT_BITS 10U
#define CXI_SEND_COOKIE_SLOT_BITS 11U
#define CXI_SEND_COOKIE_INDEX_BITS (CXI_QP_SLOT_BITS + CXI_SEND_COOKIE_SLOT_BITS)
#define CXI_QP_SLOT_MASK ((1U << CXI_QP_SLOT_BITS) - 1)
#define CXI_SEND_COOKIE_SLOT_MASK ((1U << CXI_SEND_COOKIE_SLOT_BITS) - 1)
#define CXI_SEND_COOKIE_GENERATION_MAX (UINT64_MAX >> CXI_SEND_COOKIE_INDEX_BITS)

struct cxi_device {
	struct verbs_device verbs_dev;
	int page_size;
};

struct cxi_context {
	struct verbs_context verbs_ctx;
	uint32_t nid; /* this port's NIC address */
	uint32_t pid_bits; /* width of the PID field in match/DFA encoding */
	uint32_t preferred_svc_id;
	uint32_t tc;
	bool tc_valid;
	pthread_mutex_t tc_lock;
	/*
	 * Device-wide HW properties fetched once via query_device's
	 * driver-specific response (see cxi_ibv_devinfo, kernel-headers/
	 * rdma/cxiverbs-abi.h). Exposed to callers outside this provider through
	 * cxidv_query_device() (cxidv.h), since a plain libibverbs consumer
	 * has no other way to reach this data.
	 */
	struct cxi_ibv_devinfo devinfo;
	pthread_spinlock_t qp_table_lock;
	atomic_uint_fast64_t send_cookie_seq;
	struct cxi_qp *qp_slots[CXI_MAX_QPS];
	struct cxi_qp *qp_by_pte[CXI_MAX_QPS];
	uint32_t qp_count;
	pthread_spinlock_t mr_list_lock;
	struct cxi_mr *mr_list;
};

struct cxi_job_key {
	struct ibv_job_key key;
	struct ibv_job *job;
	uint32_t job_id;
	struct cxi_job_key *next;
};

struct cxi_pd {
	struct ibv_pd ibv_pd;
	uint32_t pd_id;
	uint32_t pidonfep;
	bool pid_valid;
	pthread_spinlock_t jkey_lock;
	struct cxi_job_key *jkeys;
};

struct cxi_mr {
	struct verbs_mr vmr;
	struct cxi_ibv_mr_info info;
	uint64_t rkey64;
	uint64_t lkey64;
	uint64_t va;
	uint64_t iova;
	size_t len;
	struct cxi_mr *next;
};

/*
 * ibv_cq wrapper. Named cxi_ibv_cq (rather than cxi_cq) because cxi_prov_hw.h
 * already defines "struct cxi_cq" for the hardware TXQ/TGQ ring state, which
 * this struct embeds as hw_eq below (an EQ, not a CQ, but same ring machinery).
 */
struct cxi_ibv_cq {
	struct verbs_cq verbs_cq;
	struct cxi_eq hw_eq; /* ring state for polling; see cxi_eq_init() */
	void *eq_buf; /* mmap'd event-ring buffer */
	size_t eq_buf_size;
	void *eq_db; /* mmap'd EQ doorbell/CSR */
	size_t eq_db_size;
	uint32_t eqn;
	uint32_t cqe;
	struct ibv_wc cur_wc; /* completion the ibv_cq_ex cursor is on */
	__be64 cur_imm64; /* wide immediate for cur_wc, if any */
	uint32_t cur_job_id; /* sender's JobID for cur_wc (== VNI) */
	uint32_t cur_src_id; /* sender-chosen src_id for cur_wc */
	pthread_spinlock_t lock;
};

struct cxi_qp {
	struct verbs_qp vqp;
	struct cxi_cq hw_txq; /* ring state for posting; see cxi_cq_init() */
	void *txq_cmds; /* mmap'd TXQ command ring */
	size_t txq_cmds_size;
	void *txq_db; /* mmap'd TXQ doorbell */
	size_t txq_db_size;
	uint32_t txq_idx;
	uint32_t lcid;
	uint32_t src_id; /* reported to peers; see IBV_RU_ATTR_SRC_ID */
	struct ibv_job *job;
	uint32_t job_id; /* JobID (VNI) the QP was created under */
	struct cxi_cq hw_tgq; /* ring state for posting receives */
	void *tgq_cmds; /* mmap'd TGQ command ring */
	size_t tgq_cmds_size;
	void *tgq_db; /* mmap'd TGQ doorbell */
	size_t tgq_db_size;
	uint32_t tgq_idx;
	int pte_index; /* set once modify_qp reaches RTR, else -1 */
	uint32_t sq_size;
	uint32_t rq_size;
	struct cxi_ibv_cq *send_cq;
	uint32_t qp_slot;
	uint64_t *send_wrids;
	/* An ACK does not say what was sent, so remember it. */
	uint8_t *send_opcodes;
	uint32_t *send_job_ids;
	uint64_t *send_cookies;
	bool *send_slot_valid;
	uint32_t send_tail;
	uint32_t send_count;
	uint64_t *recv_wrids;
	uint32_t recv_head;
	uint32_t recv_tail;
	uint32_t recv_count;
	pthread_spinlock_t sq_lock;
	pthread_spinlock_t rq_lock;
	pthread_mutex_t builder_lock;

	/* ibv_qp_ex work-request builder state; see cxi_wr_start() in verbs.c. */
	struct cxi_wr_build {
		int err;

		/* Fields for the work request currently being built, if any. */
		bool have_wr;
		uint64_t wr_id;
		unsigned int opcode;
		struct cxi_ah *ah;
		uint32_t remote_qpn;
		uint32_t remote_nid;
		uint32_t jkey;
		uint32_t job_id;
		uint32_t send_slot;
		uint64_t remote_addr;
		uint64_t rkey64;
		uint64_t local_addr;
		uint64_t lkey;
		bool sge64;
		uint32_t length;
		bool has_sge;
		bool has_addr;
		bool has_imm;
		bool imm_is64;
		__be32 imm32;
		__be64 imm64;
	} wr_build;
	struct cxi_wr_build *pending_wrs;
	size_t pending_count;
	size_t pending_capacity;
};

struct cxi_ah {
	struct ibv_ah_ex ah_ex;
	uint32_t ah_id;
	/*
	 * Extracted from the GID the same way as the kernel's
	 * cxi_gid_to_nid(). ah_ex.remote_qpn (0 unless created via
	 * cxi_create_ah_ex()/ibv_insert_addr()) carries the peer's
	 * PIDonFEP/RI, per Phase 3 of cxi-rdma-path-audit.md.
	 */
	uint32_t nid;
};

static inline struct cxi_device *to_cxi_dev(struct ibv_device *ibv_dev)
{
	return container_of(ibv_dev, struct cxi_device, verbs_dev.device);
}

static inline struct cxi_context *to_cxi_ctx(struct ibv_context *ibv_ctx)
{
	return container_of(ibv_ctx, struct cxi_context, verbs_ctx.context);
}

static inline struct cxi_pd *to_cxi_pd(struct ibv_pd *ibv_pd)
{
	return container_of(ibv_pd, struct cxi_pd, ibv_pd);
}

static inline struct cxi_mr *to_cxi_mr(struct ibv_mr *ibv_mr)
{
	return container_of(ibv_mr, struct cxi_mr, vmr.ibv_mr);
}

static inline struct cxi_ibv_cq *to_cxi_ibv_cq(struct ibv_cq *ibv_cq)
{
	return container_of(ibv_cq, struct cxi_ibv_cq, verbs_cq.cq);
}

static inline struct cxi_ibv_cq *to_cxi_ibv_cq_ex(struct ibv_cq_ex *cq_ex)
{
	return container_of(cq_ex, struct cxi_ibv_cq, verbs_cq.cq_ex);
}

static inline struct cxi_qp *to_cxi_qp(struct ibv_qp *ibv_qp)
{
	return container_of(ibv_qp, struct cxi_qp, vqp.qp);
}

static inline struct cxi_ah *to_cxi_ah(struct ibv_ah *ibv_ah)
{
	struct ibv_ah_ex *ah_ex = container_of(ibv_ah, struct ibv_ah_ex, ah_base);

	return container_of(ah_ex, struct cxi_ah, ah_ex);
}

static inline struct cxi_ah *to_cxi_ah_ex(struct ibv_ah_ex *ah_ex)
{
	return container_of(ah_ex, struct cxi_ah, ah_ex);
}

#endif /* CXI_H */
