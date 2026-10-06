/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2026 Hewlett Packard Enterprise Development LP
 */

/*
 * Direct-verbs extension for the CXI provider.
 *
 * Standard ibv_query_device()/ibv_query_device_ex() cover the generic
 * device attributes (max_qp, max_cq, vendor_id, ...). CXI has additional
 * device-wide HW properties (NIC address, PID space geometry, resource
 * counts, ...) with no standard ibverbs equivalent; this header exposes
 * those, mirroring the mlx5dv.h / efadv.h pattern used by other rdma-core
 * providers for vendor-specific data.
 */

#ifndef __CXIDV_H__
#define __CXIDV_H__

#include <stdint.h>
#include <infiniband/verbs.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cxidv_lni {
	struct ibv_context *context;
	uint32_t handle;
	uint32_t id;
	uint32_t svc_id;
};

enum cxidv_pid_flags {
	CXIDV_PID_ABSOLUTE = 1U << 0,
};

enum cxidv_svc_flags {
	CXIDV_SVC_LIMITS = 1U << 0,
	CXIDV_SVC_CREATE_TC = 1U << 1,
	CXIDV_SVC_ENABLED = 1U << 2,
};

enum cxidv_svc_resource {
	CXIDV_SVC_PTES,
	CXIDV_SVC_TXQS,
	CXIDV_SVC_TGQS,
	CXIDV_SVC_EQS,
	CXIDV_SVC_CTS,
	CXIDV_SVC_ACS,
	CXIDV_SVC_TLES,
	CXIDV_SVC_LES,
	CXIDV_SVC_RSRC_COUNT,
};

#define CXIDV_SVC_MAX_VNIS 4

struct cxidv_svc_attr {
	uint32_t svc_id;
	/* Reserved; must be zero. */
	uint16_t vni_min;
	uint16_t vni_max;
	/* Exact-list length; zero means system-empty or is_range. */
	uint32_t vni_count;
	/* System service requires CAP_SYS_ADMIN; allocation svc_id is zero. */
	uint32_t is_system_svc;
	/* Inclusive range endpoints are carried in vnis[0] and vnis[1]. */
	uint32_t is_range;
	uint16_t vnis[CXIDV_SVC_MAX_VNIS];
	uint32_t tc_mask;
	uint32_t uid;
	uint32_t flags;
	uint16_t maximum[CXIDV_SVC_RSRC_COUNT];
	uint16_t reserved[CXIDV_SVC_RSRC_COUNT];
};

int cxidv_alloc_svc(struct ibv_context *context, const struct cxidv_svc_attr *attr,
		    uint32_t *svc_id);
int cxidv_query_svc(struct ibv_context *context, uint32_t svc_id, struct cxidv_svc_attr *attr);

struct cxidv_svc_rsrc_use {
	uint32_t svc_id;
	uint32_t tle_pool_id;
	uint16_t in_use[CXIDV_SVC_RSRC_COUNT];
};

int cxidv_get_svc_rsrc_use(struct ibv_context *context, uint32_t svc_id,
			   struct cxidv_svc_rsrc_use *usage);
int cxidv_get_svc_lpr(struct ibv_context *context, uint32_t svc_id, uint32_t *lpr);
int cxidv_destroy_svc(struct ibv_context *context, uint32_t svc_id);
int cxidv_enable_svc(struct ibv_context *context, uint32_t svc_id, int enable);
int cxidv_svc_is_enabled(struct ibv_context *context, uint32_t svc_id, int *enable);

enum cxidv_traffic_class {
	CXIDV_TC_DEDICATED_ACCESS,
	CXIDV_TC_LOW_LATENCY,
	CXIDV_TC_BULK_DATA,
	CXIDV_TC_BEST_EFFORT,
	CXIDV_TC_ETH,
};

int cxidv_alloc_lni(struct ibv_context *context, uint32_t svc_id, struct cxidv_lni **lni);
int cxidv_destroy_lni(struct cxidv_lni *lni);
struct ibv_pd *cxidv_alloc_pd(struct cxidv_lni *lni);

struct cxidv_cp {
	struct cxidv_lni *lni;
	uint32_t handle;
	uint32_t vni;
	uint32_t tc;
	uint32_t type;
	uint32_t lcid;
};

int cxidv_alloc_cp(struct cxidv_lni *lni, uint32_t vni, uint32_t tc, uint32_t type,
		   struct cxidv_cp **out);
int cxidv_destroy_cp(struct cxidv_cp *cp);

struct cxidv_ct {
	struct cxidv_lni *lni;
	uint32_t handle;
	uint32_t ctn;
	void *writeback;
	size_t writeback_size;
	uint64_t writeback_offset;
	void *doorbell;
	size_t doorbell_size;
};

int cxidv_alloc_ct(struct cxidv_lni *lni, struct cxidv_ct **out);
int cxidv_inbound_wait(struct ibv_context *context);
int cxidv_alloc_ct_writeback(struct cxidv_lni *lni, void *writeback, struct cxidv_ct **out);
int cxidv_destroy_ct(struct cxidv_ct *ct);

struct cxidv_cmdq {
	struct cxidv_lni *lni;
	uint32_t handle;
	uint32_t count;
	uint32_t index;
	void *commands;
	size_t commands_size;
	uint64_t commands_offset;
	void *doorbell;
	size_t doorbell_size;
};

int cxidv_alloc_cmdq(struct cxidv_lni *lni, uint32_t count, struct cxidv_cmdq **out);
int cxidv_alloc_trigger_cmdq(struct cxidv_lni *lni, uint32_t count, struct cxidv_cmdq **out);
int cxidv_destroy_cmdq(struct cxidv_cmdq *cmdq);

struct cxidv_wait {
	struct cxidv_lni *lni;
	int fd;
	/* Library-managed usage count; applications must treat this as read-only. */
	unsigned int users;
};

/*
 * A wait object remains valid until cxidv_destroy_wait() succeeds.
 *
 * If another object still references the wait, or another thread is creating
 * such a reference, cxidv_destroy_wait() returns EBUSY and does not close/free
 * the wait object. Callers may retry destroy after dependent objects are
 * destroyed.
 *
 * Callers must prevent new operations using this pointer from starting while
 * final destruction is in progress; a raw pointer cannot protect an operation
 * that has not yet acquired its library-managed reference.
 */
int cxidv_alloc_wait(struct cxidv_lni *lni, struct cxidv_wait **out);
int cxidv_destroy_wait(struct cxidv_wait *wait);

enum cxidv_eq_flags {
	CXIDV_EQ_REGISTER_PCT = 1U << 0,
	CXIDV_EQ_PASSTHROUGH = 1U << 1,
};

struct cxidv_eq_attr {
	void *queue;
	size_t length;
	uint32_t threshold_base;
	uint32_t threshold_delta;
	uint32_t threshold_count;
	uint32_t ec_delay;
	uint32_t cpu;
	uint32_t reserved_slots;
	uint32_t flags;
	struct cxidv_wait *event_wait;
	struct cxidv_wait *status_wait;
};

struct cxidv_eq {
	struct cxidv_lni *lni;
	struct cxidv_wait *event_wait;
	struct cxidv_wait *status_wait;
	uint32_t handle;
	uint32_t eqn;
	void *doorbell;
	size_t doorbell_size;
};

int cxidv_alloc_eq(struct cxidv_lni *lni, struct ibv_mr *mr, const struct cxidv_eq_attr *attr,
		   struct cxidv_eq **out);
int cxidv_destroy_eq(struct cxidv_eq *eq);

struct cxidv_csr {
	struct ibv_context *context;
	uint32_t handle;
	void *address;
	size_t length;
	uint64_t mmap_offset;
};

int cxidv_map_csrs(struct ibv_context *context, struct cxidv_csr **out);
int cxidv_unmap_csrs(struct cxidv_csr *csr);
int cxidv_read_csr(const struct cxidv_csr *csr, uint64_t offset, void *value, size_t length);
int cxidv_write_csr(const struct cxidv_csr *csr, uint64_t offset, const void *value, size_t length);
int cxidv_write8_csr(const struct cxidv_csr *csr, uint64_t offset, uint8_t value);

int cxidv_alloc_pid(struct ibv_pd *pd, uint32_t flags, uint32_t *pid);
int cxidv_query_pid(struct ibv_pd *pd, uint32_t *pid);

enum cxidv_cassini_version {
	CXIDV_CASSINI_1_0 = 1,
	CXIDV_CASSINI_1_1 = 2,
	CXIDV_CASSINI_2_0 = 4,
};

enum cxidv_system_type_identifier {
	CXIDV_SYSTEM_TYPE_CASSINI_1_ONLY = 0,
	CXIDV_SYSTEM_TYPE_CASSINI_2_ONLY = 1,
	CXIDV_SYSTEM_TYPE_MIXED = 2,
};

/*
 * Device-wide HW properties. Field layout is this header's own stable ABI,
 * not a copy of the kernel's internal cxi_ibv_devinfo layout, so the two can
 * evolve independently.
 */
struct cxidv_devinfo {
	uint32_t nid; /* 20-bit NIC address (NID) of this port */
	uint32_t pid_bits; /* width of the PID field (6-9 bits) */
	uint32_t pid_count; /* number of PIDs per VNI */
	uint32_t pid_granule; /* PID space granularity */
	uint32_t min_free_shift;
	uint32_t rdzv_get_idx;
	uint32_t vendor_id;
	uint32_t device_id;
	uint32_t device_rev;
	uint32_t device_proto;
	uint32_t device_platform;
	uint32_t pct_eq;
	int32_t uc_nic;
	uint64_t link_mtu;
	uint64_t link_speed;
	uint8_t link_state;
	uint16_t num_ptes;
	uint16_t num_txqs;
	uint16_t num_tgqs;
	uint16_t num_eqs;
	uint16_t num_cts;
	uint16_t num_acs;
	uint16_t num_tles;
	uint16_t num_les;
	uint32_t cassini_version; /* enum cxidv_cassini_version */
	uint32_t system_type_identifier; /* enum cxidv_system_type_identifier */
	char fru_description[16];
};

/*
 * Returns 0 and fills @attr on success. Returns EOPNOTSUPP if @ibvctx is not
 * a CXI device, or if the driver couldn't fetch this data at context-open
 * time (see cxi_alloc_context() in cxi.c).
 */
int cxidv_query_device(struct ibv_context *ibvctx, struct cxidv_devinfo *attr);

struct cxidv_mr_info {
	uint64_t va;
	uint64_t iova;
	uint64_t length;
	int32_t page_shift;
	int32_t huge_shift;
	uint32_t id;
	uint32_t lac;
};

int cxidv_mr_from_ibv_mr(struct ibv_mr *mr, struct cxidv_mr_info *info);
struct ibv_mr *cxidv_reg_native_mr(struct ibv_pd *pd, void *address, size_t length, uint32_t flags);

/*
 * Direct access to the CXI EQ backing an ibv_cq, for a consumer (libcxi)
 * that needs to poll the hardware ring directly rather than through
 * ibv_poll_cq(). ibv_create_cq()/ibv_destroy_cq() still own the CQ's
 * lifetime; this just exposes what the provider already mmap'd for its own
 * internal use (mirrors the mlx5dv_init_obj()/efadv_create_cq() pattern).
 */
struct cxidv_cq {
	uint64_t comp_mask;
	void *eq_buf; /* mmap'd event-ring buffer */
	uint64_t eq_buf_size;
	void *eq_db; /* mmap'd EQ doorbell/CSR */
	uint64_t eq_db_size;
	uint32_t eqn; /* hardware EQ index */
};

/*
 * Returns 0 and fills @attr on success. Returns EOPNOTSUPP if @ibvcq was not
 * created against a CXI device.
 */
int cxidv_cq_from_ibv_cq(struct ibv_cq *ibvcq, struct cxidv_cq *attr);

/*
 * Direct access to the TXQ/TGQ/PTE state backing an ibv_qp, for a consumer
 * (libcxi) that needs to post commands directly onto the hardware rings
 * rather than through ibv_post_send()/ibv_post_recv(). ibv_create_qp_ex()/
 * ibv_destroy_qp() still own the QP's lifetime; this just exposes what the
 * provider already mmap'd for its own internal use.
 *
 * pte_index is only valid once the QP has reached RTR (modify_qp); -1
 * otherwise, mirroring struct cxi_qp's own convention.
 */
struct cxidv_qp {
	uint64_t comp_mask;
	void *txq_cmds;
	uint64_t txq_cmds_size;
	void *txq_db;
	uint64_t txq_db_size;
	uint32_t txq_idx;
	uint32_t lcid;
	void *tgq_cmds;
	uint64_t tgq_cmds_size;
	void *tgq_db;
	uint64_t tgq_db_size;
	uint32_t tgq_idx;
	int32_t pte_index;
};

/*
 * Returns 0 and fills @attr on success. Returns EOPNOTSUPP if @ibvqp was not
 * created against a CXI device.
 */
int cxidv_qp_from_ibv_qp(struct ibv_qp *ibvqp, struct cxidv_qp *attr);

/*
 * Change the src_id (see IBV_RU_ATTR_SRC_ID) @ibvqp reports to its peers.
 * Takes effect on the next work request posted; anything already built
 * (posted or staged via the ibv_qp_ex builder but not yet flushed) keeps
 * whatever value was in effect when it was built. Returns EOPNOTSUPP if
 * @ibvqp was not created against a CXI device.
 */
int cxidv_modify_qp_src_id(struct ibv_qp *ibvqp, uint32_t src_id);

enum cxidv_job_tc_flags {
	CXIDV_JOB_TC_F_CREATE = 1U << 0,
};

struct cxidv_limits {
	uint16_t max;
	uint16_t res;
};

struct cxidv_job_tc_attr {
	uint32_t flags;
	uint32_t job_id;
	uint32_t svc_id; /* existing service to bind, 0 = allocate one */
	uint32_t tc;
	uint32_t tc_type;
	struct cxidv_limits ptes;
	struct cxidv_limits txqs;
	struct cxidv_limits tgqs;
	struct cxidv_limits eqs;
	struct cxidv_limits cts;
	struct cxidv_limits les;
	struct cxidv_limits tles;
	struct cxidv_limits acs;
	uint32_t bound_svc_id;
};

int cxidv_bind_job_tc(struct ibv_context *ibvctx, struct cxidv_job_tc_attr *attr);
int cxidv_clear_job_tc(struct ibv_context *ibvctx, uint32_t tc, uint32_t tc_type);

/*
 * Select the traffic class subsequent QPs on @ibvctx are created with, without
 * provisioning anything. Use this to run on an already-configured TC;
 * cxidv_bind_job_tc() is only needed to create a TC or a JobID service.
 *
 * Cached updates from this function and cxidv_bind_job_tc() are synchronized
 * with concurrent QP creation. Each QP uses the cached traffic class observed
 * when the provider snapshots it during creation; a concurrent update may
 * therefore affect that QP or a later one.
 */
int cxidv_set_default_tc(struct ibv_context *ibvctx, uint32_t tc);

struct cxidv_tc_entry {
	uint32_t tc;
	uint32_t tc_type;
	uint32_t res_req_dscp;
	uint32_t unres_req_dscp;
	uint32_t res_rsp_dscp;
	uint32_t unres_rsp_dscp;
	uint32_t req_pcp;
	uint32_t rsp_pcp;
	uint32_t ocuset;
	uint32_t cq_tc;
	uint32_t req_bc;
	uint32_t flags;
};

#define CXIDV_TC_ENTRY_F_CREATED_BY_RDMA (1U << 0)

int cxidv_query_tcs(struct ibv_context *ibvctx, struct cxidv_tc_entry *entries,
		    uint32_t max_entries, uint32_t *count);

#ifdef __cplusplus
}
#endif

#endif /* __CXIDV_H__ */
