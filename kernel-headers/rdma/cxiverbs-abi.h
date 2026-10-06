/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2025 Hewlett Packard Enterprise Development LP
 *
 * User-space ABI for the CXI InfiniBand RDMA driver.
 * This header is shared between the kernel driver and the libcxi_verbs
 * user-space provider in rdma-core.
 *
 * QPN encoding (UEC-aligned):
 *   bit  31     : addr_mode (1 = absolute, 0 = job-relative)
 *   bits [23:12]: Resource Index (PID-slice receive selector, not service ID)
 *   bits [11:0] : PIDonFEP (process-endpoint address bits)
 */

#ifndef __UAPI_RDMA_CXI_ABI_H__
#define __UAPI_RDMA_CXI_ABI_H__

#include <linux/types.h>

#define CXI_IB_UVERBS_ABI_VERSION 1
#define CXI_IBV_LNI_ANY 0xffffffffU

/*
 * alloc_ucontext / GET_CONTEXT
 *
 * GET_CONTEXT opens the uverbs device and returns static CXI geometry.
 * Privileged ibv_alloc_job() creates a device-scoped job; it does not allocate
 * an LNI or bind the ucontext. LNIs are allocated explicitly and selected by
 * PDs. QPs require a job key belonging to their PD. PIDonFEP may be supplied
 * as an optional default for later QP creation.
 */
enum cxi_ibv_alloc_ucontext_mask {
	CXI_IBV_ALLOC_UCONTEXT_PIDONFEP = 1U << 0,
};

#define CXI_IBV_SERVICE_ID_MAX 0xfffU
#define CXI_IBV_JOB_ID_MAX 0xffffU
#define CXI_IBV_PIDONFEP_MAX 0xfffU

/*
 * A Slingshot GID is just the 20-bit NID: subnet_prefix is zero and the NID
 * sits in the low bits of interface_id. Userspace never needs to know that -
 * it exchanges GIDs like any other transport - but a GID handed back to this
 * device must fit, or it names something we cannot reach.
 */
#define CXI_IBV_NID_MASK 0xfffffULL

struct cxi_ibv_alloc_ucontext_cmd {
	__u32 comp_mask; /* enum cxi_ibv_alloc_ucontext_mask */
	__u32 pidonfep; /* UET PIDonFEP (optional default) */
};

/*
 * TC capacity limits (one per traffic class, 0-7).
 * Used to report per-JobID resource allocation.
 */
struct cxi_ibv_tc_limit {
	__u32 tc; /* traffic class 0-7 */
	__u32 max_ptes; /* max portal table entries for this TC */
	__u32 max_cps; /* max communication profiles for this TC */
	__u32 max_qps; /* max queue pairs for this TC */
	__u32 reserved; /* for future use */
};

#define CXI_IBV_TC_MAX 8 /* 0-7 traffic classes */

struct cxi_ibv_alloc_ucontext_resp {
	__u32 nid; /* 20-bit NIC address (NID) of this port */
	__u32 pid_bits; /* width of the PID field (6–9 bits) */
	__u32 pid_count; /* number of PIDs per VNI */
	__u32 pid_granule; /* PID space granularity */
	__u32 lni_id; /* Zero; LNIs are allocated explicitly */
	__u32 num_tc_limits; /* number of valid tc_limits[] entries */
	/* variable-length tc_limits[] follows if num_tc_limits > 0 */
};

/*
 * alloc_pd / ALLOC_PD
 *
 * The protection domain selects an explicitly allocated LNI. A nonzero
 * preferred_svc_id must match that LNI's service; zero means no preference.
 */
enum cxi_ibv_alloc_pd_mask {
	CXI_IBV_ALLOC_PD_SVC_ID_PREFERRED = 1U << 0,
	CXI_IBV_ALLOC_PD_LNI = 1U << 1,
};

struct cxi_ibv_alloc_pd_cmd {
	__u32 comp_mask; /* enum cxi_ibv_alloc_pd_mask */
	__u32 preferred_svc_id; /* optional preferred service for QPs (0 = any) */
	__u32 lni_handle;
	__u32 reserved;
};

struct cxi_ibv_alloc_pd_resp {
	__u32 pd_id; /* RGID-based PD identifier (informational) */
	__u32 pad;
};

/*
 * create_cq / CREATE_CQ
 *
 * The driver allocates a CXI Event Queue (EQ) of the requested size and
 * maps the ring buffer and doorbell CSR into user space.
 *
 * After create_cq succeeds:
 *   - eq_buf_offset / eq_buf_size : mmap offset+size for the event-ring buffer
 *     (user polls this for completions)
 *   - eq_db_offset / eq_db_size   : mmap offset+size for the EQ doorbell/CSR
 *     (user writes here to arm notifications)
 *   - eqn                         : hardware EQ index
 */
struct cxi_ibv_create_cq_cmd {
	__u32 n_entries; /* requested event-ring depth in entries */
	__u32 cpu_affinity; /* NUMA / CPU affinity hint for IRQ steering */
	__u32 lni_handle;
	__u32 reserved;
};

struct cxi_ibv_create_cq_resp {
	__u64 eq_buf_offset; /* mmap offset for event-ring buffer */
	__u64 eq_buf_size; /* event-ring buffer size in bytes */
	__u64 eq_db_offset; /* mmap offset for EQ doorbell (CSR) */
	__u64 eq_db_size; /* doorbell region size in bytes */
	__u32 eqn; /* hardware EQ index */
	__u32 pad;
};

/*
 * create_qp / CREATE_QP
 *
 * On creation the driver allocates:
 *   - a CXI Domain (VNI + PID)
 *   - a Communication Profile (CP → LCID)
 *   - a transmit CQ (TXQ)
 *   - a target CQ (TGQ)
 *   - a Portal Table Entry (PTE) for receive matching
 *
 * The QP uses its required PD job key's JobID. svc_id selects the CXI
 * service/resource pool for this QP,
 * independently of its Resource Index, and must match the PD's LNI service.
 * If omitted, the driver uses that service. TC
 * defaults to CXI_TC_BEST_EFFORT unless overridden. match_bits / match_mask
 * control the portal-level receive filter (0 / 0 = accept all).
 *
 * After create_qp succeeds:
 *   - txq_cmds_offset / txq_cmds_size : mmap offset+size for the TXQ command
 *     ring (user writes commands here)
 *   - txq_db_offset / txq_db_size     : mmap offset+size for the TXQ doorbell
 *   - txq_idx                         : TXQ hardware CQ index (0–1023)
 *   - lcid                            : LCID assigned to this QP (from CP)
 *   - tgq_cmds_offset / tgq_cmds_size : mmap offset+size for the TGQ command
 *     ring (user appends receive buffers here)
 *   - tgq_db_offset / tgq_db_size     : mmap offset+size for the TGQ doorbell
 *   - tgq_idx                         : TGQ hardware CQ index (1024–1535)
 *
 * The PTE hardware index needed to post receives is not known until the QP
 * reaches RTR (see cxi_ibv_modify_qp_resp below).
 */
enum cxi_ibv_create_qp_mask {
	CXI_IBV_CREATE_QP_SVC_ID = 1U << 0,
	CXI_IBV_CREATE_QP_TC = 1U << 1,
};

struct cxi_ibv_create_qp_cmd {
	__u32 comp_mask; /* enum cxi_ibv_create_qp_mask */
	__u32 svc_id; /* optional CXI service (resource-limit pool) */
	__u32 tc; /* enum cxi_traffic_class */
	__u32 uec_qp_type; /* UEC QP type (reserved; use 0 until spec final) */
	__u32 pad;
	__u64 match_bits; /* portal match bits (0 = match all) */
	__u64 match_mask; /* matching mask (0 = match all) */
};

struct cxi_ibv_create_qp_resp {
	__u64 txq_cmds_offset; /* mmap offset for TXQ command ring */
	__u64 txq_cmds_size; /* TXQ command ring size in bytes */
	__u64 txq_db_offset; /* mmap offset for TXQ doorbell */
	__u64 txq_db_size; /* TXQ doorbell size in bytes */
	__u32 txq_idx; /* TXQ hardware index (0–1023) */
	__u32 lcid; /* LCID assigned to this QP */
	__u64 tgq_cmds_offset; /* mmap offset for TGQ command ring */
	__u64 tgq_cmds_size; /* TGQ command ring size in bytes */
	__u64 tgq_db_offset; /* mmap offset for TGQ doorbell */
	__u64 tgq_db_size; /* TGQ doorbell size in bytes */
	__u32 tgq_idx; /* TGQ hardware index (1024–1535, see cxi_cq_get_cqn()) */
	__u32 job_id; /* JobID (VNI) the QP was created under */
	__u32 pte_index;
	__u32 reserved;
};

/*
 * modify_qp / MODIFY_QP (extended)
 *
 * The PTE is mapped into the domain during the INIT->RTR transition, so its
 * hardware index is not known at create_qp time. Returned here instead.
 */
struct cxi_ibv_modify_qp_resp {
	__u32 pte_index; /* hardware PTLTE index, valid once QP reaches RTR */
	__u32 pad;
};

/*
 * query_device / QUERY_DEVICE  (driver-specific extended response)
 *
 * When the user-space provider calls ibv_query_device_ex(), the kernel
 * returns this struct as driver-specific data (via udata->out).
 * The caller must pass at least sizeof(cxi_ibv_query_device_resp) bytes
 * in the output buffer; unused bytes are zeroed.
 *
 * features:
 *   CXI_DEVICE_CAP_UEC_QPN        - QPN uses UEC bit-31 addr_mode encoding
 *   CXI_DEVICE_CAP_TRIGGERED_OPS  - counting triggers / triggered operations
 *   CXI_DEVICE_CAP_ODP            - on-demand paging MRs
 *
 * max_ctn: highest counting-trigger number (inclusive) this device supports.
 */
#define CXI_DEVICE_CAP_UEC_QPN (1U << 0)
#define CXI_DEVICE_CAP_TRIGGERED_OPS (1U << 1)
#define CXI_DEVICE_CAP_ODP (1U << 2)

/*
 * Device-wide HW properties that the native ABI exposes via the
 * DEV_INFO_GET ioctl (struct cxi_dev_info_use in uapi/ethernet/cxi-abi.h).
 * The RDMA path has no ioctl/sysfs control channel, so it must return the
 * same information here instead. Field-for-field mirror of that struct,
 * kept separate (rather than #include'd) so this ABI header doesn't pull
 * in the native ioctl definitions it has no use for; keep the two in sync.
 */
struct cxi_ibv_devinfo {
	__u32 nid;
	__u32 pid_bits;
	__u32 pid_count;
	__u32 pid_granule;
	__u32 min_free_shift;
	__u32 rdzv_get_idx;
	__u32 vendor_id;
	__u32 device_id;
	__u32 device_rev;
	__u32 device_proto;
	__u32 device_platform;
	__u32 pct_eq;
	__s32 uc_nic;
	__u64 link_mtu;
	__u64 link_speed;
	__u8 link_state;
	__u16 num_ptes;
	__u16 num_txqs;
	__u16 num_tgqs;
	__u16 num_eqs;
	__u16 num_cts;
	__u16 num_acs;
	__u16 num_tles;
	__u16 num_les;
	__u32 cassini_version; /* enum cassini_version */
	__u32 system_type_identifier; /* enum system_type_identifier */
	char fru_description[16];
	__u32 vni_matching;
};

struct cxi_ibv_query_device_resp {
	__u32 features; /* CXI_DEVICE_CAP_* bitmask */
	__u32 max_ctn; /* max counting trigger number */
	struct cxi_ibv_devinfo devinfo;
};

/*
 *
 * The driver registers user memory with the CXI ATU (Address Translation
 * Unit).  The lkey encodes the LAC (Local Address Context) slot and the
 * hardware MD identifier.  The rkey is a random token used as the portal
 * match-bits for remote RDMA WRITE/READ operations targeting this MR.
 */
/*
 * 64-bit memory keys.
 *
 *   lkey64  bits [2:0]   LAC, the hardware address context
 *           bits [34:3]  ATU memory descriptor index
 *   rkey64  an opaque token the initiator presents as the portal match bits
 *
 * The 32-bit lkey and rkey keep the older narrow encoding, which packs the
 * LAC into bits [31:24] and truncates the descriptor index to 24 bits, for
 * callers that cannot carry a wide key.
 */
#define CXI_LKEY64_LAC_MASK 0x7ULL
#define CXI_LKEY64_MD_SHIFT 3
#define CXI_LKEY64_MD_MASK 0xffffffffULL

/*
 * A caller may choose the remote key rather than take a generated one. The
 * value is used exactly as given, so one that fits in 32 bits produces a
 * region a 32-bit peer can reach without anything having to truncate.
 */
#define CXI_REG_MR_USER_RKEY (1 << 0)
#define CXI_REG_MR_NATIVE_MAP (1 << 1)

#define CXI_RKEY_MAX 0xffffffffffffULL

struct cxi_ibv_reg_mr {
	__aligned_u64 rkey64;
	__u32 flags;
	__u32 native_flags;
};

struct cxi_ibv_mr_info {
	__u64 va __attribute__((packed));
	__u64 iova __attribute__((packed));
	__u64 length __attribute__((packed));
	__s32 page_shift;
	__s32 huge_shift;
	__u32 id;
	__u32 lac;
};

struct cxi_ibv_reg_mr_resp {
	/*
	 * The narrow keys alias the low word of the wide ones. REG_MR is a
	 * legacy write command whose response declares __u32 driver_data[], so
	 * this payload begins at offset 12 and nothing here can be eight-byte
	 * aligned; packed drops the requirement without moving anything.
	 */
	union {
		__u64 lkey64 __attribute__((packed));
		struct {
			__u32 lkey;
			__u32 lkey_hi;
		};
	};
	union {
		__u64 rkey64 __attribute__((packed));
		struct {
			__u32 rkey;
			__u32 rkey_hi;
		};
	};
	/* ATU address for @start; commands must use this, not the VA. */
	__u64 iova __attribute__((packed));
	struct cxi_ibv_mr_info info;
};

/*
 * Custom uverbs for Counting Triggers (CT).
 *
 * The driver allocates a CXI Completion Table (CT) of the requested size and
 * maps the ring buffer (writeback page) and doorbell CSR into user space.
 *
 * After create_ct succeeds:
 *   - ctn               : hardware CT number (u32); used in triggered commands
 *   - wb_mmap_offset    : mmap() offset for the writeback page
 *   - wb_mmap_length    : size of the writeback page in bytes
 *   - db_mmap_offset    : mmap() offset for the CT doorbell CSR
 *   - db_mmap_length    : size of the doorbell region in bytes
 *
 * Object/method/attribute IDs are driver-namespace values
 * (UVERBS_ID_DRIVER_NS = 1 << UVERBS_ID_NS_SHIFT).
 */
#include <rdma/ib_user_ioctl_cmds.h>

enum cxi_ib_object_ids {
	CXI_IB_OBJECT_CT = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_OBJECT_JOB_TC,
	CXI_IB_OBJECT_LNI,
	CXI_IB_OBJECT_SVC,
	CXI_IB_OBJECT_CP,
	CXI_IB_OBJECT_EQ,
	CXI_IB_OBJECT_CSR,
	CXI_IB_OBJECT_WAIT,
	CXI_IB_OBJECT_CMDQ,
};

enum cxi_ib_methods_cmdq {
	CXI_IB_METHOD_CMDQ_ALLOC = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_METHOD_CMDQ_DESTROY,
};

enum cxi_ib_attrs_cmdq {
	CXI_IB_ATTR_CMDQ_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_ATTR_CMDQ_LNI,
	CXI_IB_ATTR_CMDQ_COUNT,
	CXI_IB_ATTR_CMDQ_INFO,
	CXI_IB_ATTR_CMDQ_FLAGS,
};

enum cxi_ib_cmdq_flags {
	CXI_IB_CMDQ_TRIGGER = 1U << 0,
};

struct cxi_ibv_cmdq_info {
	__aligned_u64 commands_offset;
	__aligned_u64 commands_length;
	__aligned_u64 doorbell_offset;
	__aligned_u64 doorbell_length;
	__u32 count;
	__u32 index;
};

enum cxi_ib_methods_wait {
	CXI_IB_METHOD_WAIT_ALLOC = (1U << UVERBS_ID_NS_SHIFT),
};

enum cxi_ib_attrs_wait {
	CXI_IB_ATTR_WAIT_FD = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_ATTR_WAIT_LNI,
};

enum cxi_ib_methods_csr {
	CXI_IB_METHOD_CSR_MAP = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_METHOD_CSR_UNMAP,
	CXI_IB_METHOD_CSR_INBOUND_WAIT,
};

enum cxi_ib_attrs_csr {
	CXI_IB_ATTR_CSR_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_ATTR_CSR_INFO,
};

struct cxi_ibv_csr_info {
	__aligned_u64 offset;
	__aligned_u64 length;
};

enum cxi_ib_methods_eq {
	CXI_IB_METHOD_EQ_ALLOC = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_METHOD_EQ_DESTROY,
};

enum cxi_ib_attrs_eq {
	CXI_IB_ATTR_EQ_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_ATTR_EQ_LNI,
	CXI_IB_ATTR_EQ_MR,
	CXI_IB_ATTR_EQ_CONFIG,
	CXI_IB_ATTR_EQ_INFO,
	CXI_IB_ATTR_EQ_FLAGS,
	CXI_IB_ATTR_EQ_EVENT_WAIT,
	CXI_IB_ATTR_EQ_STATUS_WAIT,
};

enum cxi_ib_eq_flags {
	CXI_IB_EQ_REGISTER_PCT = 1U << 0,
	CXI_IB_EQ_PASSTHROUGH = 1U << 1,
};

struct cxi_ibv_eq_config {
	__aligned_u64 address;
	__aligned_u64 length;
	__u32 threshold_base;
	__u32 threshold_delta;
	__u32 threshold_count;
	__u32 ec_delay;
	__u32 cpu;
	__u32 reserved_slots;
};

struct cxi_ibv_eq_info {
	__aligned_u64 doorbell_offset;
	__aligned_u64 doorbell_size;
	__u32 eqn;
	__u32 reserved;
};

enum cxi_ib_methods_cp {
	CXI_IB_METHOD_CP_ALLOC = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_METHOD_CP_DESTROY,
};

enum cxi_ib_attrs_cp {
	CXI_IB_ATTR_CP_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_ATTR_CP_LNI,
	CXI_IB_ATTR_CP_VNI,
	CXI_IB_ATTR_CP_TC,
	CXI_IB_ATTR_CP_TYPE,
	CXI_IB_ATTR_CP_INFO,
};

struct cxi_ibv_cp_info {
	__u32 vni;
	__u32 tc;
	__u32 type;
	__u32 lcid;
};

enum cxi_ib_methods_svc {
	CXI_IB_METHOD_SVC_ALLOC = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_METHOD_SVC_DESTROY,
	CXI_IB_METHOD_SVC_QUERY,
	CXI_IB_METHOD_SVC_ENABLE,
};

enum cxi_ib_attrs_svc {
	CXI_IB_ATTR_SVC_ID = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_ATTR_SVC_CONFIG,
	CXI_IB_ATTR_SVC_FLAGS,
	CXI_IB_ATTR_SVC_USAGE,
	CXI_IB_ATTR_SVC_LPR,
};

enum cxi_ib_svc_flags {
	CXI_IB_SVC_LIMITS = 1U << 0,
	CXI_IB_SVC_CREATE_TC = 1U << 1,
	CXI_IB_SVC_ENABLED = 1U << 2,
};

enum cxi_ib_svc_resource {
	CXI_IB_SVC_PTES,
	CXI_IB_SVC_TXQS,
	CXI_IB_SVC_TGQS,
	CXI_IB_SVC_EQS,
	CXI_IB_SVC_CTS,
	CXI_IB_SVC_ACS,
	CXI_IB_SVC_TLES,
	CXI_IB_SVC_LES,
	CXI_IB_SVC_RSRC_COUNT,
};

#define CXI_IB_SVC_MAX_VNIS 4

struct cxi_ibv_svc_config {
	__u32 svc_id;
	/* Reserved; must be zero. */
	__u16 vni_min;
	__u16 vni_max;
	/* Exact-list length; zero means system-empty or is_range. */
	__u32 vni_count;
	/* System service requires CAP_SYS_ADMIN and svc_id zero on allocation. */
	__u32 is_system_svc;
	/* Inclusive range endpoints are carried in vnis[0] and vnis[1]. */
	__u32 is_range;
	__u16 vnis[CXI_IB_SVC_MAX_VNIS];
	__u32 tc_mask;
	__u32 uid;
	__u32 flags;
	__u16 maximum[CXI_IB_SVC_RSRC_COUNT];
	__u16 reserved[CXI_IB_SVC_RSRC_COUNT];
};

struct cxi_ibv_svc_rsrc_use {
	__u32 svc_id;
	__u32 tle_pool_id;
	__u16 in_use[CXI_IB_SVC_RSRC_COUNT];
};

enum cxi_ib_methods_lni {
	CXI_IB_METHOD_LNI_ALLOC = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_METHOD_LNI_DESTROY,
};

enum cxi_ib_attrs_lni_alloc {
	CXI_IB_ATTR_LNI_ALLOC_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_ATTR_LNI_ALLOC_SVC_ID,
	CXI_IB_ATTR_LNI_ALLOC_ID,
};

enum cxi_ib_attrs_lni_destroy {
	CXI_IB_ATTR_LNI_DESTROY_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
};

enum cxi_ib_methods_pd {
	CXI_IB_METHOD_PD_PID_ALLOC = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_METHOD_PD_PID_QUERY,
};

enum cxi_ib_attrs_pd_pid {
	CXI_IB_ATTR_PD_PID_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_ATTR_PD_PID_FLAGS,
	CXI_IB_ATTR_PD_PID_VALUE,
};

#define CXI_IB_PD_PID_ABSOLUTE (1U << 0)

struct cxi_ibv_create_jkey_cmd {
	__u32 tc;
	__u32 reserved;
};

enum cxi_ib_methods_ct {
	CXI_IB_METHOD_CT_ALLOC = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_METHOD_CT_DESTROY = (1U << UVERBS_ID_NS_SHIFT) + 1,
};

enum cxi_ib_attrs_ct_alloc {
	CXI_IB_ATTR_CT_ALLOC_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_ATTR_CT_ALLOC_CTN,
	CXI_IB_ATTR_CT_ALLOC_WB_MMAP_OFFSET,
	CXI_IB_ATTR_CT_ALLOC_WB_MMAP_LENGTH,
	CXI_IB_ATTR_CT_ALLOC_DB_MMAP_OFFSET,
	CXI_IB_ATTR_CT_ALLOC_DB_MMAP_LENGTH,
	CXI_IB_ATTR_CT_ALLOC_LNI_HANDLE,
	CXI_IB_ATTR_CT_ALLOC_WB_ADDRESS,
};

enum cxi_ib_attrs_ct_destroy {
	CXI_IB_ATTR_CT_DESTROY_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
};

enum cxi_ib_job_tc_flags {
	CXI_IB_JOB_TC_F_CREATE = 1U << 0,
};

enum cxi_ib_methods_job_tc {
	CXI_IB_METHOD_JOB_TC_BIND = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_METHOD_JOB_TC_CLEAR,
	CXI_IB_METHOD_JOB_TC_QUERY,
};

struct cxi_ibv_tc_entry {
	__u32 tc;
	__u32 tc_type;
	__u32 res_req_dscp;
	__u32 unres_req_dscp;
	__u32 res_rsp_dscp;
	__u32 unres_rsp_dscp;
	__u32 req_pcp;
	__u32 rsp_pcp;
	__u32 ocuset;
	__u32 cq_tc;
	__u32 req_bc;
	__u32 flags;
};

#define CXI_IBV_TC_ENTRY_F_CREATED_BY_RDMA (1U << 0)

enum cxi_ib_attrs_job_tc_bind {
	CXI_IB_ATTR_JOB_TC_BIND_FLAGS = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_ATTR_JOB_TC_BIND_JOB_ID,
	CXI_IB_ATTR_JOB_TC_BIND_TC,
	CXI_IB_ATTR_JOB_TC_BIND_TC_TYPE,
	CXI_IB_ATTR_JOB_TC_BIND_SVC_ID,
	CXI_IB_ATTR_JOB_TC_BIND_PTES_MAX,
	CXI_IB_ATTR_JOB_TC_BIND_PTES_RES,
	CXI_IB_ATTR_JOB_TC_BIND_TXQS_MAX,
	CXI_IB_ATTR_JOB_TC_BIND_TXQS_RES,
	CXI_IB_ATTR_JOB_TC_BIND_TGQS_MAX,
	CXI_IB_ATTR_JOB_TC_BIND_TGQS_RES,
	CXI_IB_ATTR_JOB_TC_BIND_EQS_MAX,
	CXI_IB_ATTR_JOB_TC_BIND_EQS_RES,
	CXI_IB_ATTR_JOB_TC_BIND_CTS_MAX,
	CXI_IB_ATTR_JOB_TC_BIND_CTS_RES,
	CXI_IB_ATTR_JOB_TC_BIND_LES_MAX,
	CXI_IB_ATTR_JOB_TC_BIND_LES_RES,
	CXI_IB_ATTR_JOB_TC_BIND_TLES_MAX,
	CXI_IB_ATTR_JOB_TC_BIND_TLES_RES,
	CXI_IB_ATTR_JOB_TC_BIND_ACS_MAX,
	CXI_IB_ATTR_JOB_TC_BIND_ACS_RES,
	CXI_IB_ATTR_JOB_TC_BIND_RESP_SVC_ID,
};

enum cxi_ib_attrs_job_tc_clear {
	CXI_IB_ATTR_JOB_TC_CLEAR_TC = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_ATTR_JOB_TC_CLEAR_TC_TYPE,
};

enum cxi_ib_attrs_job_tc_query {
	CXI_IB_ATTR_JOB_TC_QUERY_MAX_ENTRIES = (1U << UVERBS_ID_NS_SHIFT),
	CXI_IB_ATTR_JOB_TC_QUERY_RESP_COUNT,
	CXI_IB_ATTR_JOB_TC_QUERY_RESP_ENTRIES,
};

#endif /* __UAPI_RDMA_CXI_ABI_H__ */
