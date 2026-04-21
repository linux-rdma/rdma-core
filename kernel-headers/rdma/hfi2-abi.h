/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/*
 * Copyright 2025 Cornelis Networks
 * Copyright (c) 2026 Cornelis Networks
 */

#ifndef _LINUX_HFI2_USER_H
#define _LINUX_HFI2_USER_H

#include <linux/types.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/rdma_user_ioctl.h>

/*
 * This version number is given to the driver by the user code during
 * initialization in the spu_userversion field of hfi2_user_info, so
 * the driver can check for compatibility with user code.
 *
 * The major version changes when data structures change in an incompatible
 * way. The driver must be the same for initialization to succeed.
 */
#define HFI2_USER_SWMAJOR 6
#define HFI2_RDMA_USER_SWMAJOR 10

/*
 * Minor version differences are always compatible
 * a within a major version, however if user software is larger
 * than driver software, some new features and/or structure fields
 * may not be implemented; the user code must deal with this if it
 * cares, or it must abort after initialization reports the difference.
 */
#define HFI2_USER_SWMINOR 3
#define HFI2_RDMA_USER_SWMINOR 0

/*
 * We will encode the major/minor inside a single 32bit version number.
 */
#define HFI2_SWMAJOR_SHIFT 16

/*
 * Set of HW and driver capability/feature bits.
 * These bit values are used to configure enabled/disabled HW and
 * driver features. The same set of bits are communicated to user
 * space.
 */
#define HFI2_CAP_DMA_RTAIL        (1UL <<  0) /* Use DMA'ed RTail value */
#define HFI2_CAP_SDMA             (1UL <<  1) /* Enable SDMA support */
#define HFI2_CAP_SDMA_AHG         (1UL <<  2) /* Enable SDMA AHG support */
#define HFI2_CAP_EXTENDED_PSN     (1UL <<  3) /* Enable Extended PSN support */
#define HFI2_CAP_HDRSUPP          (1UL <<  4) /* Enable Header Suppression */
#define HFI2_CAP_TID_RDMA         (1UL <<  5) /* Enable TID RDMA operations */
#define HFI2_CAP_USE_SDMA_HEAD    (1UL <<  6) /* DMA Hdr Q tail vs. use CSR */
#define HFI2_CAP_MULTI_PKT_EGR    (1UL <<  7) /* Enable multi-packet Egr buffs*/
#define HFI2_CAP_NODROP_RHQ_FULL  (1UL <<  8) /* Don't drop on Hdr Q full */
#define HFI2_CAP_NODROP_EGR_FULL  (1UL <<  9) /* Don't drop on EGR buffs full */
#define HFI2_CAP_TID_UNMAP        (1UL << 10) /* Disable Expected TID caching */
#define HFI2_CAP_PRINT_UNIMPL     (1UL << 11) /* Show for unimplemented feats */
#define HFI2_CAP_ALLOW_PERM_JKEY  (1UL << 12) /* Allow use of permissive JKEY */
#define HFI2_CAP_NO_INTEGRITY     (1UL << 13) /* Enable ctxt integrity checks */
#define HFI2_CAP_PKEY_CHECK       (1UL << 14) /* Enable ctxt PKey checking */
#define HFI2_CAP_STATIC_RATE_CTRL (1UL << 15) /* Allow PBC.StaticRateControl */
#define HFI2_CAP_OPFN             (1UL << 16) /* Enable the OPFN protocol */
#define HFI2_CAP_SDMA_HEAD_CHECK  (1UL << 17) /* SDMA head checking */
#define HFI2_CAP_EARLY_CREDIT_RETURN (1UL << 18) /* early credit return */
#define HFI2_CAP_AIP              (1UL << 19) /* Enable accelerated IP */

#define HFI2_RCVHDR_ENTSIZE_2    (1UL << 0)
#define HFI2_RCVHDR_ENTSIZE_16   (1UL << 1)
#define HFI2_RCVDHR_ENTSIZE_32   (1UL << 2)

#define _HFI2_EVENT_FROZEN_BIT         0
#define _HFI2_EVENT_LINKDOWN_BIT       1
#define _HFI2_EVENT_LID_CHANGE_BIT     2
#define _HFI2_EVENT_LMC_CHANGE_BIT     3
#define _HFI2_EVENT_SL2VL_CHANGE_BIT   4
#define _HFI2_EVENT_TID_MMU_NOTIFY_BIT 5
#define _HFI2_MAX_EVENT_BIT _HFI2_EVENT_TID_MMU_NOTIFY_BIT

#define HFI2_EVENT_FROZEN            (1UL << _HFI2_EVENT_FROZEN_BIT)
#define HFI2_EVENT_LINKDOWN          (1UL << _HFI2_EVENT_LINKDOWN_BIT)
#define HFI2_EVENT_LID_CHANGE        (1UL << _HFI2_EVENT_LID_CHANGE_BIT)
#define HFI2_EVENT_LMC_CHANGE        (1UL << _HFI2_EVENT_LMC_CHANGE_BIT)
#define HFI2_EVENT_SL2VL_CHANGE      (1UL << _HFI2_EVENT_SL2VL_CHANGE_BIT)
#define HFI2_EVENT_TID_MMU_NOTIFY    (1UL << _HFI2_EVENT_TID_MMU_NOTIFY_BIT)

/*
 * These are the status bits readable (in ASCII form, 64bit value)
 * from the "status" sysfs file.  For binary compatibility, values
 * must remain as is; removed states can be reused for different
 * purposes.
 */
#define HFI2_STATUS_INITTED       0x1    /* basic initialization done */
/* Chip has been found and initialized */
#define HFI2_STATUS_CHIP_PRESENT 0x20
/* IB link is at ACTIVE, usable for data traffic */
#define HFI2_STATUS_IB_READY     0x40
/* link is configured, LID, MTU, etc. have been set */
#define HFI2_STATUS_IB_CONF      0x80
/* A Fatal hardware error has occurred. */
#define HFI2_STATUS_HWERROR     0x200

/*
 * Number of supported shared contexts.
 * This is the maximum number of software contexts that can share
 * a hardware send/receive context.
 */
#define HFI2_MAX_SHARED_CTXTS 8

/*
 * Poll types
 */
#define HFI2_POLL_TYPE_ANYRCV     0x0
#define HFI2_POLL_TYPE_URGENT     0x1

enum hfi2_sdma_comp_state {
	FREE = 0,
	QUEUED,
	COMPLETE,
	ERROR
};

/*
 * SDMA completion ring entry
 */
struct hfi2_sdma_comp_entry {
	__u32 status;
	__u32 errcode;
};

/*
 * Device status and notifications from driver to user-space.
 * hfi1 and hfi2 status are different.
 */
struct hfi1_status {
	__aligned_u64 dev;      /* device/hw status bits */
	__aligned_u64 port;     /* port state and status bits */
	char freezemsg[];
};

struct hfi2_status {
	__aligned_u64 dev;      /* device/hw status bits */
	__aligned_u64 ports[];  /* port state and status bits */
};

enum sdma_req_opcode {
	EXPECTED = 0,
	EAGER
};

#define HFI2_SDMA_REQ_VERSION_MASK 0xF
#define HFI2_SDMA_REQ_VERSION_SHIFT 0x0
#define HFI2_SDMA_REQ_OPCODE_MASK 0xF
#define HFI2_SDMA_REQ_OPCODE_SHIFT 0x4
#define HFI2_SDMA_REQ_IOVCNT_MASK 0x7F
#define HFI2_SDMA_REQ_IOVCNT_SHIFT 0x8
#define HFI2_SDMA_REQ_MEMINFO_MASK 0x1
#define HFI2_SDMA_REQ_MEMINFO_SHIFT 0xF

struct sdma_req_info {
	/*
	 * bits 0-3 - version (currently unused)
	 * bits 4-7 - opcode (enum sdma_req_opcode)
	 * bits 8-14 - io vector count
	 * bit  15 - meminfo present
	 */
	__u16 ctrl;
	/*
	 * Number of fragments contained in this request.
	 * User-space has already computed how many
	 * fragment-sized packet the user buffer will be
	 * split into.
	 */
	__u16 npkts;
	/*
	 * Size of each fragment the user buffer will be
	 * split into.
	 */
	__u16 fragsize;
	/*
	 * Index of the slot in the SDMA completion ring
	 * this request should be using. User-space is
	 * in charge of managing its own ring.
	 */
	__u16 comp_idx;
} __packed;

#define HFI2_MEMINFO_TYPE_ENTRY_BITS 4
#define HFI2_MEMINFO_TYPE_ENTRY_MASK ((1 << HFI2_MEMINFO_TYPE_ENTRY_BITS) - 1)
#define HFI2_MEMINFO_TYPE_ENTRY_GET(m, n)              \
	(((m) >> ((n) * HFI2_MEMINFO_TYPE_ENTRY_BITS)) & \
	 HFI2_MEMINFO_TYPE_ENTRY_MASK)
#define HFI2_MEMINFO_TYPE_ENTRY_SET(m, n, e)    \
	((m) |= ((e) & HFI2_MEMINFO_TYPE_ENTRY_MASK) \
	     << ((n) * HFI2_MEMINFO_TYPE_ENTRY_BITS))
#define HFI2_MAX_MEMINFO_ENTRIES \
	(sizeof(__u64) * 8 / HFI2_MEMINFO_TYPE_ENTRY_BITS)

#define HFI2_MEMINFO_TYPE_SYSTEM 0

struct sdma_req_meminfo {
	/*
	 * Packed memory type indicators for each data iovec entry.
	 */
	__u64 types;
	/*
	 * Type-specific context for each data iovec entry.
	 */
	__u64 context[HFI2_MAX_MEMINFO_ENTRIES];
};

/*
 * SW KDETH header.
 * swdata is SW defined portion.
 */
struct hfi2_kdeth_header {
	__le32 ver_tid_offset;
	__le16 jkey;
	__le16 hcrc;
	__le32 swdata[7];
} __packed;

/*
 * Structure describing the headers that User space uses. The
 * structure above is a subset of this one.
 */
struct hfi2_pkt_header {
	__le16 pbc[4];
	__be16 lrh[4];
	__be32 bth[3];
	struct hfi2_kdeth_header kdeth;
} __packed;


/*
 * The list of usermode accessible registers.
 */
enum hfi2_ureg {
	/* (RO)  DMA RcvHdr to be used next. */
	ur_rcvhdrtail = 0,
	/* (RW)  RcvHdr entry to be processed next by host. */
	ur_rcvhdrhead = 1,
	/* (RO)  Index of next Eager index to use. */
	ur_rcvegrindextail = 2,
	/* (RW)  Eager TID to be processed next */
	ur_rcvegrindexhead = 3,
	/* (RO)  Receive Eager Offset Tail */
	ur_rcvegroffsettail = 4,
	/* For internal use only; max register number. */
	ur_maxreg,
	/* (RW)  Receive TID flow table */
	ur_rcvtidflowtable = 256
};

/*
 * This structure is passed to the driver to tell it where
 * user code buffers are, sizes, etc.   The offsets and sizes of the
 * fields must remain unchanged, for binary compatibility.  It can
 * be extended, if userversion is changed so user code can tell, if needed
 */
struct hfi2_user_info {
	/*
	 * version of user software, to detect compatibility issues.
	 * Should be set to HFI2_USER_SWVERSION.
	 */
	__u32 userversion;
	__u32 pad; /* Port Address */
	/*
	 * If two or more processes wish to share a context, each process
	 * must set the subcontext_cnt and subcontext_id to the same
	 * values.  The only restriction on the subcontext_id is that
	 * it be unique for a given node.
	 */
	__u16 subctxt_cnt;
	__u16 subctxt_id;
	/* 128bit UUID passed in by PSM. */
	__u8 uuid[16];
};

struct hfi2_ctxt_info {
	__aligned_u64 runtime_flags;    /* chip/drv runtime flags (HFI2_CAP_*) */
	__u32 rcvegr_size;      /* size of each eager buffer */
	__u16 num_active;       /* number of active units */
	__u16 unit;             /* unit (chip) assigned to caller */
	__u16 ctxt;             /* ctxt on unit assigned to caller */
	__u16 subctxt;          /* subctxt on unit assigned to caller */
	__u16 rcvtids;          /* number of Rcv TIDs for this context */
	__u16 credits;          /* number of PIO credits for this context */
	__u16 numa_node;        /* NUMA node of the assigned device */
	__u16 rec_cpu;          /* cpu # for affinity (0xffff if none) */
	__u16 send_ctxt;        /* send context in use by this user context */
	__u16 egrtids;          /* number of RcvArray entries for Eager Rcvs */
	__u16 rcvhdrq_cnt;      /* number of RcvHdrQ entries */
	__u16 rcvhdrq_entsize;  /* size (in bytes) for each RcvHdrQ entry */
	__u16 sdma_ring_size;   /* number of entries in SDMA request ring */
};

struct hfi1_tid_info {
	/* virtual address of first page in transfer */
	__aligned_u64 vaddr;
	/* pointer to tid array. this array is big enough */
	__aligned_u64 tidlist;
	/* number of tids programmed by this request */
	__u32 tidcnt;
	/* length of transfer buffer programmed by this request */
	__u32 length;
};

#define HFI2_TID_UPDATE_FLAGS_MEMINFO_BITS 4
#define HFI2_TID_UPDATE_FLAGS_MEMINFO_MASK ((1UL << HFI2_TID_UPDATE_FLAGS_MEMINFO_BITS) - 1)
#define HFI2_TID_UPDATE_FLAGS_RESERVED_MASK (~(__u64)(HFI2_TID_UPDATE_FLAGS_MEMINFO_MASK))

struct hfi2_tid_info {
	/* virtual address of first page in transfer */
	__aligned_u64 vaddr;
	/* pointer to tid array. this array is big enough */
	__aligned_u64 tidlist;
	/* number of tids programmed by this request */
	__u32 tidcnt;
	/* length of transfer buffer programmed by this request */
	__u32 length;

	/*
	 * bits 0-3 memory_type
	 *   memory_type=0 will always mean system memory
	 *   See HFI2_MEMINFO_TYPE* defines
	 * bits 4-63 reserved; must be 0
	 */
	__aligned_u64 flags;
	/* Reserved; must be 0 */
	__aligned_u64 context;
};

/*
 * This structure is returned by the driver immediately after
 * open to get implementation-specific info, and info specific to this
 * instance.
 *
 * This struct must have explicit padding fields where type sizes
 * may result in different alignments between 32 and 64 bit
 * programs, since the 64 bit * bit kernel requires the user code
 * to have matching offsets
 */
struct hfi2_base_info {
	/* version of hardware, for feature checking. */
	__u32 hw_version;
	/* version of software, for feature checking. */
	__u32 sw_version;
	/* Job key */
	__u16 jkey;
	__u16 padding1;
	/*
	 * The special QP (queue pair) value that identifies PSM
	 * protocol packet from standard IB packets.
	 */
	__u32 bthqp;
	/* PIO credit return address, */
	__aligned_u64 sc_credits_addr;
	/*
	 * Base address of write-only pio buffers for this process.
	 * Each buffer has sendpio_credits*64 bytes.
	 */
	__aligned_u64 pio_bufbase_sop;
	/*
	 * Base address of write-only pio buffers for this process.
	 * Each buffer has sendpio_credits*64 bytes.
	 */
	__aligned_u64 pio_bufbase;
	/* address where receive buffer queue is mapped into */
	__aligned_u64 rcvhdr_bufbase;
	/* base address of Eager receive buffers. */
	__aligned_u64 rcvegr_bufbase;
	/* base address of SDMA completion ring */
	__aligned_u64 sdma_comp_bufbase;
	/*
	 * User register base for init code, not to be used directly by
	 * protocol or applications.  Always maps real chip register space.
	 * the register addresses are:
	 * ur_rcvhdrhead, ur_rcvhdrtail, ur_rcvegrhead, ur_rcvegrtail,
	 * ur_rcvtidflow
	 */
	__aligned_u64 user_regbase;
	/* notification events */
	__aligned_u64 events_bufbase;
	/* status page */
	__aligned_u64 status_bufbase;
	/* rcvhdrtail update */
	__aligned_u64 rcvhdrtail_base;
	/*
	 * shared memory pages for subctxts if ctxt is shared; these cover
	 * all the processes in the group sharing a single context.
	 * all have enough space for the num_subcontexts value on this job.
	 */
	__aligned_u64 subctxt_uregbase;
	__aligned_u64 subctxt_rcvegrbuf;
	__aligned_u64 subctxt_rcvhdrbuf;
};

struct hfi2_pin_stats {
	int memtype;
	/*
	 * If -1, driver returns total number of stats entries for the given
	 * memtype, otherwise returns stats for the given { memtype, index }.
	 */
	int index;
	__u64 id;
	__u64 cache_entries;
	__u64 total_refcounts;
	__u64 total_bytes;
	__u64 hits;
	__u64 misses;
	__u64 hint_hits;
	__u64 hint_misses;
	__u64 internal_evictions; /* due to self-imposed size limit */
	__u64 external_evictions; /* system-driven evictions */
};

/*
 * RDMA character device ioctls
 */

/* verbs objects */
enum hfi2_objects {
	HFI2_OBJECT_DV0 = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_OBJECT_DV1,
};

/* methods for custom objects dv0 and dv1 - max of 8 per object */
enum hfi2_methods_dv0 {
	HFI2_METHOD_ASSIGN_CTXT = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_METHOD_CTXT_INFO,
	HFI2_METHOD_USER_INFO,
	HFI2_METHOD_TID_UPDATE,
	HFI2_METHOD_TID_FREE,
	HFI2_METHOD_CREDIT_UPD,
	HFI2_METHOD_RECV_CTRL,
	HFI2_METHOD_POLL_TYPE,
};

enum hfi2_methods_dv1 {
	HFI2_METHOD_ACK_EVENT = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_METHOD_SET_PKEY,
	HFI2_METHOD_CTXT_RESET,
	HFI2_METHOD_TID_INVAL_READ,
	HFI2_METHOD_GET_VERS,
	HFI2_METHOD_PIN_STATS,
};

/*
 * assign_ctxt
 */
enum hfi2_attrs_assign_ctxt {
	HFI2_ATTR_ASSIGN_CTXT_CMD = (1U << UVERBS_ID_NS_SHIFT),
};

struct hfi2_assign_ctxt_cmd {
	__u32 userversion;	/* user library version */
	__u8 port;		/* target port number */
	__u8 kdeth_rcvhdrsz;	/* 0 means default */
	__u16 reserved1;
	__u16 subctxt_cnt;
	__u16 subctxt_id;
	__u8 uuid[16];		/* 128bit UUID */
	__u32 reserved2;
};

/*
 * ctxt_info
 */
enum hfi2_attrs_ctxt_info {
	HFI2_ATTR_CTXT_INFO_RSP = (1U << UVERBS_ID_NS_SHIFT),
};

struct hfi2_ctxt_info_rsp {
	__aligned_u64 runtime_flags; /* chip/drv runtime flags (HFI2_CAP_*) */

	__u32 rcvegr_size;      /* size of each eager buffer */
	__u16 num_active;       /* number of active units */
	__u16 unit;             /* unit (chip) assigned to caller */

	__u16 ctxt;             /* ctxt on unit assigned to caller */
	__u16 subctxt;          /* subctxt on unit assigned to caller */
	__u16 rcvtids;          /* number of Rcv TIDs for this context */
	__u16 credits;          /* number of PIO credits for this context */

	__u16 numa_node;        /* NUMA node of the assigned device */
	__u16 rec_cpu;          /* cpu # for affinity (0xffff if none) */
	__u16 send_ctxt;        /* send context in use by this user context */
	__u16 egrtids;          /* number of RcvArray entries for Eager Rcvs */

	__u16 rcvhdrq_cnt;      /* number of RcvHdrQ entries */
	__u16 rcvhdrq_entsize;  /* size (in bytes) for each RcvHdrQ entry */
	__u16 sdma_ring_size;   /* number of entries in SDMA request ring */
	__u16 reserved;
};

/*
 * user_info
 */
enum hfi2_attrs_user_info {
	HFI2_ATTR_USER_INFO_RSP = (1U << UVERBS_ID_NS_SHIFT),
};

/*
 * Returns both general and specific information to this device open.
 */
struct hfi2_user_info_rsp {
	/* version of hardware, for feature checking. */
	__u32 hw_version;
	/* version of software, for feature checking. */
	__u32 sw_version;
	/* Job key */
	__u16 jkey;
	__u16 reserved;
	/*
	 * The special QP (queue pair) value that identifies PSM/OPX
	 * protocol packet from standard IB packets.
	 */
	__u32 bthqp;
	/* PIO credit return address */
	__aligned_u64 sc_credits_addr;
	/*
	 * Base address of write-only pio buffers for this process.
	 * Each buffer has sendpio_credits*64 bytes.
	 */
	__aligned_u64 pio_bufbase_sop;
	/*
	 * Base address of write-only pio buffers for this process.
	 * Each buffer has sendpio_credits*64 bytes.
	 */
	__aligned_u64 pio_bufbase;
	/* address where receive buffer queue is mapped into */
	__aligned_u64 rcvhdr_bufbase;
	/* base address of Eager receive buffers. */
	__aligned_u64 rcvegr_bufbase;
	/* base address of SDMA completion ring */
	__aligned_u64 sdma_comp_bufbase;
	/*
	 * User register base for init code, not to be used directly by
	 * protocol or applications.  Always maps real chip register space.
	 * the register addresses are:
	 * ur_rcvhdrhead, ur_rcvhdrtail, ur_rcvegrhead, ur_rcvegrtail,
	 * ur_rcvtidflow
	 */
	__aligned_u64 user_regbase;
	/* notification events */
	__aligned_u64 events_bufbase;
	/* status page */
	__aligned_u64 status_bufbase;
	/* rcvhdrtail update */
	__aligned_u64 rcvhdrtail_base;
	/*
	 * Shared memory pages for subctxts if ctxt is shared.  These cover
	 * all the processes in the group sharing a single context.
	 * All have enough space for the num_subcontexts value on this job.
	 */
	__aligned_u64 subctxt_uregbase;
	__aligned_u64 subctxt_rcvegrbuf;
	__aligned_u64 subctxt_rcvhdrbuf;
	/* receive header error queue */
	__aligned_u64 rheq_bufbase;
};

/*
 * tid_update
 */
enum hfi2_attrs_tid_update {
	HFI2_ATTR_TID_UPDATE_CMD = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_ATTR_TID_UPDATE_RSP,
};

struct hfi2_tid_update_cmd {
	__aligned_u64 vaddr;	/* virtual address of buffer */
	__aligned_u64 tidlist;	/* address of output tid array */
	__u32 length;		/* buffer length, in bytes */
	__u32 tidcnt;		/* tidlist size, in TIDs */
	__aligned_u64 flags;	/* flags: [3:0] mem type, [63:4] reserved */
	__aligned_u64 context;	/* reserved */
};

struct hfi2_tid_update_rsp {
	__u32 length;		/* mapped buffer length */
	__u32 tidcnt;		/* number of assigned TIDs */
};

/*
 * tid_free
 */
enum hfi2_attrs_tid_free {
	HFI2_ATTR_TID_FREE_CMD = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_ATTR_TID_FREE_RSP,
};

struct hfi2_tid_free_cmd {
	__aligned_u64 tidlist;  /* user buffer pointer */
	__u32 tidcnt;           /* number of TID entries in buffer */
	__u32 reserved;
};

struct hfi2_tid_free_rsp {
	__u32 tidcnt;		/* number actually freed */
	__u32 reserved;
};

/*
 * credit_upd
 * (no arguments)
 */

/*
 * recv_ctrl
 */
enum hfi2_attrs_recv_ctrl {
	HFI2_ATTR_RECV_CTRL_CMD = (1U << UVERBS_ID_NS_SHIFT),
	/* no response */
};

struct hfi2_recv_ctrl_cmd {
	__u8 start_stop;
	__u8 reserved[7];
};

/*
 * poll_type
 */
enum hfi2_attrs_poll_type {
	HFI2_ATTR_POLL_TYPE_CMD = (1U << UVERBS_ID_NS_SHIFT),
	/* no response */
};

struct hfi2_poll_type_cmd {
	__u32 poll_type;
	__u32 reserved;
};

/*
 * ack_event
 */
enum hfi2_attrs_ack_event {
	HFI2_ATTR_ACK_EVENT_CMD = (1U << UVERBS_ID_NS_SHIFT),
	/* no response */
};

struct hfi2_ack_event_cmd {
	__u64 event;
};

/*
 * set_pkey
 */
enum hfi2_attrs_set_pkey {
	HFI2_ATTR_SET_PKEY_CMD = (1U << UVERBS_ID_NS_SHIFT),
	/* no response */
};

struct hfi2_set_pkey_cmd {
	__u16 pkey;
	__u8 reserved[6];
};

/*
 * ctxt_reset
 * (no arguments)
 */

/*
 * tid_inval_read
 */
enum hfi2_attrs_tid_inval_read {
	HFI2_ATTR_TID_INVAL_READ_CMD = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_ATTR_TID_INVAL_READ_RSP,
};

struct hfi2_tid_inval_read_cmd {
	__aligned_u64 tidlist;  /* user buffer pointer */
	__u32 tidcnt;		/* space for this many TIDs */
	__u32 reserved;
};

struct hfi2_tid_inval_read_rsp {
	__u32 tidcnt;           /* numnber of returned tids */
	__u32 reserved;
};

/*
 * get_vers
 */
enum hfi2_attrs_get_vers {
	/* no cmd */
	HFI2_ATTR_GET_VERS_RSP = (1U << UVERBS_ID_NS_SHIFT),
};

struct hfi2_get_vers_rsp {
	__u32 version;
	__u32 reserved;
};

/*
 * pin_stats
 */
enum hfi2_attrs_pin_stats {
	HFI2_ATTR_PIN_STATS_CMD = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_ATTR_PIN_STATS_RSP,
};

struct hfi2_pin_stats_cmd {
	__u32 memtype;
	/*
	 * If -1, driver returns total number of stats entries for the given
	 * memtype, otherwise returns stats for the given { memtype, index }.
	 */
	__s32 index;
};

struct hfi2_pin_stats_rsp {
	__u64 id;
	__u64 cache_entries;
	__u64 total_refcounts;
	__u64 total_bytes;
	__u64 hits;
	__u64 misses;
	__u64 hint_hits;
	__u64 hint_misses;
	__u64 internal_evictions; /* due to self-imposed size limit */
	__u64 external_evictions; /* system-driven evictions */
};

#endif /* _LINIUX_HFI2_USER_H */
