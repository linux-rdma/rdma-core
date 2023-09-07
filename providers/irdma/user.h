/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2023 Intel Corporation */
#ifndef IRDMA_USER_H
#define IRDMA_USER_H

#include "osdep.h"

#define irdma_handle void *
#define irdma_adapter_handle irdma_handle
#define irdma_qp_handle irdma_handle
#define irdma_cq_handle irdma_handle
#define irdma_pd_id irdma_handle
#define irdma_stag_handle irdma_handle
#define irdma_stag_index __u32
#define irdma_stag __u32
#define irdma_stag_key __u8
#define irdma_tagged_offset __u64
#define irdma_access_privileges __u32
#define irdma_physical_fragment __u64
#define irdma_address_list __u64 *
#define irdma_sgl struct irdma_sge *

#define	IRDMA_MAX_MR_SIZE       0x200000000000ULL

#define IRDMA_ACCESS_FLAGS_LOCALREAD		0x01
#define IRDMA_ACCESS_FLAGS_LOCALWRITE		0x02
#define IRDMA_ACCESS_FLAGS_REMOTEREAD_ONLY	0x04
#define IRDMA_ACCESS_FLAGS_REMOTEREAD		0x05
#define IRDMA_ACCESS_FLAGS_REMOTEWRITE_ONLY	0x08
#define IRDMA_ACCESS_FLAGS_REMOTEWRITE		0x0a
#define IRDMA_ACCESS_FLAGS_BIND_WINDOW		0x10
#define IRDMA_ACCESS_FLAGS_ZERO_BASED		0x20
#define IRDMA_ACCESS_FLAGS_ALL			0x3f

#define IRDMA_OP_TYPE_RDMA_WRITE		0x00
#define IRDMA_OP_TYPE_RDMA_READ			0x01
#define IRDMA_OP_TYPE_SEND			0x03
#define IRDMA_OP_TYPE_SEND_INV			0x04
#define IRDMA_OP_TYPE_SEND_SOL			0x05
#define IRDMA_OP_TYPE_SEND_SOL_INV		0x06
#define IRDMA_OP_TYPE_RDMA_WRITE_SOL		0x0d
#define IRDMA_OP_TYPE_BIND_MW			0x08
#define IRDMA_OP_TYPE_FAST_REG_NSMR		0x09
#define IRDMA_OP_TYPE_INV_STAG			0x0a
#define IRDMA_OP_TYPE_RDMA_READ_INV_STAG	0x0b
#define IRDMA_OP_TYPE_NOP			0x0c
#define IRDMA_OP_TYPE_REC	0x3e
#define IRDMA_OP_TYPE_REC_IMM	0x3f

#define IRDMA_FLUSH_MAJOR_ERR	1

enum irdma_device_caps_const {
	IRDMA_WQE_SIZE =			4,
	IRDMA_CQP_WQE_SIZE =			8,
	IRDMA_CQE_SIZE =			4,
	IRDMA_EXTENDED_CQE_SIZE =		8,
	IRDMA_AEQE_SIZE =			2,
	IRDMA_CEQE_SIZE =			1,
	IRDMA_CQP_CTX_SIZE =			8,
	IRDMA_SHADOW_AREA_SIZE =		8,
	IRDMA_GATHER_STATS_BUF_SIZE =		1024,
	IRDMA_MIN_IW_QP_ID =			0,
	IRDMA_QUERY_FPM_BUF_SIZE =		176,
	IRDMA_COMMIT_FPM_BUF_SIZE =		176,
	IRDMA_MAX_IW_QP_ID =			262143,
	IRDMA_MIN_CEQID =			0,
	IRDMA_MAX_CEQID =			1023,
	IRDMA_CEQ_MAX_COUNT =			IRDMA_MAX_CEQID + 1,
	IRDMA_MIN_CQID =			0,
	IRDMA_MAX_CQID =			524287,
	IRDMA_MIN_AEQ_ENTRIES =			1,
	IRDMA_MAX_AEQ_ENTRIES =			524287,
	IRDMA_MIN_CEQ_ENTRIES =			1,
	IRDMA_MAX_CEQ_ENTRIES =			262143,
	IRDMA_MIN_CQ_SIZE =			1,
	IRDMA_MAX_CQ_SIZE =			1048575,
	IRDMA_DB_ID_ZERO =			0,
	IRDMA_MAX_WQ_FRAGMENT_COUNT =		13,
	IRDMA_MAX_SGE_RD =			13,
	IRDMA_MAX_OUTBOUND_MSG_SIZE =		2147483647,
	IRDMA_MAX_INBOUND_MSG_SIZE =		2147483647,
	IRDMA_MAX_PUSH_PAGE_COUNT =		1024,
	IRDMA_MAX_PE_ENA_VF_COUNT =		32,
	IRDMA_MAX_VF_FPM_ID =			47,
	IRDMA_MAX_SQ_PAYLOAD_SIZE =		2145386496,
	IRDMA_MAX_INLINE_DATA_SIZE =		101,
	IRDMA_MAX_WQ_ENTRIES =			32768,
	IRDMA_Q2_BUF_SIZE =			256,
	IRDMA_QP_CTX_SIZE =			256,
	IRDMA_MAX_PDS =				262144,
};

enum irdma_addressing_type {
	IRDMA_ADDR_TYPE_ZERO_BASED = 0,
	IRDMA_ADDR_TYPE_VA_BASED   = 1,
};

enum irdma_flush_opcode {
	FLUSH_INVALID = 0,
	FLUSH_GENERAL_ERR,
	FLUSH_PROT_ERR,
	FLUSH_REM_ACCESS_ERR,
	FLUSH_LOC_QP_OP_ERR,
	FLUSH_REM_OP_ERR,
	FLUSH_LOC_LEN_ERR,
	FLUSH_FATAL_ERR,
	FLUSH_RETRY_EXC_ERR,
	FLUSH_MW_BIND_ERR,
	FLUSH_REM_INV_REQ_ERR,
};

enum irdma_cmpl_status {
	IRDMA_COMPL_STATUS_SUCCESS = 0,
	IRDMA_COMPL_STATUS_FLUSHED,
	IRDMA_COMPL_STATUS_INVALID_WQE,
	IRDMA_COMPL_STATUS_QP_CATASTROPHIC,
	IRDMA_COMPL_STATUS_REMOTE_TERMINATION,
	IRDMA_COMPL_STATUS_INVALID_STAG,
	IRDMA_COMPL_STATUS_BASE_BOUND_VIOLATION,
	IRDMA_COMPL_STATUS_ACCESS_VIOLATION,
	IRDMA_COMPL_STATUS_INVALID_PD_ID,
	IRDMA_COMPL_STATUS_WRAP_ERROR,
	IRDMA_COMPL_STATUS_STAG_INVALID_PDID,
	IRDMA_COMPL_STATUS_RDMA_READ_ZERO_ORD,
	IRDMA_COMPL_STATUS_QP_NOT_PRIVLEDGED,
	IRDMA_COMPL_STATUS_STAG_NOT_INVALID,
	IRDMA_COMPL_STATUS_INVALID_PHYS_BUF_SIZE,
	IRDMA_COMPL_STATUS_INVALID_PHYS_BUF_ENTRY,
	IRDMA_COMPL_STATUS_INVALID_FBO,
	IRDMA_COMPL_STATUS_INVALID_LEN,
	IRDMA_COMPL_STATUS_INVALID_ACCESS,
	IRDMA_COMPL_STATUS_PHYS_BUF_LIST_TOO_LONG,
	IRDMA_COMPL_STATUS_INVALID_VIRT_ADDRESS,
	IRDMA_COMPL_STATUS_INVALID_REGION,
	IRDMA_COMPL_STATUS_INVALID_WINDOW,
	IRDMA_COMPL_STATUS_INVALID_TOTAL_LEN,
	IRDMA_COMPL_STATUS_UNKNOWN,
};

enum irdma_cmpl_notify {
	IRDMA_CQ_COMPL_EVENT     = 0,
	IRDMA_CQ_COMPL_SOLICITED = 1,
};

enum irdma_qp_caps {
	IRDMA_WRITE_WITH_IMM = 1,
	IRDMA_SEND_WITH_IMM  = 2,
	IRDMA_ROCE	     = 4,
	IRDMA_PUSH_MODE      = 8,
};

struct irdma_qp_uk;
struct irdma_cq_uk;
struct irdma_qp_uk_init_info;
struct irdma_cq_uk_init_info;

struct irdma_sge {
	irdma_tagged_offset tag_off;
	__u32 len;
	irdma_stag stag;
};

struct irdma_ring {
	__u32 head;
	__u32 tail;
	__u32 size;
};

struct irdma_cqe {
	__le64 buf[IRDMA_CQE_SIZE];
};

struct irdma_extended_cqe {
	__le64 buf[IRDMA_EXTENDED_CQE_SIZE];
};

struct irdma_post_send {
	irdma_sgl sg_list;
	__u32 num_sges;
	__u32 qkey;
	__u32 dest_qp;
	__u32 ah_id;
};

struct irdma_post_rq_info {
	__u64 wr_id;
	irdma_sgl sg_list;
	__u32 num_sges;
};

struct irdma_rdma_write {
	irdma_sgl lo_sg_list;
	__u32 num_lo_sges;
	struct irdma_sge rem_addr;
};

struct irdma_rdma_read {
	irdma_sgl lo_sg_list;
	__u32 num_lo_sges;
	struct irdma_sge rem_addr;
};

struct irdma_bind_window {
	irdma_stag mr_stag;
	__u64 bind_len;
	void *va;
	enum irdma_addressing_type addressing_type;
	bool ena_reads:1;
	bool ena_writes:1;
	irdma_stag mw_stag;
	bool mem_window_type_1:1;
};

struct irdma_inv_local_stag {
	irdma_stag target_stag;
};

struct irdma_post_sq_info {
	__u64 wr_id;
	__u8 op_type;
	__u8 l4len;
	bool signaled:1;
	bool read_fence:1;
	bool local_fence:1;
	bool inline_data:1;
	bool imm_data_valid:1;
	bool push_wqe:1;
	bool report_rtt:1;
	bool udp_hdr:1;
	bool defer_flag:1;
	__u32 imm_data;
	__u32 stag_to_inv;
	union {
		struct irdma_post_send send;
		struct irdma_rdma_write rdma_write;
		struct irdma_rdma_read rdma_read;
		struct irdma_bind_window bind_window;
		struct irdma_inv_local_stag inv_local_stag;
	} op;
};

struct irdma_cq_poll_info {
	__u64 wr_id;
	irdma_qp_handle qp_handle;
	__u32 bytes_xfered;
	__u32 tcp_seq_num_rtt;
	__u32 qp_id;
	__u32 ud_src_qpn;
	__u32 imm_data;
	irdma_stag inv_stag; /* or L_R_Key */
	enum irdma_cmpl_status comp_status;
	__u16 major_err;
	__u16 minor_err;
	__u16 ud_vlan;
	__u8 ud_smac[6];
	__u8 op_type;
	__u8 q_type;
	bool stag_invalid_set:1; /* or L_R_Key set */
	bool push_dropped:1;
	bool error:1;
	bool solicited_event:1;
	bool ipv4:1;
	bool ud_vlan_valid:1;
	bool ud_smac_valid:1;
	bool imm_valid:1;
};

int irdma_uk_inline_rdma_write(struct irdma_qp_uk *qp,
			       struct irdma_post_sq_info *info, bool post_sq);
int irdma_uk_inline_send(struct irdma_qp_uk *qp,
			 struct irdma_post_sq_info *info, bool post_sq);
int irdma_uk_mw_bind(struct irdma_qp_uk *qp, struct irdma_post_sq_info *info,
		     bool post_sq);
int irdma_uk_post_nop(struct irdma_qp_uk *qp, __u64 wr_id, bool signaled,
		      bool post_sq);
int irdma_uk_post_receive(struct irdma_qp_uk *qp,
			  struct irdma_post_rq_info *info);
void irdma_uk_qp_post_wr(struct irdma_qp_uk *qp);
int irdma_uk_rdma_read(struct irdma_qp_uk *qp, struct irdma_post_sq_info *info,
		       bool inv_stag, bool post_sq);
int irdma_uk_rdma_write(struct irdma_qp_uk *qp, struct irdma_post_sq_info *info,
			bool post_sq);
int irdma_uk_send(struct irdma_qp_uk *qp, struct irdma_post_sq_info *info,
		  bool post_sq);
int irdma_uk_stag_local_invalidate(struct irdma_qp_uk *qp,
				   struct irdma_post_sq_info *info,
				   bool post_sq);

struct irdma_wqe_uk_ops {
	void (*iw_copy_inline_data)(__u8 *dest, struct irdma_sge *sge_list,
				    __u32 num_sges, __u8 polarity);
	__u16 (*iw_inline_data_size_to_quanta)(__u32 data_size);
	void (*iw_set_fragment)(__le64 *wqe, __u32 offset, struct irdma_sge *sge,
				__u8 valid);
	void (*iw_set_mw_bind_wqe)(__le64 *wqe,
				   struct irdma_bind_window *op_info);
};

int irdma_uk_cq_poll_cmpl(struct irdma_cq_uk *cq,
			  struct irdma_cq_poll_info *info);
void irdma_uk_cq_request_notification(struct irdma_cq_uk *cq,
				      enum irdma_cmpl_notify cq_notify);
void irdma_uk_cq_resize(struct irdma_cq_uk *cq, void *cq_base, int size);
void irdma_uk_cq_set_resized_cnt(struct irdma_cq_uk *qp, __u16 cnt);
int irdma_uk_cq_init(struct irdma_cq_uk *cq,
		     struct irdma_cq_uk_init_info *info);
int irdma_uk_qp_init(struct irdma_qp_uk *qp,
		     struct irdma_qp_uk_init_info *info);
int irdma_uk_calc_depth_shift_sq(struct irdma_qp_uk_init_info *ukinfo,
				 __u32 *sq_depth, __u8 *sq_shift);
int irdma_uk_calc_depth_shift_rq(struct irdma_qp_uk_init_info *ukinfo,
				 __u32 *rq_depth, __u8 *rq_shift);

struct irdma_sq_uk_wr_trk_info {
	__u64 wrid;
	__u32 wr_len;
	__u16 quanta;
	__u8 reserved[2];
};

struct irdma_qp_quanta {
	__le64 elem[IRDMA_WQE_SIZE];
};

struct irdma_qp_uk {
	struct irdma_qp_quanta *sq_base;
	struct irdma_qp_quanta *rq_base;
	struct irdma_uk_attrs *uk_attrs;
	__u32 *wqe_alloc_db;
	struct irdma_sq_uk_wr_trk_info *sq_wrtrk_array;
	__u64 *rq_wrid_array;
	__le64 *shadow_area;
	__le32 *push_db;
	__le64 *push_wqe;
	struct irdma_ring sq_ring;
	struct irdma_ring rq_ring;
	struct irdma_ring initial_ring;
	__u32 qp_id;
	__u32 qp_caps;
	__u32 sq_size;
	__u32 rq_size;
	__u32 max_sq_frag_cnt;
	__u32 max_rq_frag_cnt;
	__u32 max_inline_data;
	struct irdma_wqe_uk_ops wqe_ops;
	__u16 conn_wqes;
	__u8 qp_type;
	__u8 swqe_polarity;
	__u8 swqe_polarity_deferred;
	__u8 rwqe_polarity;
	__u8 rq_wqe_size;
	__u8 rq_wqe_size_multiplier;
	bool deferred_flag:1;
	bool push_mode:1; /* whether the last post wqe was pushed */
	bool push_dropped:1;
	bool first_sq_wq:1;
	bool sq_flush_complete:1; /* Indicates flush was seen and SQ was empty after the flush */
	bool rq_flush_complete:1; /* Indicates flush was seen and RQ was empty after the flush */
	bool destroy_pending:1; /* Indicates the QP is being destroyed */
	void *back_qp;
	pthread_spinlock_t *lock;
	__u8 dbg_rq_flushed;
	__u8 sq_flush_seen;
	__u8 rq_flush_seen;
};

struct irdma_cq_uk {
	struct irdma_cqe *cq_base;
	__u32 *cqe_alloc_db;
	__u32 *cq_ack_db;
	__le64 *shadow_area;
	__u32 cq_id;
	__u32 cq_size;
	struct irdma_ring cq_ring;
	__u8 polarity;
	bool avoid_mem_cflct:1;
};

struct irdma_qp_uk_init_info {
	struct irdma_qp_quanta *sq;
	struct irdma_qp_quanta *rq;
	struct irdma_uk_attrs *uk_attrs;
	__u32 *wqe_alloc_db;
	__le64 *shadow_area;
	struct irdma_sq_uk_wr_trk_info *sq_wrtrk_array;
	__u64 *rq_wrid_array;
	__u32 qp_id;
	__u32 qp_caps;
	__u32 sq_size;
	__u32 rq_size;
	__u32 max_sq_frag_cnt;
	__u32 max_rq_frag_cnt;
	__u32 max_inline_data;
	__u32 sq_depth;
	__u32 rq_depth;
	__u8 first_sq_wq;
	__u8 type;
	__u8 sq_shift;
	__u8 rq_shift;
	int abi_ver;
	bool legacy_mode;
};

struct irdma_cq_uk_init_info {
	__u32 *cqe_alloc_db;
	__u32 *cq_ack_db;
	struct irdma_cqe *cq_base;
	__le64 *shadow_area;
	__u32 cq_size;
	__u32 cq_id;
	bool avoid_mem_cflct;
};

__le64 *irdma_qp_get_next_send_wqe(struct irdma_qp_uk *qp, __u32 *wqe_idx,
				   __u16 quanta, __u32 total_size,
				   struct irdma_post_sq_info *info);
__le64 *irdma_qp_get_next_recv_wqe(struct irdma_qp_uk *qp, __u32 *wqe_idx);
void irdma_uk_clean_cq(void *q, struct irdma_cq_uk *cq);
int irdma_nop(struct irdma_qp_uk *qp, __u64 wr_id, bool signaled, bool post_sq);
int irdma_fragcnt_to_quanta_sq(__u32 frag_cnt, __u16 *quanta);
int irdma_fragcnt_to_wqesize_rq(__u32 frag_cnt, __u16 *wqe_size);
void irdma_get_wqe_shift(struct irdma_uk_attrs *uk_attrs, __u32 sge,
			 __u32 inline_data, __u8 *shift);
int irdma_get_sqdepth(struct irdma_uk_attrs *uk_attrs, __u32 sq_size,
		      __u8 shift, __u32 *wqdepth);
int irdma_get_rqdepth(struct irdma_uk_attrs *uk_attrs, __u32 rq_size,
		      __u8 shift, __u32 *wqdepth);
void irdma_qp_push_wqe(struct irdma_qp_uk *qp, __le64 *wqe, __u16 quanta,
		       __u32 wqe_idx, bool post_sq);
void irdma_clr_wqes(struct irdma_qp_uk *qp, __u32 qp_wqe_idx);
#endif /* IRDMA_USER_H */
