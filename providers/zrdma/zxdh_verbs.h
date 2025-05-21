/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
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
#ifndef __ZXDH_VERBS_H__
#define __ZXDH_VERBS_H__
#include "zxdh_defs.h"

#define zxdh_handle void *
#define zxdh_adapter_handle zxdh_handle
#define zxdh_qp_handle zxdh_handle
#define zxdh_cq_handle zxdh_handle
#define zxdh_pd_id zxdh_handle
#define zxdh_stag_handle zxdh_handle
#define zxdh_stag_index __u32
#define zxdh_stag __u32
#define zxdh_stag_key __u8
#define zxdh_tagged_offset __u64
#define zxdh_access_privileges __u32
#define zxdh_physical_fragment __u64
#define zxdh_address_list __u64 *
#define zxdh_sgl struct zxdh_sge *

#define ZXDH_MAX_MR_SIZE 0x200000000000ULL

#define ZXDH_ACCESS_FLAGS_LOCALREAD 0x01
#define ZXDH_ACCESS_FLAGS_LOCALWRITE 0x02
#define ZXDH_ACCESS_FLAGS_REMOTEREAD_ONLY 0x04
#define ZXDH_ACCESS_FLAGS_REMOTEREAD 0x05
#define ZXDH_ACCESS_FLAGS_REMOTEWRITE_ONLY 0x08
#define ZXDH_ACCESS_FLAGS_REMOTEWRITE 0x0a
#define ZXDH_ACCESS_FLAGS_BIND_WINDOW 0x10
#define ZXDH_ACCESS_FLAGS_ZERO_BASED 0x20
#define ZXDH_ACCESS_FLAGS_ALL 0x3f

#define ZXDH_OP_TYPE_NOP 0x00
#define ZXDH_OP_TYPE_SEND 0x01
#define ZXDH_OP_TYPE_SEND_WITH_IMM 0x02
#define ZXDH_OP_TYPE_SEND_INV 0x03
#define ZXDH_OP_TYPE_WRITE 0x04
#define ZXDH_OP_TYPE_WRITE_WITH_IMM 0x05
#define ZXDH_OP_TYPE_READ 0x06
#define ZXDH_OP_TYPE_BIND_MW 0x07
#define ZXDH_OP_TYPE_FAST_REG_MR 0x08
#define ZXDH_OP_TYPE_LOCAL_INV 0x09
#define ZXDH_OP_TYPE_UD_SEND 0x0a
#define ZXDH_OP_TYPE_UD_SEND_WITH_IMM 0x0b
#define ZXDH_OP_TYPE_REC 0x3e
#define ZXDH_OP_TYPE_REC_IMM 0x3f

#define ZXDH_FLUSH_MAJOR_ERR 1
#define ZXDH_RETRY_ACK_MAJOR_ERR 0x8
#define ZXDH_RETRY_ACK_MINOR_ERR 0xf3
#define ZXDH_TX_WINDOW_QUERY_ITEM_MINOR_ERR 0xf5

#define ZXDH_MAX_SQ_FRAG 31
#define ZXDH_MAX_SQ_INLINE_DATELEN_WITH_IMM 210

#define INLINE_DATASIZE_7BYTES 7
#define INLINE_DATASIZE_24BYTES 24
#define INLINE_FRAG_DATASIZE_31BYTES 31

#define INLINE_DATA_OFFSET_7BYTES 7
#define WQE_OFFSET_7BYTES 7
#define WQE_OFFSET_8BYTES 8
#define WQE_OFFSET_24BYTES 24

#define ZXDH_SQE_SIZE 4
#define ZXDH_RQE_SIZE 2

#define ZXDH_SRQ_INVALID_LKEY 0x100
#define ZXDH_SRQ_DB_INIT_VALUE 0x8000

#define ZXDH_WQEALLOC_WQE_DESC_INDEX GENMASK(31, 20)

#define ZXDH_SRQE_SIZE 2
#define ZXDH_CQE_SIZE 8
#define ZXDH_EXTENDED_CQE_SIZE 8
#define ZXDH_MAX_INLINE_DATA_SIZE 217
#define ZXDH_MAX_SQ_PAYLOAD_SIZE 2147483648
#define ZXDH_MIN_CQ_SIZE 1
#define ZXDH_MAX_CQ_SIZE 2097152

enum zxdh_addressing_type {
	ZXDH_ADDR_TYPE_ZERO_BASED = 0,
	ZXDH_ADDR_TYPE_VA_BASED = 1,
};

enum zxdh_flush_opcode {
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

enum zxdh_cmpl_status {
	ZXDH_COMPL_STATUS_SUCCESS = 0,
	ZXDH_COMPL_STATUS_FLUSHED,
	ZXDH_COMPL_STATUS_INVALID_WQE,
	ZXDH_COMPL_STATUS_QP_CATASTROPHIC,
	ZXDH_COMPL_STATUS_REMOTE_TERMINATION,
	ZXDH_COMPL_STATUS_INVALID_STAG,
	ZXDH_COMPL_STATUS_BASE_BOUND_VIOLATION,
	ZXDH_COMPL_STATUS_ACCESS_VIOLATION,
	ZXDH_COMPL_STATUS_INVALID_PD_ID,
	ZXDH_COMPL_STATUS_WRAP_ERROR,
	ZXDH_COMPL_STATUS_STAG_INVALID_PDID,
	ZXDH_COMPL_STATUS_RDMA_READ_ZERO_ORD,
	ZXDH_COMPL_STATUS_QP_NOT_PRIVLEDGED,
	ZXDH_COMPL_STATUS_STAG_NOT_INVALID,
	ZXDH_COMPL_STATUS_INVALID_PHYS_BUF_SIZE,
	ZXDH_COMPL_STATUS_INVALID_PHYS_BUF_ENTRY,
	ZXDH_COMPL_STATUS_INVALID_FBO,
	ZXDH_COMPL_STATUS_INVALID_LEN,
	ZXDH_COMPL_STATUS_INVALID_ACCESS,
	ZXDH_COMPL_STATUS_PHYS_BUF_LIST_TOO_LONG,
	ZXDH_COMPL_STATUS_INVALID_VIRT_ADDRESS,
	ZXDH_COMPL_STATUS_INVALID_REGION,
	ZXDH_COMPL_STATUS_INVALID_WINDOW,
	ZXDH_COMPL_STATUS_INVALID_TOTAL_LEN,
	ZXDH_COMPL_STATUS_RETRY_ACK_ERR,
	ZXDH_COMPL_STATUS_TX_WINDOW_QUERY_ITEM_ERR,
	ZXDH_COMPL_STATUS_UNKNOWN,
};

enum zxdh_cmpl_notify {
	ZXDH_CQ_COMPL_EVENT = 0,
	ZXDH_CQ_COMPL_SOLICITED = 1,
};

enum zxdh_qp_caps {
	ZXDH_WRITE_WITH_IMM = 1,
	ZXDH_SEND_WITH_IMM = 2,
	ZXDH_ROCE = 4,
	ZXDH_PUSH_MODE = 8,
};

enum zxdh_page_size {
	ZXDH_PAGE_SIZE_4K = 0,
	ZXDH_PAGE_SIZE_2M = 9,
	ZXDH_PAGE_SIZE_1G = 18,
};

enum zxdh_rdmatx_parse_top_err {
	ZXDH_TX_PARSE_TOP_AXI_ERR = 0x1,
	ZXDH_TX_PARSE_TOP_WQE_FLUSH = 0x10001,
	ZXDH_TX_PARSE_TOP_ORD_ERR = 0x20020,
	ZXDH_TX_PARSE_TOP_OPCODE_ERR_FLAG = 0x20021,
	ZXDH_TX_PARSE_TOP_CQP_STATE_AXI_ERR = 0x20022,
	ZXDH_TX_PARSE_TOP_WQE_LEN_ERR = 0x20023,
	ZXDH_TX_PARSE_TOP_DATA_LEN_ERR = 0x20024,
	ZXDH_TX_PARSE_TOP_AH_VALID0_ERR = 0x20025,
	ZXDH_TX_PARSE_TOP_UD_PDINDEX_ERR = 0x20026,
	ZXDH_TX_PARSE_TOP_QP_STATE_ERR = 0x20027,
	ZXDH_TX_PARSE_TOP_SERVICE_TYPE_ERR = 0x20028,
	ZXDH_TX_PARSE_TOP_UD_PAYLOAD_ERR = 0x20029,
	ZXDH_TX_PARSE_TOP_WQE_LEN0_ERR = 0x2002a,
	ZXDH_TX_PARSE_TOP_WQE_DEFICIENT_CLR_ERR = 0x2002b,
	ZXDH_TX_PARSE_TOP_IMMDT_ERR = 0x2002c,
	ZXDH_TX_PARSE_TOP_FRAGMENT_LENGTH_ERR = 0x2009f,
	ZXDH_TX_PARSE_TOP_MRTE_STATE_ERR = 0x90091,
	ZXDH_TX_PARSE_TOP_QP_CHECK_ERR = 0x90092,
	ZXDH_TX_PARSE_TOP_PD_CHECK_ERR = 0x90093,
	ZXDH_TX_PARSE_TOP_LKEY_CHECK_ERR = 0x90094,
	ZXDH_TX_PARSE_TOP_STAG_INDEX_CHECK_ERR = 0x90095,
	ZXDH_TX_PARSE_TOP_VADDR_LEN_CHECK_ERR = 0x90096,
	ZXDH_TX_PARSE_TOP_ACCESS_RIGHT_CHECK_ERR = 0x90097,
	ZXDH_TX_PARSE_TOP_STAG_INDEX_CHECK_ZERO_ERR = 0x90098,
};

enum zxdh_rdmatx_ack_sys_top_err {
	ZXDH_TX_ACK_SYS_TOP_NVME_INDEX_ERR = 0x30030,
	ZXDH_TX_ACK_SYS_TOP_NVME_NOF_QID_ERR = 0x30031,
	ZXDH_TX_ACK_SYS_TOP_NVME_NOF_PD_INDEX_ERR = 0x30032,
	ZXDH_TX_ACK_SYS_TOP_NVME_LENGTH_ERR = 0x30033,
	ZXDH_TX_ACK_SYS_TOP_NVME_KEY_ERR = 0x30034,
	ZXDH_TX_ACK_SYS_TOP_NVME_ACCESS_ERR = 0x30035,
	ZXDH_TX_ACK_SYS_TOP_MRTE_STATE_ERR = 0x50091,
	ZXDH_TX_ACK_SYS_TOP_QP_CHECK_ERR = 0x50092,
	ZXDH_TX_ACK_SYS_TOP_PD_CHECK_ERR = 0x50093,
	ZXDH_TX_ACK_SYS_TOP_LKEY_CHECK_ERR = 0x50094,
	ZXDH_TX_ACK_SYS_TOP_STAG_INDEX_CHECK_ERR = 0x50095,
	ZXDH_TX_ACK_SYS_TOP_VADDR_LEN_CHECK_ERR = 0x50096,
	ZXDH_TX_ACK_SYS_TOP_ACCESS_RIGHT_CHECK_ERR = 0x50097,
	ZXDH_TX_ACK_SYS_TOP_STAG_INDEX_CHECK_ZERO_ERR = 0x50098,
	ZXDH_TX_ACK_SYS_TOP_LOC_LEN_ERR = 0x600c0,
	ZXDH_TX_ACK_SYS_TOP_NAK_INVALID_REQ = 0x700d0,
	ZXDH_TX_ACK_SYS_TOP_NAK_REMOTE_ACCESS_ERR = 0x700d1,
	ZXDH_TX_ACK_SYS_TOP_NAK_REMOTE_OPERATIONAL_ERR = 0x700d2,
	ZXDH_TX_ACK_SYS_TOP_NAK_RETRY_LIMIT = 0x800f1,
	ZXDH_TX_ACK_SYS_TOP_READ_RETRY_LIMIT = 0x800f2,
	ZXDH_TX_ACK_SYS_TOP_TIMEOUT_RETRY_LIMIT = 0x800f3,
	ZXDH_TX_ACK_SYS_TOP_RNR_RETRY_LIMIT = 0x800f4,
};

enum zxdh_rdmatx_window_top_err {
	ZXDH_TX_WINDOW_TOP_WINDOW_NO_ENTRY = 0x800f5,
	ZXDH_TX_WINDOW_TOP_WINDOW_BACK_MSN = 0x800f6,
	ZXDH_TX_WINDOW_TOP_WINDOW_SMALL_MSN = 0x800f7,
};

enum zxdh_rdmatx_doorbell_mgr_err {
	ZXDH_TX_DOORBELL_MGR_INDEX_CHECK_ERROR = 0x30036,
	ZXDH_TX_DOORBELL_MGR_QID_CHECK_ERROR = 0x30037,
	ZXDH_TX_DOORBELL_MGR_PD_INDEX_CHECK_ERROR = 0x30038,
	ZXDH_TX_DOORBELL_MGR_LENGTH_CHECK_ERROR = 0x30039,
	ZXDH_TX_DOORBELL_MGR_KEY_CHECK_ERROR = 0x3003a,
	ZXDH_TX_DOORBELL_MGR_ACCESS_CHECK_ERROR = 0x3003b,
};

enum zxdh_rdmarx_err {
	ZXDH_RX_CQP_FLUSH = 0x12,
	ZXDH_RX_FIRST_PACKET_ERR = 0x4f,
	ZXDH_RX_INVALID_OPCODE = 0x50,
	ZXDH_RX_ORDER_ERR = 0x51,
	ZXDH_RX_LEN_ERR = 0x52,
	ZXDH_RX_SQR_STATE_ERR = 0x53,
	ZXDH_RX_WQE_SIGN_ERR = 0x54,
	ZXDH_RX_WQE_LEN_ERR = 0x55,
	ZXDH_RX_SQR_WATER_LEVEL_ERR = 0x80,
	ZXDH_RX_SRQ_AXI_RESP_ERR = 0xb1,
	ZXDH_RX_CQ_OVERFLOW_ERR = 0x76,
	ZXDH_RX_QP_CQ_OVERFLOW_ERR = 0x78,
	ZXDH_RX_CQ_STATE_ERR = 0x7a,
	ZXDH_RX_CQ_AXI_ERR = 0x7b,
	ZXDH_RX_QP_CQ_AXI_ERR = 0x7c,
	ZXDH_RX_NOF_IOQ_ERR = 0x70,
	ZXDH_RX_NOF_PDNUM_ERR = 0x71,
	ZXDH_RX_NOF_LEN_ERR = 0x72,
	ZXDH_RX_NOF_RKEY_ERR = 0x73,
	ZXDH_RX_NOF_ACC_ERR = 0x74,
	ZXDH_RX_IRD_OVF = 0x77,
	ZXDH_RX_MR_MW_STATE_FREE_ERR = 0x90,
	ZXDH_RX_MR_MW_STATE_INVALID_ERR = 0x91,
	ZXDH_RX_TYPE2B_MW_QPN_CHECK_ERR = 0x92,
	ZXDH_RX_MR_MW_PD_CHECK_ERR = 0x93,
	ZXDH_RX_MR_MW_KEY_CHECK_ERR = 0x94,
	ZXDH_RX_MR_MW_STAG_INDEX_CHECK_ERR = 0x95,
	ZXDH_RX_MR_MW_BOUNDARY_CHECK_ERR = 0x96,
	ZXDH_RX_MR_MW_ACCESS_CHECK_ERR = 0x97,
	ZXDH_RX_MR_MW_0STAG_INDEX_CHECK_ERR = 0x98,
	ZXDH_RX_MW_STATE_INVALID_ERR = 0x99,
	ZXDH_RX_MW_PD_CHECK_ERR = 0x9a,
	ZXDH_RX_MW_RKEY_CHECK_ERR = 0x9b,
	ZXDH_RX_TYPE2BMW_QPN_CHECK_ERR = 0x9c,
	ZXDH_RX_MW_STAG_INDEX_CHECK_ERR = 0x9d,
	ZXDH_RX_MW_SHARE_MR_CHECK_ERR = 0x9e,
	ZXDH_RX_MW_TYPE1_CHECK_ERR = 0x9f,
	ZXDH_RX_MR_PD_CHECK_ERR = 0xa0,
	ZXDH_RX_MR_RKEY_CHECK_ERR = 0xa1,
	ZXDH_RX_MR_SHARE_MR_CHECK_ERR = 0xa4,
	ZXDH_RX_MR_BOND_MW_NUM_CHECK_ERR = 0xa5,
	ZXDH_RX_MR_CANBE_R_INVALID_CHECK_ERR = 0xa6,
	ZXDH_RX_AXI_RESP_ERR = 0xb0,
};

struct zxdh_qp;
struct zxdh_cq;
struct zxdh_cq_init_info;

struct zxdh_sge {
	zxdh_tagged_offset tag_off;
	__u32 len;
	zxdh_stag stag;
};

struct zxdh_ring {
	__u32 head;
	__u32 tail;
	__u32 size;
};

struct zxdh_cqe {
	__le64 buf[ZXDH_CQE_SIZE];
};

struct zxdh_extended_cqe {
	__le64 buf[ZXDH_EXTENDED_CQE_SIZE];
};

struct zxdh_post_send {
	zxdh_sgl sg_list;
	__u32 num_sges;
	__u32 qkey;
	__u32 dest_qp;
	__u32 ah_id;
};

struct zxdh_inline_rdma_send {
	void *data;
	__u32 len;
	__u32 qkey;
	__u32 dest_qp;
	__u32 ah_id;
};

struct zxdh_post_rq_info {
	__u64 wr_id;
	zxdh_sgl sg_list;
	__u32 num_sges;
};

struct zxdh_rdma_write {
	zxdh_sgl lo_sg_list;
	__u32 num_lo_sges;
	struct zxdh_sge rem_addr;
};

struct zxdh_inline_rdma_write {
	void *data;
	__u32 len;
	struct zxdh_sge rem_addr;
};

struct zxdh_rdma_read {
	zxdh_sgl lo_sg_list;
	__u32 num_lo_sges;
	struct zxdh_sge rem_addr;
};

struct zxdh_bind_window {
	zxdh_stag mr_stag;
	__u64 bind_len;
	void *va;
	enum zxdh_addressing_type addressing_type;
	__u8 ena_reads : 1;
	__u8 ena_writes : 1;
	zxdh_stag mw_stag;
	__u8 mem_window_type_1 : 1;
	__u8 host_page_size;
	__u8 leaf_pbl_size;
	__u16 root_leaf_offset;
	__u64 mw_pa_pble_index;
};

struct zxdh_inv_local_stag {
	zxdh_stag target_stag;
};

struct zxdh_post_sq_info {
	__u64 wr_id;
	__u8 op_type;
	__u8 l4len;
	__u8 signaled : 1;
	__u8 read_fence : 1;
	__u8 local_fence : 1;
	__u8 inline_data : 1;
	__u8 imm_data_valid : 1;
	__u8 push_wqe : 1;
	__u8 report_rtt : 1;
	__u8 udp_hdr : 1;
	__u8 defer_flag : 1;
	__u8 solicited : 1;
	__u32 imm_data;
	__u32 stag_to_inv;
	union {
		struct zxdh_post_send send;
		struct zxdh_rdma_write rdma_write;
		struct zxdh_rdma_read rdma_read;
		struct zxdh_bind_window bind_window;
		struct zxdh_inv_local_stag inv_local_stag;
		struct zxdh_inline_rdma_write inline_rdma_write;
		struct zxdh_inline_rdma_send inline_rdma_send;
	} op;
};

struct zxdh_cq_poll_info {
	__u64 wr_id;
	zxdh_qp_handle qp_handle;
	__u32 bytes_xfered;
	__u32 tcp_seq_num_rtt;
	__u32 qp_id;
	__u32 ud_src_qpn;
	__u32 imm_data;
	zxdh_stag inv_stag; /* or L_R_Key */
	enum zxdh_cmpl_status comp_status;
	__u16 major_err;
	__u16 minor_err;
	__u8 op_type;
	__u8 stag_invalid_set : 1; /* or L_R_Key set */
	__u8 push_dropped : 1;
	__u8 error : 1;
	__u8 solicited_event : 1;
	__u8 ipv4 : 1;
	__u8 imm_valid : 1;
};

enum zxdh_status_code
zxdh_mw_bind(struct zxdh_qp *qp, struct zxdh_post_sq_info *info, bool post_sq);
enum zxdh_status_code zxdh_post_nop(struct zxdh_qp *qp, __u64 wr_id,
				    bool signaled, bool post_sq);
enum zxdh_status_code zxdh_rdma_read(struct zxdh_qp *qp,
				     struct zxdh_post_sq_info *info,
				     bool inv_stag, bool post_sq);
enum zxdh_status_code zxdh_rdma_write(struct zxdh_qp *qp,
				      struct zxdh_post_sq_info *info,
				      bool post_sq);
enum zxdh_status_code
zxdh_ud_send(struct zxdh_qp *qp, struct zxdh_post_sq_info *info, bool post_sq);
enum zxdh_status_code zxdh_stag_local_invalidate(struct zxdh_qp *qp,
						 struct zxdh_post_sq_info *info,
						 bool post_sq);

struct zxdh_wqe_ops {
	void (*iw_copy_inline_data)(__u8 *dest, __u8 *src, __u32 len,
				    __u8 polarity, bool imm_data_flag);
	__u16 (*iw_inline_data_size_to_quanta)(__u32 data_size,
					       bool imm_data_flag);
	void (*iw_set_fragment)(__le64 *wqe, __u32 offset, struct zxdh_sge *sge,
				__u8 valid);
	void (*iw_set_mw_bind_wqe)(__le64 *wqe,
				   struct zxdh_bind_window *op_info);
};

__le64 *get_current_cqe(struct zxdh_cq *cq);
enum zxdh_status_code zxdh_cq_poll_cmpl(struct zxdh_cq *cq,
					struct zxdh_cq_poll_info *info);
void zxdh_cq_request_notification(struct zxdh_cq *cq,
				  enum zxdh_cmpl_notify cq_notify);
void zxdh_cq_resize(struct zxdh_cq *cq, void *cq_base, int size);
void zxdh_cq_set_resized_cnt(struct zxdh_cq *qp, __u16 cnt);
enum zxdh_status_code zxdh_cq_init(struct zxdh_cq *cq,
				   struct zxdh_cq_init_info *info);
struct zxdh_sq_wr_trk_info {
	__u64 wrid;
	__u32 wr_len;
	__u16 quanta;
	__u8 reserved[2];
};

struct zxdh_qp_sq_quanta {
	__le64 elem[ZXDH_SQE_SIZE];
};

struct zxdh_qp_rq_quanta {
	__le64 elem[ZXDH_RQE_SIZE];
};

struct zxdh_dev_attrs {
	__u64 feature_flags;
	__aligned_u64 sq_db_pa;
	__aligned_u64 cq_db_pa;
	__u32 max_hw_wq_frags;
	__u32 max_hw_read_sges;
	__u32 max_hw_inline;
	__u32 max_hw_rq_quanta;
	__u32 max_hw_srq_quanta;
	__u32 max_hw_wq_quanta;
	__u32 min_hw_cq_size;
	__u32 max_hw_cq_size;
	__u16 max_hw_sq_chunk;
	__u32 max_hw_srq_wr;
	__u8 db_addr_type;
	__u8 chip_rev;
	__u16 rdma_tool_flags;
};

struct zxdh_hw_attrs {
	struct zxdh_dev_attrs dev_attrs;
	__u64 max_hw_outbound_msg_size;
	__u64 max_hw_inbound_msg_size;
	__u64 max_mr_size;
	__u32 min_hw_qp_id;
	__u32 min_hw_aeq_size;
	__u32 max_hw_aeq_size;
	__u32 min_hw_ceq_size;
	__u32 max_hw_ceq_size;
	__u32 max_hw_device_pages;
	__u32 max_hw_vf_fpm_id;
	__u32 first_hw_vf_fpm_id;
	__u32 max_hw_ird;
	__u32 max_hw_ord;
	__u32 max_hw_wqes;
	__u32 max_hw_pds;
	__u32 max_hw_ena_vf_count;
	__u32 max_qp_wr;
	__u32 max_pe_ready_count;
	__u32 max_done_count;
	__u32 max_sleep_count;
	__u32 max_cqp_compl_wait_time_ms;
	__u16 max_stat_inst;
};

struct zxdh_qp {
	struct zxdh_qp_sq_quanta *sq_base;
	struct zxdh_qp_rq_quanta *rq_base;
	struct zxdh_dev_attrs *dev_attrs;
	__u32 *wqe_alloc_db;
	struct zxdh_sq_wr_trk_info *sq_wrtrk_array;
	__u64 *rq_wrid_array;
	__le64 *shadow_area;
	__le32 *push_db;
	__le64 *push_wqe;
	struct zxdh_ring sq_ring;
	struct zxdh_ring rq_ring;
	struct zxdh_ring initial_ring;
	__u32 qp_id;
	__u32 qp_caps;
	__u32 sq_size;
	__u32 rq_size;
	__u32 max_sq_frag_cnt;
	__u32 max_rq_frag_cnt;
	__u32 max_inline_data;
	struct zxdh_wqe_ops wqe_ops;
	__u16 conn_wqes;
	__u8 qp_type;
	__u8 swqe_polarity;
	__u8 swqe_polarity_deferred;
	__u8 rwqe_polarity;
	__u8 rq_wqe_size;
	__u8 rq_wqe_size_multiplier;
	__u8 deferred_flag : 1;
	__u8 push_mode : 1; /* whether the last post wqe was pushed */
	__u8 push_dropped : 1;
	__u8 sq_flush_complete : 1; /* Indicates flush was seen and SQ was empty after the flush */
	__u8 rq_flush_complete : 1; /* Indicates flush was seen and RQ was empty after the flush */
	__u8 destroy_pending : 1; /* Indicates the QP is being destroyed */
	void *back_qp;
	zxdh_sgl split_sg_list;
	pthread_spinlock_t *lock;
	__u16 rwqe_signature;
	__u8 dbg_rq_flushed;
	__u8 sq_flush_seen;
	__u8 rq_flush_seen;
	__u8 is_srq;
	__u16 mtu;
	__u32 next_psn;
	__u32 cqe_last_ack_qsn;
	__u32 qp_last_ack_qsn;
	__u8 cqe_retry_cnt;
	__u8 qp_reset_cnt;
};

struct zxdh_cq {
	struct zxdh_cqe *cq_base;
	__u32 *cqe_alloc_db;
	__u32 *cq_ack_db;
	__le64 *shadow_area;
	__u32 cq_id;
	__u32 cq_size;
	__u32 cqe_rd_cnt;
	struct zxdh_ring cq_ring;
	__u8 polarity;
	__u8 cqe_size;
};

struct zxdh_srq {
	struct zxdh_srq_wqe *srq_base;
	struct zxdh_dev_attrs *dev_attrs;
	__le16 *srq_list_base;
	__le64 *srq_db_base;
	__u32 srq_id;
	__u32 srq_size;
	__u32 log2_srq_size;
	__u32 srq_list_size;
	struct zxdh_ring srq_ring;
	struct zxdh_ring srq_list_ring;
	__u8 srq_list_polarity;
	__u64 *srq_wrid_array;
	__u8 srq_wqe_size;
	__u8 srq_wqe_size_multiplier;
	__u32 srq_caps;
	__u32 max_srq_frag_cnt;
	__u32 srq_type;
	pthread_spinlock_t *lock;
	__u8 srq_flush_complete : 1; /* Indicates flush was seen and SQ was empty after the flush */
	__u8 destroy_pending : 1; /* Indicates the QP is being destroyed */
	__u8 srq_flush_seen;
};

struct zxdh_qp_init_info {
	struct zxdh_qp_sq_quanta *sq;
	struct zxdh_qp_rq_quanta *rq;
	struct zxdh_dev_attrs *dev_attrs;
	__u32 *wqe_alloc_db;
	__le64 *shadow_area;
	struct zxdh_sq_wr_trk_info *sq_wrtrk_array;
	__u64 *rq_wrid_array;
	__u32 qp_id;
	__u32 qp_caps;
	__u32 sq_size;
	__u32 rq_size;
	__u32 max_sq_frag_cnt;
	__u32 max_rq_frag_cnt;
	__u32 max_inline_data;
	__u8 type;
	int abi_ver;
	bool legacy_mode;
};

struct zxdh_cq_init_info {
	__u32 *cqe_alloc_db;
	__u32 *cq_ack_db;
	struct zxdh_cqe *cq_base;
	__le64 *shadow_area;
	__u32 cq_size;
	__u32 cq_id;
	__u8 cqe_size;
};

struct zxdh_srq_init_info {
	struct zxdh_srq_wqe *srq_base;
	struct zxdh_dev_attrs *dev_attrs;
	__le16 *srq_list_base;
	__le64 *srq_db_base;
	__u64 *srq_wrid_array;
	__u32 srq_id;
	__u32 srq_caps;
	__u32 srq_size;
	__u32 log2_srq_size;
	__u32 srq_list_size;
	__u32 srq_db_size;
	__u32 max_srq_frag_cnt;
	__u32 srq_limit;
};

struct zxdh_srq_wqe {
	__le64 elem[ZXDH_SRQE_SIZE];
};

int zxdh_cq_round_up(__u32 wqdepth);
void zxdh_clean_cq(void *q, struct zxdh_cq *cq);
enum zxdh_status_code zxdh_nop(struct zxdh_qp *qp, __u64 wr_id, bool signaled,
			       bool post_sq);
__le64 *zxdh_get_srq_wqe(struct zxdh_srq *srq, int wqe_index);
void zxdh_free_srq_wqe(struct zxdh_srq *srq, int wqe_index);
#endif /* __ZXDH_VERBS_H__ */
