/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005, 2006 Cisco Systems.  All rights reserved.
 * Copyright (c) 2005 PathScale, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef KERN_ABI_H
#define KERN_ABI_H

#include <linux/types.h>

#include <rdma/ib_user_verbs.h>

/*
 * This file contains copied data from the kernel's include/uapi/rdma/ib_user_verbs.h,
 * now included above.
 *
 * Whenever possible use the definition from the kernel header and avoid
 * copying from that header into this file.
 */

/*
 * The minimum and maximum kernel ABI that we can handle.
 */
#define IB_USER_VERBS_MIN_ABI_VERSION	3
#define IB_USER_VERBS_MAX_ABI_VERSION	6

/*
 * Make sure that all structs defined in this file remain laid out so
 * that they pack the same way on 32-bit and 64-bit architectures (to
 * avoid incompatibility between 32-bit userspace and 64-bit kernels).
 * Specifically:
 *  - Do not use pointer types -- pass pointers in __u64 instead.
 *  - Make sure that any structure larger than 4 bytes is padded to a
 *    multiple of 8 bytes.  Otherwise the structure size will be
 *    different between 32-bit and 64-bit architectures.
 */

struct ex_hdr {
	struct ib_uverbs_cmd_hdr hdr;
	struct ib_uverbs_ex_cmd_hdr ex_hdr;
};

/*
 * All commands from userspace should start with a __u32 command field
 * followed by __u16 in_words and out_words fields (which give the
 * length of the command block and response buffer if any in 32-bit
 * words).  The kernel driver will read these fields first and read
 * the rest of the command struct based on these value.
 */

struct ibv_get_context {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
};

struct ibv_query_device {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
};

struct ibv_query_device_ex {
	struct ex_hdr	hdr;
	__u32		comp_mask;
	__u32		reserved;
};

struct ibv_query_port {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u8  port_num;
	__u8  reserved[7];
};

struct ibv_alloc_pd {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
};

struct ibv_dealloc_pd {
	struct ib_uverbs_cmd_hdr hdr;
	__u32 pd_handle;
};

struct ibv_open_xrcd {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u32 fd;
	__u32 oflags;
};

struct ibv_close_xrcd {
	struct ib_uverbs_cmd_hdr hdr;
	__u32 xrcd_handle;
};

struct ibv_reg_mr {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u64 start;
	__u64 length;
	__u64 hca_va;
	__u32 pd_handle;
	__u32 access_flags;
};

struct ibv_rereg_mr {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u32 mr_handle;
	__u32 flags;
	__u64 start;
	__u64 length;
	__u64 hca_va;
	__u32 pd_handle;
	__u32 access_flags;
};

struct ibv_dereg_mr {
	struct ib_uverbs_cmd_hdr hdr;
	__u32 mr_handle;
};

struct ibv_alloc_mw {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u32 pd_handle;
	__u8  mw_type;
	__u8  reserved[3];
};

struct ibv_dealloc_mw {
	struct ib_uverbs_cmd_hdr hdr;
	__u32 mw_handle;
	__u32 reserved;
};

struct ibv_create_comp_channel {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
};

struct ibv_create_cq {
	struct ib_uverbs_cmd_hdr hdr;
	struct ib_uverbs_create_cq core_payload;
};

enum ibv_create_cq_ex_kernel_flags {
	IBV_CREATE_CQ_EX_KERNEL_FLAG_COMPLETION_TIMESTAMP = 1 << 0,
};

struct ibv_create_cq_ex {
	struct ex_hdr	hdr;
	struct ib_uverbs_ex_create_cq core_payload;
};

struct ibv_poll_cq {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u32 cq_handle;
	__u32 ne;
};

struct ibv_req_notify_cq {
	struct ib_uverbs_cmd_hdr hdr;
	__u32 cq_handle;
	__u32 solicited;
};

struct ibv_resize_cq {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u32 cq_handle;
	__u32 cqe;
};

struct ibv_destroy_cq {
	struct ib_uverbs_cmd_hdr hdr;
	struct ib_uverbs_destroy_cq core_payload;
};

#define IBV_CREATE_QP_COMMON	\
	__u64 user_handle;	\
	__u32 pd_handle;	\
	__u32 send_cq_handle;	\
	__u32 recv_cq_handle;	\
	__u32 srq_handle;	\
	__u32 max_send_wr;	\
	__u32 max_recv_wr;	\
	__u32 max_send_sge;	\
	__u32 max_recv_sge;	\
	__u32 max_inline_data;	\
	__u8  sq_sig_all;	\
	__u8  qp_type;		\
	__u8  is_srq;		\
	__u8  reserved

struct ibv_create_qp {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	IBV_CREATE_QP_COMMON;
};

struct ibv_create_qp_common {
	IBV_CREATE_QP_COMMON;
};

struct ibv_open_qp {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u64 user_handle;
	__u32 pd_handle;
	__u32 qpn;
	__u8  qp_type;
	__u8  reserved[7];
};

struct ibv_create_qp_ex {
	struct ex_hdr	hdr;
	struct ibv_create_qp_common base;
	__u32 comp_mask;
	__u32 create_flags;
	__u32 ind_tbl_handle;
	__u32 source_qpn;
};

struct ibv_query_qp {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u32 qp_handle;
	__u32 attr_mask;
};

struct ibv_modify_qp {
	struct ib_uverbs_cmd_hdr hdr;
	struct ib_uverbs_modify_qp base;
};

struct ibv_modify_qp_ex {
	struct ex_hdr		    hdr;
	struct ib_uverbs_modify_qp base;
	__u32  rate_limit;
	__u32  reserved;
};

struct ibv_destroy_qp {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u32 qp_handle;
	__u32 reserved;
};

struct ibv_kern_ipv4_filter {
	__u32 src_ip;
	__u32 dst_ip;
};

struct ibv_kern_spec_ipv4 {
	__u32  type;
	__u16  size;
	__u16 reserved;
	struct ibv_kern_ipv4_filter val;
	struct ibv_kern_ipv4_filter mask;
};

struct ibv_kern_spec {
	union {
		struct ib_uverbs_flow_spec_hdr hdr;
		struct ib_uverbs_flow_spec_eth eth;
		struct ibv_kern_spec_ipv4 ipv4;
		struct ib_uverbs_flow_spec_ipv4 ipv4_ext;
		struct ib_uverbs_flow_spec_tcp_udp tcp_udp;
		struct ib_uverbs_flow_spec_ipv6 ipv6;
		struct ib_uverbs_flow_spec_tunnel tunnel;
		struct ib_uverbs_flow_spec_action_tag flow_tag;
		struct ib_uverbs_flow_spec_action_drop drop;
	};
};

struct ibv_post_send {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u32 qp_handle;
	__u32 wr_count;
	__u32 sge_count;
	__u32 wqe_size;
	struct ib_uverbs_send_wr send_wr[0];
};

struct ibv_post_recv {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u32 qp_handle;
	__u32 wr_count;
	__u32 sge_count;
	__u32 wqe_size;
	struct ib_uverbs_recv_wr recv_wr[0];
};

struct ibv_post_srq_recv {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u32 srq_handle;
	__u32 wr_count;
	__u32 sge_count;
	__u32 wqe_size;
	struct ib_uverbs_recv_wr recv_wr[0];
};

struct ibv_create_ah {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u64 user_handle;
	__u32 pd_handle;
	__u32 reserved;
	struct ib_uverbs_ah_attr attr;
};

struct ibv_destroy_ah {
	struct ib_uverbs_cmd_hdr hdr;
	__u32 ah_handle;
};

struct ibv_attach_mcast {
	struct ib_uverbs_cmd_hdr hdr;
	__u8  gid[16];
	__u32 qp_handle;
	__u16 mlid;
	__u16 reserved;
};

struct ibv_create_flow  {
	struct ex_hdr hdr;
	__u32 comp_mask;
	__u32 qp_handle;
	struct ib_uverbs_flow_attr flow_attr;
};

struct ibv_destroy_flow  {
	struct ex_hdr hdr;
	__u32 comp_mask;
	__u32 flow_handle;
};

struct ibv_detach_mcast {
	struct ib_uverbs_cmd_hdr hdr;
	__u8  gid[16];
	__u32 qp_handle;
	__u16 mlid;
	__u16 reserved;
};

struct ibv_create_srq {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u64 user_handle;
	__u32 pd_handle;
	__u32 max_wr;
	__u32 max_sge;
	__u32 srq_limit;
};

struct ibv_create_xsrq {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u64 user_handle;
	__u32 srq_type;
	__u32 pd_handle;
	__u32 max_wr;
	__u32 max_sge;
	__u32 srq_limit;
	__u32 max_num_tags;
	__u32 xrcd_handle;
	__u32 cq_handle;
};

struct ibv_modify_srq {
	struct ib_uverbs_cmd_hdr hdr;
	__u32 srq_handle;
	__u32 attr_mask;
	__u32 max_wr;
	__u32 srq_limit;
};

struct ibv_query_srq {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u32 srq_handle;
	__u32 reserved;
};

struct ibv_destroy_srq {
	struct ib_uverbs_cmd_hdr hdr;
	__u64 response;
	__u32 srq_handle;
	__u32 reserved;
};

struct ibv_modify_srq_v3 {
	struct ib_uverbs_cmd_hdr hdr;
	__u32 srq_handle;
	__u32 attr_mask;
	__u32 max_wr;
	__u32 max_sge;
	__u32 srq_limit;
	__u32 reserved;
};

struct ibv_create_qp_resp_v3 {
	__u32 qp_handle;
	__u32 qpn;
};

struct ibv_create_qp_resp_v4 {
	__u32 qp_handle;
	__u32 qpn;
	__u32 max_send_wr;
	__u32 max_recv_wr;
	__u32 max_send_sge;
	__u32 max_recv_sge;
	__u32 max_inline_data;
};

struct ibv_create_srq_resp_v5 {
	__u32 srq_handle;
};

struct ibv_create_wq {
	struct ex_hdr hdr;
	__u32 comp_mask;
	__u32 wq_type;
	__u64 user_handle;
	__u32 pd_handle;
	__u32 cq_handle;
	__u32 max_wr;
	__u32 max_sge;
	__u32 create_flags;
	__u32 reserved;
};

struct ibv_destroy_wq {
	struct ex_hdr hdr;
	__u32 comp_mask;
	__u32 wq_handle;
};

struct ibv_modify_wq  {
	struct ex_hdr hdr;
	__u32 attr_mask;
	__u32 wq_handle;
	__u32 wq_state;
	__u32 curr_wq_state;
	__u32 flags;
	__u32 flags_mask;
};

struct ibv_create_rwq_ind_table {
	struct ex_hdr hdr;
	__u32 comp_mask;
	__u32 log_ind_tbl_size;
	/* Following are wq handles based on log_ind_tbl_size, must be 64 bytes aligned.
	 * __u32 wq_handle1
	 * __u32 wq_handle2
	 */
};

struct ibv_destroy_rwq_ind_table {
	struct ex_hdr hdr;
	__u32 comp_mask;
	__u32 ind_tbl_handle;
};

struct ibv_modify_cq {
	struct ex_hdr hdr;
	__u32 cq_handle;
	__u32 attr_mask;
	struct ib_uverbs_cq_moderation attr;
	__u32 reserved;
};

#endif /* KERN_ABI_H */
