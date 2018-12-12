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
#include <assert.h>
#include <ccan/container_of.h>

#include <rdma/ib_user_verbs.h>
#include <kernel-abi/ib_user_verbs.h>

/*
 * The minimum and maximum kernel ABI that we can handle.
 */
#define IB_USER_VERBS_MIN_ABI_VERSION	3
#define IB_USER_VERBS_MAX_ABI_VERSION	6

struct ex_hdr {
	struct ib_uverbs_cmd_hdr hdr;
	struct ib_uverbs_ex_cmd_hdr ex_hdr;
};

/*
 * These macros expand to type names that refer to the ABI structure type
 * associated with the given enum string.
 */
#define IBV_ABI_REQ(_enum) _ABI_REQ_STRUCT_##_enum
#define IBV_KABI_REQ(_enum) _KABI_REQ_STRUCT_##_enum
#define IBV_KABI_RESP(_enum) _KABI_RESP_STRUCT_##_enum

#define IBV_ABI_ALIGN(_enum) _ABI_ALIGN_##_enum

/*
 * Historically the code had copied the data in the kernel headers, modified
 * it and placed them in structs.  To avoid recoding eveything we continue to
 * preserve the same struct layout, with the kernel struct 'loose' inside the
 * modified userspace struct.
 *
 * This is automated with the make_abi_structs.py script which produces the
 * _STRUCT_xx macro that produces a tagless version of the kernel struct. The
 * tagless struct produces a layout that matches the original code.
 */
#define DECLARE_CMDX(_enum, _name, _kabi, _kabi_resp)                          \
	struct _name {                                                         \
		struct ib_uverbs_cmd_hdr hdr;                                  \
		union {                                                        \
			_STRUCT_##_kabi;                                       \
			struct _kabi core_payload;                             \
		};                                                             \
	};                                                                     \
	typedef struct _name IBV_ABI_REQ(_enum);                               \
	typedef struct _kabi IBV_KABI_REQ(_enum);                              \
	typedef struct _kabi_resp IBV_KABI_RESP(_enum);                        \
	enum { IBV_ABI_ALIGN(_enum) = 4 };                                     \
	static_assert(sizeof(struct _kabi_resp) % 4 == 0,                      \
		      "Bad resp alignment");                                   \
	static_assert(_enum != -1, "Bad enum");                                \
	static_assert(sizeof(struct _name) ==                                  \
			      sizeof(struct ib_uverbs_cmd_hdr) +               \
				      sizeof(struct _kabi),                    \
		      "Bad size")

#define DECLARE_CMD(_enum, _name, _kabi)                                       \
	DECLARE_CMDX(_enum, _name, _kabi, _kabi##_resp)

#define DECLARE_CMD_EXX(_enum, _name, _kabi, _kabi_resp)                       \
	struct _name {                                                         \
		struct ex_hdr hdr;                                             \
		union {                                                        \
			_STRUCT_##_kabi;                                       \
			struct _kabi core_payload;                             \
		};                                                             \
	};                                                                     \
	typedef struct _name IBV_ABI_REQ(_enum);                               \
	typedef struct _kabi IBV_KABI_REQ(_enum);                              \
	typedef struct _kabi_resp IBV_KABI_RESP(_enum);                        \
	enum { IBV_ABI_ALIGN(_enum) = 8 };                                     \
	static_assert(_enum != -1, "Bad enum");                                \
	static_assert(sizeof(struct _kabi) % 8 == 0, "Bad req alignment");     \
	static_assert(sizeof(struct _kabi_resp) % 8 == 0,                      \
		      "Bad resp alignment");                                   \
	static_assert(sizeof(struct _name) ==                                  \
			      sizeof(struct ex_hdr) + sizeof(struct _kabi),    \
		      "Bad size");                                             \
	static_assert(sizeof(struct _name) % 8 == 0, "Bad alignment")
#define DECLARE_CMD_EX(_enum, _name, _kabi)                                    \
	DECLARE_CMD_EXX(_enum, _name, _kabi, _kabi##_resp)

/* Drivers may use 'empty' for _kabi to signal no struct */
struct empty {};
#define _STRUCT_empty struct {}

/*
 * Define the ABI struct for use by the driver. The internal cmd APIs require
 * this layout. The driver specifies the enum # they wish to define for and
 * the base name, and the macros figure out the rest correctly.
 *
 * The static asserts check that the layout produced by the wrapper struct has
 * no implicit padding in strange places, specifically between the core
 * structure and the driver structure and between the driver structure and the
 * end of the struct.
 *
 * Implicit padding can arise in various cases where the structs are not sizes
 * to a multiple of 8 bytes.
 */
#define DECLARE_DRV_CMD(_name, _enum, _kabi_req, _kabi_resp)                   \
	struct _name {                                                         \
		IBV_ABI_REQ(_enum) ibv_cmd;                                    \
		union {                                                        \
			_STRUCT_##_kabi_req;                                   \
			struct _kabi_req drv_payload;                          \
		};                                                             \
	};                                                                     \
	struct _name##_resp {                                                  \
		IBV_KABI_RESP(_enum) ibv_resp;                                 \
		union {                                                        \
			_STRUCT_##_kabi_resp;                                  \
			struct _kabi_resp drv_payload;                         \
		};                                                             \
	};                                                                     \
	static_assert(sizeof(IBV_KABI_REQ(_enum)) %                            \
				      __alignof__(struct _kabi_req) ==         \
			      0,                                               \
		      "Bad kabi req struct length");                           \
	static_assert(sizeof(struct _name) ==                                  \
			      sizeof(IBV_ABI_REQ(_enum)) +                     \
				      sizeof(struct _kabi_req),                \
		      "Bad req size");                                         \
	static_assert(sizeof(struct _name) % IBV_ABI_ALIGN(_enum) == 0,        \
		      "Bad kabi req alignment");                               \
	static_assert(sizeof(IBV_KABI_RESP(_enum)) %                           \
				      __alignof__(struct _kabi_resp) ==        \
			      0,                                               \
		      "Bad kabi resp struct length");                          \
	static_assert(sizeof(struct _name##_resp) ==                           \
			      sizeof(IBV_KABI_RESP(_enum)) +                   \
				      sizeof(struct _kabi_resp),               \
		      "Bad resp size");                                        \
	static_assert(sizeof(struct _name##_resp) % IBV_ABI_ALIGN(_enum) == 0, \
		      "Bad kabi resp alignment");

DECLARE_CMD(IB_USER_VERBS_CMD_ALLOC_MW, ibv_alloc_mw, ib_uverbs_alloc_mw);
DECLARE_CMD(IB_USER_VERBS_CMD_ALLOC_PD, ibv_alloc_pd, ib_uverbs_alloc_pd);
DECLARE_CMDX(IB_USER_VERBS_CMD_ATTACH_MCAST, ibv_attach_mcast, ib_uverbs_attach_mcast, empty);
DECLARE_CMDX(IB_USER_VERBS_CMD_CLOSE_XRCD, ibv_close_xrcd, ib_uverbs_close_xrcd, empty);
DECLARE_CMD(IB_USER_VERBS_CMD_CREATE_AH, ibv_create_ah, ib_uverbs_create_ah);
DECLARE_CMD(IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL, ibv_create_comp_channel, ib_uverbs_create_comp_channel);
DECLARE_CMD(IB_USER_VERBS_CMD_CREATE_CQ, ibv_create_cq, ib_uverbs_create_cq);
DECLARE_CMD(IB_USER_VERBS_CMD_CREATE_QP, ibv_create_qp, ib_uverbs_create_qp);
DECLARE_CMD(IB_USER_VERBS_CMD_CREATE_SRQ, ibv_create_srq, ib_uverbs_create_srq);
DECLARE_CMDX(IB_USER_VERBS_CMD_CREATE_XSRQ, ibv_create_xsrq, ib_uverbs_create_xsrq, ib_uverbs_create_srq_resp);
DECLARE_CMDX(IB_USER_VERBS_CMD_DEALLOC_MW, ibv_dealloc_mw, ib_uverbs_dealloc_mw, empty);
DECLARE_CMDX(IB_USER_VERBS_CMD_DEALLOC_PD, ibv_dealloc_pd, ib_uverbs_dealloc_pd, empty);
DECLARE_CMDX(IB_USER_VERBS_CMD_DEREG_MR, ibv_dereg_mr, ib_uverbs_dereg_mr, empty);
DECLARE_CMDX(IB_USER_VERBS_CMD_DESTROY_AH, ibv_destroy_ah, ib_uverbs_destroy_ah, empty);
DECLARE_CMD(IB_USER_VERBS_CMD_DESTROY_CQ, ibv_destroy_cq, ib_uverbs_destroy_cq);
DECLARE_CMD(IB_USER_VERBS_CMD_DESTROY_QP, ibv_destroy_qp, ib_uverbs_destroy_qp);
DECLARE_CMD(IB_USER_VERBS_CMD_DESTROY_SRQ, ibv_destroy_srq, ib_uverbs_destroy_srq);
DECLARE_CMDX(IB_USER_VERBS_CMD_DETACH_MCAST, ibv_detach_mcast, ib_uverbs_detach_mcast, empty);
DECLARE_CMD(IB_USER_VERBS_CMD_GET_CONTEXT, ibv_get_context, ib_uverbs_get_context);
DECLARE_CMDX(IB_USER_VERBS_CMD_MODIFY_QP, ibv_modify_qp, ib_uverbs_modify_qp, empty);
DECLARE_CMDX(IB_USER_VERBS_CMD_MODIFY_SRQ, ibv_modify_srq, ib_uverbs_modify_srq, empty);
DECLARE_CMDX(IB_USER_VERBS_CMD_OPEN_QP, ibv_open_qp, ib_uverbs_open_qp, ib_uverbs_create_qp_resp);
DECLARE_CMD(IB_USER_VERBS_CMD_OPEN_XRCD, ibv_open_xrcd, ib_uverbs_open_xrcd);
DECLARE_CMD(IB_USER_VERBS_CMD_POLL_CQ, ibv_poll_cq, ib_uverbs_poll_cq);
DECLARE_CMD(IB_USER_VERBS_CMD_POST_RECV, ibv_post_recv, ib_uverbs_post_recv);
DECLARE_CMD(IB_USER_VERBS_CMD_POST_SEND, ibv_post_send, ib_uverbs_post_send);
DECLARE_CMD(IB_USER_VERBS_CMD_POST_SRQ_RECV, ibv_post_srq_recv, ib_uverbs_post_srq_recv);
DECLARE_CMD(IB_USER_VERBS_CMD_QUERY_DEVICE, ibv_query_device, ib_uverbs_query_device);
DECLARE_CMD(IB_USER_VERBS_CMD_QUERY_PORT, ibv_query_port, ib_uverbs_query_port);
DECLARE_CMD(IB_USER_VERBS_CMD_QUERY_QP, ibv_query_qp, ib_uverbs_query_qp);
DECLARE_CMD(IB_USER_VERBS_CMD_QUERY_SRQ, ibv_query_srq, ib_uverbs_query_srq);
DECLARE_CMD(IB_USER_VERBS_CMD_REG_MR, ibv_reg_mr, ib_uverbs_reg_mr);
DECLARE_CMDX(IB_USER_VERBS_CMD_REQ_NOTIFY_CQ, ibv_req_notify_cq, ib_uverbs_req_notify_cq, empty);
DECLARE_CMD(IB_USER_VERBS_CMD_REREG_MR, ibv_rereg_mr, ib_uverbs_rereg_mr);
DECLARE_CMD(IB_USER_VERBS_CMD_RESIZE_CQ, ibv_resize_cq, ib_uverbs_resize_cq);

DECLARE_CMD_EX(IB_USER_VERBS_EX_CMD_CREATE_CQ, ibv_create_cq_ex, ib_uverbs_ex_create_cq);
DECLARE_CMD_EX(IB_USER_VERBS_EX_CMD_CREATE_FLOW, ibv_create_flow, ib_uverbs_create_flow);
DECLARE_CMD_EX(IB_USER_VERBS_EX_CMD_CREATE_QP, ibv_create_qp_ex, ib_uverbs_ex_create_qp);
DECLARE_CMD_EX(IB_USER_VERBS_EX_CMD_CREATE_RWQ_IND_TBL, ibv_create_rwq_ind_table, ib_uverbs_ex_create_rwq_ind_table);
DECLARE_CMD_EX(IB_USER_VERBS_EX_CMD_CREATE_WQ, ibv_create_wq, ib_uverbs_ex_create_wq);
DECLARE_CMD_EXX(IB_USER_VERBS_EX_CMD_DESTROY_FLOW, ibv_destroy_flow, ib_uverbs_destroy_flow, empty);
DECLARE_CMD_EXX(IB_USER_VERBS_EX_CMD_DESTROY_RWQ_IND_TBL, ibv_destroy_rwq_ind_table, ib_uverbs_ex_destroy_rwq_ind_table, empty);
DECLARE_CMD_EX(IB_USER_VERBS_EX_CMD_DESTROY_WQ, ibv_destroy_wq, ib_uverbs_ex_destroy_wq);
DECLARE_CMD_EXX(IB_USER_VERBS_EX_CMD_MODIFY_CQ, ibv_modify_cq, ib_uverbs_ex_modify_cq, empty);
DECLARE_CMD_EX(IB_USER_VERBS_EX_CMD_MODIFY_QP, ibv_modify_qp_ex, ib_uverbs_ex_modify_qp);
DECLARE_CMD_EXX(IB_USER_VERBS_EX_CMD_MODIFY_WQ, ibv_modify_wq, ib_uverbs_ex_modify_wq, empty);
DECLARE_CMD_EX(IB_USER_VERBS_EX_CMD_QUERY_DEVICE, ibv_query_device_ex, ib_uverbs_ex_query_device);

/*
 * Both ib_uverbs_create_qp and ib_uverbs_ex_create_qp start with the same
 * structure, this function converts the ex version into the normal version
 */
static inline struct ib_uverbs_create_qp *
ibv_create_qp_ex_to_reg(struct ibv_create_qp_ex *cmd_ex)
{
	/*
	 * user_handle is the start in both places, note that the ex
	 * does not have response located in the same place, so response
	 * cannot be touched.
	 */
	return container_of(&cmd_ex->user_handle, struct ib_uverbs_create_qp,
			    user_handle);
}

/*
 * This file contains copied data from the kernel's include/uapi/rdma/ib_user_verbs.h,
 * now included above.
 *
 * Whenever possible use the definition from the kernel header and avoid
 * copying from that header into this file.
 */

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
		struct ib_uverbs_flow_spec_esp esp;
		struct ib_uverbs_flow_spec_tcp_udp tcp_udp;
		struct ib_uverbs_flow_spec_ipv6 ipv6;
		struct ib_uverbs_flow_spec_gre gre;
		struct ib_uverbs_flow_spec_tunnel tunnel;
		struct ib_uverbs_flow_spec_mpls mpls;
		struct ib_uverbs_flow_spec_action_tag flow_tag;
		struct ib_uverbs_flow_spec_action_drop drop;
		struct ib_uverbs_flow_spec_action_handle handle;
		struct ib_uverbs_flow_spec_action_count flow_count;
	};
};

struct ib_uverbs_modify_srq_v3 {
	__u32 srq_handle;
	__u32 attr_mask;
	__u32 max_wr;
	__u32 max_sge;
	__u32 srq_limit;
	__u32 reserved;
};
#define _STRUCT_ib_uverbs_modify_srq_v3
enum { IB_USER_VERBS_CMD_MODIFY_SRQ_V3 = IB_USER_VERBS_CMD_MODIFY_SRQ };
DECLARE_CMDX(IB_USER_VERBS_CMD_MODIFY_SRQ_V3, ibv_modify_srq_v3, ib_uverbs_modify_srq_v3, empty);

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

#endif /* KERN_ABI_H */
