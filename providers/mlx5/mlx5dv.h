/*
 * Copyright (c) 2017 Mellanox Technologies, Inc.  All rights reserved.
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

#ifndef _MLX5DV_H_
#define _MLX5DV_H_

#include <stdio.h>
#include <linux/types.h> /* For the __be64 type */
#include <sys/types.h>
#include <endian.h>
#if defined(__SSE3__)
#include <limits.h>
#include <emmintrin.h>
#include <tmmintrin.h>
#endif /* defined(__SSE3__) */

#include <infiniband/verbs.h>
#include <infiniband/tm_types.h>
#include <infiniband/mlx5_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Always inline the functions */
#ifdef __GNUC__
#define MLX5DV_ALWAYS_INLINE inline __attribute__((always_inline))
#else
#define MLX5DV_ALWAYS_INLINE inline
#endif

enum {
	MLX5_RCV_DBR	= 0,
	MLX5_SND_DBR	= 1,
};

enum mlx5dv_context_comp_mask {
	MLX5DV_CONTEXT_MASK_CQE_COMPRESION	= 1 << 0,
	MLX5DV_CONTEXT_MASK_SWP			= 1 << 1,
	MLX5DV_CONTEXT_MASK_STRIDING_RQ		= 1 << 2,
	MLX5DV_CONTEXT_MASK_TUNNEL_OFFLOADS	= 1 << 3,
	MLX5DV_CONTEXT_MASK_DYN_BFREGS		= 1 << 4,
	MLX5DV_CONTEXT_MASK_CLOCK_INFO_UPDATE	= 1 << 5,
	MLX5DV_CONTEXT_MASK_FLOW_ACTION_FLAGS	= 1 << 6,
};

struct mlx5dv_cqe_comp_caps {
	uint32_t max_num;
	uint32_t supported_format; /* enum mlx5dv_cqe_comp_res_format */
};

struct mlx5dv_sw_parsing_caps {
	uint32_t sw_parsing_offloads; /* Use enum mlx5dv_sw_parsing_offloads */
	uint32_t supported_qpts;
};

struct mlx5dv_striding_rq_caps {
	uint32_t min_single_stride_log_num_of_bytes;
	uint32_t max_single_stride_log_num_of_bytes;
	uint32_t min_single_wqe_log_num_of_strides;
	uint32_t max_single_wqe_log_num_of_strides;
	uint32_t supported_qpts;
};

enum mlx5dv_tunnel_offloads {
	MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_VXLAN	= 1 << 0,
	MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_GRE	= 1 << 1,
	MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_GENEVE	= 1 << 2,
	MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_CW_MPLS_OVER_GRE	= 1 << 3,
	MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_CW_MPLS_OVER_UDP	= 1 << 4,
};

enum mlx5dv_flow_action_cap_flags {
	MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM		  = 1 << 0,
	MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM_REQ_METADATA = 1 << 1,
	MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM_SPI_STEERING = 1 << 2,
	MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM_FULL_OFFLOAD = 1 << 3,
	MLX5DV_FLOW_ACTION_FLAGS_ESP_AES_GCM_TX_IV_IS_ESN = 1 << 4,
};

/*
 * Direct verbs device-specific attributes
 */
struct mlx5dv_context {
	uint8_t		version;
	uint64_t	flags;
	uint64_t	comp_mask;
	struct mlx5dv_cqe_comp_caps	cqe_comp_caps;
	struct mlx5dv_sw_parsing_caps sw_parsing_caps;
	struct mlx5dv_striding_rq_caps striding_rq_caps;
	uint32_t	tunnel_offloads_caps;
	uint32_t	max_dynamic_bfregs;
	uint64_t	max_clock_info_update_nsec;
	uint32_t        flow_action_flags; /* use enum mlx5dv_flow_action_cap_flags */
};

enum mlx5dv_context_flags {
	/*
	 * This flag indicates if CQE version 0 or 1 is needed.
	 */
	MLX5DV_CONTEXT_FLAGS_CQE_V1	= (1 << 0),
	MLX5DV_CONTEXT_FLAGS_OBSOLETE	= (1 << 1), /* Obsoleted, don't use */
	MLX5DV_CONTEXT_FLAGS_MPW_ALLOWED = (1 << 2),
	MLX5DV_CONTEXT_FLAGS_ENHANCED_MPW = (1 << 3),
	MLX5DV_CONTEXT_FLAGS_CQE_128B_COMP = (1 << 4), /* Support CQE 128B compression */
	MLX5DV_CONTEXT_FLAGS_CQE_128B_PAD = (1 << 5), /* Support CQE 128B padding */
};

enum mlx5dv_cq_init_attr_mask {
	MLX5DV_CQ_INIT_ATTR_MASK_COMPRESSED_CQE	= 1 << 0,
	MLX5DV_CQ_INIT_ATTR_MASK_FLAGS		= 1 << 1,
	MLX5DV_CQ_INIT_ATTR_MASK_CQE_SIZE = 1 << 2,
};

enum mlx5dv_cq_init_attr_flags {
	MLX5DV_CQ_INIT_ATTR_FLAGS_CQE_PAD	= 1 << 0,
	MLX5DV_CQ_INIT_ATTR_FLAGS_RESERVED	= 1 << 1,
};

struct mlx5dv_cq_init_attr {
	uint64_t comp_mask; /* Use enum mlx5dv_cq_init_attr_mask */
	uint8_t cqe_comp_res_format; /* Use enum mlx5dv_cqe_comp_res_format */
	uint32_t flags; /* Use enum mlx5dv_cq_init_attr_flags */
	uint16_t cqe_size; /* when MLX5DV_CQ_INIT_ATTR_MASK_CQE_SIZE set */
};

struct ibv_cq_ex *mlx5dv_create_cq(struct ibv_context *context,
				   struct ibv_cq_init_attr_ex *cq_attr,
				   struct mlx5dv_cq_init_attr *mlx5_cq_attr);

enum mlx5dv_qp_create_flags {
	MLX5DV_QP_CREATE_TUNNEL_OFFLOADS = 1 << 0,
	MLX5DV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_UC = 1 << 1,
	MLX5DV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_MC = 1 << 2,
	MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE = 1 << 3,
	MLX5DV_QP_CREATE_ALLOW_SCATTER_TO_CQE = 1 << 4,
};

enum mlx5dv_qp_init_attr_mask {
	MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS	= 1 << 0,
	MLX5DV_QP_INIT_ATTR_MASK_DC			= 1 << 1,
};

enum mlx5dv_dc_type {
	MLX5DV_DCTYPE_DCT     = 1,
	MLX5DV_DCTYPE_DCI,
};

struct mlx5dv_dc_init_attr {
	enum mlx5dv_dc_type	dc_type;
	uint64_t dct_access_key;
};

struct mlx5dv_qp_init_attr {
	uint64_t comp_mask;	/* Use enum mlx5dv_qp_init_attr_mask */
	uint32_t create_flags;	/* Use enum mlx5dv_qp_create_flags */
	struct mlx5dv_dc_init_attr  dc_init_attr;
};

struct ibv_qp *mlx5dv_create_qp(struct ibv_context *context,
				struct ibv_qp_init_attr_ex *qp_attr,
				struct mlx5dv_qp_init_attr *mlx5_qp_attr);

enum mlx5dv_flow_action_esp_mask {
	MLX5DV_FLOW_ACTION_ESP_MASK_FLAGS	= 1 << 0,
};

struct mlx5dv_flow_action_esp {
	uint64_t comp_mask;  /* Use enum mlx5dv_flow_action_esp_mask */
	uint32_t action_flags; /* Use enum mlx5dv_flow_action_flags */
};

struct mlx5dv_flow_match_parameters {
	size_t match_sz;
	uint64_t match_buf[]; /* Device spec format */
};

struct mlx5dv_flow_matcher_attr {
	enum ibv_flow_attr_type type;
	uint32_t flags; /* From enum ibv_flow_flags */
	uint16_t priority;
	uint8_t match_criteria_enable; /* Device spec format */
	struct mlx5dv_flow_match_parameters *match_mask;
	uint64_t comp_mask;
};

struct mlx5dv_flow_matcher;

struct mlx5dv_flow_matcher *
mlx5dv_create_flow_matcher(struct ibv_context *context,
			   struct mlx5dv_flow_matcher_attr *matcher_attr);

int mlx5dv_destroy_flow_matcher(struct mlx5dv_flow_matcher *matcher);

enum mlx5dv_flow_action_type {
	MLX5DV_FLOW_ACTION_DEST_IBV_QP,
	MLX5DV_FLOW_ACTION_DROP,
	MLX5DV_FLOW_ACTION_IBV_COUNTER,
	MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION,
	MLX5DV_FLOW_ACTION_TAG,
	MLX5DV_FLOW_ACTION_DEST_DEVX,
	MLX5DV_FLOW_ACTION_COUNTERS_DEVX,
};

struct mlx5dv_flow_action_attr {
	enum mlx5dv_flow_action_type type;
	union {
		struct ibv_qp *qp;
		struct ibv_counters *counter;
		struct ibv_flow_action *action;
		uint32_t tag_value;
		struct mlx5dv_devx_obj *obj;
	};
};

struct ibv_flow *
mlx5dv_create_flow(struct mlx5dv_flow_matcher *matcher,
		   struct mlx5dv_flow_match_parameters *match_value,
		   size_t num_actions,
		   struct mlx5dv_flow_action_attr actions_attr[]);

struct ibv_flow_action *mlx5dv_create_flow_action_esp(struct ibv_context *ctx,
						      struct ibv_flow_action_esp_attr *esp,
						      struct mlx5dv_flow_action_esp *mlx5_attr);

/*
 * mlx5dv_create_flow_action_modify_header - Create a flow action which mutates
 * a packet. The flow action can be attached to steering rules via
 * ibv_create_flow().
 *
 * @ctx: RDMA device context to create the action on.
 * @actions_sz: The size of *actions* buffer in bytes.
 * @actions: A buffer which contains modify actions provided in device spec
 *	     format.
 * @ft_type: Defines the flow table type to which the modify
 *	     header action will be attached.
 *
 * Return a valid ibv_flow_action if successful, NULL otherwise.
 */
struct ibv_flow_action *
mlx5dv_create_flow_action_modify_header(struct ibv_context *ctx,
					size_t actions_sz,
					uint64_t actions[],
					enum mlx5dv_flow_table_type ft_type);

/*
 * mlx5dv_create_flow_action_packet_reformat - Create flow action which can
 * encap/decap packets.
 */
struct ibv_flow_action *
mlx5dv_create_flow_action_packet_reformat(struct ibv_context *ctx,
					  size_t data_sz,
					  void *data,
					  enum mlx5dv_flow_action_packet_reformat_type reformat_type,
					  enum mlx5dv_flow_table_type ft_type);
/*
 * Most device capabilities are exported by ibv_query_device(...),
 * but there is HW device-specific information which is important
 * for data-path, but isn't provided.
 *
 * Return 0 on success.
 */
int mlx5dv_query_device(struct ibv_context *ctx_in,
			struct mlx5dv_context *attrs_out);

enum mlx5dv_qp_comp_mask {
	MLX5DV_QP_MASK_UAR_MMAP_OFFSET		= 1 << 0,
	MLX5DV_QP_MASK_RAW_QP_HANDLES		= 1 << 1,
};

struct mlx5dv_qp {
	__be32			*dbrec;
	struct {
		void		*buf;
		uint32_t	wqe_cnt;
		uint32_t	stride;
	} sq;
	struct {
		void		*buf;
		uint32_t	wqe_cnt;
		uint32_t	stride;
	} rq;
	struct {
		void		*reg;
		uint32_t	size;
	} bf;
	uint64_t		comp_mask;
	off_t			uar_mmap_offset;
	uint32_t		tirn;
	uint32_t		tisn;
	uint32_t		rqn;
	uint32_t		sqn;
};

struct mlx5dv_cq {
	void			*buf;
	__be32			*dbrec;
	uint32_t		cqe_cnt;
	uint32_t		cqe_size;
	void			*cq_uar;
	uint32_t		cqn;
	uint64_t		comp_mask;
};

enum mlx5dv_srq_comp_mask {
	MLX5DV_SRQ_MASK_SRQN	= 1 << 0,
};

struct mlx5dv_srq {
	void			*buf;
	__be32			*dbrec;
	uint32_t		stride;
	uint32_t		head;
	uint32_t		tail;
	uint64_t		comp_mask;
	uint32_t		srqn;
};

struct mlx5dv_rwq {
	void		*buf;
	__be32		*dbrec;
	uint32_t	wqe_cnt;
	uint32_t	stride;
	uint64_t	comp_mask;
};

struct mlx5dv_dm {
	void		*buf;
	uint64_t	length;
	uint64_t	comp_mask;
};

struct mlx5_wqe_av;

struct mlx5dv_ah {
	struct mlx5_wqe_av      *av;
	uint64_t		comp_mask;
};

struct mlx5dv_pd {
	uint32_t		pdn;
	uint64_t		comp_mask;
};

struct mlx5dv_obj {
	struct {
		struct ibv_qp		*in;
		struct mlx5dv_qp	*out;
	} qp;
	struct {
		struct ibv_cq		*in;
		struct mlx5dv_cq	*out;
	} cq;
	struct {
		struct ibv_srq		*in;
		struct mlx5dv_srq	*out;
	} srq;
	struct {
		struct ibv_wq		*in;
		struct mlx5dv_rwq	*out;
	} rwq;
	struct {
		struct ibv_dm		*in;
		struct mlx5dv_dm	*out;
	} dm;
	struct {
		struct ibv_ah		*in;
		struct mlx5dv_ah	*out;
	} ah;
	struct {
		struct ibv_pd		*in;
		struct mlx5dv_pd	*out;
	} pd;
};

enum mlx5dv_obj_type {
	MLX5DV_OBJ_QP	= 1 << 0,
	MLX5DV_OBJ_CQ	= 1 << 1,
	MLX5DV_OBJ_SRQ	= 1 << 2,
	MLX5DV_OBJ_RWQ	= 1 << 3,
	MLX5DV_OBJ_DM	= 1 << 4,
	MLX5DV_OBJ_AH	= 1 << 5,
	MLX5DV_OBJ_PD	= 1 << 6,
};

enum mlx5dv_wq_init_attr_mask {
	MLX5DV_WQ_INIT_ATTR_MASK_STRIDING_RQ	= 1 << 0,
};

struct mlx5dv_striding_rq_init_attr {
	uint32_t	single_stride_log_num_of_bytes;
	uint32_t	single_wqe_log_num_of_strides;
	uint8_t		two_byte_shift_en;
};

struct mlx5dv_wq_init_attr {
	uint64_t				comp_mask; /* Use enum mlx5dv_wq_init_attr_mask */
	struct mlx5dv_striding_rq_init_attr	striding_rq_attrs;
};

/*
 * This function creates a work queue object with extra properties
 * defined by mlx5dv_wq_init_attr struct.
 *
 * For each bit in the comp_mask, a field in mlx5dv_wq_init_attr
 * should follow.
 *
 * MLX5DV_WQ_INIT_ATTR_MASK_STRIDING_RQ: Create a work queue with
 * striding RQ capabilities.
 * - single_stride_log_num_of_bytes represents the size of each stride in the
 *   WQE and its value should be between min_single_stride_log_num_of_bytes
 *   and max_single_stride_log_num_of_bytes that are reported in
 *   mlx5dv_query_device.
 * - single_wqe_log_num_of_strides represents the number of strides in each WQE.
 *   Its value should be between min_single_wqe_log_num_of_strides and
 *   max_single_wqe_log_num_of_strides that are reported in mlx5dv_query_device.
 * - two_byte_shift_en: When enabled, hardware pads 2 bytes of zeroes
 *   before writing the message to memory (e.g. for IP alignment)
 */
struct ibv_wq *mlx5dv_create_wq(struct ibv_context *context,
				struct ibv_wq_init_attr *wq_init_attr,
				struct mlx5dv_wq_init_attr *mlx5_wq_attr);
/*
 * This function will initialize mlx5dv_xxx structs based on supplied type.
 * The information for initialization is taken from ibv_xx structs supplied
 * as part of input.
 *
 * Request information of CQ marks its owned by DV for all consumer index
 * related actions.
 *
 * The initialization type can be combination of several types together.
 *
 * Return: 0 in case of success.
 */
int mlx5dv_init_obj(struct mlx5dv_obj *obj, uint64_t obj_type);

enum {
	MLX5_OPCODE_NOP			= 0x00,
	MLX5_OPCODE_SEND_INVAL		= 0x01,
	MLX5_OPCODE_RDMA_WRITE		= 0x08,
	MLX5_OPCODE_RDMA_WRITE_IMM	= 0x09,
	MLX5_OPCODE_SEND		= 0x0a,
	MLX5_OPCODE_SEND_IMM		= 0x0b,
	MLX5_OPCODE_TSO			= 0x0e,
	MLX5_OPCODE_RDMA_READ		= 0x10,
	MLX5_OPCODE_ATOMIC_CS		= 0x11,
	MLX5_OPCODE_ATOMIC_FA		= 0x12,
	MLX5_OPCODE_ATOMIC_MASKED_CS	= 0x14,
	MLX5_OPCODE_ATOMIC_MASKED_FA	= 0x15,
	MLX5_OPCODE_FMR			= 0x19,
	MLX5_OPCODE_LOCAL_INVAL		= 0x1b,
	MLX5_OPCODE_CONFIG_CMD		= 0x1f,
	MLX5_OPCODE_UMR			= 0x25,
	MLX5_OPCODE_TAG_MATCHING	= 0x28
};

/*
 * CQE related part
 */

enum {
	MLX5_INLINE_SCATTER_32	= 0x4,
	MLX5_INLINE_SCATTER_64	= 0x8,
};

enum {
	MLX5_CQE_SYNDROME_LOCAL_LENGTH_ERR		= 0x01,
	MLX5_CQE_SYNDROME_LOCAL_QP_OP_ERR		= 0x02,
	MLX5_CQE_SYNDROME_LOCAL_PROT_ERR		= 0x04,
	MLX5_CQE_SYNDROME_WR_FLUSH_ERR			= 0x05,
	MLX5_CQE_SYNDROME_MW_BIND_ERR			= 0x06,
	MLX5_CQE_SYNDROME_BAD_RESP_ERR			= 0x10,
	MLX5_CQE_SYNDROME_LOCAL_ACCESS_ERR		= 0x11,
	MLX5_CQE_SYNDROME_REMOTE_INVAL_REQ_ERR		= 0x12,
	MLX5_CQE_SYNDROME_REMOTE_ACCESS_ERR		= 0x13,
	MLX5_CQE_SYNDROME_REMOTE_OP_ERR			= 0x14,
	MLX5_CQE_SYNDROME_TRANSPORT_RETRY_EXC_ERR	= 0x15,
	MLX5_CQE_SYNDROME_RNR_RETRY_EXC_ERR		= 0x16,
	MLX5_CQE_SYNDROME_REMOTE_ABORTED_ERR		= 0x22,
};

enum {
	MLX5_CQE_L2_OK = 1 << 0,
	MLX5_CQE_L3_OK = 1 << 1,
	MLX5_CQE_L4_OK = 1 << 2,
};

enum {
	MLX5_CQE_L3_HDR_TYPE_NONE = 0x0,
	MLX5_CQE_L3_HDR_TYPE_IPV6 = 0x1,
	MLX5_CQE_L3_HDR_TYPE_IPV4 = 0x2,
};

enum {
	MLX5_CQE_OWNER_MASK	= 1,
	MLX5_CQE_REQ		= 0,
	MLX5_CQE_RESP_WR_IMM	= 1,
	MLX5_CQE_RESP_SEND	= 2,
	MLX5_CQE_RESP_SEND_IMM	= 3,
	MLX5_CQE_RESP_SEND_INV	= 4,
	MLX5_CQE_RESIZE_CQ	= 5,
	MLX5_CQE_NO_PACKET	= 6,
	MLX5_CQE_REQ_ERR	= 13,
	MLX5_CQE_RESP_ERR	= 14,
	MLX5_CQE_INVALID	= 15,
};

enum {
	MLX5_CQ_DOORBELL			= 0x20
};

enum {
	MLX5_CQ_DB_REQ_NOT_SOL	= 1 << 24,
	MLX5_CQ_DB_REQ_NOT	= 0 << 24,
};

struct mlx5_err_cqe {
	uint8_t		rsvd0[32];
	uint32_t	srqn;
	uint8_t		rsvd1[18];
	uint8_t		vendor_err_synd;
	uint8_t		syndrome;
	uint32_t	s_wqe_opcode_qpn;
	uint16_t	wqe_counter;
	uint8_t		signature;
	uint8_t		op_own;
};

struct mlx5_tm_cqe {
	__be32		success;
	__be16		hw_phase_cnt;
	uint8_t		rsvd0[12];
};

struct mlx5_cqe64 {
	union {
		struct {
			uint8_t		rsvd0[2];
			__be16		wqe_id;
			uint8_t		rsvd4[13];
			uint8_t		ml_path;
			uint8_t		rsvd20[4];
			__be16		slid;
			__be32		flags_rqpn;
			uint8_t		hds_ip_ext;
			uint8_t		l4_hdr_type_etc;
			__be16		vlan_info;
		};
		struct mlx5_tm_cqe tm_cqe;
		/* TMH is scattered to CQE upon match */
		struct ibv_tmh tmh;
	};
	__be32		srqn_uidx;
	__be32		imm_inval_pkey;
	uint8_t		app;
	uint8_t		app_op;
	__be16		app_info;
	__be32		byte_cnt;
	__be64		timestamp;
	__be32		sop_drop_qpn;
	__be16		wqe_counter;
	uint8_t		signature;
	uint8_t		op_own;
};

enum {
	MLX5_TMC_SUCCESS	= 0x80000000U,
};

enum mlx5dv_cqe_comp_res_format {
	MLX5DV_CQE_RES_FORMAT_HASH		= 1 << 0,
	MLX5DV_CQE_RES_FORMAT_CSUM		= 1 << 1,
	MLX5DV_CQE_RES_FORMAT_CSUM_STRIDX       = 1 << 2,
};

enum mlx5dv_sw_parsing_offloads {
	MLX5DV_SW_PARSING		= 1 << 0,
	MLX5DV_SW_PARSING_CSUM		= 1 << 1,
	MLX5DV_SW_PARSING_LSO		= 1 << 2,
};

static MLX5DV_ALWAYS_INLINE
uint8_t mlx5dv_get_cqe_owner(struct mlx5_cqe64 *cqe)
{
	return cqe->op_own & 0x1;
}

static MLX5DV_ALWAYS_INLINE
void mlx5dv_set_cqe_owner(struct mlx5_cqe64 *cqe, uint8_t val)
{
	cqe->op_own = (val & 0x1) | (cqe->op_own & ~0x1);
}

/* Solicited event */
static MLX5DV_ALWAYS_INLINE
uint8_t mlx5dv_get_cqe_se(struct mlx5_cqe64 *cqe)
{
	return (cqe->op_own >> 1) & 0x1;
}

static MLX5DV_ALWAYS_INLINE
uint8_t mlx5dv_get_cqe_format(struct mlx5_cqe64 *cqe)
{
	return (cqe->op_own >> 2) & 0x3;
}

static MLX5DV_ALWAYS_INLINE
uint8_t mlx5dv_get_cqe_opcode(struct mlx5_cqe64 *cqe)
{
	return cqe->op_own >> 4;
}

/*
 * WQE related part
 */
enum {
	MLX5_INVALID_LKEY	= 0x100,
};

enum {
	MLX5_EXTENDED_UD_AV	= 0x80000000,
};

enum {
	MLX5_WQE_CTRL_CQ_UPDATE	= 2 << 2,
	MLX5_WQE_CTRL_SOLICITED	= 1 << 1,
	MLX5_WQE_CTRL_FENCE	= 4 << 5,
	MLX5_WQE_CTRL_INITIATOR_SMALL_FENCE = 1 << 5,
};

enum {
	MLX5_SEND_WQE_BB	= 64,
	MLX5_SEND_WQE_SHIFT	= 6,
};

enum {
	MLX5_INLINE_SEG	= 0x80000000,
};

enum {
	MLX5_ETH_WQE_L3_CSUM = (1 << 6),
	MLX5_ETH_WQE_L4_CSUM = (1 << 7),
};

struct mlx5_wqe_srq_next_seg {
	uint8_t			rsvd0[2];
	__be16			next_wqe_index;
	uint8_t			signature;
	uint8_t			rsvd1[11];
};

struct mlx5_wqe_data_seg {
	__be32			byte_count;
	__be32			lkey;
	__be64			addr;
};

struct mlx5_wqe_ctrl_seg {
	__be32		opmod_idx_opcode;
	__be32		qpn_ds;
	uint8_t		signature;
	uint8_t		rsvd[2];
	uint8_t		fm_ce_se;
	__be32		imm;
};

struct mlx5_mprq_wqe {
	struct mlx5_wqe_srq_next_seg	nseg;
	struct mlx5_wqe_data_seg	dseg;
};

struct mlx5_wqe_av {
	union {
		struct {
			__be32		qkey;
			__be32		reserved;
		} qkey;
		__be64		dc_key;
	} key;
	__be32		dqp_dct;
	uint8_t		stat_rate_sl;
	uint8_t		fl_mlid;
	__be16		rlid;
	uint8_t		reserved0[4];
	uint8_t		rmac[6];
	uint8_t		tclass;
	uint8_t		hop_limit;
	__be32		grh_gid_fl;
	uint8_t		rgid[16];
};

struct mlx5_wqe_datagram_seg {
	struct mlx5_wqe_av	av;
};

struct mlx5_wqe_raddr_seg {
	__be64		raddr;
	__be32		rkey;
	__be32		reserved;
};

struct mlx5_wqe_atomic_seg {
	__be64		swap_add;
	__be64		compare;
};

struct mlx5_wqe_inl_data_seg {
	uint32_t	byte_count;
};

struct mlx5_wqe_eth_seg {
	__be32		rsvd0;
	uint8_t		cs_flags;
	uint8_t		rsvd1;
	__be16		mss;
	__be32		rsvd2;
	__be16		inline_hdr_sz;
	uint8_t		inline_hdr_start[2];
	uint8_t		inline_hdr[16];
};

struct mlx5_wqe_tm_seg {
	uint8_t		opcode;
	uint8_t		flags;
	__be16		index;
	uint8_t		rsvd0[2];
	__be16		sw_cnt;
	uint8_t		rsvd1[8];
	__be64		append_tag;
	__be64		append_mask;
};

/*
 * Control segment - contains some control information for the current WQE.
 *
 * Output:
 *	seg	  - control segment to be filled
 * Input:
 *	pi	  - WQEBB number of the first block of this WQE.
 *		    This number should wrap at 0xffff, regardless of
 *		    size of the WQ.
 *	opcode	  - Opcode of this WQE. Encodes the type of operation
 *		    to be executed on the QP.
 *	opmod	  - Opcode modifier.
 *	qp_num	  - QP/SQ number this WQE is posted to.
 *	fm_ce_se  - FM (fence mode), CE (completion and event mode)
 *		    and SE (solicited event).
 *	ds	  - WQE size in octowords (16-byte units). DS accounts for all
 *		    the segments in the WQE as summarized in WQE construction.
 *	signature - WQE signature.
 *	imm	  - Immediate data/Invalidation key/UMR mkey.
 */
static MLX5DV_ALWAYS_INLINE
void mlx5dv_set_ctrl_seg(struct mlx5_wqe_ctrl_seg *seg, uint16_t pi,
			 uint8_t opcode, uint8_t opmod, uint32_t qp_num,
			 uint8_t fm_ce_se, uint8_t ds,
			 uint8_t signature, uint32_t imm)
{
	seg->opmod_idx_opcode	= htobe32(((uint32_t)opmod << 24) | ((uint32_t)pi << 8) | opcode);
	seg->qpn_ds		= htobe32((qp_num << 8) | ds);
	seg->fm_ce_se		= fm_ce_se;
	seg->signature		= signature;
	/*
	 * The caller should prepare "imm" in advance based on WR opcode.
	 * For IBV_WR_SEND_WITH_IMM and IBV_WR_RDMA_WRITE_WITH_IMM,
	 * the "imm" should be assigned as is.
	 * For the IBV_WR_SEND_WITH_INV, it should be htobe32(imm).
	 */
	seg->imm		= imm;
}

/* x86 optimized version of mlx5dv_set_ctrl_seg()
 *
 * This is useful when doing calculations on large data sets
 * for parallel calculations.
 *
 * It doesn't suit for serialized algorithms.
 */
#if defined(__SSE3__)
static MLX5DV_ALWAYS_INLINE
void mlx5dv_x86_set_ctrl_seg(struct mlx5_wqe_ctrl_seg *seg, uint16_t pi,
			     uint8_t opcode, uint8_t opmod, uint32_t qp_num,
			     uint8_t fm_ce_se, uint8_t ds,
			     uint8_t signature, uint32_t imm)
{
	__m128i val  = _mm_set_epi32(imm, qp_num, (ds << 16) | pi,
				     (signature << 24) | (opcode << 16) | (opmod << 8) | fm_ce_se);
	__m128i mask = _mm_set_epi8(15, 14, 13, 12,	/* immediate */
				     0,			/* signal/fence_mode */
#if CHAR_MIN
				     -128, -128,        /* reserved */
#else
				     0x80, 0x80,        /* reserved */
#endif
				     3,			/* signature */
				     6,			/* data size */
				     8, 9, 10,		/* QP num */
				     2,			/* opcode */
				     4, 5,		/* sw_pi in BE */
				     1			/* opmod */
				     );
	*(__m128i *) seg = _mm_shuffle_epi8(val, mask);
}
#endif /* defined(__SSE3__) */

/*
 * Datagram Segment - contains address information required in order
 * to form a datagram message.
 *
 * Output:
 *	seg		- datagram segment to be filled.
 * Input:
 *	key		- Q_key/access key.
 *	dqp_dct		- Destination QP number for UD and DCT for DC.
 *	ext		- Address vector extension.
 *	stat_rate_sl	- Maximum static rate control, SL/ethernet priority.
 *	fl_mlid		- Force loopback and source LID for IB.
 *	rlid		- Remote LID
 *	rmac		- Remote MAC
 *	tclass		- GRH tclass/IPv6 tclass/IPv4 ToS
 *	hop_limit	- GRH hop limit/IPv6 hop limit/IPv4 TTL
 *	grh_gid_fi	- GRH, source GID address and IPv6 flow label.
 *	rgid		- Remote GID/IP address.
 */
static MLX5DV_ALWAYS_INLINE
void mlx5dv_set_dgram_seg(struct mlx5_wqe_datagram_seg *seg,
			  uint64_t key, uint32_t dqp_dct,
			  uint8_t ext, uint8_t stat_rate_sl,
			  uint8_t fl_mlid, uint16_t rlid,
			  uint8_t *rmac, uint8_t tclass,
			  uint8_t hop_limit, uint32_t grh_gid_fi,
			  uint8_t *rgid)
{

	/* Always put 64 bits, in q_key, the reserved part will be 0 */
	seg->av.key.dc_key	= htobe64(key);
	seg->av.dqp_dct		= htobe32(((uint32_t)ext << 31) | dqp_dct);
	seg->av.stat_rate_sl	= stat_rate_sl;
	seg->av.fl_mlid		= fl_mlid;
	seg->av.rlid		= htobe16(rlid);
	memcpy(seg->av.rmac, rmac, 6);
	seg->av.tclass		= tclass;
	seg->av.hop_limit	= hop_limit;
	seg->av.grh_gid_fl	= htobe32(grh_gid_fi);
	memcpy(seg->av.rgid, rgid, 16);
}

/*
 * Data Segments - contain pointers and a byte count for the scatter/gather list.
 * They can optionally contain data, which will save a memory read access for
 * gather Work Requests.
 */
static MLX5DV_ALWAYS_INLINE
void mlx5dv_set_data_seg(struct mlx5_wqe_data_seg *seg,
			 uint32_t length, uint32_t lkey,
			 uintptr_t address)
{
	seg->byte_count = htobe32(length);
	seg->lkey       = htobe32(lkey);
	seg->addr       = htobe64(address);
}
/*
 * x86 optimized version of mlx5dv_set_data_seg()
 *
 * This is useful when doing calculations on large data sets
 * for parallel calculations.
 *
 * It doesn't suit for serialized algorithms.
 */
#if defined(__SSE3__)
static MLX5DV_ALWAYS_INLINE
void mlx5dv_x86_set_data_seg(struct mlx5_wqe_data_seg *seg,
			     uint32_t length, uint32_t lkey,
			     uintptr_t address)
{

	uint64_t address64 = address;
	__m128i val  = _mm_set_epi32((uint32_t)address64, (uint32_t)(address64 >> 32), lkey, length);
	__m128i mask = _mm_set_epi8(12, 13, 14, 15,	/* local address low */
				     8, 9, 10, 11,	/* local address high */
				     4, 5, 6, 7,	/* l_key */
				     0, 1, 2, 3		/* byte count */
				     );
	*(__m128i *) seg = _mm_shuffle_epi8(val, mask);
}
#endif /* defined(__SSE3__) */

/*
 * Eth Segment - contains packet headers and information for stateless L2, L3, L4 offloading.
 *
 * Output:
 *	 seg		 - Eth segment to be filled.
 * Input:
 *	cs_flags	 - l3cs/l3cs_inner/l4cs/l4cs_inner.
 *	mss		 - Maximum segment size. For TSO WQEs, the number of bytes
 *			   in the TCP payload to be transmitted in each packet. Must
 *			   be 0 on non TSO WQEs.
 *	inline_hdr_sz	 - Length of the inlined packet headers.
 *	inline_hdr_start - Inlined packet header.
 */
static MLX5DV_ALWAYS_INLINE
void mlx5dv_set_eth_seg(struct mlx5_wqe_eth_seg *seg, uint8_t cs_flags,
			uint16_t mss, uint16_t inline_hdr_sz,
			uint8_t *inline_hdr_start)
{
	seg->cs_flags		= cs_flags;
	seg->mss		= htobe16(mss);
	seg->inline_hdr_sz	= htobe16(inline_hdr_sz);
	memcpy(seg->inline_hdr_start, inline_hdr_start, inline_hdr_sz);
}

enum mlx5dv_set_ctx_attr_type {
	MLX5DV_CTX_ATTR_BUF_ALLOCATORS = 1,
};

enum {
	MLX5_MMAP_GET_REGULAR_PAGES_CMD	= 0,
	MLX5_MMAP_GET_NC_PAGES_CMD	= 3,
};

struct mlx5dv_ctx_allocators {
	void *(*alloc)(size_t size, void *priv_data);
	void (*free)(void *ptr, void *priv_data);
	void *data;
};

/*
 * Generic context attributes set API
 *
 * Returns 0 on success, or the value of errno on failure
 * (which indicates the failure reason).
 */
int mlx5dv_set_context_attr(struct ibv_context *context,
		enum mlx5dv_set_ctx_attr_type type, void *attr);

struct mlx5dv_clock_info {
	uint64_t nsec;
	uint64_t last_cycles;
	uint64_t frac;
	uint32_t mult;
	uint32_t shift;
	uint64_t mask;
};

/*
 * Get mlx5 core clock info
 *
 * Output:
 *      clock_info  - clock info to be filled
 * Input:
 *      context     - device context
 *
 * Return: 0 on success, or the value of errno on failure
 */
int mlx5dv_get_clock_info(struct ibv_context *context,
			  struct mlx5dv_clock_info *clock_info);

/*
 * Translate device timestamp to nano-sec
 *
 * Input:
 *      clock_info  - clock info to be filled
 *      device_timestamp   - timestamp to translate
 *
 * Return: nano-sec
 */
static inline uint64_t mlx5dv_ts_to_ns(struct mlx5dv_clock_info *clock_info,
				       uint64_t device_timestamp)
{
	uint64_t delta, nsec;

	/*
	 * device_timestamp & cycles are the free running 'mask' bit counters
	 * from the hardware hca_core_clock clock.
	 */
	delta = (device_timestamp - clock_info->last_cycles) & clock_info->mask;
	nsec  = clock_info->nsec;

	/*
	 * Guess if the device_timestamp is more recent than
	 * clock_info->last_cycles, if not (too far in the future) treat
	 * it as old time stamp. This will break every max_clock_info_update_nsec.
	 */

	if (delta > clock_info->mask / 2) {
		delta = (clock_info->last_cycles - device_timestamp) &
				clock_info->mask;
		nsec -= ((delta * clock_info->mult) - clock_info->frac) >>
				clock_info->shift;
	} else {
		nsec += ((delta * clock_info->mult) + clock_info->frac) >>
				clock_info->shift;
	}

	return nsec;
}

enum mlx5dv_context_attr_flags {
	MLX5DV_CONTEXT_FLAGS_DEVX = 1 << 0,
};

struct mlx5dv_context_attr {
	uint32_t flags; /* Use enum mlx5dv_context_attr_flags */
	uint64_t comp_mask;
};

struct ibv_context *
mlx5dv_open_device(struct ibv_device *device, struct mlx5dv_context_attr *attr);

struct mlx5dv_devx_obj;

struct mlx5dv_devx_obj *
mlx5dv_devx_obj_create(struct ibv_context *context, const void *in, size_t inlen,
		       void *out, size_t outlen);
int mlx5dv_devx_obj_query(struct mlx5dv_devx_obj *obj, const void *in, size_t inlen,
			  void *out, size_t outlen);
int mlx5dv_devx_obj_modify(struct mlx5dv_devx_obj *obj, const void *in, size_t inlen,
			   void *out, size_t outlen);
int mlx5dv_devx_obj_destroy(struct mlx5dv_devx_obj *obj);
int mlx5dv_devx_general_cmd(struct ibv_context *context, const void *in, size_t inlen,
			    void *out, size_t outlen);

struct mlx5dv_devx_umem {
	uint32_t umem_id;
};

struct mlx5dv_devx_umem *
mlx5dv_devx_umem_reg(struct ibv_context *ctx, void *addr, size_t size, uint32_t access);
int mlx5dv_devx_umem_dereg(struct mlx5dv_devx_umem *umem);

struct mlx5dv_devx_uar {
	void *reg_addr;
	void *base_addr;
	uint32_t page_id;
	off_t mmap_off;
	uint64_t comp_mask;
};

struct mlx5dv_devx_uar *mlx5dv_devx_alloc_uar(struct ibv_context *context,
					      uint32_t flags);
void mlx5dv_devx_free_uar(struct mlx5dv_devx_uar *devx_uar);
int mlx5dv_devx_query_eqn(struct ibv_context *context, uint32_t vector,
			  uint32_t *eqn);

int mlx5dv_devx_cq_query(struct ibv_cq *cq, const void *in, size_t inlen,
			 void *out, size_t outlen);
int mlx5dv_devx_cq_modify(struct ibv_cq *cq, const void *in, size_t inlen,
			  void *out, size_t outlen);
int mlx5dv_devx_qp_query(struct ibv_qp *qp, const void *in, size_t inlen,
			 void *out, size_t outlen);
int mlx5dv_devx_qp_modify(struct ibv_qp *qp, const void *in, size_t inlen,
			  void *out, size_t outlen);
int mlx5dv_devx_srq_query(struct ibv_srq *srq, const void *in, size_t inlen,
			  void *out, size_t outlen);
int mlx5dv_devx_srq_modify(struct ibv_srq *srq, const void *in, size_t inlen,
			   void *out, size_t outlen);
int mlx5dv_devx_wq_query(struct ibv_wq *wq, const void *in, size_t inlen,
			 void *out, size_t outlen);
int mlx5dv_devx_wq_modify(struct ibv_wq *wq, const void *in, size_t inlen,
			  void *out, size_t outlen);
int mlx5dv_devx_ind_tbl_query(struct ibv_rwq_ind_table *ind_tbl,
			      const void *in, size_t inlen,
			      void *out, size_t outlen);
int mlx5dv_devx_ind_tbl_modify(struct ibv_rwq_ind_table *ind_tbl,
			       const void *in, size_t inlen,
			       void *out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif /* _MLX5DV_H_ */
