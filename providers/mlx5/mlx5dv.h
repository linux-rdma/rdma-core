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

/* For __be64 type */
#include <linux/types.h>
#include <arpa/inet.h>

enum {
	MLX5_RCV_DBR	= 0,
	MLX5_SND_DBR	= 1,
};

/*
 * Direct verbs device-specific attributes
 */
struct mlx5dv_context {
	uint8_t		version;
	uint64_t	flags;
	uint64_t	comp_mask;
};

enum mlx5dv_context_flags {
	/*
	 * This flag indicates if CQE version 0 or 1 is needed.
	 */
	MLX5DV_CONTEXT_FLAGS_CQE_V1 = (1 << 0),
};

/*
 * Most device capabilities are exported by ibv_query_device(...),
 * but there is HW device-specific information which is important
 * for data-path, but isn't provided.
 *
 * Return 0 on success.
 */
int mlx5dv_query_device(struct ibv_context *ctx_in,
			struct mlx5dv_context *attrs_out);

struct mlx5dv_qp {
	uint32_t		*dbrec;
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
};

struct mlx5dv_cq {
	void			*buf;
	uint32_t		*dbrec;
	uint32_t		cqe_cnt;
	uint32_t		cqe_size;
	void			*uar;
	uint32_t		cqn;
	uint64_t		comp_mask;
};

struct mlx5dv_srq {
	void			*buf;
	uint32_t		*dbrec;
	uint32_t		stride;
	uint32_t		head;
	uint32_t		tail;
	uint64_t		comp_mask;
};

struct mlx5dv_rwq {
	void		*buf;
	uint32_t	*dbrec;
	uint32_t	wqe_cnt;
	uint32_t	stride;
	uint64_t	comp_mask;
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
};

enum mlx5dv_obj_type {
	MLX5DV_OBJ_QP	= 1 << 0,
	MLX5DV_OBJ_CQ	= 1 << 1,
	MLX5DV_OBJ_SRQ	= 1 << 2,
	MLX5DV_OBJ_RWQ	= 1 << 3,
};

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

struct mlx5_cqe64 {
	uint8_t		rsvd0[17];
	uint8_t		ml_path;
	uint8_t		rsvd20[4];
	uint16_t	slid;
	uint32_t	flags_rqpn;
	uint8_t		hds_ip_ext;
	uint8_t		l4_hdr_type_etc;
	uint16_t	vlan_info;
	uint32_t	srqn_uidx;
	uint32_t	imm_inval_pkey;
	uint8_t		rsvd40[4];
	uint32_t	byte_cnt;
	__be64		timestamp;
	uint32_t	sop_drop_qpn;
	uint16_t	wqe_counter;
	uint8_t		signature;
	uint8_t		op_own;
};

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
	uint16_t		next_wqe_index;
	uint8_t			signature;
	uint8_t			rsvd1[11];
};

struct mlx5_wqe_data_seg {
	uint32_t		byte_count;
	uint32_t		lkey;
	uint64_t		addr;
};

struct mlx5_wqe_ctrl_seg {
	uint32_t	opmod_idx_opcode;
	uint32_t	qpn_ds;
	uint8_t		signature;
	uint8_t		rsvd[2];
	uint8_t		fm_ce_se;
	uint32_t	imm;
};

struct mlx5_wqe_av {
	union {
		struct {
			uint32_t	qkey;
			uint32_t	reserved;
		} qkey;
		uint64_t	dc_key;
	} key;
	uint32_t	dqp_dct;
	uint8_t		stat_rate_sl;
	uint8_t		fl_mlid;
	uint16_t	rlid;
	uint8_t		reserved0[4];
	uint8_t		rmac[6];
	uint8_t		tclass;
	uint8_t		hop_limit;
	uint32_t	grh_gid_fl;
	uint8_t		rgid[16];
};

struct mlx5_wqe_datagram_seg {
	struct mlx5_wqe_av	av;
};

struct mlx5_wqe_raddr_seg {
	uint64_t	raddr;
	uint32_t	rkey;
	uint32_t	reserved;
};

struct mlx5_wqe_atomic_seg {
	uint64_t	swap_add;
	uint64_t	compare;
};

struct mlx5_wqe_inl_data_seg {
	uint32_t	byte_count;
};

struct mlx5_wqe_eth_seg {
	uint32_t	rsvd0;
	uint8_t		cs_flags;
	uint8_t		rsvd1;
	uint16_t	mss;
	uint32_t	rsvd2;
	uint16_t	inline_hdr_sz;
	uint8_t		inline_hdr_start[2];
	uint8_t		inline_hdr[16];
};

#endif /* _MLX5DV_H_ */
