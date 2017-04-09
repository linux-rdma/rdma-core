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

#ifndef _MLX4DV_H_
#define _MLX4DV_H_

#include <linux/types.h>
#include <endian.h>
#include <infiniband/verbs.h>

enum {
	MLX4_OPCODE_NOP			= 0x00,
	MLX4_OPCODE_SEND_INVAL		= 0x01,
	MLX4_OPCODE_RDMA_WRITE		= 0x08,
	MLX4_OPCODE_RDMA_WRITE_IMM	= 0x09,
	MLX4_OPCODE_SEND		= 0x0a,
	MLX4_OPCODE_SEND_IMM		= 0x0b,
	MLX4_OPCODE_LSO			= 0x0e,
	MLX4_OPCODE_RDMA_READ		= 0x10,
	MLX4_OPCODE_ATOMIC_CS		= 0x11,
	MLX4_OPCODE_ATOMIC_FA		= 0x12,
	MLX4_OPCODE_MASKED_ATOMIC_CS	= 0x14,
	MLX4_OPCODE_MASKED_ATOMIC_FA	= 0x15,
	MLX4_OPCODE_BIND_MW		= 0x18,
	MLX4_OPCODE_FMR			= 0x19,
	MLX4_OPCODE_LOCAL_INVAL		= 0x1b,
	MLX4_OPCODE_CONFIG_CMD		= 0x1f,

	MLX4_RECV_OPCODE_RDMA_WRITE_IMM	= 0x00,
	MLX4_RECV_OPCODE_SEND		= 0x01,
	MLX4_RECV_OPCODE_SEND_IMM	= 0x02,
	MLX4_RECV_OPCODE_SEND_INVAL	= 0x03,

	MLX4_CQE_OPCODE_ERROR		= 0x1e,
	MLX4_CQE_OPCODE_RESIZE		= 0x16,
};

enum {
	MLX4_CQ_DOORBELL			= 0x20
};

#define MLX4_CQ_DB_REQ_NOT_SOL			(1 << 24)
#define MLX4_CQ_DB_REQ_NOT			(2 << 24)

enum {
	MLX4_CQE_VLAN_PRESENT_MASK		= 1 << 29,
	MLX4_CQE_QPN_MASK			= 0xffffff,
};

enum {
	MLX4_CQE_OWNER_MASK			= 0x80,
	MLX4_CQE_IS_SEND_MASK			= 0x40,
	MLX4_CQE_OPCODE_MASK			= 0x1f
};

enum {
	MLX4_CQE_SYNDROME_LOCAL_LENGTH_ERR		= 0x01,
	MLX4_CQE_SYNDROME_LOCAL_QP_OP_ERR		= 0x02,
	MLX4_CQE_SYNDROME_LOCAL_PROT_ERR		= 0x04,
	MLX4_CQE_SYNDROME_WR_FLUSH_ERR			= 0x05,
	MLX4_CQE_SYNDROME_MW_BIND_ERR			= 0x06,
	MLX4_CQE_SYNDROME_BAD_RESP_ERR			= 0x10,
	MLX4_CQE_SYNDROME_LOCAL_ACCESS_ERR		= 0x11,
	MLX4_CQE_SYNDROME_REMOTE_INVAL_REQ_ERR		= 0x12,
	MLX4_CQE_SYNDROME_REMOTE_ACCESS_ERR		= 0x13,
	MLX4_CQE_SYNDROME_REMOTE_OP_ERR			= 0x14,
	MLX4_CQE_SYNDROME_TRANSPORT_RETRY_EXC_ERR	= 0x15,
	MLX4_CQE_SYNDROME_RNR_RETRY_EXC_ERR		= 0x16,
	MLX4_CQE_SYNDROME_REMOTE_ABORTED_ERR		= 0x22,
};

struct mlx4_err_cqe {
	uint32_t	vlan_my_qpn;
	uint32_t	reserved1[5];
	uint16_t	wqe_index;
	uint8_t		vendor_err;
	uint8_t		syndrome;
	uint8_t		reserved2[3];
	uint8_t		owner_sr_opcode;
};

enum mlx4_cqe_status {
	MLX4_CQE_STATUS_TCP_UDP_CSUM_OK	= (1 <<  2),
	MLX4_CQE_STATUS_IPV4_PKT	= (1 << 22),
	MLX4_CQE_STATUS_IP_HDR_CSUM_OK	= (1 << 28),
	MLX4_CQE_STATUS_IPV4_CSUM_OK	= MLX4_CQE_STATUS_IPV4_PKT |
					MLX4_CQE_STATUS_IP_HDR_CSUM_OK |
					MLX4_CQE_STATUS_TCP_UDP_CSUM_OK
};

struct mlx4_cqe {
	uint32_t	vlan_my_qpn;
	uint32_t	immed_rss_invalid;
	uint32_t	g_mlpath_rqpn;
	union {
		struct {
			uint16_t	sl_vid;
			uint16_t	rlid;
		};
		uint32_t ts_47_16;
	};
	uint32_t	status;
	uint32_t	byte_cnt;
	uint16_t	wqe_index;
	uint16_t	checksum;
	uint8_t		reserved3;
	uint8_t		ts_15_8;
	uint8_t		ts_7_0;
	uint8_t		owner_sr_opcode;
};

struct mlx4dv_qp {
	uint32_t		*rdb;
	uint32_t		*sdb;
	uint32_t		doorbell_qpn;
	struct {
		uint32_t	wqe_cnt;
		int		wqe_shift;
		int		offset;
	} sq;
	struct {
		uint32_t	wqe_cnt;
		int		wqe_shift;
		int		offset;
	} rq;
	struct {
		void			*buf;
		size_t			length;
	} buf;
	uint64_t		comp_mask;
};

struct mlx4dv_cq {
	struct {
		void			*buf;
		size_t			length;
	} buf;
	uint32_t			cqe_cnt;
	uint32_t			cqn;
	uint32_t		       *set_ci_db;
	uint32_t		       *arm_db;
	int				arm_sn;
	int				cqe_size;
	uint64_t			comp_mask;
};
struct mlx4dv_srq {
	struct {
		void			*buf;
		size_t			length;
	} buf;
	int				wqe_shift;
	int				head;
	int				tail;
	uint32_t		       *db;
	uint64_t			comp_mask;
};

struct mlx4dv_obj {
	struct {
		struct ibv_qp		*in;
		struct mlx4dv_qp	*out;
	} qp;
	struct {
		struct ibv_cq		*in;
		struct mlx4dv_cq	*out;
	} cq;
	struct {
		struct ibv_srq		*in;
		struct mlx4dv_srq	*out;
	} srq;
};

enum mlx4dv_obj_type {
	MLX4DV_OBJ_QP	= 1 << 0,
	MLX4DV_OBJ_CQ	= 1 << 1,
	MLX4DV_OBJ_SRQ	= 1 << 2,
};

/*
 * This function will initialize mlx4dv_xxx structs based on supplied type.
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
int mlx4dv_init_obj(struct mlx4dv_obj *obj, uint64_t obj_type);

/*
 * WQE related part
 */

enum {
	MLX4_SEND_DOORBELL	= 0x14,
};

enum {
	MLX4_WQE_CTRL_SOLICIT		= 1 << 1,
	MLX4_WQE_CTRL_CQ_UPDATE		= 3 << 2,
	MLX4_WQE_CTRL_IP_HDR_CSUM	= 1 << 4,
	MLX4_WQE_CTRL_TCP_UDP_CSUM	= 1 << 5,
	MLX4_WQE_CTRL_FENCE		= 1 << 6,
	MLX4_WQE_CTRL_STRONG_ORDER	= 1 << 7
};

enum {
	MLX4_WQE_BIND_TYPE_2		= (1<<31),
	MLX4_WQE_BIND_ZERO_BASED	= (1<<30),
};

enum {
	MLX4_INLINE_SEG		= 1 << 31,
	MLX4_INLINE_ALIGN	= 64,
};

enum {
	MLX4_INVALID_LKEY	= 0x100,
};

enum {
	MLX4_WQE_MW_REMOTE_READ   = 1 << 29,
	MLX4_WQE_MW_REMOTE_WRITE  = 1 << 30,
	MLX4_WQE_MW_ATOMIC        = 1 << 31
};

struct mlx4_wqe_local_inval_seg {
	uint64_t		reserved1;
	uint32_t		mem_key;
	uint32_t		reserved2;
	uint64_t		reserved3[2];
};

struct mlx4_wqe_bind_seg {
	uint32_t		flags1;
	uint32_t		flags2;
	uint32_t		new_rkey;
	uint32_t		lkey;
	uint64_t		addr;
	uint64_t		length;
};

struct mlx4_wqe_ctrl_seg {
	uint32_t		owner_opcode;
	union {
		struct {
			uint8_t			reserved[3];
			uint8_t			fence_size;
		};
		uint32_t	bf_qpn;
	};
	/*
	 * High 24 bits are SRC remote buffer; low 8 bits are flags:
	 * [7]   SO (strong ordering)
	 * [5]   TCP/UDP checksum
	 * [4]   IP checksum
	 * [3:2] C (generate completion queue entry)
	 * [1]   SE (solicited event)
	 * [0]   FL (force loopback)
	 */
	uint32_t		srcrb_flags;
	/*
	 * imm is immediate data for send/RDMA write w/ immediate;
	 * also invalidation key for send with invalidate; input
	 * modifier for WQEs on CCQs.
	 */
	uint32_t		imm;
};

struct mlx4_wqe_datagram_seg {
	uint32_t		av[8];
	uint32_t		dqpn;
	uint32_t		qkey;
	uint16_t		vlan;
	uint8_t			mac[6];
};

struct mlx4_wqe_data_seg {
	uint32_t		byte_count;
	uint32_t		lkey;
	uint64_t		addr;
};

struct mlx4_wqe_inline_seg {
	uint32_t		byte_count;
};

struct mlx4_wqe_srq_next_seg {
	uint16_t		reserved1;
	uint16_t		next_wqe_index;
	uint32_t		reserved2[3];
};

struct mlx4_wqe_raddr_seg {
	uint64_t		raddr;
	uint32_t		rkey;
	uint32_t		reserved;
};

struct mlx4_wqe_atomic_seg {
	uint64_t		swap_add;
	uint64_t		compare;
};

#endif /* _MLX4DV_H_ */

