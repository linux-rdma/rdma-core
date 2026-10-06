/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2026 Hewlett Packard Enterprise Development LP
 */

/*
 * List entries the provider appends to an RU QP's PTE. The PTE is a
 * matching PTE, so an entry is selected by match_bits (under ignore_bits)
 * and by the initiator's match_id; both must be right or nothing matches.
 */

#ifndef CXI_LE_H
#define CXI_LE_H

#include <stdint.h>
#include <errno.h>
#include <string.h>
#include "cxi_prov_hw.h"
#include <rdma/cxiverbs-abi.h>

/* SEND carries no key, so a receive buffer matches exactly the zero no rkey is. */
#define CXI_LE_RECV_MATCH_BITS 0ULL

#define CXI_LE_VNI_MASK 0xffffULL
#define CXI_LE_RKEY_MAX 0xffffffffffffULL

static inline int cxi_le_wire_key(uint64_t rkey, uint64_t *wire_key)
{
	if (rkey > CXI_LE_RKEY_MAX)
		return -EOPNOTSUPP;
	*wire_key = rkey << 16;
	return 0;
}

static inline int cxi_le_set_vni(union c_cmdu *cmd, uint64_t rkey, uint16_t vni)
{
	uint64_t wire_key;
	int ret = cxi_le_wire_key(rkey, &wire_key);

	if (ret)
		return ret;
	cmd->target.match_bits = wire_key | vni;
	cmd->target.ignore_bits &= ~CXI_LE_VNI_MASK;
	return 0;
}

static inline void cxi_le_recv(union c_cmdu *cmd, uint16_t ptlte_index, uint8_t lac, uint64_t iova,
			       uint64_t length)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->command.opcode = C_CMD_TGT_APPEND;
	cmd->target.ptlte_index = ptlte_index;
	cmd->target.ptl_list = C_PTL_LIST_PRIORITY;
	cmd->target.op_put = 1;
	cmd->target.use_once = 1;
	cmd->target.lac = lac;
	cmd->target.start = iova;
	cmd->target.length = length;
	cmd->target.match_bits = CXI_LE_RECV_MATCH_BITS;
	cmd->target.ignore_bits = 0;
	cmd->target.match_id = CXI_MATCH_ID_ANY;
}

/*
 * An attached region matches its rkey exactly: a region reachable by a
 * narrow key is made that way at registration, so the key carries its own
 * width. It persists until detached, and buffer_id names it for the unlink.
 */
static inline void cxi_le_region(union c_cmdu *cmd, uint16_t ptlte_index, uint64_t lkey64,
				 uint64_t rkey64, uint64_t iova, uint64_t length)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->command.opcode = C_CMD_TGT_APPEND;
	cmd->target.ptlte_index = ptlte_index;
	cmd->target.ptl_list = C_PTL_LIST_PRIORITY;
	cmd->target.op_put = 1;
	cmd->target.op_get = 1;
	cmd->target.lac = lkey64 & CXI_LKEY64_LAC_MASK;
	cmd->target.start = iova;
	cmd->target.length = length;
	cmd->target.match_bits = rkey64;
	cmd->target.ignore_bits = 0;
	cmd->target.match_id = CXI_MATCH_ID_ANY;
	cmd->target.use_once = 0;
	cmd->target.buffer_id = (uint16_t)(rkey64 & 0xffff);
}

static inline void cxi_le_region_unlink(union c_cmdu *cmd, uint16_t ptlte_index, uint64_t rkey64)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->command.opcode = C_CMD_TGT_UNLINK;
	cmd->target.ptlte_index = ptlte_index;
	cmd->target.ptl_list = C_PTL_LIST_PRIORITY;
	cmd->target.buffer_id = (uint16_t)(rkey64 & 0xffff);
}

#endif /* CXI_LE_H */
