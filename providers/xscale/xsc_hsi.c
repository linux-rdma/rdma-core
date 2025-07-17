// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <stdint.h>
#include <stdbool.h>

#include <util/mmio.h>

#include "xscale.h"
#include "xsc_hsi.h"

static void andes_ring_tx_doorbell(void *db_addr, u32 sqn,
				   u32 next_pid)
{
	u32 tx_db = 0;

	tx_db = FIELD_PREP(ANDES_SEND_DB_NEXT_PID_MASK, next_pid) |
		FIELD_PREP(ANDES_SEND_DB_QP_ID_MASK, sqn);

	udma_to_device_barrier();
	mmio_write32_le(db_addr, htole32(tx_db));
}

static void andes_ring_rx_doorbell(void *db_addr, u32 rqn,
				   u32 next_pid)
{
	u32 rx_db = 0;

	rx_db = FIELD_PREP(ANDES_RECV_DB_NEXT_PID_MASK, next_pid) |
		FIELD_PREP(ANDES_RECV_DB_QP_ID_MASK, rqn);

	udma_to_device_barrier();
	mmio_write32_le(db_addr, htole32(rx_db));
}

static void andes_update_cq_db(void *db_addr, u32 cqn, u32 next_cid,
			       u8 solicited)
{
	u32 cq_db;

	cq_db = FIELD_PREP(ANDES_CQ_DB_NEXT_CID_MASK, next_cid) |
		FIELD_PREP(ANDES_CQ_DB_CQ_ID_MASK, cqn) |
		FIELD_PREP(ANDES_CQ_DB_ARM_MASK, solicited);

	udma_to_device_barrier();
	mmio_wc_start();
	mmio_write32_le(db_addr, htole32(cq_db));
	mmio_flush_writes();
}

static void andes_set_cq_ci(void *db_addr, u32 cqn, u32 next_cid)
{
	u32 cq_db;

	cq_db = FIELD_PREP(ANDES_CQ_DB_NEXT_CID_MASK, next_cid) |
		FIELD_PREP(ANDES_CQ_DB_CQ_ID_MASK, cqn) |
		FIELD_PREP(ANDES_CQ_DB_ARM_MASK, 0);

	udma_to_device_barrier();
	mmio_write32_le(db_addr, htole32(cq_db));
}

static bool andes_is_err_cqe(struct xsc_cqe *cqe)
{
	return FIELD_GET(CQE_DATA0_IS_ERR_MASK, le32toh(cqe->data0));
}

static u8 andes_get_cqe_error_code(struct xsc_cqe *cqe)
{
	return FIELD_GET(CQE_DATA0_ERROR_CODE_ANDES_MASK,
			 le32toh(cqe->data0));
}

static u8 andes_get_msg_opcode(struct xsc_cqe *cqe)
{
	return FIELD_GET(CQE_DATA0_MSG_OPCODE_ANDES_MASK,
			 le32toh(cqe->data0));
}

static struct xsc_hw_ops andes_ops = {
	.ring_tx_doorbell = andes_ring_tx_doorbell,
	.ring_rx_doorbell = andes_ring_rx_doorbell,
	.update_cq_db = andes_update_cq_db,
	.set_cq_ci = andes_set_cq_ci,
	.is_err_cqe = andes_is_err_cqe,
	.get_cqe_error_code = andes_get_cqe_error_code,
	.get_cqe_msg_opcode = andes_get_msg_opcode,
};

void xsc_init_hw_ops(struct xsc_context *ctx)
{
	ctx->hw_ops = &andes_ops;
}
