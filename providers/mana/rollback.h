/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2024, Microsoft Corporation. All rights reserved.
 */

#ifndef _ROLLBACK_H_
#define _ROLLBACK_H_

#include <linux/types.h>
#include <util/udma_barrier.h>
#include <util/mmio.h>
#include <util/util.h>
#include <sys/mman.h>
#include "mana.h"

#define MAKE_TAG(a, b, c, d) (((uint32_t)(d) << 24) | ((c) << 16) | ((b) << 8) | (a))
#define RNIC_ROLLBACK_SHARED_MEM_SIG MAKE_TAG('R', 'L', 'B', 'K')

struct mana_ib_rollback_shared_mem {
	uint32_t signature;
	uint32_t size;

	_Atomic(uint32_t) left_offset;
	_Atomic(uint32_t) right_offset;
};

static inline struct mana_ib_rollback_shared_mem
	*mana_ib_get_rollback_sh_mem(struct mana_qp *qp)
{
	struct mana_ib_rollback_shared_mem *rb_shmem;
	struct mana_gdma_queue *req_sq =
		&qp->rc_qp.queues[USER_RC_SEND_QUEUE_REQUESTER];

	rb_shmem = (struct mana_ib_rollback_shared_mem *)
		((uint8_t *)req_sq->buffer + req_sq->size);

	return rb_shmem;
}

static inline void mana_ib_init_rb_shmem(struct mana_qp *qp)
{
	// take some bytes for rollback memory
	struct mana_gdma_queue *req_sq =
		&qp->rc_qp.queues[USER_RC_SEND_QUEUE_REQUESTER];
	req_sq->size -= sizeof(struct mana_ib_rollback_shared_mem);

	struct mana_ib_rollback_shared_mem *rb_shmem =
		mana_ib_get_rollback_sh_mem(qp);

	memset(rb_shmem, 0, sizeof(*rb_shmem));
	rb_shmem->signature = RNIC_ROLLBACK_SHARED_MEM_SIG;
	rb_shmem->size = sizeof(struct mana_ib_rollback_shared_mem);
}

static inline void mana_ib_deinit_rb_shmem(struct mana_qp *qp)
{
	// return back bytes for rollback memory
	struct mana_gdma_queue *req_sq =
		&qp->rc_qp.queues[USER_RC_SEND_QUEUE_REQUESTER];
	req_sq->size += sizeof(struct mana_ib_rollback_shared_mem);
}

static inline void mana_ib_reset_rb_shmem(struct mana_qp *qp)
{
	struct mana_ib_rollback_shared_mem *rb_shmem =
		mana_ib_get_rollback_sh_mem(qp);

	atomic_store(&rb_shmem->right_offset, 0);
	atomic_store(&rb_shmem->left_offset, 0);
}

static inline void mana_ib_update_shared_mem_right_offset(struct mana_qp *qp, uint32_t offset_in_bu)
{
	struct mana_ib_rollback_shared_mem *rb_shmem =
			mana_ib_get_rollback_sh_mem(qp);

	atomic_store(&rb_shmem->right_offset, offset_in_bu);
}

static inline void mana_ib_update_shared_mem_left_offset(struct mana_qp *qp, uint32_t offset_in_bu)
{
	struct mana_ib_rollback_shared_mem *rb_shmem =
			mana_ib_get_rollback_sh_mem(qp);

	atomic_store(&rb_shmem->left_offset, offset_in_bu);
}

#endif //_ROLLBACK_H_
