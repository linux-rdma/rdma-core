/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2018-2020 Cray Inc. All rights reserved
 *
 * CXI event queue and command queue definitions and accessors.
 */

#ifndef __CXI_PROV_HW
#define __CXI_PROV_HW

/* Userspace copy: stand in for the kernel types and headers. */
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <ccan/array_size.h>
#include <util/util.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;

/*
 * wp_fence() - Fence operation used before advancing the command queue write
 * pointer. This ensures that all commands are write visible before hardware
 * processing the write pointer update.
 *
 * wc_fence() - Fence operation used to ensuring ordering between writes to
 * write combining buffers.
 */

#if defined(__aarch64__)

#define aarch64_dmb(opt) ({ asm volatile("dmb " #opt::: "memory"); })

#define sfence() aarch64_dmb(oshst)

/* Data memory barrier with outer shareability is enough to ensure write
 * ordering between host memory command writes and write pointer doorbell
 * writes.
 */
#define wp_fence() aarch64_dmb(oshst)

/* Data memory barrier with outer shareability is enough writes to device memory
 * gather regions (i.e. write combined regions) are ordered with respect to
 * subsequent device memory gather region writes.
 */
#define wc_fence() aarch64_dmb(oshst)

#elif defined(__x86_64__)

static inline void sfence(void)
{
	__asm__ __volatile__("sfence" ::: "memory");
}

#define wp_fence() sfence()
#define wc_fence() sfence()

#else
#error "Unsupported CPU architecture"
#endif

#include <ethernet/cassini_user_defs.h>

static const u8 amo_size[16] = { 1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 8, 16, 16 };

/*
 * Padding needed for a command given the command size and
 * position. eg. a command of size 3 (256 bytes), with a wr_ptr at
 * pos % 8 = 2 needs pad_slots[2][3] = 6 32-bytes block.
 */
static const u32 __cxi_pad_slots[8][4] = { { 0, 0, 0, 0 }, { 0, 1, 3, 7 }, { 0, 0, 2, 6 },
					   { 0, 1, 1, 5 }, { 0, 0, 0, 4 }, { 0, 1, 3, 3 },
					   { 0, 0, 2, 2 }, { 0, 1, 1, 1 } };

/*
 * Number of 32-bytes slots needed for a command
 */
static const u32 __cxi_cmd_slots[4] = { 1, 2, 4, 8 };

/*
 * Return the command size to fit a certain payload. 32 bytes or less
 * return 0 (C_CMD_SIZE_32B), 33 to 64 returns 1 (C_CMD_SIZE_64B), ...
 */
static inline enum c_cmd_size __cxi_cmd_size(u32 size)
{
	if (size <= 16)
		return C_CMD_SIZE_32B;
	else
		return (enum c_cmd_size)(8 * sizeof(u64) - __builtin_clzll((size - 1)) - 5);
}

/*
 * Note.
 *
 * The hardware command granularity is 64 bytes (a slot). However the
 * hardware also support 32 bytes commands. If a command is 32 bytes,
 * there will always be a second 32 bytes command in that 64 bytes
 * slot, and may be a NoOp.
 */

struct cxi_cmd32 {
	u8 pad[32];
};

#define C_CQ_CMD_SIZE 64
#define C_CQ_FIRST_WR_PTR 4
#define C_CQ_FIRST_WR_PTR_32 (2 * C_CQ_FIRST_WR_PTR)

#define LL_OFFSET(wp32) ((((wp32) / 2) & 0x0f) * 64)

struct cxi_cmd64 {
	u8 pad[C_CQ_CMD_SIZE];
};

union c_cmdu {
	u8 u8;
	struct c_cmd command;
	struct c_cstate_cmd c_state;
	struct c_idc_hdr idc_hdr;
	struct c_idc_eth_cmd idc_eth;
	struct c_idc_put_cmd idc_put;
	struct c_idc_amo_cmd idc_amo;
	struct c_idc_msg_hdr idc_msg;
	struct c_nomatch_dma_cmd nomatch_dma;
	struct c_full_dma_cmd full_dma;
	struct c_dma_amo_cmd dma_amo;
	struct c_dma_eth_cmd dma_eth;
	struct c_ct_cmd ct;
	struct c_cq_cmd cq;
	struct c_target_cmd target;
	struct c_set_state_cmd set_state;
};

/* User command queue */
struct cxi_cq {
	/* Command queue size */
	u32 size;

	/* Memory mapped write pointer location */
	u64 *wp_addr;

	/* Low-latency write regions. */
	u8 *ll_64;
	u8 *ll_128a;
	u8 *ll_128u;

	/* CQ status and commands buffer. CQ status occupies the first 8 32-byte
	 * slots. Commands start after.
	 */
	union {
		struct cxi_cmd32 *cmds32;
		volatile struct c_cq_status *status;
	};
	u64 rp32;

	/* CQ index. Transmit CQs use 0 to 1023, and target CQs use
	 * 1024 to 1535. Use cxi_cq_get_cqn() to retrieve the CQ
	 * number, going from 0 to 1023, or 0 to 512 respectively.
	 */
	u32 idx;

	/* 32-bytes internal write pointer */
	u32 size32;
	u64 wp32;
	u64 hw_wp32;
};

#define C_EE_CFG_ECB_SIZE 64
union c_event {
	/* Use as event header, to access event_size and event_type
	 * only
	 */
	struct c_event_cmd_fail hdr;

	struct c_event_initiator_short init_short;
	struct c_event_initiator_long init_long;
	struct c_event_trig_op_short trig_short;
	struct c_event_trig_op_long trig_long;
	struct c_event_cmd_fail cmd_fail;
	struct c_event_target_long tgt_long;
	struct c_event_target_short tgt_short;
	struct c_event_target_enet enet;
	struct c_event_enet_fgfc enet_fgfc;
	struct c_event_timestamp timestamp;
	struct c_event_eq_switch eq_switch;
	struct c_event_pct pct;
};

#define C_LE_EVENT_CT_BYTES BIT(0)
#define C_LE_EVENT_CT_OVERFLOW BIT(1)
#define C_LE_EVENT_CT_COMM BIT(2)
#define C_LE_EVENT_UNLINK_DISABLE BIT(3)
#define C_LE_EVENT_SUCCESS_DISABLE BIT(4)
#define C_LE_EVENT_COMM_DISABLE BIT(5)
#define C_LE_EVENT_LINK_DISABLE BIT(6)
#define C_LE_UNRESTRICTED_END_RO BIT(7)
#define C_LE_UNRESTRICTED_BODY_RO BIT(8)
#define C_LE_UNEXPECTED_HDR_DISABLE BIT(9)
#define C_LE_USE_ONCE BIT(10)
#define C_LE_NO_TRUNCATE BIT(11)
#define C_LE_MANAGE_LOCAL BIT(12)
#define C_LE_OP_GET BIT(13)
#define C_LE_OP_PUT BIT(14)
#define C_LE_RESTART_SEQ BIT(15)

static inline void cxi_target_cmd_setopts(struct c_target_cmd *cmd, u32 flags)
{
	if (flags & C_LE_EVENT_CT_BYTES)
		cmd->event_ct_bytes = 1;
	if (flags & C_LE_EVENT_CT_OVERFLOW)
		cmd->event_ct_overflow = 1;
	if (flags & C_LE_EVENT_CT_COMM)
		cmd->event_ct_comm = 1;
	if (flags & C_LE_EVENT_UNLINK_DISABLE)
		cmd->event_unlink_disable = 1;
	if (flags & C_LE_EVENT_SUCCESS_DISABLE)
		cmd->event_success_disable = 1;
	if (flags & C_LE_EVENT_COMM_DISABLE)
		cmd->event_comm_disable = 1;
	if (flags & C_LE_EVENT_LINK_DISABLE)
		cmd->event_link_disable = 1;
	if (flags & C_LE_UNRESTRICTED_END_RO)
		cmd->unrestricted_end_ro = 1;
	if (flags & C_LE_UNRESTRICTED_BODY_RO)
		cmd->unrestricted_body_ro = 1;
	if (flags & C_LE_USE_ONCE)
		cmd->use_once = 1;
	if (flags & C_LE_NO_TRUNCATE)
		cmd->no_truncate = 1;
	if (flags & C_LE_MANAGE_LOCAL)
		cmd->manage_local = 1;
	if (flags & C_LE_OP_GET)
		cmd->op_get = 1;
	if (flags & C_LE_OP_PUT)
		cmd->op_put = 1;
	if (flags & C_LE_RESTART_SEQ)
		cmd->restart_seq = 1;
}

static inline s32 cxi_init_event_rc(const union c_event *event)
{
	if (event->hdr.event_size == C_EVENT_SIZE_16_BYTE)
		return event->init_short.return_code;
	return event->init_long.return_code;
}

static inline s32 cxi_tgt_event_rc(const union c_event *event)
{
	if (event->hdr.event_size == C_EVENT_SIZE_32_BYTE)
		return event->tgt_short.return_code;
	return event->tgt_long.return_code;
}

static inline s32 cxi_event_rc(const union c_event *event)
{
	switch (event->hdr.event_type) {
	case C_EVENT_PUT:
	case C_EVENT_GET:
	case C_EVENT_ATOMIC:
	case C_EVENT_FETCH_ATOMIC:
	case C_EVENT_PUT_OVERFLOW:
	case C_EVENT_GET_OVERFLOW:
	case C_EVENT_ATOMIC_OVERFLOW:
	case C_EVENT_FETCH_ATOMIC_OVERFLOW:
	case C_EVENT_LINK:
	case C_EVENT_SEARCH:
	case C_EVENT_STATE_CHANGE:
	case C_EVENT_UNLINK:
	case C_EVENT_RENDEZVOUS:
	case C_EVENT_MATCH:
		return cxi_tgt_event_rc(event);

	case C_EVENT_SEND:
	case C_EVENT_ACK:
	case C_EVENT_REPLY:
		return cxi_init_event_rc(event);

	case C_EVENT_ETHERNET:
		return event->enet.return_code;
	case C_EVENT_COMMAND_FAILURE:
		return event->cmd_fail.return_code;
	case C_EVENT_TRIGGERED_OP:
		if (event->hdr.event_size == C_EVENT_SIZE_16_BYTE)
			return event->trig_short.return_code;
		else
			return event->trig_long.return_code;
	case C_EVENT_ETHERNET_FGFC:
		return event->enet_fgfc.return_code;
	case C_EVENT_PCT:
		return event->pct.return_code;
	case C_EVENT_ERROR:
		return C_RC_NO_EVENT;
	case C_EVENT_TIMESTAMP:
		return event->timestamp.return_code;
	case C_EVENT_EQ_SWITCH:
		return event->eq_switch.return_code;
	case C_EVENT_NULL_EVENT:
		return C_RC_NO_EVENT;
	}

	return C_RC_NO_EVENT;
}

/* Generate match_id. match_id is present in LEs, DMA commands and EQ events.
 * The highest 'pid_bits' bits are used to hold a PID value. The remaining,
 * low-order 32-'pid_bits' bits are used to store an Endpoint ID. When using a
 * PtlTE configured for logical matching, the Endpoint ID represents a logical
 * rank ID. Otherwise, the Endpoint ID contains a 20 bit physical NIC ID.
 */
#define CXI_MATCH_ID(pid_bits, pid, ep)                                                            \
	((((pid) & ((1U << (pid_bits)) - 1)) << (32U - (pid_bits))) |                              \
	 ((ep) & ((1U << (32 - (pid_bits))) - 1)))
#define CXI_MATCH_ID_ANY CXI_MATCH_ID(C_DFA_PID_BITS_MAX, C_PID_ANY, C_RANK_ANY)

#define CXI_MATCH_ID_PID(pid_bits, match_id) ((match_id) >> (32 - (pid_bits)))
#define CXI_MATCH_ID_EP(pid_bits, match_id) ((match_id) & ((1U << (32 - (pid_bits))) - 1))

/**
 * struct cxi_rdzv_match_bits - Match bits used for Rendezvous Get.
 * @match_bits: Match bits mirrored from the Rendezvous Put operation
 * @transaction_type: Rendezvous transaction type, must match device
 * configuration
 * @rendezvous_id: Rendezvous ID used for Rendezvous Put operation
 *
 * The 64-bit rendezvous match bits value has two uses.
 * 1. Rendezvous Put Initiator: Match bits used in a source buffer LE linked to
 *    the rendezvous source PtlTE.
 * 2. Rendezvous Put Target: Match bits used in a SW issued Get.
 */
struct cxi_rdzv_match_bits {
	union {
		struct {
			u64 rendezvous_id : 8;
			u64 transaction_type : 4;
			u64 unused : 36;
			u64 match_bits : 16;
		};
		u64 raw;
	};
};

/**
 * struct cxi_rdzv_user_ptr - User pointer format for Rendezvous Get events.
 * @src_nid: Source fabric address NID of the Rendezvous Put
 * @src_pid: Source fabric address PID of the Rendezvous Put
 * @ptlte_index: PltTE index the target LE was appended on
 * @rendezvous_id: Rendezvous ID from the Rendezvous Put
 * @buffer_id: Buffer ID of the target LE from the Rendezvous Put
 *
 * The user_ptr field in a Reply event for a Hardware issued Rendezvous Get is
 * formatted using this structure.
 */
struct cxi_rdzv_user_ptr {
	union {
		struct {
			u64 src_nid : 20;
			u64 src_pid : 9;
			u64 ptlte_index : 11;
			u64 rendezvous_id : 8;
			u64 buffer_id : 16;
		};
		u64 raw;
	};
};

#define CT_INC_SUCCESS_OFFSET 0
#define CT_INC_FAILURE_OFFSET 64
#define CT_RESET_SUCCESS_OFFSET 128
#define CT_RESET_FAILURE_OFFSET 192
#define CT_SUCCESS_MASK ((1ULL << C_CT_SUCCESS_BITS) - 1)
#define CT_FAILURE_MASK ((1ULL << C_CT_FAILURE_BITS) - 1)

/* User counter */
struct cxi_ct {
	/* Memory mapped doorbell. */
	u64 *doorbell;

	/* The allocated CT number, which will be used in commands. */
	u32 ctn;

	/* Writeback buffer backpoint for CT owner. */
	struct c_ct_writeback *wb;
};

/* Hardware reserves two event slots: one for detecting EQ overrun and the first
 * slot for providing EQ status writeback.
 */
#define C_EQ_RESERVED_EVENT_SLOTS 2U

/* User event queue */
struct cxi_eq {
	/* Event queue byte size */
	u32 byte_size;

	/* EQ software state, which includes the read pointer. Keep a
	 * local copy and update the fields as needed before copying
	 * it to the adapter.
	 */
	union c_ee_cfg_eq_sw_state sw_state;
	u64 *sw_state_addr;

	/* Cached status write-back timestamp. */
	u64 last_ts_sec;
	u64 last_ts_ns;

	/* Current read offset */
	u32 rd_offset;

	/* Previous read offset - before last call to
	 * cxi_eq_ack_events()
	 */
	u32 prev_rd_offset;

	/* The allocated EQ number, which will be used in commands. */
	u32 eqn;

	/* Backpointer for the owner of the EQ. */
	void *context;

	union {
		/* Ring buffer for events */
		u8 *events;

		/* EQ status write-back pointer. Updated when the number of free
		 * events crosses a configurable threshold, or when events are
		 * dropped.
		 */
		struct c_eq_status *status;
	};
};

/* Check to see if command queue is empty. */
static inline bool cxi_cq_empty(struct cxi_cq *cq)
{
	u64 wp = cq->wp32 / 2;

	return wp == cq->status->rd_ptr;
}

/*
 * Advance the internal write pointer for the given command
 * size. cmd_size is 0, 1, 2 or 3 (C_CMD_SIZE_XXX).
 * If the write pointer wraps, set wp32 to the first valid offset for a command.
 * The start of the queue is used by Cassini to return status.
 */
static inline void __cxi_cq_advance_wp(struct cxi_cq *cq, enum c_cmd_size cmd_size)
{
	cq->wp32 = (cq->wp32 + (1 << cmd_size));
	if (cq->wp32 >= cq->size32)
		cq->wp32 = C_CQ_FIRST_WR_PTR_32;
}

/*
 * Return the number of usable slots in the queue using the cached read
 * pointer. Remove 1 full 64-bytes slot to prevent queue overrun (wr_ptr ==
 * rd_ptr). Remove 4 full slots because the start of the queue is used by
 * Cassini to return rd_ptr and status.
 */
static inline s32 __cxi_cq_free_slots_check(const struct cxi_cq *cq)
{
	if (cq->wp32 >= cq->rp32)
		return cq->size32 - cq->wp32 + cq->rp32 - 2 - C_CQ_FIRST_WR_PTR_32;
	else
		return cq->rp32 - cq->wp32 - 2;
}

/*
 * Return the number of usable slots in the queue.
 *
 * Cassini regularly writes the read pointer to host memory. Avoid accessing
 * the read pointer to reduce expensive loads from memory.
 */
static inline s32 __cxi_cq_free_slots(struct cxi_cq *cq)
{
	s32 slots = __cxi_cq_free_slots_check(cq);

	if (slots < 16) {
		cq->rp32 = cq->status->rd_ptr * 2;
		slots = __cxi_cq_free_slots_check(cq);
	}

	return slots;
}

/**
 * cxi_cq_update_wp() - Update the real write pointer.
 *
 * This lets the rest of the software manage the ring buffer as
 * 64-bytes slots, while internally it's managed as 32 bytes slots.
 *
 * If the internal write pointer is odd, add a NoOp to pad to a 64
 * bytes block.
 *
 * Users should not call this function. Instead, they should use
 * cxi_cq_ll_ring() or cxi_cq_ring().
 */
static inline void cxi_cq_update_wp(struct cxi_cq *cq)
{
	if (cq->wp32 & 1) {
		struct cxi_cmd32 *cmd = &cq->cmds32[cq->wp32];

		/* Command opcode and DFA must be cleared */
		memset(cmd->pad, 0, sizeof(u64));
		__cxi_cq_advance_wp(cq, C_CMD_SIZE_32B);
	}

	/* Ensure commands are in memory. */
	wp_fence();
}

/**
 * cxi_memcpy_aligned() - Copy to 64-bit aligned buffer.
 *
 * dest and n must be 64-bit aligned.
 */
static inline void cxi_memcpy_aligned(void *dest, const void *src, size_t n)
{
	size_t i;

	for (i = 0; i < n / 8; i++)
		((u64 *)dest)[i] = ((u64 *)src)[i];
}

/**
 * __cxi_cq_inc_hw_wp32() - Increment software's mirror of the hardware write
 * pointer by count amount of 32-byte chunks. Count must not exceed CQ size.
 */
static inline void __cxi_cq_inc_hw_wp32(struct cxi_cq *cq, u32 count)
{
	cq->hw_wp32 += count;
	if (cq->hw_wp32 == cq->size32)
		cq->hw_wp32 = C_CQ_FIRST_WR_PTR_32;
}

/**
 * cxi_cq_ll_write64() - Write commands to 64-byte low-latency region.
 *
 * Note: Users should not call this function.
 */
static inline void cxi_cq_ll_write64(struct cxi_cq *cq)
{
	struct cxi_cmd64 *ll = (struct cxi_cmd64 *)(cq->ll_64 + LL_OFFSET(cq->hw_wp32));

	cxi_memcpy_aligned(ll, &cq->cmds32[cq->hw_wp32], sizeof(struct cxi_cmd64));

	__cxi_cq_inc_hw_wp32(cq, 2);
}

/**
 * cxi_cq_ll_write128_aligned() - Write commands to 128-byte aligned
 * low-latency region. The CQ hardware write pointer must be aligned to a
 * 128-byte boundary (i.e. hw_wp32 % 8 == 0, 4).
 *
 * Note: Users should not call this function.
 */
static inline void cxi_cq_ll_write128_aligned(struct cxi_cq *cq)
{
	struct cxi_cmd64 *ll = (struct cxi_cmd64 *)(cq->ll_128a + LL_OFFSET(cq->hw_wp32));

	cxi_memcpy_aligned(ll, &cq->cmds32[cq->hw_wp32], sizeof(struct cxi_cmd64) * 2);

	__cxi_cq_inc_hw_wp32(cq, 4);
}

/**
 * cxi_cq_ll_write128_unaligned() - Write commands to 128-byte unaligned
 * low-latency region. The CQ hardware write pointer must be unaligned to a
 * 128-byte boundary (i.e. hw_wp32 % 8 == 2, 6).
 *
 * Note: Users should not call this function.
 */
static inline void cxi_cq_ll_write128_unaligned(struct cxi_cq *cq)
{
	struct cxi_cmd64 *ll;

	/*
	 * These two 32-byte slots MUST be NOOPs. Thus, skip over them in the
	 * command queue since hardware will skip the corresponding 64-byte
	 * slot.
	 */
	__cxi_cq_inc_hw_wp32(cq, 2);

	ll = (struct cxi_cmd64 *)(cq->ll_128u + LL_OFFSET(cq->hw_wp32));

	cxi_memcpy_aligned(ll, &cq->cmds32[cq->hw_wp32], sizeof(struct cxi_cmd64) * 2);

	__cxi_cq_inc_hw_wp32(cq, 4);
}

/**
 * cxi_cq_ring() - Update the CQ write pointer and ring the CQ to
 * execute the new posted commands.
 *
 * After posting one or more commands, the user would call this
 * function to let the new work start.
 *
 * @cq: the command queue
 */
static inline void cxi_cq_ring(struct cxi_cq *cq)
{
	u64 wr_ptr;

	if (cq->wp32 == cq->hw_wp32)
		return;

	cxi_cq_update_wp(cq);

	cq->hw_wp32 = cq->wp32;
	wr_ptr = cq->wp32 / 2;
	*cq->wp_addr = wr_ptr;
	wc_fence();
}

/**
 * cxi_cq_ll_ring() - Commit outstanding commands to hardware using the
 * low-latency write mechanism. This function will account for the alignment of
 * the CQ hardware write pointer to ensure that the proper low-latency region
 * is written to. This function guarantees that all commands are committed to
 * HW. A standard doorbell ring may be used to accomplish that.
 *
 * Note: 256-byte commands cannot use the low-latency region. A standard
 * doorbell ring is used to commit incompatible commands.
 */
static inline void cxi_cq_ll_ring(struct cxi_cq *cq)
{
	const struct c_cmd *cmd;
	s32 cmd32_count;

	if (cq->wp32 == cq->hw_wp32)
		return;

	cmd = (struct c_cmd *)&cq->cmds32[cq->hw_wp32];
	if (cmd->cmd_size == C_CMD_SIZE_256B) {
		cxi_cq_ring(cq);
		return;
	}

	/* Align CQ to 64-byte boundary. */
	cxi_cq_update_wp(cq);

	cmd32_count = cq->wp32 - cq->hw_wp32;
	if (cmd32_count < 0)
		cmd32_count = cq->size32 - cq->hw_wp32;

	/*
	 * Identify the low-latency region to be written based on the CQ
	 * hardware write pointer alignment.
	 */
	if (cmd32_count == 2) {
		cxi_cq_ll_write64(cq);
	} else if (cq->hw_wp32 % 4) {
		cmd = (struct c_cmd *)&cq->cmds32[cq->hw_wp32];

		if (cmd->opcode == C_CMD_NOOP) {
			cmd = (struct c_cmd *)&cq->cmds32[cq->hw_wp32 + 2];

			if (cmd->cmd_size == C_CMD_SIZE_256B) {
				cxi_cq_ring(cq);
				return;
			}

			cxi_cq_ll_write128_unaligned(cq);
		} else {
			cxi_cq_ll_write64(cq);
		}
	} else {
		cxi_cq_ll_write128_aligned(cq);
	}

	/* Flush WC buffers. */
	wc_fence();

	/* Perform a doorbell ring if there are more commands ready. */
	if (cq->wp32 != cq->hw_wp32)
		cxi_cq_ring(cq);
}

/**
 * cxi_cq_align_for_cmd() - Prepare command queue for new command
 *
 * Check whether the command queue has enough space for cmd_size
 * 32-bytes blocks. For the current implementation we must ensure that
 * 1 64-bytes block (ie. 2 32 bytes blocks) is always free to avoid
 * queue wrap around. If the command doesn't align with the current
 * block, prepend one or more NoOp for padding.
 */
static inline s32 cxi_cq_align_for_cmd(struct cxi_cq *cq, enum c_cmd_size cmd_size)
{
	u32 pad_slots;
	u32 cmd_slots;

	if ((unsigned int)cmd_size >= ARRAY_SIZE(__cxi_cmd_slots) || !cq->status ||
	    cq->size32 < C_CQ_FIRST_WR_PTR_32 + 8 || cq->size32 % 8 ||
	    cq->wp32 < C_CQ_FIRST_WR_PTR_32 || cq->wp32 >= cq->size32)
		return -EINVAL;
	pad_slots = __cxi_pad_slots[cq->wp32 % 8][cmd_size];
	cmd_slots = __cxi_cmd_slots[cmd_size];

	/* Space available in the queue */
	if (__cxi_cq_free_slots(cq) < (s32)(cmd_slots + pad_slots))
		return -ENOSPC;

	if (pad_slots) {
		struct cxi_cmd32 *cmd = &cq->cmds32[cq->wp32];
		u32 i;

		for (i = 0; i < pad_slots; i++, cmd++) {
			/* Command opcode and DFA must be cleared */
			memset(cmd->pad, 0, 8);
		}

		cq->wp32 += pad_slots;
		if (cq->wp32 >= cq->size32)
			cq->wp32 = C_CQ_FIRST_WR_PTR_32;
	}

	return 0;
}

/**
 * cxi_cq_get_cqn() - Return the CQ number
 *
 * From the allocated CQ index, return its number, which ranges from 0
 * to 1023 for transmit CQs, and 0 to 511 for target CQs.
 *
 * @cq: the command queue
 */
static inline u32 cxi_cq_get_cqn(const struct cxi_cq *cq)
{
	if (cq->idx >= C_NUM_TRANSMIT_CQS)
		return cq->idx - C_NUM_TRANSMIT_CQS;
	else
		return cq->idx;
}

/**
 * cxi_cq_align_for_ct128_cmd() - Prepare command queue for new CT command
 *
 * For CT commands, the NoOp must be of type C_CMD_TYPE_CT. Commands
 * on these queues are also only 64 or 128 bytes. Only called for 128
 * bytes commands, as 64 bytes commands will never need padding.
 */
static inline s32 cxi_cq_align_for_ct128_cmd(struct cxi_cq *cq)
{
	const enum c_cmd_size cmd_size = C_CMD_SIZE_128B;
	const u32 pad_slots = __cxi_pad_slots[cq->wp32 % 8][cmd_size];
	const s32 cmd_slots = __cxi_cmd_slots[cmd_size];

	/* Space available in the queue */
	if (__cxi_cq_free_slots(cq) < (s32)(cmd_slots + pad_slots))
		return -ENOSPC;

	/* A triggger TXQ only accepts 64-byte or 128-byte commands. If padding
	 * is required for a 128-byte command, it only needs to be padded with a
	 * single 64-byte command.
	 */
	if (pad_slots) {
		struct c_cmd *cmd = (struct c_cmd *)&cq->cmds32[cq->wp32];

		/* Command opcode and DFA must be cleared */
		memset(cmd, 0, 8);
		cmd->cmd_type = C_CMD_TYPE_CT;
		cmd->cmd_size = C_CMD_SIZE_64B;
		cmd->opcode = C_CMD_CT_NOOP;

		cq->wp32 += pad_slots;
		if (cq->wp32 >= cq->size32)
			cq->wp32 = C_CQ_FIRST_WR_PTR_32;
	}

	return 0;
}

/**
 * cxi_cq_emit_cq_cmd() - Emit a NOOP or FENCE CQ command
 *
 * opcode is either C_CMD_CQ_NOOP or C_CMD_CQ_FENCE.
 */
static inline s32 __attribute__((warn_unused_result)) cxi_cq_emit_cq_cmd(struct cxi_cq *cq,
									 u32 opcode)
{
	struct c_cq_cmd *cmd;
	s32 rc;
	const enum c_cmd_size cmd_size = C_CMD_SIZE_64B;

	rc = cxi_cq_align_for_cmd(cq, cmd_size);
	if (rc)
		return rc;

	cmd = (struct c_cq_cmd *)&cq->cmds32[cq->wp32];

	/* Command opcode and DFA must be cleared */
	memset(cmd, 0, 8);
	cmd->command.cmd_type = C_CMD_TYPE_CQ;
	cmd->command.cmd_size = cmd_size;
	cmd->command.opcode = opcode;

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_emit_cq_lcid() - Emit an LCID CQ command
 *
 * The LCID command must be prepared differently than the NOOP and
 * FENCE commands; it must be 128-bytes aligned, and padded with a NOP
 * command after it.
 */
static inline s32 __attribute__((warn_unused_result)) cxi_cq_emit_cq_lcid(struct cxi_cq *cq,
									  u8 lcid)
{
	struct c_cq_cmd *cmd;
	s32 rc;
	const enum c_cmd_size cmd_size = C_CMD_SIZE_64B;

	rc = cxi_cq_align_for_cmd(cq, C_CMD_SIZE_128B);
	if (rc)
		return rc;

	cmd = (struct c_cq_cmd *)&cq->cmds32[cq->wp32];

	/* Command opcode and DFA must be cleared */
	memset(cmd, 0, 8);
	cmd->command.cmd_type = C_CMD_TYPE_CQ;
	cmd->command.cmd_size = cmd_size;
	cmd->command.opcode = C_CMD_CQ_LCID;
	cmd->lcid = lcid;

	__cxi_cq_advance_wp(cq, cmd_size);

	rc = cxi_cq_emit_cq_cmd(cq, C_CMD_CQ_NOOP);
	if (rc)
		return -ENOSPC; /* not possible */

	return 0;
}

/**
 * cxi_cq_emit_cmd() - Emit the given command.
 *
 * The command may use 1 to 4 slots. Padding will be added if needed.
 */
static inline s32 cxi_cq_emit_cmd(struct cxi_cq *cq, const union c_cmdu *cmd_in, size_t cmd_length)
{
	struct c_cmd *cmd;
	const enum c_cmd_size cmd_size = __cxi_cmd_size(cmd_length);
	s32 rc;

	rc = cxi_cq_align_for_cmd(cq, cmd_size);
	if (rc)
		return rc;

	cmd = (struct c_cmd *)&cq->cmds32[cq->wp32];
	memcpy(cmd, cmd_in, cmd_length);
	cmd->cmd_size = cmd_size;

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_emit_c_state() - Emit an IDC C_STATE command.
 *
 * the command uses 1 slot. Padding will be added if needed.
 */
static inline s32 cxi_cq_emit_c_state(struct cxi_cq *cq, const struct c_cstate_cmd *cmd_in)
{
	struct c_cstate_cmd *cmd;
	s32 rc;

	rc = cxi_cq_align_for_cmd(cq, C_CMD_SIZE_32B);
	if (rc)
		return -ENOSPC;

	cmd = (struct c_cstate_cmd *)&cq->cmds32[cq->wp32];

	*cmd = *cmd_in;

	cmd->command.cmd_type = C_CMD_TYPE_IDC;
	cmd->command.cmd_size = C_CMD_SIZE_32B; /* Always 32 bytes */
	cmd->command.opcode = C_CMD_CSTATE;
	cmd->length = sizeof(struct c_cstate_cmd);

	__cxi_cq_advance_wp(cq, C_CMD_SIZE_32B);

	return 0;
}

/**
 * cxi_cq_emit_idc_put() - Emit an IDC PUT command.
 *
 * May use 1 to 4 slots. Padding will be added if needed.
 */
static inline s32 cxi_cq_emit_idc_put(struct cxi_cq *cq, const struct c_idc_put_cmd *cmd_in,
				      const void *payload, size_t payload_length)
{
	struct c_idc_put_cmd *cmd;
	const enum c_cmd_size cmd_size = __cxi_cmd_size(16 + payload_length);
	s32 rc;

	rc = cxi_cq_align_for_cmd(cq, cmd_size);
	if (rc)
		return rc;

	cmd = (struct c_idc_put_cmd *)&cq->cmds32[cq->wp32];

	*cmd = *cmd_in;

	cmd->idc_header.command.cmd_size = cmd_size;
	cmd->idc_header.command.cmd_type = C_CMD_TYPE_IDC;
	cmd->idc_header.command.opcode = C_CMD_PUT;

	memcpy(cmd->data, payload, payload_length);

	/* account for header */
	cmd->idc_header.length = sizeof(cmd->idc_header) + payload_length;

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_emit_idc_msg() - Emit an IDC small message command.
 *
 * May use 1 to 4 slots. Padding will be added if needed.
 *
 * May return -EINVAL if payload_length is greater than
 * C_MAX_IDC_PAYLOAD_UNR
 */
static inline s32 cxi_cq_emit_idc_msg(struct cxi_cq *cq, const struct c_idc_msg_hdr *cmd_in,
				      const void *payload, size_t payload_length)
{
	struct c_idc_msg_hdr *cmd;
	enum c_cmd_size cmd_size = __cxi_cmd_size(sizeof(struct c_idc_msg_hdr) + payload_length);
	s32 rc;

	if (payload_length > C_MAX_IDC_PAYLOAD_UNR)
		return -EINVAL;
	if (cmd_size == C_CMD_SIZE_32B)
		cmd_size = C_CMD_SIZE_64B; /* Minimum size is 64B */

	rc = cxi_cq_align_for_cmd(cq, cmd_size);
	if (rc)
		return rc;

	cmd = (struct c_idc_msg_hdr *)&cq->cmds32[cq->wp32];

	*cmd = *cmd_in;

	cmd->command.cmd_size = cmd_size;
	cmd->command.cmd_type = C_CMD_TYPE_IDC;
	cmd->command.opcode = C_CMD_SMALL_MESSAGE;

	memcpy(cmd->data, payload, payload_length);

	/* account for header */
	cmd->length = sizeof(struct c_idc_msg_hdr) + payload_length;

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_emit_idc_eth() - Emit an IDC Ethernet command.
 *
 * May use 1 to 4 slots. Padding will be added if needed.
 */
static inline s32 cxi_cq_emit_idc_eth(struct cxi_cq *cq, const struct c_idc_eth_cmd *cmd_in,
				      const void *payload, size_t payload_length)
{
	struct c_idc_eth_cmd *cmd;
	const u64 len = sizeof(struct c_idc_eth_cmd) + payload_length;
	const enum c_cmd_size cmd_size = __cxi_cmd_size(len);
	s32 rc;

	rc = cxi_cq_align_for_cmd(cq, cmd_size);
	if (rc)
		return rc;

	cmd = (struct c_idc_eth_cmd *)&cq->cmds32[cq->wp32];

	*cmd = *cmd_in;

	cmd->command.cmd_size = cmd_size;
	cmd->command.cmd_type = C_CMD_TYPE_IDC;
	cmd->command.opcode = C_CMD_ETHERNET_TX;

	memcpy(cmd->data, payload, payload_length);

	cmd->length = len;

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_emit_idc_amo() - Emit an IDC AMO command.
 *
 * If possible, emit the AMO with a small_amo request.
 */
static inline s32 cxi_cq_emit_idc_amo(struct cxi_cq *cq, const struct c_idc_amo_cmd *cmd_in,
				      bool fetching)
{
	s32 rc;
	enum c_cmd_size cmd_size;

	if (cmd_in->atomic_type == C_AMO_TYPE_DOUBLE_COMPLEX_T ||
	    cmd_in->atomic_op == C_AMO_OP_CSWAP || cmd_in->atomic_op == C_AMO_OP_AXOR || fetching) {
		struct c_idc_amo_cmd *cmd;

		cmd_size = C_CMD_SIZE_64B;

		rc = cxi_cq_align_for_cmd(cq, cmd_size);
		if (rc)
			return rc;

		cmd = (struct c_idc_amo_cmd *)&cq->cmds32[cq->wp32];

		*cmd = *cmd_in;

		cmd->idc_header.command.cmd_size = cmd_size;
		cmd->idc_header.command.cmd_type = C_CMD_TYPE_IDC;
		cmd->idc_header.command.opcode = fetching ? C_CMD_FETCHING_ATOMIC : C_CMD_ATOMIC;

		/* Large AMOs always have a length of 64 bytes. */
		cmd->idc_header.length = sizeof(*cmd);
	} else {
		struct c_idc_put_cmd *cmd;
		struct c_small_amo_payload *payload;

		cmd_size = C_CMD_SIZE_32B;

		rc = cxi_cq_align_for_cmd(cq, cmd_size);
		if (rc)
			return rc;

		cmd = (struct c_idc_put_cmd *)&cq->cmds32[cq->wp32];
		payload = (struct c_small_amo_payload *)cmd->data;

		cmd->idc_header = cmd_in->idc_header;

		cmd->idc_header.command.cmd_size = cmd_size;
		cmd->idc_header.command.cmd_type = C_CMD_TYPE_IDC;
		cmd->idc_header.command.opcode = C_CMD_ATOMIC;

		/* Small AMOs always have a length of 32 bytes. */
		cmd->idc_header.length = 32;

		payload->amo_op = cmd_in->atomic_op;
		payload->amo_type = cmd_in->atomic_type;
		payload->op1_word1 = cmd_in->op1_word1;
	}

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_emit_dma_amo() - Emit a DMA AMO command.
 *
 * Uses 2 slots. Padding will be added if needed.
 */
static inline s32 cxi_cq_emit_dma_amo(struct cxi_cq *cq, struct c_dma_amo_cmd *cmd_in,
				      bool fetching)
{
	struct c_dma_amo_cmd *cmd;
	const enum c_cmd_size cmd_size = C_CMD_SIZE_128B;
	s32 rc;

	rc = cxi_cq_align_for_cmd(cq, cmd_size);
	if (rc)
		return rc;

	cmd = (struct c_dma_amo_cmd *)&cq->cmds32[cq->wp32];

	*cmd = *cmd_in;

	cmd->command.cmd_size = cmd_size;
	cmd->command.cmd_type = C_CMD_TYPE_DMA;
	cmd->command.opcode = fetching ? C_CMD_FETCHING_ATOMIC : C_CMD_ATOMIC;
	cmd->request_len = amo_size[cmd->atomic_type];

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_emit_dma_eth() - Emit a DMA ethernet command.
 */
static inline s32 cxi_cq_emit_dma_eth(struct cxi_cq *cq, const struct c_dma_eth_cmd *cmd_in)
{
	const enum c_cmd_size cmd_size = C_CMD_SIZE_128B;
	struct c_dma_eth_cmd *cmd;
	u32 total_len = 0;
	s32 rc;
	s32 i;

	rc = cxi_cq_align_for_cmd(cq, cmd_size);
	if (rc)
		return rc;

	cmd = (struct c_dma_eth_cmd *)&cq->cmds32[cq->wp32];

	*cmd = *cmd_in;

	cmd->command.cmd_type = C_CMD_TYPE_DMA;
	cmd->command.cmd_size = cmd_size;
	cmd->command.opcode = C_CMD_ETHERNET_TX;

	for (i = 0; i < cmd_in->num_segments; i++)
		total_len += cmd_in->len[i];
	cmd->total_len = total_len;

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_emit_dma() - Emit a non restricted DMA command.
 */
static inline s32 cxi_cq_emit_dma(struct cxi_cq *cq, struct c_full_dma_cmd *cmd_in)
{
	struct c_full_dma_cmd *cmd;
	s32 rc;
	const enum c_cmd_size cmd_size = C_CMD_SIZE_64B;

	rc = cxi_cq_align_for_cmd(cq, cmd_size);
	if (rc)
		return rc;

	cmd = (struct c_full_dma_cmd *)&cq->cmds32[cq->wp32];

	*cmd = *cmd_in;

	cmd->command.cmd_type = C_CMD_TYPE_DMA;
	cmd->command.cmd_size = cmd_size;

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_emit_nomatch_dma() - Emit a non-matching DMA command.
 *
 * This command is used to target a non-matching PtlTE where remote target
 * events are not needed (restricted send option bit is always set). Valid
 * command operations are CMD_NOMATCH_GET and CMD_NOMATCH_PUT.
 *
 * Note: With this command, only errors will be generated on the EQ. Use
 * cxi_cq_emit_dma() with the restricted bit set if per transaction success
 * events are needed.
 */
static inline s32 cxi_cq_emit_nomatch_dma(struct cxi_cq *cq, struct c_nomatch_dma_cmd *cmd_in)
{
	struct c_nomatch_dma_cmd *cmd;
	s32 rc;
	const enum c_cmd_size cmd_size = C_CMD_SIZE_32B;

	rc = cxi_cq_align_for_cmd(cq, cmd_size);
	if (rc)
		return rc;

	cmd = (struct c_nomatch_dma_cmd *)&cq->cmds32[cq->wp32];

	*cmd = *cmd_in;

	cmd->command.cmd_type = C_CMD_TYPE_DMA;
	cmd->command.cmd_size = cmd_size;
	cmd->restricted = 1;

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_emit_target() - Emit a target command.
 *
 * All the target commands (c_target_cmd and c_set_state) are 64
 * bytes.
 */
static inline s32 cxi_cq_emit_target(struct cxi_cq *cq, const void *cmd_in)
{
	const enum c_cmd_size cmd_size = C_CMD_SIZE_64B;
	struct c_target_cmd *cmd;

	/* Space available in the queue */
	if (__cxi_cq_free_slots(cq) < (int)__cxi_cmd_slots[cmd_size])
		return -ENOSPC;

	cmd = (struct c_target_cmd *)&cq->cmds32[cq->wp32];

	memcpy(cmd, cmd_in, sizeof(*cmd));

	cmd->command.cmd_type = C_CMD_TYPE_CQ;
	cmd->command.cmd_size = cmd_size;

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_emit_ct() - Emit a counting event (CT) command without embedded data.
 *
 * This function can also be used for trigger event, trigger inc, and trigger
 * set.
 */
static inline s32 cxi_cq_emit_ct(struct cxi_cq *cq, u32 opcode, const struct c_ct_cmd *cmd_in)
{
	const enum c_cmd_size cmd_size = C_CMD_SIZE_64B;
	struct c_ct_cmd *cmd;

	/* Space available in the queue */
	if (__cxi_cq_free_slots(cq) < (int)__cxi_cmd_slots[cmd_size])
		return -ENOSPC;

	cmd = (struct c_ct_cmd *)&cq->cmds32[cq->wp32];

	*cmd = *cmd_in;

	cmd->command.cmd_type = C_CMD_TYPE_CT;
	cmd->command.cmd_size = cmd_size;
	cmd->command.opcode = opcode;

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_emit_trig_full_dma() - Emit a triggered full DMA command.
 *
 * Trigger command with embedded data is always 128 bytes.
 */
static inline s32 cxi_cq_emit_trig_full_dma(struct cxi_cq *cq, const struct c_ct_cmd *cmd_in,
					    const struct c_full_dma_cmd *dma_in)
{
	const enum c_cmd_size cmd_size = C_CMD_SIZE_128B;
	struct c_ct_cmd *cmd;
	struct c_full_dma_cmd *dma;
	s32 rc;

	rc = cxi_cq_align_for_ct128_cmd(cq);
	if (rc)
		return rc;

	cmd = (struct c_ct_cmd *)&cq->cmds32[cq->wp32];
	dma = (struct c_full_dma_cmd *)cmd->embedded_dma;

	*cmd = *cmd_in;
	*dma = *dma_in;

	cmd->command.cmd_type = C_CMD_TYPE_CT;
	cmd->command.cmd_size = cmd_size;
	cmd->command.opcode = C_CMD_CT_TRIG_DMA;

	dma->command.cmd_type = C_CMD_TYPE_DMA;
	dma->command.cmd_size = C_CMD_SIZE_64B;

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_emit_trig_nomatch_dma() - Emit a triggered nomatch DMA command.
 *
 * Trigger command with embedded data is always 128 bytes.
 */
static inline s32 cxi_cq_emit_trig_nomatch_dma(struct cxi_cq *cq, const struct c_ct_cmd *cmd_in,
					       const struct c_nomatch_dma_cmd *dma_in)
{
	const enum c_cmd_size cmd_size = C_CMD_SIZE_128B;
	struct c_ct_cmd *cmd;
	struct c_nomatch_dma_cmd *dma;
	s32 rc;

	rc = cxi_cq_align_for_ct128_cmd(cq);
	if (rc)
		return rc;

	cmd = (struct c_ct_cmd *)&cq->cmds32[cq->wp32];
	dma = (struct c_nomatch_dma_cmd *)cmd->embedded_dma;

	*cmd = *cmd_in;
	*dma = *dma_in;

	cmd->command.cmd_type = C_CMD_TYPE_CT;
	cmd->command.cmd_size = cmd_size;
	cmd->command.opcode = C_CMD_CT_TRIG_DMA;

	dma->command.cmd_type = C_CMD_TYPE_DMA;
	dma->command.cmd_size = C_CMD_SIZE_32B;
	dma->restricted = 1;

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_emit_trig_dma_amo() Emit a triggered DMA AMO command.
 *
 * Trigger command with embedded data is always 128 bytes.
 */
static inline s32 cxi_cq_emit_trig_dma_amo(struct cxi_cq *cq, const struct c_ct_cmd *cmd_in,
					   const struct c_dma_amo_cmd *amo_in, bool fetching)
{
	const enum c_cmd_size cmd_size = C_CMD_SIZE_128B;
	struct c_ct_cmd *cmd;
	struct c_dma_amo_cmd *amo;
	s32 rc;

	rc = cxi_cq_align_for_ct128_cmd(cq);
	if (rc)
		return rc;

	cmd = (struct c_ct_cmd *)&cq->cmds32[cq->wp32];
	amo = (struct c_dma_amo_cmd *)cmd->embedded_dma;

	*cmd = *cmd_in;
	*amo = *amo_in;

	cmd->command.cmd_type = C_CMD_TYPE_CT;
	cmd->command.cmd_size = cmd_size;
	cmd->command.opcode = C_CMD_CT_TRIG_DMA;

	amo->command.cmd_type = C_CMD_TYPE_DMA;
	amo->command.cmd_size = C_CMD_SIZE_128B;
	amo->command.opcode = fetching ? C_CMD_FETCHING_ATOMIC : C_CMD_ATOMIC;
	amo->request_len = amo_size[amo->atomic_type];

	__cxi_cq_advance_wp(cq, cmd_size);

	return 0;
}

/**
 * cxi_cq_init() - Initialize a command queue
 * @cq: The command queue
 * @cmds: The commands memory
 * @count: Count (size) of command queue
 * @launch_addr: The CQ launch address
 * @cqn: Command queue number
 */
static inline void cxi_cq_init(struct cxi_cq *cq, struct cxi_cmd64 *cmds, u32 count,
			       void *launch_addr, u32 idx)
{
	struct c_cmdq *la = (struct c_cmdq *)launch_addr;

	cq->size = count;
	cq->size32 = 2 * count;
	cq->wp32 = C_CQ_FIRST_WR_PTR_32;
	cq->hw_wp32 = cq->wp32;
	cq->rp32 = cq->wp32;

	/* Setting status pointer sets the commands pointer. */
	if (cmds) {
		cq->status = (struct c_cq_status *)&cmds[0];
		cq->status->rd_ptr = C_CQ_FIRST_WR_PTR;
		cq->status->return_code = C_RC_OK;
	}

	if (launch_addr) {
		cq->wp_addr = (u64 *)launch_addr;
		cq->ll_64 = (u8 *)la->ll_wr64a0123;
		cq->ll_128a = (u8 *)la->ll_wr128a02;
		cq->ll_128u = (u8 *)la->ll_wr128a13;
	}
	cq->idx = idx;
}

/**
 * cxi_eq_empty() - Check if event queue is empty
 */
static inline bool cxi_eq_empty(struct cxi_eq *eq)
{
	u32 rd_offset = eq->rd_offset;
	const union c_event *event = (union c_event *)(eq->events + rd_offset);

	if (event->hdr.event_size == C_EVENT_SIZE_NO_EVENT)
		return true;
	else
		return false;
}

/**
 * cxi_eq_peek_event() - Get the next event on an event queue without advancing
 *                       the software read pointer.
 *
 * Returns a pointer in the event queue.
 */
static inline const union c_event *cxi_eq_peek_event(struct cxi_eq *eq)
{
	u32 rd_offset = eq->rd_offset;
	const volatile union c_event *event;
	s32 rc_offset;

again:
	event = (union c_event *)(eq->events + rd_offset);

	/* No event */
	if (event->hdr.event_size == C_EVENT_SIZE_NO_EVENT)
		return NULL;

	/* Ensure the event has fully arrived by checking the return
	 * code is not C_RC_NO_EVENT (0). The return_code is 6 bits in
	 * the last byte of the event (so either offset 15, 31 or
	 * 63).
	 */
	rc_offset = (8 << event->hdr.event_size) - 1;
	if (((((u8 *)event)[rc_offset]) & 0x3f) == C_RC_NO_EVENT)
		return NULL;

	if (event->hdr.event_type == C_EVENT_NULL_EVENT) {
		/* Consume the event and move to the next one */
		rd_offset += (8 << event->hdr.event_size);
		if (rd_offset >= eq->byte_size)
			rd_offset = C_EE_CFG_ECB_SIZE;
		eq->rd_offset = rd_offset;

		goto again;
	}

	return (const union c_event *)event;
}

/**
 * cxi_eq_next_event() - Advance the event queue to the next event.
 */
static inline void cxi_eq_next_event(struct cxi_eq *eq)
{
	const union c_event *event;
	u32 rd_offset = eq->rd_offset;

	event = (union c_event *)(eq->events + rd_offset);
	rd_offset = eq->rd_offset + (8 << event->hdr.event_size);
	if (rd_offset >= eq->byte_size)
		rd_offset = C_EE_CFG_ECB_SIZE;
	eq->rd_offset = rd_offset;
}

/**
 * cxi_eq_get_event() - Get the next event on an event queue.
 *
 * Returns a pointer in the event queue. The event must be processed
 * before calling cxi_eq_ack_events().
 */
static inline const union c_event *cxi_eq_get_event(struct cxi_eq *eq)
{
	const union c_event *event;

	event = cxi_eq_peek_event(eq);
	if (!event)
		return NULL;

	cxi_eq_next_event(eq);

	return event;
}

/**
 * cxi_eq_move_rp() - Move the EQ read pointer
 * @eq: The EQ to have read pointer moved.
 *
 * There should be no need to call this function. Use cxi_eq_ack_events().
 *
 * Return: Updated read pointer
 */
static inline u64 cxi_eq_move_rp(struct cxi_eq *eq)
{
	u32 rd_offset = eq->rd_offset;
	u32 prev_rd_offset = eq->prev_rd_offset;
	u64 rd_ptr = rd_offset / C_EE_CFG_ECB_SIZE;
	u8 *p = &eq->events[prev_rd_offset];

	if (prev_rd_offset < rd_offset) {
		memset(p, 0, rd_offset - prev_rd_offset);
	} else if (prev_rd_offset > rd_offset) {
		memset(p, 0, eq->byte_size - prev_rd_offset);
		memset(eq->events + C_EE_CFG_ECB_SIZE, 0, rd_offset - C_EE_CFG_ECB_SIZE);
	}
	eq->prev_rd_offset = rd_offset;

	return rd_ptr;
}

/**
 * cxi_eq_ack_events() - Acknowledge consumed events in the event queue
 *
 * All events returned through cxi_eq_get_event() are cleared and the
 * producer read pointer is advanced. These events must therefore be
 * processed before calling this function.
 *
 * An application doesn't need to call this function after each event;
 * it may process several events before.
 */
static inline void cxi_eq_ack_events(struct cxi_eq *eq)
{
	eq->sw_state.rd_ptr = cxi_eq_move_rp(eq);

	*eq->sw_state_addr = eq->sw_state.qw;
}

/**
 * cxi_eq_get_status() - Query for an event queue status update.
 *
 * Cassini updates event queue status when:
 *
 * -The number of free 64-byte events slots remaining in the queue crosses a
 *  software configured threshold.
 * -An event is dropped due to the event queue being full.
 *
 * Status fields of interest to providers are:
 * -thld_sts: Asserted if the update was due to a fill threshold being crossed.
 * -thld_id: Indicates the ID of the fill level threshold crossed (if thld_sts
 *           is asserted).
 * -unackd_dropped_event: Indicates that one or more events have been dropped
 *                        since the last status update.
 * -event_slots_free: The number of 64-byte event slots that were unused in the
 *                    event queue buffer when the event queue status was updated.
 * -timestamp_ns: The nanoseconds field of the real-time when the event queue
 *                status was last updated.
 * -timestamp_sec: The seconds field of the real-time when the event queue
 *                 status was last updated.
 *
 * @eq: The event queue to query.
 * @status: On success, contains a copy of the status update.
 *
 * Returns non-zero if a new event queue status update is available.
 */
static inline s32 cxi_eq_get_status(struct cxi_eq *eq, struct c_eq_status *status)
{
	struct c_eq_status status_cpy;
	s32 tries = 100;

	/* Fast path: return 0 if the last status looks old. */
	if (eq->last_ts_ns == eq->status->timestamp_ns_cpy &&
	    eq->last_ts_sec == eq->status->timestamp_sec_cpy)
		return 0;

	/* Read the entire status update. A status update may not be written
	 * atomically on all architectures.  Re-read the full status until a
	 * valid update is read.
	 */
	do {
		memcpy(&status_cpy, eq->status, sizeof(status_cpy));

		if (status_cpy.timestamp_ns == status_cpy.timestamp_ns_cpy &&
		    status_cpy.timestamp_sec == status_cpy.timestamp_sec_cpy)
			break;
	} while (--tries);

	/* Return 0 if a full status update was unavailable. */
	if (!tries)
		return 0;

	/* Keep a record that we read this status update in software and return
	 * the update.
	 */
	eq->last_ts_sec = status_cpy.timestamp_sec;
	eq->last_ts_ns = status_cpy.timestamp_ns;

	*status = status_cpy;
	return 1;
}

/**
 * cxi_eq_status_fill_level() - Return status update fill level.
 *
 * @eq: The EQ which generated the status update.
 * @status: Pointer to a status update.
 *
 * Returns the fill level (as a percentage) reported by the provided status
 * update. Valid only if status->thld_sts is set.
 */
static inline u32 cxi_eq_status_fill_level(struct cxi_eq *eq, struct c_eq_status *status)
{
	return 100 - status->event_slots_free * 100 / (eq->byte_size / C_EE_CFG_ECB_SIZE);
}

/**
 * cxi_eq_get_drops() - Return non-zero if new events have been dropped.
 *
 * When there is insufficient space in the EQ for events to be delivered, new
 * events are dropped. In this case the NIC performs an EQ status write-back
 * indicating events were dropped. All subsequent status write-backs will
 * indicate that events were dropped until drops are acknowledged.
 *
 * After observing that events were dropped, a user should recover space in the
 * EQ and then acknowledge the dropped events using cxi_eq_ack_drops(). After
 * this call, subsequent EQ status write-backs will not indicate that events
 * were dropped until new events are dropped.
 */
static inline s32 cxi_eq_get_drops(struct cxi_eq *eq)
{
	return eq->status->unackd_dropped_event;
}

/**
 * cxi_eq_ack_drops() - Acknowledge dropped events in the event queue
 */
static inline void cxi_eq_ack_drops(struct cxi_eq *eq)
{
	eq->status->unackd_dropped_event = 0;
	eq->sw_state.event_drop_seq_no = eq->status->event_drop_seq_no;
	cxi_eq_ack_events(eq);
}

/**
 * cxi_eq_int_enable() - Unmask EQ event interrupts
 */
static inline void cxi_eq_int_enable(struct cxi_eq *eq)
{
	eq->sw_state.event_int_disable = 0;
	cxi_eq_ack_events(eq);
}

/**
 * cxi_eq_int_disable() - Mask EQ event interrupts
 */
static inline void cxi_eq_int_disable(struct cxi_eq *eq)
{
	eq->sw_state.event_int_disable = 1;
	cxi_eq_ack_events(eq);
}

/**
 * cxi_eq_sts_int_enable() - Unmask EQ status update interrupts
 */
static inline void cxi_eq_sts_int_enable(struct cxi_eq *eq)
{
	eq->sw_state.eq_sts_int_disable = 0;
	cxi_eq_ack_events(eq);
}

/**
 * cxi_eq_sts_int_disable() - Mask EQ status update interrupts
 */
static inline void cxi_eq_sts_int_disable(struct cxi_eq *eq)
{
	eq->sw_state.eq_sts_int_disable = 1;
	cxi_eq_ack_events(eq);
}

/**
 * cxi_eq_init() - Initialize an event queue
 * @eq: The event queue to initialize
 * @events: The events buffer
 * @size: Size in bytes of the events buffer
 * @eqn: The EQ number to use in commands
 * @sw_state_addr: Software state CSR address
 */
static inline void cxi_eq_init(struct cxi_eq *eq, u8 *events, u32 size, u32 eqn, u64 *sw_state_addr)
{
	eq->events = events;
	eq->rd_offset = C_EE_CFG_ECB_SIZE;
	eq->prev_rd_offset = C_EE_CFG_ECB_SIZE;
	eq->byte_size = size;
	eq->sw_state_addr = sw_state_addr;
	eq->eqn = eqn;
}

#define CXI_MASK(n) ((1 << (n)) - 1)

#define CXI_MCAST_FA_FORMAT 0x1ff
#define CXI_MCAST_FA_ACTION 0x7
#define CXI_DFA_EP_WIDTH 12
#define CXI_DFA_EXT_WIDTH 5
#define CXI_EP_WIDTH (CXI_DFA_EP_WIDTH + CXI_DFA_EXT_WIDTH)
#define CXI_DFA_EP_MASK CXI_MASK(CXI_DFA_EP_WIDTH)
#define CXI_DFA_EXT_MASK CXI_MASK(CXI_DFA_EXT_WIDTH)

/**
 * cxi_build_dfa_ep() - Build 12 bit DFA EP Index.
 * @pid: The DFA PID value.
 * @pid_width: The DFA PID width.
 * @idx: The DFA PTE index.
 */
static inline u32 cxi_build_dfa_ep(u32 pid, u32 pid_width, u32 idx)
{
	return ((idx >> CXI_DFA_EXT_WIDTH) << pid_width) + pid;
}

/**
 * cxi_build_dfa_ext() - Return 5 bit DFA extension.
 * @idx: The DFA PTE index.
 */
static inline u32 cxi_build_dfa_ext(u32 idx)
{
	return idx & CXI_DFA_EXT_MASK;
}

/**
 * cxi_dfa_ep() - Return 12 bit DFA EP.
 * @dfa: The DFA to parse.
 */
static inline u32 cxi_dfa_ep(u32 dfa)
{
	return dfa & CXI_DFA_EP_MASK;
}

/**
 * cxi_dfa_pid() - Return variable width DFA PID.
 * @dfa: The DFA to parse.
 */
static inline u32 cxi_dfa_pid(u32 dfa, u32 pid_width)
{
	return dfa & CXI_MASK(pid_width);
}

/**
 * cxi_dfa_nid() - Return 20 bit DFA NID.
 * @dfa: The DFA to parse.
 */
static inline u32 cxi_dfa_nid(u32 dfa)
{
	return dfa >> CXI_DFA_EP_WIDTH;
}

/**
 * cxi_dfa_to_init() - Convert 32 bit DFA to initiator ID.
 * @dfa: The DFA to convert.
 * @pid_width: The DFA PID width.
 */
static inline u32 cxi_dfa_to_init(u32 dfa, u32 pid_width)
{
	return CXI_MATCH_ID(pid_width, cxi_dfa_pid(dfa, pid_width), cxi_dfa_nid(dfa));
}

/**
 * cxi_build_dfa() - Build a destination fabric address
 * @nic_addr: Destination NIC address
 * @pid: VNI partition
 * @pid_granule: VNI partition granule
 * @idx: Index into the VNI partition
 * @dfa: Destination fabric address to be set
 * @dfa_ext: DFA extension to be set
 */
static inline void cxi_build_dfa(u32 nic_addr, u32 pid, u32 pid_width, u32 idx,
				 union c_fab_addr *dfa, u8 *dfa_ext)
{
	dfa->unicast.nid = nic_addr;
	dfa->unicast.endpoint_defined = cxi_build_dfa_ep(pid, pid_width, idx);
	*dfa_ext = cxi_build_dfa_ext(idx);
}

/**
 * cxi_build_mcast_dfa() - Build a destination multicast fabric address
 *
 * @mcast_id: Destination multicast address
 * @red_id: Reduction ID value
 * @idx_ext: Multicast index extension
 * @dfa: Destination fabric address to be set
 * @dfa_ext: DFA extension to be set
 */
static inline void cxi_build_mcast_dfa(u32 mcast_id, u32 red_id, u32 idx_ext, union c_fab_addr *dfa,
				       u8 *dfa_ext)
{
	memset(dfa, 0, sizeof(*dfa));
	dfa->multicast.format = CXI_MCAST_FA_FORMAT;
	dfa->multicast.reduction_id = red_id;
	dfa->multicast.multicast_id = mcast_id;
	dfa->multicast.action = CXI_MCAST_FA_ACTION;

	*dfa_ext = cxi_build_dfa_ext(idx_ext);
}

/**
 * cxi_ct_init() - Initialize a counter
 * @ct: Counter to initialize
 * @wb: Writeback buffer
 * @doorbell_addr: Doorbell address
 */
static inline void cxi_ct_init(struct cxi_ct *ct, struct c_ct_writeback *wb, u32 ctn,
			       u64 *doorbell_addr)
{
	ct->wb = wb;
	ct->ctn = ctn;
	ct->doorbell = doorbell_addr;
}

/**
 * cxi_ct_inc_success() - Increment counter success value
 * @ct: Counter
 * @value: Value
 *
 * Note: Value is constrained to 48 bits.
 */
static inline void cxi_ct_inc_success(struct cxi_ct *ct, u64 value)
{
	ct->doorbell[CT_INC_SUCCESS_OFFSET / sizeof(u64)] = value & CT_SUCCESS_MASK;
}

/**
 * cxi_ct_inc_failure() - Increment counter failure value
 * @ct: Counter
 * @value: Value
 *
 * Note: Value is constrained to 7 bits.
 */
static inline void cxi_ct_inc_failure(struct cxi_ct *ct, u8 value)
{
	ct->doorbell[CT_INC_FAILURE_OFFSET / sizeof(u64)] = value & CT_FAILURE_MASK;
}

/**
 * cxi_ct_reset_success() - Reset success counter to zero.
 * @ct: Counting event to be reset.
 */
static inline void cxi_ct_reset_success(struct cxi_ct *ct)
{
	ct->doorbell[CT_RESET_SUCCESS_OFFSET / sizeof(u64)] = 0;
}

/**
 * cxi_ct_reset_failure() - Reset failure counter to zero.
 * @ct: Counting event to be reset.
 */
static inline void cxi_ct_reset_failure(struct cxi_ct *ct)
{
	ct->doorbell[CT_RESET_FAILURE_OFFSET / sizeof(u64)] = 0;
}

#endif /* __CXI_PROV_HW */
