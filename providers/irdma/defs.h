/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2021 Intel Corporation */
#ifndef IRDMA_DEFS_H
#define IRDMA_DEFS_H

#include "osdep.h"


#define IRDMA_QP_TYPE_IWARP	1
#define IRDMA_QP_TYPE_UDA	2
#define IRDMA_QP_TYPE_ROCE_RC	3
#define IRDMA_QP_TYPE_ROCE_UD	4

#define IRDMA_HW_PAGE_SIZE	4096
#define IRDMA_HW_PAGE_SHIFT	12
#define IRDMA_CQE_QTYPE_RQ	0
#define IRDMA_CQE_QTYPE_SQ	1

#define IRDMA_QP_SW_MIN_WQSIZE	8u /* in WRs*/
#define IRDMA_QP_WQE_MIN_SIZE	32
#define IRDMA_QP_WQE_MAX_SIZE	256
#define IRDMA_QP_WQE_MIN_QUANTA 1
#define IRDMA_MAX_RQ_WQE_SHIFT_GEN1 2
#define IRDMA_MAX_RQ_WQE_SHIFT_GEN2 3

#define IRDMA_SQ_RSVD	258
#define IRDMA_RQ_RSVD	1

#define IRDMA_FEATURE_RTS_AE			1ULL
#define IRDMA_FEATURE_CQ_RESIZE			2ULL
#define IRDMAQP_OP_RDMA_WRITE			0x00
#define IRDMAQP_OP_RDMA_READ			0x01
#define IRDMAQP_OP_RDMA_SEND			0x03
#define IRDMAQP_OP_RDMA_SEND_INV		0x04
#define IRDMAQP_OP_RDMA_SEND_SOL_EVENT		0x05
#define IRDMAQP_OP_RDMA_SEND_SOL_EVENT_INV	0x06
#define IRDMAQP_OP_BIND_MW			0x08
#define IRDMAQP_OP_FAST_REGISTER		0x09
#define IRDMAQP_OP_LOCAL_INVALIDATE		0x0a
#define IRDMAQP_OP_RDMA_READ_LOC_INV		0x0b
#define IRDMAQP_OP_NOP				0x0c

#define IRDMA_CQPHC_QPCTX GENMASK_ULL(63, 0)
#define IRDMA_QP_DBSA_HW_SQ_TAIL GENMASK_ULL(14, 0)
#define IRDMA_CQ_DBSA_CQEIDX GENMASK_ULL(19, 0)
#define IRDMA_CQ_DBSA_SW_CQ_SELECT GENMASK_ULL(13, 0)
#define IRDMA_CQ_DBSA_ARM_NEXT BIT_ULL(14)
#define IRDMA_CQ_DBSA_ARM_NEXT_SE BIT_ULL(15)
#define IRDMA_CQ_DBSA_ARM_SEQ_NUM GENMASK_ULL(17, 16)

/* CQP and iWARP Completion Queue */
#define IRDMA_CQ_QPCTX IRDMA_CQPHC_QPCTX

#define IRDMA_CQ_MINERR GENMASK_ULL(15, 0)
#define IRDMA_CQ_MAJERR GENMASK_ULL(31, 16)
#define IRDMA_CQ_WQEIDX GENMASK_ULL(46, 32)
#define IRDMA_CQ_EXTCQE BIT_ULL(50)
#define IRDMA_OOO_CMPL BIT_ULL(54)
#define IRDMA_CQ_ERROR BIT_ULL(55)
#define IRDMA_CQ_SQ BIT_ULL(62)

#define IRDMA_CQ_VALID BIT_ULL(63)
#define IRDMA_CQ_IMMVALID BIT_ULL(62)
#define IRDMA_CQ_UDSMACVALID BIT_ULL(61)
#define IRDMA_CQ_UDVLANVALID BIT_ULL(60)
#define IRDMA_CQ_UDSMAC GENMASK_ULL(47, 0)
#define IRDMA_CQ_UDVLAN GENMASK_ULL(63, 48)

#define IRDMA_CQ_IMMDATA_S 0
#define IRDMA_CQ_IMMDATA_M (0xffffffffffffffffULL << IRDMA_CQ_IMMVALID_S)
#define IRDMA_CQ_IMMDATALOW32 GENMASK_ULL(31, 0)
#define IRDMA_CQ_IMMDATAUP32 GENMASK_ULL(63, 32)
#define IRDMACQ_PAYLDLEN GENMASK_ULL(31, 0)
#define IRDMACQ_TCPSEQNUMRTT GENMASK_ULL(63, 32)
#define IRDMACQ_INVSTAG GENMASK_ULL(31, 0)
#define IRDMACQ_QPID GENMASK_ULL(55, 32)

#define IRDMACQ_UDSRCQPN GENMASK_ULL(31, 0)
#define IRDMACQ_PSHDROP BIT_ULL(51)
#define IRDMACQ_STAG BIT_ULL(53)
#define IRDMACQ_IPV4 BIT_ULL(53)
#define IRDMACQ_SOEVENT BIT_ULL(54)
#define IRDMACQ_OP GENMASK_ULL(61, 56)

/* Manage Push Page - MPP */
#define IRDMA_INVALID_PUSH_PAGE_INDEX_GEN_1 0xffff
#define IRDMA_INVALID_PUSH_PAGE_INDEX 0xffffffff

#define IRDMAQPSQ_OPCODE GENMASK_ULL(37, 32)
#define IRDMAQPSQ_COPY_HOST_PBL BIT_ULL(43)
#define IRDMAQPSQ_ADDFRAGCNT GENMASK_ULL(41, 38)
#define IRDMAQPSQ_PUSHWQE BIT_ULL(56)
#define IRDMAQPSQ_STREAMMODE BIT_ULL(58)
#define IRDMAQPSQ_WAITFORRCVPDU BIT_ULL(59)
#define IRDMAQPSQ_READFENCE BIT_ULL(60)
#define IRDMAQPSQ_LOCALFENCE BIT_ULL(61)
#define IRDMAQPSQ_UDPHEADER BIT_ULL(61)
#define IRDMAQPSQ_L4LEN GENMASK_ULL(45, 42)
#define IRDMAQPSQ_SIGCOMPL BIT_ULL(62)
#define IRDMAQPSQ_VALID BIT_ULL(63)

#define IRDMAQPSQ_FRAG_TO IRDMA_CQPHC_QPCTX
#define IRDMAQPSQ_FRAG_VALID BIT_ULL(63)
#define IRDMAQPSQ_FRAG_LEN GENMASK_ULL(62, 32)
#define IRDMAQPSQ_FRAG_STAG GENMASK_ULL(31, 0)
#define IRDMAQPSQ_GEN1_FRAG_LEN GENMASK_ULL(31, 0)
#define IRDMAQPSQ_GEN1_FRAG_STAG GENMASK_ULL(63, 32)
#define IRDMAQPSQ_REMSTAGINV GENMASK_ULL(31, 0)
#define IRDMAQPSQ_DESTQKEY GENMASK_ULL(31, 0)
#define IRDMAQPSQ_DESTQPN GENMASK_ULL(55, 32)
#define IRDMAQPSQ_AHID GENMASK_ULL(16, 0)
#define IRDMAQPSQ_INLINEDATAFLAG BIT_ULL(57)

#define IRDMA_INLINE_VALID_S 7
#define IRDMAQPSQ_INLINEDATALEN GENMASK_ULL(55, 48)
#define IRDMAQPSQ_IMMDATAFLAG BIT_ULL(47)
#define IRDMAQPSQ_REPORTRTT BIT_ULL(46)

#define IRDMAQPSQ_IMMDATA GENMASK_ULL(63, 0)
#define IRDMAQPSQ_REMSTAG GENMASK_ULL(31, 0)

#define IRDMAQPSQ_REMTO IRDMA_CQPHC_QPCTX

#define IRDMAQPSQ_STAGRIGHTS GENMASK_ULL(52, 48)
#define IRDMAQPSQ_VABASEDTO BIT_ULL(53)
#define IRDMAQPSQ_MEMWINDOWTYPE BIT_ULL(54)

#define IRDMAQPSQ_MWLEN IRDMA_CQPHC_QPCTX
#define IRDMAQPSQ_PARENTMRSTAG GENMASK_ULL(63, 32)
#define IRDMAQPSQ_MWSTAG GENMASK_ULL(31, 0)

#define IRDMAQPSQ_BASEVA_TO_FBO IRDMA_CQPHC_QPCTX

#define IRDMAQPSQ_LOCSTAG GENMASK_ULL(31, 0)

/* iwarp QP RQ WQE common fields */
#define IRDMAQPRQ_ADDFRAGCNT IRDMAQPSQ_ADDFRAGCNT
#define IRDMAQPRQ_VALID IRDMAQPSQ_VALID
#define IRDMAQPRQ_COMPLCTX IRDMA_CQPHC_QPCTX
#define IRDMAQPRQ_FRAG_LEN IRDMAQPSQ_FRAG_LEN
#define IRDMAQPRQ_STAG IRDMAQPSQ_FRAG_STAG
#define IRDMAQPRQ_TO IRDMAQPSQ_FRAG_TO

#define IRDMAPFINT_OICR_HMC_ERR_M BIT(26)
#define IRDMAPFINT_OICR_PE_PUSH_M BIT(27)
#define IRDMAPFINT_OICR_PE_CRITERR_M BIT(28)

#define IRDMA_CQP_INIT_WQE(wqe) memset(wqe, 0, 64)

#define IRDMA_GET_CURRENT_CQ_ELEM(_cq) \
	( \
		(_cq)->cq_base[IRDMA_RING_CURRENT_HEAD((_cq)->cq_ring)].buf  \
	)
#define IRDMA_GET_CURRENT_EXTENDED_CQ_ELEM(_cq) \
	( \
		((struct irdma_extended_cqe *) \
		((_cq)->cq_base))[IRDMA_RING_CURRENT_HEAD((_cq)->cq_ring)].buf \
	)

#define IRDMA_RING_INIT(_ring, _size) \
	{ \
		(_ring).head = 0; \
		(_ring).tail = 0; \
		(_ring).size = (_size); \
	}
#define IRDMA_RING_SIZE(_ring) ((_ring).size)
#define IRDMA_RING_CURRENT_HEAD(_ring) ((_ring).head)
#define IRDMA_RING_CURRENT_TAIL(_ring) ((_ring).tail)

#define IRDMA_RING_MOVE_HEAD(_ring, _retcode) \
	{ \
		register __u32 size; \
		size = (_ring).size;  \
		if (!IRDMA_RING_FULL_ERR(_ring)) { \
			(_ring).head = ((_ring).head + 1) % size; \
			(_retcode) = 0; \
		} else { \
			(_retcode) = IRDMA_ERR_RING_FULL; \
		} \
	}
#define IRDMA_RING_MOVE_HEAD_BY_COUNT(_ring, _count, _retcode) \
	{ \
		register __u32 size; \
		size = (_ring).size; \
		if ((IRDMA_RING_USED_QUANTA(_ring) + (_count)) < size) { \
			(_ring).head = ((_ring).head + (_count)) % size; \
			(_retcode) = 0; \
		} else { \
			(_retcode) = IRDMA_ERR_RING_FULL; \
		} \
	}
#define IRDMA_SQ_RING_MOVE_HEAD(_ring, _retcode) \
	{ \
		register __u32 size; \
		size = (_ring).size;  \
		if (!IRDMA_SQ_RING_FULL_ERR(_ring)) { \
			(_ring).head = ((_ring).head + 1) % size; \
			(_retcode) = 0; \
		} else { \
			(_retcode) = IRDMA_ERR_RING_FULL; \
		} \
	}
#define IRDMA_SQ_RING_MOVE_HEAD_BY_COUNT(_ring, _count, _retcode) \
	{ \
		register __u32 size; \
		size = (_ring).size; \
		if ((IRDMA_RING_USED_QUANTA(_ring) + (_count)) < (size - 256)) { \
			(_ring).head = ((_ring).head + (_count)) % size; \
			(_retcode) = 0; \
		} else { \
			(_retcode) = IRDMA_ERR_RING_FULL; \
		} \
	}
#define IRDMA_RING_MOVE_HEAD_BY_COUNT_NOCHECK(_ring, _count) \
	(_ring).head = ((_ring).head + (_count)) % (_ring).size

#define IRDMA_RING_MOVE_TAIL(_ring) \
	(_ring).tail = ((_ring).tail + 1) % (_ring).size

#define IRDMA_RING_MOVE_HEAD_NOCHECK(_ring) \
	(_ring).head = ((_ring).head + 1) % (_ring).size

#define IRDMA_RING_MOVE_TAIL_BY_COUNT(_ring, _count) \
	(_ring).tail = ((_ring).tail + (_count)) % (_ring).size

#define IRDMA_RING_SET_TAIL(_ring, _pos) \
	(_ring).tail = (_pos) % (_ring).size

#define IRDMA_RING_FULL_ERR(_ring) \
	( \
		(IRDMA_RING_USED_QUANTA(_ring) == ((_ring).size - 1))  \
	)

#define IRDMA_ERR_RING_FULL2(_ring) \
	( \
		(IRDMA_RING_USED_QUANTA(_ring) == ((_ring).size - 2))  \
	)

#define IRDMA_ERR_RING_FULL3(_ring) \
	( \
		(IRDMA_RING_USED_QUANTA(_ring) == ((_ring).size - 3))  \
	)

#define IRDMA_SQ_RING_FULL_ERR(_ring) \
	( \
		(IRDMA_RING_USED_QUANTA(_ring) == ((_ring).size - 257))  \
	)

#define IRDMA_ERR_SQ_RING_FULL2(_ring) \
	( \
		(IRDMA_RING_USED_QUANTA(_ring) == ((_ring).size - 258))  \
	)
#define IRDMA_ERR_SQ_RING_FULL3(_ring) \
	( \
		(IRDMA_RING_USED_QUANTA(_ring) == ((_ring).size - 259))  \
	)
#define IRDMA_RING_MORE_WORK(_ring) \
	( \
		(IRDMA_RING_USED_QUANTA(_ring) != 0) \
	)

#define IRDMA_RING_USED_QUANTA(_ring) \
	( \
		(((_ring).head + (_ring).size - (_ring).tail) % (_ring).size) \
	)

#define IRDMA_RING_FREE_QUANTA(_ring) \
	( \
		((_ring).size - IRDMA_RING_USED_QUANTA(_ring) - 1) \
	)

#define IRDMA_SQ_RING_FREE_QUANTA(_ring) \
	( \
		((_ring).size - IRDMA_RING_USED_QUANTA(_ring) - 257) \
	)

#define IRDMA_ATOMIC_RING_MOVE_HEAD(_ring, index, _retcode) \
	{ \
		index = IRDMA_RING_CURRENT_HEAD(_ring); \
		IRDMA_RING_MOVE_HEAD(_ring, _retcode); \
	}

enum irdma_qp_wqe_size {
	IRDMA_WQE_SIZE_32  = 32,
	IRDMA_WQE_SIZE_64  = 64,
	IRDMA_WQE_SIZE_96  = 96,
	IRDMA_WQE_SIZE_128 = 128,
	IRDMA_WQE_SIZE_256 = 256,
};

/**
 * set_64bit_val - set 64 bit value to hw wqe
 * @wqe_words: wqe addr to write
 * @byte_index: index in wqe
 * @val: value to write
 **/
static inline void set_64bit_val(__le64 *wqe_words, __u32 byte_index, __u64 val)
{
	wqe_words[byte_index >> 3] = htole64(val);
}

/**
 * set_32bit_val - set 32 bit value to hw wqe
 * @wqe_words: wqe addr to write
 * @byte_index: index in wqe
 * @val: value to write
 **/
static inline void set_32bit_val(__le32 *wqe_words, __u32 byte_index, __u32 val)
{
	wqe_words[byte_index >> 2] = htole32(val);
}

/**
 * get_64bit_val - read 64 bit value from wqe
 * @wqe_words: wqe addr
 * @byte_index: index to read from
 * @val: read value
 **/
static inline void get_64bit_val(__le64 *wqe_words, __u32 byte_index, __u64 *val)
{
	*val = le64toh(wqe_words[byte_index >> 3]);
}

/**
 * get_32bit_val - read 32 bit value from wqe
 * @wqe_words: wqe addr
 * @byte_index: index to reaad from
 * @val: return 32 bit value
 **/
static inline void get_32bit_val(__le32 *wqe_words, __u32 byte_index, __u32 *val)
{
	*val = le32toh(wqe_words[byte_index >> 2]);
}
#endif /* IRDMA_DEFS_H */
