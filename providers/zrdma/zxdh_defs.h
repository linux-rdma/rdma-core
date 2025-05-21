/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * Copyright (c) 2024 ZTE Corporation.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef ZXDH_DEFS_H
#define ZXDH_DEFS_H
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <util/udma_barrier.h>
#include <util/util.h>
#include <linux/types.h>
#include <inttypes.h>
#include <pthread.h>
#include <endian.h>
#define ZXDH_RECV_ERR_FLAG_NAK_RNR_NAK 1
#define ZXDH_RECV_ERR_FLAG_READ_RESP 2
#define ZXDH_RETRY_CQE_SQ_OPCODE_ERR 32
#define ZXDH_QP_RETRY_COUNT 2
#define ZXDH_RESET_RETRY_CQE_SQ_OPCODE_ERR 0x1f

#define ZXDH_QP_TYPE_ROCE_RC 1
#define ZXDH_QP_TYPE_ROCE_UD 2

#define ZXDH_HW_PAGE_SIZE 4096
#define ZXDH_HW_PAGE_SHIFT 12
#define ZXDH_CQE_QTYPE_RQ 0
#define ZXDH_CQE_QTYPE_SQ 1

#define ZXDH_MAX_SQ_WQES_PER_PAGE 128
#define ZXDH_MAX_SQ_DEPTH 32768

#define ZXDH_QP_SW_MIN_WQSIZE 64u /* in WRs*/
#define ZXDH_QP_WQE_MIN_SIZE 32
#define ZXDH_QP_SQE_MIN_SIZE 32
#define ZXDH_QP_RQE_MIN_SIZE 16
#define ZXDH_QP_WQE_MAX_SIZE 256
#define ZXDH_QP_WQE_MIN_QUANTA 1
#define ZXDH_MAX_RQ_WQE_SHIFT_GEN1 2
#define ZXDH_MAX_RQ_WQE_SHIFT_GEN2 3
#define ZXDH_SRQ_FRAG_BYTESIZE 16
#define ZXDH_QP_FRAG_BYTESIZE 16
#define ZXDH_SQ_WQE_BYTESIZE 32
#define ZXDH_SRQ_WQE_MIN_SIZE 16

#define ZXDH_SQ_RSVD 1
#define ZXDH_RQ_RSVD 1
#define ZXDH_SRQ_RSVD 1

#define ZXDH_FEATURE_RTS_AE 1ULL
#define ZXDH_FEATURE_CQ_RESIZE 2ULL
#define ZXDHQP_OP_RDMA_WRITE 0x00
#define ZXDHQP_OP_RDMA_READ 0x01
#define ZXDHQP_OP_RDMA_SEND 0x03
#define ZXDHQP_OP_RDMA_SEND_INV 0x04
#define ZXDHQP_OP_RDMA_SEND_SOL_EVENT 0x05
#define ZXDHQP_OP_RDMA_SEND_SOL_EVENT_INV 0x06
#define ZXDHQP_OP_BIND_MW 0x08
#define ZXDHQP_OP_FAST_REGISTER 0x09
#define ZXDHQP_OP_LOCAL_INVALIDATE 0x0a
#define ZXDHQP_OP_RDMA_READ_LOC_INV 0x0b
#define ZXDHQP_OP_NOP 0x0c

#define ZXDH_CQPHC_QPCTX GENMASK_ULL(63, 0)
#define ZXDH_QP_DBSA_HW_SQ_TAIL GENMASK_ULL(14, 0)
#define ZXDH_CQ_DBSA_CQEIDX GENMASK_ULL(22, 0)
#define ZXDH_CQ_DBSA_SW_CQ_SELECT GENMASK_ULL(28, 23)
#define ZXDH_CQ_DBSA_ARM_NEXT BIT_ULL(31)
#define ZXDH_CQ_DBSA_ARM_SEQ_NUM GENMASK_ULL(30, 29)
#define ZXDH_CQ_ARM_CQ_ID_S 10
#define ZXDH_CQ_ARM_CQ_ID GENMASK_ULL(29, 10)
#define ZXDH_CQ_ARM_DBSA_VLD_S 30
#define ZXDH_CQ_ARM_DBSA_VLD BIT_ULL(30)

/* CQP and iWARP Completion Queue */
#define ZXDH_CQ_QPCTX ZXDH_CQPHC_QPCTX

#define ZXDH_CQ_MINERR GENMASK_ULL(22, 7)
#define ZXDH_CQ_MAJERR GENMASK_ULL(38, 23)
#define ZXDH_CQ_WQEIDX GENMASK_ULL(54, 40)
#define ZXDH_CQ_EXTCQE BIT_ULL(50)
#define ZXDH_OOO_CMPL BIT_ULL(54)
#define ZXDH_CQ_ERROR BIT_ULL(39)
#define ZXDH_CQ_SQ BIT_ULL(4)

#define ZXDH_CQ_VALID BIT_ULL(5)
#define ZXDH_CQ_IMMVALID BIT_ULL(0)
#define ZXDH_CQ_UDSMACVALID BIT_ULL(26)
#define ZXDH_CQ_UDVLANVALID BIT_ULL(27)
#define ZXDH_CQ_IMMDATA GENMASK_ULL(31, 0)
#define ZXDH_CQ_UDSMAC GENMASK_ULL(47, 0)
#define ZXDH_CQ_UDVLAN GENMASK_ULL(63, 48)

#define ZXDH_CQ_IMMDATA_S 0
#define ZXDH_CQ_IMMDATA_M (0xffffffffffffffffULL << ZXDH_CQ_IMMVALID_S)
#define ZXDH_CQ_IMMDATALOW32 GENMASK_ULL(31, 0)
#define ZXDH_CQ_IMMDATAUP32 GENMASK_ULL(63, 32)
#define ZXDHCQ_PAYLDLEN GENMASK_ULL(63, 32)
#define ZXDHCQ_TCPSEQNUMRTT GENMASK_ULL(63, 32)
#define ZXDHCQ_INVSTAG_S 11
#define ZXDHCQ_INVSTAG GENMASK_ULL(42, 11)
#define ZXDHCQ_QPID GENMASK_ULL(63, 44)

#define ZXDHCQ_UDSRCQPN GENMASK_ULL(24, 1)
#define ZXDHCQ_PSHDROP BIT_ULL(51)
#define ZXDHCQ_STAG_S 43
#define ZXDHCQ_STAG BIT_ULL(43)
#define ZXDHCQ_IPV4 BIT_ULL(25)
#define ZXDHCQ_SOEVENT BIT_ULL(6)
#define ZXDHCQ_OP GENMASK_ULL(63, 58)

/* Manage Push Page - MPP */
#define ZXDH_INVALID_PUSH_PAGE_INDEX_GEN_1 0xffff
#define ZXDH_INVALID_PUSH_PAGE_INDEX 0xffffffff

#define ZXDHQPSQ_OPCODE GENMASK_ULL(62, 57)
#define ZXDHQPSQ_COPY_HOST_PBL BIT_ULL(43)
#define ZXDHQPSQ_ADDFRAGCNT GENMASK_ULL(39, 32)
#define ZXDHQPSQ_PUSHWQE BIT_ULL(56)
#define ZXDHQPSQ_STREAMMODE BIT_ULL(58)
#define ZXDHQPSQ_WAITFORRCVPDU BIT_ULL(59)
#define ZXDHQPSQ_READFENCE BIT_ULL(54)
#define ZXDHQPSQ_LOCALFENCE BIT_ULL(55)
#define ZXDHQPSQ_UDPHEADER BIT_ULL(61)
#define ZXDHQPSQ_L4LEN GENMASK_ULL(45, 42)
#define ZXDHQPSQ_SIGCOMPL BIT_ULL(56)
#define ZXDHQPSQ_SOLICITED BIT_ULL(53)
#define ZXDHQPSQ_VALID BIT_ULL(63)

#define ZXDHQPSQ_FIRST_FRAG_VALID BIT_ULL(0)
#define ZXDHQPSQ_FIRST_FRAG_LEN GENMASK_ULL(31, 1)
#define ZXDHQPSQ_FIRST_FRAG_STAG GENMASK_ULL(63, 32)
#define ZXDHQPSQ_FRAG_TO ZXDH_CQPHC_QPCTX
#define ZXDHQPSQ_FRAG_VALID BIT_ULL(63)
#define ZXDHQPSQ_FRAG_LEN GENMASK_ULL(62, 32)
#define ZXDHQPSQ_FRAG_STAG GENMASK_ULL(31, 0)
#define ZXDHQPSQ_GEN1_FRAG_LEN GENMASK_ULL(31, 0)
#define ZXDHQPSQ_GEN1_FRAG_STAG GENMASK_ULL(63, 32)
#define ZXDHQPSQ_REMSTAGINV GENMASK_ULL(31, 0)
#define ZXDHQPSQ_DESTQKEY GENMASK_ULL(31, 0)
#define ZXDHQPSQ_DESTQPN GENMASK_ULL(55, 32)
#define ZXDHQPSQ_AHID GENMASK_ULL(18, 0)
#define ZXDHQPSQ_INLINEDATAFLAG BIT_ULL(63)
#define ZXDHQPSQ_UD_INLINEDATAFLAG BIT_ULL(50)
#define ZXDHQPSQ_UD_INLINEDATALEN GENMASK_ULL(49, 42)
#define ZXDHQPSQ_UD_ADDFRAGCNT GENMASK_ULL(36, 29)
#define ZXDHQPSQ_WRITE_INLINEDATAFLAG BIT_ULL(48)
#define ZXDHQPSQ_WRITE_INLINEDATALEN GENMASK_ULL(47, 40)

#define ZXDH_INLINE_VALID_S 7
#define ZXDHQPSQ_INLINE_VALID BIT_ULL(63)
#define ZXDHQPSQ_INLINEDATALEN GENMASK_ULL(62, 55)
#define ZXDHQPSQ_IMMDATAFLAG BIT_ULL(52)
#define ZXDHQPSQ_REPORTRTT BIT_ULL(46)

#define ZXDHQPSQ_IMMDATA GENMASK_ULL(31, 0)
#define ZXDHQPSQ_REMSTAG_S 0
#define ZXDHQPSQ_REMSTAG GENMASK_ULL(31, 0)

#define ZXDHQPSQ_REMTO ZXDH_CQPHC_QPCTX

#define ZXDHQPSQ_IMMDATA_VALID BIT_ULL(63)
#define ZXDHQPSQ_STAGRIGHTS GENMASK_ULL(50, 46)
#define ZXDHQPSQ_VABASEDTO BIT_ULL(51)
#define ZXDHQPSQ_MEMWINDOWTYPE BIT_ULL(52)

#define ZXDHQPSQ_MWLEN ZXDH_CQPHC_QPCTX
#define ZXDHQPSQ_PARENTMRSTAG GENMASK_ULL(31, 0)
#define ZXDHQPSQ_MWSTAG GENMASK_ULL(31, 0)
#define ZXDHQPSQ_MW_PA_PBLE_ONE GENMASK_ULL(63, 46)
#define ZXDHQPSQ_MW_PA_PBLE_TWO GENMASK_ULL(63, 32)
#define ZXDHQPSQ_MW_PA_PBLE_THREE GENMASK_ULL(33, 32)
#define ZXDHQPSQ_MW_HOST_PAGE_SIZE GENMASK_ULL(40, 36)
#define ZXDHQPSQ_MW_LEAF_PBL_SIZE GENMASK_ULL(35, 34)
#define ZXDHQPSQ_MW_LEVLE2_FIRST_PBLE_INDEX GENMASK_ULL(41, 32)
#define ZXDHQPSQ_MW_LEVLE2_ROOT_PBLE_INDEX GENMASK_ULL(50, 42)

#define ZXDHQPSQ_BASEVA_TO_FBO ZXDH_CQPHC_QPCTX

#define ZXDHQPSQ_LOCSTAG GENMASK_ULL(31, 0)

#define ZXDHQPSRQ_RSV GENMASK_ULL(63, 40)
#define ZXDHQPSRQ_VALID_SGE_NUM GENMASK_ULL(39, 32)
#define ZXDHQPSRQ_SIGNATURE GENMASK_ULL(31, 24)
#define ZXDHQPSRQ_NEXT_WQE_INDEX GENMASK_ULL(15, 0)
#define ZXDHQPSRQ_START_PADDING BIT_ULL(63)
#define ZXDHQPSRQ_FRAG_LEN GENMASK_ULL(62, 32)
#define ZXDHQPSRQ_FRAG_STAG GENMASK_ULL(31, 0)

/* QP RQ WQE common fields */
#define ZXDHQPRQ_SIGNATURE GENMASK_ULL(31, 16)
#define ZXDHQPRQ_ADDFRAGCNT ZXDHQPSQ_ADDFRAGCNT
#define ZXDHQPRQ_VALID ZXDHQPSQ_VALID
#define ZXDHQPRQ_COMPLCTX ZXDH_CQPHC_QPCTX
#define ZXDHQPRQ_FRAG_LEN ZXDHQPSQ_FRAG_LEN
#define ZXDHQPRQ_STAG ZXDHQPSQ_FRAG_STAG
#define ZXDHQPRQ_TO ZXDHQPSQ_FRAG_TO

//QP RQ DBSA fields
#define ZXDHQPDBSA_RQ_POLARITY_S 15
#define ZXDHQPDBSA_RQ_POLARITY BIT_ULL(15)
#define ZXDHQPDBSA_RQ_SW_HEAD_S 0
#define ZXDHQPDBSA_RQ_SW_HEAD GENMASK_ULL(14, 0)

#define ZXDHPFINT_OICR_HMC_ERR_M BIT(26)
#define ZXDHPFINT_OICR_PE_PUSH_M BIT(27)
#define ZXDHPFINT_OICR_PE_CRITERR_M BIT(28)

#define ZXDH_SRQ_PARITY_SIGN_S 15
#define ZXDH_SRQ_PARITY_SIGN BIT_ULL(15)
#define ZXDH_SRQ_SW_SRQ_HEAD_S 0
#define ZXDH_SRQ_SW_SRQ_HEAD GENMASK_ULL(14, 0)
#define ZXDH_CQE_SQ_OPCODE_RESET BIT(5)

#define ZXDH_CQP_INIT_WQE(wqe) memset(wqe, 0, 64)

#define ZXDH_GET_CURRENT_CQ_ELEM(_cq)                                          \
	((_cq)->cq_base[ZXDH_RING_CURRENT_HEAD((_cq)->cq_ring)].buf)
#define ZXDH_GET_CURRENT_EXTENDED_CQ_ELEM(_cq)                                 \
	(((struct zxdh_extended_cqe                                            \
		   *)((_cq)->cq_base))[ZXDH_RING_CURRENT_HEAD((_cq)->cq_ring)] \
		 .buf)

#define ZXDH_RING_INIT(_ring, _size)                                           \
	{                                                                      \
		(_ring).head = 0;                                              \
		(_ring).tail = 0;                                              \
		(_ring).size = (_size);                                        \
	}
#define ZXDH_RING_SIZE(_ring) ((_ring).size)
#define ZXDH_RING_CURRENT_HEAD(_ring) ((_ring).head)
#define ZXDH_RING_CURRENT_TAIL(_ring) ((_ring).tail)

#define ZXDH_RING_MOVE_HEAD(_ring, _retcode)                                   \
	{                                                                      \
		register __u32 size;                                           \
		size = (_ring).size;                                           \
		if (!ZXDH_RING_FULL_ERR(_ring)) {                              \
			(_ring).head = ((_ring).head + 1) % size;              \
			(_retcode) = 0;                                        \
		} else {                                                       \
			(_retcode) = ZXDH_ERR_RING_FULL;                       \
		}                                                              \
	}
#define ZXDH_RING_MOVE_HEAD_BY_COUNT(_ring, _count, _retcode)                  \
	{                                                                      \
		register __u32 size;                                           \
		size = (_ring).size;                                           \
		if ((ZXDH_RING_USED_QUANTA(_ring) + (_count)) < size) {        \
			(_ring).head = ((_ring).head + (_count)) % size;       \
			(_retcode) = 0;                                        \
		} else {                                                       \
			(_retcode) = ZXDH_ERR_RING_FULL;                       \
		}                                                              \
	}

#define ZXDH_RING_MOVE_HEAD_BY_COUNT_NOCHECK(_ring, _count)                    \
	(_ring).head = ((_ring).head + (_count)) % (_ring).size

#define ZXDH_RING_MOVE_TAIL(_ring)                                             \
	(_ring).tail = ((_ring).tail + 1) % (_ring).size

#define ZXDH_RING_MOVE_HEAD_NOCHECK(_ring)                                     \
	(_ring).head = ((_ring).head + 1) % (_ring).size

#define ZXDH_RING_MOVE_TAIL_BY_COUNT(_ring, _count)                            \
	(_ring).tail = ((_ring).tail + (_count)) % (_ring).size

#define ZXDH_RING_SET_TAIL(_ring, _pos) (_ring).tail = (_pos) % (_ring).size

#define ZXDH_RING_FULL_ERR(_ring)                                              \
	((ZXDH_RING_USED_QUANTA(_ring) == ((_ring).size - 1)))

#define ZXDH_ERR_RING_FULL2(_ring)                                             \
	((ZXDH_RING_USED_QUANTA(_ring) == ((_ring).size - 2)))

#define ZXDH_ERR_RING_FULL3(_ring)                                             \
	((ZXDH_RING_USED_QUANTA(_ring) == ((_ring).size - 3)))

#define ZXDH_RING_MORE_WORK(_ring) ((ZXDH_RING_USED_QUANTA(_ring) != 0))

#define ZXDH_RING_USED_QUANTA(_ring)                                           \
	((((_ring).head + (_ring).size - (_ring).tail) % (_ring).size))

#define ZXDH_RING_FREE_QUANTA(_ring)                                           \
	(((_ring).size - ZXDH_RING_USED_QUANTA(_ring) - 1))

#define ZXDH_ATOMIC_RING_MOVE_HEAD(_ring, index, _retcode)                     \
	{                                                                      \
		index = ZXDH_RING_CURRENT_HEAD(_ring);                         \
		ZXDH_RING_MOVE_HEAD(_ring, _retcode);                          \
	}

enum zxdh_qp_wqe_size {
	ZXDH_WQE_SIZE_32 = 32,
	ZXDH_WQE_SIZE_64 = 64,
	ZXDH_WQE_SIZE_96 = 96,
	ZXDH_WQE_SIZE_128 = 128,
	ZXDH_WQE_SIZE_256 = 256,
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
 * set_16bit_val - set 16 bit value to hw wqe
 * @wqe_words: wqe addr to write
 * @byte_index: index in wqe
 * @val: value to write
 **/
static inline void set_16bit_val(__le16 *wqe_words, __u32 byte_index, __u16 val)
{
	wqe_words[byte_index >> 1] = htole16(val);
}

/**
 * get_64bit_val - read 64 bit value from wqe
 * @wqe_words: wqe addr
 * @byte_index: index to read from
 * @val: read value
 **/
static inline void get_64bit_val(__le64 *wqe_words, __u32 byte_index,
				 __u64 *val)
{
	*val = le64toh(wqe_words[byte_index >> 3]);
}

/**
 * get_32bit_val - read 32 bit value from wqe
 * @wqe_words: wqe addr
 * @byte_index: index to reaad from
 * @val: return 32 bit value
 **/
static inline void get_32bit_val(__le32 *wqe_words, __u32 byte_index,
				 __u32 *val)
{
	*val = le32toh(wqe_words[byte_index >> 2]);
}

static inline void db_wr32(__u32 val, __u32 *wqe_word)
{
	*wqe_word = val;
}

#define read_wqe_need_split(pre_cal_psn, next_psn, chip_rev)                   \
	(!(chip_rev == 2) &&                                                   \
	 (((pre_cal_psn < next_psn) && (pre_cal_psn != 0)) ||                  \
	  ((next_psn <= 0x7FFFFF) && (pre_cal_psn > 0x800000))))
#endif /* ZXDH_DEFS_H */
