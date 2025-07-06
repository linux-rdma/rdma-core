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
#ifndef ZXDH_STATUS_H
#define ZXDH_STATUS_H

/* Error Codes */
enum zxdh_status_code {
	ZXDH_SUCCESS = 0,
	ZXDH_ERR_NVM = -1,
	ZXDH_ERR_NVM_CHECKSUM = -2,
	ZXDH_ERR_CFG = -4,
	ZXDH_ERR_PARAM = -5,
	ZXDH_ERR_DEVICE_NOT_SUPPORTED = -6,
	ZXDH_ERR_RESET_FAILED = -7,
	ZXDH_ERR_SWFW_SYNC = -8,
	ZXDH_ERR_NO_MEMORY = -9,
	ZXDH_ERR_BAD_PTR = -10,
	ZXDH_ERR_INVALID_PD_ID = -11,
	ZXDH_ERR_INVALID_QP_ID = -12,
	ZXDH_ERR_INVALID_CQ_ID = -13,
	ZXDH_ERR_INVALID_CEQ_ID = -14,
	ZXDH_ERR_INVALID_AEQ_ID = -15,
	ZXDH_ERR_INVALID_SIZE = -16,
	ZXDH_ERR_INVALID_ARP_INDEX = -17,
	ZXDH_ERR_INVALID_FPM_FUNC_ID = -18,
	ZXDH_ERR_QP_INVALID_MSG_SIZE = -19,
	ZXDH_ERR_QP_TOOMANY_WRS_POSTED = -20,
	ZXDH_ERR_INVALID_FRAG_COUNT = -21,
	ZXDH_ERR_Q_EMPTY = -22,
	ZXDH_ERR_INVALID_ALIGNMENT = -23,
	ZXDH_ERR_FLUSHED_Q = -24,
	ZXDH_ERR_INVALID_PUSH_PAGE_INDEX = -25,
	ZXDH_ERR_INVALID_INLINE_DATA_SIZE = -26,
	ZXDH_ERR_TIMEOUT = -27,
	ZXDH_ERR_OPCODE_MISMATCH = -28,
	ZXDH_ERR_CQP_COMPL_ERROR = -29,
	ZXDH_ERR_INVALID_VF_ID = -30,
	ZXDH_ERR_INVALID_HMCFN_ID = -31,
	ZXDH_ERR_BACKING_PAGE_ERROR = -32,
	ZXDH_ERR_NO_PBLCHUNKS_AVAILABLE = -33,
	ZXDH_ERR_INVALID_PBLE_INDEX = -34,
	ZXDH_ERR_INVALID_SD_INDEX = -35,
	ZXDH_ERR_INVALID_PAGE_DESC_INDEX = -36,
	ZXDH_ERR_INVALID_SD_TYPE = -37,
	ZXDH_ERR_MEMCPY_FAILED = -38,
	ZXDH_ERR_INVALID_HMC_OBJ_INDEX = -39,
	ZXDH_ERR_INVALID_HMC_OBJ_COUNT = -40,
	ZXDH_ERR_BUF_TOO_SHORT = -43,
	ZXDH_ERR_BAD_IWARP_CQE = -44,
	ZXDH_ERR_NVM_BLANK_MODE = -45,
	ZXDH_ERR_NOT_IMPL = -46,
	ZXDH_ERR_PE_DOORBELL_NOT_ENA = -47,
	ZXDH_ERR_NOT_READY = -48,
	ZXDH_NOT_SUPPORTED = -49,
	ZXDH_ERR_FIRMWARE_API_VER = -50,
	ZXDH_ERR_RING_FULL = -51,
	ZXDH_ERR_MPA_CRC = -61,
	ZXDH_ERR_NO_TXBUFS = -62,
	ZXDH_ERR_SEQ_NUM = -63,
	ZXDH_ERR_LIST_EMPTY = -64,
	ZXDH_ERR_INVALID_MAC_ADDR = -65,
	ZXDH_ERR_BAD_STAG = -66,
	ZXDH_ERR_CQ_COMPL_ERROR = -67,
	ZXDH_ERR_Q_DESTROYED = -68,
	ZXDH_ERR_INVALID_FEAT_CNT = -69,
	ZXDH_ERR_REG_CQ_FULL = -70,
	ZXDH_ERR_VF_MSG_ERROR = -71,
	ZXDH_ERR_NO_INTR = -72,
	ZXDH_ERR_REG_QSET = -73,
	ZXDH_ERR_FEATURES_OP = -74,
	ZXDH_ERR_INVALID_FRAG_LEN = -75,
	ZXDH_ERR_RETRY_ACK_ERR	= -76,
	ZXDH_ERR_RETRY_ACK_NOT_EXCEED_ERR	= -77,
};
#endif /* ZXDH_STATUS_H */
