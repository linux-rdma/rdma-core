/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2021 Intel Corporation */
#ifndef I40IW_HW_H
#define I40IW_HW_H

enum i40iw_device_caps_const {
	I40IW_MAX_WQ_FRAGMENT_COUNT		= 3,
	I40IW_MAX_SGE_RD			= 1,
	I40IW_MAX_PUSH_PAGE_COUNT		= 0,
	I40IW_MAX_INLINE_DATA_SIZE		= 48,
	I40IW_MAX_IRD_SIZE			= 63,
	I40IW_MAX_ORD_SIZE			= 127,
	I40IW_MAX_WQ_ENTRIES			= 2048,
	I40IW_MAX_WQE_SIZE_RQ			= 128,
	I40IW_MAX_PDS				= 32768,
	I40IW_MAX_STATS_COUNT			= 16,
	I40IW_MAX_CQ_SIZE			= 1048575,
	I40IW_MAX_OUTBOUND_MSG_SIZE		= 2147483647,
	I40IW_MAX_INBOUND_MSG_SIZE		= 2147483647,
};

#define I40IW_QP_WQE_MIN_SIZE   32
#define I40IW_QP_WQE_MAX_SIZE   128
#define I40IW_QP_SW_MIN_WQSIZE  4
#define I40IW_MAX_RQ_WQE_SHIFT  2
#define I40IW_MAX_QUANTA_PER_WR 2

#define I40IW_QP_SW_MAX_SQ_QUANTA 2048
#define I40IW_QP_SW_MAX_RQ_QUANTA 16384
#define I40IW_QP_SW_MAX_WQ_QUANTA 2048
#endif /* I40IW_HW_H */
