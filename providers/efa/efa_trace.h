/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2023-2025 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#if defined(LTTNG_ENABLED)

#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER rdma_core_efa

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "efa_trace.h"

#if !defined(__EFA_TRACE_H__) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define __EFA_TRACE_H__

#include <lttng/tracepoint.h>
#include <infiniband/verbs.h>

LTTNG_UST_TRACEPOINT_EVENT(
	/* Tracepoint provider name */
	rdma_core_efa,

	/* Tracepoint name */
	post_recv,

	/* Input arguments */
	LTTNG_UST_TP_ARGS(
		char *, dev_name,
		uint64_t, wr_id,
		uint32_t, qp_num,
		int, num_sge
	),

	/* Output event fields */
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_string(dev_name, dev_name)
		lttng_ust_field_integer(uint64_t, wr_id, wr_id)
		lttng_ust_field_integer(uint32_t, qp_num, qp_num)
		lttng_ust_field_integer(int, num_sge, num_sge)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(
	/* Tracepoint provider name */
	rdma_core_efa,

	/* Tracepoint name */
	post_send,

	/* Input arguments */
	LTTNG_UST_TP_ARGS(
		char *, dev_name,
		uint64_t, wr_id,
		uint8_t, op_type,
		uint32_t, src_qp_num,
		uint32_t, dst_qp_num,
		uint16_t, ah_num,
		uint32_t, length
	),

	/* Output event fields */
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_string(dev_name, dev_name)
		lttng_ust_field_integer(uint64_t, wr_id, wr_id)
		lttng_ust_field_integer(uint8_t, op_type, op_type)
		lttng_ust_field_integer(uint32_t, src_qp_num, src_qp_num)
		lttng_ust_field_integer(uint32_t, dst_qp_num, dst_qp_num)
		lttng_ust_field_integer(uint16_t, ah_num, ah_num)
		lttng_ust_field_integer(uint32_t, length, length)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(
	/* Tracepoint provider name */
	rdma_core_efa,

	/* Tracepoint name */
	process_completion,

	/* Input arguments */
	LTTNG_UST_TP_ARGS(
		char *, dev_name,
		uint64_t, wr_id,
		int, status,
		int, opcode,
		uint32_t, src_qp_num,
		uint32_t, dst_qp_num,
		uint16_t, ah_num,
		uint32_t, length
	),

	/* Output event fields */
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_string(dev_name, dev_name)
		lttng_ust_field_integer(uint64_t, wr_id, wr_id)
		lttng_ust_field_integer(int, status, status)
		lttng_ust_field_integer(int, opcode, opcode)
		lttng_ust_field_integer(uint32_t, src_qp_num, src_qp_num)
		lttng_ust_field_integer(uint32_t, dst_qp_num, dst_qp_num)
		lttng_ust_field_integer(uint16_t, ah_num, ah_num)
		lttng_ust_field_integer(uint32_t, length, length)
	)
)

#endif /* __EFA_TRACE_H__*/

#include <lttng/tracepoint-event.h>

#else

#ifndef __EFA_TRACE_H__
#define __EFA_TRACE_H__

#endif /* __EFA_TRACE_H__*/

#endif /* defined(LTTNG_ENABLED) */
