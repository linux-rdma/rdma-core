/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2025 Hisilicon Limited.
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

#if defined(LTTNG_ENABLED)

#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER rdma_core_hns

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "hns_roce_u_trace.h"

#if !defined(__HNS_TRACE_H__) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define __HNS_TRACE_H__

#include <lttng/tracepoint.h>
#include <infiniband/verbs.h>

LTTNG_UST_TRACEPOINT_EVENT(
	/* Tracepoint provider name */
	rdma_core_hns,

	/* Tracepoint name */
	post_send,

	/* Input arguments */
	LTTNG_UST_TP_ARGS(
		char *, dev_name,
		uint64_t, wr_id,
		int32_t, num_sge,
		uint32_t, lqpn,
		uint32_t, rqpn,
		uint32_t, send_flags,
		uint32_t, msg_len,
		uint8_t, opcode,
		uint8_t, sl,
		uint8_t, t_class
	),

	/* Output event fields */
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_string(dev_name, dev_name)
		lttng_ust_field_integer_hex(uint64_t, wr_id, wr_id)
		lttng_ust_field_integer_hex(int32_t, num_sge, num_sge)
		lttng_ust_field_integer_hex(uint32_t, lqpn, lqpn)
		lttng_ust_field_integer_hex(uint32_t, rqpn, rqpn)
		lttng_ust_field_integer_hex(uint32_t, send_flags, send_flags)
		lttng_ust_field_integer_hex(uint32_t, msg_len, msg_len)
		lttng_ust_field_integer_hex(uint8_t, opcode, opcode)
		lttng_ust_field_integer_hex(uint8_t, sl, sl)
		lttng_ust_field_integer_hex(uint8_t, t_class, t_class)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(
	/* Tracepoint provider name */
	rdma_core_hns,

	/* Tracepoint name */
	post_recv,

	/* Input arguments */
	LTTNG_UST_TP_ARGS(
		char *, dev_name,
		uint64_t, wr_id,
		int32_t, num_sge,
		uint32_t, rqn,
		uint8_t, is_srq
	),

	/* Output event fields */
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_string(dev_name, dev_name)
		lttng_ust_field_integer_hex(uint64_t, wr_id, wr_id)
		lttng_ust_field_integer_hex(int32_t, num_sge, num_sge)
		lttng_ust_field_integer_hex(uint32_t, rqn, rqn)
		lttng_ust_field_integer_hex(uint8_t, is_srq, is_srq)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(
	/* Tracepoint provider name */
	rdma_core_hns,

	/* Tracepoint name */
	poll_cq,

	/* Input arguments */
	LTTNG_UST_TP_ARGS(
		char *, dev_name,
		uint64_t, wr_id,
		uint8_t, status,
		uint8_t, opcode,
		uint8_t, wc_flags,
		uint8_t, vendor_err,
		uint8_t, pktype,
		uint32_t, lqpn,
		uint32_t, rqpn,
		uint32_t, byte_len
	),

	/* Output event fields */
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_string(dev_name, dev_name)
		lttng_ust_field_integer_hex(uint64_t, wr_id, wr_id)
		lttng_ust_field_integer_hex(uint8_t, status, status)
		lttng_ust_field_integer_hex(uint8_t, opcode, opcode)
		lttng_ust_field_integer_hex(uint8_t, wc_flags, wc_flags)
		lttng_ust_field_integer_hex(uint8_t, vendor_err, vendor_err)
		lttng_ust_field_integer_hex(uint8_t, pktype, pktype)
		lttng_ust_field_integer_hex(uint32_t, lqpn, lqpn)
		lttng_ust_field_integer_hex(uint32_t, rqpn, rqpn)
		lttng_ust_field_integer_hex(uint32_t, byte_len, byte_len)
	)
)

#define rdma_tracepoint(arg...) lttng_ust_tracepoint(arg)

#endif /* __HNS_TRACE_H__*/

#include <lttng/tracepoint-event.h>

#else

#ifndef __HNS_TRACE_H__
#define __HNS_TRACE_H__

#define rdma_tracepoint(arg...)

#endif /* __HNS_TRACE_H__*/

#endif /* defined(LTTNG_ENABLED) */
