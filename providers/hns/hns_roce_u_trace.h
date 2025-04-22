/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2025 Hisilicon Limited.
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

#define rdma_tracepoint(arg...) lttng_ust_tracepoint(arg)

#endif /* __HNS_TRACE_H__*/

#include <lttng/tracepoint-event.h>

#else

#ifndef __HNS_TRACE_H__
#define __HNS_TRACE_H__

#define rdma_tracepoint(arg...)

#endif /* __HNS_TRACE_H__*/

#endif /* defined(LTTNG_ENABLED) */
