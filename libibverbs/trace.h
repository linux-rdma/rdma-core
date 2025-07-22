/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2025 Hisilicon Limited.
 */

#ifndef _TRACE_H
#define _TRACE_H

#if defined(LTTNG_ENABLED)

#include <lttng/tracepoint.h>

#define rdma_tracepoint(arg...) lttng_ust_tracepoint(arg)

#else

#define rdma_tracepoint(arg...)

#endif /* defined(LTTNG_ENABLED) */

#endif /* _TRACE_H */
