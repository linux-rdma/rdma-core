---
layout: page
title: IONIC_DV_QP_GET_RECV_DBELL_DATA
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_qp_get_recv_dbell_data - Get receive queue doorbell data for GDA mode

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

int ionic_dv_qp_get_recv_dbell_data(struct ibv_qp *ibqp, uint64_t *dbdata);
```

# DESCRIPTION

**ionic_dv_qp_get_recv_dbell_data()** retrieves the current doorbell data
for the receive queue of *ibqp*. This is used in GPU-Direct Async (GDA)
mode.

In GDA mode, **ibv_post_recv()** writes WQEs into the descriptor ring
without ringing the doorbell. After polling completions and re-posting
receive buffers, the application queries the doorbell data. The GPU
writes this data to the memory mapped doorbell register after consuming
the received data, making the buffers available for the next transfer.

Doorbells must be rung in sequential order. If buffers are posted in
batches A, B, and C, the GPU must not write B before A, or C before B.
Skipping intermediate doorbells is allowed (e.g., writing only C makes
all preceding buffers available).

# ARGUMENTS

*ibqp*
:	The queue pair to query. Must be an ionic queue pair.

*dbdata*
:	Output parameter to receive the 64-bit doorbell data value.

# RETURN VALUE

Returns 0 on success, or a positive errno value on failure:

*EPERM*
:	*ibqp* is not an ionic queue pair.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_qp_set_gda**(3),
**ionic_dv_qp_get_send_dbell_data**(3),
**ionic_dv_get_ctx**(3)

# AUTHORS

Advanced Micro Devices, Inc.
