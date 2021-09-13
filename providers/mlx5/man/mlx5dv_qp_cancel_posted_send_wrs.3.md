---
layout: page
title: mlx5dv_qp_cancel_posted_send_wrs
section: 3
tagline: Verbs
---

# NAME

mlx5dv_qp_cancel_posted_send_wrs -  Cancel all pending send work requests with supplied WRID in a QP in SQD state

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_qp_cancel_posted_send_wrs(struct mlx5dv_qp_ex *mqp, uint64_t wr_id);
```

# DESCRIPTION

The canceled work requests are replaced with NOPs (no operation), and will
generate good completions according to the signaling originally requested in
the send flags, or "flushed" completions in case the QP goes to error. A work
request can only be canceled when the QP is in SQD state.

The cancel function is a part of the signature pipelining feature. The feature
allows posting a signature related transfer operation together with a SEND with
a good response to the client. Normally, the application must wait for the
transfer to end, check the MKEY for errors, and only then send a good or bad
response. However this increases the latency of the good flow of a transaction.

To enable this feature, a QP must be created with the
**MLX5DV_QP_CREATE_SIG_PIPELINING** creation flag. Such QP will stop after
a transfer operation that failed signature validation in SQD state.
**IBV_EVENT_SQ_DRAINED** is generated to inform about the new state.

The SEND operation that might need to be canceled due to a bad signature of
a previous operation must be posted with the **IBV_SEND_FENCE** option in
**ibv_qp_ex->wr_flags** field.

When QP stopped at SQD, it means that at least one WR caused signature error.
It may not be the last WR. It may be that more than one WRs cause signature
errors by the time the QP finally stopped. It is guaranteed that the QP has
stopped somewhere between the WQE that generated the signature error, and the
next WQE that has **IBV_SEND_FENCE** on it.

Software must handle the SQD event as described below:

1. Poll everything (polling until 0 once) on the respective CQ, allowing the
discovery of all possible signature errors.

2. Look through all "open" transactions, check related signature MKEYs using
**mlx5dv_mkey_check**(3), find the one with the signature error, get a **WRID**
from the operation software context and handle the failed operation.

3. Cancel the SEND WR by the WRID using **mlx5dv_qp_cancel_posted_send_wrs**().

4. Modify the QP back to RTS state.

# ARGUMENTS

*mqp*

:	The QP to investigate, which must be in SQD state.

*wr_id*

:	The WRID to cancel.

# RETURN VALUE
Number of work requests that were canceled, or -errno on error.

# NOTES
A DEVX context should be opened by using **mlx5dv_open_device**(3).

Must be called with a QP in SQD state.

QP should be created with **MLX5DV_QP_CREATE_SIG_PIPELINING** creation flag.
Application must listen on QP events, and expect a SQD event.

# SEE ALSO
**mlx5dv_mkey_check**(3), **mlx5dv_wr_mkey_configure**(3),
**mlx5dv_wr_set_mkey_sig_block**(3), **mlx5dv_create_mkey**(3),
**mlx5dv_destroy_mkey**(3)

# AUTHORS

Oren Duer <oren@nvidia.com>

Sergey Gorenko <sergeygo@nvidia.com>
