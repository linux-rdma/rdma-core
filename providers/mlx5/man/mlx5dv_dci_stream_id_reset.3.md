---
layout: page
title: mlx5dv_dci_stream_id_reset
section: 3
tagline: Verbs
---

# NAME

mlx5dv_dci_stream_id_reset - Reset stream_id of a given DCI QP

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_dci_stream_id_reset(struct ibv_qp *qp, uint16_t stream_id);
```

# DESCRIPTION

Used by SW to reset an errored *stream_id* in the HW DCI context.

On work completion with error, the application should call ibv_query_qp() to check if the QP was moved to an error state,
or it's still operational (in RTS state), which means that the specific *stream_id* that caused the completion with error is in error state.

Errors which are stream related will cause only that *stream_id's* work request to be flushed as they are handled in order in the send queue.
Once all *stream_id* WR's are flushed, application should reset the errored *stream_id* by calling mlx5dv_dci_stream_id_reset().
Work requested for other *stream_id's* will continue to be processed by the QP.
The DCI QP will move to an error state and stop operating once the number of unique *stream_id* in error reaches the DCI QP's 'log_num_errored' streams defined by SW.

Application should use the 'wr_id' in the ibv_wc to find the *stream_id* from it’s private context.

# ARGUMENTS

*qp*
:	The ibv_qp object to issue the action on.

*stream_id*
:	The DCI stream channel id that need to be reset.

# RETURN VALUE

Returns 0 on success, or the value of errno on failure (which indicates the failure reason).

# AUTHOR

Lior Nahmanson <liorna@nvidia.com>
