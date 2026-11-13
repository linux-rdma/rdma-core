---
layout: page
title: IONIC_DV_QP_SET_GDA
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_qp_set_gda - Enable or disable GPU-Direct Async mode on a queue pair

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

int ionic_dv_qp_set_gda(struct ibv_qp *ibqp, bool enable_send,
                         bool enable_recv);
```

# DESCRIPTION

**ionic_dv_qp_set_gda()** enables or disables GPU-Direct Async (GDA) mode
on the queue pair *ibqp*.

In GDA mode, **ibv_post_send()** and **ibv_post_recv()** write WQEs into
the descriptor ring without ringing the doorbell. The application obtains
the doorbell data via **ionic_dv_qp_get_send_dbell_data**(3) or
**ionic_dv_qp_get_recv_dbell_data**(3), then arranges for the GPU to write
that data to the memory mapped doorbell register to initiate the transfer.

GDA mode is incompatible with express doorbell (EXPDB) on the same queue.
If EXPDB is active on the send or receive queue, the corresponding GDA
enable will fail.

# ARGUMENTS

*ibqp*
:	The queue pair to configure. Must be an ionic queue pair.

*enable_send*
:	Enable GDA mode for the send queue.

*enable_recv*
:	Enable GDA mode for the receive queue.

# RETURN VALUE

Returns 0 on success, or a positive errno value on failure:

*EPERM*
:	*ibqp* is not an ionic queue pair.

*EINVAL*
:	GDA was requested on a queue that has express doorbell enabled.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_qp_get_send_dbell_data**(3),
**ionic_dv_qp_get_recv_dbell_data**(3),
**ionic_dv_get_ctx**(3)

# AUTHORS

Advanced Micro Devices, Inc.
