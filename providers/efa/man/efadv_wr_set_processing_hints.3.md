---
layout: page
title: EFADV_WR_SET_PROCESSING_HINTS
section: 3
tagline: Verbs
date: 2026-05-05
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_wr_set_processing_hints - Set processing hints on the current
work request

# SYNOPSIS

```c
#include <infiniband/efadv.h>

static inline void efadv_wr_set_processing_hints(
	struct efadv_qp *efadv_qp,
	uint32_t hints);
```

# DESCRIPTION

**efadv_wr_set_processing_hints()** sets processing hints on the
current work request being built. Hints allow the application to
communicate intended usage patterns to the device, which may use them
to optimize processing.

This function is a work request setter and must be called after the
work request opcode function (e.g. **ibv_wr_send()**) and before
**ibv_wr_complete()** or the next work request opcode call.

Use **efadv_qp_from_ibv_qp_ex()** to get the efadv_qp for accessing
this interface.

The QP must be created with **EFADV_WR_EX_WITH_PROCESSING_HINTS** set
in *efadv_qp_init_attr.wr_flags* to use this function.

The *hints* argument is a bitmask of **efadv_wr_processing_hint**
values:

```c
enum efadv_wr_processing_hint {
	EFADV_WR_PROCESSING_HINT_BURST_PPS_SENSITIVE = 1 << 0,
};
```

*EFADV_WR_PROCESSING_HINT_BURST_PPS_SENSITIVE*
:	Optimize for throughput in bursty, packet-rate sensitive
	workloads.

# SEE ALSO

**efadv**(7), **efadv_create_qp_ex**(3), **ibv_wr_start**(3)

# AUTHORS

Michael Margolin <mrgolin@amazon.com>
