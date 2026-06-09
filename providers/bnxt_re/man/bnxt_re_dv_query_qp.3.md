---
layout: page
title: bnxt_re_dv_query_qp
section: 3
tagline: Verbs
date: 2026-06-05
header: "Broadcom BNXT-RE Direct Verbs Manual"
footer: bnxt_re
---

# NAME

bnxt_re_dv_query_qp - query attributes of a DV queue pair

# SYNOPSIS

```c
#include <infiniband/bnxt_re_dv.h>
#include <rdma/ib_user_verbs.h>

int bnxt_re_dv_query_qp(void *qp_handle, struct ib_uverbs_qp_attr *attr);
```

# DESCRIPTION

**bnxt_re_dv_query_qp**() queries the current attributes of a queue pair
created with **bnxt_re_dv_create_qp**(3) and fills *attr* with the result.

The caller sets **attr->qp_attr_mask** to the bitmask of attributes to
query before calling this function, following the same attribute mask
conventions as **ibv_query_qp**(3). On success, *attr* is populated with
the requested fields and **attr->qp_attr_mask** is preserved.

# RETURN VALUE

Returns 0 on success, or a non-zero error code on failure with errno set.

# SEE ALSO

**bnxt_re_dv**(7),
**bnxt_re_dv_create_qp**(3),
**bnxt_re_dv_modify_qp**(3),
**ibv_query_qp**(3)

# AUTHORS

Sriharsha Basavapatna \<sriharsha.basavapatna@broadcom.com\>,
Selvin Xavier \<selvin.xavier@broadcom.com\>
