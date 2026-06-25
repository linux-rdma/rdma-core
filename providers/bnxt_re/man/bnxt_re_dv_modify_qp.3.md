---
layout: page
title: bnxt_re_dv_modify_qp
section: 3
tagline: Verbs
date: 2026-06-05
header: "Broadcom BNXT-RE Direct Verbs Manual"
footer: bnxt_re
---

# NAME

bnxt_re_dv_modify_qp - modify attributes of a DV queue pair

# SYNOPSIS

```c
#include <infiniband/bnxt_re_dv.h>

int bnxt_re_dv_modify_qp(struct ibv_qp *ibv_qp,
                          struct ibv_qp_attr *attr,
                          int attr_mask);
```

# DESCRIPTION

**bnxt_re_dv_modify_qp**() modifies the attributes of a queue pair
previously created with **bnxt_re_dv_create_qp**(3). It drives standard
QP state transitions using *attr* and *attr_mask* following the same
semantics as **ibv_modify_qp**(3).

# RETURN VALUE

Returns 0 on success, or a non-zero error code on failure with errno set.

# SEE ALSO

**bnxt_re_dv**(7),
**bnxt_re_dv_create_qp**(3),
**bnxt_re_dv_query_qp**(3),
**ibv_modify_qp**(3)

# AUTHORS

Sriharsha Basavapatna \<sriharsha.basavapatna@broadcom.com\>,
Selvin Xavier \<selvin.xavier@broadcom.com\>
