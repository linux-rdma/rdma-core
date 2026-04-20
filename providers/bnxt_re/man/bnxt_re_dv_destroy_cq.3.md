---
layout: page
title: bnxt_re_dv_destroy_cq
section: 3
tagline: Verbs
date: 2025-06-17
header: "Broadcom BNXT-RE Direct Verbs Manual"
footer: bnxt_re
---

# NAME

bnxt_re_dv_destroy_cq - destroy a CQ created with bnxt_re_dv_create_cq

# SYNOPSIS

```c
#include <infiniband/bnxt_re_dv.h>

int bnxt_re_dv_destroy_cq(struct ibv_cq *ibv_cq);
```

# DESCRIPTION

**bnxt_re_dv_destroy_cq**() destroys a completion queue previously created by
**bnxt_re_dv_create_cq**(3), using the provider’s normal CQ teardown path.

# RETURN VALUE

Returns 0 on success, or non-zero on failure (see **errno**).

# SEE ALSO

**bnxt_re_dv**(7),
**bnxt_re_dv_create_cq**(3),
**ibv_destroy_cq**(3)

# AUTHORS

Sriharsha Basavapatna \<sriharsha.basavapatna@broadcom.com\>,
Kalesh AP \<kalesh-anakkur.purayil@broadcom.com\>,
Selvin Xavier \<selvin.xavier@broadcom.com\>
