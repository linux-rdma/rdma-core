---
layout: page
title: bnxt_re_dv_destroy_qp
section: 3
tagline: Verbs
date: 2026-06-05
header: "Broadcom BNXT-RE Direct Verbs Manual"
footer: bnxt_re
---

# NAME

bnxt_re_dv_destroy_qp - destroy a QP created with bnxt_re_dv_create_qp

# SYNOPSIS

```c
#include <infiniband/bnxt_re_dv.h>

int bnxt_re_dv_destroy_qp(struct ibv_qp *ibvqp);
```

# DESCRIPTION

**bnxt_re_dv_destroy_qp**() destroys a queue pair previously created by
**bnxt_re_dv_create_qp**(3) using the provider's normal QP teardown path.

Any umem registrations used for the SQ or RQ rings may be released with
**bnxt_re_dv_umem_dereg**(3) after this call returns successfully.

# RETURN VALUE

Returns 0 on success, or a non-zero error code on failure with errno set.

# SEE ALSO

**bnxt_re_dv**(7),
**bnxt_re_dv_create_qp**(3),
**bnxt_re_dv_modify_qp**(3),
**bnxt_re_dv_umem_dereg**(3),
**ibv_destroy_qp**(3)

# AUTHORS

Sriharsha Basavapatna \<sriharsha.basavapatna@broadcom.com\>,
Selvin Xavier \<selvin.xavier@broadcom.com\>
