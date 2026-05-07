---
layout: page
title: bnxt_re_dv_umem_dereg
section: 3
tagline: Verbs
date: 2025-06-17
header: "Broadcom BNXT-RE Direct Verbs Manual"
footer: bnxt_re
---

# NAME

bnxt_re_dv_umem_dereg - deregister user memory registered with bnxt_re_dv_umem_reg

# SYNOPSIS

```c
#include <infiniband/bnxt_re_dv.h>

int bnxt_re_dv_umem_dereg(struct bnxt_re_dv_umem *umem);
```

# DESCRIPTION

**bnxt_re_dv_umem_dereg**() clears **MADV_DONTFORK** for the registered range and
frees the **bnxt_re_dv_umem** object. The application must not use *umem* with
direct verbs after this call.

# RETURN VALUE

Returns 0.

# SEE ALSO

**bnxt_re_dv**(7),
**bnxt_re_dv_umem_reg**(3)

# AUTHORS

Kalesh AP \<kalesh-anakkur.purayil@broadcom.com\>,
Sriharsha Basavapatna \<sriharsha.basavapatna@broadcom.com\>
