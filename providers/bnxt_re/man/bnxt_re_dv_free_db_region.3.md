---
layout: page
title: bnxt_re_dv_free_db_region
section: 3
tagline: Verbs
date: 2025-06-17
header: "Broadcom BNXT-RE Direct Verbs Manual"
footer: bnxt_re
---

# NAME

bnxt_re_dv_free_db_region - free a doorbell region allocated with bnxt_re_dv_alloc_db_region

# SYNOPSIS

```c
#include <infiniband/bnxt_re_dv.h>

int bnxt_re_dv_free_db_region(struct ibv_context *ctx,
			      struct bnxt_re_dv_db_region_attr *attr);
```

# DESCRIPTION

**bnxt_re_dv_free_db_region**() unmmaps the doorbell page, requests the driver to
free the region identified by *attr*, and frees the **bnxt_re_dv_db_region_attr**
structure.

*attr* must be the pointer returned by **bnxt_re_dv_alloc_db_region**(3) for the
same *ctx*.

# RETURN VALUE

Returns 0 on success. On ioctl failure returns a non-zero error value and sets
**errno** to that value.

# SEE ALSO

**bnxt_re_dv**(7),
**bnxt_re_dv_alloc_db_region**(3),
**bnxt_re_dv_get_default_db_region**(3)

# AUTHOR

Kalesh AP \<kalesh-anakkur.purayil@broadcom.com\>
