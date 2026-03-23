---
layout: page
title: bnxt_re_dv_get_default_db_region
section: 3
tagline: Verbs
date: 2025-06-17
header: "Broadcom BNXT-RE Direct Verbs Manual"
footer: bnxt_re
---

# NAME

bnxt_re_dv_get_default_db_region - query the default doorbell region for a context

# SYNOPSIS

```c
#include <infiniband/bnxt_re_dv.h>

int bnxt_re_dv_get_default_db_region(struct ibv_context *ibvctx,
				     struct bnxt_re_dv_db_region_attr *out);
```

# DESCRIPTION

**bnxt_re_dv_get_default_db_region**() fills *out* with the default doorbell page
index (**dpi**), user doorbell base (**umdbr**), and a pointer (**dbr**) to the
user-mapped doorbell page already associated with the **ibv_context**.

Unlike **bnxt_re_dv_alloc_db_region**(3), this does not allocate a new region.

# ARGUMENTS

*out*
:	Output structure; **handle** is not used for the default region; **dbr**,
	**dpi**, and **umdbr** are valid on success.
	For the definition of **struct bnxt_re_dv_db_region_attr** and its members, see
	**bnxt_re_dv_alloc_db_region**(3).

# RETURN VALUE

Returns 0 on success, or a negative error code on failure.

# SEE ALSO

**bnxt_re_dv**(7),
**bnxt_re_dv_alloc_db_region**(3),
**bnxt_re_dv_free_db_region**(3),
**ibv_open_device**(3)

# AUTHOR

Kalesh AP \<kalesh-anakkur.purayil@broadcom.com\>
