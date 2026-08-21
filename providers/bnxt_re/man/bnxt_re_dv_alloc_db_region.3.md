---
layout: page
title: bnxt_re_dv_alloc_db_region
section: 3
tagline: Verbs
date: 2025-06-17
header: "Broadcom BNXT-RE Direct Verbs Manual"
footer: bnxt_re
---

# NAME

bnxt_re_dv_alloc_db_region - allocate an additional doorbell region

# SYNOPSIS

```c
#include <infiniband/bnxt_re_dv.h>

struct bnxt_re_dv_db_region_attr *
bnxt_re_dv_alloc_db_region(struct ibv_context *ctx);
```

# DESCRIPTION

**bnxt_re_dv_alloc_db_region**() allocates a new doorbell region for *ctx*.
The kernel returns a doorbell region handle and attributes; the library
memory-maps the doorbell page so the application can post doorbells using the
returned mapping.

The returned pointer must be released with **bnxt_re_dv_free_db_region**(3).

# ARGUMENTS

*ctx*
:   Verbs device context returned by **ibv_open_device**(3). Identifies the
    device instance on which the new doorbell region is allocated.

# RETURN VALUE

On success, returns a pointer to a **struct bnxt_re_dv_db_region_attr**
with all fields filled in:

```c
struct bnxt_re_dv_db_region_attr {
        uint32_t  handle;   /* kernel handle for this doorbell region */
        uint32_t  dpi;      /* doorbell page index */
        uint64_t  umdbr;    /* unmapped doorbell BAR offset */
        uint64_t *dbr;      /* mapped doorbell page (user virtual address) */
};
```

On failure, returns NULL and sets errno.

# SEE ALSO

**bnxt_re_dv**(7),
**bnxt_re_dv_free_db_region**(3),
**bnxt_re_dv_get_default_db_region**(3),
**ibv_open_device**(3)

# AUTHOR

Kalesh AP \<kalesh-anakkur.purayil@broadcom.com\>
