---
date: 2015-01-29
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_INC_RKEY
---

# NAME

ibv_inc_rkey - creates a new rkey from the given one

# SYNOPSIS

```c
#include <infiniband/verbs.h>

uint32_t ibv_inc_rkey(uint32_t rkey);
```

# DESCRIPTION

**ibv_inc_rkey()** Increases the 8 LSB of *rkey* and returns the new value.


# RETURN VALUE

**ibv_inc_rkey()** returns the new rkey.

# NOTES


The verb generates a new rkey that is different from the previous one on its
tag part but has the same index (bits 0xffffff00). A use case for this verb
can be to create a new rkey from a Memory window's rkey when binding it to a
Memory region.

# AUTHORS

Majd Dibbiny <majd@mellanox.com>,
Yishai Hadas <yishaih@mellanox.com>
