---
date: 2026-05-29
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_alloc_buf
---

# NAME

ibv_alloc_buf, ibv_free_buf - allocate and free provider-aware buffers

# SYNOPSIS

```c
#include <infiniband/verbs.h>

void *ibv_alloc_buf(struct ibv_pd *pd, size_t size, struct ibv_buf **buf);

void ibv_free_buf(struct ibv_buf *buf);
```

# DESCRIPTION

**ibv_alloc_buf()** allocates a buffer using the allocation method selected by
the provider for the protection domain *pd*. On success it returns the mapped
address and stores an opaque buffer handle in *buf*. The handle is used by
**ibv_free_buf()** and must not be interpreted by applications.

# ARGUMENTS

*pd*
:	The protection domain (or parent domain) to allocate from; its provider selects the buffer's backing allocation method. It must remain valid until the buffer is freed with **ibv_free_buf()**.

*size*
:	Size of the buffer to allocate, in bytes.

*buf*
:	For **ibv_alloc_buf()**, an output parameter set on success to an opaque buffer handle. For **ibv_free_buf()**, the buffer handle returned by **ibv_alloc_buf()** that is to be released.

# RETURN VALUE

**ibv_alloc_buf()** returns the mapped buffer address on success, or NULL if the
request fails.

**ibv_free_buf()** does not return a value.
