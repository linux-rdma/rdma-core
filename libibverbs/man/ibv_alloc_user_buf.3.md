---
date: 2026-08-19
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_alloc_user_buf
---

# NAME

ibv_alloc_user_buf, ibv_free_user_buf - associate an ibv_buf with
application-owned memory

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_buf *ibv_alloc_user_buf(struct ibv_pd *pd, void *addr, size_t size,
                                   int dmabuf_fd);

void ibv_free_user_buf(struct ibv_buf *buf);
```

# DESCRIPTION

**ibv_alloc_user_buf()** associates an **ibv_buf** with memory the application
already owns, either a plain virtual address range or a DMA-buf. Unlike
**ibv_alloc_buf()**, no memory is allocated; *addr* must already be a valid
virtual address for that memory, and must remain valid for as long as the
returned handle is in use.

**ibv_free_user_buf()** releases a handle returned by
**ibv_alloc_user_buf()**. It does not free or otherwise affect the
underlying memory; only the handle itself and any bookkeeping
**ibv_alloc_user_buf()** performed (such as fork protection) are released.

The returned handle is meant for providers that accept an **ibv_buf**
directly without registering an MR, such as driver-specific control-buffer
descriptors.

**Use of this API is discouraged.** Applications should allocate buffers with
**ibv_alloc_buf()** whenever possible. See NOTES below.

# ARGUMENTS

*pd*
:	Protection domain the buffer is associated with.

*addr*
:	Application-owned virtual address of the buffer.

*size*
:	Size of the buffer in bytes.

*dmabuf_fd*
:	A DMA-buf file descriptor backing the buffer, or -1 if the buffer is
	plain virtual memory at *addr*.

*buf*
:	Handle returned by **ibv_alloc_user_buf()**, to be released with
	**ibv_free_user_buf()**.

# NOTES

**ibv_alloc_buf()** is the preferred way to obtain an **ibv_buf**. Its
allocation is selected by the provider for the protection domain, and therefore
accounts for platform requirements such as confidential computing (CoCo), where
memory may have to be allocated as unprotected/shared memory (see
**IBV_PARENT_DOMAIN_INIT_ATTR_ALLOW_CC_UNPROTECTED_ALLOC** in
**ibv_alloc_parent_domain**(3)).

**ibv_alloc_user_buf()** bypasses this allocator abstraction. Neither
libibverbs nor the provider can verify or adjust memory the application
allocated itself, so the application is solely responsible for ensuring that
the memory is suitable for the device and for the platform it runs on (for
example, that it is usable by the device inside a CoCo guest). The application
generally does not have enough information to guarantee this in a portable
way.

Use this API only when the memory must come from a source that
**ibv_alloc_buf()** cannot provide, such as an existing DMA-buf allocation
shared with another device or subsystem, or memory whose lifetime is managed by
the application. Otherwise, use **ibv_alloc_buf()**.

# RETURN VALUE

**ibv_alloc_user_buf()** returns a buffer handle on success, or NULL if the
request fails.

**ibv_free_user_buf()** does not return a value.

# SEE ALSO

**ibv_alloc_buf**(3),
**ibv_alloc_parent_domain**(3)
