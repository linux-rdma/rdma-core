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

ibv_alloc_buf, ibv_free_buf, ibv_reg_buf_mr - allocate provider-aware buffers and register them as memory regions

# SYNOPSIS

```c
#include <infiniband/verbs.h>

void *ibv_alloc_buf(struct ibv_pd *pd, size_t size, struct ibv_buf **buf);

void ibv_free_buf(struct ibv_buf *buf);

struct ibv_mr *ibv_reg_buf_mr(struct ibv_pd *pd, struct ibv_buf *buf, void *addr,
                              size_t length, int access);
```

# DESCRIPTION

**ibv_alloc_buf()** allocates a buffer using the allocation method selected by
the provider for the protection domain *pd*. On success it returns the mapped
address and stores an opaque buffer handle in *buf*. The handle is used by
**ibv_free_buf()**, **ibv_reg_buf_mr()**, and **ibv_reg_mr_ex()** with
**IBV_REG_MR_MASK_BUF**, and must not be interpreted by applications.

**ibv_free_buf()** releases a buffer handle returned by **ibv_alloc_buf()**. The
protection domain used for allocation must remain valid until the buffer is
freed.

**ibv_reg_buf_mr()** registers a memory region for a buffer returned by
**ibv_alloc_buf()**. Applications can register the same buffer through
**ibv_reg_mr_ex()** by setting both **IBV_REG_MR_MASK_BUF** and
**IBV_REG_MR_MASK_ADDR**, passing the buffer handle in `mr_init_attr->buf` and
the address to register in `mr_init_attr->addr`. When **IBV_REG_MR_MASK_BUF**
is set the caller must not set **IBV_REG_MR_MASK_FD** or
**IBV_REG_MR_MASK_FD_OFFSET**, and, for a DMA-buf backed buffer, must not set
**IBV_REG_MR_MASK_IOVA**; libibverbs derives these from the buffer handle and
otherwise fails with **EINVAL**. The *pd* argument must be
the same protection domain that was used to allocate the buffer.
If a different protection domain is supplied, registration fails
with **EINVAL**. For ordinary memory it behaves like **ibv_reg_mr()**.
For provider allocations backed by a DMA-buf, it registers
the corresponding DMA-buf range using the metadata stored in
the opaque *buf* handle.

# ARGUMENTS

*pd*
:	For **ibv_alloc_buf()**, the protection domain (or parent domain) to allocate from; its provider selects the buffer's backing allocation method. It must remain valid until the buffer is freed with **ibv_free_buf()**. For **ibv_reg_buf_mr()**, the same protection domain that allocated *buf* (otherwise registration fails with **EINVAL**).

*size*
:	Size of the buffer to allocate, in bytes (**ibv_alloc_buf()**).

*buf*
:	For **ibv_alloc_buf()**, an output parameter set on success to an opaque buffer handle. For **ibv_free_buf()** and **ibv_reg_buf_mr()**, the buffer handle returned by **ibv_alloc_buf()** to be released or registered, respectively.

*addr*
:	The start address to register (**ibv_reg_buf_mr()**): the buffer base returned by **ibv_alloc_buf()** or an address within that buffer.

*length*
:	Length in bytes to register (**ibv_reg_buf_mr()**); *addr* + *length* must stay within the buffer.

*access*
:	Access flags for the memory region (**ibv_reg_buf_mr()**), the same as for **ibv_reg_mr()**.

# RETURN VALUE

**ibv_alloc_buf()** returns the mapped buffer address on success, or NULL if the
request fails.

**ibv_reg_buf_mr()** returns a pointer to the registered MR on success, or NULL
if the request fails.

**ibv_free_buf()** does not return a value.

# SEE ALSO

**ibv_reg_mr**(3),
**ibv_reg_mr_ex**(3),
**ibv_reg_dmabuf_mr**(3)
