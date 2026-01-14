---
date: 2025-5-8
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_alloc_dmah
---

# NAME

ibv_alloc_dmah - allocate a dma handle

int ibv_dealloc_dmah - deallocate a dma handle

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_dmah *ibv_alloc_dmah(struct ibv_context *context, struct ibv_dmah_init_attr *attr);

int ibv_dealloc_dmah(struct ibv_dmah *dmah);

```

# DESCRIPTION

**ibv_alloc_dmah()** allocates an *ibv_dmah* object that is associated with the given
*context* and the input *attr* parameter.

The allocated handle can be later used for optimizing DMA and RDMA operations associated
with a registered memory region.

Once the *ibv_dmah* usage has been ended *ibv_dealloc_dmah()* should be called.

This call will release resources that were earlier allocated using the **ibv_alloc_dmah()** API.

# ARGUMENTS

## attr

```c

enum ibv_tph_mem_type {
	IBV_TPH_MEM_TYPE_VM, /* volatile memory */
	IBV_TPH_MEM_TYPE_PM, /* persistent memory */
};

enum ibv_dmah_init_attr_mask {
	IBV_DMAH_INIT_ATTR_MASK_CPU_ID = 1 << 0,
	IBV_DMAH_INIT_ATTR_MASK_PH = 1 << 1,
	IBV_DMAH_INIT_ATTR_MASK_TPH_MEM_TYPE = 1 << 2,
};

struct ibv_dmah_init_attr {
	uint32_t comp_mask; /* From ibv_dmah_init_attr_mask */
	uint32_t cpu_id;
	uint8_t ph;
	uint8_t tph_mem_type; /* From enum ibv_tph_mem_type */
};
```
*comp_mask*
:	Bitmask specifying what fields in the structure are valid.

*cpu_id*
:	The cpu id that the dma handle refers to.

*ph*
:	 Processing hints, used to aid in optimizing the handling of transactions over PCIe.

*tph_mem_type*
:	The target memory type, one among *enum ibv_tph_mem_type*.

# RETURN VALUE

**ibv_alloc_dmah()** returns a pointer to the allocated dma handle object, or NULL if the request fails.

**ibv_dealloc_dmah()** returns 0 upon success, otherwise the errno value.

# SEE ALSO

**ibv_reg_mr_ex**(3)

# AUTHOR

Yishai Hadas <yishaih@nvidia.com>
