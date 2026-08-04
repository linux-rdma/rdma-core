---
layout: page
title: EFADV_CREATE_COMP_CNTR
section: 3
tagline: Verbs
date: 2026-04-27
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_create_comp_cntr - Create EFA specific Completion Counter

# SYNOPSIS

```c
#include <infiniband/efadv.h>

struct ibv_comp_cntr *efadv_create_comp_cntr(struct ibv_context *context,
					     struct ibv_comp_cntr_init_attr *attr,
					     struct efadv_comp_cntr_init_attr *efa_attr,
					     uint32_t inlen);
```

# DESCRIPTION

**efadv_create_comp_cntr()** creates a Completion Counter with EFA specific
properties, such as external memory for the counter values.

The argument *attr* is an ibv_comp_cntr_init_attr struct, as defined in
<infiniband/verbs.h>.

Compatibility is handled using the comp_mask and inlen fields.

```c
enum {
	EFADV_MEMORY_LOCATION_VA,
	EFADV_MEMORY_LOCATION_DMABUF,
};

struct efadv_memory_location {
	uint8_t *ptr;
	struct {
		uint64_t offset;
		int32_t fd;
		uint32_t reserved;
	} dmabuf;
	uint8_t type;
	uint8_t reserved[7];
};

struct efadv_comp_cntr_init_attr {
	uint64_t comp_mask;
	uint32_t flags;
	uint32_t reserved;
	struct efadv_memory_location comp_cntr_ext_mem;
	struct efadv_memory_location err_cntr_ext_mem;
};
```

*inlen*
:	In: Size of struct efadv_comp_cntr_init_attr.

*comp_mask*
:	Compatibility mask.

*flags*
:	A bitwise OR of the various values described below.

	**EFADV_COMP_CNTR_INIT_WITH_COMP_EXTERNAL_MEM**:
		Use application-provided memory for the completion count, as
		described by *comp_cntr_ext_mem*.

	**EFADV_COMP_CNTR_INIT_WITH_ERR_EXTERNAL_MEM**:
		Use application-provided memory for the error count, as
		described by *err_cntr_ext_mem*.

*comp_cntr_ext_mem*
:	Memory location for the completion count when using external memory.

*err_cntr_ext_mem*
:	Memory location for the error count when using external memory.

## efadv_memory_location

The external memory is described by an **efadv_memory_location** structure
which supports two modes:

*type*
:	**EFADV_MEMORY_LOCATION_VA** for a virtual address, or
	**EFADV_MEMORY_LOCATION_DMABUF** for a DMA-BUF reference.

*ptr*
:	Virtual address pointer. Required when type is
	**EFADV_MEMORY_LOCATION_VA**. When type is
	**EFADV_MEMORY_LOCATION_DMABUF**, may optionally be set to provide a
	process-accessible mapping of the DMA-BUF memory.

*dmabuf.fd*
:	DMA-BUF file descriptor (used when type is
	**EFADV_MEMORY_LOCATION_DMABUF**).

*dmabuf.offset*
:	Offset within the DMA-BUF.

# RETURN VALUE

efadv_create_comp_cntr() returns a pointer to the created ibv_comp_cntr, or
NULL if the request fails.

# SEE ALSO

**efadv**(7), **ibv_create_comp_cntr**(3), **ibv_qp_attach_comp_cntr**(3)

# AUTHORS

Michael Margolin <mrgolin@amazon.com>
