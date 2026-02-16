---
date: 2026-02-09
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_create_comp_cntr
tagline: Verbs
---

# NAME

**ibv_create_comp_cntr**, **ibv_destroy_comp_cntr** - Create or destroy a
completion counter

**ibv_set_comp_cntr**, **ibv_set_err_comp_cntr** - Set the value of a
completion or error counter

**ibv_inc_comp_cntr**, **ibv_inc_err_comp_cntr** - Increment a completion or
error counter

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_comp_cntr *ibv_create_comp_cntr(struct ibv_context *context,
                                           struct ibv_comp_cntr_init_attr *cc_attr);

int ibv_destroy_comp_cntr(struct ibv_comp_cntr *comp_cntr);

int ibv_set_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t value);
int ibv_set_err_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t value);
int ibv_inc_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t amount);
int ibv_inc_err_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t amount);
```

# DESCRIPTION

Completion counters provide a lightweight completion mechanism as an
alternative or extension to completion queues (CQs). Rather than generating
individual completion queue entries, a completion counter tracks the aggregate
number of completed operations. This makes them well suited for applications
that need to know how many requests have completed without requiring
per-request details, such as credit based flow control or tracking responses
from remote peers.

Each completion counter maintains two distinct 64-bit values: a completion
count that is incremented on successful completions, and an error count that
is incremented when operations complete in error.

**ibv_create_comp_cntr**() allocates a new completion counter for the RDMA
device context *context*. The properties of the counter are defined by
*cc_attr*. On success, the returned **ibv_comp_cntr** structure contains
pointers to the completion and error count values. The maximum number of
completion counters a device supports is reported by the *max_comp_cntr*
field of **ibv_device_attr_ex**.

**ibv_destroy_comp_cntr**() releases all resources associated with the
completion counter *comp_cntr*. The counter must not be attached to any QP
when destroyed.

**ibv_set_comp_cntr**() sets the completion count of *comp_cntr* to *value*.

**ibv_set_err_comp_cntr**() sets the error count of *comp_cntr* to *value*.

**ibv_inc_comp_cntr**() increments the completion count of *comp_cntr* by
*amount*.

**ibv_inc_err_comp_cntr**() increments the error count of *comp_cntr* by
*amount*.

## External memory

By default, the memory backing the counter values is allocated internally.
When the **IBV_COMP_CNTR_INIT_WITH_EXTERNAL_MEM** flag is set in
*ibv_comp_cntr_init_attr.flags*, the application provides its own memory for
the completion and error counts via the *comp_cntr_ext_mem* and
*err_cntr_ext_mem* fields. The external memory is described by an
**ibv_memory_location** structure which supports two modes: a virtual address
(**IBV_MEMORY_LOCATION_VA**), where the application supplies a direct pointer, or
a DMA-BUF reference (**IBV_MEMORY_LOCATION_DMABUF**), where the application
supplies a file descriptor and offset into an exported DMA-BUF. When using
DMA-BUF, the *ptr* field may also be set to provide a process-accessible
mapping of the memory; if provided, the *comp_count* and *err_count* pointers
in the returned **ibv_comp_cntr** will point to it. Using external memory
allows the counter values to reside in application-managed buffers or in
memory exported through DMA-BUF, enabling zero-copy observation of completion
progress by co-located processes or devices.

# ARGUMENTS

## ibv_comp_cntr

```c
struct ibv_comp_cntr {
	struct ibv_context *context;
	uint32_t handle;
	uint64_t *comp_count;
	uint64_t *err_count;
	uint64_t comp_count_max_value;
	uint64_t err_count_max_value;
};
```

*context*
:	Device context associated with the completion counter.

*handle*
:	Kernel object handle for the completion counter.

*comp_count*
:	Pointer to the current successful completion count. When the counter
	is backed by CPU-accessible memory, this pointer may be read directly
	by the application.

*err_count*
:	Pointer to the current error completion count. When the counter is
	backed by CPU-accessible memory, this pointer may be read directly
	by the application.

*comp_count_max_value*
:	The maximum value the completion count can hold. A subsequent
	increment that would exceed this value wraps the counter to zero.

*err_count_max_value*
:	The maximum value the error count can hold. A subsequent increment
	that would exceed this value wraps the counter to zero.

## ibv_comp_cntr_init_attr

```c
struct ibv_comp_cntr_init_attr {
	uint32_t comp_mask;
	uint32_t flags;
	struct ibv_memory_location comp_cntr_ext_mem;
	struct ibv_memory_location err_cntr_ext_mem;
};
```

*comp_mask*
:	Bitmask specifying what fields in the structure are valid.

*flags*
:	Creation flags. The following flags are supported:

	**IBV_COMP_CNTR_INIT_WITH_EXTERNAL_MEM** - Use application-provided
	memory for the counter values, as specified by *comp_cntr_ext_mem*
	and *err_cntr_ext_mem*.

*comp_cntr_ext_mem*
:	Memory location for the completion count when using external memory.

*err_cntr_ext_mem*
:	Memory location for the error count when using external memory.

## ibv_memory_location

```c
enum ibv_memory_location_type {
	IBV_MEMORY_LOCATION_VA,
	IBV_MEMORY_LOCATION_DMABUF,
};

struct ibv_memory_location {
	uint8_t *ptr;
	struct {
		uint64_t offset;
		int32_t fd;
		uint32_t reserved;
	} dmabuf;
	uint8_t type;
	uint8_t reserved[7];
};
```

*type*
:	The type of memory location. **IBV_MEMORY_LOCATION_VA** for a virtual
	address, or **IBV_MEMORY_LOCATION_DMABUF** for a DMA-BUF reference.

*ptr*
:	Virtual address pointer. Required when type is
	**IBV_MEMORY_LOCATION_VA**. When type is
	**IBV_MEMORY_LOCATION_DMABUF**, may optionally be set to provide a
	process-accessible mapping of the DMA-BUF memory.

*dmabuf.fd*
:	DMA-BUF file descriptor (used when type is
	**IBV_MEMORY_LOCATION_DMABUF**).

*dmabuf.offset*
:	Offset within the DMA-BUF.

# RETURN VALUE

**ibv_create_comp_cntr**() returns a pointer to the allocated ibv_comp_cntr
object, or NULL if the request fails (and sets errno to indicate the failure
reason).

**ibv_destroy_comp_cntr**(), **ibv_set_comp_cntr**(),
**ibv_set_err_comp_cntr**(), **ibv_inc_comp_cntr**(), and
**ibv_inc_err_comp_cntr**() return 0 on success, or the value of errno on
failure (which indicates the failure reason).

# ERRORS

ENOTSUP
:	Completion counters are not supported on this device.

ENOMEM
:	Not enough resources to create the completion counter.

EINVAL
:	Invalid argument(s) passed.

EBUSY
:	The completion counter is still attached to a QP
	(**ibv_destroy_comp_cntr**() only).

# NOTES

Counter values should not be modified directly by writing to the memory
pointed to by *comp_count* or *err_count*. Applications must use the provided
API functions (**ibv_set_comp_cntr**(), **ibv_set_err_comp_cntr**(),
**ibv_inc_comp_cntr**(), **ibv_inc_err_comp_cntr**()) to update counter
values.

Updates made to counter values (e.g. via **ibv_set_comp_cntr**() or
**ibv_inc_comp_cntr**()) may not be immediately visible when reading the
counter. A small delay may occur between the update and the observed value.
However, the final updated value will eventually be reflected.

Applications should ensure that the counter value is stable before calling
**ibv_set_comp_cntr**() or **ibv_set_err_comp_cntr**(). Otherwise, concurrent
updates may be lost.

# SEE ALSO

**ibv_qp_attach_comp_cntr**(3), **ibv_create_cq**(3),
**ibv_create_cq_ex**(3), **ibv_create_qp**(3)

# AUTHORS

Michael Margolin <mrgolin@amazon.com>
