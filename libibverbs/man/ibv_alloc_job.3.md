---
date: 2026-08-08
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_alloc_job
---

# NAME

ibv_alloc_job - allocate a job

ibv_dealloc_job - deallocate a job

ibv_query_job - query the attributes of a job

ibv_export_job - export a job so another process may import it

ibv_import_job - import a job exported by another process

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_job *ibv_alloc_job(struct ibv_context *context,
                              struct ibv_job_attr *attr, void *user_context);

int ibv_dealloc_job(struct ibv_job *job);

int ibv_query_job(struct ibv_job *job, struct ibv_job_attr *attr);

int ibv_export_job(struct ibv_job *job, int *fd);

int ibv_import_job(struct ibv_context *context, int fd, struct ibv_job **job);
```

# DESCRIPTION

An Ultra Ethernet job identifies a distributed application. Every endpoint
that may communicate with a given peer belongs to the same job as that peer,
and a transfer arriving from a different job is rejected by the receiver.

A job is a device-level object that may be shared between processes.
Configuring one is a privileged operation, so an unprivileged process
normally imports a job that a privileged process has already allocated, and
is given a job key rather than the JobID value itself. See **ibv_uet**(7)
for the wider model and **ibv_create_jkey**(3) for job keys.

**ibv_alloc_job()** allocates a job on the device associated with *context*,
using the attributes in *attr*. The *user_context* pointer is recorded in
the returned object and is not interpreted by the library.

**ibv_dealloc_job()** deallocates a *job*. It fails if any job key, queue
pair or memory region still references the job.

**ibv_query_job()** returns the current attributes of a *job* in *attr*. The
caller sets *attr->comp_mask* to the attributes it wants returned, and on
return *attr->comp_mask* reports the attributes actually filled in.

**ibv_export_job()** returns in *fd* a file descriptor representing a *job*,
which may be passed to another process by any mechanism that transfers file
descriptors. The caller closes the descriptor once it has been transferred.

**ibv_import_job()** creates in a *job* a reference to the job represented by
*fd*, associated with *context*. The imported job must be released with
**ibv_dealloc_job()**, which releases only the importing process's
reference.

# ARGUMENTS

## attr

```c
struct ibv_job_attr {
	uint32_t comp_mask;
	unsigned int flags;
	uint32_t id;
	uint32_t max_addr_entries;
	uint32_t port_num;
	uint8_t sgid_index;
};
```

*comp_mask*
:	Bitmask from *enum ibv_job_attr_mask* selecting which of the following
	members are valid. On allocation it selects the members the caller has
	set; on query it selects the members the caller wants returned, and is
	overwritten with those actually returned.

*flags*
:	Reserved for future use. Selected by *IBV_JOB_ATTR_FLAGS* and MUST be
	zero.

*id*
:	The JobID. Selected by *IBV_JOB_ATTR_ID*.

*max_addr_entries*
:	Number of entries in the job address table. Selected by
	*IBV_JOB_ATTR_MAX_ADDR_ENTRIES*, and MUST NOT exceed the
	*max_addr_entries* limit reported by **ibv_query_device_ex**(3). See
	**ibv_insert_addr**(3).

*port_num*
:	Device port the job is associated with. Selected by
	*IBV_JOB_ATTR_PORT_NUM*.

*sgid_index*
:	Index into the port's GID table giving the source address of endpoints
	in this job. Selected by *IBV_JOB_ATTR_SGID_INDEX*. The GID type
	determines the address family used on the wire; see
	**ibv_query_gid_ex**(3).

## user_context

Opaque pointer stored in the returned *struct ibv_job* and returned to the
caller in its *user_context* member.

# RETURN VALUE

**ibv_alloc_job()** returns a pointer to the allocated job, or NULL on
failure with *errno* set.

**ibv_dealloc_job()**, **ibv_query_job()**, **ibv_export_job()** and
**ibv_import_job()** return 0 on success, or the value of *errno* on
failure.

# NOTES

Jobs are supported only by devices reporting *IBV_DEVICE_RU* in
*device_cap_flags_ex*; on other devices these calls fail with EOPNOTSUPP.
The number of jobs a device supports is reported as *max_job_ids* by
**ibv_query_device_ex**(3).

# SEE ALSO

**ibv_create_jkey**(3),
**ibv_insert_addr**(3),
**ibv_query_device_ex**(3),
**ibv_query_gid_ex**(3),
**ibv_create_qp_ex**(3),
**ibv_uet**(7)

# AUTHOR

Eric Davis <eric.davis@broadcom.com>
