---
date: 2026-08-08
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_create_jkey
---

# NAME

ibv_create_jkey - create a job key

ibv_destroy_jkey - destroy a job key

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_job_key *ibv_create_jkey(struct ibv_pd *pd, struct ibv_job *job,
                                    unsigned int flags);

int ibv_destroy_jkey(struct ibv_job_key *job_key);
```

# DESCRIPTION

A job key binds a job to a protection domain. It JobID is the value carried
on the wire to prove that a transfer belongs to a job, and it bounds which
memory regions that transfer may reach.

The indirection exists so that the JobID itself can stay privileged: a
process is handed a job key rather than the JobID value, and the key is only
meaningful within the protection domain it was created against. See
**ibv_uet**(7).

**ibv_create_jkey()** creates a job key associating *job* with *pd*. The
returned object exposes the key value in its *jkey* member.

**ibv_destroy_jkey()** destroys *job_key*. It fails if a queue pair or
memory region still references the key.

A job key is named on a work request with **ibv_wr_set_job_key**(), or in
the *jkey* member of the *ru* or *ru_rdma* arm of *struct ibv_send_wr*; see
**ibv_wr_post**(3) and **ibv_post_send**(3). It may also be supplied at
queue pair creation through *IBV_QP_INIT_ATTR_JKEY* for receive side
processing with relative addressing, and at memory registration
through *IBV_REG_MR_MASK_JKEY* to restrict a region to the job.
See **ibv_create_qp_ex**(3), **ibv_reg_mr**(3), and **lib_uet**(7).

# ARGUMENTS

## pd

The protection domain the key is created against.

## job

The job to associate with *pd*, as returned by **ibv_alloc_job**(3) or
**ibv_import_job**(3).

## flags

Reserved for future use. MUST be zero.

# RETURN VALUE

**ibv_create_jkey()** returns a pointer to the created job key, or NULL on
failure with *errno* set.

**ibv_destroy_jkey()** returns 0 on success, or the value of *errno* on
failure.

# NOTES

Job keys are supported only by devices reporting *IBV_DEVICE_RU* in
*device_cap_flags_ex*; on other devices these calls fail with EOPNOTSUPP.
The number of job keys a device supports is reported as *max_job_keys* by
**ibv_query_device_ex**(3).

# SEE ALSO

**ibv_alloc_job**(3),
**ibv_create_qp_ex**(3),
**ibv_reg_mr**(3),
**ibv_wr_post**(3),
**ibv_post_send**(3),
**ibv_query_device_ex**(3),
**ibv_uet**(7)

# AUTHOR

Eric Davis <eric.davis@broadcom.com>
