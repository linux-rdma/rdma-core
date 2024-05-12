---
layout: page
title: EFADV_CREATE_CQ
section: 3
tagline: Verbs
date: 2021-01-04
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_create_cq - Create EFA specific Completion Queue (CQ)

# SYNOPSIS

```c
#include <infiniband/efadv.h>

struct ibv_cq_ex *efadv_create_cq(struct ibv_context *context,
				  struct ibv_cq_init_attr_ex *attr_ex,
				  struct efadv_cq_init_attr *efa_attr,
				  uint32_t inlen);

static inline int efadv_wc_read_sgid(struct efadv_cq *efadv_cq,
				     union ibv_gid *sgid);
```

# DESCRIPTION

**efadv_create_cq()** creates a Completion Queue (CQ) with specific driver
properties.

The argument attr_ex is an ibv_cq_init_attr_ex struct,
as defined in <infiniband/verbs.h>.

The EFADV work completions APIs (efadv_wc_\*) is an extension for IBV work
completions API (ibv_wc_\*) with efa specific features for polling fields in
the completion. This may be used together with or without ibv_wc_* calls.

Use efadv_cq_from_ibv_cq_ex() to get the efadv_cq for accessing the work
completion interface.

Compatibility is handled using the comp_mask and inlen fields.

```c
struct efadv_cq_init_attr {
	uint64_t comp_mask;
	uint64_t wc_flags;
};
```

*inlen*
:	In: Size of struct efadv_cq_init_attr.

*comp_mask*
:	Compatibility mask.

*wc_flags*
:       A bitwise OR of the various values described below.

	EFADV_WC_EX_WITH_SGID:
		if source AH is unknown, require sgid in WC.

	EFADV_WC_EX_WITH_IS_UNSOLICITED:
		request for an option to check whether a receive WC is unsolicited.


# Completion iterator functions

*efadv_wc_read_sgid*
:	Get the source GID field from the current completion.
	If the AH is known, a negative error value is returned.

*efadv_wc_is_unsolicited*
:	Check whether it's an unsolicited receive completion that has no matching work request.
	This function is available if the CQ was created with EFADV_WC_EX_WITH_IS_UNSOLICITED.


# RETURN VALUE

efadv_create_cq() returns a pointer to the created extended CQ, or NULL if the
request fails.

# SEE ALSO

**efadv**(7), **ibv_create_cq_ex**(3)

# AUTHORS

Daniel Kranzdorf <dkkranzd@amazon.com>
