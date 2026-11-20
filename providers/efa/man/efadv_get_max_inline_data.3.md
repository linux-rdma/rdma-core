---
layout: page
title: EFADV_GET_MAX_INLINE_DATA
section: 3
tagline: Verbs
date: 2026-09-08
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_get_max_inline_data - Get EFA max inline data size based on QP creation attributes

# SYNOPSIS

```c
#include <infiniband/efadv.h>

int efadv_get_max_inline_data(struct ibv_context *ibvctx,
			      struct efadv_inline_data_attr *attr, uint32_t inlen);
```

# DESCRIPTION

**efadv_get_max_inline_data()** returns the largest *max_inline_data* a QP can
be created with, by **ibv_create_qp_ex**(3) or **efadv_create_qp_ex**(3), for the
given EFA attributes. Features that reserve space in the WQE, such as completion
actions, reduce the inline data size, so the value depends on the flags the QP
is created with.

Compatibility is handled using the comp_mask and inlen fields.

```c
struct efadv_inline_data_attr {
	uint64_t comp_mask;
	uint32_t flags;
	uint8_t reserved[4];
};
```

*inlen*
:	In: Size of struct efadv_inline_data_attr.

*comp_mask*
:	Compatibility mask.

*flags*
:	A bitwise OR of the values described below.

	EFADV_INLINE_DATA_ATTR_COMP_ACTION_WITH_DATA:
		The QP will be created with completion actions enabled, see
		**efadv_create_qp_ex**(3).

# RETURN VALUE

**efadv_get_max_inline_data()** returns the maximum inline data size in bytes on
success, or the negative value of errno on failure (which indicates the failure
reason).

# SEE ALSO

**efadv**(7), **efadv_create_qp_ex**(3), **efadv_get_max_sq_depth**(3)

# AUTHORS

Ilia Kolominsky <ikolomin@amazon.com>
