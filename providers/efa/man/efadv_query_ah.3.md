---
layout: page
title: EFADV_QUERY_AH
section: 3
tagline: Verbs
date: 2019-05-19
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_query_ah - Query EFA specific Address Handle attributes

# SYNOPSIS

```c
#include <infiniband/efadv.h>

int efadv_query_ah(struct ibv_ah *ibvah, struct efadv_ah_attr *attr,
		   uint32_t inlen);
```

# DESCRIPTION

**efadv_query_ah()** queries device-specific Address Handle attributes.

Compatibility is handled using the comp_mask and inlen fields.

```c
struct efadv_ah_attr {
	uint64_t comp_mask;
	uint16_t ahn;
	uint8_t reserved[6];
};
```

*inlen*
:	In: Size of struct efadv_ah_attr.

*comp_mask*
:	Compatibility mask.

*ahn*
:	Device's Address Handle number.

# RETURN VALUE

**efadv_query_ah()** returns 0 on success, or the value of errno on failure
(which indicates the failure reason).

# SEE ALSO

**efadv**(7)

# NOTES

* Compatibility mask (comp_mask) is an out field and currently has no values.

# AUTHORS

Gal Pressman <galpress@amazon.com>
