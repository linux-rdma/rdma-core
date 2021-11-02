---
layout: page
title: manadv_set_context_attr
section: 3
tagline: Verbs
---

# NAME
manadv_set_context_attr - Set context attributes

# SYNOPSIS
```c
#include <infiniband/manadv.h>

int manadv_set_context_attr(struct ibv_context *context,
                            enum manadv_set_ctx_attr_type attr_type,
                            void *attr);
```

# DESCRIPTION
manadv_set_context_attr gives the ability to set vendor specific attributes on
the RDMA context.

# ARGUMENTS
*context*
:	RDMA device context to work on.

*attr_type*
:	The type of the provided attribute.

*attr*
:	Pointer to the attribute to be set.

## attr_type
```c
enum manadv_set_ctx_attr_type {
	/* Attribute type uint8_t */
	MANADV_SET_CTX_ATTR_BUF_ALLOCATORS = 0,
};
```
*MANADV_SET_CTX_ATTR_BUF_ALLOCATORS*
:	Provide an external buffer allocator

```c
struct manadv_ctx_allocators {
	void *(*alloc)(size_t size, void *priv_data);
	void (*free)(void *ptr, void *priv_data);
	void *data;
};
```
*alloc*
:	Function used for buffer allocation instead of libmana internal method

*free*
:	Function used to free buffers allocated by alloc function

*data*
:	Metadata that can be used by alloc and free functions

# RETURN VALUE
Returns 0 on success, or the value of errno on failure
(which indicates the failure reason).

# AUTHOR
Long Li <longli@microsoft.com>
