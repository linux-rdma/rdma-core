---
layout: page
title: manadv_init_obj
section: 3
tagline: Verbs
---

# NAME
manadv_init_obj \- Initialize mana direct verbs object from ibv_xxx structures

# SYNOPSIS"
```c
#include <infiniband/manadv.h>

int manadv_init_obj(struct manadv_obj *obj, uint64_t obj_type);
```

# DESCRIPTION
manadv_init_obj()
This function will initialize manadv_xxx structs based on supplied type. The information
for initialization is taken from ibv_xx structs supplied as part of input.

# ARGUMENTS
*obj*
:	The manadv_xxx structs be to returned.

```c
struct manadv_qp {
	void		*sq_buf;
	uint32_t	sq_count;
	uint32_t	sq_size;
	uint32_t	sq_id;
	uint32_t	tx_vp_offset;
	void		*db_page;
};

struct manadv_cq {
	void		*buf;
	uint32_t	count;
	uint32_t	cq_id;
};

struct manadv_rwq {
	void		*buf;
	uint32_t	count;
	uint32_t	size;
	uint32_t	wq_id;
	void		*db_page;
};

struct manadv_obj {
	struct {
		struct ibv_qp		*in;
		struct manadv_qp	*out;
	} qp;

	struct {
		struct ibv_cq		*in;
		struct manadv_cq	*out;
	} cq;

	struct {
		struct ibv_wq		*in;
		struct manadv_rwq	*out;
	} rwq;
};
```

*obj_type*
:	The types of the manadv_xxx structs to be returned.

```c
enum manadv_obj_type {
	MANADV_OBJ_QP   = 1 << 0,
	MANADV_OBJ_CQ   = 1 << 1,
	MANADV_OBJ_RWQ  = 1 << 2,
};
```
# RETURN VALUE
0 on success or the value of errno on failure (which indicates the failure reason).

# AUTHORS
Long Li <longli@microsoft.com>
