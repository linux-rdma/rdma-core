---
layout: page
title: mlx5dv_devx_qp[/cq/srq/wq/ind_tbl]_modify / query
section: 3
tagline: Verbs
---

# NAME

mlx5dv_devx_qp_modify -  Modifies a verbs QP via DEVX

mlx5dv_devx_qp_query -   Queries a verbs QP via DEVX

mlx5dv_devx_cq_modify -  Modifies a verbs CQ via DEVX

mlx5dv_devx_cq_query -   Queries a verbs CQ via DEVX

mlx5dv_devx_srq_modify -  Modifies a verbs SRQ via DEVX

mlx5dv_devx_srq_query -   Queries a verbs SRQ via DEVX

mlx5dv_devx_wq_modify -  Modifies a verbs WQ via DEVX

mlx5dv_devx_wq_query -   Queries a verbs WQ via DEVX

mlx5dv_devx_ind_tbl_modify -  Modifies a verbs indirection table via DEVX

mlx5dv_devx_ind_tbl_query -   Queries a verbs indirection table via DEVX

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>
int mlx5dv_devx_qp_modify(struct ibv_qp *qp, const void *in, size_t inlen,
                          void *out, size_t outlen);
int mlx5dv_devx_qp_query(struct ibv_qp *qp, const void *in, size_t inlen,
                         void *out, size_t outlen);
int mlx5dv_devx_cq_modify(struct ibv_cq *cq, const void *in, size_t inlen,
                          void *out, size_t outlen);
int mlx5dv_devx_cq_query(struct ibv_cq *cq, const void *in, size_t inlen,
                         void *out, size_t outlen);
int mlx5dv_devx_srq_modify(struct ibv_srq *srq, const void *in, size_t inlen,
                           void *out, size_t outlen);
int mlx5dv_devx_srq_query(struct ibv_srq *srq, const void *in, size_t inlen,
                          void *out, size_t outlen);
int mlx5dv_devx_wq_modify(struct ibv_wq *wq, const void *in, size_t inlen,
                          void *out, size_t outlen);
int mlx5dv_devx_wq_query(struct ibv_wq *wq, const void *in, size_t inlen,
                         void *out, size_t outlen);
int mlx5dv_devx_ind_tbl_modify(struct ibv_rwq_ind_table *ind_tbl,
                               const void *in, size_t inlen,
                               void *out, size_t outlen);
int mlx5dv_devx_ind_tbl_query(struct ibv_rwq_ind_table *ind_tbl,
                              const void *in, size_t inlen,
                              void *out, size_t outlen);
```

# DESCRIPTION

Modify / query a verb object over the DEVX interface.

The DEVX API enables direct access from the user space area to the mlx5 device
driver by using the KABI mechanism.  The main purpose is to make the user
space driver as independent as possible from the kernel so that future device
functionality and commands can be activated with minimal to none kernel changes.

The above APIs enables modifying/querying a verb object via the DEVX interface.
This enables interoperability between verbs and DEVX.  As such an application
can use the create method from verbs (e.g. ibv_create_qp) and modify and query the created
object via DEVX (e.g. mlx5dv_devx_qp_modify).

# ARGUMENTS
*qp/cq/wq/srq/ind_tbl*
:	The ibv_xxx object to issue the action on.

*in*
:	A buffer which contains the command's input data provided in a device specification format.

*inlen*
:	The size of *in* buffer in bytes.

*out*
:	 A buffer which contains the command's output data according to the device specification format.

*outlen*
:	The size of *out* buffer in bytes.


# RETURN VALUE

Upon success 0 is returned or the value of errno on a failure.

# SEE ALSO

**mlx5dv_open_device**, **mlx5dv_devx_obj_create**

#AUTHOR

Yishai Hadas  <yishaih@mellanox.com>
