---
date: 2019-02-24
footer: mlx5
header: "mlx5 Programmer's Manual"
tagline: Verbs
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: MLX5DV_WR
---

# NAME

mlx5dv_wr_set_dc_addr - Attach a DC info to the last work request

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

static inline void mlx5dv_wr_set_dc_addr(struct mlx5dv_qp_ex *mqp,
                                         struct ibv_ah *ah,
                                         uint32_t remote_dctn,
                                         uint64_t remote_dc_key);
```

# DESCRIPTION

The MLX5DV work request APIs (mlx5dv_wr_\*) is an extension for IBV work
request API (ibv_wr_\*) with mlx5 specific features for send work request.
This may be used together with or without ibv_wr_* calls.

# USAGE

To use these APIs a QP must be created using mlx5dv_create_qp() with
*send_ops_flags* of struct ibv_qp_init_attr_ex set.

If the QP does not support all the requested work request types then QP
creation will fail.

The mlx5dv_qp_ex is extracted from the IBV_QP by ibv_qp_to_qp_ex() and
mlx5dv_qp_ex_from_ibv_qp_ex(). This should be used to apply the mlx5 specific
features on the posted WR.

A work request creation requires to use the ibv_qp_ex as described in the
man for ibv_wr_post and mlx5dv_qp with its available builders and setters.

## QP Specific setters

*DCI* QPs
:   *mlx5dv_wr_set_dc_addr()* must be called to set the DCI WR properties. The
    destination address of the work is specified by *ah*, the remote DCT
    number is specified by *remote_dctn* and the DC key is specified by
    *remote_dc_key*.
    This setter is available when the QP transport is DCI and send_ops_flags
    in struct ibv_qp_init_attr_ex is set.
    The available builders and setters for DCI QP are the same as RC QP.

# EXAMPLE

```c
/* create DC QP type and specify the required send opcodes */
attr_ex.qp_type = IBV_QPT_DRIVER;
attr_ex.comp_mask |= IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
attr_ex.send_ops_flags |= IBV_QP_EX_WITH_RDMA_WRITE;

attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_DC;
attr_dv.dc_init_attr.dc_type = MLX5DV_DCTYPE_DCI;

ibv_qp *qp = mlx5dv_create_qp(ctx, attr_ex, attr_dv);
ibv_qp_ex *qpx = ibv_qp_to_qp_ex(qp);
mlx5dv_qp_ex *mqpx = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);

ibv_wr_start(qpx);

/* Use ibv_qp_ex object to set WR generic attributes */
qpx->wr_id = my_wr_id_1;
qpx->wr_flags = IBV_SEND_SIGNALED;
ibv_wr_rdma_write(qpx, rkey, remote_addr_1);
ibv_wr_set_sge(qpx, lkey, local_addr_1, length_1);

/* Use mlx5 DC setter using mlx5dv_qp_ex object */
mlx5dv_wr_set_wr_dc_addr(mqpx, ah, remote_dctn, remote_dc_key);

ret = ibv_wr_complete(qpx);
```

# SEE ALSO

**ibv_post_send**(3), **ibv_create_qp_ex(3)**, **ibv_wr_post(3)**.

# AUTHOR

Guy Levi <guyle@mellanox.com>
