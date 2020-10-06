---
layout: page
title: mlx5dv_wr_mkey_configure
section: 3
tagline: Verbs
---

# NAME

mlx5dv_wr_mkey_configure - Create a work request to configure an MKEY

mlx5dv_wr_set_mkey_access_flags - Set the memory protection attributes
for an MKEY

mlx5dv_wr_set_mkey_layout_list - Set a memory layout for an MKEY based
on SGE list

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

static inline void mlx5dv_wr_mkey_configure(struct mlx5dv_qp_ex *mqp,
                                            struct mlx5dv_mkey *mkey,
                                            uint8_t num_setters,
                                            struct mlx5dv_mkey_conf_attr *attr);

static inline void mlx5dv_wr_set_mkey_access_flags(struct mlx5dv_qp_ex *mqp,
                                                   uint32_t access_flags);

static inline void mlx5dv_wr_set_mkey_layout_list(struct mlx5dv_qp_ex *mqp,
                                                  uint16_t num_sges,
                                                  const struct ibv_sge *sge);
```

# DESCRIPTION

The MLX5DV MKEY configure API and the related setters (mlx5dv_wr_set_mkey\*)
are an extension of IBV work request API (ibv_wr\*) with specific features for
MLX5DV MKEY.

MKEYs allow creation of virtually-contiguous address spaces out of
non-contiguous chunks of memory regions already registered with the hardware.
Additionally it provides access to some advanced hardware offload features, e.g.
signature offload.

These APIs are intended to be used to access additional functionality beyond
what is provided by **mlx5dv_wr_mr_list**() and **mlx5dv_wr_mr_interleaved**().
The MKEY features can be optionally enabled using the mkey configure setters.
It allows to use different features in the same MKEY.

# USAGE

To use these APIs a QP must be created using **mlx5dv_create_qp**(3) which
allows setting the **MLX5DV_QP_EX_WITH_MKEY_CONFIGURE** in **send_ops_flags**.

The MKEY configuration work request is created by calling
**mlx5dv_wr_mkey_configure**(), a WR builder function, followed by required
setter functions. *num_setters* is a number of required setters for the WR. All
setters are optional. *num_setters* can be zero to apply *attr* only. Each
setter can be called only once per the WR builder.

The WR configures *mkey* and applies *attr* of the builder function and setter
functions' arguments for it. If *mkey* is already configured the WR overrides
some *mkey* properties depends on builder and setter functions' arguments (see
details in setters' description). To clear configuration of *mkey*, use
**ibv_post_send**() with **IBV_WR_LOCAL_INV** opcode or **ibv_wr_local_inv**().

Current implementation requires the **IBV_SEND_INLINE** option to be set in
**wr_flags** field of **ibv_qp_ex** structure prior to builder function call.
Non-inline payload is currently not supported by this API. Please note that
inlining here is done for MKEY configuration data, not for user data referenced
by data layouts.

Once MKEY is configured, it may be used in subsequent work requests (SEND,
RDMA_READ, RDMA_WRITE, etc). If these work requests are posted on the same QP,
there is no need to wait for completion of MKEY configuration work request.
They can be posted immediately after the last setter (or builder if no
setters). Usually there is no need to even request a completion for MKEY
configuration work request.

If completion is requested for MKEY configuration work request it will be
delivered with the **IBV_WC_DRIVER1** opcode.

## Builder function

**mlx5dv_wr_mkey_configure()**

:	Post a work request to configure an existing MKEY. With this
	call alone it is possible to configure the MKEY and keep or
	reset signature attributes. This call may be followed by zero or
	more optional setters.

	*mqp*

	:	The QP to post the work request on.

	*mkey*

	:	The MKEY to configure.

	*num_setters*

	:	The number of setters that must be called after this function.

	*attr*

	:	The MKEY configuration attributes

## MKEY configuration attributes

MKEY configuration attributes are provided in
**mlx5dv_mkey_conf_attr** structure.

```c
struct mlx5dv_mkey_conf_attr {
        uint32_t conf_flags;
        uint64_t comp_mask;
};
```

*conf_flags*

:	Reserved for future extension, must be 0 now.

*comp_mask*

:	Reserved for future extension, must be 0 now.

## Generic setters

**mlx5dv_wr_set_mkey_access_flags()**

:	Set the memory protection attributes for the MKEY. If the MKEY is
	configured, the setter overrides the previous value. For example,
	two MKEY configuration WRs are posted. The first one sets
	**IBV_ACCESS_REMOTE_READ**. The second one sets
	**IBV_ACCESS_REMOTE_WRITE**. In this case, the second WR overrides
	the memory protection attributes, and only **IBV_ACCESS_REMOTE_WRITE**
	is allowed for the MKEY when the WR is completed.

	*mqp*

	:	The QP where an MKEY configuration work request was created
		by **mlx5dv_wr_mkey_configure()**.

	*access_flags*

	:	The desired memory protection attributes; it is either 0 or
		the bitwise OR of one or more of flags in **enum
		ibv_access_flags**.

## Data layout setters

Data layout setters define how data referenced by the MKEY will be
scattered/gathered in the memory. In order to use MKEY with RDMA
operations it must be configured with a layout.

Not more than one data layout setter may follow builder
function. Layout can be updated in the next calls to builder
function.

When MKEY is used in RDMA operations, it should be used in a
zero-based mode, i.e. the **addr** field in **ibv_sge** structure is
an offset in the total data.

**mlx5dv_wr_set_mkey_layout_list()**

:	Set a memory layout for an MKEY based on SGE list. If the MKEY is
	configured and the data layout was defined by some data layout setter
	(not necessary this one), the setter overrides the previous value.

	Default WQE size can fit only 4 SGE entries. To allow more the QP
	should be created with a larger WQE size that may fit it. This
	should be done using the **max_inline_data** attribute of **struct
	ibv_qp_cap** upon QP creation.

	*mqp*

	:	The QP where an MKEY configuration work request was created
		by **mlx5dv_wr_mkey_configure()**.

	*num_sges*

	:	Number of SGEs in the list.

	*sge*

	:	Pointer to the list of **ibv_sge** structures.

# EXAMPLES

## Create QP and MKEY

Code below creates a QP with MKEY configure operation support and an
indirect mkey.

```c
/* Create QP with MKEY configure support */
struct ibv_qp_init_attr_ex attr_ex = {};
attr_ex.comp_mask |= IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
attr_ex.send_ops_flags |= IBV_QP_EX_WITH_RDMA_WRITE;

struct mlx5dv_qp_init_attr attr_dv = {};
attr_dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS;
attr_dv.send_ops_flags = MLX5DV_QP_EX_WITH_MKEY_CONFIGURE;

ibv_qp *qp = mlx5dv_create_qp(ctx, attr_ex, attr_dv);
ibv_qp_ex *qpx = ibv_qp_to_qp_ex(qp);
mlx5dv_qp_ex *mqpx = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);

mkey_attr.create_flags = MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT;
struct mlx5dv_mkey *mkey = mlx5dv_create_mkey(&mkey_attr);
```

## List data layout configuration

Code below configures an MKEY which allows remote access for read and
write and is based on SGE list layout with two entries. When this MKEY
is used in RDMA write operation, data will be scattered between two
memory regions. The first 64 bytes will go to memory referenced by
**mr1**. The next 4096 bytes will go to memory referenced by **mr2**.

```c
ibv_wr_start(qpx);
qpx->wr_id = my_wr_id_1;
qpx->wr_flags = IBV_SEND_INLINE;

struct mlx5dv_mkey_conf_attr mkey_attr = {};
mlx5dv_wr_mkey_configure(mqpx, mkey, 2, &mkey_attr);
mlx5dv_wr_set_mkey_access_flags(mqpx, IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
struct ibv_sge sgl[2];
sgl[0].addr = mr1->addr;
sgl[0].length = 64;
sgl[0].lkey = mr1->lkey;
sgl[1].addr = mr2->addr;
sgl[1].length = 4096;
sgl[1].lkey = mr2->lkey;
mlx5dv_wr_set_mkey_layout_list(mqpx, 2, sgl);
ret = ibv_wr_complete(qpx);
```

# NOTES

A DEVX context should be opened by using **mlx5dv_open_device**(3).

# SEE ALSO

**mlx5dv_create_mkey**(3), **mlx5dv_create_qp**(3)

# AUTHORS

Oren Duer  <oren@nvidia.com>

Sergey Gorenko <sergeygo@nvidia.com>

Evgenii Kochetov <evgeniik@nvidia.com>
