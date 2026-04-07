---
layout: page
title: mlx5dv_devx_umem_export / mlx5dv_devx_umem_import / mlx5dv_devx_umem_unimport
section: 3
tagline: Verbs
---

# NAME

mlx5dv_devx_umem_export - Export DEVX UMEM attributes for cross-process sharing

mlx5dv_devx_umem_import - Import a DEVX UMEM from exported attributes

mlx5dv_devx_umem_unimport - Unimport a DEVX UMEM

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_devx_umem_export(struct mlx5dv_devx_umem *umem, void *data);

struct mlx5dv_devx_umem *
mlx5dv_devx_umem_import(struct ibv_context *context, void *data);

void mlx5dv_devx_umem_unimport(struct mlx5dv_devx_umem *umem);
```

# DESCRIPTION

These functions enable cross-process sharing of DEVX UMEM objects.

*mlx5dv_devx_umem_export()* exports DEVX UMEM attributes into a data buffer.
The buffer must be allocated by the caller with at least the size returned by
*mlx5dv_get_export_sizes()* in the *devx_umem_attrs_size* field.

*mlx5dv_devx_umem_import()* returns a DEVX UMEM that is associated with the
exported attributes in the given *context*. The *data* buffer must have been
previously filled by *mlx5dv_devx_umem_export()*.

The *context* can be the original UMEM registering context or any context sharing
the same kernel resources (e.g., via *ibv_import_device()*).

*mlx5dv_devx_umem_unimport()* unimports a DEVX UMEM that was imported via
*mlx5dv_devx_umem_import()*. Once the UMEM usage has ended, either
*mlx5dv_devx_umem_dereg()* or *mlx5dv_devx_umem_unimport()* should be called.
*mlx5dv_devx_umem_dereg()* deregisters the kernel object, while
*mlx5dv_devx_umem_unimport()* only cleans up local resources without affecting
the kernel object.

It is the responsibility of the application to coordinate between all contexts
that use this UMEM. Once deregistration is done, no other process can use
the object except for unimport. All users must collaborate to ensure this.

# ARGUMENTS

## mlx5dv_devx_umem_export

*umem*
:	The DEVX UMEM to export.

*data*
:	Pointer to a buffer to be filled with the exported attributes.
	The buffer must be at least *devx_umem_attrs_size* bytes as returned by
	*mlx5dv_get_export_sizes()*.

## mlx5dv_devx_umem_import

*context*
:	RDMA device context to import the DEVX UMEM into.

*data*
:	Pointer to a buffer previously filled by *mlx5dv_devx_umem_export()*.

# RETURN VALUE

*mlx5dv_devx_umem_export()* returns 0 on success, or the value of errno on error.

*mlx5dv_devx_umem_import()* returns a pointer to a *struct mlx5dv_devx_umem* on success,
or NULL on error with errno set.

# SEE ALSO

**mlx5dv_devx_umem_reg**, **mlx5dv_get_export_sizes**, **mlx5dv_open_device**

# AUTHOR

Maher Sanalla <msanalla@nvidia.com>
