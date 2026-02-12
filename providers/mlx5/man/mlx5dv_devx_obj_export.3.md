---
layout: page
title: mlx5dv_devx_obj_export / mlx5dv_devx_obj_import / mlx5dv_devx_obj_unimport
section: 3
tagline: Verbs
---

# NAME

mlx5dv_devx_obj_export - Export DEVX object attributes for cross-process sharing

mlx5dv_devx_obj_import - Import a DEVX object from exported attributes

mlx5dv_devx_obj_unimport - Unimport a DEVX object

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_devx_obj_export(struct mlx5dv_devx_obj *obj, void *data);

struct mlx5dv_devx_obj *mlx5dv_devx_obj_import(struct ibv_context *context,
                                               void *data);

void mlx5dv_devx_obj_unimport(struct mlx5dv_devx_obj *obj);
```

# DESCRIPTION

These functions enable cross-process sharing of DEVX objects.

*mlx5dv_devx_obj_export()* exports DEVX object attributes into a buffer.
The buffer must be allocated by the caller with at least the size returned by
*mlx5dv_get_export_sizes()* in the *devx_obj_attrs_size* field.

*mlx5dv_devx_obj_import()* returns a DEVX object that is associated with the
exported attributes in the given *context*. The *data* buffer must have been
previously filled by *mlx5dv_devx_obj_export()*.

The *context* can be the original object creating context or any context sharing
the same kernel resources (e.g., via *ibv_import_device()*).

*mlx5dv_devx_obj_unimport()* unimports a DEVX object that was imported via
*mlx5dv_devx_obj_import()*. Once the object usage has ended, either
*mlx5dv_devx_obj_destroy()* or *mlx5dv_devx_obj_unimport()* should be called.
*mlx5dv_devx_obj_destroy()* destroys the kernel object, while
*mlx5dv_devx_obj_unimport()* only cleans up local resources without affecting
the kernel object.

It is the responsibility of the application to coordinate between all contexts
that use this object. Once destroy is done, no other process can use
the object except for unimport. All users must collaborate to ensure this.

# ARGUMENTS

## mlx5dv_devx_obj_export

*obj*
:	The DEVX object to export.

*data*
:	Pointer to a buffer to be filled with the exported attributes.
	The buffer must be at least *devx_obj_attrs_size* bytes as returned by
	*mlx5dv_get_export_sizes()*.

## mlx5dv_devx_obj_import

*context*
:	RDMA device context to import the DEVX object into.

*data*
:	Pointer to a buffer previously filled by *mlx5dv_devx_obj_export()*.

# RETURN VALUE

*mlx5dv_devx_obj_export()* returns 0 on success, or the value of errno on error.

*mlx5dv_devx_obj_import()* returns a pointer to a *struct mlx5dv_devx_obj* on success,
or NULL on error with errno set.

# SEE ALSO

**mlx5dv_devx_obj_create**, **mlx5dv_get_export_sizes**, **mlx5dv_open_device**

# AUTHOR

Maher Sanalla <msanalla@nvidia.com>
