---
layout: page
title: mlx5dv_var_export / mlx5dv_var_import / mlx5dv_var_unimport
section: 3
tagline: Verbs
---

# NAME

mlx5dv_var_export - Export VAR attributes for cross-process sharing

mlx5dv_var_import - Import a VAR from exported attributes

mlx5dv_var_unimport - Unimport a VAR

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_var_export(struct mlx5dv_var *dv_var, void *data);

struct mlx5dv_var *mlx5dv_var_import(struct ibv_context *context,
                                     void *data);

void mlx5dv_var_unimport(struct mlx5dv_var *dv_var);
```

# DESCRIPTION

These functions enable cross-process sharing of VAR objects.

*mlx5dv_var_export()* exports a VAR attributes into a data buffer.
The buffer must be allocated by the caller with at least the size returned by
*mlx5dv_get_export_sizes()* in the *var_attrs_size* field.

*mlx5dv_var_import()* returns a VAR that is associated with the exported
attributes in the given *context*.

The *context* can be the original VAR allocating context or any context sharing
the same kernel resources (e.g., via *ibv_import_device()*).

*mlx5dv_var_unimport()* unimports a VAR that was imported via
*mlx5dv_var_import()*. Once the VAR usage has ended, either *mlx5dv_free_var()*
or *mlx5dv_var_unimport()* should be called. *mlx5dv_free_var()* destroys the
kernel object, while *mlx5dv_var_unimport()* only cleans up local resources
without affecting the kernel object.

It is the responsibility of the application to coordinate between all contexts
that use this VAR. Once destroy/free is done, no other process can use the
object except for unimport. All users must collaborate to ensure this.

# ARGUMENTS

## mlx5dv_var_export

*dv_var*
:	The VAR object to export.

*data*
:	Pointer to a buffer to be filled with the exported attributes.
	The buffer must be at least *var_attrs_size* bytes as returned by
	*mlx5dv_get_export_sizes()*.

## mlx5dv_var_import

*context*
:	RDMA device context to import the VAR into.

*data*
:	Pointer to a buffer previously filled by *mlx5dv_var_export()*.

# RETURN VALUE

*mlx5dv_var_export()* returns 0 on success, or the value of errno on error.

*mlx5dv_var_import()* returns a pointer to a *struct mlx5dv_var* on success,
or NULL on error with errno set.

# SEE ALSO

**mlx5dv_alloc_var**, **mlx5dv_get_export_sizes**, **mlx5dv_open_device**

# AUTHOR

Maher Sanalla <msanalla@nvidia.com>
