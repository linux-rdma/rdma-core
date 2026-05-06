---
layout: page
title: mlx5dv_get_export_sizes
section: 3
tagline: Verbs
---

# NAME

mlx5dv_get_export_sizes - Query export buffer sizes for mlx5 objects

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_export_sizes {
	uint32_t var_attrs_size;
	uint32_t devx_umem_attrs_size;
	uint32_t devx_obj_attrs_size;
};

void mlx5dv_get_export_sizes(struct mlx5dv_export_sizes *sizes);
```

# DESCRIPTION

*mlx5dv_get_export_sizes()* returns the buffer sizes required by the
export/import APIs for each supported object type. The caller should use these
sizes to allocate data buffers before calling the corresponding export/import functions.

The returned sizes reflect the library's internal data layout and may change
between library versions.

# ARGUMENTS

*sizes*
:	Pointer to a *struct mlx5dv_export_sizes* to be filled.

## mlx5dv_export_sizes

*var_attrs_size*
:	Buffer size required for *mlx5dv_var_export()* / *mlx5dv_var_import()*.

*devx_umem_attrs_size*
:	Buffer size required for *mlx5dv_devx_umem_export()* / *mlx5dv_devx_umem_import()*.

*devx_obj_attrs_size*
:	Buffer size required for *mlx5dv_devx_obj_export()* / *mlx5dv_devx_obj_import()*.

# SEE ALSO

**mlx5dv_var_export**, **mlx5dv_devx_umem_export**, **mlx5dv_devx_obj_export**

# AUTHOR

Maher Sanalla <msanalla@nvidia.com>
