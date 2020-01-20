---
date: 2019-11-18
layout: page
title: MLX5DV_DUMP API
section: 3
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
header: "mlx5 Programmer's Manual"
footer: mlx5
---

# NAME

mlx5dv_dump_dr_domain - Dump DR Domain

mlx5dv_dump_dr_table - Dump DR Table

mlx5dv_dump_dr_matcher - Dump DR Matcher

mlx5dv_dump_dr_rule - Dump DR Rule

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_dump_dr_domain(FILE *fout, struct mlx5dv_dr_domain *domain);
int mlx5dv_dump_dr_table(FILE *fout, struct mlx5dv_dr_table *table);
int mlx5dv_dump_dr_matcher(FILE *fout, struct mlx5dv_dr_matcher *matcher);
int mlx5dv_dump_dr_rule(FILE *fout, struct mlx5dv_dr_rule *rule);
```

# DESCRIPTION

The Dump API (mlx5dv_dump_\*) allows the dumping of the existing rdma-core resources to the provided file.
The output file format is vendor specific.

*mlx5dv_dump_dr_domain()* dumps a DR Domain object properties to a specified file.

*mlx5dv_dump_dr_table()* dumps a DR Table object properties to a specified file.

*mlx5dv_dump_dr_matcher()* dumps a DR Matcher object properties to a specified file.

*mlx5dv_dump_dr_rule()* dumps a DR Rule object properties to a specified file.

# RETURN VALUE
The API calls returns 0 on success, or the value of errno on failure (which indicates the failure reason).
The calls are blocking - function returns only when all related resources info is written to the file.

# AUTHOR

Yevgeny Kliteynik <kliteyn@mellanox.com>
Muhammad Sammar <muhammads@mellanox.com>
