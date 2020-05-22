---
layout: page
title: mlx5dv_modify_qp_lag_port
section: 3
tagline: Verbs
---

# NAME

mlx5dv_modify_qp_lag_port - Modify the lag port information of a given QP

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_modify_qp_lag_port(struct ibv_qp *qp, uint8_t port_num);
```

# DESCRIPTION

This API enables modifying the configured port num of a given QP.

If the QP state is modified later, the port num may be implicitly re-configured.

Use query mlx5dv_query_qp_lag_port to check the configured and active port num values.

# ARGUMENTS

*qp*
:	The ibv_qp object to issue the action on.

*port_num*
:	The port_num to set for the QP.

# RETURN VALUE
0 on success; EOPNOTSUPP if not in LAG mode, or other errno value on other failures.

# SEE ALSO

*mlx5dv_query_qp_lag_port(3)*

# AUTHOR

Aharon Landau <aharonl@mellanox.com>
