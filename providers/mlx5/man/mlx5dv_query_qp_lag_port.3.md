---
layout: page
title: mlx5dv_query_qp_lag_port
section: 3
tagline: Verbs
---

# NAME

mlx5dv_query_qp_lag_port - Query the lag port information of a given QP

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_query_qp_lag_port(struct ibv_qp *qp, uint8_t *port_num,
			     uint8_t *active_port_num);
```

# DESCRIPTION

This API returns the configured and active port num of a given QP in mlx5 devices.

The active port num indicates which port that the QP sends traffic out in a LAG configuration.

The num_lag_ports field of struct mlx5dv_context greater than 1 means LAG is supported on this device.

# ARGUMENTS

*qp*
:	The ibv_qp object to issue the action on.

*port_num*
:	The configured port num of the QP.

*active_port_num*
:	The current port num of the QP, which may different from the configured value because of the bonding status.

# RETURN VALUE
0 on success; EOPNOTSUPP if not in LAG mode, or other errno value on other failures.

# SEE ALSO

*mlx5dv_modify_qp_lag_port(3)*

# AUTHOR

Aharon Landau <aharonl@mellanox.com>
