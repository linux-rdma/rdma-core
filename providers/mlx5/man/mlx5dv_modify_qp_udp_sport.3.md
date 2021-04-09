---
layout: page
title: mlx5dv_modify_qp_udp_sport
section: 3
tagline: Verbs
---

# NAME

mlx5dv_modify_qp_udp_sport - Modify the UDP source port of a given QP

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_modify_qp_udp_sport(struct ibv_qp *qp, uint16_t udp_sport)
```

# DESCRIPTION

The UDP source port is used to create entropy for network routers (ECMP),
load balancers and 802.3ad link aggregation switching that are not aware of
RoCE IB headers.

This API enables modifying the configured UDP source port of a given RC/UC QP
when QP is in RTS state.

# ARGUMENTS

*qp*
:	The ibv_qp object to issue the action on.

*udp_sport*
:	The UDP source port to set for the QP.

# RETURN VALUE

Returns 0 on success, or the value of errno on failure (which indicates the failure reason).

# AUTHOR

Maor Gottlieb <maorg@nvidia.com>
