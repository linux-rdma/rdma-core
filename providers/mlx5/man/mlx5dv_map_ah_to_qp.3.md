---
layout: page
title: mlx5dv_map_ah_to_qp
section: 3
tagline: Verbs
---

# NAME

mlx5dv_map_ah_to_qp - Map the destination path information in address handle (AH) to the
information extracted from the qp.

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_map_ah_to_qp(struct ibv_ah *ah, uint32_t qp_num);
```

# DESCRIPTION

This API maps the destination path information in address handle (*ah*) to the information
extracted from the qp (e.g. congestion control from ECE).

This API serves as an enhancement to DC and UD QPs to achieve better performance by using per-address
congestion control (CC) algorithms, enabling DC/UD QPs to use multiple CC algorithms in the same datacenter.

The mapping created by this API is implicitly destroyed when the address handle is destroyed.
It is not affected by the destruction of QP *qp_num*.

A duplicate mapping to the same address handle is ignored. As this API is just a hint for the hardware in this
case it would do nothing and return success regardless of the new qp_num ECE.

The function must be called after ECE negotiation/preconfiguration was done by some external means.

# ARGUMENTS

*ah*
:	The target’s address handle.

*qp_num*
:	The initiator QP from which congestion control information is extracted from its ECE.

# RETURN VALUE

Upon success, returns 0; Upon failure, the value of errno is returned.

# SEE ALSO

*rdma_cm(7)*, *rdma_get_remote_ece(3)*, *ibv_query_ece(3)*, *ibv_set_ece(3)*

# AUTHOR

Yochai Cohen <yochai@nvidia.com>

Patrisious Haddad <phaddad@nvidia.com>
