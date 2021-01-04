---
layout: page
title: mlx5dv_modify_qp_sched_elem
section: 3
tagline: Verbs
date: 2020-9-22
header: "mlx5 Programmer's Manual"
footer: mlx5
---

# NAME

mlx5dv_modify_qp_sched_elem - Connect a QP with a requestor and/or a responder scheduling element

# SYNOPSIS

```c
int mlx5dv_modify_qp_sched_elem(struct ibv_qp *qp,
				struct mlx5dv_sched_leaf *requestor,
				struct mlx5dv_sched_leaf *responder);

```

# DESCRIPTION

The QP scheduling element (SE) allows the association of a QP to a SE tree. The SE is described in *mlx5dv_sched_node_create(3)* man page.

By default, all QPs are not associated to SE. The default setting is ensuring fair bandwidth allocation with no maximum bandwidth limiting.

A QP can be associate to a requestor and/or a responder SE following the IB spec definition.

# RETURN VALUE

upon success 0 is returned or the value of errno on a failure.

# SEE ALSO

**mlx5dv_sched_node_create**(3)

# AUTHOR

Mark Zhang <markzhang@nvidia.com>
Ariel Almog <ariela@nvidia.com>
