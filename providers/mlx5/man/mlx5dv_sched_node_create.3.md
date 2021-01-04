---
layout: page
title: mlx5dv_sched_node[/leaf]_create / modify / destroy
section: 3
tagline: Verbs
date: 2020-9-3
header: "mlx5 Programmer's Manual"
footer: mlx5
---

# NAME

mlx5dv_sched_node_create - Creates a scheduling node element

mlx5dv_sched_leaf_create - Creates a scheduling leaf element

mlx5dv_sched_node_modify - Modifies a node scheduling element

mlx5dv_sched_leaf_modify - Modifies a leaf scheduling element

mlx5dv_sched_node_destroy - Destroys a node scheduling element

mlx5dv_sched_leaf_destroy - Destroys a leaf scheduling element

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_sched_node *mlx5dv_sched_node_create(struct ibv_context *context,
						   struct mlx5dv_sched_attr *sched_attr);

struct mlx5dv_sched_leaf *mlx5dv_sched_leaf_create(struct ibv_context *context,
						   struct mlx5dv_sched_attr *sched_attr);

int mlx5dv_sched_node_modify(struct mlx5dv_sched_node *node,
			     struct mlx5dv_sched_attr *sched_attr);

int mlx5dv_sched_leaf_modify(struct mlx5dv_sched_leaf *leaf,
			     struct mlx5dv_sched_attr *sched_attr);

int mlx5dv_sched_node_destroy(struct mlx5dv_sched_node *node);

int mlx5dv_sched_leaf_destroy(struct mlx5dv_sched_leaf *leaf);

```


# DESCRIPTION

The transmit scheduling element (SE) is scheduling the transmission for of all nodes connected it.
By configuring the SE, QoS policies may be enforced between the competing entities (e.g. SQ, QP).

In each scheduling cycle, the SE schedules all ready-to-transmit entities. The SE assures that weight for each entity is met.
If entity has reached its maximum allowed bandwidth within the scheduling cycle, it won’t be scheduled till end of the scheduling cycle.
The unused transmission bandwidth will be distributed among the remaining entities assuring the weight setting.

The SEs are connected in a tree structure. The entity is connected to a leaf. One or more leaves can be connected to a SE node.
One or more SE nodes can be connected to a SE node, until reaching the SE root.
For each input on each node, user can assign the maximum bandwidth and the scheduling weight.

The SE APIs (mlx5dv_sched_*) allows access by verbs application to set the hierarchical SE tree to the device.
The ibv_qp shall be connected to a leaf.

# ARGUMENTS

Please see *ibv_create_qp_ex(3)* man page for *context*.

## mlx5dv_sched_attr

```c

struct mlx5dv_sched_attr {
	struct mlx5dv_sched_node *parent;
	uint32_t flags;
	uint32_t bw_share;
	uint32_t max_avg_bw;
	uint64_t comp_mask;
};
```

*parent*
:	A node handler to the parent scheduling element which this scheduling element will be connected to. The root scheduling element doesn't have a parent.

*flags*
:	Specifying what attributes in the structure are valid:

	MLX5DV_SCHED_ELEM_ATTR_FLAGS_BW_SHARE for *bw_share*

	MLX5DV_SCHED_ELEM_ATTR_FLAGS_MAX_AVG_BW for *max_avg_bw*

*bw_share*
:	The relative bandwidth share allocated for this element. This field has no units.
        The bandwidth is shared between all elements connected to the same parent element, relatively to their bw_share.
        Value of 0, indicates a device default Weight. This field must be 0 for the root TSAR.

*max_avg_bw*
:	The maximal transmission rate allowed for the element, averaged over time. Value is given in units of 1 Mbit/sec. Value 0x0 indicates the rate is unlimited.
        This field must be 0 for the root TSAR.

*comp_mask*
:	Reserved for future extension, must be 0 now.

*node/leaf*
:      For modify, destroy: the scheduling element to work on.

*sched_attr*
:      For create, modify: the attribute of the scheduling element to work on.

# NOTES

For example if an application wants to create 2 QoS QP groups:
```c
g1: 70% bandwidth share of this application
g2: 30% bandwidth share of this application, with maximum average bandwidth limited to 4Gbps
```

Pseudo code:

```c

struct mlx5dv_sched_node *root;
struct mlx5dv_sched_leaf *leaf_g1, *leaf_g2;
struct mlx5dv_sched_attr;
struct ibv_qp *qp1, qp2;

/* Create root node */
attr.comp_mask = 0;
attr.parent = NULL;
attr.flags = 0;
root = mlx5dv_sched_node_create(context, attr);

/* Create group1 */
attr.comp_mask = 0;
attr.parent = root;
attr.bw_share = 7;
attr.flags = MLX5DV_SCHED_ELEM_ATTR_FLAGS_BW_SHARE;
leaf_g1 = mlx5dv_sched_leaf_create(context, attr);

/* Create group2 */
attr.comp_mask = 0;
attr.parent = root;
attr.bw_share = 3;
attr.max_avg_bw = 4096;
attr.flags = MLX5DV_SCHED_ELEM_ATTR_FLAGS_BW_SHARE | MLX5DV_SCHED_ELEM_ATTR_FLAGS_MAX_AVG_BW;
leaf_g2 = mlx5dv_sched_leaf_create(context, attr);

foreach (qp1 in group1)
	mlx5dv_modify_qp_sched_elem(qp1, leaf_g1, NULL);

foreach (qp2 in group2)
	mlx5dv_modify_qp_sched_elem(qp2, leaf_g2, NULL);

```

# RETURN VALUE

Upon success *mlx5dv_sched_node[/leaf]_create()* will return a new *struct mlx5dv_sched_node[/leaf]*, on error NULL will be returned and errno will be set.

Upon success modify and destroy, 0 is returned or the value of errno on a failure.

# SEE ALSO

**ibv_create_qp_ex**(3), **mlx5dv_modify_qp_sched_elem**(3)

# AUTHOR

Mark Zhang <markzhang@nvidia.com>

Ariel Almog <ariela@nvidia.com>

