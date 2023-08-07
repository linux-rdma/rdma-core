---
date: 2020-3-3
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_query_qp_data_in_order
---

# NAME

ibv_query_qp_data_in_order - check if qp data is guaranteed to be in order.

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_query_qp_data_in_order(struct ibv_qp *qp, enum ibv_wr_opcode op, uint32_t flags);

```


# DESCRIPTION

**ibv_query_qp_data_in_order()** Checks whether WQE data is guaranteed to be
written in-order, and thus reader may poll for data instead of poll for completion.
This function indicates data is written in-order within each WQE, but cannot be used to determine ordering between separate WQEs.
This function describes ordering at the receiving side of the QP, not the sending side.

# ARGUMENTS
*qp*
:       The local queue pair (QP) to query.

*op*
:       The operation type to query about. Different operation types may write data in a different order.
	For RDMA read operations: describes ordering of RDMA reads posted on this local QP.
	For RDMA write operations: describes ordering of remote RDMA writes being done into this local QP.
	For RDMA send operations: describes ordering of remote RDMA sends being done into this local QP.
	This function should not be used to determine ordering of other operation types.

*flags*
:	Flags are used to select a query type. Supported values:

IBV_QUERY_QP_DATA_IN_ORDER_RETURN_CAPS - Query for supported capabilities and return a capabilities vector.

Passing 0 is equivalent to using IBV_QUERY_QP_DATA_IN_ORDER_RETURN_CAPS and checking for IBV_QUERY_QP_DATA_IN_ORDER_WHOLE_MSG support.

# RETURN VALUE

**ibv_query_qp_data_in_order()** Return value is determined by flags. For each capability bit, 1 is returned if the data is guaranteed to be written in-order for selected operation and type, 0 otherwise.
If IBV_QUERY_QP_DATA_IN_ORDER_RETURN_CAPS flag is used, return value can consist of following capabilities:

IBV_QUERY_QP_DATA_IN_ORDER_WHOLE_MSG - All data is being written in order.

IBV_QUERY_QP_DATA_IN_ORDER_ALIGNED_128_BYTES - Each 128 bytes aligned block is being written in order.

If flags is 0, the function will return 1 if IBV_QUERY_QP_DATA_IN_ORDER_WHOLE_MSG is supported and 0 otherwise.

# NOTES

Return value is valid only when the data is read by the CPU and relaxed ordering MR is not the target of the transfer.

# SEE ALSO

**ibv_query_qp**(3)

# AUTHOR

Patrisious Haddad <phaddad@nvidia.com>

Yochai Cohen <yochai@nvidia.com>
