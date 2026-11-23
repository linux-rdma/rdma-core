---
layout: page
title: EFADV_WR_SET_COMP_ACTION
section: 3
tagline: Verbs
date: 2026-09-20
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_wr_set_local_comp_action, efadv_wr_set_remote_comp_action,
efadv_wr_set_local_comp_action_with_data,
efadv_wr_set_remote_comp_action_with_data - Set completion action on the
current work request

# SYNOPSIS

```c
#include <infiniband/efadv.h>

static inline void efadv_wr_set_local_comp_action(struct efadv_qp *efadv_qp,
						   uint32_t action_id);

static inline void efadv_wr_set_remote_comp_action(struct efadv_qp *efadv_qp,
						    uint32_t action_id);

static inline void efadv_wr_set_local_comp_action_with_data(struct efadv_qp *efadv_qp,
							     uint32_t action_id,
							     uint64_t data);

static inline void efadv_wr_set_remote_comp_action_with_data(struct efadv_qp *efadv_qp,
							      uint32_t action_id,
							      uint64_t data);
```

# DESCRIPTION

These functions attach a completion action to the current work request
being built. The specified action is triggered on the local or remote
side upon WR completion.

These are work request setters and must be called after the work request
opcode function (e.g. **ibv_wr_rdma_write()**) and before
**ibv_wr_complete()** or the next work request opcode call.

Use **efadv_qp_from_ibv_qp_ex()** to get the efadv_qp for accessing this
interface.

The QP must be created with **EFADV_WR_EX_WITH_COMP_ACTION** (or
**EFADV_WR_EX_WITH_COMP_ACTION_WITH_DATA** for the data variants) set in
*efadv_qp_init_attr.wr_flags* to use these functions.

**efadv_wr_set_local_comp_action()** triggers the action identified by
*action_id* on the initiator side upon local WR completion.

**efadv_wr_set_remote_comp_action()** triggers the action identified by
*action_id* on the target side upon remote WR completion.

**efadv_wr_set_local_comp_action_with_data()** triggers the action on the
initiator side and passes *data* as the action operand.

**efadv_wr_set_remote_comp_action_with_data()** triggers the action on the
target side and passes *data* as the action operand.

If the action expects a data operand but the initiator uses a setter
without data, the operand defaults to 0.

The *action_id* is the value returned in *efadv_comp_action.action_id*
after Completion Action creation on the target (or local) side.

The action is visible only after the data in the work request becomes
visible. An invalid action ID results in a completion with error.

# SEE ALSO

**efadv**(7), **efadv_create_comp_action**(3),
**efadv_create_qp_ex**(3), **ibv_wr_start**(3)

# AUTHORS

Michael Margolin <mrgolin@amazon.com>
