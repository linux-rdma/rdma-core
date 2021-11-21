---
date: 2019-03-28
layout: page
title: MLX5DV_DR API
section: 3
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
header: "mlx5 Programmer's Manual"
footer: mlx5
---

# NAME

mlx5dv_dr_domain_create, mlx5dv_dr_domain_sync, mlx5dv_dr_domain_destroy, mlx5dv_dr_domain_set_reclaim_device_memory, mlx5dv_dr_domain_allow_duplicate_rules - Manage flow domains

mlx5dv_dr_table_create, mlx5dv_dr_table_destroy - Manage flow tables

mlx5dv_dr_matcher_create, mlx5dv_dr_matcher_destroy, mlx5dv_dr_matcher_set_layout - Manage flow matchers

mlx5dv_dr_rule_create, mlx5dv_dr_rule_destroy - Manage flow rules

mlx5dv_dr_action_create_drop - Create drop action

mlx5dv_dr_action_create_default_miss - Create default miss action

mlx5dv_dr_action_create_tag - Create tag actions

mlx5dv_dr_action_create_dest_ibv_qp - Create packet destination QP action

mlx5dv_dr_action_create_dest_table  - Create packet destination dr table action

mlx5dv_dr_action_create_dest_vport - Create packet destination vport action

mlx5dv_dr_action_create_dest_ib_port - Create packet destination IB port action

mlx5dv_dr_action_create_dest_devx_tir - Create packet destination TIR action

mlx5dv_dr_action_create_dest_array - Create destination array action

mlx5dv_dr_action_create_packet_reformat - Create packet reformat actions

mlx5dv_dr_action_create_modify_header - Create modify header actions

mlx5dv_dr_action_create_flow_counter - Create devx flow counter actions

mlx5dv_dr_action_create_aso, mlx5dv_dr_action_modify_aso - Create and modify ASO actions

mlx5dv_dr_action_create_flow_meter, mlx5dv_dr_action_modify_flow_meter - Create and modify meter action

mlx5dv_dr_action_create_flow_sampler - Create flow sampler action

mlx5dv_dr_action_create_pop_vlan - Create pop vlan action

mlx5dv_dr_action_create_push_vlan- Create push vlan action

mlx5dv_dr_action_destroy - Destroy actions

mlx5dv_dr_aso_other_domain_link, mlx5dv_dr_aso_other_domain_unlink - link/unlink ASO devx object to work with different domains

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_dr_domain *mlx5dv_dr_domain_create(
		struct ibv_context *ctx,
		enum mlx5dv_dr_domain_type type);

int mlx5dv_dr_domain_sync(
		struct mlx5dv_dr_domain *domain,
		uint32_t flags);

int mlx5dv_dr_domain_destroy(struct mlx5dv_dr_domain *domain);

void mlx5dv_dr_domain_set_reclaim_device_memory(
		struct mlx5dv_dr_domain *dmn,
		bool enable);

void mlx5dv_dr_domain_allow_duplicate_rules(struct mlx5dv_dr_domain *dmn, bool allow);

struct mlx5dv_dr_table *mlx5dv_dr_table_create(
		struct mlx5dv_dr_domain *domain,
		uint32_t level);

int mlx5dv_dr_table_destroy(struct mlx5dv_dr_table *table);

struct mlx5dv_dr_matcher *mlx5dv_dr_matcher_create(
		struct mlx5dv_dr_table *table,
		uint16_t priority,
		uint8_t match_criteria_enable,
		struct mlx5dv_flow_match_parameters *mask);

int mlx5dv_dr_matcher_destroy(struct mlx5dv_dr_matcher *matcher);


int mlx5dv_dr_matcher_set_layout(struct mlx5dv_dr_matcher *matcher, struct mlx5dv_dr_matcher_layout *matcher_layout);

struct mlx5dv_dr_rule *mlx5dv_dr_rule_create(
		struct mlx5dv_dr_matcher *matcher,
		struct mlx5dv_flow_match_parameters *value,
		size_t num_actions,
		struct mlx5dv_dr_action *actions[]);

void mlx5dv_dr_rule_destroy(struct mlx5dv_dr_rule *rule);

struct mlx5dv_dr_action *mlx5dv_dr_action_create_drop(void);

struct mlx5dv_dr_action *mlx5dv_dr_action_create_default_miss(void);

struct mlx5dv_dr_action *mlx5dv_dr_action_create_tag(
		uint32_t tag_value);

struct mlx5dv_dr_action *mlx5dv_dr_action_create_dest_ibv_qp(
		struct ibv_qp *ibqp);

struct mlx5dv_dr_action *mlx5dv_dr_action_create_dest_table(
		struct mlx5dv_dr_table *table);

struct mlx5dv_dr_action *mlx5dv_dr_action_create_dest_vport(
		struct mlx5dv_dr_domain *domain,
		uint32_t vport);

struct mlx5dv_dr_action *mlx5dv_dr_action_create_dest_ib_port(
		struct mlx5dv_dr_domain *domain,
		uint32_t ib_port);

struct mlx5dv_dr_action *mlx5dv_dr_action_create_dest_devx_tir(
		struct mlx5dv_devx_obj *devx_obj);

struct mlx5dv_dr_action *mlx5dv_dr_action_create_packet_reformat(
		struct mlx5dv_dr_domain *domain,
		uint32_t flags,
		enum mlx5dv_flow_action_packet_reformat_type reformat_type,
		size_t data_sz, void *data);

struct mlx5dv_dr_action *mlx5dv_dr_action_create_modify_header(
		struct mlx5dv_dr_domain *domain,
		uint32_t flags,
		size_t actions_sz,
		__be64 actions[]);

struct mlx5dv_dr_action *mlx5dv_dr_action_create_flow_counter(
		struct mlx5dv_devx_obj *devx_obj,
		uint32_t offset);

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_aso(struct mlx5dv_dr_domain *domain,
			    struct mlx5dv_devx_obj *devx_obj,
			    uint32_t offset,
			    uint32_t flags,
			    uint8_t return_reg_c);

int mlx5dv_dr_action_modify_aso(struct mlx5dv_dr_action *action,
				uint32_t offset,
				uint32_t flags,
				uint8_t return_reg_c);

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_flow_meter(struct mlx5dv_dr_flow_meter_attr *attr);

int mlx5dv_dr_action_modify_flow_meter(struct mlx5dv_dr_action *action,
				       struct mlx5dv_dr_flow_meter_attr *attr,
				       __be64 modify_field_select);

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_flow_sampler(struct mlx5dv_dr_flow_sampler_attr *attr);

struct mlx5dv_dr_action *
mlx5dv_dr_action_create_dest_array(struct mlx5dv_dr_domain *domain,
				   size_t num_dest,
				   struct mlx5dv_dr_action_dest_attr *dests[]);

struct mlx5dv_dr_action *mlx5dv_dr_action_create_pop_vlan(void);

struct mlx5dv_dr_action *mlx5dv_dr_action_create_push_vlan(
		struct mlx5dv_dr_domain *dmn,
		__be32 vlan_hdr)

int mlx5dv_dr_action_destroy(struct mlx5dv_dr_action *action);

int mlx5dv_dr_aso_other_domain_link(struct mlx5dv_devx_obj *devx_obj,
				    struct mlx5dv_dr_domain *peer_dmn,
				    struct mlx5dv_dr_domain *dmn,
				    uint32_t flags,
				    uint8_t return_reg_c);

int mlx5dv_dr_aso_other_domain_unlink(struct mlx5dv_devx_obj *devx_obj,
				      struct mlx5dv_dr_domain *dmn);
```

# DESCRIPTION

The Direct Rule API (mlx5dv_dr_\*) allows complete access by verbs application to the device`s packet steering functionality.

Steering flow rules are the combination of attributes with a match pattern and a list of actions.
Rules can have several distinct actions (such as counting, encapsulating, decapsulating before redirecting packets to a particular queue or port, etc.).
In order to manage the rule execution order for the packet processing matching by HW, multiple flow tables in an ordered chain and multiple flow matchers sorted by priorities are defined.

## Domain
*mlx5dv_dr_domain_create()* creates a DR domain object to be used with *mlx5dv_dr_table_create()* and *mlx5dv_dr_action_create_\*()*.

A domain should be destroyed by calling *mlx5dv_dr_domain_destroy()* once all depended resources are released.

The device support the following domains types:

**MLX5DV_DR_DOMAIN_TYPE_NIC_RX**
Manage ethernet packets received on the NIC. Packets in this domain can be dropped, dispatched to QP`s, modified or redirected to additional tables inside the domain.
Default behavior: Drop packet.

**MLX5DV_DR_DOMAIN_TYPE_NIC_TX**
Manage ethernet packets transmit on the NIC. Packets in this domain can be dropped, modified or redirected to additional tables inside the domain.
Default behavior: Forward packet to NIC vport (to eSwitch or wire).

**MLX5DV_DR_DOMAIN_TYPE_FDB**
Manage ethernet packets in the eSwitch Forwarding Data Base for packets received from wire or from any other vport. Packets in this domain can be dropped, dispatched to vport, modified or redirected to additional tables inside the domain.
Default behavior: Forward packet to eSwitch manager vport.

*mlx5dv_dr_domain_sync()* is used in order to flush the rule submission queue. By default, rules in a domain are updated in HW asynchronously. **flags** should be a set of type *enum mlx5dv_dr_domain_sync_flags*:

**MLX5DV_DR_DOMAIN_SYNC_FLAGS_SW**: block until completion of all software queued tasks.

**MLX5DV_DR_DOMAIN_SYNC_FLAGS_HW**: clear the steering HW cache to enforce next packet hits the latest rules, in addition to the SW SYNC handling.

**MLX5DV_DR_DOMAIN_SYNC_FLAGS_MEM**: sync device memory to free cached memory.


*mlx5dv_dr_domain_set_reclaim_device_memory()* is used to enable the reclaiming of device memory back to the system when not in use, by default this feature is disabled.

*mlx5dv_dr_domain_allow_duplicate_rules()* is used to allow or prevent insertion of rules matching on same fields(duplicates) on non root tables, by default this feature is allowed.

## Table
*mlx5dv_dr_table_create()* creates a DR table in the **domain**, at the appropriate **level**, and can be used with *mlx5dv_dr_matcher_create()* and *mlx5dv_dr_action_create_dest_table()*.
All packets start traversing the steering domain tree at table **level** zero (0).
Using rule and action, packets can by redirected to other tables in the domain.

A table should be destroyed by calling *mlx5dv_dr_table_destroy()* once all depended resources are released.

## Matcher
*mlx5dv_dr_matcher_create()* create a matcher object in **table**, at sorted **priority** (lower value is check first). A matcher can hold multiple rules, all with identical **mask** of type *struct mlx5dv_flow_match_parameters* which represents the exact attributes to be compared by HW steering. The **match_criteria_enable** and **mask** are defined in a device spec format. Only the fields that where masked in the *matcher* should be filled by the rule in *mlx5dv_dr_rule_create()*.

A matcher should be destroyed by calling *mlx5dv_dr_matcher_destroy()* once all depended resources are released.

*mlx5dv_dr_matcher_set_layout()* is used to set specific layout parameters of a matcher, on some conditions setting some attributes might not be supported, in such cases ENOTSUP will be returned. **flags** should be a set of type *enum mlx5dv_dr_matcher_layout_flags*:

**MLX5DV_DR_MATCHER_LAYOUT_RESIZABLE**: The matcher can resize its scale and resources according to the rules that are inserted or removed.

**MLX5DV_DR_MATCHER_LAYOUT_NUM_RULE**: Indicates a hint from the application about the number of the rules the matcher is expected to handle. This allows preallocation of matcher resources for faster rule updates when using with non-resizable layout mode.

## Actions
A set of action create API are defined by *mlx5dv_dr_action_create_\*()*. All action are created as *struct mlx5dv_dr_action*.
An action should be destroyed by calling *mlx5dv_dr_action_destroy()* once all depended rules are destroyed.

When an action handle is reused for multiple rules, the same action will be executed. e.g.: action 'count' will count multiple flows rules on the same HW flow counter context. action 'drop' will drop packets of different rule from any matcher.

Action: Drop
*mlx5dv_dr_action_create_drop* create a terminating action which drops packets. Can not be mixed with Destination actions.

Action: Default miss
*mlx5dv_dr_action_create_default_miss* create a terminating action which will execute the default behavior based on the domain type.

Action: Tag
*mlx5dv_dr_action_create_tag* creates a non-terminating action which tags packets with **tag_value**. The **tag_value** is available in the CQE of the packet received. Valid only on domain type NIC_RX.

Action: Destination
*mlx5dv_dr_action_create_dest_ibv_qp* creates a terminating action delivering the packet to a QP, defined by **ibqp**. Valid only on domain type NIC_RX.
*mlx5dv_dr_action_create_dest_table* creates a forwarding action to another flow table, defined by **table**. The destination **table** must be from the same domain with a level higher than zero.
*mlx5dv_dr_action_create_dest_vport* creates a forwarding action to a **vport** on the same **domain**. Valid only on domain type FDB.
*mlx5dv_dr_action_create_dest_ib_port* creates a forwarding action to a **ib_port** on the same **domain**. The valid range of ports is a based on the capability phys_port_cnt_ex provided by ibq_query_device_ex and it is possible to query the ports details using mlx5dv_query_port. Action is supported only on domain type FDB.
*mlx5dv_dr_action_create_dest_devx_tir* creates a terminating action delivering the packet to a TIR, defined by **devx_obj**. Valid only on domain type NIC_RX.

Action: Array
*mlx5dv_dr_action_create_dest_array* creates an action which replicates a packet to multiple destinations. **num_dest** defines the number of replication destinations.
Each **dests** destination array entry can be of different **type**. Use type MLX5DV_DR_ACTION_DEST for direct forwarding to an action destination. Use type MLX5DV_DR_ACTION_DEST_REFORMAT when reformat action should be performed on the packet before it is forwarding to the destination action.

Action: Packet Reformat
*mlx5dv_dr_action_create_packet_reformat* create a packet reformat context and action in the **domain**. The **reformat_type**, **data_sz** and **data** are defined in *man mlx5dv_create_flow_action_packet_reformat*.

Action: Modify Header
*mlx5dv_dr_action_create_modify_header* create a modify header context and action in the **domain**. The **actions_sz** and **actions** are defined in *man mlx5dv_create_flow_action_modify_header*.

Action: Flow Count
*mlx5dv_dr_action_create_flow_counter* creates a flow counter action from a DEVX flow counter object, based on **devx_obj** and specific counter index from **offset** in the counter bulk.

Action: ASO
*mlx5dv_dr_action_create_aso* receives a **domain** pointer and creates an ASO action from the DEVX ASO object, based on **devx_obj**.
Use **offset** to select the specific ASO object in the **devx_obj** bulk.
DR rules using this action can optionally update the ASO object value according to **flags** to choose the specific wanted behavior of this object.
After a packet hits the rule with the ASO object the value of the ASO object will be copied into the chosen **return_reg_c** which can be used for match in following DR rules.

*mlx5dv_dr_action_modify_aso* modifies ASO action **action** with new values for **offset**, **return_reg_c** and **flags**.
Only new DR rules using this **action** will use the modified values. Existing DR rules do not change the HW action values stored.

**flags** can be set to one of the types of *mlx5dv_dr_action_aso_first_hit_flags* or *mlx5dv_dr_action_aso_flow_meter_flags* or *mlx5dv_dr_action_aso_ct_flags*:
**MLX5DV_DR_ACTION_ASO_FIRST_HIT_FLAGS_SET**: is used to set the ASO first hit object context, else the context is only copied to the return_reg_c.
**MLX5DV_DR_ACTION_FLAGS_ASO_FLOW_METER_RED**: is used to indicate to update the initial color in ASO flow meter object value to red.
**MLX5DV_DR_ACTION_FLAGS_ASO_FLOW_METER_YELLOW**: is used to indicate to update the initial color in ASO flow meter object value to yellow.
**MLX5DV_DR_ACTION_FLAGS_ASO_FLOW_METER_GREEN**: is used to indicate to update the initial color in ASO flow meter object value to green.
**MLX5DV_DR_ACTION_FLAGS_ASO_FLOW_METER_UNDEFINED**: is used to indicate to update the initial color in ASO flow meter object value to undefined.
**MLX5DV_DR_ACTION_FLAGS_ASO_CT_DIRECTION_INITIATOR**: is used to indicate the TCP connection direction the SYN packet was sent on.
**MLX5DV_DR_ACTION_FLAGS_ASO_CT_DIRECTION_RESPONDER**: is used to indicate the TCP connection direction the SYN-ACK packet was sent on.

Action: Meter
*mlx5dv_dr_action_create_flow_meter* creates a meter action based on the flow meter parameters. The paramertes are according to the device specification.
*mlx5dv_dr_action_modify_flow_meter* modifies existing flow meter **action** based on **modify_field_select**. **modify_field_select** is according to the device specification.

Action: Sampler
*mlx5dv_dr_action_create_flow_sampler* creates a sampler action, allowing us to duplicate and sample a portion of traffic.
Packets steered to the sampler action will be sampled with an approximate probability of 1/sample_ratio provided in **attr**, and sample_actions provided in **attr** will be executed over them.
All original packets will be steered to default_next_table in **attr**.
A modify header format SET_ACTION data can be provided in action of **attr**, which can be executed on packets before going to default flow table. On some devices, this is required to set register value.

Action Flags: action **flags** can be set to one of the types of *enum mlx5dv_dr_action_flags*:

Action: Pop Vlan
*mlx5dv_dr_action_create_pop_vlan* creates a pop vlan action which removes VLAN tags from packets layer 2.

Action: Push Vlan
*mlx5dv_dr_action_create_push_vlan* creates a push vlan action which adds VLAN tags to packets layer 2.

**MLX5DV_DR_ACTION_FLAGS_ROOT_LEVEL**: is used to indicate the action is targeted for flow table in level=0 (ROOT) of the specific domain.

## Rule
*mlx5dv_dr_rule_create()* creates a HW steering rule entry in **matcher**. The **value** of type *struct mlx5dv_flow_match_parameters* holds the exact attribute values of the steering rule to be matched, in a device spec format. Only the fields that where masked in the *matcher* should be filled.
HW will perform the set of **num_actions** from the **action** array of type *struct mlx5dv_dr_action*, once a packet matches the exact **value** of the rule (referred to as a 'hit').

*mlx5dv_dr_rule_destroy()* destroys the rule.

## Other
*mlx5dv_dr_aso_other_domain_link()* links the ASO devx object, **devx_obj** to a domain **dmn**, this will allow creating a rule with ASO action using the given object on the linked domain **dmn**.
**peer_dmn** is the domain that the ASO devx object was created on.
**dmn** is the domain that ASO devx object will be linked to.
**flags** choose the specific wanted behavior of this object according to the flags, same as for ASO action creation flags.
**regc_index** After a packet hits the rule with the ASO object the value of the ASO object will be copied into the regc register indicated by this param, and then we can use the value for matching in the following DR rules.

*mlx5dv_dr_aso_other_domain_unlink()* will unlink the **devx_obj** from the linked **dmn**.
**dmn** is the domain that ASO devx object is linked to.

# RETURN VALUE
The create API calls will return a pointer to the relevant object: table, matcher, action, rule. on failure, NULL will be returned and errno will be set.

The destroy API calls will returns 0 on success, or the value of errno on failure (which indicates the failure reason).

# LIMITATIONS
Application can verify is a feature is supported by *trail and error*. No capabilities are exposed, as the combination of all the options exposed are way to large to define.

Tables are size less by definition. They are expected to grow and shrink to accommodate for all rules, according to driver capabilities. Once reaching a limit, an error is returned.

Matchers in same priority, in the same table, will have undefined ordered.

A rule with identical value pattern to another rule on a given matcher are rejected.

IP version in matcher mask and rule should be equal and set to 4, 6 or 0.
# SEE ALSO

**mlx5dv_open_device(3)**, **mlx5dv_create_flow_action_packet_reformat(3)**, **mlx5dv_create_flow_action_modify_header(3)**.

# AUTHOR

Alex Rosenbaum <alexr@mellanox.com>
Alex Vesker <valex@mellanox.com>
