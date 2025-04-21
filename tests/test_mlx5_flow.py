# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia All rights reserved. See COPYING file
"""
Test module for pyverbs' mlx5 flow module.
"""

import unittest
import errno

from pyverbs.providers.mlx5.mlx5dv_flow import Mlx5FlowMatcher, \
    Mlx5FlowMatcherAttr, Mlx5FlowMatchParameters, Mlx5FlowActionAttr, Mlx5Flow,\
    Mlx5PacketReformatFlowAction
from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr, Mlx5DevxObj
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError
import pyverbs.providers.mlx5.mlx5_enums as dve
import pyverbs.enums as e
from tests.mlx5_base import Mlx5RDMATestCase, create_privileged_context, Mlx5RcResources
from tests.utils import requires_root_on_eth, PacketConsts, is_eth, requires_root, \
    requires_no_sriov
from tests.base import RawResources
import tests.utils as u
import struct


MAX_MATCH_PARAM_SIZE = 0x180
NIC_RX_RDMA_TABLE_TYPE = 0X7
NIC_TX_RDMA_TABLE_TYPE = 0X8
RDMA_TRANSPORT_RX = 0xd
RDMA_TRANSPORT_TX = 0xe
DROP_ACTION = 0X2
ALLOW_ACTION = 0X1
TABLE_LEVEL = 200


@u.skip_unsupported
def requires_reformat_support(func):
    def func_wrapper(instance):
        nic_tbl_caps = u.query_nic_flow_table_caps(instance)
        # Verify that both NIC RX and TX support reformat actions by checking
        # the following PRM fields: encap_general_header,
        # log_max_packet_reformat, and reformat (for both RX and TX).
        if not(nic_tbl_caps.encap_general_header and
               nic_tbl_caps.log_max_packet_reformat_context and
               nic_tbl_caps.flow_table_properties_nic_receive.reformat and
               nic_tbl_caps.flow_table_properties_nic_transmit.reformat):
            raise unittest.SkipTest('NIC flow table does not support reformat')
        return func(instance)
    return func_wrapper


def gen_vxlan_l2_tunnel_encap_header(msg_size):
    vxlan_header = u.gen_vxlan_header()
    udp_header = u.gen_udp_header(packet_len=msg_size + len(vxlan_header),
                                  dst_port=PacketConsts.VXLAN_PORT)
    ip_header = u.gen_ipv4_header(packet_len=msg_size + len(vxlan_header) + len(udp_header))
    mac_header = u.gen_ethernet_header()
    return mac_header + ip_header + udp_header + vxlan_header


def check_rdma_transport_domain_caps(agr_obj):
    """
    Check if the device and the given resources support rdma transport domain
    creation. If not, it raises unittest.SkipTest.
    This function should be called (directly or indirectly) from test functions
    only.
    :param agr_obj: Aggregation object which contains all resources necessary.
    """
    from tests.mlx5_prm_structs import QueryAdvRdmaCapOut, \
    QueryHcaCapIn, QueryCmdHcaCapOut, QueryHcaCapOp, QueryHcaCapMod
    query_cap_in = QueryHcaCapIn(op_mod=0x1)
    query_cap_out = QueryCmdHcaCapOut(agr_obj.ctx.devx_general_cmd(
        query_cap_in, len(QueryCmdHcaCapOut())))

    if query_cap_out.status:
        raise unittest.SkipTest('Failed to query general HCA CAPs with syndrome '
                                f'({query_cap_out.syndrome}')

    if not query_cap_out.capability.adv_rdma_cap:
        raise unittest.SkipTest("The device doesn't support adv_rdma_cap")

    query_adv_rdma_cap_in = QueryHcaCapIn(op_mod=(QueryHcaCapOp.ADV_RDMA_CAP << 0x1) | \
                                            QueryHcaCapMod.CURRENT)
    query_adv_rdma_cap_out = QueryAdvRdmaCapOut(agr_obj.ctx.devx_general_cmd(
        query_adv_rdma_cap_in, len(QueryAdvRdmaCapOut())))

    if not query_adv_rdma_cap_out.capability.rdma_transport_rx_flow_table_properties.ft_support:
        raise unittest.SkipTest("The device doesn't support the RDMA transport domain")


class Mlx5FlowResources(RawResources):
    def create_matcher(self, mask, match_criteria_enable, flags=0,
                       ft_type=dve.MLX5DV_FLOW_TABLE_TYPE_NIC_RX_):
        """
        Creates a matcher from a provided mask.
        :param mask: The mask to match on (in bytes)
        :param match_criteria_enable: Bitmask representing which of the
                                      headers and parameters in match_criteria
                                      are used
        :param flags: Flow matcher flags
        :param ft_type: Flow table type
        :return: Resulting matcher
        """
        try:
            flow_match_param = Mlx5FlowMatchParameters(len(mask), mask)
            attr = Mlx5FlowMatcherAttr(match_mask=flow_match_param,
                                       match_criteria_enable=match_criteria_enable,
                                       flags=flags, ft_type=ft_type)
            matcher = Mlx5FlowMatcher(self.ctx, attr)
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Matcher creation is not supported')
            raise ex
        return matcher

    @requires_root_on_eth()
    def create_qps(self):
        super().create_qps()


class Mlx5RCFlowResources(Mlx5RcResources):
    def __init__(self, dev_name, ib_port, gid_index, is_privileged_ctx=False, **kwargs):
        """
        Initializes a Mlx5RCFlowResources object with the given values and creates
        basic RDMA resources.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param is_privileged_ctx: If True, creates a privileged context (default: False)
        """
        self.obj_to_cleanup = []
        self.is_privileged_ctx = is_privileged_ctx
        super().__init__(dev_name, ib_port, gid_index, **kwargs)

    def create_context(self):
        if self.is_privileged_ctx:
            create_privileged_context(self)
            check_rdma_transport_domain_caps(self)
            return
        super().create_context()

    def close_resources(self):
        for obj in self.obj_to_cleanup:
            if obj:
                obj.close()

    def create_matcher(self, mask, match_criteria_enable, flags=0,
                       ft_type=dve.MLX5DV_FLOW_TABLE_TYPE_NIC_RX_, ib_port=1):
        """
        Creates a matcher from a provided mask.
        :param mask: The mask to match on (in bytes)
        :param match_criteria_enable: Bitmask representing which of the
                                      headers and parameters in match_criteria
                                      are used
        :param flags: Flow matcher flags
        :param ft_type: Flow table type
        :param ib_port: Specify its corresponding port.
        :return: Resulting matcher
        """
        try:
            flow_match_param = Mlx5FlowMatchParameters(len(mask), mask)
            comp_mask = dve.MLX5DV_FLOW_MATCHER_MASK_FT_TYPE

            if ft_type in [dve.MLX5DV_FLOW_TABLE_TYPE_RDMA_TRANSPORT_RX_,
                           dve.MLX5DV_FLOW_TABLE_TYPE_RDMA_TRANSPORT_TX_]:
                if not is_eth(self.ctx, ib_port):
                    raise unittest.SkipTest('Must be run on Ethernet link layer')

                comp_mask |= dve.MLX5DV_FLOW_MATCHER_MASK_IB_PORT

            attr = Mlx5FlowMatcherAttr(match_mask=flow_match_param,
                                       match_criteria_enable=match_criteria_enable,
                                       flags=flags, ft_type=ft_type, comp_mask=comp_mask,
                                       ib_port=ib_port)
            matcher = Mlx5FlowMatcher(self.ctx, attr)
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Matcher creation is not supported')
            raise ex
        return matcher

    def store_for_cleanup_stage(self, flow_table_obj):
        """
        Stores the given object for cleanup in the correct order.
        :param flow_table_obj: The object to be stored.
        """
        self.obj_to_cleanup.insert(0, flow_table_obj)

    def create_devx_flow_table(self, table_type, level):
        """
        Creates a DEVX flow table with the given type and level.
        :param table_type: The flow table type.
        :param level: The flow table level.
        :return: A tuple containing the created flow table object and the table ID.
        """
        from tests.mlx5_prm_structs import CreateFlowTableIn,\
            CreateFlowTableOut, FlowTableContext,CreateFlowTableOut
        cmd_in = CreateFlowTableIn(table_type=table_type,
                                   flow_table_context=FlowTableContext(level=level))
        flow_table_obj = Mlx5DevxObj(self.ctx, cmd_in, len(CreateFlowTableOut()))
        self.store_for_cleanup_stage(flow_table_obj)
        out = CreateFlowTableOut(flow_table_obj.out_view)
        return flow_table_obj, out.table_id

    def create_devx_flow_group(self, table_id, table_type):
        """
        Creates a DEVX flow group for the specified table.
        :param table_id: The ID of the flow table.
        :param table_type: The type of the flow table.
        :return: The ID of the created flow group.
        """
        from tests.mlx5_prm_structs import CreateFlowGroupIn, CreateFlowGroupOut
        cmd_in = CreateFlowGroupIn(table_type=table_type,
                                   table_id=table_id)
        flow_group_ojb = Mlx5DevxObj(self.ctx, cmd_in, len(CreateFlowGroupOut()))
        self.store_for_cleanup_stage(flow_group_ojb)
        out = CreateFlowGroupOut(flow_group_ojb.out_view)
        return out.group_id

    def create_devx_flow_entry(self, table_id, group_id, action, table_type):
        """
        Creates a DEVX flow table entry with the specified parameters.
        :param table_id: The ID of the flow table.
        :param group_id: The ID of the flow group.
        :param action: The action for the flow entry.
        :param table_type: The type of the flow table.
        :return: The created flow table entry object.
        """
        from tests.mlx5_prm_structs import SetFlowTableEntryIn, FlowContext, SetFlowTableEntryOut
        cmd_in = SetFlowTableEntryIn(table_type=table_type, table_id=table_id,
                                     flow_context=FlowContext(group_id=group_id, action=action))
        flow_table_entry_obj = Mlx5DevxObj(self.ctx, cmd_in, len(SetFlowTableEntryOut()))
        self.store_for_cleanup_stage(flow_table_entry_obj)


class Mlx5MatcherTest(Mlx5RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None

    def tearDown(self):
        """
        Cleans up resources if manual cleanup is needed.
        """
        if self.server and hasattr(self.server, 'obj_to_cleanup'):
            self.server.close_resources()
        if self.client and hasattr(self.client, 'obj_to_cleanup'):
            self.client.close_resources()
        super().tearDown()

    @u.skip_unsupported
    def test_create_empty_matcher(self):
        """
        Creates an empty matcher
        """
        self.res = Mlx5FlowResources(**self.dev_info)
        empty_mask = bytes(MAX_MATCH_PARAM_SIZE)
        self.res.create_matcher(empty_mask, u.MatchCriteriaEnable.NONE)

    @u.skip_unsupported
    def test_create_smac_matcher(self):
        """
        Creates a matcher to match on outer source mac
        """
        self.res = Mlx5FlowResources(**self.dev_info)
        smac_mask = bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
        self.res.create_matcher(smac_mask, u.MatchCriteriaEnable.OUTER)

    def generic_test_mlx5_flow_table(self, flow_table_type_mapping, action, ib_port=1,
                                     traffic=False):
        """
        This function performs the following steps:
        1. Creates a DEVX flow table with the specified table type.
        2. Creates a flow group in the DEVX flow table.
        3. Inserts a flow table entry (FTE) into the flow table group.
        4. Creates an mlx5 flow with an empty matcher (to steer all packets) on the specified
        table type, directing them to the DEVX flow table created in step #1.
        5. If the `traffic` flag is set to `True`, RDMA traffic is run to test the flow steering.

        :param flow_table_type_mapping: Dictionary mapping flow table types.
        :param action: Specifies the action to be performed on the matched packets.
        :param ib_port: The port for flow matching.
        :param traffic: Boolean flag indicating whether RDMA traffic should run.
        """
        empty_mask = bytes(MAX_MATCH_PARAM_SIZE)

        for ft_type, table_type in flow_table_type_mapping.items():
            devx_table_obj, table_id = self.server.create_devx_flow_table(table_type,
                                                                          level=TABLE_LEVEL)
            matcher = self.server.create_matcher(empty_mask, u.MatchCriteriaEnable.NONE,
                                                 ft_type=ft_type, ib_port=ib_port)
            self.server.store_for_cleanup_stage(matcher)
            group_id = self.server.create_devx_flow_group(table_id, table_type)
            self.server.create_devx_flow_entry(table_id, group_id, action, table_type)
            empty_value_param = Mlx5FlowMatchParameters(len(empty_mask), empty_mask)
            action_dest = Mlx5FlowActionAttr(action_type=dve.MLX5DV_FLOW_ACTION_DEST_DEVX,
                                             obj=devx_table_obj)
            self.server.flow = Mlx5Flow(matcher, empty_value_param, [action_dest], 1)

            if traffic:
                u.traffic(client=self.client, server=self.server,iters=self.iters,
                          gid_idx=self.gid_index, port=self.ib_port, is_cq_ex=True)

    @u.skip_unsupported
    @requires_root()
    @requires_no_sriov()
    def test_flow_table_drop(self):
        """
        Creates rules with DevX objects for RDMA RX and TX tables.
            - Creates two flow tables, one for RDMA RX and one for RDMA TX.
            - Configures matchers with different flow tables.
            - Configures flow actions to drop.
        """
        self.create_players(Mlx5RCFlowResources)
        flow_table_type_mapping = {
            dve.MLX5DV_FLOW_TABLE_TYPE_RDMA_RX_: NIC_RX_RDMA_TABLE_TYPE,
            dve.MLX5DV_FLOW_TABLE_TYPE_RDMA_TX_: NIC_TX_RDMA_TABLE_TYPE}
        self.generic_test_mlx5_flow_table(flow_table_type_mapping, action=DROP_ACTION)

    @u.skip_unsupported
    @requires_root()
    def test_flow_rdma_transport_domain_traffic(self):
        """
        Creates a devx table object with the RDMA transport domain,
        Verifies that the traffic passes successfully.
        """
        self.client = Mlx5RcResources(**self.dev_info)
        self.server = Mlx5RCFlowResources(is_privileged_ctx=True, **self.dev_info)
        self.pre_run()
        self.sync_remote_attr()
        flow_table_type_mapping = {
            dve.MLX5DV_FLOW_TABLE_TYPE_RDMA_TRANSPORT_RX_: RDMA_TRANSPORT_RX,
            dve.MLX5DV_FLOW_TABLE_TYPE_RDMA_TRANSPORT_TX_: RDMA_TRANSPORT_TX}
        self.generic_test_mlx5_flow_table(flow_table_type_mapping, action=ALLOW_ACTION, ib_port=1,
                                          traffic=True)

    @u.skip_unsupported
    def test_smac_matcher_to_qp_flow(self):
        """
        Creates a matcher to match on outer source mac and a flow that forwards
        packets to QP when matching on source mac.
        """
        self.create_players(Mlx5FlowResources)
        smac_mask = bytes([0xff] * 6)
        matcher = self.server.create_matcher(smac_mask,
                                             u.MatchCriteriaEnable.OUTER)
        smac_value = struct.pack('!6s',
                                 bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        value_param = Mlx5FlowMatchParameters(len(smac_value), smac_value)
        action_qp = Mlx5FlowActionAttr(action_type=dve.MLX5DV_FLOW_ACTION_DEST_IBV_QP,
                                       qp=self.server.qp)
        self.server.flow = Mlx5Flow(matcher, value_param, [action_qp], 1)
        u.raw_traffic(self.client, self.server, self.iters)

    @requires_reformat_support
    @u.requires_encap_disabled_if_eswitch_on
    def test_tx_packet_reformat(self):
        """
        Creates packet reformat (encap) action on TX and with QP action on RX
        verifies that the packet was encapsulated as expected.
        """
        self.client = Mlx5FlowResources(**self.dev_info)
        outer = gen_vxlan_l2_tunnel_encap_header(self.client.msg_size)
        # Due to encapsulation action Ipv4 and UDP checksum of the outer header
        # will be recalculated, need to skip them during packet validation.
        ipv4_id_idx = [18, 19]
        ipv4_chksum_idx = [24, 25]
        udp_chksum_idx = [34, 35]
        # Server will receive encaped packet so message size must include the
        # length of the outer part.
        self.server = Mlx5FlowResources(msg_size=self.client.msg_size + len(outer),
                                        **self.dev_info)
        empty_bytes_arr = bytes(MAX_MATCH_PARAM_SIZE)
        empty_value_param = Mlx5FlowMatchParameters(len(empty_bytes_arr),
                                                    empty_bytes_arr)

        # TX steering
        tx_matcher = self.client.create_matcher(empty_bytes_arr,
                                                u.MatchCriteriaEnable.NONE,
                                                e.IBV_FLOW_ATTR_FLAGS_EGRESS,
                                                dve.MLX5DV_FLOW_TABLE_TYPE_NIC_TX_)
        # Create encap action
        reformat_action = Mlx5PacketReformatFlowAction(
            self.client.ctx, data=outer,
            reformat_type=dve.MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L2_TUNNEL_,
            ft_type=dve.MLX5DV_FLOW_TABLE_TYPE_NIC_TX_)
        action_reformat_attr = Mlx5FlowActionAttr(flow_action=reformat_action,
                                                  action_type=dve.MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION)
        self.client.flow = Mlx5Flow(tx_matcher, empty_value_param,
                                    [action_reformat_attr], 1)

        # RX steering
        rx_matcher = self.server.create_matcher(empty_bytes_arr, u.MatchCriteriaEnable.NONE)
        action_qp_attr = Mlx5FlowActionAttr(action_type=dve.MLX5DV_FLOW_ACTION_DEST_IBV_QP,
                                            qp=self.server.qp)
        self.server.flow = Mlx5Flow(rx_matcher, empty_value_param, [action_qp_attr], 1)

        # Send traffic and validate packet
        packet = u.gen_packet(self.client.msg_size)
        u.raw_traffic(self.client, self.server, self.iters,
                      expected_packet=outer + packet,
                      skip_idxs=ipv4_id_idx + ipv4_chksum_idx + udp_chksum_idx)
