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
from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError
from tests.utils import requires_root_on_eth, PacketConsts
import pyverbs.providers.mlx5.mlx5_enums as dve
from tests.mlx5_base import Mlx5RDMATestCase
from tests.base import RawResources
import pyverbs.enums as e
import tests.utils as u
import struct


MAX_MATCH_PARAM_SIZE = 0x180

MLX5_CMD_OP_QUERY_HCA_CAP = 0x100
MLX5_CMD_MOD_NIC_FLOW_TABLE_CAP = 0x7
MLX5_CMD_OP_QUERY_HCA_CAP_OUT_LEN = 0x1010


@u.skip_unsupported
def requires_reformat_support(func):
    def func_wrapper(instance):
        try:
            ctx = Mlx5Context(Mlx5DVContextAttr(), instance.dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not open mlx5 context ({ex})')
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening mlx5 context is not supported')
        # Query NIC Flow Table capabilities
        cmd_in = struct.pack('!HIH8s', MLX5_CMD_OP_QUERY_HCA_CAP, 0,
                             MLX5_CMD_MOD_NIC_FLOW_TABLE_CAP << 1 | 0x1,
                             bytes(8))
        try:
            cmd_out = Mlx5Context.devx_general_cmd(ctx, cmd_in,
                                                   MLX5_CMD_OP_QUERY_HCA_CAP_OUT_LEN)
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('DevX general command is not supported')
            raise ex
        cmd_view = memoryview(cmd_out)
        status = cmd_view[0]
        if status:
            raise PyverbsRDMAError('Query NIC Flow Table CAPs failed with status'
                                   f' ({status})')
        # Verify that both NIC RX and TX support reformat actions by checking
        # the following PRM fields: encap_general_header,
        # log_max_packet_reformat, and reformat (for both RX and TX).
        if not (cmd_view[20] & 0x80 and cmd_view[21] & 0x1f and
                cmd_view[80] & 0x1 and cmd_view[272] & 0x1):
            raise unittest.SkipTest('NIC flow table does not support reformat')
        return func(instance)
    return func_wrapper


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


class Mlx5MatcherTest(Mlx5RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server = None
        self.client = None

    def create_players(self, resource, **resource_arg):
        """
        Init Flow tests resources.
        :param resource: The RDMA resources to use.
        :param resource_arg: Dict of args that specify the resource specific
                             attributes.
        :return: None
        """
        self.client = resource(**self.dev_info, **resource_arg)
        self.server = resource(**self.dev_info, **resource_arg)

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
    def test_tx_packet_reformat(self):
        """
        Creates packet reformat (encap) action on TX and with QP action on RX
        verifies that the packet was encapsulated as expected.
        """
        self.client = Mlx5FlowResources(**self.dev_info)
        outer = u.gen_outer_headers(self.client.msg_size)
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
