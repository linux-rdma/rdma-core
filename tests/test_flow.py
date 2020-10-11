# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia All rights reserved. See COPYING file
"""
Test module for pyverbs' flow module.
"""
from tests.base import RDMATestCase, RawResources, PyverbsRDMAError
from tests.utils import requires_root_on_eth
from pyverbs.flow import FlowAttr, Flow
from pyverbs.spec import EthSpec
import tests.utils as u
import unittest
import errno


class FlowRes(RawResources):
    def __init__(self, dev_name, ib_port, gid_index):
        """
        Initialize Flow resources based on Raw resources that include Raw QP.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        """
        super().__init__(dev_name=dev_name, ib_port=ib_port,
                         gid_index=gid_index)

    @requires_root_on_eth()
    def create_qps(self):
        super().create_qps()

    @staticmethod
    def create_eth_spec():
        """
        Creates ethernet spec that matches on ethertype, source and destination
        macs.
        :return: created ethernet spec
        """
        eth_spec = EthSpec(ether_type=u.PacketConsts.ETHER_TYPE_IPV4,
                           dst_mac=u.PacketConsts.DST_MAC)
        eth_spec.src_mac = u.PacketConsts.SRC_MAC
        eth_spec.src_mac_mask = u.PacketConsts.MAC_MASK
        return eth_spec

    def create_flow(self, specs=[]):
        """
        Creates flow to match on provided specs.
        :param specs: list of specs to match on
        :return: created flow
        """
        flow_attr = FlowAttr(num_of_specs=len(specs), port=self.ib_port)
        for spec in specs:
            flow_attr.specs.append(spec)
        try:
            flow = Flow(self.qp, flow_attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Flow creation is not supported')
            raise ex
        return flow


class FlowTest(RDMATestCase):
    """
    Test various functionalities of the Flow class.
    """
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

    def test_eth_spec_flow_traffic(self):
        """
        Test raw ethernet traffic with eth spec flow.
        """
        self.create_players(FlowRes)
        eth_spec = self.server.create_eth_spec()
        self.flow = self.server.create_flow([eth_spec])
        u.raw_traffic(self.client, self.server, self.iters)
