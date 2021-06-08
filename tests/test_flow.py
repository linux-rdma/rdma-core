# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia All rights reserved. See COPYING file
"""
Test module for pyverbs' flow module.
"""
from tests.base import RDMATestCase, RawResources, PyverbsRDMAError
from pyverbs.spec import EthSpec, Ipv4ExtSpec, Ipv6Spec, TcpUdpSpec
from tests.utils import requires_root_on_eth, PacketConsts
from pyverbs.flow import FlowAttr, Flow
import pyverbs.enums as e
import tests.utils as u
import unittest
import socket
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
    def create_eth_spec(ether_type=PacketConsts.ETHER_TYPE_IPV4):
        """
        Creates ethernet spec that matches on ethertype, source and destination
        macs.
        :param ether_type: IPv4 or IPv6
        :return: created ethernet spec
        """
        eth_spec = EthSpec(ether_type=ether_type, dst_mac=PacketConsts.DST_MAC)
        eth_spec.src_mac = PacketConsts.SRC_MAC
        eth_spec.src_mac_mask = PacketConsts.SRC_MAC
        return eth_spec

    def create_ip_spec(self, ver=PacketConsts.IP_V4,
                       next_hdr=socket.IPPROTO_UDP):
        """
        Creates IPv4 or IPv6 spec that matches on source and destination ips.
        :param ver: IP version
        :param next_hdr: Next header type
        :return: created IPv4 or IPv6 spec
        """
        if ver == PacketConsts.IP_V4:
            ip_spec = Ipv4ExtSpec(src_ip=PacketConsts.SRC_IP,
                                  dst_ip=PacketConsts.DST_IP, proto=next_hdr)
        else:
            ip_spec = Ipv6Spec(src_ip=PacketConsts.SRC_IP6,
                               dst_ip=PacketConsts.DST_IP6, next_hdr=next_hdr)
        return ip_spec

    @staticmethod
    def create_tcp_udp_spec(spec_type):
        """
        Creates TcpUdp spec that matches on ethertype, source and destination
        macs.
        :param spec_type: Spec type TCP or UDP
        :return: TCP or UDP spec
        """
        spec = TcpUdpSpec(spec_type, src_port=PacketConsts.SRC_PORT,
                          dst_port=PacketConsts.DST_PORT)
        return spec

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

    def flow_traffic(self, specs, l3=PacketConsts.IP_V4,
                     l4=PacketConsts.UDP_PROTO):
        """
        Execute raw ethernet traffic with given specs flow.
        :param specs: list of specs
        :param l3: Packet layer 3 type: 4 for IPv4 or 6 for IPv6
        :param l4: Packet layer 4 type: 'tcp' or 'udp'
        :return: None
        """
        self.flow = self.server.create_flow(specs)
        u.raw_traffic(self.client, self.server, self.iters, l3, l4)

    def test_eth_spec_flow_traffic(self):
        self.create_players(FlowRes)
        self.flow_traffic([self.server.create_eth_spec()])

    def test_ipv4_spec_flow_traffic(self):
        self.create_players(FlowRes)
        if self.is_eth_and_has_roce_hw_bug():
            raise unittest.SkipTest(f'Device {self.dev_name} doesn\'t support Ipv4ExtSpec')
        self.flow_traffic([self.server.create_ip_spec()])

    def test_ipv6_spec_flow_traffic(self):
        self.create_players(FlowRes)
        eth_spec = self.server.create_eth_spec(PacketConsts.ETHER_TYPE_IPV6)
        if self.is_eth_and_has_roce_hw_bug():
            raise unittest.SkipTest(f'Device {self.dev_name} doesn\'t support Ipv6Spec')
        ip_spec = self.server.create_ip_spec(PacketConsts.IP_V6)
        self.flow_traffic([eth_spec, ip_spec], PacketConsts.IP_V6)

    def test_udp_spec_flow_traffic(self):
        self.create_players(FlowRes)
        eth_spec = self.server.create_eth_spec()
        if self.is_eth_and_has_roce_hw_bug():
            raise unittest.SkipTest(f'Device {self.dev_name} doesn\'t support Ipv4ExtSpec')
        ip_spec = self.server.create_ip_spec()
        udp_spec = self.server.create_tcp_udp_spec(e.IBV_FLOW_SPEC_UDP)
        self.flow_traffic([eth_spec, ip_spec, udp_spec], PacketConsts.IP_V4,
                          PacketConsts.UDP_PROTO)

    def test_tcp_spec_flow_traffic(self):
        self.create_players(FlowRes)
        eth_spec = self.server.create_eth_spec(PacketConsts.ETHER_TYPE_IPV6)
        if self.is_eth_and_has_roce_hw_bug():
            raise unittest.SkipTest(f'Device {self.dev_name} doesn\'t support Ipv6Spec')
        ip_spec = self.server.create_ip_spec(PacketConsts.IP_V6,
                                             socket.IPPROTO_TCP)
        tcp_spec = self.server.create_tcp_udp_spec(e.IBV_FLOW_SPEC_TCP)
        self.flow_traffic([eth_spec, ip_spec, tcp_spec], PacketConsts.IP_V6,
                          PacketConsts.TCP_PROTO)
