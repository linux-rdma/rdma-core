# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia. All rights reserved.

from pyverbs.pyverbs_error import PyverbsError
from libc.string cimport memcpy
import socket, struct

U32_MASK = 0xffffffff


cdef class Spec(PyverbsObject):
    """
    Abstract class for all the specs to derive from.
    """
    def __init__(self):
        raise NotImplementedError('This class is abstract.')

    @property
    def size(self):
        return self.size

    cpdef _copy_data(self, unsigned long ptr):
        """
        memcpy the spec to the provided address in proper order.
        This function must be implemented in each subclass.
        :param addr: address to copy spec to
        """
        raise NotImplementedError('Must be implemented in subclass.')

    def __str__(self):
        return f"{'Spec type':<16}: {self.type_to_str(self.spec_type):<20}\n" \
               f"{'Size':<16}: {self.size:<20}\n"

    @staticmethod
    def type_to_str(spec_type):
        types = {v.IBV_FLOW_SPEC_ETH      : 'IBV_FLOW_SPEC_ETH',
                 v.IBV_FLOW_SPEC_IPV4_EXT : "IBV_FLOW_SPEC_IPV4_EXT",
                 v.IBV_FLOW_SPEC_IPV6     : "IBV_FLOW_SPEC_IPV6",
                 v.IBV_FLOW_SPEC_TCP      : "IBV_FLOW_SPEC_TCP",
                 v.IBV_FLOW_SPEC_UDP      : "IBV_FLOW_SPEC_UDP"}
        res_str = ""
        if spec_type & v.IBV_FLOW_SPEC_INNER:
            res_str += 'IBV_FLOW_SPEC_INNER '
        try:
            s_type = spec_type & ~v.IBV_FLOW_SPEC_INNER
            res_str += types[s_type]
        except IndexError:
            raise PyverbsError(f'This type {s_type} is not implemented yet')
        return res_str

    @staticmethod
    def _set_val_mask(default_mask, val=None, val_mask=None):
        """
        If value is given without val_mask, default_mask will be returned.
        :param default_mask: default mask to set if not provided
        :param val: user provided value
        :param val_mask: user provided mask
        :return: resulting value and mask
        """
        res_val = 0
        res_mask = 0
        if val is not None:
            res_val = val
            res_mask = default_mask if val_mask is None else val_mask
        return res_val, res_mask


cdef class EthSpec(Spec):
    MAC_LEN = 6
    MAC_MASK = ('ff:' * MAC_LEN)[:-1]
    ZERO_MAC = [0] * MAC_LEN

    def __init__(self, dst_mac=None, dst_mac_mask=None, src_mac=None,
                 src_mac_mask=None, ether_type=None, ether_type_mask=None,
                 vlan_tag=None, vlan_tag_mask=None, is_inner=0):
        """
        Initialize a EthSpec object over an underlying ibv_flow_spec_eth C
        object that defines Ethernet header specifications for steering flow to
        match on.
        :param dst_mac: destination mac to match on (e.g. 'aa:bb:12:13:14:fe')
        :param dst_mac_mask: destination mac mask (e.g. 'ff:ff:ff:ff:ff:ff')
        :param src_mac: source mac to match on
        :param src_mac_mask: source mac mask
        :param ether_type: ethertype to match on
        :param ether_type_mask: ethertype mask
        :param vlan_tag: VLAN tag to match on
        :param vlan_tag_mask: VLAN tag mask
        :param is_inner: is inner spec
        """
        self.spec_type = v.IBV_FLOW_SPEC_ETH
        if is_inner:
            self.spec_type |= v.IBV_FLOW_SPEC_INNER
        self.size = sizeof(v.ibv_flow_spec_eth)
        self.dst_mac, self.dst_mac_mask = self._set_val_mask(self.MAC_MASK,
                                                             dst_mac,
                                                             dst_mac_mask)
        self.src_mac, self.src_mac_mask = self._set_val_mask(self.MAC_MASK,
                                                             src_mac,
                                                             src_mac_mask)
        self.val.ether_type, self.mask.ether_type =  \
            map(socket.htons, self._set_val_mask(0xffff, ether_type,
                                                 ether_type_mask))
        self.val.vlan_tag, self.mask.vlan_tag = \
            map(socket.htons, self._set_val_mask(0xffff, vlan_tag,
                                                 vlan_tag_mask))

    cdef _mac_to_str(self, unsigned char mac[6]):
        s = ''
        if len(mac) == 0:
            return s
        # Building string from array
        # [0xa, 0x1b, 0x2c, 0x3c, 0x4d, 0x5e] -> "0a:1b:2c:3c:4d:5e"
        for i in range(self.MAC_LEN):
            s += hex(mac[i])[2:].zfill(2) + ':'
        return s[:-1]

    def _set_mac(self, val):
        mac = EthSpec.ZERO_MAC[:]
        if val:
            s = val.split(':')
            for i in range(self.MAC_LEN):
                mac[i] = int(s[i], 16)
        return mac

    @property
    def dst_mac(self):
        return self._mac_to_str(self.val.dst_mac)

    @dst_mac.setter
    def dst_mac(self, val):
        self.val.dst_mac = self._set_mac(val)

    @property
    def dst_mac_mask(self):
        return self._mac_to_str(self.mask.dst_mac)

    @dst_mac_mask.setter
    def dst_mac_mask(self, val):
        self.mask.dst_mac = self._set_mac(val)

    @property
    def src_mac(self):
        return self._mac_to_str(self.val.src_mac)

    @src_mac.setter
    def src_mac(self, val):
        self.val.src_mac = self._set_mac(val)

    @property
    def src_mac_mask(self):
        return self._mac_to_str(self.mask.src_mac)

    @src_mac_mask.setter
    def src_mac_mask(self, val):
        self.mask.src_mac = self._set_mac(val)

    @property
    def ether_type(self):
        return socket.ntohs(self.val.ether_type)

    @ether_type.setter
    def ether_type(self, val):
        self.val.ether_type = socket.htons(val)

    @property
    def ether_type_mask(self):
        return socket.ntohs(self.mask.ether_type)

    @ether_type_mask.setter
    def ether_type_mask(self, val):
        self.mask.ether_type =  socket.htons(val)

    @property
    def vlan_tag(self):
        return socket.ntohs(self.val.vlan_tag)

    @vlan_tag.setter
    def vlan_tag(self, val):
        self.val.vlan_tag = socket.htons(val)

    @property
    def vlan_tag_mask(self):
        return socket.ntohs(self.mask.vlan_tag)

    @vlan_tag_mask.setter
    def vlan_tag_mask(self, val):
        self.mask.vlan_tag =  socket.htons(val)

    def __str__(self):
        return super().__str__() + \
           f"{'Src mac':<16}: {self.src_mac:<20} {self.src_mac_mask:<20}\n" \
           f"{'Dst mac':<16}: {self.dst_mac:<20} {self.dst_mac_mask:<20}\n" \
           f"{'Ether type':<16}: {self.val.ether_type:<20} " \
           f"{self.mask.ether_type:<20}\n" \
           f"{'Vlan tag':<16}: {self.val.vlan_tag:<20} " \
           f"{self.mask.vlan_tag:<20}\n"

    cpdef _copy_data(self, unsigned long ptr):
        cdef v.ibv_flow_spec_eth eth
        eth.size = self.size
        eth.type = self.spec_type
        eth.val = self.val
        eth.mask = self.mask
        memcpy(<void*>ptr, &eth, self.size)

cdef class Ipv4ExtSpec(Spec):
    def __init__(self, dst_ip=None, dst_ip_mask=None, src_ip=None,
                 src_ip_mask=None, proto=None, proto_mask=None, tos=None,
                 tos_mask=None, ttl=None, ttl_mask=None, flags=None,
                 flags_mask=None, is_inner=False):
        """
        Initialize an Ipv4ExtSpec object over an underlying ibv_flow_ipv4_ext C
        object that defines IPv4 header specifications for steering flow to
        match on.
        :param dst_ip: Destination IP to match on (e.g. '1.2.3.4')
        :param dst_ip_mask: Destination IP mask (e.g. '255.255.255.255')
        :param src_ip: source IP to match on
        :param src_ip_mask: Source IP mask
        :param proto: Protocol to match on
        :param proto_mask: Protocol mask
        :param tos: Type of service to match on
        :param tos_mask: Type of service mask
        :param ttl: Time to live to match on
        :param ttl_mask: Time to live mask
        :param flags: Flags to match on
        :param flags_mask: Flags mask
        :param is_inner: Is inner spec
        """
        self.spec_type = v.IBV_FLOW_SPEC_IPV4_EXT
        if is_inner:
            self.spec_type |= v.IBV_FLOW_SPEC_INNER
        self.size = sizeof(v.ibv_flow_spec_ipv4_ext)

        self.val.dst_ip, self.mask.dst_ip = \
            map(socket.htonl, self._set_val_mask(U32_MASK,
                                                 self._str_to_ip(dst_ip),
                                                 self._str_to_ip(dst_ip_mask)))
        self.val.src_ip, self.mask.src_ip = \
            map(socket.htonl, self._set_val_mask(U32_MASK,
                                                 self._str_to_ip(src_ip),
                                                 self._str_to_ip(src_ip_mask)))
        self.val.proto, self.mask.proto = self._set_val_mask(0xff, proto,
                                                             proto_mask)
        self.val.tos, self.mask.tos = self._set_val_mask(0xff, tos, tos_mask)
        self.val.ttl, self.mask.ttl = self._set_val_mask(0xff, ttl, ttl_mask)
        self.val.flags, self.mask.flags = self._set_val_mask(0xff, flags,
                                                             flags_mask)
    @staticmethod
    def _str_to_ip(ip_str):
        return None if ip_str is None else \
            struct.unpack('!L', socket.inet_aton(ip_str))[0]

    @staticmethod
    def _ip_to_str(ip):
        return socket.inet_ntoa(struct.pack('!L', ip))

    @property
    def dst_ip(self):
        return self._ip_to_str(socket.ntohl(self.val.dst_ip))

    @dst_ip.setter
    def dst_ip(self, val):
        self.val.dst_ip = socket.htonl(self._str_to_ip(val))

    @property
    def dst_ip_mask(self):
        return self._ip_to_str(socket.ntohl(self.mask.dst_ip))

    @dst_ip_mask.setter
    def dst_ip_mask(self, val):
        self.mask.dst_ip = socket.htonl(self._str_to_ip(val))

    @property
    def src_ip(self):
        return self._ip_to_str(socket.ntohl(self.val.src_ip))

    @src_ip.setter
    def src_ip(self, val):
        self.val.src_ip = socket.htonl(self._str_to_ip(val))

    @property
    def src_ip_mask(self):
        return self._ip_to_str(socket.ntohl(self.mask.src_ip))

    @src_ip_mask.setter
    def src_ip_mask(self, val):
        self.mask.src_ip = socket.htonl(self._str_to_ip(val))

    @property
    def proto(self):
        return self.val.proto

    @proto.setter
    def proto(self, val):
        self.val.proto = val

    @property
    def proto_mask(self):
        return self.mask.proto

    @proto_mask.setter
    def proto_mask(self, val):
        self.mask.proto = val

    @property
    def tos(self):
        return self.val.tos

    @tos.setter
    def tos(self, val):
        self.val.tos = val

    @property
    def tos_mask(self):
        return self.mask.tos

    @tos_mask.setter
    def tos_mask(self, val):
        self.mask.tos = val

    @property
    def ttl(self):
        return self.val.ttl

    @ttl.setter
    def ttl(self, val):
        self.val.ttl = val

    @property
    def ttl_mask(self):
        return self.mask.ttl

    @ttl_mask.setter
    def ttl_mask(self, val):
        self.mask.ttl = val

    @property
    def flags(self):
        return self.val.flags

    @flags.setter
    def flags(self, val):
        self.val.flags = val

    @property
    def flags_mask(self):
        return self.mask.flags

    @flags_mask.setter
    def flags_mask(self, val):
        self.mask.flags = val

    def __str__(self):
        return super().__str__() + \
           f"{'Src IP':<16}: {self.src_ip:<20} {self.src_ip_mask:<20}\n" \
           f"{'Dst IP':<16}: {self.dst_ip:<20} {self.dst_ip_mask:<20}\n" \
           f"{'Proto':<16}: {self.val.proto:<20} {self.mask.proto:<20}\n" \
           f"{'ToS':<16}: {self.val.tos:<20} {self.mask.tos:<20}\n" \
           f"{'TTL':<16}: {self.val.ttl:<20} {self.mask.ttl:<20}\n" \
           f"{'Flags':<16}: {self.val.flags:<20} {self.mask.flags:<20}\n"

    cpdef _copy_data(self, unsigned long ptr):
        cdef v.ibv_flow_spec_ipv4_ext ipv4
        ipv4.size = self.size
        ipv4.type = self.spec_type
        ipv4.val = self.val
        ipv4.mask = self.mask
        memcpy(<void*>ptr, &ipv4, self.size)


cdef class TcpUdpSpec(Spec):
    def __init__(self, v.ibv_flow_spec_type spec_type, dst_port=None,
                 dst_port_mask=None, src_port=None, src_port_mask=None,
                 is_inner=False):
        """
        Initialize a TcpUdpSpec object over an underlying ibv_flow_tcp_udp C
        object that defines TCP or UDP header specifications for steering flow
        to match on.
        :param spec_type: IBV_FLOW_SPEC_TCP or IBV_FLOW_SPEC_UDP
        :param dst_port: Destination port to match on
        :param dst_port_mask: Destination port mask
        :param src_port: Source port to match on
        :param src_port_mask: Source port mask
        :param is_inner: Is inner spec
        """
        if spec_type is not v.IBV_FLOW_SPEC_TCP and spec_type is not\
                v.IBV_FLOW_SPEC_UDP:
            raise PyverbsError('Spec type must be IBV_FLOW_SPEC_TCP or'
                               ' IBV_FLOW_SPEC_UDP')
        self.spec_type = spec_type
        if is_inner:
            self.spec_type |= v.IBV_FLOW_SPEC_INNER
        self.size = sizeof(v.ibv_flow_spec_tcp_udp)
        self.val.dst_port, self.mask.dst_port = \
            map(socket.htons, self._set_val_mask(0xffff, dst_port,
                                                 dst_port_mask))
        self.val.src_port, self.mask.src_port = \
            map(socket.htons, self._set_val_mask(0xffff, src_port,
                                                 src_port_mask))
    @property
    def dst_port(self):
        return socket.ntohs(self.val.dst_port)

    @dst_port.setter
    def dst_port(self, val):
        self.val.dst_port = socket.htons(val)

    @property
    def dst_port_mask(self):
        return socket.ntohs(self.mask.dst_port)

    @dst_port_mask.setter
    def dst_port_mask(self, val):
        self.mask.dst_port = socket.htons(val)

    @property
    def src_port(self):
        return socket.ntohs(self.val.src_port)

    @src_port.setter
    def src_port(self, val):
        self.val.src_port = socket.htons(val)

    @property
    def src_port_mask(self):
        return socket.ntohs(self.mask.src_port)

    @src_port_mask.setter
    def src_port_mask(self, val):
        self.mask.src_port = socket.htons(val)

    def __str__(self):
        return super().__str__() + \
           f"{'Src port':<16}: {self.src_port:<20} {self.src_port_mask:<20}\n" \
           f"{'Dst port':<16}: {self.dst_port:<20} {self.dst_port_mask:<20}\n"

    cpdef _copy_data(self, unsigned long ptr):
        cdef v.ibv_flow_spec_tcp_udp tcp_udp
        tcp_udp.size = self.size
        tcp_udp.type = self.spec_type
        tcp_udp.val = self.val
        tcp_udp.mask = self.mask
        memcpy(<void*>ptr, &tcp_udp, self.size)


cdef class Ipv6Spec(Spec):
    EMPTY_IPV6 = [0] * 16
    IPV6_MASK = ("ffff:" * 8)[:-1]
    FLOW_LABEL_MASK = 0xfffff

    def __init__(self, dst_ip=None, dst_ip_mask=None, src_ip=None,
                 src_ip_mask=None, flow_label=None, flow_label_mask=None,
                 next_hdr=None, next_hdr_mask=None, traffic_class=None,
                 traffic_class_mask=None, hop_limit=None, hop_limit_mask=None,
                 is_inner=False):
        """
        Initialize an Ipv6Spec object over an underlying ibv_flow_ipv6 C
        object that defines IPv6 header specifications for steering flow to
        match on.
        :param dst_ip: Destination IPv6 to match on (e.g. 'a0a1::a2a3:a4a5:a6a7:a8a9')
        :param dst_ip_mask: Destination IPv6 mask (e.g. 'ffff::ffff:ffff:ffff:ffff')
        :param src_ip: Source IPv6 to match on
        :param src_ip_mask: Source IPv6 mask
        :param flow_label: Flow label to match on
        :param flow_label_mask: Flow label mask
        :param next_hdr: Next header to match on
        :param next_hdr_mask: Next header mask
        :param traffic_class: Traffic class to match on
        :param traffic_class_mask: Traffic class mask
        :param hop_limit: Hop limit to match on
        :param hop_limit_mask: Hop limit mask
        :param is_inner: Is inner spec
        """
        self.spec_type = v.IBV_FLOW_SPEC_IPV6
        if is_inner:
            self.spec_type |= v.IBV_FLOW_SPEC_INNER
        self.size = sizeof(v.ibv_flow_spec_ipv6)

        self.dst_ip, self.dst_ip_mask = self._set_val_mask(self.IPV6_MASK,
                                                           dst_ip, dst_ip_mask)
        self.src_ip, self.src_ip_mask = self._set_val_mask(self.IPV6_MASK,
                                                           src_ip, src_ip_mask)
        self.val.flow_label, self.mask.flow_label = \
            map(socket.htonl, self._set_val_mask(self.FLOW_LABEL_MASK,
                                                 flow_label, flow_label_mask))
        self.val.next_hdr, self.mask.next_hdr = \
            self._set_val_mask(0xff, next_hdr, next_hdr_mask)
        self.val.traffic_class, self.mask.traffic_class = \
            self._set_val_mask(0xff, traffic_class, traffic_class_mask)
        self.val.hop_limit, self.mask.hop_limit = \
            self._set_val_mask(0xff, hop_limit, hop_limit_mask)

    @property
    def dst_ip(self):
        return socket.inet_ntop(socket.AF_INET6, self.val.dst_ip)

    @dst_ip.setter
    def dst_ip(self, val):
        self.val.dst_ip = socket.inet_pton(socket.AF_INET6, val)

    @property
    def dst_ip_mask(self):
        return socket.inet_ntop(socket.AF_INET6, self.mask.dst_ip)

    @dst_ip_mask.setter
    def dst_ip_mask(self, val):
        self.mask.dst_ip = socket.inet_pton(socket.AF_INET6, val)

    @property
    def src_ip(self):
        return socket.inet_ntop(socket.AF_INET6, self.val.src_ip)

    @src_ip.setter
    def src_ip(self, val):
        self.val.src_ip = socket.inet_pton(socket.AF_INET6, val)

    @property
    def src_ip_mask(self):
        return socket.inet_ntop(socket.AF_INET6, self.mask.src_ip)

    @src_ip_mask.setter
    def src_ip_mask(self, val):
        self.mask.src_ip = socket.inet_pton(socket.AF_INET6, val)

    @property
    def flow_label(self):
        return socket.ntohl(self.val.flow_label)

    @flow_label.setter
    def flow_label(self, val):
        self.val.flow_label = socket.htonl(val)

    @property
    def flow_label_mask(self):
        return socket.ntohl(self.mask.flow_label)

    @flow_label_mask.setter
    def flow_label_mask(self, val):
        self.mask.flow_label = socket.htonl(val)

    @property
    def next_hdr(self):
        return self.val.next_hdr

    @next_hdr.setter
    def next_hdr(self, val):
        self.val.next_hdr = val

    @property
    def next_hdr_mask(self):
        return self.mask.next_hdr

    @next_hdr_mask.setter
    def next_hdr_mask(self, val):
        self.mask.next_hdr = val

    @property
    def traffic_class(self):
        return self.val.traffic_class

    @traffic_class.setter
    def traffic_class(self, val):
        self.val.traffic_class = val

    @property
    def traffic_class_mask(self):
        return self.mask.traffic_class

    @traffic_class_mask.setter
    def traffic_class_mask(self, val):
        self.mask.traffic_class = val

    @property
    def hop_limit(self):
        return self.val.hop_limit

    @hop_limit.setter
    def hop_limit(self, val):
        self.val.hop_limit = val

    @property
    def hop_limit_mask(self):
        return self.mask.hop_limit

    @hop_limit_mask.setter
    def hop_limit_mask(self, val):
        self.mask.hop_limit = val

    def __str__(self):
        return super().__str__() + \
           f"{'Src IP':<16}: {self.src_ip:<20} {self.src_ip_mask:<20}\n" \
           f"{'Dst IP':<16}: {self.dst_ip:<20} {self.dst_ip_mask:<20}\n" \
           f"{'Flow label':<16}: {self.flow_label:<20} {self.flow_label_mask:<20}\n" \
           f"{'Next header':<16}: {self.next_hdr:<20} {self.next_hdr_mask:<20}\n" \
           f"{'Traffic class':<16}: {self.traffic_class:<20} {self.traffic_class_mask:<20}\n" \
           f"{'Hop limit':<16}: {self.hop_limit:<20} {self.hop_limit_mask:<20}\n"

    cpdef _copy_data(self, unsigned long ptr):
        cdef v.ibv_flow_spec_ipv6 ipv6
        ipv6.size = self.size
        ipv6.type = self.spec_type
        ipv6.val = self.val
        ipv6.mask = self.mask
        memcpy(<void*>ptr, &ipv6, self.size)
