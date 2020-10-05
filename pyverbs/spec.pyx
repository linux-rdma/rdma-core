# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia. All rights reserved.

from pyverbs.pyverbs_error import PyverbsError
from libc.string cimport memcpy
import socket

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
        types = {v.IBV_FLOW_SPEC_ETH : 'IBV_FLOW_SPEC_ETH'}
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
