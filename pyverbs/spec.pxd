# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia All rights reserved.

#cython: language_level=3

from pyverbs.base cimport PyverbsObject
cimport pyverbs.libibverbs as v

cdef class Spec(PyverbsObject):
    cdef object spec_type
    cdef unsigned short size
    cpdef _copy_data(self, unsigned long ptr)

cdef class EthSpec(Spec):
    cdef v.ibv_flow_eth_filter val
    cdef v.ibv_flow_eth_filter mask
    cdef _mac_to_str(self, unsigned char mac[6])

cdef class Ipv4ExtSpec(Spec):
    cdef v.ibv_flow_ipv4_ext_filter val
    cdef v.ibv_flow_ipv4_ext_filter mask

cdef class TcpUdpSpec(Spec):
    cdef v.ibv_flow_tcp_udp_filter val
    cdef v.ibv_flow_tcp_udp_filter mask

cdef class Ipv6Spec(Spec):
    cdef v.ibv_flow_ipv6_filter val
    cdef v.ibv_flow_ipv6_filter mask
