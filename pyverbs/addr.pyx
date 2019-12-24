# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

from libc.stdint cimport uint8_t

from pyverbs.utils import gid_str_to_array, gid_str
from .pyverbs_error import PyverbsUserError
from pyverbs.base import PyverbsRDMAErrno
cimport pyverbs.libibverbs as v
from pyverbs.pd cimport PD
from pyverbs.cq cimport WC

cdef extern from 'endian.h':
    unsigned long be64toh(unsigned long host_64bits)


cdef class GID(PyverbsObject):
    """
    GID class represents ibv_gid. It enables user to query for GIDs values.
    """
    def __init__(self, val=None):
        super().__init__()
        if val is not None:
            vals = gid_str_to_array(val)

            for i in range(16):
                self.gid.raw[i] = <uint8_t>int(vals[i],16)

    @property
    def gid(self):
        """
        Expose the inner GID
        :return: A GID string in an 8 words format:
        'xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx'
        """
        return self.__str__()
    @gid.setter
    def gid(self, val):
        """
        Sets the inner GID
        :param val: A GID string in an 8 words format:
        'xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx'
        :return: None
        """
        self._set_gid(val)

    def _set_gid(self, val):
        vals = gid_str_to_array(val)

        for i in range(16):
            self.gid.raw[i] = <uint8_t>int(vals[i],16)

    def __str__(self):
        return gid_str(self.gid._global.subnet_prefix,
                       self.gid._global.interface_id)


cdef class GRH(PyverbsObject):
    """
    Represents ibv_grh struct. Used when creating or initializing an
    Address Handle from a Work Completion.
    """
    def __init__(self, GID sgid=None, GID dgid=None, version_tclass_flow=0,
                 paylen=0, next_hdr=0, hop_limit=1):
        """
        Initializes a GRH object
        :param sgid: Source GID
        :param dgid: Destination GID
        :param version_tclass_flow: A 32b big endian used to communicate
                                    service level e.g. across subnets
        :param paylen: A 16b big endian that is the packet length in bytes,
                       starting from the first byte after the GRH up to and
                       including the last byte of the ICRC
        :param next_hdr: An 8b unsigned integer specifying the next header
                         For non-raw packets: 0x1B
                         For raw packets: According to IETF RFC 1700
        :param hop_limit: An 8b unsigned integer specifying the number of hops
                          (i.e. routers) that the packet is permitted to take
                          prior to being discarded
        :return: A GRH object
        """
        super().__init__()
        self.grh.dgid = dgid.gid
        self.grh.sgid = sgid.gid
        self.grh.version_tclass_flow = version_tclass_flow
        self.grh.paylen = paylen
        self.grh.next_hdr = next_hdr
        self.grh.hop_limit = hop_limit

    @property
    def dgid(self):
        return gid_str(self.grh.dgid._global.subnet_prefix,
                       self.grh.dgid._global.interface_id)
    @dgid.setter
    def dgid(self, val):
        vals = gid_str_to_array(val)
        for i in range(16):
            self.grh.dgid.raw[i] = <uint8_t>int(vals[i],16)

    @property
    def sgid(self):
        return gid_str(self.grh.sgid._global.subnet_prefix,
                       self.grh.sgid._global.interface_id)
    @sgid.setter
    def sgid(self, val):
        vals = gid_str_to_array(val)
        for i in range(16):
            self.grh.sgid.raw[i] = <uint8_t>int(vals[i],16)

    @property
    def version_tclass_flow(self):
        return self.grh.version_tclass_flow

    @version_tclass_flow.setter
    def version_tclass_flow(self, val):
        self.grh.version_tclass_flow = val

    @property
    def paylen(self):
        return self.grh.paylen
    @paylen.setter
    def paylen(self, val):
        self.grh.paylen = val

    @property
    def next_hdr(self):
        return self.grh.next_hdr
    @next_hdr.setter
    def next_hdr(self, val):
        self.grh.next_hdr = val

    @property
    def hop_limit(self):
        return self.grh.hop_limit
    @hop_limit.setter
    def hop_limit(self, val):
        self.grh.hop_limit = val

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        return print_format.format('DGID', self.dgid) +\
               print_format.format('SGID', self.sgid) +\
               print_format.format('version tclass flow', self.version_tclass_flow) +\
               print_format.format('paylen', self.paylen) +\
               print_format.format('next header', self.next_hdr) +\
               print_format.format('hop limit', self.hop_limit)


cdef class GlobalRoute(PyverbsObject):
    """
    Represents ibv_global_route. Used in Address Handle creation and describes
    the values to be used in the GRH of the packets that will be sent using
    this Address Handle.
    """
    def __init__(self, GID dgid=None, flow_label=0, sgid_index=0, hop_limit=1,
                 traffic_class=0):
        """
        Initializes a GlobalRoute object with given parameters.
        :param dgid: Destination GID
        :param flow_label: A 20b value. If non-zero, gives a hint to switches
                           and routers that this sequence of packets must be
                           delivered in order
        :param sgid_index: An index in the port's GID table that identifies the
                           originator of the packet
        :param hop_limit: An 8b unsigned integer specifying the number of hops
                          (i.e. routers) that the packet is permitted to take
                          prior to being discarded
        :param traffic_class: An 8b unsigned integer specifying the required
                              delivery priority for routers
        :return: A GlobalRoute object
        """
        super().__init__()
        self.gr.dgid=dgid.gid
        self.gr.flow_label = flow_label
        self.gr.sgid_index = sgid_index
        self.gr.hop_limit = hop_limit
        self.gr.traffic_class = traffic_class

    @property
    def dgid(self):
        return gid_str(self.gr.dgid._global.subnet_prefix,
                       self.gr.dgid._global.interface_id)
    @dgid.setter
    def dgid(self, val):
        vals = gid_str_to_array(val)
        for i in range(16):
            self.gr.dgid.raw[i] = <uint8_t>int(vals[i],16)

    @property
    def flow_label(self):
        return self.gr.flow_label
    @flow_label.setter
    def flow_label(self, val):
        self.gr.flow_label = val

    @property
    def sgid_index(self):
        return self.gr.sgid_index
    @sgid_index.setter
    def sgid_index(self, val):
        self.gr.sgid_index = val

    @property
    def hop_limit(self):
        return self.gr.hop_limit
    @hop_limit.setter
    def hop_limit(self, val):
        self.gr.hop_limit = val

    @property
    def traffic_class(self):
        return self.gr.traffic_class
    @traffic_class.setter
    def traffic_class(self, val):
        self.gr.traffic_class = val

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        return print_format.format('DGID', self.dgid) +\
               print_format.format('flow label', self.flow_label) +\
               print_format.format('sgid index', self.sgid_index) +\
               print_format.format('hop limit', self.hop_limit) +\
               print_format.format('traffic class', self.traffic_class)


cdef class AHAttr(PyverbsObject):
    """ Represents ibv_ah_attr struct """
    def __init__(self, dlid=0, sl=0, src_path_bits=0, static_rate=0,
                 is_global=0, port_num=1, GlobalRoute gr=None):
        """
        Initializes an AHAttr object.
        :param dlid: Destination LID, a 16b unsigned integer
        :param sl: Service level, an 8b unsigned integer
        :param src_path_bits: When LMC (LID mask count) is used in the port,
                              packets are being sent with the port's base LID,
                              bitwise ORed with the value of the src_path_bits.
                              An 8b unsigned integer
        :param static_rate: An 8b unsigned integer limiting the rate of packets
                            that are being sent to the subnet
        :param is_global: If non-zero, GRH information exists in the Address
                          Handle
        :param port_num: The local physical port from which the packets will be
                         sent
        :param grh: Attributes of a global routing header. Will only be used if
                    is_global is non zero.
        :return: An AHAttr object
        """
        super().__init__()
        self.ah_attr.port_num = port_num
        self.ah_attr.sl = sl
        self.ah_attr.src_path_bits = src_path_bits
        self.ah_attr.dlid = dlid
        self.ah_attr.static_rate = static_rate
        self.ah_attr.is_global = is_global
        # Do not set GRH fields for a non-global AH
        if is_global:
            if gr is None:
                raise PyverbsUserError('Global AH Attr is created but gr parameter is None')
            self.ah_attr.grh.dgid = gr.gr.dgid
            self.ah_attr.grh.flow_label = gr.flow_label
            self.ah_attr.grh.sgid_index = gr.sgid_index
            self.ah_attr.grh.hop_limit = gr.hop_limit
            self.ah_attr.grh.traffic_class = gr.traffic_class

    @property
    def port_num(self):
        return self.ah_attr.port_num
    @port_num.setter
    def port_num(self, val):
        self.ah_attr.port_num = val

    @property
    def sl(self):
        return self.ah_attr.sl
    @sl.setter
    def sl(self, val):
        self.ah_attr.sl = val

    @property
    def src_path_bits(self):
        return self.ah_attr.src_path_bits
    @src_path_bits.setter
    def src_path_bits(self, val):
        self.ah_attr.src_path_bits = val

    @property
    def dlid(self):
        return self.ah_attr.dlid
    @dlid.setter
    def dlid(self, val):
        self.ah_attr.dlid = val

    @property
    def static_rate(self):
        return self.ah_attr.static_rate
    @static_rate.setter
    def static_rate(self, val):
        self.ah_attr.static_rate = val

    @property
    def is_global(self):
        return self.ah_attr.is_global
    @is_global.setter
    def is_global(self, val):
        self.ah_attr.is_global = val

    @property
    def dgid(self):
        if self.ah_attr.is_global:
            return gid_str(self.ah_attr.grh.dgid._global.subnet_prefix,
                           self.ah_attr.grh.dgid._global.interface_id)
    @dgid.setter
    def dgid(self, val):
        if self.ah_attr.is_global:
            vals = gid_str_to_array(val)
            for i in range(16):
                self.ah_attr.grh.dgid.raw[i] = <uint8_t>int(vals[i],16)

    @property
    def flow_label(self):
        if self.ah_attr.is_global:
            return self.ah_attr.grh.flow_label
    @flow_label.setter
    def flow_label(self, val):
        self.ah_attr.grh.flow_label = val

    @property
    def sgid_index(self):
        if self.ah_attr.is_global:
            return self.ah_attr.grh.sgid_index
    @sgid_index.setter
    def sgid_index(self, val):
        self.ah_attr.grh.sgid_index = val

    @property
    def hop_limit(self):
        if self.ah_attr.is_global:
            return self.ah_attr.grh.hop_limit
    @hop_limit.setter
    def hop_limit(self, val):
        self.ah_attr.grh.hop_limit = val

    @property
    def traffic_class(self):
        if self.ah_attr.is_global:
            return self.ah_attr.grh.traffic_class
    @traffic_class.setter
    def traffic_class(self, val):
        self.ah_attr.grh.traffic_class = val

    def __str__(self):
        print_format = '  {:22}: {:<20}\n'
        if self.is_global:
            global_format = print_format.format('dgid', self.dgid) +\
                            print_format.format('flow label', self.flow_label) +\
                            print_format.format('sgid index', self.sgid_index) +\
                            print_format.format('hop limit', self.hop_limit) +\
                            print_format.format('traffic_class', self.traffic_class)
        else:
            global_format = ''
        return print_format.format('port num', self.port_num) +\
               print_format.format('sl', self.sl) +\
               print_format.format('source path bits', self.src_path_bits) +\
               print_format.format('dlid', self.dlid) +\
               print_format.format('static rate', self.static_rate) +\
               print_format.format('is global', self.is_global) + global_format


cdef class AH(PyverbsCM):
    def __init__(self, PD pd, **kwargs):
        """
        Initializes an AH object with the given values.
        Two creation methods are supported:
        - Creation via AHAttr object (calls ibv_create_ah)
        - Creation via a WC object (calls ibv_create_ah_from_wc)
        :param pd: PD object this AH belongs to
        :param kwargs: Arguments:
            * *attr* (AHAttr)
               An AHAttr object (represents ibv_ah_attr struct)
            * *wc*
               A WC object to use for AH initialization
            * *grh*
               A GRH object to use for AH initialization (when using wc)
            * *port_num*
               Port number to be used for this AH (when using wc)
        :return: An AH object on success
        """
        super().__init__()
        if len(kwargs) == 1:
            # Create AH via ib_create_ah
            ah_attr = <AHAttr>kwargs['attr']
            self.ah = v.ibv_create_ah(pd.pd, &ah_attr.ah_attr)
        else:
            # Create AH from WC
            wc = <WC>kwargs['wc']
            grh = <GRH>kwargs['grh']
            port_num = kwargs['port_num']
            self.ah = v.ibv_create_ah_from_wc(pd.pd, &wc.wc, &grh.grh, port_num)
        if self.ah == NULL:
            raise PyverbsRDMAErrno('Failed to create AH')
        pd.add_ref(self)
        self.pd = pd

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        self.logger.debug('Closing AH')
        if self.ah != NULL:
            if v.ibv_destroy_ah(self.ah):
                raise PyverbsRDMAErrno('Failed to destroy AH')
            self.ah = NULL
            self.pd = None
