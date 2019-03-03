# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

"""
Device module introduces the Context and DeviceAttr class.
It allows user to open an IB device (using Context(name=<name>) and query it,
which returns a DeviceAttr object.
"""
import weakref

from .pyverbs_error import PyverbsRDMAError, PyverbsError
from .pyverbs_error import PyverbsUserError
from pyverbs.base import PyverbsRDMAErrno
cimport pyverbs.libibverbs_enums as e
cimport pyverbs.libibverbs as v
from pyverbs.addr cimport GID
from pyverbs.mr import DMMR
from pyverbs.pd cimport PD

cdef extern from 'errno.h':
    int errno
cdef extern from 'endian.h':
    unsigned long be64toh(unsigned long host_64bits);
cdef extern from 'stdlib.h':
    void free(void *ptr)
cdef extern from 'string.h':
    void *memset(void *s, int c, size_t n)
cdef extern from 'malloc.h':
    void *malloc(size_t size)
cdef extern from 'stdint.h':
    ctypedef int uint64_t


class Device(PyverbsObject):
    """
    Device class represents the C ibv_device. It stores device's properties.
    It is not a part of objects creation order - there's no need for the user
    to create it for such purposes.
    """
    def __init__(self, name, guid, node_type, transport_type):
        self._node_type = node_type
        self._transport_type = transport_type
        self._name = name
        self._guid = guid

    @property
    def name(self):
        return self._name

    @property
    def node_type(self):
        return self._node_type

    @property
    def transport_type(self):
        return self._transport_type

    @property
    def guid(self):
        return self._guid

    def __str__(self):
        return 'Device {dev}, node type {ntype}, transport type {ttype},' \
               ' guid {guid}'.format(dev=self.name.decode(),
                ntype=translate_node_type(self.node_type),
                ttype=translate_transport_type(self.transport_type),
                guid=guid_to_hex(self.guid))


cdef class Context(PyverbsCM):
    """
    Context class represents the C ibv_context.
    """
    def __cinit__(self, **kwargs):
        """
        Initializes a Context object. The function searches the IB devices list
        for a device with the name provided by the user. If such a device is
        found, it is opened.
        :param kwargs: Currently supports 'name' argument only, the IB device's
                       name.
        :return: None
        """
        cdef int count
        cdef v.ibv_device **dev_list

        self.pds = weakref.WeakSet()
        self.dms = weakref.WeakSet()

        dev_name = kwargs.get('name')

        if dev_name is not None:
            self.name = dev_name
        else:
            raise PyverbsUserError('Device name must be provided')

        dev_list = v.ibv_get_device_list(&count)
        if dev_list == NULL:
            raise PyverbsRDMAError('Failed to get devices list')
        try:
            for i in range(count):
                if dev_list[i].name.decode() == self.name:
                    self.context = v.ibv_open_device(dev_list[i])
                    if self.context == NULL:
                        raise PyverbsRDMAErrno('Failed to open device {dev}'.
                                               format(dev=self.name))
                    self.logger.debug('Context: opened device {dev}'.
                                      format(dev=self.name))
                    break
            else:
                raise PyverbsRDMAError('Failed to find device {dev}'.
                                       format(dev=self.name))
        finally:
            v.ibv_free_device_list(dev_list)

    def __dealloc__(self):
        """
        Closes the inner IB device.
        :return: None
        """
        self.close()

    cpdef close(self):
        self.logger.debug('Closing Context')
        self.close_weakrefs([self.dms, self.pds])
        if self.context != NULL:
            rc = v.ibv_close_device(self.context)
            if rc != 0:
                raise PyverbsRDMAErrno('Failed to close device {dev}'.
                                       format(dev=self.device.name), errno)
            self.context = NULL

    def query_device(self):
        """
        Queries the device's attributes.
        :return: A DeviceAttr object which holds the device's attributes as
                 reported by the hardware.
        """
        dev_attr = DeviceAttr()
        rc = v.ibv_query_device(self.context, &dev_attr.dev_attr)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to query device {name}'.
                                   format(name=self.name), errno)
        return dev_attr

    def query_device_ex(self, QueryDeviceExInput ex_input = None):
        """
        Queries the device's extended attributes.
        :param ex_input: An extensible input struct for possible future
                         extensions
        :return: DeviceAttrEx object
        """
        dev_attr_ex = DeviceAttrEx()
        rc = v.ibv_query_device_ex(self.context,
                                   &ex_input.input if ex_input is not None else NULL,
                                   &dev_attr_ex.dev_attr)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to query EX device {name}'.
                                   format(name=self.name))
        return dev_attr_ex

    def query_gid(self, unsigned int port_num, int index):
        gid = GID()
        rc = v.ibv_query_gid(self.context, port_num, index, &gid.gid)
        if rc != 0:
            raise PyverbsRDMAError('Failed to query gid {idx} of port {port}'.
                                                                   format(idx=index, port=port_num))
        return gid

    def query_port(self, unsigned int port_num):
        """
        Query port <port_num> of the device and returns its attributes.
        :param port_num: Port number to query
        :return: PortAttr object on success
        """
        port_attrs = PortAttr()
        rc = v.ibv_query_port(self.context, port_num, &port_attrs.attr)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to query port {p}'.format(p=port_num))
        return port_attrs

    cdef add_ref(self, obj):
        if isinstance(obj, PD):
            self.pds.add(obj)
        elif isinstance(obj, DM):
            self.dms.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')


cdef class DeviceAttr(PyverbsObject):
    """
    DeviceAttr represents ibv_device_attr C class. It exposes the same
    properties (read only) and also provides an __str__() function for
    readability.
    """
    @property
    def fw_version(self):
        return self.dev_attr.fw_ver.decode()
    @property
    def node_guid(self):
        return self.dev_attr.node_guid
    @property
    def sys_image_guid(self):
        return self.dev_attr.sys_image_guid
    @property
    def max_mr_size(self):
        return self.dev_attr.max_mr_size
    @property
    def page_size_cap(self):
        return self.dev_attr.page_size_cap
    @property
    def vendor_id(self):
        return self.dev_attr.vendor_id
    @property
    def vendor_part_id(self):
        return self.dev_attr.vendor_part_id
    @property
    def hw_ver(self):
        return self.dev_attr.hw_ver
    @property
    def max_qp(self):
        return self.dev_attr.max_qp
    @property
    def max_qp_wr(self):
        return self.dev_attr.max_qp_wr
    @property
    def device_cap_flags(self):
        return self.dev_attr.device_cap_flags
    @property
    def max_sge(self):
        return self.dev_attr.max_sge
    @property
    def max_sge_rd(self):
        return self.dev_attr.max_sge_rd
    @property
    def max_cq(self):
        return self.dev_attr.max_cq
    @property
    def max_cqe(self):
        return self.dev_attr.max_cqe
    @property
    def max_mr(self):
        return self.dev_attr.max_mr
    @property
    def max_pd(self):
        return self.dev_attr.max_pd
    @property
    def max_qp_rd_atom(self):
        return self.dev_attr.max_qp_rd_atom
    @property
    def max_ee_rd_atom(self):
        return self.dev_attr.max_ee_rd_atom
    @property
    def max_res_rd_atom(self):
        return self.dev_attr.max_res_rd_atom
    @property
    def max_qp_init_rd_atom(self):
        return self.dev_attr.max_qp_init_rd_atom
    @property
    def max_ee_init_rd_atom(self):
        return self.dev_attr.max_ee_init_rd_atom
    @property
    def atomic_caps(self):
        return self.dev_attr.atomic_cap
    @property
    def max_ee(self):
        return self.dev_attr.max_ee
    @property
    def max_rdd(self):
        return self.dev_attr.max_rdd
    @property
    def max_mw(self):
        return self.dev_attr.max_mw
    @property
    def max_raw_ipv6_qps(self):
        return self.dev_attr.max_raw_ipv6_qp
    @property
    def max_raw_ethy_qp(self):
        return self.dev_attr.max_raw_ethy_qp
    @property
    def max_mcast_grp(self):
        return self.dev_attr.max_mcast_grp
    @property
    def max_mcast_qp_attach(self):
        return self.dev_attr.max_mcast_qp_attach
    @property
    def max_ah(self):
        return self.dev_attr.max_ah
    @property
    def max_fmr(self):
        return self.dev_attr.max_fmr
    @property
    def max_map_per_fmr(self):
        return self.dev_attr.max_map_per_fmr
    @property
    def max_srq(self):
        return self.dev_attr.max_srq
    @property
    def max_srq_wr(self):
        return self.dev_attr.max_srq_wr
    @property
    def max_srq_sge(self):
        return self.dev_attr.max_srq_sge
    @property
    def max_pkeys(self):
        return self.dev_attr.max_pkeys
    @property
    def local_ca_ack_delay(self):
        return self.dev_attr.local_ca_ack_delay
    @property
    def phys_port_cnt(self):
        return self.dev_attr.phys_port_cnt

    def __str__(self):
        print_format = '{:<22}: {:<20}\n'
        return print_format.format('FW version', self.fw_version) +\
            print_format.format('Node guid', guid_format(self.node_guid)) +\
            print_format.format('Sys image GUID', guid_format(self.sys_image_guid)) +\
            print_format.format('Max MR size', hex(self.max_mr_size).replace('L', '')) +\
            print_format.format('Page size cap', hex(self.page_size_cap).replace('L', '')) +\
            print_format.format('Vendor ID', hex(self.vendor_id)) +\
            print_format.format('Vendor part ID', self.vendor_part_id) +\
            print_format.format('HW version', self.hw_ver) +\
            print_format.format('Max QP', self.max_qp) +\
            print_format.format('Max QP WR', self.max_qp_wr) +\
            print_format.format('Device cap flags', self.device_cap_flags) +\
            print_format.format('Max SGE', self.max_sge) +\
            print_format.format('Max SGE RD', self.max_sge_rd) +\
            print_format.format('MAX CQ', self.max_cq) +\
            print_format.format('Max CQE', self.max_cqe) +\
            print_format.format('Max MR', self.max_mr) +\
            print_format.format('Max PD', self.max_pd) +\
            print_format.format('Max QP RD atom', self.max_qp_rd_atom) +\
            print_format.format('Max EE RD atom', self.max_ee_rd_atom) +\
            print_format.format('Max res RD atom', self.max_res_rd_atom) +\
            print_format.format('Max QP init RD atom', self.max_qp_init_rd_atom) +\
            print_format.format('Max EE init RD atom', self.max_ee_init_rd_atom) +\
            print_format.format('Atomic caps', self.atomic_caps) +\
            print_format.format('Max EE', self.max_ee) +\
            print_format.format('Max RDD', self.max_rdd) +\
            print_format.format('Max MW', self.max_mw) +\
            print_format.format('Max raw IPv6 QPs', self.max_raw_ipv6_qps) +\
            print_format.format('Max raw ethy QP', self.max_raw_ethy_qp) +\
            print_format.format('Max mcast group', self.max_mcast_grp) +\
            print_format.format('Max mcast QP attach', self.max_mcast_qp_attach) +\
            print_format.format('Max AH', self.max_ah) +\
            print_format.format('Max FMR', self.max_fmr) +\
            print_format.format('Max map per FMR', self.max_map_per_fmr) +\
            print_format.format('Max SRQ', self.max_srq) +\
            print_format.format('Max SRQ WR', self.max_srq_wr) +\
            print_format.format('Max SRQ SGE', self.max_srq_sge) +\
            print_format.format('Max PKeys', self.max_pkeys) +\
            print_format.format('local CA ack delay', self.local_ca_ack_delay) +\
            print_format.format('Phys port count', self.phys_port_cnt)


cdef class QueryDeviceExInput(PyverbsObject):
    def __cinit__(self, comp_mask):
        self.ex_input.comp_mask = comp_mask


cdef class ODPCaps(PyverbsObject):
    @property
    def general_caps(self):
        return self.odp_caps.general_caps
    @property
    def rc_odp_caps(self):
        return self.odp_caps.per_transport_caps.rc_odp_caps
    @property
    def uc_odp_caps(self):
        return self.odp_caps.per_transport_caps.uc_odp_caps
    @property
    def ud_odp_caps(self):
        return self.odp_caps.per_transport_caps.ud_odp_caps


cdef class TSOCaps(PyverbsObject):
    @property
    def max_tso(self):
        return self.tso_caps.max_tso
    @property
    def supported_qpts(self):
        return self.tso_caps.supported_qpts


cdef class RSSCaps(PyverbsObject):
    @property
    def supported_qpts(self):
        return self.rss_caps.supported_qpts
    @property
    def max_rwq_indirection_tables(self):
        return self.rss_caps.max_rwq_indirection_tables
    @property
    def rx_hash_fields_mask(self):
        return self.rss_caps.rx_hash_fields_mask
    @property
    def rx_hash_function(self):
        return self.rss_caps.rx_hash_function
    @property
    def max_rwq_indirection_table_size(self):
        return self.rss_caps.max_rwq_indirection_table_size


cdef class PacketPacingCaps(PyverbsObject):
    @property
    def qp_rate_limit_min(self):
        return self.packet_pacing_caps.qp_rate_limit_min
    @property
    def qp_rate_limit_max(self):
        return self.packet_pacing_caps.qp_rate_limit_max
    @property
    def supported_qpts(self):
        return self.packet_pacing_caps.supported_qpts


cdef class TMCaps(PyverbsObject):
    @property
    def max_rndv_hdr_size(self):
        return self.tm_caps.max_rndv_hdr_size
    @property
    def max_num_tags(self):
        return self.tm_caps.max_num_tags
    @property
    def flags(self):
        return self.tm_caps.flags
    @property
    def max_ops(self):
        return self.tm_caps.max_ops
    @property
    def max_sge(self):
        return self.tm_caps.max_sge


cdef class CQModerationCaps(PyverbsObject):
    @property
    def max_cq_count(self):
        return self.cq_mod_caps.max_cq_count
    @property
    def max_cq_period(self):
        return self.cq_mod_caps.max_cq_period


cdef class DeviceAttrEx(PyverbsObject):
    @property
    def orig_attr(self):
        attr = DeviceAttr()
        attr.dev_attr = self.dev_attr.orig_attr
        return attr
    @property
    def comp_mask(self):
        return self.dev_attr.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.dev_attr.comp_mask = val
    @property
    def odp_caps(self):
        caps = ODPCaps()
        caps.odp_caps = self.dev_attr.odp_caps
        return caps
    @property
    def completion_timestamp_mask(self):
        return self.dev_attr.completion_timestamp_mask
    @property
    def hca_core_clock(self):
        return self.dev_attr.hca_core_clock
    @property
    def device_cap_flags_ex(self):
        return self.dev_attr.device_cap_flags_ex
    @property
    def tso_caps(self):
        caps = TSOCaps()
        caps.tso_caps = self.dev_attr.tso_caps
        return caps
    @property
    def rss_caps(self):
        caps = RSSCaps()
        caps.rss_caps = self.dev_attr.rss_caps
        return caps
    @property
    def max_wq_type_rq(self):
        return self.dev_attr.max_wq_type_rq
    @property
    def packet_pacing_caps(self):
        caps = PacketPacingCaps()
        caps.packet_pacing_caps = self.dev_attr.packet_pacing_caps
        return caps
    @property
    def raw_packet_caps(self):
        return self.dev_attr.raw_packet_caps
    @property
    def tm_caps(self):
        caps = TMCaps()
        caps.tm_caps = self.dev_attr.tm_caps
        return caps
    @property
    def cq_mod_caps(self):
        caps = CQModerationCaps()
        caps.cq_mod_caps = self.dev_attr.cq_mod_caps
        return caps
    @property
    def max_dm_size(self):
        return self.dev_attr.max_dm_size


cdef class AllocDmAttr(PyverbsObject):
    def __cinit__(self, length, log_align_req = 0, comp_mask = 0):
        """
        Creates an AllocDmAttr object with the given parameters. This object
        can than be used to create a DM object.
        :param length: Length of the future device memory
        :param log_align_req: log2 of address alignment requirement
        :param comp_mask: compatibility mask
        :return: An AllocDmAttr object
        """
        self.alloc_dm_attr.length = length
        self.alloc_dm_attr.log_align_req = log_align_req
        self.alloc_dm_attr.comp_mask = comp_mask

    @property
    def length(self):
        return self.alloc_dm_attr.length

    @length.setter
    def length(self, val):
        self.alloc_dm_attr.length = val

    @property
    def log_align_req(self):
        return self.alloc_dm_attr.log_align_req

    @log_align_req.setter
    def log_align_req(self, val):
        self.alloc_dm_attr.log_align_req = val

    @property
    def comp_mask(self):
        return self.alloc_dm_attr.comp_mask

    @comp_mask.setter
    def comp_mask(self, val):
        self.alloc_dm_attr.comp_mask = val


cdef class DM(PyverbsCM):
    def __cinit__(self, Context context, AllocDmAttr dm_attr not None):
        """
        Allocate a device (direct) memory.
        :param context: The context of the device on which to allocate memory
        :param dm_attr: Attributes that define the DM
        :return: A DM object on success
        """
        self.dm_mrs = weakref.WeakSet()
        device_attr = context.query_device_ex()
        if device_attr.max_dm_size <= 0:
            raise PyverbsUserError('Device doesn\'t support dm allocation')
        self.dm = v.ibv_alloc_dm(<v.ibv_context*>context.context,
                                 &dm_attr.alloc_dm_attr)
        if self.dm == NULL:
            raise PyverbsRDMAErrno('Failed to allocate device memory of size '
                                   '{size}. Max available size {max}.'
                                   .format(size=dm_attr.length,
                                           max=device_attr.max_dm_size))
        self.context = context
        context.add_ref(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        self.logger.debug('Closing DM')
        self.close_weakrefs([self.dm_mrs])
        if self.dm != NULL:
            rc = v.ibv_free_dm(self.dm)
            if rc != 0:
                raise PyverbsRDMAErrno('Failed to free dm')
            self.dm = NULL
        self.context = None

    cdef add_ref(self, obj):
        if isinstance(obj, DMMR):
            self.dm_mrs.add(obj)

    def copy_to_dm(self, dm_offset, data, length):
        rc = v.ibv_memcpy_to_dm(<v.ibv_dm *>self.dm, <uint64_t>dm_offset,
                                <char *>data, <size_t>length)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to copy to dm')

    def copy_from_dm(self, dm_offset, length):
        cdef char *data =<char*>malloc(length)
        memset(data, 0, length)
        rc = v.ibv_memcpy_from_dm(<void *>data, <v.ibv_dm *>self.dm,
                                  <uint64_t>dm_offset, <size_t>length)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to copy from dm')
        res = data[:length]
        free(data)
        return res


cdef class PortAttr(PyverbsObject):
    @property
    def state(self):
        return self.attr.state
    @property
    def max_mtu(self):
        return self.attr.max_mtu
    @property
    def active_mtu(self):
        return self.attr.active_mtu
    @property
    def gid_tbl_len(self):
        return self.attr.gid_tbl_len
    @property
    def port_cap_flags(self):
        return self.attr.port_cap_flags
    @property
    def max_msg_sz(self):
        return self.attr.max_msg_sz
    @property
    def bad_pkey_cntr(self):
        return self.attr.bad_pkey_cntr
    @property
    def qkey_viol_cntr(self):
        return self.attr.qkey_viol_cntr
    @property
    def pkey_tbl_len(self):
        return self.attr.pkey_tbl_len
    @property
    def lid(self):
        return self.attr.lid
    @property
    def sm_lid(self):
        return self.attr.sm_lid
    @property
    def lmc(self):
        return self.attr.lmc
    @property
    def max_vl_num(self):
        return self.attr.max_vl_num
    @property
    def sm_sl(self):
        return self.attr.sm_sl
    @property
    def subnet_timeout(self):
        return self.attr.subnet_timeout
    @property
    def init_type_reply(self):
        return self.attr.init_type_reply
    @property
    def active_width(self):
        return self.attr.active_width
    @property
    def active_speed(self):
        return self.attr.active_speed
    @property
    def phys_state(self):
        return self.attr.phys_state
    @property
    def link_layer(self):
        return self.attr.link_layer
    @property
    def flags(self):
        return self.attr.flags
    @property
    def port_cap_flags2(self):
        return self.attr.port_cap_flags2

    def __str__(self):
        print_format = '{:<24}: {:<20}\n'
        return print_format.format('Port state', port_state_to_str(self.attr.state)) +\
            print_format.format('Max MTU', translate_mtu(self.attr.max_mtu)) +\
            print_format.format('Active MTU', translate_mtu(self.attr.active_mtu)) +\
            print_format.format('SM lid', self.attr.sm_lid) +\
            print_format.format('Port lid', self.attr.lid) +\
            print_format.format('lmc', hex(self.attr.lmc)) +\
            print_format.format('Link layer', translate_link_layer(self.attr.link_layer)) +\
            print_format.format('Max message size', hex(self.attr.max_msg_sz)) +\
            print_format.format('Port cap flags', translate_port_cap_flags(self.attr.port_cap_flags)) +\
            print_format.format('Port cap flags 2', translate_port_cap_flags2(self.attr.port_cap_flags2)) +\
            print_format.format('max VL num', self.attr.max_vl_num) +\
            print_format.format('Bad Pkey counter', self.attr.bad_pkey_cntr) +\
            print_format.format('Qkey violations counter', self.attr.qkey_viol_cntr) +\
            print_format.format('GID table len', self.attr.gid_tbl_len) +\
            print_format.format('Pkey table len', self.attr.pkey_tbl_len) +\
            print_format.format('SM sl', self.attr.sm_sl) +\
            print_format.format('Subnet timeout', self.attr.subnet_timeout) +\
            print_format.format('Init type reply', self.attr.init_type_reply) +\
            print_format.format('Active width', width_to_str(self.attr.active_width)) +\
            print_format.format('Active speed', speed_to_str(self.attr.active_speed)) +\
            print_format.format('Phys state', phys_state_to_str(self.attr.phys_state)) +\
            print_format.format('Flags', self.attr.flags)

def guid_format(num):
    """
    Get GUID representation of the given number, including change of endianness.
    :param num: Number to change to GUID format.
    :return: GUID-formatted string.
    """
    num = be64toh(num)
    hex_str = "%016x" % (num)
    hex_array = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    hex_array = [''.join(x) for x in zip(hex_array[0::2], hex_array[1::2])]
    return ':'.join(hex_array)

def translate_transport_type(transport_type):
    return {-1:'UNKNOWN', 0:'IB', 1:'IWARP', 2:'USNIC',
            3:'USNIC_UDP'}[transport_type]

def translate_node_type(node_type):
    return {-1:'UNKNOWN', 1:'CA', 2:'SWITCH', 3:'ROUTER',
            4:'RNIC', 5:'USNIC', 6:'USNIC_UDP'}[node_type]

def guid_to_hex(node_guid):
    return hex(node_guid).replace('L', '').replace('0x', '')

def port_state_to_str(port_state):
    l = {0: 'NOP', 1: 'Down', 2: 'Init', 3: 'Armed',4: 'Active',
         5: 'Active defer'}
    try:
        return '{s} ({n})'.format(s=l[port_state], n=port_state)
    except:
        return 'Invalid state'

def translate_mtu(mtu):
    l = {1: 256, 2: 512, 3: 1024, 4: 2048, 5: 4096}
    try:
        return '{s} ({n})'.format(s=l[mtu], n=mtu)
    except:
        return 'Invalid MTU'

def translate_link_layer(ll):
    l = {0: 'Unspecified', 1:'InfiniBand', 2:'Ethernet'}
    try:
        return l[ll]
    except:
        return 'Invalid link layer {ll}'.format(ll=ll)

def translate_port_cap_flags(flags):
    l = {e.IBV_PORT_SM: 'IBV_PORT_SM',
         e.IBV_PORT_NOTICE_SUP: 'IBV_PORT_NOTICE_SUP',
         e.IBV_PORT_TRAP_SUP: 'IBV_PORT_TRAP_SUP',
         e.IBV_PORT_OPT_IPD_SUP: 'IBV_PORT_OPT_IPD_SUP',
         e.IBV_PORT_AUTO_MIGR_SUP: 'IBV_PORT_AUTO_MIGR_SUP',
         e.IBV_PORT_SL_MAP_SUP: 'IBV_PORT_SL_MAP_SUP',
         e.IBV_PORT_MKEY_NVRAM: 'IBV_PORT_MKEY_NVRAM',
         e.IBV_PORT_PKEY_NVRAM: 'IBV_PORT_PKEY_NVRAM',
         e.IBV_PORT_LED_INFO_SUP: 'IBV_PORT_LED_INFO_SUP',
         e.IBV_PORT_SYS_IMAGE_GUID_SUP: 'IBV_PORT_SYS_IMAGE_GUID_SUP',
         e.IBV_PORT_PKEY_SW_EXT_PORT_TRAP_SUP: 'IBV_PORT_PKEY_SW_EXT_PORT_TRAP_SUP',
         e.IBV_PORT_EXTENDED_SPEEDS_SUP: 'IBV_PORT_EXTENDED_SPEEDS_SUP',
         e.IBV_PORT_CAP_MASK2_SUP: 'IBV_PORT_CAP_MASK2_SUP',
         e.IBV_PORT_CM_SUP: 'IBV_PORT_CM_SUP',
         e.IBV_PORT_SNMP_TUNNEL_SUP: 'IBV_PORT_SNMP_TUNNEL_SUP',
         e.IBV_PORT_REINIT_SUP: 'IBV_PORT_REINIT_SUP',
         e.IBV_PORT_DEVICE_MGMT_SUP: 'IBV_PORT_DEVICE_MGMT_SUP',
         e.IBV_PORT_VENDOR_CLASS_SUP: 'IBV_PORT_VENDOR_CLASS_SUP',
         e.IBV_PORT_DR_NOTICE_SUP: 'IBV_PORT_DR_NOTICE_SUP',
         e.IBV_PORT_CAP_MASK_NOTICE_SUP: 'IBV_PORT_CAP_MASK_NOTICE_SUP',
         e.IBV_PORT_BOOT_MGMT_SUP: 'IBV_PORT_BOOT_MGMT_SUP',
         e.IBV_PORT_LINK_LATENCY_SUP: 'IBV_PORT_LINK_LATENCY_SUP',
         e.IBV_PORT_CLIENT_REG_SUP: 'IBV_PORT_CLIENT_REG_SUP',
         e.IBV_PORT_IP_BASED_GIDS: 'IBV_PORT_IP_BASED_GIDS'}
    return str_from_flags(flags, l)

def translate_port_cap_flags2(flags):
    l = {e.IBV_PORT_SET_NODE_DESC_SUP: 'IBV_PORT_SET_NODE_DESC_SUP',
         e.IBV_PORT_INFO_EXT_SUP: 'IBV_PORT_INFO_EXT_SUP',
         e.IBV_PORT_VIRT_SUP: 'IBV_PORT_VIRT_SUP',
         e.IBV_PORT_SWITCH_PORT_STATE_TABLE_SUP: 'IBV_PORT_SWITCH_PORT_STATE_TABLE_SUP',
         e.IBV_PORT_LINK_WIDTH_2X_SUP: 'IBV_PORT_LINK_WIDTH_2X_SUP',
         e.IBV_PORT_LINK_SPEED_HDR_SUP: 'IBV_PORT_LINK_SPEED_HDR_SUP'}
    return str_from_flags(flags, l)

def str_from_flags(flags, dictionary):
    str_flags = ""
    for bit in dictionary:
        if flags & bit:
            str_flags += dictionary[bit]
            str_flags += ' '
    return str_flags

def phys_state_to_str(phys):
    l =  {1: 'Sleep', 2: 'Polling', 3: 'Disabled',
          4: 'Port configuration training', 5: 'Link up',
          6: 'Link error recovery', 7: 'Phy test'}
    try:
        return '{s} ({n})'.format(s=l[phys], n=phys)
    except:
        return 'Invalid physical state'

def width_to_str(width):
    l = {1: '1X', 2: '4X', 4: '8X', 16: '2X'}
    try:
        return '{s} ({n})'.format(s=l[width], n=width)
    except:
        return 'Invalid width'

def speed_to_str(speed):
    l = {1: '2.5 Gbps', 2: '5.0 Gbps', 4: '5.0 Gbps', 8: '10.0 Gbps',
         16: '14.0 Gbps', 32: '25.0 Gbps', 64: '50.0 Gbps'}
    try:
        return '{s} ({n})'.format(s=l[speed], n=speed)
    except:
        return 'Invalid speed'

def get_device_list():
    """
    :return: list of IB_devices on current node
             each list element contains a Device with:
                 device name
                 device node type
                 device transport type
                 device guid
    """
    cdef int count = 0;
    cdef v.ibv_device **dev_list;
    dev_list = v.ibv_get_device_list(&count)
    if dev_list == NULL:
            raise PyverbsRDMAError('Failed to get devices list')
    devices = []
    try:
        for i in range(count):
            name = dev_list[i].name
            node = dev_list[i].node_type
            transport = dev_list[i].transport_type
            guid = be64toh(v.ibv_get_device_guid(dev_list[i]))
            devices.append(Device(name, guid, node, transport))
    finally:
        v.ibv_free_device_list(dev_list)
    return devices
