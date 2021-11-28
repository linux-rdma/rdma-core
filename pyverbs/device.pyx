# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

"""
Device module introduces the Context and DeviceAttr class.
It allows user to open an IB device (using Context(name=<name>) and query it,
which returns a DeviceAttr object.
"""
import weakref

from .pyverbs_error import PyverbsRDMAError, PyverbsError
from pyverbs.cq cimport CQEX, CQ, CompChannel
from .pyverbs_error import PyverbsUserError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.base cimport close_weakrefs
cimport pyverbs.libibverbs_enums as e
cimport pyverbs.libibverbs as v
cimport pyverbs.librdmacm as cm
from pyverbs.cmid cimport CMID
from pyverbs.xrcd cimport XRCD
from pyverbs.addr cimport GID
from pyverbs.mr import DMMR
from pyverbs.pd cimport PD
from pyverbs.qp cimport QP
from libc.stdlib cimport free, malloc
from libc.string cimport memset
from libc.stdint cimport uint64_t
from libc.stdint cimport uint16_t
from libc.stdint cimport uint32_t
from pyverbs.utils import gid_str

cdef extern from 'endian.h':
    unsigned long be64toh(unsigned long host_64bits);


class Device(PyverbsObject):
    """
    Device class represents the C ibv_device. It stores device's properties.
    It is not a part of objects creation order - there's no need for the user
    to create it for such purposes.
    """
    def __init__(self, name, guid, node_type, transport_type, index):
        self._node_type = node_type
        self._transport_type = transport_type
        self._name = name
        self._guid = guid
        self._index = index

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

    @property
    def index(self):
        return self._index

    def __str__(self):
        return 'Device {dev}, node type {ntype}, transport type {ttype},' \
               ' guid {guid}, index {index}'.format(dev=self.name.decode(),
                ntype=translate_node_type(self.node_type),
                ttype=translate_transport_type(self.transport_type),
                guid=guid_to_hex(self.guid), index=self._index)


cdef class Context(PyverbsCM):
    """
    Context class represents the C ibv_context.
    """
    def __init__(self, **kwargs):
        """
        Initializes a Context object. The function searches the IB devices list
        for a device with the name provided by the user. If such a device is
        found, it is opened (unless provider attributes were given).
        In case of cmid argument, CMID object already holds an ibv_context
        initiated pointer, hence all we have to do is assign this pointer to
        Context's object pointer.
        :param kwargs: Arguments:
            * *name*
              The device's name
            * *attr*
              Provider-specific attributes. If not None, it means that the
              device will be opened by the provider and __init__ will return
              after locating the requested device.
            * *cmid*
              A CMID object. If not None, it means that the device was already
              opened by a CMID class, and only a pointer assignment is missing.
            * *cmd_fd*
              A command FD. If passed, the device will be imported from the
              given cmd_fd using ibv_import_device.
        :return: None
        """
        cdef int count
        cdef v.ibv_device **dev_list
        cdef CMID cmid

        super().__init__()
        self.pds = weakref.WeakSet()
        self.dms = weakref.WeakSet()
        self.ccs = weakref.WeakSet()
        self.cqs = weakref.WeakSet()
        self.qps = weakref.WeakSet()
        self.xrcds = weakref.WeakSet()
        self.vars = weakref.WeakSet()
        self.uars = weakref.WeakSet()
        self.pps = weakref.WeakSet()
        self.sched_nodes = weakref.WeakSet()
        self.sched_leafs = weakref.WeakSet()
        self.dr_domains = weakref.WeakSet()

        self.name = kwargs.get('name')
        provider_attr = kwargs.get('attr')
        cmid = kwargs.get('cmid')
        cmd_fd = kwargs.get('cmd_fd')
        if cmid is not None:
            self.context = cmid.id.verbs
            cmid.ctx = self
            return
        if cmd_fd is not None:
            self.context = v.ibv_import_device(cmd_fd)
            if self.context == NULL:
                raise PyverbsRDMAErrno('Failed to import device')
            return

        if self.name is None:
            raise PyverbsUserError('Device name must be provided')
        dev_list = v.ibv_get_device_list(&count)
        if dev_list == NULL:
            raise PyverbsRDMAError('Failed to get devices list')
        try:
            for i in range(count):
                if dev_list[i].name.decode() == self.name:
                    if provider_attr is not None:
                        # A provider opens its own context, we're just
                        # setting its IB device
                        self.device = dev_list[i]
                        return
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
        if self.context != NULL:
            self.logger.debug('Closing Context')
            close_weakrefs([self.qps, self.ccs, self.cqs, self.dms, self.pds,
                            self.xrcds, self.vars, self.sched_leafs,
                            self.sched_nodes, self.dr_domains])
            rc = v.ibv_close_device(self.context)
            if rc != 0:
                raise PyverbsRDMAErrno(f'Failed to close device {self.name}')
            self.context = NULL

    @property
    def num_comp_vectors(self):
        return self.context.num_comp_vectors

    def query_device(self):
        """
        Queries the device's attributes.
        :return: A DeviceAttr object which holds the device's attributes as
                 reported by the hardware.
        """
        dev_attr = DeviceAttr()
        rc = v.ibv_query_device(self.context, &dev_attr.dev_attr)
        if rc != 0:
            raise PyverbsRDMAError('Failed to query device {name}'.
                                   format(name=self.name), rc)
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
            raise PyverbsRDMAError('Failed to query EX device {name}'.
                                   format(name=self.name), rc)
        return dev_attr_ex

    def query_pkey(self, unsigned int port_num, int index):
        cdef uint16_t pkey
        rc = v.ibv_query_pkey(self.context, port_num, index, &pkey)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to query pkey {index} of port {port_num}')
        return pkey

    def query_gid(self, unsigned int port_num, int index):
        gid = GID()
        rc = v.ibv_query_gid(self.context, port_num, index, &gid.gid)
        if rc != 0:
            raise PyverbsRDMAError('Failed to query gid {idx} of port {port}'.
                                                                   format(idx=index, port=port_num))
        return gid

    def query_gid_type(self, unsigned int port_num, unsigned int index):
        cdef v.ibv_gid_type_sysfs gid_type
        rc = v.ibv_query_gid_type(self.context, port_num, index, &gid_type)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to query gid type of port {p} and gid index {g}'
                                   .format(p=port_num, g=index))
        return gid_type

    def query_port(self, unsigned int port_num):
        """
        Query port <port_num> of the device and returns its attributes.
        :param port_num: Port number to query
        :return: PortAttr object on success
        """
        port_attrs = PortAttr()
        rc = v.ibv_query_port(self.context, port_num, &port_attrs.attr)
        if rc != 0:
            raise PyverbsRDMAError('Failed to query port {p}'.
                                   format(p=port_num), rc)
        return port_attrs

    def query_gid_table(self, size_t max_entries, uint32_t flags=0):
        """
        Queries the GID tables of the device for at most <max_entries> entries
        and returns them.
        :param max_entries: Maximum number of GID entries to retrieve
        :param flags: Specifies new extra members of struct ibv_gid_entry to
                      query
        :return: List of GIDEntry objects on success
        """
        cdef v.ibv_gid_entry *entries
        cdef v.ibv_gid_entry entry

        entries = <v.ibv_gid_entry *>malloc(max_entries *
                                            sizeof(v.ibv_gid_entry))
        rc = v.ibv_query_gid_table(self.context, entries, max_entries, flags)
        if rc < 0:
            raise PyverbsRDMAError('Failed to query gid tables of the device',
                                   rc)
        gid_entries = []
        for i in range(rc):
            entry = entries[i]
            gid_entries.append(GIDEntry(entry.gid._global.subnet_prefix,
                               entry.gid._global.interface_id, entry.gid_index,
                               entry.port_num, entry.gid_type,
                               entry.ndev_ifindex))
        free(entries)
        return gid_entries

    def query_gid_ex(self, uint32_t port_num, uint32_t gid_index,
                     uint32_t flags=0):
        """
        Queries the GID table of port <port_num> in index <gid_index>, and
        returns the GID entry.
        :param port_num: The port number to query
        :param gid_index: The index in the GID table to query
        :param flags: Specifies new extra members of struct ibv_gid_entry to
                      query
        :return: GIDEntry object on success
        """
        entry = GIDEntry()
        rc = v.ibv_query_gid_ex(self.context, port_num, gid_index,
                                &entry.entry, flags)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to query gid table of port '\
                                   f'{port_num} in index {gid_index}', rc)
        return entry

    def query_rt_values_ex(self, comp_mask=v.IBV_VALUES_MASK_RAW_CLOCK):
        """
        Query an RDMA device for some real time values.
        :return: A tuple of the real time values according to comp_mask (sec, nsec)
        """
        cdef v.ibv_values_ex *val
        val = <v.ibv_values_ex *>malloc(sizeof(v.ibv_values_ex))
        val.comp_mask = comp_mask
        rc = v.ibv_query_rt_values_ex(self.context, val)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to query real time values', rc)
        if val.comp_mask != comp_mask:
            raise PyverbsRDMAError(f'Failed to query real time values with requested comp_mask')
        nsec = (<v.ibv_values_ex *>val).raw_clock.tv_nsec
        sec = (<v.ibv_values_ex *>val).raw_clock.tv_sec
        free(val)
        return sec, nsec

    cdef add_ref(self, obj):
        if isinstance(obj, PD):
            self.pds.add(obj)
        elif isinstance(obj, DM):
            self.dms.add(obj)
        elif isinstance(obj, CompChannel):
            self.ccs.add(obj)
        elif isinstance(obj, CQ) or isinstance(obj, CQEX):
            self.cqs.add(obj)
        elif isinstance(obj, QP):
            self.qps.add(obj)
        elif isinstance(obj, XRCD):
            self.xrcds.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    def get_async_event(self):
        event = AsyncEvent()
        rc = v.ibv_get_async_event(self.context, &event.event)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to get async event', rc)
        return event

    @property
    def cmd_fd(self):
        return self.context.cmd_fd

    @property
    def name(self):
        return self.name


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
            print_format.format('Device cap flags',
                                translate_device_caps(self.device_cap_flags)) +\
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
    def __init__(self, comp_mask):
        super().__init__()
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
    @property
    def xrc_odp_caps(self):
        return self.xrc_odp_caps
    @xrc_odp_caps.setter
    def xrc_odp_caps(self, val):
       self.xrc_odp_caps = val

    def __str__(self):
        general_caps = {e.IBV_ODP_SUPPORT: 'IBV_ODP_SUPPORT',
              e.IBV_ODP_SUPPORT_IMPLICIT: 'IBV_ODP_SUPPORT_IMPLICIT'}

        l = {e.IBV_ODP_SUPPORT_SEND: 'IBV_ODP_SUPPORT_SEND',
             e.IBV_ODP_SUPPORT_RECV: 'IBV_ODP_SUPPORT_RECV',
             e.IBV_ODP_SUPPORT_WRITE: 'IBV_ODP_SUPPORT_WRITE',
             e.IBV_ODP_SUPPORT_READ: 'IBV_ODP_SUPPORT_READ',
             e.IBV_ODP_SUPPORT_ATOMIC: 'IBV_ODP_SUPPORT_ATOMIC',
             e.IBV_ODP_SUPPORT_SRQ_RECV: 'IBV_ODP_SUPPORT_SRQ_RECV'}

        print_format = '{}: {}\n'
        return print_format.format('ODP General caps', str_from_flags(self.general_caps, general_caps)) +\
            print_format.format('RC ODP caps', str_from_flags(self.rc_odp_caps, l)) +\
            print_format.format('UD ODP caps', str_from_flags(self.ud_odp_caps, l)) +\
            print_format.format('UC ODP caps', str_from_flags(self.uc_odp_caps, l)) +\
            print_format.format('XRC ODP caps', str_from_flags(self.xrc_odp_caps, l))


cdef class PCIAtomicCaps(PyverbsObject):
    @property
    def fetch_add(self):
        return self.caps.fetch_add
    @property
    def swap(self):
        return self.caps.swap
    @property
    def compare_swap(self):
        return self.caps.compare_swap


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
        caps.xrc_odp_caps = self.dev_attr.xrc_odp_caps
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
    def pci_atomic_caps(self):
        caps = PCIAtomicCaps()
        caps.caps = self.dev_attr.pci_atomic_caps
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
    @property
    def phys_port_cnt_ex(self):
        return self.dev_attr.phys_port_cnt_ex


cdef class AllocDmAttr(PyverbsObject):
    def __init__(self, length, log_align_req = 0, comp_mask = 0):
        """
        Creates an AllocDmAttr object with the given parameters. This object
        can than be used to create a DM object.
        :param length: Length of the future device memory
        :param log_align_req: log2 of address alignment requirement
        :param comp_mask: compatibility mask
        :return: An AllocDmAttr object
        """
        super().__init__()
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
    def __init__(self, Context context, AllocDmAttr dm_attr=None, **kwargs):
        """
        Allocate a device (direct) memory.
        :param context: The context of the device on which to allocate memory
        :param dm_attr: Attributes that define the DM
        :param kwargs: Arguments:
            * *handle*
                A valid kernel handle for a DM object in the given context.
                If passed, the DM will be imported and associated with the
                given context using ibv_import_dm.
        :return: A DM object on success
        """
        super().__init__()
        self.dm_mrs = weakref.WeakSet()

        dm_handle = kwargs.get('handle')
        if dm_handle is not None:
            self.dm = v.ibv_import_dm(context.context, dm_handle)
            if self.dm == NULL:
                raise PyverbsRDMAErrno('Failed to import DM')
            self._is_imported = True
        else:
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

    def unimport(self):
        v.ibv_unimport_dm(self.dm)
        self.close()

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        """
        Closes the underlying C object of the DM.
        In case of an imported DM, the DM won't be freed, and it's kept for the
        original DM object, in order to prevent double free by Python GC.
        """
        if self.dm != NULL:
            self.logger.debug('Closing DM')
            close_weakrefs([self.dm_mrs])
            if not self._is_imported:
                rc = v.ibv_free_dm(self.dm)
                if rc != 0:
                    raise PyverbsRDMAError('Failed to free dm', rc)
            self.dm = NULL
            self.context = None

    cdef add_ref(self, obj):
        if isinstance(obj, DMMR):
            self.dm_mrs.add(obj)

    def copy_to_dm(self, dm_offset, data, length):
        rc = v.ibv_memcpy_to_dm(<v.ibv_dm *>self.dm, <uint64_t>dm_offset,
                                <char *>data, <size_t>length)
        if rc != 0:
            raise PyverbsRDMAError('Failed to copy to dm', rc)

    def copy_from_dm(self, dm_offset, length):
        cdef char *data =<char*>malloc(length)
        memset(data, 0, length)
        rc = v.ibv_memcpy_from_dm(<void *>data, <v.ibv_dm *>self.dm,
                                  <uint64_t>dm_offset, <size_t>length)
        if rc != 0:
            raise PyverbsRDMAError('Failed to copy from dm', rc)
        res = data[:length]
        free(data)
        return res

    @property
    def handle(self):
        return self.dm.handle


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


cdef class GIDEntry(PyverbsObject):
    def __init__(self, subnet_prefix=0, interface_id=0, gid_index=0,
                 port_num=0, gid_type=0, ndev_ifindex=0):
        super().__init__()
        self.entry.gid._global.subnet_prefix = subnet_prefix
        self.entry.gid._global.interface_id = interface_id
        self.entry.gid_index = gid_index
        self.entry.port_num = port_num
        self.entry.gid_type = gid_type
        self.entry.ndev_ifindex = ndev_ifindex

    @property
    def gid_subnet_prefix(self):
        return self.entry.gid._global.subnet_prefix

    @property
    def gid_interface_id(self):
        return self.entry.gid._global.interface_id

    @property
    def gid_index(self):
        return self.entry.gid_index

    @property
    def port_num(self):
        return self.entry.port_num

    @property
    def gid_type(self):
        return self.entry.gid_type

    @property
    def ndev_ifindex(self):
        return self.entry.ndev_ifindex

    def gid_str(self):
        return gid_str(self.gid_subnet_prefix, self.gid_interface_id)

    def __str__(self):
        print_format = '{:<24}: {:<20}\n'
        return print_format.format('GID', self.gid_str()) +\
            print_format.format('GID Index', self.gid_index) +\
            print_format.format('Port number', self.port_num) +\
            print_format.format('GID type', translate_gid_type(
                                self.gid_type)) +\
            print_format.format('Ndev ifindex', self.ndev_ifindex)


cdef class AsyncEvent(PyverbsObject):
    def __init__(self, event_type=0):
        super().__init__()
        self.event.event_type = event_type

    def ack(self):
        v.ibv_ack_async_event(&self.event)

    @property
    def event_type(self):
        return self.event.event_type

    def __str__(self):
        print_format = '{:<24}: {:<20}\n'
        return print_format.format('Event Type', translate_event_type(
                                   self.event.event_type))


def translate_gid_type(gid_type):
    types = {e.IBV_GID_TYPE_IB: 'IB', e.IBV_GID_TYPE_ROCE_V1: 'RoCEv1',
             e.IBV_GID_TYPE_ROCE_V2: 'RoCEv2'}
    try:
        return types[gid_type]
    except KeyError:
        return f'Unknown gid_type ({gid_type})'


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
    l = {0: 'IB', 1: 'IWARP', 2: 'USNIC', 3: 'USNIC UDP'}
    try:
        return l[transport_type]
    except KeyError:
        return 'Unknown'


def translate_node_type(node_type):
    l = {1: 'CA', 2: 'Switch', 3: 'Router', 4: 'RNIC', 5: 'USNIC',
         6: 'USNIC UDP'}
    try:
        return l[node_type]
    except KeyError:
        return 'Unknown'


def guid_to_hex(node_guid):
    return hex(node_guid).replace('L', '').replace('0x', '')


def port_state_to_str(port_state):
    l = {0: 'NOP', 1: 'Down', 2: 'Init', 3: 'Armed', 4: 'Active', 5: 'Defer'}
    try:
        return '{s} ({n})'.format(s=l[port_state], n=port_state)
    except KeyError:
        return 'Invalid state ({s})'.format(s=port_state)


def translate_mtu(mtu):
    l = {1: 256, 2: 512, 3: 1024, 4: 2048, 5: 4096}
    try:
        return '{s} ({n})'.format(s=l[mtu], n=mtu)
    except KeyError:
        return 'Invalid MTU ({m})'.format(m=mtu)


def translate_link_layer(ll):
    l = {0: 'Unspecified', 1:'InfiniBand', 2:'Ethernet'}
    try:
        return l[ll]
    except KeyError:
        return 'Invalid link layer ({ll})'.format(ll=ll)


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


def translate_device_caps(flags):
    l = {e.IBV_DEVICE_RESIZE_MAX_WR: 'IBV_DEVICE_RESIZE_MAX_WR',
         e.IBV_DEVICE_BAD_PKEY_CNTR: 'IBV_DEVICE_BAD_PKEY_CNTR',
         e.IBV_DEVICE_BAD_QKEY_CNTR: 'IBV_DEVICE_BAD_QKEY_CNTR',
         e.IBV_DEVICE_RAW_MULTI: 'IBV_DEVICE_RAW_MULTI',
         e.IBV_DEVICE_AUTO_PATH_MIG: 'IBV_DEVICE_AUTO_PATH_MIG',
         e.IBV_DEVICE_CHANGE_PHY_PORT: 'IBV_DEVICE_CHANGE_PHY_PORT',
         e.IBV_DEVICE_UD_AV_PORT_ENFORCE: 'IBV_DEVICE_UD_AV_PORT_ENFORCE',
         e.IBV_DEVICE_CURR_QP_STATE_MOD: 'IBV_DEVICE_CURR_QP_STATE_MOD',
         e.IBV_DEVICE_SHUTDOWN_PORT: 'IBV_DEVICE_SHUTDOWN_PORT',
         e.IBV_DEVICE_INIT_TYPE: 'IBV_DEVICE_INIT_TYPE',
         e.IBV_DEVICE_PORT_ACTIVE_EVENT: 'IBV_DEVICE_PORT_ACTIVE_EVENT',
         e.IBV_DEVICE_SYS_IMAGE_GUID: 'IBV_DEVICE_SYS_IMAGE_GUID',
         e.IBV_DEVICE_RC_RNR_NAK_GEN: 'IBV_DEVICE_RC_RNR_NAK_GEN',
         e.IBV_DEVICE_SRQ_RESIZE: 'IBV_DEVICE_SRQ_RESIZE',
         e.IBV_DEVICE_N_NOTIFY_CQ: 'IBV_DEVICE_N_NOTIFY_CQ',
         e.IBV_DEVICE_MEM_WINDOW: 'IBV_DEVICE_MEM_WINDOW',
         e.IBV_DEVICE_UD_IP_CSUM: 'IBV_DEVICE_UD_IP_CSUM',
         e.IBV_DEVICE_XRC: 'IBV_DEVICE_XRC',
         e.IBV_DEVICE_MEM_MGT_EXTENSIONS: 'IBV_DEVICE_MEM_MGT_EXTENSIONS',
         e.IBV_DEVICE_MEM_WINDOW_TYPE_2A: 'IBV_DEVICE_MEM_WINDOW_TYPE_2A',
         e.IBV_DEVICE_MEM_WINDOW_TYPE_2B: 'IBV_DEVICE_MEM_WINDOW_TYPE_2B',
         e.IBV_DEVICE_RC_IP_CSUM: 'IBV_DEVICE_RC_IP_CSUM',
         e.IBV_DEVICE_RAW_IP_CSUM: 'IBV_DEVICE_RAW_IP_CSUM',
         e.IBV_DEVICE_MANAGED_FLOW_STEERING: 'IBV_DEVICE_MANAGED_FLOW_STEERING'}
    return str_from_flags(flags, l)


def str_from_flags(flags, dictionary):
    str_flags = "\n  "
    for bit in dictionary:
        if flags & bit:
            str_flags += dictionary[bit]
            str_flags += '\n  '
    return str_flags


def phys_state_to_str(phys):
    l =  {1: 'Sleep', 2: 'Polling', 3: 'Disabled',
          4: 'Port configuration training', 5: 'Link up',
          6: 'Link error recovery', 7: 'Phy test'}
    try:
        return '{s} ({n})'.format(s=l[phys], n=phys)
    except KeyError:
        return 'Invalid physical state'


def width_to_str(width):
    l = {1: '1X', 2: '4X', 4: '8X', 16: '2X'}
    try:
        return '{s} ({n})'.format(s=l[width], n=width)
    except KeyError:
        return 'Invalid width'


def speed_to_str(speed):
    l = {0: '0.0 Gbps', 1: '2.5 Gbps', 2: '5.0 Gbps', 4: '5.0 Gbps',
         8: '10.0 Gbps', 16: '14.0 Gbps', 32: '25.0 Gbps', 64: '50.0 Gbps',
         128: '100.0 Gbps'}
    try:
        return '{s} ({n})'.format(s=l[speed], n=speed)
    except KeyError:
        return 'Invalid speed'


def get_device_list():
    """
    :return: list of IB_devices on current node
             each list element contains a Device with:
                 device name
                 device node type
                 device transport type
                 device guid
                 device index
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
            index = v.ibv_get_device_index(dev_list[i])
            devices.append(Device(name, guid, node, transport, index))
    finally:
        v.ibv_free_device_list(dev_list)
    return devices


def rdma_get_devices():
    """
    Get the RDMA devices.
    :return: list of Device objects.
    """
    cdef int count
    cdef v.ibv_context **ctx_list
    ctx_list = cm.rdma_get_devices(&count)
    if ctx_list == NULL:
        raise PyverbsRDMAErrno('Failed to get device list')
    devices = []
    for i in range(count):
        name = ctx_list[i].device.name
        node = ctx_list[i].device.node_type
        transport = ctx_list[i].device.transport_type
        guid = be64toh(v.ibv_get_device_guid(ctx_list[i].device))
        index = v.ibv_get_device_index(ctx_list[i].device)
        devices.append(Device(name, guid, node, transport, index))
    cm.rdma_free_devices(ctx_list)
    return devices


def translate_event_type(event_type):
    types = {
        e.IBV_EVENT_CQ_ERR: 'IBV_EVENT_CQ_ERR',
        e.IBV_EVENT_QP_FATAL: 'IBV_EVENT_QP_FATAL',
        e.IBV_EVENT_QP_REQ_ERR: 'IBV_EVENT_QP_REQ_ERR',
        e.IBV_EVENT_QP_ACCESS_ERR: 'IBV_EVENT_QP_ACCESS_ERR',
        e.IBV_EVENT_COMM_EST: 'IBV_EVENT_COMM_EST',
        e.IBV_EVENT_SQ_DRAINED: 'IBV_EVENT_SQ_DRAINED',
        e.IBV_EVENT_PATH_MIG: 'IBV_EVENT_PATH_MIG',
        e.IBV_EVENT_PATH_MIG_ERR: 'IBV_EVENT_PATH_MIG_ERR',
        e.IBV_EVENT_DEVICE_FATAL: 'IBV_EVENT_DEVICE_FATAL',
        e.IBV_EVENT_PORT_ACTIVE: 'IBV_EVENT_PORT_ACTIVE',
        e.IBV_EVENT_PORT_ERR: 'IBV_EVENT_PORT_ERR',
        e.IBV_EVENT_LID_CHANGE: 'IBV_EVENT_LID_CHANGE',
        e.IBV_EVENT_PKEY_CHANGE: 'IBV_EVENT_PKEY_CHANGE',
        e.IBV_EVENT_SM_CHANGE: 'IBV_EVENT_SM_CHANGE',
        e.IBV_EVENT_SRQ_ERR: 'IBV_EVENT_SRQ_ERR',
        e.IBV_EVENT_SRQ_LIMIT_REACHED: 'IBV_EVENT_SRQ_LIMIT_REACHED',
        e.IBV_EVENT_QP_LAST_WQE_REACHED: '.IBV_EVENT_QP_LAST_WQE_REACHED',
        e.IBV_EVENT_CLIENT_REREGISTER: 'IBV_EVENT_CLIENT_REREGISTER',
        e.IBV_EVENT_GID_CHANGE: 'IBV_EVENT_GID_CHANGE',
        e.IBV_EVENT_WQ_FATAL: 'IBV_EVENT_WQ_FATAL'
    }
    try:
        return types[event_type]
    except KeyError:
        return f'Unknown event_type ({event_type})'
