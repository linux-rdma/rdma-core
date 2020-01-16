# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

#cython: language_level=3

from .base cimport PyverbsObject, PyverbsCM
cimport pyverbs.libibverbs as v


cdef class Context(PyverbsCM):
    cdef v.ibv_context *context
    cdef v.ibv_device *device
    cdef object name
    cdef add_ref(self, obj)
    cdef object pds
    cdef object dms
    cdef object ccs
    cdef object cqs
    cdef object qps
    cdef object xrcds
    cdef object vars

cdef class DeviceAttr(PyverbsObject):
    cdef v.ibv_device_attr dev_attr

cdef class QueryDeviceExInput(PyverbsObject):
    cdef v.ibv_query_device_ex_input input

cdef class ODPCaps(PyverbsObject):
    cdef v.ibv_odp_caps odp_caps
    cdef object xrc_odp_caps

cdef class RSSCaps(PyverbsObject):
    cdef v.ibv_rss_caps rss_caps

cdef class PacketPacingCaps(PyverbsObject):
    cdef v.ibv_packet_pacing_caps packet_pacing_caps

cdef class PCIAtomicCaps(PyverbsObject):
    cdef v.ibv_pci_atomic_caps caps

cdef class TMCaps(PyverbsObject):
    cdef v.ibv_tm_caps tm_caps

cdef class CQModerationCaps(PyverbsObject):
    cdef v.ibv_cq_moderation_caps cq_mod_caps

cdef class TSOCaps(PyverbsObject):
    cdef v.ibv_tso_caps tso_caps

cdef class DeviceAttrEx(PyverbsObject):
    cdef v.ibv_device_attr_ex dev_attr

cdef class AllocDmAttr(PyverbsObject):
    cdef v.ibv_alloc_dm_attr alloc_dm_attr

cdef class DM(PyverbsCM):
    cdef v.ibv_dm *dm
    cdef object dm_mrs
    cdef object context
    cdef add_ref(self, obj)

cdef class PortAttr(PyverbsObject):
    cdef v.ibv_port_attr attr

cdef class VAR(PyverbsObject):
    cdef object context
    cpdef close(self)
