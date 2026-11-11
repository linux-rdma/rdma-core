# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2020-2026 Amazon.com, Inc. or its affiliates. All rights reserved.

cimport pyverbs.providers.efa.efa_enums as dve
cimport pyverbs.providers.efa.libefa as dv

import weakref

from pyverbs.addr cimport GID
from pyverbs.base import PyverbsRDMAErrno, PyverbsRDMAError
from pyverbs.base cimport PyverbsCM, close_weakrefs
from pyverbs.pyverbs_error import PyverbsError
from pyverbs.comp_cntr cimport CompCntrInitAttr, CompCntr
from pyverbs.cq cimport CQEX, CqInitAttrEx
from pyverbs.device cimport Context
from pyverbs.libibverbs_enums import ibv_qp_attr_mask
cimport pyverbs.libibverbs as v
from pyverbs.mr cimport MR
from pyverbs.pd cimport PD
from pyverbs.qp cimport QP, QPEx, QPInitAttr, QPInitAttrEx
from libc.string cimport memset
from libc.stdint cimport uintptr_t, uint8_t


def dev_cap_to_str(flags):
    l = {
            dve.EFADV_DEVICE_ATTR_CAPS_RDMA_READ: 'RDMA Read',
            dve.EFADV_DEVICE_ATTR_CAPS_RNR_RETRY: 'RNR Retry',
            dve.EFADV_DEVICE_ATTR_CAPS_CQ_WITH_SGID: 'CQ entries with source GID',
            dve.EFADV_DEVICE_ATTR_CAPS_RDMA_WRITE: 'RDMA Write',
            dve.EFADV_DEVICE_ATTR_CAPS_UNSOLICITED_WRITE_RECV: 'Unsolicited RDMA Write receive',
            dve.EFADV_DEVICE_ATTR_CAPS_CQ_WITH_EXT_MEM_DMABUF: 'CQ with external memory',
            dve.EFADV_DEVICE_ATTR_CAPS_COMP_CNTR: 'Completion Counters',
            dve.EFADV_DEVICE_ATTR_CAPS_COMP_ACTION: 'Completion Actions',
    }
    return bitmask_to_str(flags, l)


def bitmask_to_str(bits, values):
    numeric_bits = bits
    flags = []
    for k, v in sorted(values.items()):
        if bits & k:
            flags.append(v)
            bits -= k
    if bits:
        flags.append(f'??({bits:x})')
    if not flags:
        flags.append('None')
    return ', '.join(flags) + f' ({numeric_bits:x})'


cdef class EfaContext(Context):
    """
    Represent efa context, which extends Context.
    """
    def __init__(self, name=''):
        """
        Open an efa device
        :param name: The RDMA device's name (used by parent class)
        :return: None
        """
        super().__init__(name=name)
        self.comp_actions = weakref.WeakSet()

    cdef add_ref(self, obj):
        try:
            Context.add_ref(self, obj)
        except PyverbsError:
            if isinstance(obj, EfaCompAction):
                self.comp_actions.add(obj)
            else:
                raise PyverbsError('Unrecognized object type')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.context != NULL:
            close_weakrefs([self.comp_actions])
            super(EfaContext, self).close()

    def query_efa_device(self):
        """
        Queries the provider for device-specific attributes.
        :return: An EfaDVDeviceAttr containing the attributes.
        """
        dv_attr = EfaDVDeviceAttr()
        rc = dv.efadv_query_device(self.context, &dv_attr.device_attr, sizeof(dv_attr.device_attr))
        if rc:
            raise PyverbsRDMAError(f'Failed to query efa device {self.name}', rc)
        return dv_attr


cdef class EfaDVDeviceAttr(PyverbsObject):
    """
    Represents efadv_context struct, which exposes efa-specific capabilities,
    reported by efadv_query_device.
    """
    @property
    def comp_mask(self):
        return self.device_attr.comp_mask

    @property
    def max_sq_wr(self):
        return self.device_attr.max_sq_wr

    @property
    def max_rq_wr(self):
        return self.device_attr.max_rq_wr

    @property
    def max_sq_sge(self):
        return self.device_attr.max_sq_sge

    @property
    def max_rq_sge(self):
        return self.device_attr.max_rq_sge

    @property
    def inline_buf_size(self):
        return self.device_attr.inline_buf_size

    @property
    def inline_buf_size_ex(self):
        return self.device_attr.inline_buf_size_ex

    @property
    def device_caps(self):
        return self.device_attr.device_caps

    @property
    def max_rdma_size(self):
        return self.device_attr.max_rdma_size

    @property
    def max_comp_actions(self):
        return self.device_attr.max_comp_actions

    @property
    def comp_action_supp_ops(self):
        return self.device_attr.comp_action_supp_ops

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('comp_mask', self.device_attr.comp_mask) + \
            print_format.format('Max SQ WR', self.device_attr.max_sq_wr) + \
            print_format.format('Max RQ WR', self.device_attr.max_rq_wr) + \
            print_format.format('Max SQ SQE', self.device_attr.max_sq_sge) + \
            print_format.format('Max RQ SQE', self.device_attr.max_rq_sge) + \
            print_format.format('Inline buffer size', self.device_attr.inline_buf_size) + \
            print_format.format('Inline buffer size ex', self.device_attr.inline_buf_size_ex) + \
            print_format.format('Device Capabilities', dev_cap_to_str(self.device_attr.device_caps)) + \
            print_format.format('Max RDMA Size', self.device_attr.max_rdma_size) + \
            print_format.format('Max Comp Actions', self.device_attr.max_comp_actions) +\
            print_format.format('Comp Action Supported Ops', hex(self.device_attr.comp_action_supp_ops))


cdef class EfaDVAHAttr(PyverbsObject):
    """
    Represents efadv_ah_attr struct
    """
    @property
    def comp_mask(self):
        return self.ah_attr.comp_mask

    @property
    def ahn(self):
        return self.ah_attr.ahn

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('comp_mask', self.ah_attr.comp_mask) + \
            print_format.format('ahn', self.ah_attr.ahn)


cdef class EfaAH(AH):
    def query_efa_ah(self):
        """
        Queries the provider for EFA specific AH attributes.
        :return: An EfaDVAHAttr containing the attributes.
        """
        ah_attr = EfaDVAHAttr()
        err = dv.efadv_query_ah(self.ah, &ah_attr.ah_attr, sizeof(ah_attr.ah_attr))
        if err:
            raise PyverbsRDMAError('Failed to query efa ah', err)
        return ah_attr


cdef class SRDQP(QP):
    """
    Initializes an SRD QP according to the user-provided data.
    :param pd: PD object
    :param init_attr: QPInitAttr object
    :return: An initialized SRDQP
    """
    def __init__(self, PD pd not None, QPInitAttr init_attr not None):
        pd.add_ref(self)
        self.qp = dv.efadv_create_driver_qp(pd.pd, &init_attr.attr, dve.EFADV_QP_DRIVER_TYPE_SRD)
        if self.qp == NULL:
            raise PyverbsRDMAErrno('Failed to create SRD QP')
        super().__init__(pd, init_attr)


cdef class EfaQPInitAttr(PyverbsObject):
    """
    Represents efadv_qp_init_attr struct.
    """
    @property
    def comp_mask(self):
        return self.qp_init_attr.comp_mask

    @property
    def driver_qp_type(self):
        return self.qp_init_attr.driver_qp_type

    @driver_qp_type.setter
    def driver_qp_type(self, val):
        self.qp_init_attr.driver_qp_type = val

    @property
    def flags(self):
        return self.qp_init_attr.flags

    @flags.setter
    def flags(self, val):
        self.qp_init_attr.flags = val

    @property
    def sl(self):
        return self.qp_init_attr.sl

    @sl.setter
    def sl(self,val):
        self.qp_init_attr.sl = val

    @property
    def wr_flags(self):
        return self.qp_init_attr.wr_flags

    @wr_flags.setter
    def wr_flags(self, val):
        self.qp_init_attr.wr_flags = val


cdef class SRDQPEx(QPEx):
    """
    Initializes an SRD QPEx according to the user-provided data.
    :param ctx: Context object
    :param attr_ex: QPInitAttrEx object
    :param efa_init_attr: EFAQPInitAttr object
    :return: An initialized SRDQPEx
    """
    def __init__(self, Context ctx not None, QPInitAttrEx attr_ex not None, EfaQPInitAttr efa_init_attr not None):
        cdef PD pd
        self.qp = dv.efadv_create_qp_ex(ctx.context, &attr_ex.attr, &efa_init_attr.qp_init_attr, sizeof(efa_init_attr.qp_init_attr))
        if self.qp == NULL:
            raise PyverbsRDMAErrno('Failed to create SRD QPEx')
        self.context = ctx
        ctx.add_ref(self)
        if attr_ex.pd is not None:
            pd=<PD>attr_ex.pd
            pd.add_ref(self)
        super().__init__(ctx, attr_ex)
        self.dv_qp = dv.efadv_qp_from_ibv_qp_ex(self.qp_ex)

    def _get_comp_mask(self, dst):
        srd_mask = {'INIT': ibv_qp_attr_mask.IBV_QP_PKEY_INDEX | ibv_qp_attr_mask.IBV_QP_PORT | ibv_qp_attr_mask.IBV_QP_QKEY,
                    'RTR': 0,
                    'RTS': ibv_qp_attr_mask.IBV_QP_SQ_PSN}
        return srd_mask [dst] | ibv_qp_attr_mask.IBV_QP_STATE

    def wr_set_processing_hints(self, hints):
        dv.efadv_wr_set_processing_hints(self.dv_qp, hints)

    def wr_set_local_comp_action(self, action_id):
        dv.efadv_wr_set_local_comp_action(self.dv_qp, action_id)

    def wr_set_remote_comp_action(self, action_id):
        dv.efadv_wr_set_remote_comp_action(self.dv_qp, action_id)

    def wr_set_local_comp_action_with_data(self, action_id, data):
        dv.efadv_wr_set_local_comp_action_with_data(self.dv_qp, action_id, data)

    def wr_set_remote_comp_action_with_data(self, action_id, data):
        dv.efadv_wr_set_remote_comp_action_with_data(self.dv_qp, action_id, data)


cdef class EfaDVCQInitAttr(PyverbsObject):
    """
    Represents efadv_cq_init_attr struct.
    """
    def __init__(self, wc_flags=0):
        super().__init__()
        self.cq_init_attr.wc_flags = wc_flags

    @property
    def comp_mask(self):
        return self.cq_init_attr.comp_mask

    @property
    def wc_flags(self):
        return self.cq_init_attr.wc_flags

    @wc_flags.setter
    def wc_flags(self, val):
        self.cq_init_attr.wc_flags = val


cdef class EfaCQ(CQEX):
    """
    Initializes an Efa CQ according to the user-provided data.
    :param ctx: Context object
    :param attr_ex: CQInitAttrEx object
    :param efa_init_attr: EfaDVCQInitAttr object
    :return: An initialized EfaCQ
    """
    def __init__(self, Context ctx not None, CqInitAttrEx attr_ex not None, EfaDVCQInitAttr efa_init_attr):
        if efa_init_attr is None:
            efa_init_attr = EfaDVCQInitAttr()
        self.cq = dv.efadv_create_cq(ctx.context, &attr_ex.attr, &efa_init_attr.cq_init_attr, sizeof(efa_init_attr.cq_init_attr))
        if self.cq == NULL:
            raise PyverbsRDMAErrno('Failed to create EFA CQ')
        self.ibv_cq = v.ibv_cq_ex_to_cq(self.cq)
        self.dv_cq = dv.efadv_cq_from_ibv_cq_ex(self.cq)
        self.context = ctx
        ctx.add_ref(self)
        super().__init__(ctx, attr_ex)

    def read_sgid(self):
        """
        Read SGID from last work completion, if AH is unknown.
        """
        sgid = GID()
        err = dv.efadv_wc_read_sgid(self.dv_cq, &sgid.gid)
        if err:
            return None
        return sgid

    def is_unsolicited(self):
        """
        Check if current work completion is unsolicited.
        """
        return dv.efadv_wc_is_unsolicited(self.dv_cq)


cdef class EfaDVMRAttr(PyverbsObject):
    """
    Represents efadv_mr_attr struct, which exposes efa-specific MR attributes,
    reported by efadv_query_mr.
    """
    @property
    def comp_mask(self):
        return self.mr_attr.comp_mask

    @property
    def ic_id_validity(self):
        return self.mr_attr.ic_id_validity

    @property
    def recv_ic_id(self):
        return self.mr_attr.recv_ic_id

    @property
    def rdma_read_ic_id(self):
        return self.mr_attr.rdma_read_ic_id

    @property
    def rdma_recv_ic_id(self):
        return self.mr_attr.rdma_recv_ic_id

    def __str__(self):
        print_format = '{:28}: {:<20}\n'
        return print_format.format('comp_mask', self.mr_attr.comp_mask) + \
            print_format.format('Interconnect id validity', self.mr_attr.ic_id_validity) + \
            print_format.format('Receive interconnect id', self.mr_attr.recv_ic_id) + \
            print_format.format('RDMA read interconnect id', self.mr_attr.rdma_read_ic_id) + \
            print_format.format('RDMA receive interconnect id', self.mr_attr.rdma_recv_ic_id)


cdef class EfaMR(MR):
    """
    Represents an MR with EFA specific properties
    """
    def query(self):
        """
        Queries the MR for device-specific attributes.
        :return: An EfaDVMRAttr containing the attributes.
        """
        mr_attr = EfaDVMRAttr()
        rc = dv.efadv_query_mr(self.mr, &mr_attr.mr_attr, sizeof(mr_attr.mr_attr))
        if rc:
            raise PyverbsRDMAError(f'Failed to query EFA MR', rc)

        return mr_attr


cdef class EfaDVSQDepthAttr(PyverbsObject):
    """
    Represents efadv_sq_depth_attr struct
    """
    @property
    def comp_mask(self):
        return self.sq_depth_attr.comp_mask

    @comp_mask.setter
    def comp_mask(self, val):
        self.sq_depth_attr.comp_mask = val

    @property
    def flags(self):
        return self.sq_depth_attr.flags

    @flags.setter
    def flags(self, val):
        self.sq_depth_attr.flags = val

    @property
    def max_send_sge(self):
        return self.sq_depth_attr.max_send_sge

    @max_send_sge.setter
    def max_send_sge(self, val):
        self.sq_depth_attr.max_send_sge = val

    @property
    def max_rdma_sge(self):
        return self.sq_depth_attr.max_rdma_sge

    @max_rdma_sge.setter
    def max_rdma_sge(self, val):
        self.sq_depth_attr.max_rdma_sge = val

    @property
    def max_inline_data(self):
        return self.sq_depth_attr.max_inline_data

    @max_inline_data.setter
    def max_inline_data(self, val):
        self.sq_depth_attr.max_inline_data = val


cdef class EfaDVRQDepthAttr(PyverbsObject):
    """
    Represents efadv_rq_depth_attr struct
    """
    @property
    def comp_mask(self):
        return self.sq_depth_attr.comp_mask

    @comp_mask.setter
    def comp_mask(self, val):
        self.rq_depth_attr.comp_mask = val

    @property
    def max_recv_sge(self):
        return self.sq_depth_attr.max_recv_sge

    @max_recv_sge.setter
    def max_recv_sge(self, val):
        self.rq_depth_attr.max_recv_sge = val


cdef class EfaCompCntrInitAttr(PyverbsObject):
    """Represents efadv_comp_cntr_init_attr struct."""
    cdef dv.efadv_comp_cntr_init_attr attr

    def __init__(self, comp_ext_mem_ptr=None, err_ext_mem_ptr=None):
        super().__init__()
        memset(&self.attr, 0, sizeof(self.attr))
        if comp_ext_mem_ptr is not None:
            self.attr.flags |= dve.EFADV_COMP_CNTR_INIT_WITH_COMP_EXTERNAL_MEM
            self.attr.comp_cntr_ext_mem.type = dve.EFADV_MEMORY_LOCATION_VA
            self.attr.comp_cntr_ext_mem.ptr = <uint8_t *><uintptr_t>comp_ext_mem_ptr
        if err_ext_mem_ptr is not None:
            self.attr.flags |= dve.EFADV_COMP_CNTR_INIT_WITH_ERR_EXTERNAL_MEM
            self.attr.err_cntr_ext_mem.type = dve.EFADV_MEMORY_LOCATION_VA
            self.attr.err_cntr_ext_mem.ptr = <uint8_t *><uintptr_t>err_ext_mem_ptr

    def set_comp_ext_mem_va(self, uintptr_t ptr):
        """Set completion counter external memory VA."""
        self.attr.flags |= dve.EFADV_COMP_CNTR_INIT_WITH_COMP_EXTERNAL_MEM
        self.attr.comp_cntr_ext_mem.type = dve.EFADV_MEMORY_LOCATION_VA
        self.attr.comp_cntr_ext_mem.ptr = <uint8_t *>ptr

    def set_err_ext_mem_va(self, uintptr_t ptr):
        """Set error counter external memory VA."""
        self.attr.flags |= dve.EFADV_COMP_CNTR_INIT_WITH_ERR_EXTERNAL_MEM
        self.attr.err_cntr_ext_mem.type = dve.EFADV_MEMORY_LOCATION_VA
        self.attr.err_cntr_ext_mem.ptr = <uint8_t *>ptr


cdef class EfaCompCntr(CompCntr):
    """EFA-specific Completion Counter with external memory support."""
    def __init__(self, Context ctx not None, CompCntrInitAttr attr not None,
                 EfaCompCntrInitAttr efa_attr=None):
        """Create an EFA completion counter.

        :param ctx: Device context.
        :param attr: Completion counter init attributes.
        :param efa_attr: EFA-specific init attributes (optional).
        """
        PyverbsCM.__init__(self)
        if efa_attr is None:
            efa_attr = EfaCompCntrInitAttr()
        self.comp_cntr = dv.efadv_create_comp_cntr(
            ctx.context, &attr.attr, &efa_attr.attr, sizeof(efa_attr.attr))
        if self.comp_cntr == NULL:
            raise PyverbsRDMAErrno('Failed to create EFA comp_cntr')
        self.ctx = ctx
        ctx.add_ref(self)

    def __dealloc__(self):
        self.close()


cdef class EfaMemCompActionInitAttr(PyverbsObject):
    """Represents efadv_mem_comp_action_init_attr struct."""
    def __init__(self, PD pd=None,
                 comp_mem_modify_type=dve.EFADV_MEM_COMP_ACTION_SET_INITIATOR_VAL,
                 mem_modify_size=4, mem_size=None, comp_mem_ptr=None):
        """Initialize memory completion action attributes.

        :param pd: The protection domain to associate the action with.
        :param comp_mem_modify_type: The memory modification performed on completion
                        (EFADV_MEM_COMP_ACTION_*).
        :param mem_modify_size: Size in bytes of each memory modification (1, 2 or 4).
        :param mem_size: Total size in bytes of the target region (defaults to
                         mem_modify_size, a single modification).
        :param comp_mem_ptr: VA of the application memory target (optional).
        """
        super().__init__()
        memset(&self.attr, 0, sizeof(self.attr))
        self.attr.comp_mem_modify_type = comp_mem_modify_type
        self.attr.mem_modify_size = mem_modify_size
        self.attr.mem_size = mem_modify_size if mem_size is None else mem_size
        if pd is not None:
            self.attr.pd = pd.pd
            self.pd = pd
        if comp_mem_ptr is not None:
            self.set_comp_mem_va(comp_mem_ptr)

    def set_comp_mem_va(self, uintptr_t ptr):
        """Set the completion memory target VA."""
        self.attr.comp_mem.type = dve.EFADV_MEMORY_LOCATION_VA
        self.attr.comp_mem.ptr = <uint8_t *>ptr

    @property
    def comp_mask(self):
        return self.attr.comp_mask

    @comp_mask.setter
    def comp_mask(self, val):
        self.attr.comp_mask = val

    @property
    def flags(self):
        return self.attr.flags

    @flags.setter
    def flags(self, val):
        self.attr.flags = val

    @property
    def comp_mem_modify_type(self):
        return self.attr.comp_mem_modify_type

    @comp_mem_modify_type.setter
    def comp_mem_modify_type(self, val):
        self.attr.comp_mem_modify_type = val

    @property
    def mem_modify_size(self):
        return self.attr.mem_modify_size

    @mem_modify_size.setter
    def mem_modify_size(self, val):
        self.attr.mem_modify_size = val

    @property
    def mem_size(self):
        return self.attr.mem_size

    @mem_size.setter
    def mem_size(self, val):
        self.attr.mem_size = val


cdef class EfaCompAction(PyverbsCM):
    """Represents an EFA Completion Action."""
    def __init__(self, Context ctx not None, EfaMemCompActionInitAttr attr not None):
        """Create a memory completion action.

        :param ctx: Device context.
        :param attr: Init attributes.
        """
        super().__init__()
        self.mem_action = dv.efadv_create_mem_comp_action(ctx.context, &attr.attr,
                                                          sizeof(attr.attr))
        if self.mem_action == NULL:
            raise PyverbsRDMAErrno('Failed to create EFA comp action')
        self.action = &self.mem_action.comp_action
        self.ctx = ctx
        self.pd = attr.pd
        ctx.add_ref(self)

    @property
    def handle(self):
        return self.action.handle

    @property
    def action_id(self):
        return self.action.action_id

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            rc = dv.efadv_destroy_comp_action(self.action)
            if rc:
                raise PyverbsRDMAError('Failed to destroy EFA comp action', rc)
            self.action = NULL
            self.mem_action = NULL
            self.ctx = None
            self.pd = None
