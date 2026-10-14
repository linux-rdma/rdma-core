# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2026 Broadcom. All rights reserved.
"""
Ultra Ethernet Transport objects.

A UET device addresses its peers through a *job*: a shared context, named by a
job id, that carries an address table indexed by resource index rather than by
per-peer connection state. A *job key* binds a protection domain to a job, and
is what a queue pair presents at creation time to say which job it belongs to.
"""
import weakref

from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError, \
    PyverbsUserError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.base cimport close_weakrefs
from pyverbs.device cimport Context
from pyverbs.addr cimport AHAttr
from pyverbs.pd cimport PD
cimport pyverbs.libibverbs_enums as e
cimport pyverbs.libibverbs as v


cdef class JobAttr(PyverbsObject):
    def __init__(self, comp_mask=0, flags=0, id=0, max_addr_entries=0,
                 port_num=1, sgid_index=0):
        """
        Initializes a JobAttr object, the attributes of a UET job.
        :param comp_mask: Which of the remaining fields are set, from
                          ibv_job_attr_mask
        :param flags: Job creation flags
        :param id: The job id, shared by every endpoint taking part in the job
        :param max_addr_entries: Size of the job's address table
        :param port_num: Port the job is created on
        :param sgid_index: Index into the port's GID table for the source
                           address
        """
        super().__init__()
        self.attr.comp_mask = comp_mask
        self.attr.flags = flags
        self.attr.id = id
        self.attr.max_addr_entries = max_addr_entries
        self.attr.port_num = port_num
        self.attr.sgid_index = sgid_index

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
    def id(self):
        return self.attr.id
    @id.setter
    def id(self, val):
        self.attr.id = val

    @property
    def max_addr_entries(self):
        return self.attr.max_addr_entries
    @max_addr_entries.setter
    def max_addr_entries(self, val):
        self.attr.max_addr_entries = val

    @property
    def port_num(self):
        return self.attr.port_num
    @port_num.setter
    def port_num(self, val):
        self.attr.port_num = val

    @property
    def sgid_index(self):
        return self.attr.sgid_index
    @sgid_index.setter
    def sgid_index(self, val):
        self.attr.sgid_index = val

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('comp mask', self.attr.comp_mask) +\
            print_format.format('flags', self.attr.flags) +\
            print_format.format('id', self.attr.id) +\
            print_format.format('max addr entries', self.attr.max_addr_entries) +\
            print_format.format('port num', self.attr.port_num) +\
            print_format.format('sgid index', self.attr.sgid_index)


cdef class AHAttrEx(PyverbsObject):
    def __init__(self, AHAttr ah_attr=None, remote_qpn=0):
        """
        Initializes an AHAttrEx object: an address handle attribute together
        with the remote queue pair number it addresses. This is what a job's
        address table holds, one per resource index.
        :param ah_attr: The address handle attribute
        :param remote_qpn: The queue pair number at the far end
        """
        super().__init__()
        if ah_attr is not None:
            self.attr.ah_attr = ah_attr.ah_attr
        self.attr.remote_qpn = remote_qpn

    @property
    def ah_attr(self):
        attr = AHAttr()
        attr.ah_attr = self.attr.ah_attr
        return attr
    @ah_attr.setter
    def ah_attr(self, AHAttr val not None):
        self.attr.ah_attr = val.ah_attr

    @property
    def remote_qpn(self):
        return self.attr.remote_qpn
    @remote_qpn.setter
    def remote_qpn(self, val):
        self.attr.remote_qpn = val

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return str(self.ah_attr) +\
            print_format.format('remote qpn', self.attr.remote_qpn)


cdef class QPSemantics(PyverbsObject):
    """
    The semantics of a queue pair: message ordering, the largest RDMA
    operations it will accept, and its payload MTU. Read what a device offers
    with query_qp_semantics(); hand one to QPInitAttrEx to state what a queue
    pair is being created with.
    """
    def __init__(self, comp_mask=0, msg_order=0, max_rdma_raw_size=0,
                 max_rdma_war_size=0, max_rdma_waw_size=0, max_pdu=0,
                 imm_data_size=0, usage_flags=0):
        """
        :param comp_mask: Which of the remaining fields are set, from
                          ibv_qp_semantics_mask
        :param msg_order: Message ordering guarantees
        :param max_rdma_raw_size: Largest read-after-write kept ordered
        :param max_rdma_war_size: Largest write-after-read kept ordered
        :param max_rdma_waw_size: Largest write-after-write kept ordered
        :param max_pdu: Payload MTU, the largest payload carried in one packet
        :param imm_data_size: Immediate data width, from ibv_imm_data_size
        :param usage_flags: Usage hints
        """
        super().__init__()
        self.semantics.comp_mask = comp_mask
        self.semantics.msg_order = msg_order
        self.semantics.max_rdma_raw_size = max_rdma_raw_size
        self.semantics.max_rdma_war_size = max_rdma_war_size
        self.semantics.max_rdma_waw_size = max_rdma_waw_size
        self.semantics.max_pdu = max_pdu
        self.semantics.imm_data_size = imm_data_size
        self.semantics.usage_flags = usage_flags

    @property
    def comp_mask(self):
        return self.semantics.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.semantics.comp_mask = val

    @property
    def msg_order(self):
        return self.semantics.msg_order
    @msg_order.setter
    def msg_order(self, val):
        self.semantics.msg_order = val

    @property
    def max_rdma_raw_size(self):
        return self.semantics.max_rdma_raw_size
    @max_rdma_raw_size.setter
    def max_rdma_raw_size(self, val):
        self.semantics.max_rdma_raw_size = val

    @property
    def max_rdma_war_size(self):
        return self.semantics.max_rdma_war_size
    @max_rdma_war_size.setter
    def max_rdma_war_size(self, val):
        self.semantics.max_rdma_war_size = val

    @property
    def max_rdma_waw_size(self):
        return self.semantics.max_rdma_waw_size
    @max_rdma_waw_size.setter
    def max_rdma_waw_size(self, val):
        self.semantics.max_rdma_waw_size = val

    @property
    def max_pdu(self):
        return self.semantics.max_pdu
    @max_pdu.setter
    def max_pdu(self, val):
        self.semantics.max_pdu = val

    @property
    def imm_data_size(self):
        return self.semantics.imm_data_size
    @imm_data_size.setter
    def imm_data_size(self, val):
        self.semantics.imm_data_size = val

    @property
    def usage_flags(self):
        return self.semantics.usage_flags
    @usage_flags.setter
    def usage_flags(self, val):
        self.semantics.usage_flags = val

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('comp mask', self.semantics.comp_mask) +\
            print_format.format('msg order', self.semantics.msg_order) +\
            print_format.format('max rdma raw', self.semantics.max_rdma_raw_size) +\
            print_format.format('max rdma war', self.semantics.max_rdma_war_size) +\
            print_format.format('max rdma waw', self.semantics.max_rdma_waw_size) +\
            print_format.format('max pdu', self.semantics.max_pdu) +\
            print_format.format('imm data size', self.semantics.imm_data_size) +\
            print_format.format('usage flags', self.semantics.usage_flags)


def query_qp_semantics(Context context not None, qp_type, port_num=1,
                       sgid_index=0):
    """
    Query the semantics the device offers for a queue pair type.
    :param context: The device's Context
    :param qp_type: The queue pair type, from ibv_qp_type
    :param port_num: Port to query
    :param sgid_index: Index into the port's GID table
    :return: A QPSemantics object
    """
    sem = QPSemantics()
    rc = v.ibv_query_qp_semantics(context.context, qp_type, port_num,
                                  sgid_index, &(<QPSemantics>sem).semantics,
                                  sizeof(v.ibv_qp_semantics))
    if rc != 0:
        raise PyverbsRDMAError('Failed to query QP semantics', rc)
    return sem


cdef class Job(PyverbsCM):
    def __init__(self, Context context not None, JobAttr attr=None,
                 user_context=None, **kwargs):
        """
        Allocates or imports a UET job.
        :param context: The Context the job is allocated on
        :param attr: A JobAttr describing the job. Required unless importing.
        :param user_context: An opaque object handed back on query
        :param kwargs: Arguments:
            * *fd*
                A file descriptor obtained from Job.export() in another
                process. If passed, the job is imported rather than allocated
                and attr is ignored.
        """
        super().__init__()
        fd = kwargs.get('fd')
        if fd is not None:
            rc = v.ibv_import_job(context.context, fd, &self.job)
            if rc != 0:
                raise PyverbsRDMAError('Failed to import job', rc)
            self._is_imported = True
        else:
            if attr is None:
                raise PyverbsUserError('A JobAttr is required to allocate a job')
            self.job = v.ibv_alloc_job(context.context, &attr.attr,
                                       <void*>user_context
                                       if user_context is not None else NULL)
            if self.job == NULL:
                raise PyverbsRDMAErrno('Failed to allocate job')
            self._is_imported = False
        self._user_context = user_context
        self.ctx = context
        context.add_ref(self)
        self.jkeys = weakref.WeakSet()
        if self.logger:
            self.logger.debug('Created Job')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.job != NULL:
            if self.logger:
                self.logger.debug('Closing Job')
            close_weakrefs([self.jkeys])
            rc = v.ibv_dealloc_job(self.job)
            if rc != 0:
                raise PyverbsRDMAError('Failed to deallocate job', rc)
            self.job = NULL
            self.ctx = None
            self._user_context = None

    cdef add_ref(self, obj):
        if isinstance(obj, JKey):
            self.jkeys.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    def query(self):
        """
        Query the job's attributes.
        :return: A JobAttr object
        """
        attr = JobAttr()
        rc = v.ibv_query_job(self.job, &(<JobAttr>attr).attr)
        if rc != 0:
            raise PyverbsRDMAError('Failed to query job', rc)
        return attr

    def export(self):
        """
        Export the job so another process can import it.
        :return: A file descriptor naming the job
        """
        cdef int fd = -1
        rc = v.ibv_export_job(self.job, &fd)
        if rc != 0:
            raise PyverbsRDMAError('Failed to export job', rc)
        return fd

    def insert_addr(self, AHAttrEx ah_attr not None, addr_idx, flags=0):
        """
        Insert a peer into the job's address table.
        :param ah_attr: The peer's address and remote queue pair number
        :param addr_idx: The resource index the peer is reachable at
        :param flags: Insertion flags
        """
        rc = v.ibv_insert_addr(self.job, &ah_attr.attr, addr_idx, flags)
        if rc != 0:
            raise PyverbsRDMAError('Failed to insert address at index '
                                   f'{addr_idx}', rc)

    def remove_addr(self, addr_idx, flags=0):
        """
        Remove a peer from the job's address table.
        :param addr_idx: The resource index to clear
        :param flags: Removal flags
        """
        rc = v.ibv_remove_addr(self.job, addr_idx, flags)
        if rc != 0:
            raise PyverbsRDMAError('Failed to remove address at index '
                                   f'{addr_idx}', rc)

    def query_addr(self, addr_idx, flags=0):
        """
        Read back a peer from the job's address table.
        :param addr_idx: The resource index to read
        :param flags: Query flags
        :return: An AHAttrEx object
        """
        attr = AHAttrEx()
        rc = v.ibv_query_addr(self.job, addr_idx, &(<AHAttrEx>attr).attr, flags)
        if rc != 0:
            raise PyverbsRDMAError('Failed to query address at index '
                                   f'{addr_idx}', rc)
        return attr

    @property
    def handle(self):
        return self.job.handle

    @property
    def is_imported(self):
        return bool(self._is_imported)

    @property
    def user_context(self):
        return self._user_context


cdef class JKey(PyverbsCM):
    def __init__(self, PD pd not None, Job job not None, flags=0):
        """
        Creates a job key: the binding between a protection domain and a job.
        A queue pair presents one at creation time to join the job, and the
        device refuses a key created against a different protection domain.
        :param pd: The protection domain to bind
        :param job: The job to bind it to
        :param flags: Creation flags
        """
        super().__init__()
        self.job_key = v.ibv_create_jkey(pd.pd, job.job, flags)
        if self.job_key == NULL:
            raise PyverbsRDMAErrno('Failed to create jkey')
        self.pd = pd
        self.job = job
        job.add_ref(self)
        if self.logger:
            self.logger.debug('Created JKey')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.job_key != NULL:
            if self.logger:
                self.logger.debug('Closing JKey')
            rc = v.ibv_destroy_jkey(self.job_key)
            if rc != 0:
                raise PyverbsRDMAError('Failed to destroy jkey', rc)
            self.job_key = NULL
            self.pd = None
            self.job = None

    @property
    def jkey(self):
        return self.job_key.jkey

    @property
    def handle(self):
        return self.job_key.handle
