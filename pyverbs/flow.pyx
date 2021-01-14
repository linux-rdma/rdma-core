# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia All rights reserved.

from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from pyverbs.base import PyverbsRDMAErrno
from libc.stdlib cimport calloc, free
from libc.string cimport memcpy
from pyverbs.qp cimport QP


cdef class FlowAttr(PyverbsObject):
    def __init__(self, num_of_specs=0, flow_type=v.IBV_FLOW_ATTR_NORMAL,
                 priority=0, port=1, flags=0):
        """
        Initialize a FlowAttr object over an underlying ibv_flow_attr C object
        which contains attributes for creating a steering flow.
        :param num_of_specs: number of specs
        :param flow_type: flow type
        :param priority: flow priority
        :param port: port number
        :param flags: flow flags
        """
        super().__init__()
        self.attr.type = flow_type
        self.attr.size = sizeof(v.ibv_flow_attr)
        self.attr.priority = priority
        self.attr.num_of_specs = num_of_specs
        self.attr.port = port
        self.attr.flags = flags
        self.specs = list()

    @property
    def type(self):
        return self.attr.type

    @type.setter
    def type(self, val):
        self.attr.type = val

    @property
    def priority(self):
        return self.attr.priority

    @priority.setter
    def priority(self, val):
        self.attr.priority = val

    @property
    def num_of_specs(self):
        return self.attr.num_of_specs

    @num_of_specs.setter
    def num_of_specs(self, val):
        self.attr.num_of_specs = val

    @property
    def port(self):
        return self.attr.port

    @port.setter
    def port(self, val):
        self.attr.port = val

    @property
    def flags(self):
        return self.attr.flags

    @flags.setter
    def flags(self, val):
        self.attr.flags = val

    @property
    def specs(self):
        return self.specs


cdef class Flow(PyverbsCM):
    def __init__(self, QP qp, FlowAttr flow_attr):
        """
        Initialize a Flow object over an underlying ibv_flow C object which
        represents a steering flow.
        :param qp: QP to create flow for
        :param flow_attr: Flow attributes for flow creation
        """
        super().__init__()
        cdef char *flow_addr
        cdef char *dst_addr
        cdef v.ibv_flow_attr attr = flow_attr.attr
        if flow_attr.num_of_specs != len(flow_attr.specs):
            self.logger.warn(f'The number of appended specs '
                             f'({len(flow_attr.specs)}) is not equal to the '
                             f'number of declared specs '
                             f'({flow_attr.flow_attr.num_of_specs})')
        # Calculate total size for allocation
        total_size = sizeof(v.ibv_flow_attr)
        for spec in flow_attr.specs:
            total_size += spec.size
        flow_addr = <char*>calloc(1, total_size)
        if flow_addr == NULL:
            raise PyverbsError(f'Failed to allocate memory of size '
                               f'{total_size}')
        dst_addr = flow_addr
        # Copy flow_attr at the beginning of the allocated memory
        memcpy(dst_addr, &attr, sizeof(v.ibv_flow_attr))
        dst_addr = <char*>(dst_addr + sizeof(v.ibv_flow_attr))
        # Copy specs one after another into the allocated memory after flow_attr
        for spec in flow_attr.specs:
            spec._copy_data(<unsigned long>dst_addr)
            dst_addr += spec.size

        self.flow = v.ibv_create_flow(qp.qp, <v.ibv_flow_attr*>flow_addr)
        free(flow_addr)
        if self.flow == NULL:
            raise PyverbsRDMAErrno('Flow creation failed')
        self.qp = qp
        qp.add_ref(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.flow != NULL:
            self.logger.debug('Closing Flow')
            rc = v.ibv_destroy_flow(self.flow)
            if rc != 0:
                raise PyverbsRDMAError('Failed to destroy Flow', rc)
            self.flow = NULL
            self.qp = None


cdef class FlowAction(PyverbsObject):
    def __cinit__(self):
        self.action = NULL
