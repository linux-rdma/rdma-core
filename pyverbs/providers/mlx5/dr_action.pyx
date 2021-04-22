# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

from pyverbs.base import PyverbsRDMAErrno, PyverbsRDMAError
from pyverbs.providers.mlx5.dr_domain cimport DrDomain
from pyverbs.providers.mlx5.dr_rule cimport DrRule
from pyverbs.pyverbs_error import PyverbsError
from pyverbs.base cimport close_weakrefs
from libc.stdlib cimport calloc, free
import weakref
import struct
import errno

be64toh = lambda num: struct.unpack('Q'.encode(), struct.pack('!8s'.encode(), num))[0]
ACTION_SIZE = 8


cdef class DrAction(PyverbsCM):
    def __init__(self):
        super().__init__()
        self.dr_rules = weakref.WeakSet()

    cdef add_ref(self, obj):
        if isinstance(obj, DrRule):
            self.dr_rules.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            self.logger.debug('Closing DrAction.')
            close_weakrefs([self.dr_rules])
            rc = dv.mlx5dv_dr_action_destroy(self.action)
            if rc:
                raise PyverbsRDMAError('Failed to destroy DrAction.', rc)
            self.action = NULL


cdef class DrActionQp(DrAction):
    def __init__(self, QP qp):
        super().__init__()
        self.action = dv.mlx5dv_dr_action_create_dest_ibv_qp((<QP>qp).qp)
        if self.action == NULL:
            raise PyverbsRDMAErrno('DrActionQp creation failed.')
        self.qp = <QP>qp
        qp.dr_actions.add(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            super(DrActionQp, self).close()
            self.qp = None

cdef class DrActionModify(DrAction):
    def __init__(self, DrDomain domain, flags=0, actions=list()):
        """
        Create DR modify header actions.
        :param domain: DrDomain object where the action should be located.
        :param flags: Modify action flags.
        :param actions: List of Bytes of the actions command input data
                        provided in a device specification format
                        (Stream of bytes or __bytes__ is implemented).
        """
        super().__init__()
        action_buf_size = len(actions) * ACTION_SIZE
        cdef unsigned long long *buf = <unsigned long long*>calloc(1, action_buf_size)
        if buf == NULL:
           raise MemoryError('Failed to allocate memory', errno)

        for i in range(len(actions)):
            buf[i] = be64toh(bytes(actions[i]))
        self.action = dv.mlx5dv_dr_action_create_modify_header(domain.domain, flags,
                                                               action_buf_size, buf)
        free(buf)

        if self.action == NULL:
            raise PyverbsRDMAErrno('Failed to create dr action modify header')
        self.domain = domain
        domain.dr_actions.add(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            super(DrActionModify, self).close()
            self.domain = None
