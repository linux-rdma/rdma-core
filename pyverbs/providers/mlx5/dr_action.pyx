# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

from pyverbs.base import PyverbsRDMAErrno, PyverbsRDMAError


cdef class DrAction(PyverbsCM):
    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            self.logger.debug('Closing DrAction.')
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
