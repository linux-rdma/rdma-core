# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

from pyverbs.base import PyverbsRDMAErrno, PyverbsRDMAError
from pyverbs.providers.mlx5.dr_domain cimport DrDomain


cdef class DrTable(PyverbsCM):
    def __init__(self, DrDomain domain, level):
        """
        Initialize DrTable object over underlying mlx5dv_dr_table C object.
        :param domain: Domain object
        :param level: Table level
        """
        super().__init__()
        self.table = dv.mlx5dv_dr_table_create(domain.domain, level)
        if self.table == NULL:
            raise PyverbsRDMAErrno('DrTable creation failed.')
        domain.add_ref(self)
        self.dr_domain = domain

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.table != NULL:
            self.logger.debug('Closing DrTable.')
            rc = dv.mlx5dv_dr_table_destroy(self.table)
            if rc:
                raise PyverbsRDMAError('Failed to destroy DrTable.', rc)
            self.table = NULL
            self.dr_domain = None
