# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

from pyverbs.base import PyverbsRDMAErrno, PyverbsRDMAError
from pyverbs.providers.mlx5.dr_table import DrTable
from pyverbs.pyverbs_error import PyverbsError
from pyverbs.base cimport close_weakrefs
from pyverbs.device cimport Context
cimport pyverbs.libibverbs as v
import weakref


cdef class DrDomain(PyverbsCM):
    def __init__(self, Context context, domain_type):
        """
        Initialize DrDomain object over underlying mlx5dv_dr_domain C object.
        :param context: Context object
        :param domain_type: Type of the domain
        """
        super().__init__()
        self.domain = dv.mlx5dv_dr_domain_create(<v.ibv_context*>context.context, domain_type)
        if self.domain == NULL:
            raise PyverbsRDMAErrno('DrDomain creation failed.')
        self.dr_tables = weakref.WeakSet()

    cdef add_ref(self, obj):
        if isinstance(obj, DrTable):
            self.dr_tables.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.domain != NULL:
            self.logger.debug('Closing DrDomain.')
            close_weakrefs([self.dr_tables])
            rc = dv.mlx5dv_dr_domain_destroy(self.domain)
            if rc:
                raise PyverbsRDMAError('Failed to destroy DrDomain.', rc)
            self.domain = NULL
