# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

from pyverbs.base import PyverbsRDMAErrno, PyverbsRDMAError
from pyverbs.providers.mlx5.dr_action cimport DrAction
from pyverbs.providers.mlx5.dr_table cimport DrTable
from pyverbs.pyverbs_error import PyverbsError
from pyverbs.base cimport close_weakrefs
from pyverbs.device cimport Context
cimport pyverbs.libibverbs as v
cimport libc.stdio as s
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
        self.context = context
        context.dr_domains.add(self)
        self.dr_actions = weakref.WeakSet()

    def allow_duplicate_rules(self, allow):
        """
        Allows or prevents duplicate rules insertion, by default this feature is
        allowed.
        :param allow: Boolean to allow or prevent
        """
        dv.mlx5dv_dr_domain_allow_duplicate_rules(self.domain, allow)

    cdef add_ref(self, obj):
        if isinstance(obj, DrTable):
            self.dr_tables.add(obj)
        elif isinstance(obj, DrAction):
            self.dr_actions.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    def sync(self, flags=dv.MLX5DV_DR_DOMAIN_SYNC_FLAGS_SW |
                         dv.MLX5DV_DR_DOMAIN_SYNC_FLAGS_HW):
        """
        Sync is used in order to flush the rule submission queue.
        :param flags:
            MLX5DV_DR_DOMAIN_SYNC_FLAGS_SW - block until completion of all
                                             software queued tasks
            MLX5DV_DR_DOMAIN_SYNC_FLAGS_HW - clear the steering HW cache to
                                             enforce next packet hits the
                                             latest rules.
            MLX5DV_DR_DOMAIN_SYNC_FLAGS_MEM - sync device memory to free cached
                                              memory.
        """
        if dv.mlx5dv_dr_domain_sync(self.domain, flags):
            raise PyverbsRDMAErrno('DrDomain sync failed.')

    def dump(self, filepath):
        """
        Dumps the debug info of the domain into a file.
        :param filepath: Path to the file
        """
        cdef s.FILE *fp
        fp = s.fopen(filepath.encode('utf-8'), 'w+')
        if fp == NULL:
            raise PyverbsError('Opening dump file failed.')
        rc = dv.mlx5dv_dump_dr_domain(fp, self.domain)
        if rc != 0:
            raise PyverbsRDMAError('Domain dump failed.', rc)
        if s.fclose(fp) != 0:
            raise PyverbsError('Closing dump file failed.')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.domain != NULL:
            self.logger.debug('Closing DrDomain.')
            close_weakrefs([self.dr_actions, self.dr_tables])
            rc = dv.mlx5dv_dr_domain_destroy(self.domain)
            if rc:
                raise PyverbsRDMAError('Failed to destroy DrDomain.', rc)
            self.domain = NULL
