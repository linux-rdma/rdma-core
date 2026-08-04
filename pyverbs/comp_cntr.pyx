# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright Amazon.com, Inc. or its affiliates. All rights reserved.

#cython: language_level=3

from pyverbs.base import PyverbsRDMAErrno, PyverbsRDMAError
from pyverbs.device cimport Context
cimport pyverbs.libibverbs as v


cdef class CompCntrInitAttr(PyverbsObject):
    """Represents ibv_comp_cntr_init_attr struct."""
    def __init__(self, comp_mask=0, cntr_type=0, flags=0):
        super().__init__()
        self.attr.comp_mask = comp_mask
        self.attr.type = cntr_type
        self.attr.flags = flags

    @property
    def comp_mask(self):
        return self.attr.comp_mask

    @property
    def cntr_type(self):
        return self.attr.type

    @property
    def flags(self):
        return self.attr.flags


cdef class CompCntr(PyverbsCM):
    """Completion Counter object for tracking aggregate completions."""
    def __init__(self, Context ctx not None, CompCntrInitAttr attr not None):
        """Create a completion counter.

        :param ctx: Device context to create the counter on.
        :param attr: Completion counter init attributes.
        """
        super().__init__()
        self.comp_cntr = v.ibv_create_comp_cntr(ctx.context, &attr.attr)
        if self.comp_cntr == NULL:
            raise PyverbsRDMAErrno('Failed to create comp_cntr')
        self.ctx = ctx
        ctx.add_ref(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        """Destroy the completion counter."""
        if self.comp_cntr != NULL:
            rc = v.ibv_destroy_comp_cntr(self.comp_cntr)
            if rc:
                raise PyverbsRDMAError('Failed to destroy comp_cntr', rc)
            self.comp_cntr = NULL

    def set(self, value):
        """Set the completion count to the given value."""
        rc = v.ibv_set_comp_cntr(self.comp_cntr, value)
        if rc:
            raise PyverbsRDMAError('Failed to set comp_cntr', rc)

    def set_err(self, value):
        """Set the error count to the given value."""
        rc = v.ibv_set_err_comp_cntr(self.comp_cntr, value)
        if rc:
            raise PyverbsRDMAError('Failed to set_err comp_cntr', rc)

    def inc(self, amount):
        """Increment the completion count by amount."""
        rc = v.ibv_inc_comp_cntr(self.comp_cntr, amount)
        if rc:
            raise PyverbsRDMAError('Failed to inc comp_cntr', rc)

    def inc_err(self, amount):
        """Increment the error count by amount."""
        rc = v.ibv_inc_err_comp_cntr(self.comp_cntr, amount)
        if rc:
            raise PyverbsRDMAError('Failed to inc_err comp_cntr', rc)

    def read(self):
        """Read and return the current completion count."""
        cdef unsigned long value = 0
        rc = v.ibv_read_comp_cntr(self.comp_cntr, &value)
        if rc:
            raise PyverbsRDMAError('Failed to read comp_cntr', rc)
        return value

    def read_err(self):
        """Read and return the current error count."""
        cdef unsigned long value = 0
        rc = v.ibv_read_err_comp_cntr(self.comp_cntr, &value)
        if rc:
            raise PyverbsRDMAError('Failed to read_err comp_cntr', rc)
        return value
