# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2026 Hewlett Packard Enterprise Development LP
"""
CXI direct verbs needed to use Ultra Ethernet objects on a CXI device: the
LNI a PD is allocated from, and the PID bound to that PD.
"""
from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
from pyverbs.device cimport Context
from pyverbs.pd cimport PD
cimport pyverbs.libibverbs as v
from libc.stdint cimport uint32_t

cdef extern from "infiniband/cxidv.h":
    int cxidv_alloc_lni(v.ibv_context *context, uint32_t svc_id,
                        cxidv_lni **lni)
    int cxidv_destroy_lni(cxidv_lni *lni)
    int cxidv_alloc_pid(v.ibv_pd *pd, uint32_t flags, uint32_t *pid)


def alloc_pid(PD pd not None, uint32_t flags=0):
    cdef uint32_t pid
    rc = cxidv_alloc_pid(pd.pd, flags, &pid)
    if rc != 0:
        raise PyverbsRDMAError('Failed to allocate CXI PID', rc)
    return pid


cdef class LNI(PyverbsCM):
    def __init__(self, Context context not None, unsigned int svc_id=1):
        super().__init__()
        self.lni = NULL
        rc = cxidv_alloc_lni(context.context, svc_id, &self.lni)
        if rc != 0:
            raise PyverbsRDMAError('Failed to allocate CXI LNI', rc)
        self.ctx = context
        context.lnis.add(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        cdef int rc

        if self.lni != NULL:
            rc = cxidv_destroy_lni(self.lni)
            if rc != 0:
                raise PyverbsRDMAError('Failed to destroy CXI LNI', rc)
            self.lni = NULL
            self.ctx = None

    cdef add_ref(self, obj):
        raise PyverbsError('CXI LNI does not own Python resources')

    @property
    def handle(self):
        return self.lni.handle if self.lni != NULL else 0

    @property
    def id(self):
        return self.lni.id if self.lni != NULL else 0

    @property
    def svc_id(self):
        return self.lni.svc_id if self.lni != NULL else 0
