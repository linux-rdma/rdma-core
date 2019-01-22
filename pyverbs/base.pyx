# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved.

import logging
from pyverbs.pyverbs_error import PyverbsRDMAError


cdef extern from 'errno.h':
    int errno

cpdef PyverbsRDMAErrno(str msg):
    return PyverbsRDMAError(msg, errno)

LOG_LEVEL=logging.INFO
LOG_FORMAT='[%(levelname)s] %(asctime)s %(filename)s:%(lineno)s: %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=LOG_LEVEL, datefmt='%d %b %Y %H:%M:%S')

cdef class PyverbsObject(object):

    def __cinit__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def set_log_level(self, val):
        self.logger.setLevel(val)
