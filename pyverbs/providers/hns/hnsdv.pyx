# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 HiSilicon Limited. All rights reserved.

from libc.stdint cimport uintptr_t, uint8_t, uint16_t, uint32_t
import logging

from pyverbs.pyverbs_error import PyverbsUserError

cimport pyverbs.providers.hns.hnsdv_enums as dve
cimport pyverbs.providers.hns.libhns as dv

from pyverbs.qp cimport QPInitAttrEx, QPEx
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.base cimport close_weakrefs
from pyverbs.pd cimport PD

cdef class HnsDVContextAttr(PyverbsObject):
    """
    Represent hnsdv_context_attr struct. This class is used to open an hns
    device.
    """
    def __init__(self, flags=0, comp_mask=0, dca_qps=1):
        super().__init__()
        self.attr.flags = flags
        self.attr.comp_mask = comp_mask
        if dca_qps > 0:
            self.attr.comp_mask |= dve.HNSDV_CONTEXT_MASK_DCA_PRIME_QPS
            self.attr.dca_prime_qps = dca_qps

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('flags', self.attr.flags) +\
               print_format.format('comp_mask', self.attr.comp_mask)

    @property
    def flags(self):
        return self.attr.flags
    @flags.setter
    def flags(self, val):
        self.attr.flags = val

    @property
    def comp_mask(self):
        return self.attr.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.attr.comp_mask = val

cdef class HnsContext(Context):
    """
    Represent hns context, which extends Context.
    """
    def __init__(self, HnsDVContextAttr attr not None, name=''):
        """
        Open an hns device using the given attributes
        :param name: The RDMA device's name (used by parent class)
        :param attr: hns-specific device attributes
        :return: None
        """
        super().__init__(name=name, attr=attr)
        if not dv.hnsdv_is_supported(self.device):
            raise PyverbsUserError('This is not an HNS device')
        self.context = dv.hnsdv_open_device(self.device, &attr.attr)
        if self.context == NULL:
            raise PyverbsRDMAErrno('Failed to open hns context on {dev}'
                                   .format(dev=self.name))

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.context != NULL:
            super(HnsContext, self).close()

cdef class HnsDVQPInitAttr(PyverbsObject):
    """
    Represents hnsdv_qp_init_attr struct, initial attributes used for hns QP
    creation.
    """
    def __init__(self, comp_mask=0, create_flags=0):
        """
        Initializes an HnsDVQPInitAttr object with the given user data.
        :param comp_mask: A bitmask specifying which fields are valid
        :param create_flags: A bitwise OR of hnsdv_qp_create_flags
        :return: An initialized HnsDVQPInitAttr object
        """
        super().__init__()
        self.attr.comp_mask = comp_mask
        self.attr.create_flags = create_flags

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('Comp mask',
                                   qp_comp_mask_to_str(self.attr.comp_mask)) +\
               print_format.format('Create flags',
                                   qp_create_flags_to_str(self.attr.create_flags))

    @property
    def comp_mask(self):
        return self.attr.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.attr.comp_mask = val

    @property
    def create_flags(self):
        return self.attr.create_flags
    @create_flags.setter
    def create_flags(self, val):
        self.attr.create_flags = val

cdef class HnsQP(QPEx):
    def __init__(self, Context context, QPInitAttrEx init_attr,
                 HnsDVQPInitAttr dv_init_attr):
        """
        Initializes an hns QP according to the user-provided data.
        :param context: Context object
        :param init_attr: QPInitAttrEx object
        :return: An initialized HnsQP
        """
        cdef PD pd

        # Initialize the logger here as the parent's __init__ is called after
        # the QP is allocated. Allocation can fail, which will lead to exceptions
        # thrown during object's teardown.
        self.logger = logging.getLogger(self.__class__.__name__)
        if init_attr.pd is not None:
            pd = <PD>init_attr.pd
            pd.add_ref(self)
        self.qp = \
            dv.hnsdv_create_qp(context.context,
                                &init_attr.attr,
                                &dv_init_attr.attr if dv_init_attr is not None
                                else NULL)
        if self.qp == NULL:
            raise PyverbsRDMAErrno('Failed to create HNS QP.\nQPInitAttrEx '
                                   'attributes:\n{}\nHNSDVQPInitAttr:\n{}'.
                                   format(init_attr, dv_init_attr))
        super().__init__(context, init_attr)

def bitmask_to_str(bits, values):
    numeric_bits = bits
    res = ''
    for t in values.keys():
        if t & bits:
            res += values[t] + ', '
            bits -= t
        if bits == 0:
            break
    return res[:-2] + ' ({})'.format(numeric_bits) # Remove last comma and space

def qp_comp_mask_to_str(flags):
    l = {dve.HNSDV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS: 'Create flags'}
    return bitmask_to_str(flags, l)

def qp_create_flags_to_str(flags):
    l = {dve.HNSDV_QP_CREATE_ENABLE_DCA_MODE: 'Enable DCA'}
    return bitmask_to_str(flags, l)
