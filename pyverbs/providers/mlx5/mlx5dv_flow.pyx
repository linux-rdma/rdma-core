# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

from libc.stdlib cimport calloc, free
from libc.string cimport memcpy

from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.device cimport Context
cimport pyverbs.libibverbs as v


cdef class Mlx5FlowMatchParameters(PyverbsObject):
    def __init__(self, size=0, values=bytes()):
        """
        Initialize a Mlx5FlowMatchParameters object over an underlying
        mlx5dv_flow_match_parameters C object that defines match parameters for
        steering flow.
        :param size: Length of the mask/value in bytes
        :param values: Bytes with mask/value to use in format of Flow Table
                       Entry Match Parameters Format table in PRM.
        """
        super().__init__()
        struct_size = sizeof(size_t) + size
        self.params = <dv.mlx5dv_flow_match_parameters *>calloc(1, struct_size)
        if self.params == NULL:
            raise PyverbsError(f'Failed to allocate buffer of size {struct_size}')
        self.params.match_sz = size
        if size:
            memcpy(self.params.match_buf, <char*>values, size)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.params != NULL:
            self.logger.debug('Closing Mlx5FlowMatchParameters')
            free(self.params)
            self.params = NULL


cdef class Mlx5FlowMatcherAttr(PyverbsObject):
    def __init__(self, Mlx5FlowMatchParameters match_mask,
                 attr_type=v.IBV_FLOW_ATTR_NORMAL, flags=0, priority=0,
                 match_criteria_enable=0, comp_mask=0, ft_type=0):
        """
        Initialize a Mlx5FlowMatcherAttr object over an underlying
        mlx5dv_flow_matcher_attr C object that defines matcher's attributes.
        :param match_mask: Match parameters to match on
        :param attr_type: Type of matcher to be created
        :param flags: Special flags to control rule: Nothing or zero value
                       means matcher will store ingress flow rules.
                       IBV_FLOW_ATTR_FLAGS_EGRESS: Specified this matcher will
                       store egress flow rules.
        :param priority: Matcher priority
        :param match_criteria_enable: Bitmask representing which of the
                                       headers and parameters in match_criteria
                                       are used in defining the Flow.
                                       Bit 0: outer_headers
                                       Bit 1: misc_parameters
                                       Bit 2: inner_headers
                                       Bit 3: misc_parameters_2
                                       Bit 4: misc_parameters_3
                                       Bit 5: misc_parameters_4
        :param comp_mask: MLX5DV_FLOW_MATCHER_MASK_FT_TYPE for ft_type (the
                           only option that is currently supported)
        :param ft_type: Specified in which flow table type, the matcher will
                         store the flow rules: MLX5DV_FLOW_TABLE_TYPE_NIC_RX:
                         Specified this matcher will store ingress flow rules.
                         MLX5DV_FLOW_TABLE_TYPE_NIC_TX - matcher will store
                                                         egress flow rules.
                         MLX5DV_FLOW_TABLE_TYPE_FDB - matcher will store FDB
                                                      rules.
                         MLX5DV_FLOW_TABLE_TYPE_RDMA_RX - matcher will store
                                                          ingress RDMA flow
                                                          rules.
                         MLX5DV_FLOW_TABLE_TYPE_RDMA_TX - matcher will store
                                                          egress RDMA flow rules.
        """
        super().__init__()
        self.attr.type = attr_type
        self.attr.flags = flags
        self.attr.priority = priority
        self.attr.match_criteria_enable = match_criteria_enable
        self.attr.match_mask = match_mask.params
        self.attr.comp_mask = comp_mask
        self.attr.ft_type = ft_type


cdef class Mlx5FlowMatcher(PyverbsObject):
    def __init__(self, Context context, Mlx5FlowMatcherAttr attr):
        """
        Initialize a Mlx5FlowMatcher object over an underlying
         mlx5dv_flow_matcher C object that defines a matcher for steering flow.
        :param context: Context object
        :param attr: Flow matcher attributes
        """
        super().__init__()
        self.flow_matcher = dv.mlx5dv_create_flow_matcher(context.context,
                                                          &attr.attr)
        if self.flow_matcher == NULL:
            raise PyverbsRDMAErrno('Flow matcher creation failed.')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.flow_matcher != NULL:
            self.logger.debug('Closing Mlx5FlowMatcher')
            rc = dv.mlx5dv_destroy_flow_matcher(self.flow_matcher)
            if rc:
                raise PyverbsRDMAError('Destroy matcher failed.', rc)
            self.flow_matcher = NULL
