# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

from libc.stdlib cimport calloc, free
from libc.string cimport memcpy

from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError, \
    PyverbsUserError
from pyverbs.device cimport Context
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.base cimport close_weakrefs
from pyverbs.device cimport Context
cimport pyverbs.libibverbs as v
from pyverbs.qp cimport QP
import weakref


cdef class Mlx5FlowMatchParameters(PyverbsObject):
    def __init__(self, size, values):
        """
        Initialize a Mlx5FlowMatchParameters object over an underlying
        mlx5dv_flow_match_parameters C object that defines match parameters for
        steering flow.
        :param size: Length of the mask/value in bytes
        :param values: Bytes with mask/value to use in format of Flow Table
                       Entry Match Parameters Format table in PRM or instance
                       of FlowTableEntryMatchParam class.

        """
        cdef char *py_bytes_c
        super().__init__()
        struct_size = sizeof(size_t) + size
        self.params = <dv.mlx5dv_flow_match_parameters *>calloc(1, struct_size)
        if self.params == NULL:
            raise PyverbsError(f'Failed to allocate buffer of size {struct_size}')
        self.params.match_sz = size
        if size:
            py_bytes = bytes(values)
            py_bytes_c = py_bytes
            memcpy(self.params.match_buf, py_bytes_c, len(values))

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
        self.flows = weakref.WeakSet()

    cdef add_ref(self, obj):
        if isinstance(obj, Flow):
            self.flows.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.flow_matcher != NULL:
            self.logger.debug('Closing Mlx5FlowMatcher')
            close_weakrefs([self.flows])
            rc = dv.mlx5dv_destroy_flow_matcher(self.flow_matcher)
            if rc:
                raise PyverbsRDMAError('Destroy matcher failed.', rc)
            self.flow_matcher = NULL


cdef class Mlx5PacketReformatFlowAction(FlowAction):
    def __init__(self, Context context, data=None,
                 reformat_type=dv.MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TUNNEL_TO_L2,
                 ft_type=dv.MLX5DV_FLOW_TABLE_TYPE_NIC_RX):
        """
        Initialize a Mlx5PacketReformatFlowAction object derived from FlowAction
        class and represents reformat flow steering action that allows
        adding/removing packet headers.
        :param context: Context object
        :param data: Encap headers (if needed)
        :param reformat_type: L2 or L3 encap or decap
        :param ft_type: dv.MLX5DV_FLOW_TABLE_TYPE_NIC_RX for ingress or
                        dv.MLX5DV_FLOW_TABLE_TYPE_NIC_TX for egress
        """
        super().__init__()
        cdef char *buf = NULL
        data_len = 0 if data is None else len(data)
        if data:
            arr = bytearray(data)
            buf = <char *>calloc(1, data_len)
            for i in range(data_len):
                buf[i] = arr[i]
        reformat_data = NULL if data is None else buf
        self.action = dv.mlx5dv_create_flow_action_packet_reformat(
            context.context, data_len, reformat_data, reformat_type, ft_type)
        if data:
            free(buf)
        if self.action == NULL:
            raise PyverbsRDMAErrno('Failed to create flow action packet reformat')


cdef class Mlx5FlowActionAttr(PyverbsObject):
    def __init__(self, action_type=None, QP qp=None,
                 FlowAction flow_action=None):
        """
        Initialize a Mlx5FlowActionAttr object over an underlying
        mlx5dv_flow_action_attr C object that defines actions attributes for
        the flow matcher.
        :param action_type: Type of the action
        :param qp: A QP target for go to QP action
        :param flow_action: An action to perform for the flow
        """
        super().__init__()
        if action_type:
            self.attr.type = action_type
        if action_type == dv.MLX5DV_FLOW_ACTION_DEST_IBV_QP:
            self.attr.qp = qp.qp
            self.qp = qp
        elif action_type == dv.MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION:
            self.attr.action = flow_action.action
            self.action = flow_action
        elif action_type:
            raise PyverbsUserError(f'Unsupported action type: {action_type}.')

    @property
    def type(self):
        return self.attr.type

    @type.setter
    def type(self, action_type):
        if self.attr.type != dv.MLX5DV_FLOW_ACTION_DEST_IBV_QP:
            raise PyverbsUserError(f'Unsupported action type: {action_type}.')
        self.attr.type = action_type

    @property
    def qp(self):
        if self.attr.type != dv.MLX5DV_FLOW_ACTION_DEST_IBV_QP:
            raise PyverbsUserError(f'Action attr of type {self.attr.type} doesn\'t have a qp')
        return self.qp

    @qp.setter
    def qp(self, QP qp):
        if self.attr.type != dv.MLX5DV_FLOW_ACTION_DEST_IBV_QP:
            raise PyverbsUserError(f'Action attr of type {self.attr.type} doesn\'t have a qp')
        self.qp = qp

    @property
    def action(self):
        if self.attr.type != dv.MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION:
            raise PyverbsUserError(f'Action attr of type {self.attr.type} doesn\'t have an action')
        return self.action

    @action.setter
    def action(self, FlowAction action):
        if self.attr.type != dv.MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION:
            raise PyverbsUserError(f'Action attr of type {self.attr.type} doesn\'t have an action')
        self.action = action
        self.attr.action = action.action


cdef class Mlx5Flow(Flow):
    def __init__(self, Mlx5FlowMatcher matcher,
                 Mlx5FlowMatchParameters match_value, action_attrs=[],
                 num_actions=0):
        """
        Initialize a Mlx5Flow object derived form Flow class.
        :param matcher: A matcher with the fields to match on
        :param match_value: Match parameters with values to match on
        :param action_attrs: List of actions to perform
        :param num_actions: Number of actions
        """
        cdef void *tmp_addr
        cdef void *attr_addr

        super(Flow, self).__init__()
        if len(action_attrs) != num_actions:
            self.logger.warn('num_actions is different from actions array length.')
        total_size = num_actions * sizeof(dv.mlx5dv_flow_action_attr)
        attr_addr = calloc(1, total_size)
        if attr_addr == NULL:
            raise PyverbsError(f'Failed to allocate memory of size {total_size}')
        tmp_addr = attr_addr
        for attr in action_attrs:
            if (<Mlx5FlowActionAttr>attr).attr.type == dv.MLX5DV_FLOW_ACTION_DEST_IBV_QP:
                (<QP>(attr.qp)).add_ref(self)
                self.qp = (<Mlx5FlowActionAttr>attr).qp
            elif (<Mlx5FlowActionAttr>attr).attr.type not in [dv.MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION]:
               raise PyverbsUserError(f'Unsupported action type: '
                                      f'{<Mlx5FlowActionAttr>attr).attr.type}.')
            memcpy(tmp_addr, &(<Mlx5FlowActionAttr>attr).attr,
                   sizeof(dv.mlx5dv_flow_action_attr))
            tmp_addr += sizeof(dv.mlx5dv_flow_action_attr)
        self.flow = dv.mlx5dv_create_flow(matcher.flow_matcher,
                                          match_value.params, num_actions,
                                          <dv.mlx5dv_flow_action_attr *>attr_addr)
        free(attr_addr)
        if self.flow == NULL:
            raise PyverbsRDMAErrno('Flow creation failed.')
        matcher.add_ref(self)
