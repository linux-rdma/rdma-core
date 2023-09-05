# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

from pyverbs.base import PyverbsRDMAErrno, PyverbsRDMAError
from pyverbs.providers.mlx5.dr_domain cimport DrDomain
from pyverbs.providers.mlx5.mlx5dv cimport Mlx5DevxObj
from pyverbs.providers.mlx5.dr_rule cimport DrRule
import pyverbs.providers.mlx5.mlx5_enums as dve
from pyverbs.pyverbs_error import PyverbsError
from pyverbs.base cimport close_weakrefs
from libc.stdlib cimport calloc, free
from libc.stdint cimport uint32_t, uint8_t
from libc.string cimport memcpy
import weakref
import struct
import errno

be64toh = lambda num: struct.unpack('Q'.encode(), struct.pack('!8s'.encode(), num))[0]
ACTION_SIZE = 8


cdef class DrAction(PyverbsCM):
    def __init__(self):
        super().__init__()
        self.dr_rules = weakref.WeakSet()
        self.dr_used_actions = weakref.WeakSet()

    cdef add_ref(self, obj):
        if isinstance(obj, DrRule):
            self.dr_rules.add(obj)
        elif isinstance(obj, DrAction):
            self.dr_used_actions.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            if self.logger:
                self.logger.debug('Closing DrAction.')
            close_weakrefs([self.dr_rules, self.dr_used_actions])
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


cdef class DrActionFlowCounter(DrAction):
    def __init__(self, Mlx5DevxObj devx_obj, offset=0):
        """
        Create DR flow counter action.
        :param devx_obj: Mlx5DevxObj object which is the flow counter object.
        :param offset: Offset of the specific counter in the counter object.
        """
        super().__init__()
        self.action = dv.mlx5dv_dr_action_create_flow_counter(devx_obj.obj, offset)
        if self.action == NULL:
            raise PyverbsRDMAErrno('DrActionFlowCounter creation failed.')
        self.devx_obj = devx_obj
        devx_obj.add_ref(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            super(DrActionFlowCounter, self).close()
            self.devx_obj = None


cdef class DrActionDrop(DrAction):
    def __init__(self):
        """
        Create DR flow drop action.
        """
        super().__init__()
        self.action = dv.mlx5dv_dr_action_create_drop()
        if self.action == NULL:
            raise PyverbsRDMAErrno('DrActionDrop creation failed.')


cdef class DrActionModify(DrAction):
    def __init__(self, DrDomain domain, flags=0, actions=list()):
        """
        Create DR modify header actions.
        :param domain: DrDomain object where the action should be located.
        :param flags: Modify action flags.
        :param actions: List of Bytes of the actions command input data
                        provided in a device specification format
                        (Stream of bytes or __bytes__ is implemented).
        """
        super().__init__()
        action_buf_size = len(actions) * ACTION_SIZE
        cdef unsigned long long *buf = <unsigned long long*>calloc(1, action_buf_size)
        if buf == NULL:
           raise MemoryError('Failed to allocate memory', errno)

        for i in range(len(actions)):
            buf[i] = be64toh(bytes(actions[i]))
        self.action = dv.mlx5dv_dr_action_create_modify_header(domain.domain, flags,
                                                               action_buf_size, buf)
        free(buf)

        if self.action == NULL:
            raise PyverbsRDMAErrno('Failed to create dr action modify header')
        self.domain = domain
        domain.dr_actions.add(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            super(DrActionModify, self).close()
            self.domain = None


cdef class DrActionTag(DrAction):
    def __init__(self, tag):
        """
        Create DR tag action.
        :param tag: Tag value
        """
        super().__init__()
        self.action = dv.mlx5dv_dr_action_create_tag(tag)
        if self.action == NULL:
            raise PyverbsRDMAErrno('DrActionTag creation failed.')


cdef class DrActionDestTable(DrAction):
    def __init__(self, DrTable table):
        """
        Create DR destination table action.
        :param table: Destination table
        """
        super().__init__()
        self.action = dv.mlx5dv_dr_action_create_dest_table(table.table)
        if self.action == NULL:
            raise PyverbsRDMAErrno('DrActionDestTable creation failed.')
        self.table = table
        table.dr_actions.add(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            super(DrActionDestTable, self).close()
            self.table = None


cdef class DrActionPopVLan(DrAction):
    def __init__(self):
        """
        Create DR Pop VLAN action.
        """
        super().__init__()
        self.action = dv.mlx5dv_dr_action_create_pop_vlan()
        if self.action == NULL:
            raise PyverbsRDMAErrno('DrActionPopVLan creation failed.')


cdef class DrActionPushVLan(DrAction):
    def __init__(self, DrDomain domain, vlan_hdr):
        """
        Create DR Push VLAN action.
        :param domain: DrDomain object where the action should be located.
        :param vlan_hdr: VLAN header.
        """
        super().__init__()
        self.domain = domain
        self.action = dv.mlx5dv_dr_action_create_push_vlan(domain.domain,
                                                           <uint32_t>vlan_hdr)
        if self.action == NULL:
            raise PyverbsRDMAErrno('DrActionPushVLan creation failed.')
        domain.dr_actions.add(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            super(DrActionPushVLan, self).close()
            self.domain = None


cdef class DrActionDestAttr(PyverbsCM):
    def __init__(self, action_type, DrAction dest, DrAction reformat=None):
        """
        Multi destination attributes class used in order to create
        multi destination array action.
        :param action_type: Type of action DEST or DEST_REFORMAT
        :param dest: Destination action to use
        :param reformat: Reformat action to use before destination action
        """
        super().__init__()
        self.dest_reformat = NULL
        self.action_dest_attr = NULL
        if action_type == dve.MLX5DV_DR_ACTION_DEST:
            self.action_dest_attr = <dv.mlx5dv_dr_action_dest_attr *> calloc(
                1, sizeof(dv.mlx5dv_dr_action_dest_attr))
            if self.action_dest_attr == NULL:
                raise PyverbsRDMAErrno('Memory allocation for DrActionDestAttr failed.')
            self.action_dest_attr.type = action_type
            self.action_dest_attr.dest = dest.action
            self.dest = dest
        elif action_type == dve.MLX5DV_DR_ACTION_DEST_REFORMAT:
            self.dest_reformat = <dv.mlx5dv_dr_action_dest_reformat *> calloc(
                1, sizeof(dv.mlx5dv_dr_action_dest_reformat))
            if self.dest_reformat == NULL:
                raise PyverbsRDMAErrno('Memory allocation for DrActionDestAttr failed.')
            self.action_dest_attr.dest_reformat = self.dest_reformat
            self.action_dest_attr.dest_reformat.reformat = reformat.action
            self.action_dest_attr.dest_reformat.dest = dest.action
        else:
            raise PyverbsError('Unsupported action type is provided.')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        super(DrActionDestAttr, self).close()
        if self.logger:
            self.logger.debug('Closing DrActionDestAttr')
        if self.action_dest_attr != NULL:
            free(self.action_dest_attr)
            self.action_dest_attr = NULL
        if self.dest_reformat != NULL:
            free(self.dest_reformat)
            self.dest_reformat = NULL


cdef class DrActionDestArray(DrAction):
    def __init__(self, DrDomain domain, actions_num, dest_actions):
        """
        Create Dest Array Action.
        :param domain: DrDomain object where the action should be located.
        :param actions_num: Number of actions.
        :param dest_actions: Destination actions to use for dest array action.
        """
        cdef dv.mlx5dv_dr_action_dest_attr ** ptr_list
        cdef DrActionDestAttr temp_attr
        super().__init__()
        if not actions_num or not dest_actions or not domain:
            raise PyverbsError('Domain, number of actions and '
                               'dest_actions list must be provided '
                               'for creating dest array action.')
        self.domain = domain
        self.dest_actions = dest_actions
        ptr_list = <dv.mlx5dv_dr_action_dest_attr**>calloc(
            actions_num, sizeof(dv.mlx5dv_dr_action_dest_attr *))
        if ptr_list == NULL:
            raise PyverbsError('Failed to allocate memory.')
        for j in range(actions_num):
            temp_attr = <DrActionDestAttr>(dest_actions[j])
            ptr_list[j] = <dv.mlx5dv_dr_action_dest_attr*>temp_attr.action_dest_attr
        self.action = dv.mlx5dv_dr_action_create_dest_array(
                        domain.domain, actions_num, ptr_list)
        if self.action == NULL:
            raise PyverbsRDMAErrno('DrActionDestArray creation failed.')
        free(ptr_list)
        domain.dr_actions.add(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            super(DrActionDestArray, self).close()
            self.domain = None
            self.dest_actions = None


cdef class DrActionDefMiss(DrAction):
    def __init__(self):
        """
        Create DR default miss action.
        """
        super().__init__()
        self.action = dv.mlx5dv_dr_action_create_default_miss()
        if self.action == NULL:
            raise PyverbsRDMAErrno('DrActionDefMiss creation failed.')


cdef class DrActionVPort(DrAction):
    def __init__(self, DrDomain domain, vport):
        """
        Create DR vport action.
        :param domain: DrDomain object where the action should be placed.
        :param vport: VPort number.
        """
        super().__init__()
        self.action = dv.mlx5dv_dr_action_create_dest_vport(domain.domain, vport)
        if self.action == NULL:
            raise PyverbsRDMAErrno('Failed to create dr VPort action')
        self.domain = domain
        self.vport = vport
        domain.dr_actions.add(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            super(DrActionVPort, self).close()
            self.domain = None


cdef class DrActionIBPort(DrAction):
    def __init__(self, DrDomain domain, ib_port):
        """
        Create DR IB port action.
        :param domain: DrDomain object where the action should be placed.
        :param ib_port: IB port number.
        """
        super().__init__()
        self.action = dv.mlx5dv_dr_action_create_dest_ib_port(domain.domain, ib_port)
        if self.action == NULL:
            raise PyverbsRDMAErrno('Failed to create dr IB port action')
        self.domain = domain
        self.ib_port = ib_port
        domain.dr_actions.add(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            super(DrActionIBPort, self).close()
            self.domain = None

cdef class DrActionDestTir(DrAction):
    def __init__(self, Mlx5DevxObj devx_tir):
        """
        Create DR dest devx tir action.
        :param devx_tir: Destination Mlx5DevxObj tir.
        """
        super().__init__()
        self.action = dv.mlx5dv_dr_action_create_dest_devx_tir(devx_tir.obj)
        if self.action == NULL:
            raise PyverbsRDMAErrno('Failed to create TIR action')
        self.devx_obj = devx_tir
        devx_tir.add_ref(self)


cdef class DrActionPacketReformat(DrAction):
    def __init__(self, DrDomain domain, flags=0,
                 reformat_type=dv.MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TUNNEL_TO_L2,
                 data=None):
        """
        Create DR Packet Reformat action.
        :param domain: DrDomain object where the action should be placed.
        :param flags: Packet reformat action flags.
        :param reformat_type: L2 or L3 encap or decap.
        :param data: Encap headers (optional).
        """
        super().__init__()
        cdef char *reformat_data = NULL
        data_len = 0 if data is None else len(data)
        if data:
            arr = bytearray(data)
            reformat_data = <char *>calloc(1, data_len)
            for i in range(data_len):
                reformat_data[i] = arr[i]
        self.action = dv.mlx5dv_dr_action_create_packet_reformat(
                        domain.domain, flags, reformat_type, data_len, reformat_data)
        if data:
            free(reformat_data)
        if self.action == NULL:
            raise PyverbsRDMAErrno('Failed to create dr action packet reformat')
        self.domain = domain
        domain.dr_actions.add(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            super(DrActionPacketReformat, self).close()
            self.domain = None


cdef class DrFlowSamplerAttr(PyverbsCM):
    def __init__(self, sample_ratio, DrTable default_next_table, sample_actions,
                 action=None):
        """
        Create DrFlowSamplerAttr.
        :param sample_ratio: The probability for a packet to be sampled by the sampler
         is 1/sample_ratio
        :param default_next_table: All the packets continue to the default table id destination
        :param sample_actions: The actions that are being preformed on The replicated sampled
         packets at sample_table_id destination
        :param action: If sample table ID is FDB table type, the object will pass RegC0 from
         input to both sampler and default output destination as SetActionIn
        """
        cdef dv.mlx5dv_dr_action **actions_ptr_list = NULL
        self.attr = <dv.mlx5dv_dr_flow_sampler_attr *>calloc(1,
                sizeof(dv.mlx5dv_dr_flow_sampler_attr))
        if self.attr == NULL:
            raise MemoryError('Failed to allocate memory.')
        size = len(sample_actions) * sizeof(dv.mlx5dv_dr_action *)
        actions_ptr_list = <dv.mlx5dv_dr_action **>calloc(1, size)
        if actions_ptr_list == NULL:
            raise MemoryError('Failed to allocate memory of size {size}.')
        self.attr.sample_ratio = <uint32_t>sample_ratio
        self.attr.default_next_table = default_next_table.table
        self.attr.num_sample_actions = len(sample_actions)
        for i in range(self.attr.num_sample_actions):
            actions_ptr_list[i] = \
                <dv.mlx5dv_dr_action*>(<DrAction>sample_actions[i]).action
        self.attr.sample_actions = actions_ptr_list
        if action is not None:
            self.attr.action = be64toh(bytes(action))
        self.actions = sample_actions[:]
        self.table = default_next_table

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.attr != NULL:
            if self.attr.sample_actions:
                free(self.attr.sample_actions)
            self.attr.sample_actions = NULL
            self.table = None
            free(self.attr)
            self.attr = NULL


cdef class DrActionFlowSample(DrAction):
    def __init__(self, DrFlowSamplerAttr attr):
        """
        Create DR Flow Sample action.
        :param attr: DrFlowSamplerAttr attr
        """
        super().__init__()
        self.action = dv.mlx5dv_dr_action_create_flow_sampler(attr.attr)
        if self.action == NULL:
            raise PyverbsRDMAErrno('DrActionFlowSample creation failed.')
        self.attr = attr
        self.dr_table = self.attr.table
        self.attr.table.add_ref(self)
        self.dr_actions = self.attr.actions
        for action in self.dr_actions:
            (<DrAction>action).add_ref(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            super(DrActionFlowSample, self).close()
            self.dr_table = None
            self.dr_actions = None
            self.attr = None
            self.action = NULL


cdef class DrFlowMeterAttr(PyverbsCM):
    def __init__(self, DrTable next_table, active=1, reg_c_index=0, flow_meter_parameter=None):
        """
        Create DrFlowMeterAttr.
        :param next_table: Destination Table to which packet would be redirected
                           after passing through the Meter.
        :param active: When set, the Monitor is considered connected to at least
                       one Flow and should be monitored.
        :param reg_c_index: Index of Register C, where the packet color will be
                            set after passing through the Meter. Valid values
                            are according to QUERY_HCA_CAP.flow_meter_reg_id.
                            The result will be set in the 8 LSB of the register.
        :param flow_meter_parameter: PRM data that defines the meter behavior:
                                     rates, colors, etc.
        """
        cdef bytes py_bytes = bytes(flow_meter_parameter)
        self.attr = <dv.mlx5dv_dr_flow_meter_attr *>calloc(1, sizeof(dv.mlx5dv_dr_flow_meter_attr))
        if self.attr == NULL:
            raise MemoryError('Failed to allocate memory.')
        self.attr.next_table = next_table.table
        self.attr.active = <uint8_t>active
        self.attr.reg_c_index = <uint8_t>reg_c_index
        param_size = len(py_bytes)
        self.attr.flow_meter_parameter_sz = param_size
        self.attr.flow_meter_parameter = calloc(1, param_size)
        if self.attr.flow_meter_parameter == NULL:
            free(self.attr)
            raise MemoryError('Failed to allocate memory.')
        memcpy(<void *> self.attr.flow_meter_parameter, <char *>py_bytes, param_size)
        self.table = next_table

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.attr != NULL:
            if self.attr.flow_meter_parameter != NULL:
                free(self.attr.flow_meter_parameter)
            self.attr.flow_meter_parameter = NULL
            self.table = None
            free(self.attr)
            self.attr = NULL


cdef class DrActionFlowMeter(DrAction):
    def __init__(self, DrFlowMeterAttr attr):
        """
        Create DR Flow Meter action.
        :param attr: DrFlowMeterAttr attr
        """
        super().__init__()
        self.action = dv.mlx5dv_dr_action_create_flow_meter(attr.attr)
        if self.action == NULL:
            raise PyverbsRDMAErrno('DrActionFlowMeter creation failed.')
        self.attr = attr
        self.dr_table = self.attr.table
        self.attr.table.add_ref(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            super(DrActionFlowMeter, self).close()
            self.dr_table = None
            self.attr = None

    def modify(self, DrFlowMeterAttr attr, modify_field_select):
        """
        Modify flow meter action by selected field.
        :param attr: DrFlowMeterAttr attr
        :param modify_field_select: which fields to modify:
        Bit 0: Active
        Bit 1: CBS - affects cbs_exponent and cbs_mantissa
        Bit 2: CIR - affects cir_exponent and cir_mantissa
        Bit 3: EBS - affects ebs_exponent and ebs_mantissa
        Bit 4: EIR - affects eir_exponent and eir_mantissa
        """
        ret = dv.mlx5dv_dr_action_modify_flow_meter(self.action, attr.attr, modify_field_select)
        if ret:
            raise PyverbsRDMAErrno('Modify DrActionFlowMeter failed.')
