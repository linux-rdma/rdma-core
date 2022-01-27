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
from libc.stdint cimport uint32_t
import weakref
import struct
import errno

be64toh = lambda num: struct.unpack('Q'.encode(), struct.pack('!8s'.encode(), num))[0]
ACTION_SIZE = 8


cdef class DrAction(PyverbsCM):
    def __init__(self):
        super().__init__()
        self.dr_rules = weakref.WeakSet()

    cdef add_ref(self, obj):
        if isinstance(obj, DrRule):
            self.dr_rules.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            self.logger.debug('Closing DrAction.')
            close_weakrefs([self.dr_rules])
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
