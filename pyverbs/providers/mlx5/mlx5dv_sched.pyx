# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

from pyverbs.pyverbs_error import PyverbsRDMAError
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.device cimport Context


cdef class Mlx5dvSchedAttr(PyverbsObject):
    def __init__(self, Mlx5dvSchedNode parent_sched_node=None, bw_share=0,
                 max_avg_bw=0, flags=0, comp_mask=0):
        """
        Create a Schedule attr.
        :param parent_sched_node: The parent Mlx5dvSchedNode. None if this Attr
                                  is for the root node.
        :param flags: Bitmask specifying what attributes in the structure
                      are valid.
        :param bw_share: The relative bandwidth share allocated for this
                         element.
        :param max_avg_bw: The maximal transmission rate allowed for the element,
                           averaged over time.
        :param comp_mask: Reserved for future extension.
        """
        self.parent_sched_node = parent_sched_node
        parent_node = parent_sched_node.sched_node if parent_sched_node \
            else NULL
        self.sched_attr.parent = parent_node
        self.sched_attr.flags = flags
        self.sched_attr.bw_share = bw_share
        self.sched_attr.max_avg_bw = max_avg_bw
        self.sched_attr.comp_mask = comp_mask

    @property
    def bw_share(self):
        return self.sched_attr.bw_share

    @property
    def max_avg_bw(self):
        return self.sched_attr.max_avg_bw

    @property
    def flags(self):
        return self.sched_attr.flags

    @property
    def comp_mask(self):
        return self.sched_attr.comp_mask

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return 'Mlx5dvSchedAttr:\n' +\
               print_format.format('BW share', self.bw_share) +\
               print_format.format('Max avgerage BW', self.max_avg_bw) +\
               print_format.format('Flags', self.flags) +\
               print_format.format('Comp mask', self.comp_mask)


cdef class Mlx5dvSchedNode(PyverbsObject):
    def __init__(self, Context context not None, Mlx5dvSchedAttr sched_attr):
        """
        Create a Schedule node.
        :param context: Context to create the schedule resources on.
        :param sched_attr: Mlx5dvSchedAttr, containing the sched attributes.
        """
        self.sched_attr = sched_attr
        self.sched_node = dv.mlx5dv_sched_node_create(context.context,
                                                      &sched_attr.sched_attr)
        if self.sched_node == NULL:
            raise PyverbsRDMAErrno('Failed to create sched node')
        self.context = context
        context.sched_nodes.add(self)

    def modify(self, Mlx5dvSchedAttr sched_attr):
        rc = dv.mlx5dv_sched_node_modify(self.sched_node,
                                         &sched_attr.sched_attr)

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return 'Mlx5dvSchedNode:\n' +\
               print_format.format('sched attr', str(self.sched_attr))

    @property
    def sched_attr(self):
        return self.sched_attr

    @property
    def bw_share(self):
        return self.sched_attr.bw_share

    @property
    def max_avg_bw(self):
        return self.sched_attr.max_avg_bw

    @property
    def flags(self):
        return self.sched_attr.flags

    @property
    def comp_mask(self):
        return self.sched_attr.comp_mask

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.sched_node != NULL:
            rc = dv.mlx5dv_sched_node_destroy(self.sched_node)
            if rc != 0:
                raise PyverbsRDMAError('Failed to destroy a sched node', rc)
            self.sched_node = NULL
            self.context = None


cdef class Mlx5dvSchedLeaf(PyverbsObject):
    def __init__(self, Context context not None, Mlx5dvSchedAttr sched_attr):
        """
        Create a Schedule leaf.
        :param context: Context to create the schedule resources on.
        :param sched_attr: Mlx5dvSchedAttr, containing the sched attributes.
        """
        self.sched_attr = sched_attr
        self.sched_leaf = dv.mlx5dv_sched_leaf_create(context.context,
                                                      &sched_attr.sched_attr)
        if self.sched_leaf == NULL:
            raise PyverbsRDMAErrno('Failed to create sched leaf')
        self.context = context
        context.sched_leafs.add(self)

    def modify(self, Mlx5dvSchedAttr sched_attr):
        rc = dv.mlx5dv_sched_leaf_modify(self.sched_leaf,
                                         &sched_attr.sched_attr)

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return 'Mlx5dvSchedLeaf:\n' +\
               print_format.format('sched attr', str(self.sched_attr))

    @property
    def sched_attr(self):
        return self.sched_attr

    @property
    def bw_share(self):
        return self.sched_attr.bw_share

    @property
    def max_avg_bw(self):
        return self.sched_attr.max_avg_bw

    @property
    def flags(self):
        return self.sched_attr.flags

    @property
    def comp_mask(self):
        return self.sched_attr.comp_mask

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.sched_leaf != NULL:
            rc = dv.mlx5dv_sched_leaf_destroy(self.sched_leaf)
            if rc != 0:
                raise PyverbsRDMAError('Failed to destroy a sched leaf', rc)
            self.sched_leaf = NULL
            self.context = None
