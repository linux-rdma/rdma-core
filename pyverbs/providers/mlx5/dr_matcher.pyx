# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

from pyverbs.providers.mlx5.mlx5dv_flow cimport Mlx5FlowMatchParameters
from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
from pyverbs.providers.mlx5.dr_table cimport DrTable
from pyverbs.providers.mlx5.dr_rule cimport DrRule
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.base cimport close_weakrefs
import weakref


cdef class DrMatcher(PyverbsCM):
    def __init__(self, DrTable table, priority, match_criteria_enable,
                  Mlx5FlowMatchParameters mask):
        """
        Initialize DrMatcher object over underlying mlx5dv_dr_matcher C object.
        :param table: Table to create the matcher on
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
        :param mask: Match parameters to match on
        """
        super().__init__()
        self.matcher = dv.mlx5dv_dr_matcher_create(table.table, priority,
                                                   match_criteria_enable,
                                                   mask.params)
        if self.matcher == NULL:
            raise PyverbsRDMAErrno('DrMatcher creation failed.')
        table.add_ref(self)
        self.dr_table = table
        self.dr_rules = weakref.WeakSet()

    cdef add_ref(self, obj):
        if isinstance(obj, DrRule):
            self.dr_rules.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    def set_layout(self, log_num_of_rules=0, flags=dv.MLX5DV_DR_MATCHER_LAYOUT_NUM_RULE):
        """
        Set the size of the table for the matcher
        :param log_num_of_rules: Log of the table size (relevant for MLX5DV_DR_MATCHER_LAYOUT_NUM_RULE)
        :param flags: Matcher layout flags
        """
        cdef dv.mlx5dv_dr_matcher_layout matcher_layout
        matcher_layout.log_num_of_rules_hint = log_num_of_rules
        matcher_layout.flags = flags
        rc = dv.mlx5dv_dr_matcher_set_layout(self.matcher, &matcher_layout)
        if rc:
            raise PyverbsRDMAError('Setting matcher layout failed.', rc)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.matcher != NULL:
            self.logger.debug('Closing Matcher.')
            close_weakrefs([self.dr_rules])
            if dv.mlx5dv_dr_matcher_destroy(self.matcher):
                raise PyverbsRDMAErrno('Failed to destroy DrMatcher.')
            self.matcher = NULL
            self.dr_table = None
