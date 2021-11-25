# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

from libc.stdlib cimport calloc, free

from pyverbs.providers.mlx5.mlx5dv_flow cimport Mlx5FlowMatchParameters
from pyverbs.base import PyverbsRDMAErrno, PyverbsRDMAError
from pyverbs.providers.mlx5.dr_matcher cimport DrMatcher
from pyverbs.providers.mlx5.dr_action cimport DrAction
from pyverbs.pyverbs_error import PyverbsError


cdef class DrRule(PyverbsCM):
    def __init__(self, DrMatcher matcher, Mlx5FlowMatchParameters value,
                 actions=[]):
        """
        Initialize DrRule object over underlying mlx5dv_dr_rule C object.
        :param matcher: A matcher with the fields to match on
        :param value: Match parameters with values to match on
        :param actions: List of actions to perform
        """
        super().__init__()
        cdef dv.mlx5dv_dr_action**actions_arr
        actions_arr = <dv.mlx5dv_dr_action**>calloc(len(actions),
                                                    sizeof(dv.mlx5dv_dr_action*))
        if actions_arr == NULL:
            raise PyverbsError('Failed to allocate memory.')
        for i in range(0, len(actions)):
            actions_arr[i] = <dv.mlx5dv_dr_action*>(<DrAction>actions[i]).action
        self.rule = dv.mlx5dv_dr_rule_create(matcher.matcher, value.params,
                                             len(actions), actions_arr)
        free(actions_arr)
        if self.rule == NULL:
            raise PyverbsRDMAErrno('DrRule creation failed.')
        for i in range(0, len(actions)):
            (<DrAction>actions[i]).add_ref(self)
        matcher.add_ref(self)
        self.dr_matcher = matcher

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.rule != NULL:
            self.logger.debug('Closing DrRule.')
            rc = dv.mlx5dv_dr_rule_destroy(self.rule)
            if rc:
                raise PyverbsRDMAError('Failed to destroy DrRule.', rc)
            self.rule = NULL
            self.dr_matcher = None
