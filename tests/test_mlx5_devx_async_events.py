# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2025 Nvidia Inc. All rights reserved. See COPYING file

"""
Test module for mlx5 DevX Async Events.
"""

from pyverbs.providers.mlx5.mlx5_enums import mlx5dv_devx_create_event_channel_flags
from pyverbs.providers.mlx5.mlx5dv_event import EventChannel, EventFD
from pyverbs.pyverbs_error import PyverbsError
from tests.mlx5_base import Mlx5DevxRcResources, Mlx5DevxTrafficBase
import tests.utils as u

import time
import sys


EVENT_COOKIE = 100
OMIT_EV_DATA = mlx5dv_devx_create_event_channel_flags.MLX5DV_DEVX_CREATE_EVENT_CHANNEL_FLAGS_OMIT_EV_DATA
POLL_EVENT_TIMEOUT = 10
CQ_OVERRUN = 0x1


def get_event(event_c, fd=None, count=1):
    """
    Polls given event channel 'count' number of times
    :param event_c: Event channel
    :param fd: File descriptor
    :param count: Number of expected events
    :return: List of event responses
    """
    events_resp = []
    start_poll_t = time.perf_counter()

    while count > 0 and (time.perf_counter() - start_poll_t < POLL_EVENT_TIMEOUT):
        try:
            event = event_c.get_event(fd=fd)
            events_resp.append(event)
        except PyverbsError as err:
            raise err
        count -= 1

    if count > 0:
        raise PyverbsError(f'Got timeout on polling ({count} EQEs remaining)')

    return events_resp


class Mlx5EventsTrafficTest(Mlx5DevxTrafficBase):
    """
    Test various functionality of mlx5 events
    """
    def cq_error_event(self, with_fd=True):
        """
        Creates DEVX resources and executes traffic without polling the CQ,
        which generates CQ error
        """
        from tests.mlx5_prm_structs import EventType
        self.create_players(Mlx5DevxRcResources)
        fd = EventFD() if with_fd else None
        cookie = EVENT_COOKIE if not with_fd else None
        flags = OMIT_EV_DATA if with_fd else 0
        ec = EventChannel(self.server.ctx, flags=flags)
        ec.subscribe([EventType.CQ_ERROR], cookie=cookie, obj=self.server.cq, fd=fd)
        for _ in range(self.client.num_msgs):
        # Post send/recv without polling the CQ in order to exceed its size for CQ error event
            self.server.post_recv()
            self.client.post_send()
        return get_event(ec, fd)

    def test_cq_error_event_fd(self):
        """
        CQ error event test with FD
        """
        comp_events = self.cq_error_event()
        self.assertEqual(len(comp_events), 1)
        self.assertEqual(comp_events[0], 1)

    def test_cq_error_event_cookie(self):
        """
        CQ error event test with cookie
        """
        from tests.mlx5_prm_structs import SwEqe, CreateCqOut
        comp_events = self.cq_error_event(with_fd=False)
        self.assertEqual(len(comp_events), 1)
        data = SwEqe(comp_events[0].data).event_data
        cqn = CreateCqOut(self.server.cq.out_view).cqn
        self.assertEqual(comp_events[0].cookie, EVENT_COOKIE)
        self.assertEqual(data.cqn, cqn)
        self.assertEqual(data.syndrome, CQ_OVERRUN)
