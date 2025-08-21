# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2025 Nvidia Inc. All rights reserved. See COPYING file

#cython: language_level=3

from libc.stdint cimport uint8_t, uint16_t, uint64_t
from libc.stdlib cimport free, malloc
from cpython.bytes cimport PyBytes_FromStringAndSize
from pyverbs.providers.mlx5.mlx5dv cimport Mlx5DevxObj
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.pyverbs_error import PyverbsError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.device cimport Context

cdef extern from 'unistd.h':
    ssize_t read(int fd, void *buf, size_t count)
cdef extern from 'sys/eventfd.h':
    int eventfd(unsigned int initval, int flags)


DEFAULT_EQE_SIZE = 1024


cdef class EventChannel(PyverbsCM):
    """
    EventChannel class represents Devx Event Channel
    (mlx5dv_devx_event_channel rdma-core struct).
    """
    def __init__(self, Context context not None, flags=0):
        """
        EventChannel class represents Devx Event Channel
        (mlx5dv_devx_event_channel rdma-core struct).
        :param context: Context to create the schedule resources on.
        :param flags: Create flags of the event channel.
        """
        super().__init__()
        self.ec = dv.mlx5dv_devx_create_event_channel(context.context, flags)
        if self.ec == NULL:
            raise PyverbsRDMAErrno('Failed to create a devx event channel')
        context.event_channels.add(self)

    def subscribe(self, events_num, cookie=None, Mlx5DevxObj obj=None,
                  EventFD fd=None):
        """
        Subscribe to the event channel.
        :param self: The event channel instance to subscribe to
        :param events_num: An array that contains event type numbers to
        subscribe. If fd is given, it can be either a number or an array with
        one number (since subscription with fd supports only one event number)
        :param cookie: A 64b number that can be used as an ID for the
        subscription
        :param obj: The object that's related to subscribed event (None in case
        of an unaffiliated event)
        :param fd: EventFD. If given, the subscription will be done on the
        eventfd using the event_fd subscription API
        """
        if fd:
            if cookie:
                self.logger.warning('Cookie is ignored in fd subscription')
            if hasattr(events_num, '__len__') and len(events_num) > 1:
                    raise PyverbsError('Only one event must be provided in '
                                       'events_num in fd subscription')
            event_num = events_num[0] if hasattr(events_num, '__len__') else \
                events_num
            self._subscribe_fd(event_num, fd, obj)
        else:
            if cookie is None:
                raise PyverbsError('Cookie must be provided with subscription')
            self._subscribe(events_num, cookie, obj)

    def _subscribe(self, events_num, cookie, Mlx5DevxObj obj=None):
        cdef dv.mlx5dv_devx_obj *devx_obj = obj.obj if obj else NULL
        # Size of each event number is 16b which is 2 Bytes
        size = len(events_num) * 2
        cdef uint16_t *events_n = <uint16_t*>malloc(size)
        if not events_n:
            raise PyverbsRDMAErrno('Couldn\'t allocate array for events_num')
        for i in range(len(events_num)):
            events_n[i] = events_num[i]
        if dv.mlx5dv_devx_subscribe_devx_event(self.ec, devx_obj, size,
                                               events_n, cookie):
            raise PyverbsRDMAErrno('Failed to subscribe to devx event channel')
        free(events_n)

    def _subscribe_fd(self, event_num, EventFD fd, Mlx5DevxObj obj=None):
        cdef dv.mlx5dv_devx_obj *devx_obj = obj.obj if obj else NULL
        if dv.mlx5dv_devx_subscribe_devx_event_fd(self.ec, (<EventFD>fd).fd,
                                                  devx_obj, event_num):
            raise PyverbsRDMAErrno('Failed to subscribe to devx event channel fd')

    def get_event(self, event_resp_len=DEFAULT_EQE_SIZE, EventFD fd=None):
        """
        Gets an event (if any) that the user subscribed to this channel.
        If no events were generated this function will block until the arrival
        of an event.
        :param event_resp_len: The size in bytes of the allocated event
        response. (1024B by default, which satisfies all current event types)
        :param fd: EventFD. If given, will use read function directly on the
        eventfd to read any gotten events
        :return: EventHeader or the read value from the eventfd in case of fd
        """
        if fd:
            return self._get_event_fd(fd)
        return self._get_event(event_resp_len)

    def _get_event(self, event_resp_len=DEFAULT_EQE_SIZE):
        cdef dv.mlx5dv_devx_async_event_hdr *event_data = \
            <dv.mlx5dv_devx_async_event_hdr*>malloc(event_resp_len)
        if not event_data:
            raise PyverbsRDMAErrno('Couldn\'t allocate array for events_data')
        bytes_read = dv.mlx5dv_devx_get_event(self.ec, event_data,
                                              event_resp_len)
        if bytes_read < 0:
            free(event_data)
            raise PyverbsRDMAErrno('Failed to get devx event')
        data_bytes = PyBytes_FromStringAndSize(<char*>event_data.out_data,
                                               bytes_read)
        event_header = EventHeader(event_data.cookie, data_bytes)
        free(event_data)
        return event_header

    def _get_event_fd(self, fd):
        cdef uint64_t buff
        rc = read(fd.fd, &buff, sizeof(buff))
        if rc < 0:
            raise PyverbsRDMAErrno('Failed to get event from FD')
        return buff

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.logger:
            self.logger.debug('Closing EventChannel')
        if self.ec != NULL:
            dv.mlx5dv_devx_destroy_event_channel(self.ec)
            self.ec = NULL

    @property
    def fd(self):
        return self.ec.fd


cdef class EventHeader(PyverbsObject):
    """
    Event header that contains the event cookie and the event data.
    An instance of this class is returned to the Python user by
    EventChannel.get_event() function to represent the returned event in a
    friendly manner.
    """
    def __init__(self, cookie, data):
        """
        Create EventHeader object
        :param cookie: Cookie retrieved from the event (used upon subscription)
        :param data: Event data
        """
        super().__init__()
        self.cookie = cookie
        self.data = data

    @property
    def cookie(self):
        return self.cookie

    @property
    def data(self):
        return self.data


cdef class EventFD(PyverbsObject):
    """
    Represent eventfd, a file descriptor for event notification.
    """
    def __init__(self, initval=0, flags=0):
        """
        Create an EventFD.
        :param initval: The eventfd counter initial value
        :param flags: The eventfd flags
        """
        super().__init__()
        event_fd = eventfd(initval, flags)
        if event_fd < 0:
            raise PyverbsRDMAErrno('Failed to create a event fd')
        self.fd = event_fd

    @property
    def fd(self):
        return self.fd
