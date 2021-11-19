# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Kamal Heib <kamalheib1@gmail.com>, All rights reserved.  See COPYING file
# Copyright (c) 2021 Nvidia, Inc. All rights reserved. See COPYING file

import argparse
import sys


class ArgsParser(object):
    def __init__(self):
        self.args = None

    def get_config(self):
        return self.args

    def parse_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--dev',
                            help='RDMA device to run the tests on')
        parser.add_argument('--pci-dev',
                            help='PCI device to run the tests on, which is '
                                 'needed by some tests where the RDMA device is '
                                 'not available (e.g. VFIO)')
        parser.add_argument('--port',
                            help='Use port <port> of RDMA device', type=int,
                            default=1)
        parser.add_argument('--gid',
                            help='Use gid index <gid> of RDMA device', type=int)
        parser.add_argument('--gpu', nargs='?', type=int, const=0, default=0,
                            help='GPU unit to allocate dmabuf from')
        parser.add_argument('--gtt', action='store_true', default=False,
                            help='Allocate dmabuf from GTT instead of VRAM')
        parser.add_argument('-v', '--verbose', dest='verbosity',
                            action='store_const',
                            const=2, help='Verbose output')
        parser.add_argument('--list-tests', action='store_true', default=False,
                            help='Print a list of the full test names that are '
                                 'loaded by default and exit without running '
                                 'them.')
        ns, args = parser.parse_known_args()
        self.args = vars(ns)
        if self.args['verbosity']:
            args += ['--verbose']
        sys.argv[1:] = args


parser = ArgsParser()
