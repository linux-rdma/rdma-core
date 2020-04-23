# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Kamal Heib <kamalheib1@gmail.com>, All rights reserved.  See COPYING file

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
        parser.add_argument('-v', '--verbose', dest='verbosity',
                            action='store_const',
                            const=2, help='Verbose output')
        ns, args = parser.parse_known_args()
        self.args = vars(ns)
        if self.args['verbosity']:
            args += ['--verbose']
        sys.argv[1:] = args


parser = ArgsParser()
