#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

from pyverbs import device as d
import sys


lst = d.get_device_list()
dev = 'Device'
node = 'Node Type'
trans = 'Transport Type'
guid = 'Node GUID'
print_format = '{:^20}{:^20}{:^20}{:^20}'
print (print_format.format(dev, node, trans, guid))
print (print_format.format('-'*len(dev), '-'*len(node), '-'*len(trans),
	   '-'*len(guid)))
for i in lst:
	print (print_format.format(i.name.decode(), d.translate_node_type(i.node_type),
		   d.translate_transport_type(i.transport_type),
		   d.guid_to_hex(i.guid)))
