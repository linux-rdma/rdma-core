# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2023 Red Hat, Inc, All rights reserved.  See COPYING file

import unittest

INTEL_VENDOR_ID = 0x8086
IRDMA_DEVS = {
        0x1572, # I40E_DEV_ID_SFP_XL710
        0x1574, # I40E_DEV_ID_QEMU
        0x1580, # I40E_DEV_ID_KX_B
        0x1581, # I40E_DEV_ID_KX_C
        0x1583, # I40E_DEV_ID_QSFP_A
        0x1584, # I40E_DEV_ID_QSFP_B
        0x1585, # I40E_DEV_ID_QSFP_C
        0x1586, # I40E_DEV_ID_10G_BASE_T
        0x1587, # I40E_DEV_ID_20G_KR2
        0x1588, # I40E_DEV_ID_20G_KR2_A
        0x1589, # I40E_DEV_ID_10G_BASE_T4
        0x158A, # I40E_DEV_ID_25G_B
        0x158B, # I40E_DEV_ID_25G_SFP28
        0x154C, # I40E_DEV_ID_VF
        0x1571, # I40E_DEV_ID_VF_HV
        0x374C, # I40E_DEV_ID_X722_A0
        0x374D, # I40E_DEV_ID_X722_A0_VF
        0x37CE, # I40E_DEV_ID_KX_X722
        0x37CF, # I40E_DEV_ID_QSFP_X722
        0x37D0, # I40E_DEV_ID_SFP_X722
        0x37D1, # I40E_DEV_ID_1G_BASE_T_X722
        0x37D2, # I40E_DEV_ID_10G_BASE_T_X722
        0x37D3, # I40E_DEV_ID_SFP_I_X722
        0x37CD, # I40E_DEV_ID_X722_VF
        0x37D9, # I40E_DEV_ID_X722_VF_HV

        0x124C, # Intel(R) Ethernet Connection E823-L for backplane
        0x124D, # Intel(R) Ethernet Connection E823-L for SFP
        0x124E, # Intel(R) Ethernet Connection E823-L/X557-AT 10GBASE-T
        0x124F, # Intel(R) Ethernet Connection E823-L 1GbE
        0x151D, # Intel(R) Ethernet Connection E823-L for QSFP
        0x1591, # Intel(R) Ethernet Controller E810-C for backplane
        0x1592, # Intel(R) Ethernet Controller E810-C for QSFP
        0x1593, # Intel(R) Ethernet Controller E810-C for SFP
        0x1599, # Intel(R) Ethernet Controller E810-XXV for backplane
        0x159A, # Intel(R) Ethernet Controller E810-XXV for QSFP
        0x159B, # Intel(R) Ethernet Controller E810-XXV for SFP
        0x188A, # Intel(R) Ethernet Connection E823-C for backplane
        0x188B, # Intel(R) Ethernet Connection E823-C for QSFP
        0x188C, # Intel(R) Ethernet Connection E823-C for SFP
        0x188D, # Intel(R) Ethernet Connection E823-C/X557-AT 10GBASE-T
        0x188E, # Intel(R) Ethernet Connection E823-C 1GbE
        0x1890, # Intel(R) Ethernet Connection C822N for backplane
        0x1891, # Intel(R) Ethernet Connection C822N for QSFP
        0x1892, # Intel(R) Ethernet Connection C822N for SFP
        0x1893, # Intel(R) Ethernet Connection E822-C/X557-AT 10GBASE-T
        0x1894, # Intel(R) Ethernet Connection E822-C 1GbE
        0x1897, # Intel(R) Ethernet Connection E822-L for backplane
        0x1898, # Intel(R) Ethernet Connection E822-L for SFP
        0x1899, # Intel(R) Ethernet Connection E822-L/X557-AT 10GBASE-T
        0x189A, # Intel(R) Ethernet Connection E822-L 1GbE
}


def is_irdma_dev(ctx):
    dev_attrs = ctx.query_device()
    return dev_attrs.vendor_id == INTEL_VENDOR_ID and \
            dev_attrs.vendor_part_id in IRDMA_DEVS


def skip_if_irdma_dev(ctx):
    if is_irdma_dev(ctx):
        raise unittest.SkipTest('Can not run the test over irdma device')
