==========
IBCCCONFIG
==========

-------------------------------------
configure congestion control settings
-------------------------------------

:Date: 2012-05-31
:Manual section: 8
:Manual group: OpenIB Diagnostics


SYNOPSIS
========

ibccconfig [common_options] [-c cckey] <op> <lid|guid> [port]

DESCRIPTION
===========

**ibccconfig**
supports the configuration of congestion control settings on switches
and HCAs.

**WARNING -- You should understand what you are doing before using this tool.
Misuse of this tool could result in a broken fabric.**

OPTIONS
=======

Current supported operations and their parameters:
  CongestionKeyInfo (CK) <lid|guid> <cckey> <cckeyprotectbit> <cckeyleaseperiod> <cckeyviolations>
  SwitchCongestionSetting (SS) <lid|guid> <controlmap> <victimmask> <creditmask> <threshold> <packetsize> <csthreshold> <csreturndelay> <markingrate>
  SwitchPortCongestionSetting (SP) <lid|guid> <portnum> <valid> <control_type> <threshold> <packet_size> <cong_parm_marking_rate> 
  CACongestionSetting (CS) <lid|guid> <port_control> <control_map> <ccti_timer> <ccti_increase> <trigger_threshold> <ccti_min>
  CongestionControlTable (CT) <lid|guid> <cctilimit> <index> <cctentry> <cctentry> ...

**--cckey, -c, <cckey>**
Specify a congestion control (CC) key.  If none is specified, a key of 0 is used.


Debugging flags
---------------

.. include:: common/opt_d.rst
.. include:: common/opt_e.rst
.. include:: common/opt_h.rst
.. include:: common/opt_v.rst
.. include:: common/opt_V.rst

Addressing Flags
----------------

.. include:: common/opt_G.rst
.. include:: common/opt_L.rst
.. include:: common/opt_s.rst


Port Selection flags
--------------------

.. include:: common/opt_C.rst
.. include:: common/opt_P.rst
.. include:: common/sec_portselection.rst

Configuration flags
-------------------

.. include:: common/opt_y.rst
.. include:: common/opt_z-config.rst


EXAMPLES
========

::

        ibccconfig SwitchCongestionSetting 2 0x1F 0x1FFFFFFFFF 0x0 0xF 8 0 0:0 1  # Configure Switch Congestion Settings
        ibccconfig CACongestionSetting 1 0 0x3 150 1 0 0                          # Configure CA Congestion Settings to SL 0 and SL 1
        ibccconfig CACongestionSetting 1 0 0x4 200 1 0 0                          # Configure CA Congestion Settings to SL 2
        ibccconfig CongestionControlTable 1 63 0 0:0 0:1 ...                      # Configure first block of Congestion Control Table
        ibccconfig CongestionControlTable 1 127 0 0:64 0:65 ...                   # Configure second block of Congestion Control Table

FILES
=====

.. include:: common/sec_config-file.rst

AUTHOR
======

Albert Chu
        < chu11@llnl.gov >
