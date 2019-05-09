=========
IBCCQUERY
=========

--------------------------------------
query congestion control settings/info
--------------------------------------

:Date: 2012-05-31
:Manual section: 8
:Manual group: OpenIB Diagnostics


SYNOPSIS
========
ibccquery [common_options] [-c cckey] <op> <lid|guid> [port]

DESCRIPTION
===========

ibccquery support the querying of settings and other information related
to congestion control.

OPTIONS
=======

Current supported operations and their parameters:
  CongestionInfo (CI) <addr>
  CongestionKeyInfo (CK) <addr>
  CongestionLog (CL) <addr>
  SwitchCongestionSetting (SS) <addr>
  SwitchPortCongestionSetting (SP) <addr> [<portnum>]
  CACongestionSetting (CS) <addr>
  CongestionControlTable (CT) <addr>
  Timestamp (TI) <addr>


**--cckey, -c <cckey>**
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

FILES
=====

.. include:: common/sec_config-file.rst

EXAMPLES
========

::

        ibccquery CongestionInfo 3		# Congestion Info by lid
        ibccquery SwitchPortCongestionSetting 3	# Query all Switch Port Congestion Settings
        ibccquery SwitchPortCongestionSetting 3 1 # Query Switch Port Congestion Setting for port 1

AUTHOR
======

Albert Chu
        < chu11@llnl.gov >
