============
DUMP_MFTS.SH
============

-------------------------------------------
dump InfiniBand multicast forwarding tables
-------------------------------------------

:Date: @BUILD_DATE@
:Manual section: 8
:Manual group: OpenIB Diagnostics


SYNOPSIS
========

dump_mfts.sh [\-h] [\-D] [\-C ca_name] [\-P ca_port] [\-t(imeout) timeout_ms] [>/path/to/file]

DESCRIPTION
===========

dump_mfts.sh is a script which dumps the InfiniBand multicast
forwarding tables (MFTs) in the switch nodes in the subnet.

OPTIONS
=======

**-D**
dump forwarding tables using direct routed rather than LID routed SMPs

**-h**
show help


Port Selection flags
--------------------

.. include:: common/opt_C.rst
.. include:: common/opt_P.rst
.. include:: common/sec_portselection.rst

Configuration flags
-------------------

.. include:: common/opt_z-config.rst
.. include:: common/opt_t.rst

FILES
=====

.. include:: common/sec_config-file.rst
.. include:: common/sec_node-name-map.rst


SEE ALSO
========

**dump_lfts(8), ibroute(8), ibswitches(8), opensm(8)**

AUTHOR
======

Hal Rosenstock
        < halr@voltaire.com >
