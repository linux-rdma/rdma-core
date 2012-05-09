============
DUMP_LFTS.SH
============

-----------------------------------------
dump InfiniBand unicast forwarding tables
-----------------------------------------

:Date: @BUILD_DATE@
:Manual section: 8
:Manual group: OpenIB Diagnostics



SYNOPSIS
========

dump_lfts.sh [-h] [-D] [-C ca_name] [-P ca_port] [-t(imeout) timeout_ms] [>/path/to/dump-file]


DESCRIPTION
===========

dump_lfts.sh is a script which dumps the InfiniBand unciast forwarding
tables (MFTs) in the switch nodes in the subnet.

The dump file format is compatible with loading into OpenSM using
the -R file -U /path/to/dump-file syntax.

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

**dump_mfts(8), ibroute(8), ibswitches(8), opensm(8)**


AUTHORS
=======

Sasha Khapyorsky
        < sashak@voltaire.com >

Hal Rosenstock
        < halr@voltaire.com >
