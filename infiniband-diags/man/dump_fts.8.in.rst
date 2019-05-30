========
DUMP_FTS
========

---------------------------------
dump InfiniBand forwarding tables
---------------------------------

:Date: 2013-03-26
:Manual section: 8
:Manual group: OpenIB Diagnostics



SYNOPSIS
========

dump_fts [options] [<startlid> [<endlid>]]


DESCRIPTION
===========

dump_fts is similar to ibroute but dumps tables for every switch found in an
ibnetdiscover scan of the subnet.

The dump file format is compatible with loading into OpenSM using
the -R file -U /path/to/dump-file syntax.

OPTIONS
=======

**-a, --all**
        show all lids in range, even invalid entries

**-n, --no_dests**
        do not try to resolve destinations

**-M, --Multicast**
        show multicast forwarding tables
        In this case, the range parameters are specifying the mlid range.


Port Selection flags
--------------------

.. include:: common/opt_C.rst
.. include:: common/opt_P.rst
.. include:: common/sec_portselection.rst

Debugging flags
---------------

.. include:: common/opt_d.rst
.. include:: common/opt_e.rst
.. include:: common/opt_h.rst
.. include:: common/opt_v.rst
.. include:: common/opt_V.rst

Configuration flags
-------------------

.. include:: common/opt_t.rst
.. include:: common/opt_y.rst
.. include:: common/opt_node_name_map.rst
.. include:: common/opt_z-config.rst

FILES
=====

.. include:: common/sec_config-file.rst
.. include:: common/sec_node-name-map.rst


SEE ALSO
========

**dump_lfts(8), dump_mfts(8), ibroute(8), ibswitches(8), opensm(8)**


AUTHORS
=======

Ira Weiny
        < ira.weiny@intel.com >
