=============
IBNETDISCOVER
=============

----------------------------
discover InfiniBand topology
----------------------------

:Date: 2013-06-22
:Manual section: 8
:Manual group: Open IB Diagnostics


SYNOPSIS
========

ibnetdiscover [options] [<topology-file>]


DESCRIPTION
===========

ibnetdiscover performs IB subnet discovery and outputs a human readable
topology file. GUIDs, node types, and port numbers are displayed
as well as port LIDs and NodeDescriptions.  All nodes (and links) are displayed
(full topology).  Optionally, this utility can be used to list the current
connected nodes by nodetype.  The output is printed to standard output
unless a topology file is specified.

OPTIONS
=======

**-l, --list**
List of connected nodes

**-g, --grouping**
Show grouping.  Grouping correlates IB nodes by different vendor specific
schemes.  It may also show the switch external ports correspondence.

**-H, --Hca_list**
List of connected CAs

**-S, --Switch_list**
List of connected switches

**-R, --Router_list**
List of connected routers

**-s, --show**
Show progress information during discovery.

**-f, --full**
Show full information (ports' speed and width, vlcap)

**-p, --ports**
Obtain a ports report which is a
list of connected ports with relevant information (like LID, portnum,
GUID, width, speed, and NodeDescription).

**-m, --max_hops**
Report max hops discovered.

.. include:: common/opt_o-outstanding_smps.rst


Cache File flags
----------------

.. include:: common/opt_cache.rst
.. include:: common/opt_load-cache.rst
.. include:: common/opt_diff.rst
.. include:: common/opt_diffcheck.rst


Port Selection flags
--------------------

.. include:: common/opt_C.rst
.. include:: common/opt_P.rst
.. include:: common/sec_portselection.rst

Configuration flags
-------------------

.. include:: common/opt_z-config.rst
.. include:: common/opt_o-outstanding_smps.rst
.. include:: common/opt_node_name_map.rst
.. include:: common/opt_t.rst
.. include:: common/opt_y.rst

Debugging flags
---------------

.. include:: common/opt_d.rst
.. include:: common/opt_e.rst
.. include:: common/opt_h.rst
.. include:: common/opt_v.rst
.. include:: common/opt_V.rst



FILES
=====

.. include:: common/sec_config-file.rst
.. include:: common/sec_node-name-map.rst
.. include:: common/sec_topology-file.rst



AUTHORS
=======

Hal Rosenstock
        < halr@voltaire.com >

Ira Weiny
        < ira.weiny@intel.com >
