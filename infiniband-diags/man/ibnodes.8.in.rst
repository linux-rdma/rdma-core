=======
IBNODES
=======

---------------------------------
show InfiniBand nodes in topology
---------------------------------

:Date: 2012-05-14
:Manual section: 8
:Manual group: OpenIB Diagnostics


SYNOPSIS
========

ibnodes [options] [<topology-file>]

DESCRIPTION
===========

ibnodes is a script which either walks the IB subnet topology or uses an
already saved topology file and extracts the IB nodes (CAs and switches).


OPTIONS
=======

.. include:: common/opt_C.rst
.. include:: common/opt_P.rst
.. include:: common/opt_t.rst
.. include:: common/opt_h.rst
.. include:: common/opt_z-config.rst

.. include:: common/sec_portselection.rst

FILES
=====

.. include:: common/sec_config-file.rst
.. include:: common/sec_node-name-map.rst


SEE ALSO
========

ibnetdiscover(8)

DEPENDENCIES
============

ibnetdiscover, ibnetdiscover format

AUTHOR
======

Hal Rosenstock
        < halr@voltaire.com >
