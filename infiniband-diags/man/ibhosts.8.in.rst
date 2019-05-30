=======
IBHOSTS
=======

--------------------------------------
show InfiniBand host nodes in topology
--------------------------------------

:Date: 2016-12-20
:Manual section: 8
:Manual group: OpenIB Diagnostics

SYNOPSIS
========

ibhosts [options] [<topology-file>]


DESCRIPTION
===========

ibhosts is a script which either walks the IB subnet topology or uses an
already saved topology file and extracts the CA nodes.

OPTIONS
=======

.. include:: common/opt_C.rst
.. include:: common/opt_P.rst
.. include:: common/opt_t.rst
.. include:: common/opt_y.rst
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
