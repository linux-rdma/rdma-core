======
IBPING
======

--------------------------
ping an InfiniBand address
--------------------------

:Date: @BUILD_DATE@
:Manual section: 8
:Manual group: Open IB Diagnostics


SYNOPSIS
========

ibping [options] <dest lid | guid>

DESCRIPTION
===========

ibping uses vendor mads to validate connectivity between IB nodes.
On exit, (IP) ping like output is show. ibping is run as client/server.
Default is to run as client. Note also that a default ping server is
implemented within the kernel.


OPTIONS
=======

**-c, --count**
stop after count packets

**-f, --flood**
flood destination: send packets back to back without delay

**-o, --oui**
use specified OUI number to multiplex vendor mads

**-S, --Server**
start in server mode (do not return)


Addressing Flags
----------------

.. include:: common/opt_L.rst
.. include:: common/opt_G.rst
.. include:: common/opt_s.rst


Port Selection flags
--------------------

.. include:: common/opt_C.rst
.. include:: common/opt_P.rst
.. include:: common/sec_portselection.rst


Configuration flags
-------------------

.. include:: common/opt_z-config.rst
.. include:: common/opt_t.rst


Debugging flags
---------------

.. include:: common/opt_h.rst
.. include:: common/opt_d.rst
.. include:: common/opt_e.rst
.. include:: common/opt_v.rst
.. include:: common/opt_V.rst

FILES
=====

.. include:: common/sec_config-file.rst


AUTHOR
======

Hal Rosenstock
        < halr@voltaire.com >
