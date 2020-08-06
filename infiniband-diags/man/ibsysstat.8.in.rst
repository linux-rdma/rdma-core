=========
ibsysstat
=========

--------------------------------------
system status on an InfiniBand address
--------------------------------------

:Date: 2017-08-21
:Manual section: 8
:Manual group: Open IB Diagnostics

SYNOPSIS
========

ibsysstat [options] <dest lid | guid> [<op>]

DESCRIPTION
===========

ibsysstat uses vendor mads to validate connectivity between IB nodes
and obtain other information about the IB node. ibsysstat is run as
client/server. Default is to run as client.

OPTIONS
=======

Current supported operations:

::

        ping \- verify connectivity to server (default)
        host \- obtain host information from server
        cpu  \- obtain cpu information from server

**-o, --oui**
        use specified OUI number to multiplex vendor mads

**-S, --Server**
        start in server mode (do not return)


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
.. include:: common/opt_z-config.rst


FILES
=====

.. include:: common/sec_config-file.rst



AUTHOR
======

Hal Rosenstock
        < halr@voltaire.com >
