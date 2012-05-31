========
SMPQUERY
========

:Date: @BUILD_DATE@
:Manual section: 8
:Manual group: Open IB Diagnostics

---------------------------------------------
query InfiniBand subnet management attributes
---------------------------------------------


SYNOPSIS
========

smpquery [options] <op> <dest dr_path|lid|guid> [op params]

DESCRIPTION
===========

smpquery allows a basic subset of standard SMP queries including the following:
node info, node description, switch info, port info. Fields are displayed in
human readable format.

OPTIONS
=======

Current supported operations and their parameters:

::
        nodeinfo <addr>
        nodedesc <addr>
        portinfo <addr> [<portnum>]     # default port is zero
        switchinfo <addr>
        pkeys <addr> [<portnum>]
        sl2vl <addr> [<portnum>]
        vlarb <addr> [<portnum>]
        guids <addr>
        mlnxextportinfo <addr> [<portnum>]  # default port is zero

**-c, --combined**
        Use Combined route address argument ``<lid> <DR_Path>``

**-x, --extended**
        Set SMSupportsExtendedSpeeds bit 31 in AttributeModifier
        (only impacts PortInfo queries).

.. include:: common/opt_K.rst


Addressing Flags
----------------

.. include:: common/opt_D.rst
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
.. include:: common/opt_node_name_map.rst
.. include:: common/opt_y.rst
.. include:: common/opt_z-config.rst



FILES
=====

.. include:: common/sec_config-file.rst

.. include:: common/sec_node-name-map.rst


EXAMPLES
========

::
        smpquery portinfo 3 1                     # portinfo by lid, with port modifier
        smpquery -G switchinfo 0x2C9000100D051 1  # switchinfo by guid
        smpquery -D nodeinfo 0                    # nodeinfo by direct route
        smpquery -c nodeinfo 6 0,12               # nodeinfo by combined route

SEE ALSO
========

smpdump (8)

AUTHOR
======

Hal Rosenstock
        < hal@mellanox.com >
