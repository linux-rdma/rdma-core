=========
ibtracert
=========

---------------------
trace InfiniBand path
---------------------

:Date: 2018-04-02
:Manual section: 8
:Manual group: Open IB Diagnostics

SYNOPSIS
========

ibtracert [options] [<lid|guid> [<startlid> [<endlid>]]]


DESCRIPTION
===========

ibtracert uses SMPs to trace the path from a source GID/LID to a
destination GID/LID. Each hop along the path is displayed until
the destination is reached or a hop does not respond. By using
the -m option, multicast path tracing can be performed between source
and destination nodes.

OPTIONS
=======

**-n, --no_info**
        simple format; don't show additional information

**-m**
        show the multicast trace of the specified mlid

**-f, --force**
        force route to destination port


Addressing Flags
----------------

.. include:: common/opt_G.rst
.. include:: common/opt_L.rst
.. include:: common/opt_s.rst
.. include:: common/opt_ports-file.rst


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
.. include:: common/sec_ports-file.rst


EXAMPLES
========

Unicast examples

::
        ibtracert 4 16                                  # show path between lids 4 and 16
        ibtracert -n 4 16                               # same, but using simple output format
        ibtracert -G 0x8f1040396522d 0x002c9000100d051  # use guid addresses

Multicast example

::
        ibtracert -m 0xc000 4 16    # show multicast path of mlid 0xc000 between lids 4 and 16

SEE ALSO
========
ibroute (8)


AUTHOR
======

Hal Rosenstock
        <hal.rosenstock@gmail.com>

Ira Weiny
        < ira.weiny@intel.com >
