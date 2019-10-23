======
IBADDR
======

----------------------------
query InfiniBand address(es)
----------------------------

:Date: 2013-10-11
:Manual section: 8
:Manual group: OpenIB Diagnostics


SYNOPSIS
========

ibaddr [options]


DESCRIPTION
===========


Display the lid (and range) as well as the GID address of the
port specified (by DR path, lid, or GUID) or the local port by default.

Note: this utility can be used as simple address resolver.

OPTIONS
=======

**--gid_show, -g**
show gid address only

**--lid_show, -l**
show lid range only

**--Lid_show, -L**
show lid range (in decimal) only


Addressing Flags
----------------

.. include:: common/opt_D.rst
.. include:: common/opt_G.rst
.. include:: common/opt_s.rst


Debugging flags
---------------

.. include:: common/opt_d.rst
.. include:: common/opt_e.rst
.. include:: common/opt_h.rst
.. include:: common/opt_v.rst
.. include:: common/opt_V.rst


Port Selection flags
--------------------

.. include:: common/opt_C.rst
.. include:: common/opt_P.rst
.. include:: common/sec_portselection.rst


Configuration flags
-------------------

.. include:: common/opt_y.rst
.. include:: common/opt_t.rst
.. include:: common/opt_z-config.rst

FILES
=====

.. include:: common/sec_config-file.rst


EXAMPLES
========

::

        ibaddr                  # local port\'s address
        ibaddr 32               # show lid range and gid of lid 32
        ibaddr -G 0x8f1040023   # same but using guid address
        ibaddr -l 32            # show lid range only
        ibaddr -L 32            # show decimal lid range only
        ibaddr -g 32            # show gid address only

SEE ALSO
========

**ibroute (8), ibtracert (8)**

AUTHOR
======

Hal Rosenstock
        < halr@voltaire.com >
