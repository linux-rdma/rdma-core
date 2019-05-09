======
sminfo
======

---------------------------------
query InfiniBand SMInfo attribute
---------------------------------

:Date: 2017-08-21
:Manual section: 8
:Manual group: Open IB Diagnostics

SYNOPSIS
========

sminfo [options] sm_lid | sm_dr_path [modifier]

DESCRIPTION
===========

Optionally set and display the output of a sminfo query in human readable
format. The target SM is the one listed in the local port info, or the SM
specified by the optional SM lid or by the SM direct routed path.

Note: using sminfo for any purposes other then simple query may be very
dangerous, and may result in a malfunction of the target SM.

OPTIONS
=======

**-s, --state <state>** set SM state
        0 not active

        1 discovering

        2 standby

        3 master

**-p, --priority <priority>** set priority (0-15)

**-a, --activity <val>** set activity count

Addressing Flags
----------------

.. include:: common/opt_D.rst
.. include:: common/opt_G.rst
.. include:: common/opt_L.rst


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
.. include:: common/opt_z-config.rst


FILES
=====

.. include:: common/sec_config-file.rst


EXAMPLES
========

::
        sminfo                  # local port\'s sminfo
        sminfo 32               # show sminfo of lid 32
        sminfo  -G 0x8f1040023  # same but using guid address


SEE ALSO
========

smpdump (8)

AUTHOR
======

Hal Rosenstock
        < halr@voltaire.com >
