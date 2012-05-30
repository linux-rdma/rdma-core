===========
IBPORTSTATE
===========

-----------------------------------------------------------------
handle port (physical) state and link speed of an InfiniBand port
-----------------------------------------------------------------

:Date: @BUILD_DATE@
:Manual section: 8
:Manual group: Open IB Diagnostics


SYNOPSIS
========

ibportstate [options] <dest dr_path|lid|guid> <portnum> [<op>]

DESCRIPTION
===========

ibportstate allows the port state and port physical state of an IB port
to be queried (in addition to link width and speed being validated
relative to the peer port when the port queried is a switch port),
or a switch port to be disabled, enabled, or reset. It
also allows the link speed/width enabled on any IB port to be adjusted.

OPTIONS
=======

**<op>**
        Supported ops: enable, disable, reset, speed, espeed, fdr10, width, query,
                        down, arm, active, vls, mtu, lid, smlid, lmc (Default
                        is query)

        **enable, disable, and reset** are only allowed on switch ports (An
        error is indicated if attempted on CA or router ports)

        **speed and width** are allowed on any port

        **speed** values are the legal values for PortInfo:LinkSpeedEnabled (An
        error is indicated if PortInfo:LinkSpeedSupported does not support this
        setting)

        **espeed** is allowed on any port supporting extended link speeds

        **fdr10** is allowed on any port supporting fdr10 (An error is
        indicated if port's capability mask indicates extended link speeds are
        not supported or if PortInfo:LinkSpeedExtSupported does not support
        this setting)

        **width** values are legal values for PortInfo:LinkWidthEnabled (An
        error is indicated if PortInfo:LinkWidthSupported does not support this
        setting) (NOTE: Speed and width changes are not effected until the port
        goes through link renegotiation)

        **query** also validates port characteristics (link width, speed,
        espeed, and fdr10) based on the peer port. This checking is done when
        the port queried is a switch port as it relies on combined routing (an
        initial LID route with directed routing to the peer) which can only be
        done on a switch. This peer port validation feature of query op
        requires LID routing to be functioning in the subnet.


Addressing Flags
----------------

.. include:: common/opt_L.rst
.. include:: common/opt_G.rst
.. include:: common/opt_D.rst
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
.. include:: common/opt_K.rst
.. include:: common/opt_v.rst
.. include:: common/opt_V.rst

FILES
=====

.. include:: common/sec_config-file.rst

EXAMPLES
========

::
        ibportstate 3 1 disable                  # by lid
        ibportstate -G 0x2C9000100D051 1 enable  # by guid
        ibportstate -D 0 1                       # (query) by direct route
        ibportstate 3 1 reset                    # by lid
        ibportstate 3 1 speed 1                  # by lid
        ibportstate 3 1 width 1                  # by lid
        ibportstate -D 0 1 lid 0x1234 arm        # by direct route

AUTHOR
======

Hal Rosenstock
        < hal.rosenstock@gmail.com >
