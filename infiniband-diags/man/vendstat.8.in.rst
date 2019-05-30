========
vendstat
========

------------------------------------------
query InfiniBand vendor specific functions
------------------------------------------

:Date: 2017-08-21
:Manual section: 8
:Manual group: Open IB Diagnostics

SYNOPSIS
========

vendstat [options] <lid|guid>

DESCRIPTION
===========

vendstat uses vendor specific MADs to access beyond the IB spec
vendor specific functionality. Currently, there is support for
Mellanox InfiniSwitch-III (IS3) and InfiniSwitch-IV (IS4).

OPTIONS
=======

**-N**
	show IS3 or IS4 general information.

**-w**
	show IS3 port xmit wait counters.

**-i**
	show IS4 counter group info.

**-c <num,num>**
	configure IS4 counter groups.

	Configure IS4 counter groups 0 and 1. Such configuration is not
	persistent across IS4 reboot.  First number is for counter group 0 and
	second is for counter group 1.

	Group 0 counter config values:

::
		0 - PortXmitDataSL0-7
		1 - PortXmitDataSL8-15
		2 - PortRcvDataSL0-7

	Group 1 counter config values:

::
		1 - PortXmitDataSL8-15
		2 - PortRcvDataSL0-7
		8 - PortRcvDataSL8-15

**-R, --Read <addr,mask>**
	Read configuration space record at addr

**-W, --Write <addr,val,mask>**
	Write configuration space record at addr


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


EXAMPLES
========

::
	vendstat -N 6		# read IS3 or IS4 general information
	vendstat -w 6		# read IS3 port xmit wait counters
	vendstat -i 6 12	# read IS4 port 12 counter group info
	vendstat -c 0,1 6 12	# configure IS4 port 12 counter groups for PortXmitDataSL
	vendstat -c 2,8 6 12	# configure IS4 port 12 counter groups for PortRcvDataSL

AUTHOR
======

Hal Rosenstock
	< hal.rosenstock@gmail.com >
