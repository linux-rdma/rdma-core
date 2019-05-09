===========
ibidsverify
===========

---------------------------------------------------
validate IB identifiers in subnet and report errors
---------------------------------------------------

:Date: 2017-08-21
:Manual section: 8
:Manual group: Open IB Diagnostics

SYNOPSIS
========

ibidsverify.pl [-h] [-R]

DESCRIPTION
===========

ibidsverify.pl is a perl script which uses a full topology file that was
created by ibnetdiscover, scans the network to validate the LIDs and GUIDs
in the subnet. The validation consists of checking that there are no zero
or duplicate identifiers.

Finally, ibidsverify.pl will also reuse the cached ibnetdiscover output from
some of the other diag tools which makes it a bit faster than running
ibnetdiscover from scratch.

OPTIONS
=======

**-R**
Recalculate the ibnetdiscover information, ie do not use the cached
information.  This option is slower but should be used if the diag tools have
not been used for some time or if there are other reasons to believe the
fabric has changed.

**-C <ca_name>**    use the specified ca_name.

**-P <ca_port>**    use the specified ca_port.

EXIT STATUS
===========

Exit status is 1 if errors are found, 0 otherwise.

FILES
=====

.. include:: common/sec_config-file.rst


SEE ALSO
========

**ibnetdiscover(8)**

AUTHOR
======

Hal Rosenstock
	< halr@voltaire.com >
