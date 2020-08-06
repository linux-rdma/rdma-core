.. Common text to describe the port file.

PORTS FILE FORMAT
-------------------------

The ports file can be used to specify multiple source and destination pairs.  They can be lids or guids.  If guids, use the -G option to indicate that.

**Generically:**

::

   # comment
   <src> <dst>

**Example:**

::

        73 207
        203 657
        531 101

        > OR <

        0x0008f104003f125c 0x0008f104003f133d
        0x0008f1040011ab07 0x0008f104004265c0
        0x0008f104007c5510 0x0008f1040099bb08

