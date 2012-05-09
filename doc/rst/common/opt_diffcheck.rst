.. Define the common option diffcheck

**--diffcheck <key(s)>**
Specify what diff checks should be done in the **--diff** option above.
Comma separate multiple diff check key(s).  The available diff checks
are: **sw = switches**, **ca = channel adapters**, **router** = routers,
**port** = port connections, **lid** = lids, **nodedesc** = node
descriptions.  Note that **port**, **lid**, and **nodedesc** are
checked only for the node types that are specified (e.g. **sw**,
**ca**, **router**).  If **port** is specified alongside **lid**
or **nodedesc**, remote port lids and node descriptions will also be compared.


