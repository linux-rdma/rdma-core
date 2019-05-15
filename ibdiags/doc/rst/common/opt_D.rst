.. Define the common option -D for Directed routes

**-D, --Direct**     The address specified is a directed route
::

    Examples:
       [options] -D [options] "0"          # self port
       [options] -D [options] "0,1,2,1,4"  # out via port 1, then 2, ...

       (Note the second number in the path specified must match the port being
       used.  This can be specified using the port selection flag '-P' or the
       port found through the automatic selection process.)


