infiniband-diags ReStructured Text documentation
================================================

Having documentation in ReStructured Text has the following benefits

1) The addition of common functionality (options, config files, etc.) can be
   documented once and then included in documents for multiple tools.

   1a) Documentation source is more straight forward and writers can
       concentrate on the features which are unique to each tool.

2) Documentation can be generated into multiple formats (man, html) not just
   man pages.

3) Documentation for any individual tool is complete within that page.  (There
   is no referencing of other documents and guessing which "common" options
   apply.)


Instructions
------------

Place main ``rst`` files in the rst directory.  ``common include`` rst files
should be in rst/common.

"git add" should _only_ be run on the rst source files themselves.

The best way to update generated documentation after changes is to [re]run
configure.  autoconf will run the ``generate`` script if rst2man is available
on your system.  If rst2man is not available, tarball and source rpm
distributions contain the doc/man/\*.in files and can be built from those files
a users system without rst2man.  Of course they will not get any changes made
to the rst files.  Therefore developers are required to have rst2man[*] installed.

[*] rst2man is available in the python-docutils package.


Common files
------------

Common documents should be placed in the rst/common directory.  Common files should not be put
in the 'main' rst directory.   The automated conversion script will try and
make documents out of them.

There are 2 types of common files

	1) common options

               The common options are text which describes a common option.
               The naming conventions is:

                        opt_<option>.rst

	2) common sections

                A common section contains a section header and documents a more
                advanced feature such as a config file.  The naming convention
                for the common section is:

                        sec_<section>.rst.


Common documents should actually document features which are intended to be
common across multiple tools.  Within the code these features are contained in
ibdiag_common or a sub library such as ibnetdisc or an external library such as
the node name map feature.


Examples
--------

The "man" page text is:

::
        <text>

        .. include:: common/opt_L.rst

        <text>

        .. include:: common/sec_config-file.rst


The common option "L" is:

::
        .. Define the common option -L

        **-L**   The address specified is a LID


And the common Section is:

::
        .. Common text for the config file

        CONFIG FILE
        -----------

        @IBDIAG_CONFIG_PATH@/ibdiag.conf

        A global config file is provided to set some of the common options for all
        tools.  See supplied config file for details.


