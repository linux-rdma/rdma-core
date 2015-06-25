dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(infiniband-diags, 1.6.5, linux-rdma@vger.kernel.org)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(config)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([foreign])

AC_SUBST(RELEASE, ${RELEASE:-unknown})
AC_SUBST(TARBALL, ${TARBALL:-${PACKAGE}-${VERSION}.tar.gz})

dnl support debug mode
AC_ARG_ENABLE(debug,
[  --enable-debug Turn on debug mode],
[case "${enableval}" in
  yes) debug=true ;;
  no)  debug=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
esac],[debug=false])
AM_CONDITIONAL(DEBUG, test x$debug = xtrue)

dnl Checks for programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

AC_CHECK_PROG(have_dash, [dash], true, false)
AM_CONDITIONAL(HAVE_DASH, test x$have_dash = xtrue)

dnl Checks for libraries
AC_CHECK_LIB(ibumad, umad_init, [],
	AC_MSG_ERROR([umad_init() not found. diags require libibumad.]))
AC_CHECK_LIB(ibmad, mad_dump_mlnx_ext_port_info, [],
	AC_MSG_ERROR([mad_dump_mlnx_ext_port_info() not found.
	diags require libibmad with mad_dump_mlnx_ext_port_info support.]))
AC_CHECK_LIB(ibmad, mad_dump_classportinfo, [],
	AC_MSG_ERROR([mad_dump_classportinfo() not found. diags requires a more recent libibmad.]))
AC_CHECK_MEMBER([struct umad_port.link_layer],
			[ac_have_umad_port_link_layer=yes],
			[ac_have_umad_port_link_layer=no],
			[#include <infiniband/umad.h>])
if test "$ac_have_umad_port_link_layer" = "yes"; then
   AC_DEFINE([HAVE_UMAD_PORT_LINK_LAYER], 1, [Define to 1 if struct umad_port has link_layer member])
fi
AC_CHECK_LIB(osmcomp, cl_qmap_insert, [],
	AC_MSG_ERROR([cl_qmap_insert() not found. diags require libosmcomp.]))

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h unistd.h fcntl.h inttypes.h netinet/in.h sys/ioctl.h])
AC_CHECK_HEADER(infiniband/umad.h, [],
	AC_MSG_ERROR([<infiniband/umad.h> not found. diags require libibumad.])
)
AC_CHECK_HEADER(infiniband/mad.h, [],
	AC_MSG_ERROR([<infiniband/mad.h> not found. diags require libibmad.])
)

dnl Checks for library functions
AC_FUNC_ERROR_AT_LINE
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([strchr strrchr strtol strtoul memset strtoull])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

dnl Define a configure directory
IBDIAG_CONFIG_PATH_TMP1="`eval echo ${sysconfdir}`"
IBDIAG_CONFIG_PATH_TMP2="`echo $IBDIAG_CONFIG_PATH_TMP1 | sed 's/^NONE/$ac_default_prefix/'`"
IBDIAG_CONFIG_PATH="`eval echo $IBDIAG_CONFIG_PATH_TMP2`/infiniband-diags"
AC_SUBST(IBDIAG_CONFIG_PATH)
AC_DEFINE_UNQUOTED([IBDIAG_CONFIG_PATH], "$IBDIAG_CONFIG_PATH", [Define the path to configurations])

dnl Check if we should include test utilities
AC_MSG_CHECKING(for --enable-test-utils)
AC_ARG_ENABLE(test-utils,
[  --enable-test-utils build additional test utilities (default=no)],
[case "${enableval}" in
  yes) tutils=yes ;;
  no)  tutils=no ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-test-utils) ;;
esac],[tutils=no])
AM_CONDITIONAL(ENABLE_TEST_UTILS, test x$tutils = xyes)
AC_MSG_RESULT(${tutils=no})

dnl Check if we should include compat utils
AC_MSG_CHECKING(for --enable-compat-utils)
AC_ARG_ENABLE(compat-utils,
[  --enable-compat-utils build deprecated compatibility utilities (default=no)],
[case "${enableval}" in
  yes) cutils=yes ;;
  no)  cutils=no ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-compat-utils) ;;
esac],[cutils=no])
AM_CONDITIONAL(ENABLE_COMPAT_UTILS, test x$cutils = xyes)
AC_MSG_RESULT(${cutils=no})

dnl Check for perl and perl install location
AC_MSG_CHECKING(for --with-perl-path )
AC_ARG_WITH(perl-path,
    AC_HELP_STRING([--with-perl-path=path],
                   [define perl location]),
    [ case "$withval" in
    no)
        ;;
    *)
        withperlpath=yes
        PERL=$withval
        ;;
    esac ]
)
AC_MSG_RESULT(${withperlpath=no})
AC_SUBST(PERL)

if test $withperlpath = "no"
then
    AC_PATH_PROG([PERL], [perl])
fi
AC_SUBST(PERL)

AC_MSG_CHECKING(for --with-perl-installdir )
AC_ARG_WITH(perl-installdir,
    AC_HELP_STRING([--with-perl-installdir=path],
                   [define perl install path]),
    [ case "$withval" in
    no)
        ;;
    *)
        withperlinstalldir=yes
        PERL_INSTALLDIR=$withval
        ;;
    esac ]
)
AC_MSG_RESULT(${withperlinstalldir=no})
AC_SUBST(PERL_INSTALLDIR)

if test $withperlinstalldir = "no"
then
    PERL_INSTALLDIR=`$PERL -e 'use Config; $T=$Config{installvendorlib}; print $T;'`
fi
AC_SUBST(PERL_INSTALLDIR)

AC_CACHE_CHECK(whether ld accepts --version-script, ac_cv_version_script,
    if test -n "`$LD --help < /dev/null 2>/dev/null | grep version-script`"; then
        ac_cv_version_script=yes
    else
        ac_cv_version_script=no
    fi)

AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$ac_cv_version_script" = "yes")

dnl Define override for IBPATH
AC_ARG_WITH(ibpath_override,
[  --with-ibpath_override=<path> define ib binaries path],
AC_MSG_NOTICE(Using IBPATH : $with_ibpath_override),
with_ibpath_override=)

dnl Make appropriate substitution for IB script path
dnl Must expand nested unquoting
IBSCRIPTPATH_TMP1="`eval echo ${sbindir}`"
IBSCRIPTPATH_TMP2="`echo $IBSCRIPTPATH_TMP1 | sed 's/^NONE/$ac_default_prefix/'`"
IBSCRIPTPATH="${with_ibpath_override:-`eval echo $IBSCRIPTPATH_TMP2`}"
AC_SUBST(IBSCRIPTPATH)

dnl check for glib
PKG_CHECK_MODULES([GLIB], [glib-2.0], ac_glib=yes, ac_glib=no)
AM_CONDITIONAL([HAVE_GLIB], test "$ac_glib" = "yes")
if test "$ac_glib" = "yes"; then
   AC_DEFINE([HAVE_GLIB], 1, [Define to 1 to indicate GLIB support])
else
   AC_MSG_ERROR(glib not found; glib2 is required)
fi

dnl Begin libibnetdisc stuff
ibnetdisc_api_version=`grep LIBVERSION $srcdir/libibnetdisc/libibnetdisc.ver | sed 's/LIBVERSION=//'`
if test -z $ibnetdisc_api_version; then
   echo "FAILED to find $srcdir/libibnetdisc/libibnetdisc.ver"
   exit 1
fi
AC_SUBST(ibnetdisc_api_version)
dnl End libibnetdisc stuff

dnl with or with rdma-ndd
AC_MSG_CHECKING(for --enable-rdma-ndd)
AC_ARG_ENABLE(rdma-ndd,
[  --enable-rdma-ndd build rdma-ndd (default=yes)],
[case "${enableval}" in
  yes) rdmandd=yes ;;
  no)  rdmandd=no ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-rdma-ndd) ;;
esac],[rdmandd=yes])
AM_CONDITIONAL(ENABLE_RDMA_NDD, test x$rdmandd = xyes)
AC_MSG_RESULT(${rdmandd=no})

dnl configures for rdma-ndd startup script
default_rdma_service=openibd
AC_ARG_WITH([rdma_service],
    AC_HELP_STRING([--with-rdma-service=name],
                       [name of the RDMA service: "rdma" when using /etc/init.d/rdma to start RDMA services; "openibd" when using /etc/init.d/openibd to start RDMA services [default=${default_rdma_service}]]))
AC_SUBST(RDMA_SERVICE, ${with_rdma_service:-${default_rdma_service}})

if { rpm -q sles-release || rpm -q openSUSE-release; } >/dev/null 2>&1; then
	default_stop="0 1 4 6"
else
	default_stop="0 1 6"
fi

default_start="null"

AC_SUBST(DEFAULT_START, $default_start)
AC_SUBST(DEFAULT_STOP, $default_stop)

AS_IF([test x$rdmandd = xyes], [
    PKG_CHECK_MODULES([UDEV], [libudev])
    AC_CONFIG_FILES([doc/man/rdma-ndd.8 etc/rdma-ndd.init])
    AC_SUBST([UDEV_CFLAGS])
    AC_SUBST([UDEV_LIBS])
])

dnl Generate doc/man/*.in files if possible
DOC_DATE="`date +%Y-%m-%d`"
AC_SUBST(BUILD_DATE)
AC_CHECK_PROG(have_rst2man, rst2man, "yes")
if test x$have_rst2man != xyes; then
AC_CHECK_PROG(have_rst2man, rst2man.py, "yes")
fi
if test x$have_rst2man == xyes; then
	$srcdir/doc/generate
else
	if test -f $srcdir/doc/man/infiniband-diags.8.in; then
		echo "WARNING: 'rst2man' not found; using premade man pages"
	else
		echo "FAILED to find 'rst2man' required to build man pages"
		exit 1
	fi
fi
dnl

AC_CONFIG_FILES([\
	Makefile \
	infiniband-diags.spec \
	include/ibdiag_version.h \
	scripts/ibcheckerrors \
	scripts/ibcheckerrs \
	scripts/ibchecknet \
	scripts/ibchecknode \
	scripts/ibcheckport \
	scripts/ibcheckportstate \
	scripts/ibcheckportwidth \
	scripts/ibcheckstate \
	scripts/ibcheckwidth \
	scripts/ibclearcounters \
	scripts/ibclearerrors \
	scripts/ibdatacounts \
	scripts/ibdatacounters \
	scripts/ibhosts \
	scripts/ibnodes \
	scripts/ibswitches \
	scripts/ibrouters \
	scripts/iblinkinfo.pl \
	scripts/ibqueryerrors.pl \
	scripts/dump_lfts.sh \
	scripts/dump_mfts.sh \
	doc/man/ibaddr.8 \
	doc/man/check_lft_balance.8 \
	doc/man/ibcacheedit.8 \
	doc/man/ibccconfig.8 \
	doc/man/ibccquery.8 \
	doc/man/dump_fts.8 \
	doc/man/ibhosts.8 \
	doc/man/ibidsverify.8 \
	doc/man/iblinkinfo.8 \
	doc/man/ibfindnodesusing.8 \
	doc/man/ibnetdiscover.8 \
	doc/man/ibnodes.8 \
	doc/man/ibping.8 \
	doc/man/ibportstate.8 \
	doc/man/ibqueryerrors.8 \
	doc/man/ibroute.8 \
	doc/man/ibrouters.8 \
	doc/man/ibstat.8 \
	doc/man/ibstatus.8 \
	doc/man/ibswitches.8 \
	doc/man/ibsysstat.8 \
	doc/man/ibtracert.8 \
	doc/man/perfquery.8 \
	doc/man/saquery.8 \
	doc/man/sminfo.8 \
	doc/man/smpdump.8 \
	doc/man/smpquery.8 \
	doc/man/vendstat.8 \
	doc/man/infiniband-diags.8 \
	libibnetdisc/Makefile \
])
AC_OUTPUT
