dnl Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([ibacm], [1.1.0], [linux-rdma@vger.kernel.org])
AC_CONFIG_SRCDIR([src/acm.c])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

LT_INIT(disable-static)

AC_ARG_ENABLE(libcheck, [  --disable-libcheck  do not test for presence of ib libraries],
[       if test "$enableval" = "no"; then
                disable_libcheck=yes
        fi
])

dnl Checks for programs
AC_PROG_CC

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_CHECK_SIZEOF(long)

dnl Checks for libraries
if test "$disable_libcheck" != "yes"; then
AC_CHECK_LIB(ibverbs, ibv_get_device_list, [],
    AC_MSG_ERROR([ibv_get_device_list() not found.  ibacm requires libibverbs.]))
AC_CHECK_LIB(ibumad, umad_send, [],
    AC_MSG_ERROR([umad_send() not found.  ibacm requires libibumad.]))
fi

dnl Define a configure directory
IBACM_CONFIG_PATH_TMP1="`eval echo ${sysconfdir}`"
IBACM_CONFIG_PATH_TMP2="`echo $IBACM_CONFIG_PATH_TMP1 | sed 's/^NONE/$ac_default_prefix/'`"
IBACM_CONFIG_PATH="`eval echo $IBACM_CONFIG_PATH_TMP2`/rdma"
AC_SUBST(IBACM_CONFIG_PATH)
AC_DEFINE_UNQUOTED([IBACM_CONFIG_PATH], "$IBACM_CONFIG_PATH", [Define the path to configurations])

dnl Define the bin directory
IBACM_BIN_PATH_TMP1="`eval echo ${bindir}`"
IBACM_BIN_PATH_TMP2="`echo $IBACM_BIN_PATH_TMP1 | sed 's/^NONE/$ac_default_prefix/'`"
IBACM_BIN_PATH="`eval echo $IBACM_BIN_PATH_TMP2`"
AC_SUBST(IBACM_BIN_PATH)
AC_DEFINE_UNQUOTED([IBACM_BIN_PATH], "$IBACM_BIN_PATH", [Define the path to bin directory])

dnl Define the lib directory
IBACM_LIB_PATH_TMP1="`eval echo ${libdir}`"
IBACM_LIB_PATH_TMP2="`echo $IBACM_LIB_PATH_TMP1 | sed 's/^NONE/$ac_default_prefix/'`"
IBACM_LIB_PATH="`eval echo $IBACM_LIB_PATH_TMP2`/ibacm"
AC_SUBST(IBACM_LIB_PATH)
AC_DEFINE_UNQUOTED([IBACM_LIB_PATH], "$IBACM_LIB_PATH", [Define the path to the provider lib directory])

dnl Checks for header files.
AC_HEADER_STDC
if test "$disable_libcheck" != "yes"; then
AC_CHECK_HEADER(infiniband/verbs.h, [],
    AC_MSG_ERROR([<infiniband/verbs.h> not found.  Is libibverbs installed?]))
AC_CHECK_HEADER(infiniband/umad.h, [],
    AC_MSG_ERROR([<infiniband/umad.h> not found.  Is libibumad installed?]))
fi

dnl Check netlink header files
AC_CHECK_HEADER(rdma/rdma_netlink.h,
    AC_CHECK_HEADER(rdma/ib_user_sa.h,
        AC_DEFINE(HAVE_NETLINK, 1, [Have netlink header files]),
        AC_MSG_WARN([Missing rdma/ib_user_sa.h])),
    AC_MSG_WARN([Missing rdma/rdma_netlink.h]))

dnl Check for gcc atomic intrinsics
AC_MSG_CHECKING(compiler support for atomics)
AC_TRY_LINK([int i = 0;],
    [ return __sync_add_and_fetch(&i, 1) != __sync_sub_and_fetch(&i, 1); ],
    [ AC_MSG_RESULT(yes) ],
    [
        AC_MSG_RESULT(no)
        AC_DEFINE(DEFINE_ATOMICS, 1, [Set to 1 to implement atomics])
    ])

AC_CACHE_CHECK(whether ld accepts --version-script, ac_cv_version_script,
    if test -n "`$LD --help < /dev/null 2>/dev/null | grep version-script`"; then
        ac_cv_version_script=yes
    else
        ac_cv_version_script=no
    fi)

AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$ac_cv_version_script" = "yes")

AC_ARG_VAR(rdmadir, [Directory for configuration files])
if test "x$rdmadir" = "x"; then
   AC_SUBST(rdmadir, rdma)
fi
AC_SUBST(sbindir)

AC_ARG_VAR(rdmascript, [Required dependency script name])
if test "x$rdmascript" = "x"; then
   if test -n "`grep -q 'release 6' /etc/redhat-release`"; then
      AC_SUBST(rdmascript, rdma)
   else
      AC_SUBST(rdmascript, openibd)
   fi
fi

AC_CONFIG_FILES([Makefile ibacm.spec ibacm.init])
AC_OUTPUT
