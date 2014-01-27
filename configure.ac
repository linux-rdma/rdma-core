dnl Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([librdmacm],[1.0.18],[linux-rdma@vger.kernel.org])
AC_CONFIG_SRCDIR([src/cma.c])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(config)
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

LT_INIT

AC_ARG_WITH([valgrind],
    AS_HELP_STRING([--with-valgrind],
		   [Enable valgrind annotations - default NO]))

if test "$with_valgrind" != "" && test "$with_valgrind" != "no"; then
	AC_DEFINE([INCLUDE_VALGRIND], 1,
		  [Define to 1 to enable valgrind annotations])
	if test -d $with_valgrind; then
		CPPFLAGS="$CPPLFAGS -I$with_valgrind/include"
	fi
fi

AC_ARG_ENABLE(libcheck, [  --disable-libcheck      do not test for presence of ib libraries],
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
AC_CHECK_LIB(pthread, pthread_mutex_init, [],
    AC_MSG_ERROR([pthread_mutex_init() not found.  librdmacm requires libpthread.]))
if test "$disable_libcheck" != "yes"; then
AC_CHECK_LIB(ibverbs, ibv_get_device_list, [],
    AC_MSG_ERROR([ibv_get_device_list() not found.  librdmacm requires libibverbs.]))
fi

AC_CHECK_MEMBER(struct ibv_path_record.service_id, [],
    AC_DEFINE(DEFINE_PATH_RECORD, 1, [adding path record definition]),
    [#include <infiniband/sa.h>])

dnl Check for gcc atomic intrinsics
AC_MSG_CHECKING(compiler support for atomics)
AC_LINK_IFELSE([AC_LANG_PROGRAM([[int i = 0;]],
				[[ return __sync_add_and_fetch(&i, 1) != __sync_sub_and_fetch(&i, 1); ]])],
    [ AC_MSG_RESULT(yes) ],
    [
        AC_MSG_RESULT(no)
        AC_DEFINE(DEFINE_ATOMICS, 1, [Set to 1 to implement atomics])
    ])

dnl Checks for header files.
AC_HEADER_STDC
if test "$disable_libcheck" != "yes"; then
AC_CHECK_HEADER(infiniband/verbs.h, [],
    AC_MSG_ERROR([<infiniband/verbs.h> not found.  Is libibverbs installed?]))

if test "$with_valgrind" != "" && test "$with_valgrind" != "no"; then
AC_CHECK_HEADER(valgrind/memcheck.h, [],
    AC_MSG_ERROR([valgrind requested but <valgrind/memcheck.h> not found.]))
fi
fi

dnl Checks close on exec support
AC_CHECK_HEADERS([fcntl.h sys/socket.h])

AC_CHECK_DECLS([O_CLOEXEC],,[AC_DEFINE([O_CLOEXEC],[0], [Defined to 0 if not provided])],
[[
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
]])
AC_CHECK_DECLS([SOCK_CLOEXEC],,[AC_DEFINE([SOCK_CLOEXEC],[0],[Defined to 0 if not provided])],
[[
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
]])

AC_CACHE_CHECK(for close on exec modifier for fopen(), ac_cv_feature_stream_cloexec_flag,
   [if test $ac_cv_have_decl_O_CLOEXEC = yes ; then
        if test $ac_cv_have_decl_SOCK_CLOEXEC = yes ; then
            ac_cv_feature_stream_cloexec_flag="e"
        fi
    fi])
AC_DEFINE_UNQUOTED([STREAM_CLOEXEC], "$ac_cv_feature_stream_cloexec_flag", [fopen() modifier for setting close on exec flag])

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

AC_CONFIG_FILES([Makefile librdmacm.spec])
AC_OUTPUT
