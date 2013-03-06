dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(librdmacm, 1.0.17, linux-rdma@vger.kernel.org)
AC_CONFIG_SRCDIR([src/cma.c])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(config)
AC_CONFIG_HEADERS(config.h)
AM_INIT_AUTOMAKE(librdmacm, 1.0.17)
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_PROG_LIBTOOL

AC_ARG_WITH([valgrind],
    AC_HELP_STRING([--with-valgrind],
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
AC_TRY_LINK([int i = 0;],
    [ return __sync_add_and_fetch(&i, 1) != __sync_sub_and_fetch(&i, 1); ],
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

AC_CHECK_HEADER(infiniband/acm.h, 
	AC_DEFINE([USE_IB_ACM], 1, [setting IBACM support]), [])

AC_CHECK_HEADER(infiniband/acm.h,
	AC_CHECK_MEMBER(struct acm_msg.resolve_data, [],
		AC_DEFINE(DEFINE_ACM_MSG, 1, [adding ACM message definition]),
			[#include <infiniband/acm.h>]), [])

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
