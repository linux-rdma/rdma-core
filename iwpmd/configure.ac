#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT(iwpmd, 1.0.6, linux-rdma@vger.kernel.org)
AC_CONFIG_SRCDIR([src/iwarp_pm_server.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB(pthread, pthread_cond_init, [],
	AC_MSG_ERROR([pthread_cond_init() not found. iwpmd requires libpthread.]))
AC_CHECK_LIB(nl, nlmsg_alloc, [], AC_CHECK_LIB(nl-3, nlmsg_alloc, [],
	AC_MSG_ERROR([nlmsg_alloc() not found. iwpmd requires libnl or libnl-3 to be installed])))


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h syslog.h unistd.h])
AC_CHECK_HEADERS([netlink/attr.h netlink/addr.h netlink/data.h netlink/msg.h netlink/types.h netlink/utils.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset select socket strerror])

AC_CONFIG_FILES([Makefile iwpmd.spec])
AC_OUTPUT
