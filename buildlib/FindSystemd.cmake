# COPYRIGHT (c) 2015 Obsidian Research Corporation.
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.

find_path(LIBSYSTEMD_INCLUDE_DIRS "systemd/sd-journal.h")

if (LIBSYSTEMD_INCLUDE_DIRS)
  set(SYSTEMD_INCLUDE_DIRS ${LIBSYSTEMD_INCLUDE_DIRS})
  find_library(LIBSYSTEMD_LIBRARY NAMES systemd libsystemd)
  # Older systemd uses a split library
  if (NOT LIBSYSTEMD_LIBRARY)
    find_library(LIBSYSTEMD_JOURNAL_LIBRARY NAMES systemd-journal libsystemd-journal)
    find_library(LIBSYSTEMD_ID128_LIBRARY NAMES systemd-id128 libsystemd-id128)
    find_library(LIBSYSTEMD_DAEMON_LIBRARY NAMES systemd-daemon libsystemd-daemon)

    if (LIBSYSTEMD_JOURNAL_LIBRARY AND LIBSYSTEMD_ID128_LIBRARY AND LIBSYSTEMD_DAEMON_LIBRARY)
      set(SYSTEMD_LIBRARIES
	${LIBSYSTEMD_JOURNAL_LIBRARY}
	${LIBSYSTEMD_ID128_LIBRARY}
	${LIBSYSTEMD_DAEMON_LIBRARY})
    endif()
  else()
    set(SYSTEMD_LIBRARIES ${LIBSYSTEMD_LIBRARY})
  endif()
  set(SYSTEMD_INCLUDE_DIRS)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Systemd REQUIRED_VARS SYSTEMD_LIBRARIES LIBSYSTEMD_INCLUDE_DIRS)

mark_as_advanced(LIBSYSTEMD_LIBRARY LIBSYSTEMD_JOURNAL_LIBRARY LIBSYSTEMD_ID128_LIBRARY LIBSYSTEMD_DAEMON_LIBRARY)
