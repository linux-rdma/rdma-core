# COPYRIGHT (c) 2016 Obsidian Research Corporation.
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.

find_library(LIBUDEV_LIBRARY NAMES udev libudev)

set(UDEV_LIBRARIES ${LIBUDEV_LIBRARY})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(UDev REQUIRED_VARS LIBUDEV_LIBRARY)

mark_as_advanced(LIBUDEV_LIBRARY)
