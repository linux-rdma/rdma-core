# COPYRIGHT (c) 2017 Mellanox Technologies Ltd
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.
find_program(PANDOC_EXECUTABLE NAMES pandoc)

if(PANDOC_EXECUTABLE)
  execute_process(COMMAND "${PANDOC_EXECUTABLE}" -v
    OUTPUT_VARIABLE _VERSION
    RESULT_VARIABLE _VERSION_RESULT
    ERROR_QUIET)

  if(NOT _VERSION_RESULT)
    string(REGEX REPLACE "^pandoc ([^\n]+)\n.*" "\\1" PANDOC_VERSION_STRING "${_VERSION}")
  endif()
  unset(_VERSION_RESULT)
  unset(_VERSION)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(pandoc REQUIRED_VARS PANDOC_EXECUTABLE PANDOC_VERSION_STRING VERSION_VAR PANDOC_VERSION_STRING)

mark_as_advanced(PANDOC_EXECUTABLE)
