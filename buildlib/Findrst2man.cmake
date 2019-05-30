# COPYRIGHT (c) 2019 Mellanox Technologies Ltd
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.
find_program(RST2MAN_EXECUTABLE NAMES rst2man)

if(RST2MAN_EXECUTABLE)
  execute_process(COMMAND "${RST2MAN_EXECUTABLE}" --version
    OUTPUT_VARIABLE _VERSION
    RESULT_VARIABLE _VERSION_RESULT
    ERROR_QUIET)

  if(NOT _VERSION_RESULT)
    string(REGEX REPLACE "^rst2man \\(Docutils ([^,]+), .*" "\\1" RST2MAN_VERSION_STRING "${_VERSION}")
  endif()
  unset(_VERSION_RESULT)
  unset(_VERSION)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(rst2man REQUIRED_VARS RST2MAN_EXECUTABLE RST2MAN_VERSION_STRING VERSION_VAR RST2MAN_VERSION_STRING)

mark_as_advanced(RST2MAN_EXECUTABLE)
