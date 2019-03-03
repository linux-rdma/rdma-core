# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved.  See COPYING file

execute_process(COMMAND "${PYTHON_EXECUTABLE}" -c
  "from Cython.Compiler.Main import main; import Cython; print(Cython.__version__);"
  OUTPUT_VARIABLE _VERSION
  RESULT_VARIABLE _VERSION_RESULT
  ERROR_QUIET)

if(NOT _VERSION_RESULT)
  # We make our own cython script because it is very hard to figure out which
  # cython exectuable wrapper is appropriately matched to the python
  # interpreter we want to use. Cython must use the matching version of python
  # or things will go wrong.
  string(STRIP "${_VERSION}" CYTHON_VERSION_STRING)
  set(CYTHON_EXECUTABLE "${BUILD_PYTHON}/cython")
  file(WRITE "${CYTHON_EXECUTABLE}" "#!${PYTHON_EXECUTABLE}
from Cython.Compiler.Main import main
main(command_line = 1)")
  execute_process(COMMAND "chmod" "a+x" "${CYTHON_EXECUTABLE}")

  # Dockers with older Cython versions fail to build pyverbs. Until we get to
  # the bottom of this, disable pyverbs for older Cython versions.
  if (CYTHON_VERSION_STRING VERSION_LESS "0.25")
	message("Cython version < 0.25, disabling")
	unset(CYTHON_EXECUTABLE)
  endif()

endif()
unset(_VERSION_RESULT)
unset(_VERSION)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(cython
  REQUIRED_VARS CYTHON_EXECUTABLE CYTHON_VERSION_STRING
  VERSION_VAR CYTHON_VERSION_STRING)
mark_as_advanced(CYTHON_EXECUTABLE)
