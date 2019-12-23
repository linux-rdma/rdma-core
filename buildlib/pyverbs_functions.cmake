# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved.  See COPYING file

function(rdma_cython_module PY_MODULE LINKER_FLAGS)
  foreach(PYX_FILE ${ARGN})
    get_filename_component(FILENAME ${PYX_FILE} NAME_WE)
    get_filename_component(DIR ${PYX_FILE} DIRECTORY)
	if (DIR)
		set(PYX "${CMAKE_CURRENT_SOURCE_DIR}/${DIR}/${FILENAME}.pyx")
	else()
	    set(PYX "${CMAKE_CURRENT_SOURCE_DIR}/${FILENAME}.pyx")
	endif()
    set(CFILE "${CMAKE_CURRENT_BINARY_DIR}/${FILENAME}.c")
    include_directories(${PYTHON_INCLUDE_DIRS})
    add_custom_command(
      OUTPUT "${CFILE}"
      MAIN_DEPENDENCY "${PYX}"
      COMMAND ${CYTHON_EXECUTABLE} "${PYX}" -o "${CFILE}"
      "-I${PYTHON_INCLUDE_DIRS}"
      COMMENT "Cythonizing ${PYX}"
      )

    string(REGEX REPLACE "\\.so$" "" SONAME "${FILENAME}${CMAKE_PYTHON_SO_SUFFIX}")
    add_library(${SONAME} SHARED ${CFILE})
    set_target_properties(${SONAME} PROPERTIES
      COMPILE_FLAGS "${CMAKE_C_FLAGS} -fPIC -fno-strict-aliasing -Wno-unused-function -Wno-redundant-decls -Wno-shadow -Wno-cast-function-type -Wno-implicit-fallthrough -Wno-unknown-warning -Wno-unknown-warning-option ${NO_VAR_TRACKING_FLAGS}"
      LIBRARY_OUTPUT_DIRECTORY "${BUILD_PYTHON}/${PY_MODULE}"
      PREFIX "")
    target_link_libraries(${SONAME} LINK_PRIVATE ${PYTHON_LIBRARIES} ibverbs rdmacm ${LINKER_FLAGS})
    install(TARGETS ${SONAME}
      DESTINATION ${CMAKE_INSTALL_PYTHON_ARCH_LIB}/${PY_MODULE})
  endforeach()
endfunction()

function(rdma_python_module PY_MODULE)
  foreach(PY_FILE ${ARGN})
    get_filename_component(LINK "${CMAKE_CURRENT_SOURCE_DIR}/${PY_FILE}" ABSOLUTE)
    rdma_create_symlink("${LINK}" "${BUILD_PYTHON}/${PY_MODULE}/${PY_FILE}")
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/${PY_FILE}
      DESTINATION ${CMAKE_INSTALL_PYTHON_ARCH_LIB}/${PY_MODULE})
  endforeach()
endfunction()

function(rdma_python_test PY_MODULE)
  foreach(PY_FILE ${ARGN})
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/${PY_FILE}
      DESTINATION ${CMAKE_INSTALL_DOCDIR}/${PY_MODULE})
  endforeach()
endfunction()

# Make a python script runnable from the build/bin directory with all the
# correct paths filled in
function(rdma_internal_binary)
  foreach(PY_FILE ${ARGN})
    get_filename_component(ABS "${CMAKE_CURRENT_SOURCE_DIR}/${PY_FILE}" ABSOLUTE)
    get_filename_component(FN "${CMAKE_CURRENT_SOURCE_DIR}/${PY_FILE}" NAME)
    set(BIN_FN "${BUILD_BIN}/${FN}")

    file(WRITE "${BIN_FN}" "#!/bin/sh
PYTHONPATH='${BUILD_PYTHON}' exec '${PYTHON_EXECUTABLE}' '${ABS}' \"$@\"
")
    execute_process(COMMAND "chmod" "a+x" "${BIN_FN}")
  endforeach()
endfunction()
