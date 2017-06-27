# COPYRIGHT (c) 2016 Obsidian Research Corporation.
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.

# Execute a header fixup based on NOT_NEEDED for HEADER

# The buildlib includes alternate header file shims for several scenarios, if
# the build system detects a feature is present then it should call RDMA_DoFixup
# with the test as true. If false then the shim header will be installed.

# Typically the shim header will replace a missing header with stubs, or it
# will augment an existing header with include_next.
function(RDMA_DoFixup not_needed header)
  cmake_parse_arguments(ARGS "NO_SHIM" "" "" ${ARGN})
  string(REPLACE / - header-bl ${header})

  if (NOT EXISTS "${BUILDLIB}/fixup-include/${header-bl}")
    # NO_SHIM lets cmake succeed if the header exists in the system but no
    # shim is provided, but this will always fail if the shim is needed but
    # does not exist.
    if (NOT ARGS_NO_SHIM OR NOT "${not_needed}")
      message(FATAL_ERROR "Fixup header ${BUILDLIB}/fixup-include/${header-bl} is not present")
    endif()
  endif()

  set(DEST "${BUILD_INCLUDE}/${header}")
  if (NOT "${not_needed}")
    if(CMAKE_VERSION VERSION_LESS "2.8.12")
      get_filename_component(DIR ${DEST} PATH)
    else()
      get_filename_component(DIR ${DEST} DIRECTORY)
    endif()
    file(MAKE_DIRECTORY "${DIR}")

    rdma_create_symlink("${BUILDLIB}/fixup-include/${header-bl}" "${DEST}")
  else()
    file(REMOVE ${DEST})
  endif()
endfunction()
