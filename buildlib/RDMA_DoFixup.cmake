# COPYRIGHT (c) 2016 Obsidian Research Corporation. See COPYING file

# Execute a header fixup based on NOT_NEEDED for HEADER

# The buildlib includes alternate header file shims for several scenarios, if
# the build system detects a feature is present then it should call RDMA_DoFixup
# with the test as true. If false then the shim header will be installed.

# Typically the shim header will replace a missing header with stubs, or it
# will augment an existing header with include_next.
function(RDMA_DoFixup not_needed header)
  set(DEST "${BUILD_INCLUDE}/${header}")
  if (NOT "${not_needed}")
    if(CMAKE_VERSION VERSION_LESS "2.8.12")
      get_filename_component(DIR ${DEST} PATH)
    else()
      get_filename_component(DIR ${DEST} DIRECTORY)
    endif()
    file(MAKE_DIRECTORY "${DIR}")
    string(REPLACE / - header-bl ${header})
    rdma_create_symlink("${BUILDLIB}/fixup-include/${header-bl}" "${DEST}")
  else()
    file(REMOVE ${DEST})
  endif()
endfunction()
