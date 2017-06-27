# COPYRIGHT (c) 2016 Obsidian Research Corporation.
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.

# Same as publish_headers but does not install them during the install phase
function(publish_internal_headers DEST)
  if(NOT ARGN)
    message(SEND_ERROR "Error: publish_internal_headers called without any files")
    return()
  endif()

  set(DDIR "${BUILD_INCLUDE}/${DEST}")
  file(MAKE_DIRECTORY "${DDIR}")

  foreach(SFIL ${ARGN})
    get_filename_component(FIL ${SFIL} NAME)
    rdma_create_symlink("${CMAKE_CURRENT_SOURCE_DIR}/${SFIL}" "${DDIR}/${FIL}")
  endforeach()
endfunction()

# Copy headers from the source directory to the proper place in the
# build/include directory. This also installs them into /usr/include/xx during
# the install phase
function(publish_headers DEST)
  publish_internal_headers("${DEST}" ${ARGN})

  foreach(SFIL ${ARGN})
    get_filename_component(FIL ${SFIL} NAME)
    install(FILES "${SFIL}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${DEST}/" RENAME "${FIL}")
  endforeach()
endfunction()
