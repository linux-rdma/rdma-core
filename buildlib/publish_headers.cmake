# COPYRIGHT (c) 2016 Obsidian Research Corporation. See COPYING file

# Copy headers from the source directory to the proper place in the
# build/include directory
function(PUBLISH_HEADERS DEST)
  if(NOT ARGN)
    message(SEND_ERROR "Error: PUBLISH_HEADERS called without any files")
    return()
  endif()

  set(DDIR "${BUILD_INCLUDE}/${DEST}")
  file(MAKE_DIRECTORY "${DDIR}")

  foreach(SFIL ${ARGN})
    get_filename_component(FIL ${SFIL} NAME)
    execute_process(COMMAND "ln" "-Tsf"
      "${CMAKE_CURRENT_SOURCE_DIR}/${SFIL}" "${DDIR}/${FIL}")
    install(FILES "${SFIL}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${DEST}/" RENAME "${FIL}")
  endforeach()
endfunction()
