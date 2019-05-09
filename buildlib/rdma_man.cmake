# COPYRIGHT (c) 2017-2018 Mellanox Technologies Ltd
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.

rdma_make_dir("${CMAKE_BINARY_DIR}/pandoc-prebuilt")
add_custom_target("docs" ALL DEPENDS "${OBJ}")

function(rdma_man_get_prebuilt SRC OUT)
  # If rst2man is not installed then we install the man page from the
  # pre-built cache directory under buildlib. When the release tar file is
  # made the man pages are pre-built and included. This is done via install
  # so that ./build.sh never depends on pandoc, only 'ninja install'.
  execute_process(
    COMMAND "${PYTHON_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/buildlib/pandoc-prebuilt.py" --retrieve "${CMAKE_SOURCE_DIR}" "${SRC}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE OBJ
    RESULT_VARIABLE retcode)
  if(NOT "${retcode}" STREQUAL "0")
    message(FATAL_ERROR "Failed to load prebuilt pandoc output")
  endif()
  set(${OUT} "${OBJ}" PARENT_SCOPE)
endfunction()

function(rdma_md_man_page SRC MAN_SECT MANFN)
  set(OBJ "${CMAKE_CURRENT_BINARY_DIR}/${MANFN}")

  if (PANDOC_EXECUTABLE)
    add_custom_command(
      OUTPUT "${OBJ}"
      COMMAND "${PYTHON_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/buildlib/pandoc-prebuilt.py" --build "${CMAKE_BINARY_DIR}" --pandoc "${PANDOC_EXECUTABLE}" "${SRC}" "${OBJ}"
      MAIN_DEPENDENCY "${SRC}"
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      COMMENT "Creating man page ${MANFN}"
      VERBATIM)
    add_custom_target("man-${MANFN}" ALL DEPENDS "${OBJ}")
    add_dependencies("docs" "man-${MANFN}")
  else()
    rdma_man_get_prebuilt(${SRC} OBJ)
  endif()

  install(FILES "${OBJ}"
    RENAME "${MANFN}"
    DESTINATION "${CMAKE_INSTALL_MANDIR}/man${MAN_SECT}/")
endfunction()

function(rdma_rst_man_page SRC MAN_SECT MANFN)
  set(OBJ "${CMAKE_CURRENT_BINARY_DIR}/${MANFN}")

  if (RST2MAN_EXECUTABLE)
    add_custom_command(
      OUTPUT "${OBJ}"
      COMMAND "${PYTHON_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/buildlib/pandoc-prebuilt.py" --build "${CMAKE_BINARY_DIR}" --rst "${RST2MAN_EXECUTABLE}" "${SRC}" "${OBJ}"
      MAIN_DEPENDENCY "${SRC}"
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      COMMENT "Creating man page ${MANFN}"
      VERBATIM)
    add_custom_target("man-${MANFN}" ALL DEPENDS "${OBJ}")
    add_dependencies("docs" "man-${MANFN}")
  else()
    rdma_man_get_prebuilt(${SRC} OBJ)
  endif()

  install(FILES "${OBJ}"
    RENAME "${MANFN}"
    DESTINATION "${CMAKE_INSTALL_MANDIR}/man${MAN_SECT}/")
endfunction()

# Install man pages. This deduces the section from the trailing integer in the
# filename
function(rdma_man_pages)
  foreach(I ${ARGN})
    if ("${I}" MATCHES "\\.md$")
      string(REGEX REPLACE "^.+[.](.+)\\.md$" "\\1" MAN_SECT "${I}")
      string(REGEX REPLACE "^(.+)\\.md$" "\\1" BASE_NAME "${I}")
      get_filename_component(BASE_NAME "${BASE_NAME}" NAME)

      rdma_md_man_page(
	"${I}"
	"${MAN_SECT}"
	"${BASE_NAME}")
    elseif ("${I}" MATCHES "\\.in\\.rst$")
      string(REGEX REPLACE "^.+[.](.+)\\.in\\.rst$" "\\1" MAN_SECT "${I}")
      string(REGEX REPLACE "^(.+)\\.in\\.rst$" "\\1" BASE_NAME "${I}")
      get_filename_component(BASE_NAME "${BASE_NAME}" NAME)

      configure_file("${I}" "${CMAKE_CURRENT_BINARY_DIR}/${BASE_NAME}.rst" @ONLY)

      rdma_rst_man_page(
	"${CMAKE_CURRENT_BINARY_DIR}/${BASE_NAME}.rst"
	"${MAN_SECT}"
	"${BASE_NAME}")
    elseif ("${I}" MATCHES "\\.in$")
      string(REGEX REPLACE "^.+[.](.+)\\.in$" "\\1" MAN_SECT "${I}")
      string(REGEX REPLACE "^(.+)\\.in$" "\\1" BASE_NAME "${I}")
      get_filename_component(BASE_NAME "${BASE_NAME}" NAME)
      rdma_subst_install(FILES "${I}"
	DESTINATION "${CMAKE_INSTALL_MANDIR}/man${MAN_SECT}/"
	RENAME "${BASE_NAME}")
    else()
      string(REGEX REPLACE "^.+[.](.+)$" "\\1" MAN_SECT "${I}")
      install(FILES "${I}" DESTINATION "${CMAKE_INSTALL_MANDIR}/man${MAN_SECT}/")
    endif()
  endforeach()
endfunction()

# Create an alias for a man page, using a symlink.
# Input is a list of pairs of names (MAN_PAGE ALIAS)
# NOTE: The section must currently be the same for both.
function(rdma_alias_man_pages)
  list(LENGTH ARGN LEN)
  math(EXPR LEN ${LEN}-1)
  foreach(I RANGE 0 ${LEN} 2)
    list(GET ARGN ${I} FROM)
    math(EXPR I ${I}+1)
    list(GET ARGN ${I} TO)
    string(REGEX REPLACE "^.+[.](.+)$" "\\1" MAN_SECT ${FROM})
    rdma_install_symlink("${FROM}" "${CMAKE_INSTALL_MANDIR}/man${MAN_SECT}/${TO}")
  endforeach()
endfunction()
