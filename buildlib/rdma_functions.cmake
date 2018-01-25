# COPYRIGHT (c) 2016 Obsidian Research Corporation.
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.

# Helper functions for use in the sub CMakeLists files to make them simpler
# and more uniform.

# Global list of pairs of (SHARED STATIC) libary target names
set(RDMA_STATIC_LIBS "" CACHE INTERNAL "Doc" FORCE)

set(COMMON_LIBS_PIC ccan_pic rdma_util_pic)
set(COMMON_LIBS ccan rdma_util)

# Create a symlink at filename DEST
# If the directory containing DEST does not exist then it is created
# automatically.
function(rdma_create_symlink LINK_CONTENT DEST)
  if(NOT LINK_CONTENT)
    message(FATAL_ERROR "Failed to provide LINK_CONTENT")
  endif()

  # Make sure the directory exists, cmake doesn't create target DESTINATION
  # directories until everything is finished, do it manually here if necessary
  if(CMAKE_VERSION VERSION_LESS "2.8.12")
    get_filename_component(DDIR "${DEST}" PATH)
  else()
    get_filename_component(DDIR "${DEST}" DIRECTORY)
  endif()

  IF(NOT EXISTS "${DDIR}/")
    execute_process(COMMAND "${CMAKE_COMMAND}" "-E" "make_directory"
      "${BUILD_LIB}" RESULT_VARIABLE retcode)
    if(NOT "${retcode}" STREQUAL "0")
      message(FATAL_ERROR "Failed to create directory ${DDIR}")
    endif()
  endif()

  # Newer versions of cmake can use "${CMAKE_COMMAND}" "-E" "create_symlink"
  # however it is broken weirdly on older versions.
  execute_process(COMMAND "ln" "-Tsf"
    "${LINK_CONTENT}" "${DEST}" RESULT_VARIABLE retcode)
  if(NOT "${retcode}" STREQUAL "0")
    message(FATAL_ERROR "Failed to create symlink in ${DEST}")
  endif()
endfunction()

# Install a symlink during 'make install'
function(rdma_install_symlink LINK_CONTENT DEST)
  # Create a link in the build tree with the right content
  get_filename_component(FN "${DEST}" NAME)
  rdma_create_symlink("${LINK_CONTENT}" "${CMAKE_CURRENT_BINARY_DIR}/${FN}")

  # Have cmake install it. Doing it this way lets cpack work if we ever wish
  # to use that.
  get_filename_component(DIR "${DEST}" PATH)
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${FN}"
    DESTINATION "${DIR}")
endfunction()

# Wrapper for install() that runs the single file through configure_file first.
# This only works with the basic single file install(FILE file ARGS..) pattern
function(rdma_subst_install ARG1 file)
  if (NOT "${ARG1}" STREQUAL "FILES")
    message(FATAL_ERROR "Bad use of rdma_subst_install")
  endif()
  configure_file("${file}" "${CMAKE_CURRENT_BINARY_DIR}/${file}" @ONLY)
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${file}" ${ARGN})
endfunction()

# Modify shared library target DEST to use VERSION_SCRIPT as the linker map file
function(rdma_set_library_map DEST VERSION_SCRIPT)
  if (NOT IS_ABSOLUTE ${VERSION_SCRIPT})
    set(VERSION_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/${VERSION_SCRIPT}")
  endif()
  set_property(TARGET ${DEST} APPEND_STRING PROPERTY
    LINK_FLAGS " -Wl,--version-script,${VERSION_SCRIPT}")

  # NOTE: This won't work with ninja prior to cmake 3.4
  set_property(TARGET ${DEST} APPEND_STRING PROPERTY
    LINK_DEPENDS ${VERSION_SCRIPT})
endfunction()

# Basic function to produce a standard libary with a GNU LD version script.
function(rdma_library DEST VERSION_SCRIPT SOVERSION VERSION)
  # Create a static library
  if (ENABLE_STATIC)
    add_library(${DEST}-static STATIC ${ARGN})
    set_target_properties(${DEST}-static PROPERTIES
      OUTPUT_NAME ${DEST}
      ARCHIVE_OUTPUT_DIRECTORY "${BUILD_LIB}")
    target_compile_definitions(${DEST}-static PRIVATE _STATIC_LIBRARY_BUILD_=1)
    install(TARGETS ${DEST}-static DESTINATION "${CMAKE_INSTALL_LIBDIR}")

    list(APPEND RDMA_STATIC_LIBS ${DEST} ${DEST}-static)
    set(RDMA_STATIC_LIBS "${RDMA_STATIC_LIBS}" CACHE INTERNAL "")
  endif()

  # Create a shared library
  add_library(${DEST} SHARED ${ARGN})
  rdma_set_library_map(${DEST} ${VERSION_SCRIPT})
  target_link_libraries(${DEST} LINK_PRIVATE ${COMMON_LIBS_PIC})
  set_target_properties(${DEST} PROPERTIES
    SOVERSION ${SOVERSION}
    VERSION ${VERSION}
    LIBRARY_OUTPUT_DIRECTORY "${BUILD_LIB}")
  install(TARGETS ${DEST} DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endfunction()

# Create a special provider with exported symbols in it The shared provider
# exists as a normal system library with the normal shared library SONAME and
# other convections. The system library is symlinked into the
# VERBS_PROVIDER_DIR so it can be dlopened as a provider as well.
function(rdma_shared_provider DEST VERSION_SCRIPT SOVERSION VERSION)
  # Installed driver file
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${DEST}.driver" "driver ${DEST}\n")
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${DEST}.driver" DESTINATION "${CONFIG_DIR}")

  # Uninstalled driver file
  file(MAKE_DIRECTORY "${BUILD_ETC}/libibverbs.d/")
  file(WRITE "${BUILD_ETC}/libibverbs.d/${DEST}.driver" "driver ${BUILD_LIB}/lib${DEST}\n")

  # Create a static provider library
  if (ENABLE_STATIC)
    add_library(${DEST}-static STATIC ${ARGN})
    set_target_properties(${DEST}-static PROPERTIES OUTPUT_NAME ${DEST})
    set_target_properties(${DEST}-static PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${BUILD_LIB}")
    target_compile_definitions(${DEST}-static PRIVATE _STATIC_LIBRARY_BUILD_=1)
    install(TARGETS ${DEST}-static DESTINATION "${CMAKE_INSTALL_LIBDIR}")

    list(APPEND RDMA_STATIC_LIBS ${DEST} ${DEST}-static)
    set(RDMA_STATIC_LIBS "${RDMA_STATIC_LIBS}" CACHE INTERNAL "")
  endif()

  # Create the plugin shared library
  add_library(${DEST} SHARED ${ARGN})
  rdma_set_library_map(${DEST} ${VERSION_SCRIPT})

  target_link_libraries(${DEST} LINK_PRIVATE ${COMMON_LIBS_PIC})
  target_link_libraries(${DEST} LINK_PRIVATE ibverbs)
  target_link_libraries(${DEST} LINK_PRIVATE ${CMAKE_THREAD_LIBS_INIT})
  set_target_properties(${DEST} PROPERTIES
    SOVERSION ${SOVERSION}
    VERSION ${VERSION}
    LIBRARY_OUTPUT_DIRECTORY "${BUILD_LIB}")
  install(TARGETS ${DEST} DESTINATION "${CMAKE_INSTALL_LIBDIR}")

  # Compute a relative symlink from VERBS_PROVIDER_DIR to LIBDIR
  execute_process(COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/buildlib/relpath
    "${CMAKE_INSTALL_FULL_LIBDIR}/lib${DEST}.so.${VERSION}"
    "${VERBS_PROVIDER_DIR}"
    OUTPUT_VARIABLE DEST_LINK_PATH OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE retcode)
  if(NOT "${retcode}" STREQUAL "0")
    message(FATAL_ERROR "Unable to run buildlib/relpath, do you have python?")
  endif()

  rdma_install_symlink("${DEST_LINK_PATH}" "${VERBS_PROVIDER_DIR}/lib${DEST}${IBVERBS_PROVIDER_SUFFIX}")
  rdma_create_symlink("lib${DEST}.so.${VERSION}" "${BUILD_LIB}/lib${DEST}${IBVERBS_PROVIDER_SUFFIX}")
endfunction()

# Create a provider shared library for libibverbs
function(rdma_provider DEST)
  # Installed driver file
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${DEST}.driver" "driver ${DEST}\n")
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${DEST}.driver" DESTINATION "${CONFIG_DIR}")

  # Uninstalled driver file
  file(MAKE_DIRECTORY "${BUILD_ETC}/libibverbs.d/")
  file(WRITE "${BUILD_ETC}/libibverbs.d/${DEST}.driver" "driver ${BUILD_LIB}/lib${DEST}\n")

  # Create a static provider library
  # FIXME: This is probably pointless, the provider library has no symbols so
  # what good is it? Presumably it should be used with -Wl,--whole-archive,
  # but we don't have any directions on how to make static linking work..
  if (ENABLE_STATIC)
    add_library(${DEST} STATIC ${ARGN})
    set_target_properties(${DEST} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${BUILD_LIB}")
    target_compile_definitions(${DEST} PRIVATE _STATIC_LIBRARY_BUILD_=1)
    install(TARGETS ${DEST} DESTINATION "${CMAKE_INSTALL_LIBDIR}")

    list(APPEND RDMA_STATIC_LIBS "${DEST}-rdmav${IBVERBS_PABI_VERSION}" ${DEST})
    set(RDMA_STATIC_LIBS "${RDMA_STATIC_LIBS}" CACHE INTERNAL "")
  endif()

  # Create the plugin shared library
  set(DEST "${DEST}-rdmav${IBVERBS_PABI_VERSION}")
  add_library(${DEST} MODULE ${ARGN})
  # Even though these are modules we still want to use Wl,--no-undefined
  set_target_properties(${DEST} PROPERTIES LINK_FLAGS ${CMAKE_SHARED_LINKER_FLAGS})
  rdma_set_library_map(${DEST} ${BUILDLIB}/provider.map)
  target_link_libraries(${DEST} LINK_PRIVATE ${COMMON_LIBS_PIC})
  target_link_libraries(${DEST} LINK_PRIVATE ibverbs)
  target_link_libraries(${DEST} LINK_PRIVATE ${CMAKE_THREAD_LIBS_INIT})
  set_target_properties(${DEST} PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${BUILD_LIB}")
  # Provider Plugins do not use SONAME versioning, there is no reason to
  # create the usual symlinks.

  if (VERBS_PROVIDER_DIR)
    install(TARGETS ${DEST} DESTINATION "${VERBS_PROVIDER_DIR}")
  else()
    install(TARGETS ${DEST} DESTINATION "${CMAKE_INSTALL_LIBDIR}")

    # FIXME: This symlink is provided for compat with the old build, but it
    # never should have existed in the first place, nothing should use this
    # name, we can probably remove it.
    rdma_install_symlink("lib${DEST}${IBVERBS_PROVIDER_SUFFIX}" "${CMAKE_INSTALL_LIBDIR}/lib${DEST}.so")
  endif()
endfunction()

 # Create an installed executable
function(rdma_executable EXEC)
  add_executable(${EXEC} ${ARGN})
  target_link_libraries(${EXEC} LINK_PRIVATE ${COMMON_LIBS})
  set_target_properties(${EXEC} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${BUILD_BIN}")
  install(TARGETS ${EXEC} DESTINATION "${CMAKE_INSTALL_BINDIR}")
endfunction()

 # Create an installed executable (under sbin)
function(rdma_sbin_executable EXEC)
  add_executable(${EXEC} ${ARGN})
  target_link_libraries(${EXEC} LINK_PRIVATE ${COMMON_LIBS})
  set_target_properties(${EXEC} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${BUILD_BIN}")
  install(TARGETS ${EXEC} DESTINATION "${CMAKE_INSTALL_SBINDIR}")
endfunction()

# Create an test executable (not-installed)
function(rdma_test_executable EXEC)
  add_executable(${EXEC} ${ARGN})
  target_link_libraries(${EXEC} LINK_PRIVATE ${COMMON_LIBS})
  set_target_properties(${EXEC} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${BUILD_BIN}")
endfunction()

# Install man pages. This deduces the section from the trailing integer in the
# filename
function(rdma_man_pages)
  foreach(I ${ARGN})
    if ("${I}" MATCHES "\\.in$")
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

# Finalize the setup of the static libraries by copying the meta information
# from the shared and setting up the libtool .la files.
function(rdma_finalize_libs)
  list(LENGTH RDMA_STATIC_LIBS LEN)
  if (LEN LESS 2)
    return()
  endif()

  math(EXPR LEN ${LEN}-1)
  foreach(I RANGE 0 ${LEN} 2)
    list(GET RDMA_STATIC_LIBS ${I} SHARED)
    math(EXPR I ${I}+1)
    list(GET RDMA_STATIC_LIBS ${I} STATIC)

    # PUBLIC libraries
    set(LIBS "")
    get_property(TMP TARGET ${SHARED} PROPERTY INTERFACE_LINK_LIBRARIES SET)
    if (TMP)
      get_target_property(TMP ${SHARED} INTERFACE_LINK_LIBRARIES)
      set_target_properties(${STATIC} PROPERTIES INTERFACE_LINK_LIBRARIES "${TMP}")
      set(LIBS "${TMP}")
    endif()

    # PRIVATE libraries
    get_property(TMP TARGET ${SHARED} PROPERTY LINK_LIBRARIES SET)
    if (TMP)
      get_target_property(TMP ${SHARED} LINK_LIBRARIES)
      set_target_properties(${STATIC} PROPERTIES LINK_LIBRARIES "${TMP}")
      list(APPEND LIBS "${TMP}")
    endif()
  endforeach()
endfunction()
