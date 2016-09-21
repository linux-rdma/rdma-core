# COPYRIGHT (c) 2016 Obsidian Research Corporation. See COPYING file

# Helper functions for use in the sub CMakeLists files to make them simpler
# and more uniform.

# Global list of pairs of (SHARED STATIC) libary target names
set(RDMA_STATIC_LIBS "" CACHE INTERNAL "Doc" FORCE)

# Install a symlink during 'make install'
function(rdma_install_symlink LINK_CONTENT DEST)
  # Create a link in the build tree with the right content
  get_filename_component(FN "${DEST}" NAME)
  execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink
    "${LINK_CONTENT}"
    "${CMAKE_CURRENT_BINARY_DIR}/${FN}")

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
  add_library(${DEST}-static STATIC ${ARGN})
  set_target_properties(${DEST}-static PROPERTIES
    OUTPUT_NAME ${DEST}
    LIBRARY_OUTPUT_DIRECTORY "${BUILD_LIB}")
  install(TARGETS ${DEST}-static DESTINATION "${CMAKE_INSTALL_LIBDIR}")

  list(APPEND RDMA_STATIC_LIBS ${DEST} ${DEST}-static)
  set(RDMA_STATIC_LIBS "${RDMA_STATIC_LIBS}" CACHE INTERNAL "")

  # Create a shared library
  add_library(${DEST} SHARED ${ARGN})
  rdma_set_library_map(${DEST} ${VERSION_SCRIPT})
  set_target_properties(${DEST} PROPERTIES
    SOVERSION ${SOVERSION}
    VERSION ${VERSION}
    LIBRARY_OUTPUT_DIRECTORY "${BUILD_LIB}")
  install(TARGETS ${DEST} DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endfunction()

# Create a provider shared library for libibverbs
function(rdma_provider DEST)
  # Installed driver file
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${DEST}.driver" "driver ${DEST}\n")
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${DEST}.driver" DESTINATION "${CONFIG_DIR}")

  # Uninstalled driver file
  file(MAKE_DIRECTORY "${BUILD_LIB}/libibverbs.d/")
  file(WRITE "${BUILD_LIB}/libibverbs.d/${DEST}.driver" "driver ${BUILD_LIB}/${DEST}\n")

  # FIXME: This symlink is provided for compat with the old build, but it
  # never should have existed in the first place, nothing should use this
  # name, we can probably remove it.
  rdma_install_symlink("lib${DEST}-rdmav2.so" "${CMAKE_INSTALL_LIBDIR}/lib${DEST}.so")

  # Create a static provider library
  # FIXME: This is probably pointless, the provider library has no symbols so
  # what good is it? Presumably it should be used with -Wl,--whole-archive,
  # but we don't have any directions on how to make static linking work..
  add_library(${DEST} STATIC ${ARGN})
  set_target_properties(${DEST} PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${BUILD_LIB}")
  install(TARGETS ${DEST} DESTINATION "${CMAKE_INSTALL_LIBDIR}")

  list(APPEND RDMA_STATIC_LIBS ${DEST}-rdmav2 ${DEST})
  set(RDMA_STATIC_LIBS "${RDMA_STATIC_LIBS}" CACHE INTERNAL "")

  # Create the plugin shared library
  set(DEST ${DEST}-rdmav2)
  add_library(${DEST} MODULE ${ARGN})
  # Even though these are modules we still want to use Wl,--no-undefined
  set_target_properties(${DEST} PROPERTIES LINK_FLAGS ${CMAKE_SHARED_LINKER_FLAGS})
  rdma_set_library_map(${DEST} ${BUILDLIB}/provider.map)
  target_link_libraries(${DEST} PRIVATE ibverbs)
  target_link_libraries(${DEST} PRIVATE ${CMAKE_THREAD_LIBS_INIT})
  set_target_properties(${DEST} PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${BUILD_LIB}")
  # Provider Plugins do not use SONAME versioning, there is no reason to
  # create the usual symlinks.

  install(TARGETS ${DEST} DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endfunction()

 # Create an installed executable
function(rdma_executable EXEC)
  add_executable(${EXEC} ${ARGN})
  set_target_properties(${EXEC} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${BUILD_BIN}")
  install(TARGETS ${EXEC} DESTINATION "${CMAKE_INSTALL_BINDIR}")
endfunction()

 # Create an installed executable (under sbin)
function(rdma_sbin_executable EXEC)
  add_executable(${EXEC} ${ARGN})
  set_target_properties(${EXEC} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${BUILD_BIN}")
  install(TARGETS ${EXEC} DESTINATION "${CMAKE_INSTALL_SBINDIR}")
endfunction()

# Create an test executable (not-installed)
function(rdma_test_executable EXEC)
  add_executable(${EXEC} ${ARGN})
  set_target_properties(${EXEC} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${BUILD_BIN}")
endfunction()

# Install man pages. This deduces the section from the trailing integer in the
# filename
function(rdma_man_pages)
  foreach(I ${ARGN})
    string(REGEX REPLACE "^.+[.](.+)$" "\\1" MAN_SECT ${I})
    install(FILES ${I} DESTINATION "${CMAKE_INSTALL_MANDIR}/man${MAN_SECT}/")
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

# For compatability write out a libtool .la file. This is only meaningful if
# the end user is statically linking, and only if the library has dependent
# libraries.

# FIXME: it isn't clear how this is actually useful for provider libraries and
# libibverbs itself, the user must do some trick to get the constructor to run
# in the provider, at least how to do that should be documented someplace..
function(rdma_make_libtool_la SHARED STATIC LIBS)
  get_property(LIB TARGET ${STATIC} PROPERTY OUTPUT_NAME SET)
  if (LIB)
    get_target_property(LIB ${STATIC} OUTPUT_NAME)
  else()
    set(LIB ${STATIC})
  endif()

  set(BARE_LAFN "${CMAKE_STATIC_LIBRARY_PREFIX}${LIB}.la")
  set(BARE_LIBFN "${CMAKE_STATIC_LIBRARY_PREFIX}${LIB}${CMAKE_STATIC_LIBRARY_SUFFIX}")

  get_property(SOLIB TARGET ${SHARED} PROPERTY OUTPUT_NAME SET)
  if (SOLIB)
    get_target_property(SOLIB ${SHARED} OUTPUT_NAME)
  else()
    set(SOLIB ${SHARED})
  endif()

  set(DLNAME "${CMAKE_SHARED_LIBRARY_PREFIX}${SOLIB}${CMAKE_SHARED_LIBRARY_SUFFIX}")
  get_property(TMP TARGET ${SHARED} PROPERTY SOVERSION SET)
  if (TMP)
    get_target_property(VERSION ${SHARED} VERSION)
    get_target_property(SOVERSION ${SHARED} SOVERSION)
    set(NAMES "${DLNAME}.${VERSION} ${DLNAME}.${SOVERSION} ${DLNAME}")
    set(DLNAME "${DLNAME}.${SOVERSION}")
  else()
    set(NAMES "${DLNAME}")
    set(DLNAME "${CMAKE_SHARED_LIBRARY_PREFIX}${SOLIB}${CMAKE_SHARED_LIBRARY_SUFFIX}")
  endif()

  if (LIBS)
    list(REMOVE_DUPLICATES LIBS)
    foreach(I ${LIBS})
      if (I MATCHES "^-l")
	list(APPEND DEPS "${I}")
      else()
	list(APPEND DEPS "-l${I}")
      endif()
    endforeach()
    string(REPLACE ";" " " DEPS "${DEPS}")
  endif()

  set(LAFN "${BUILD_LIB}/${BARE_LAFN}")
  file(WRITE ${LAFN}
    "# ${BARE_LAFN} - a libtool library file\n"
    "# Generated by cmake\n"
    "#\n"
    "# Please DO NOT delete this file!\n"
    "# It is necessary for linking the library.\n"
    "\n"
    "# The name that we can dlopen(3).\n"
    "dlname='${DLNAME}'\n"
    "\n"
    "# Names of this library.\n"
    "library_names='${NAMES}'\n"
    "\n"
    "# The name of the static archive.\n"
    "old_library='${BARE_LIBFN}'\n"
    "\n"
    "# Linker flags that can not go in dependency_libs.\n"
    "inherited_linker_flags=''\n"
    "\n"
    "# Libraries that this one depends upon.\n"
    "dependency_libs='${DEPS}'\n"
    "\n"
    "# Names of additional weak libraries provided by this library\n"
    "weak_library_names=''\n"
    "\n"
    "# Version information for ${CMAKE_STATIC_LIBRARY_PREFIX}${LIB}.\n"
    # We don't try very hard to emulate this, it isn't used for static linking anyhow
    "current=${SOVERSION}\n"
    "age=0\n"
    "revision=0\n"
    "\n"
    "# Is this an already installed library?\n"
    "installed=yes\n"
    "\n"
    "# Should we warn about portability when linking against -modules?\n"
    "shouldnotlink=no\n"
    "\n"
    "# Files to dlopen/dlpreopen\n"
    "dlopen=''\n"
    "dlpreopen=''\n"
    "\n"
    "# Directory that this library needs to be installed in:\n"
    "libdir='${CMAKE_INSTALL_FULL_LIBDIR}'\n"
    )
  install(FILES ${LAFN} DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endfunction()

# Finalize the setup of the static libraries by copying the meta information
# from the shared and setting up the libtool .la files.
function(rdma_finalize_libs)
  list(LENGTH RDMA_STATIC_LIBS LEN)
  math(EXPR LEN ${LEN}-1)
  foreach(I RANGE 0 ${LEN} 2)
    list(GET RDMA_STATIC_LIBS ${I} SHARED)
    math(EXPR I ${I}+1)
    list(GET RDMA_STATIC_LIBS ${I} STATIC)

    # PUBLIC libraries
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

    rdma_make_libtool_la(${SHARED} ${STATIC} "${LIBS}")
  endforeach()
endfunction()
