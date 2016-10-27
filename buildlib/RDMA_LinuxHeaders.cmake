# COPYRIGHT (c) 2016 Obsidian Research Corporation. See COPYING file

# Check that the system kernel headers are new enough, if not replace the
# headers with our internal copy.

set(DEFAULT_TEST "int main(int argc,const char *argv[]) {return 1;}")
set(MISSING_HEADERS "")

function(rdma_canon_header PATH OUT_VAR)
  string(TOUPPER "${PATH}" HAVE)
  string(REPLACE " " "_" HAVE "${HAVE}")
  string(REPLACE "/" "_" HAVE "${HAVE}")
  string(REPLACE "." "_" HAVE "${HAVE}")
  set("${OUT_VAR}" "HAVE_${HAVE}" PARENT_SCOPE)
endfunction()

function(rdma_check_kheader PATH C_TEST)
  rdma_canon_header("${PATH}" HAVE)

  if(KERNEL_DIR)
    # Drop a symlink back to the kernel into our include/ directory
    if (EXISTS "${KERNEL_DIR}/include/uapi/${PATH}")
      set(DEST "${BUILD_INCLUDE}/${PATH}")

      if(CMAKE_VERSION VERSION_LESS "2.8.12")
	get_filename_component(DIR ${DEST} PATH)
      else()
	get_filename_component(DIR ${DEST} DIRECTORY)
      endif()
      file(MAKE_DIRECTORY "${DIR}")

      # We cannot just -I the kernel UAPI dir, it depends on some
      # post-processing of things like linux/stddef.h. Instead we symlink the
      # kernel headers into our tree and rely on the distro's fixup of
      # non-rdma headers.  The RDMA headers are all compatible with this
      # scheme.
      execute_process(COMMAND "${CMAKE_COMMAND}" "-E" "create_symlink"
	"${KERNEL_DIR}/include/uapi/${PATH}"
	"${DEST}")
    else()
      message(FATAL_ERROR "Kernel tree does not contain expected UAPI header"
	"${KERNEL_DIR}/include/uapi/${PATH}")
    endif()

    set(CMAKE_REQUIRED_INCLUDES "${BUILD_INCLUDE}")
  endif()

  # Note: The RDMA kernel headers use sockaddr{_in,_in6,}/etc so we have to
  # include system headers to define sockaddrs before testing any of them.
  CHECK_C_SOURCE_COMPILES("
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <${PATH}>
${C_TEST}" "${HAVE}")

  if(KERNEL_DIR)
    if (NOT "${${HAVE}}")
      # Run the compile test against the linked kernel header, this is to help
      # make sure the compile tests work before the headers hit the distro
      message(FATAL_ERROR "Kernel UAPI header failed compile test"
	"${PATH}")
    endif()
  else()
    RDMA_DoFixup("${${HAVE}}" "${PATH}")
    if (NOT "${${HAVE}}")
      list(APPEND MISSING_HEADERS "${PATH}")
      set(MISSING_HEADERS "${MISSING_HEADERS}" PARENT_SCOPE)
    endif()
  endif()
endfunction()

function(rdma_report_missing_kheaders)
  foreach(I IN LISTS MISSING_HEADERS)
    message(STATUS " ${I} NOT found (old system kernel headers)")
  endforeach()
endfunction()

# This list is topologically sorted
rdma_check_kheader("rdma/ib_user_verbs.h" "${DEFAULT_TEST}")
rdma_check_kheader("rdma/ib_user_sa.h" "${DEFAULT_TEST}")
rdma_check_kheader("rdma/ib_user_cm.h" "${DEFAULT_TEST}")
rdma_check_kheader("rdma/ib_user_mad.h" "${DEFAULT_TEST}")
rdma_check_kheader("rdma/rdma_netlink.h" "${DEFAULT_TEST}")
rdma_check_kheader("rdma/rdma_user_cm.h" "${DEFAULT_TEST}")
rdma_check_kheader("rdma/rdma_user_rxe.h" "${DEFAULT_TEST}")
