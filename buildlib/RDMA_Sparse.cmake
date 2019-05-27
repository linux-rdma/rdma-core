# COPYRIGHT (c) 2017 Obsidian Research Corporation.
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.

function(RDMA_CheckSparse)
  # Sparse defines __CHECKER__, but only for the 'sparse pass', which has no
  # way to fail the compiler.
  CHECK_C_SOURCE_COMPILES("
#if __CHECKER__
#warning \"SPARSE DETECTED\"
#endif
int main(int argc,const char *argv[]) {return 0;}
"
    HAVE_NO_SPARSE
    FAIL_REGEX "SPARSE DETECTED")

  if (HAVE_NO_SPARSE)
    set(HAVE_SPARSE FALSE PARENT_SCOPE)
  else()
    set(HAVE_SPARSE TRUE PARENT_SCOPE)

    # Replace various glibc headers with our own versions that have embedded sparse annotations.
    execute_process(COMMAND "${PYTHON_EXECUTABLE}" "${BUILDLIB}/gen-sparse.py"
      "--out" "${BUILD_INCLUDE}/"
      "--src" "${CMAKE_SOURCE_DIR}/"
      "--cc" "${CMAKE_C_COMPILER}"
      RESULT_VARIABLE retcode)
    if(NOT "${retcode}" STREQUAL "0")
      message(FATAL_ERROR "glibc header file patching for sparse failed. Review include/*.rej and fix the rejects, then do "
	"${BUILDLIB}/gen-sparse.py -out ${BUILD_INCLUDE}/ --src ${CMAKE_SOURCE_DIR}/ --save")
    endif()

    # Enable endian analysis in sparse
    add_definitions("-D__CHECK_ENDIAN__")
  endif()
endfunction()
