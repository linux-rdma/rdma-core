# COPYRIGHT (c) 2016 Obsidian Research Corporation.
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.
# find_package helper to detect symbol version support in the compiler and
# linker. If supported then LDSYMVER_MODE will be set to GNU

# Basic sample GNU style map file
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test.map" "
IBVERBS_1.0 {
        global:
                ibv_get_device_list;
        local: *;
};

IBVERBS_1.1 {
        global:
                ibv_get_device_list;
} IBVERBS_1.0;
")

# See RDMA_CHECK_C_LINKER_FLAG
set(SAFE_CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")
set(SAFE_CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
if (POLICY CMP0056)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/test.map")
else()
  set(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES} -Wl,--version-script=${CMAKE_CURRENT_BINARY_DIR}/test.map")
endif()

# And matching source, this also checks that .symver asm works
check_c_source_compiles("
void ibv_get_device_list_1(void);
void ibv_get_device_list_1(void){}
asm(\".symver ibv_get_device_list_1, ibv_get_device_list@IBVERBS_1.1\");
void ibv_get_device_list_0(void);
void ibv_get_device_list_0(void){}
asm(\".symver ibv_get_device_list_0, ibv_get_device_list@@IBVERBS_1.0\");

int main(int argc,const char *argv[]){return 0;}" _LDSYMVER_SUCCESS)

file(REMOVE "${CMAKE_CURRENT_BINARY_DIR}/test.map")
set(CMAKE_EXE_LINKER_FLAGS "${SAFE_CMAKE_EXE_LINKER_FLAGS}")
set(CMAKE_REQUIRED_LIBRARIES "${SAFE_CMAKE_REQUIRED_LIBRARIES}")

if (_LDSYMVER_SUCCESS)
  set(LDSYMVER_MODE "GNU" CACHE INTERNAL "How to set symbol versions on shared libraries")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  LDSymVer
  REQUIRED_VARS LDSYMVER_MODE
  )
