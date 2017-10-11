cmake_minimum_required (VERSION 2.8)
set (PRJ fa)
project ($(PRJ))
set (CMAKE_CXX_STANDARD 11)

include_directories (
    /usr/include/dpdk/
  )
add_definitions(-mssse3)
add_definitions(-msse4)

#link_directories($ENV{DPDK_RTE_TARGET_1611}/lib)

set (CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -std=c++11 -Wall"
  )

set (DPDK_LIBS
    "-Wl,--whole-archive"
    "-ldpdk"
    "-Wl,--no-whole-archive"
  )

add_subdirectory (cap)

add_executable (fa main.cc)
target_link_libraries(${PRJ} ${DPDK_LIBS})
target_link_libraries (fa facap)