aux_source_directory (. DIR_CAP_SRCS)

include_directories (
    /usr/include/dpdk/
  )
  
add_definitions(-mssse3)
add_definitions(-msse4)

add_library (facap STATIC ${DIR_CAP_SRCS})

install (TARGETS facap DESTINATION lib)
install (FILES dpdk.h DESTINATION include)
