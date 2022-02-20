cmake_minimum_required(VERSION 3.16)

project(libmdx)

set(LIBMDX_SRCS
    mdx.h
    mdx.c
    ripemd128.h
    ripemd128.c
)

option(USE_ZLIB "Use zlib" ON)
if(USE_ZLIB)
    find_package(ZLIB REQUIRED)
    include_directories(${ZLIB_INCLUDE_DIRS})
    add_compile_definitions(USE_ZLIB)
    list(APPEND LIBMDX_LIBS ${ZLIB_LIBRARIES})
else()
    list(APPEND LIBMDX_SRCS miniz.h miniz.c)
    add_compile_definitions(USE_MINIZ)
endif()

option(STATIC_BUILD "Build static library" OFF)
if(STATIC_BUILD)
    add_library(mdx STATIC ${LIBMDX_SRCS})
else()
    add_library(mdx SHARED ${LIBMDX_SRCS})
endif()
add_executable(mdx_example main.c ${LIBMDX_SRCS})
target_link_libraries(mdx_example PRIVATE mdx ${LIBMDX_LIBS})
