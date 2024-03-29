cmake_minimum_required(VERSION 3.16)

project(libmdx)

set(LIBMDX_SRCS
    mdx.h
    mdx.c
    ripemd128.h
    ripemd128.c
)

find_package(LIBXML2 REQUIRED)
include_directories(${LIBXML2_INCLUDE_DIRS})
list(APPEND LIBMDX_LIBS ${LIBXML2_LIBRARIES})

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
target_link_libraries(mdx PRIVATE ${LIBMDX_LIBS})

add_executable(mdx_example main.c)
target_link_libraries(mdx_example PRIVATE mdx)
